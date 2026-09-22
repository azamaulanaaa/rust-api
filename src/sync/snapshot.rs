//! Per-user filtered replicas on stable `OxKvStore` prefixes.
//!
//! The master [`FsStore`] remains the sole write path. Each user owns one
//! replica prefix (`{db_prefix}/u/{sub}/`) holding their filtered file set.
//! Builds filter into a RAM scratch store, diff against the live replica,
//! and commit the diff plus the coverage marker in ONE transaction: crash
//! before commit leaves the old state untouched (oxkv replays only listed
//! WALs on open), and an empty diff commits nothing at all.
//!
//! The `sync:applied` sentinel inside the prefix tracks WAL coverage, so no
//! sidecar pointer object exists. Small deltas replay with idempotent
//! re-apply (sentinel written last); legacy policy marks and large ranges
//! fall back to full recalc, while rich rule/group ops resync only the
//! affected user/row. Served read-only via `/sync/db/`; wasm clients open
//! an `OxKvReader` over the prefix and follow the live manifest.

use std::collections::HashMap;

use crate::fs::error::FsError;
use crate::fs::store::FsStore;
use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, PolicyEngine};
use oxkv::{Direction, GetSet as _, OxKvReader, Store as _, Transaction as _};

use super::wal::{Wal, WalOp};

/// Sync-version marker stored inside every replica prefix.
const APPLIED_KEY: &str = "sync:applied";

/// Upper bound for file/relation ops replayed incrementally.
const MAX_REPLAY_OPS: usize = 1000;

/// Upper bound for files touched by one policy op before falling back to
/// a full recalc (keeps one group/row change from scanning the store).
const MAX_POLICY_REPLAY_FILES: usize = 1000;

/// Manager for per-user replicas.
#[derive(Clone)]
pub struct SnapshotManager {
    /// WAL for version tracking.
    pub(crate) wal: Wal,
    /// Master file store.
    pub(crate) store: FsStore,
    /// Policy for filtering.
    pub policy: PolicyEngine,
    /// Shared object store backing every replica prefix.
    pub(crate) object_store: std::sync::Arc<dyn object_store::ObjectStore>,
    /// Root prefix for replica prefixes (e.g. `"oxkv"`).
    pub(crate) db_prefix: String,
    /// Skip the oxkv storage probe (tests on `InMemory`).
    skip_probe: bool,
    /// SST block cache shared by every replica open from this manager.
    ///
    /// Writer/reader opens used to build a private cold cache per call
    /// (dropped with the handle); sharing keeps hot SSTs resident across
    /// rebuilds. Clones share the state, matching the build lock.
    sst_cache: oxkv::LruCache<String, std::sync::Arc<oxkv::SstFile>>,
    /// Serializes builds and replays per process (one live writer per prefix).
    build_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl SnapshotManager {
    /// Create a manager.
    pub fn new(
        wal: Wal,
        store: FsStore,
        policy: PolicyEngine,
        object_store: std::sync::Arc<dyn object_store::ObjectStore>,
        db_prefix: String,
        skip_probe: bool,
    ) -> Self {
        Self {
            wal,
            store,
            policy,
            object_store,
            db_prefix,
            skip_probe,
            build_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            sst_cache: crate::db::default_sst_cache(),
        }
    }

    /// Replica prefix for `sub` (`{db}/u/{sha256-hex(sub)}`).
    ///
    /// The digest keeps replica prefixes fixed-length and safe by
    /// construction (hex only): subjects are attacker-influenced OIDC
    /// values, so embedding them raw would allow traversal or collisions.
    pub fn user_prefix(&self, sub: &str) -> String {
        format!("{}/u/{}", self.db_prefix.trim_matches('/'), safe_sub(sub))
    }

    /// Full object key for `tail` inside the replica.
    ///
    /// Rejects path traversal (`..`) so the gateway cannot escape the
    /// replica prefix.
    pub fn resolve_object(&self, sub: &str, tail: &str) -> Result<String, FsError> {
        if tail.is_empty() || tail.split('/').any(|seg| seg == "..") {
            return Err(FsError::BadRequest("invalid object path".into()));
        }
        Ok(format!("{}/{tail}", self.user_prefix(sub)))
    }

    /// Reads the WAL coverage marker, or `None` when never built.
    pub async fn load_applied(&self, sub: &str) -> Result<Option<u64>, FsError> {
        use object_store::ObjectStore as _;

        let manifest =
            object_store::path::Path::from(format!("{}/manifest.json", self.user_prefix(sub)));
        match self.object_store.get(&manifest).await {
            Ok(_) => {}
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(FsError::Internal(e.to_string())),
        }
        let reader = self.open_reader(sub).await?;
        let tx = reader.begin_tx().map_err(store_err)?;
        let out = match tx.get_bytes(APPLIED_KEY).await.map_err(store_err)? {
            Some(bytes) => serde_json::from_slice(&bytes).ok(),
            None => None,
        };
        tx.rollback().await.map_err(store_err)?;
        Ok(out)
    }

    /// Builds the replica for `sub` at current `wal` head.
    ///
    /// See the module docs for the atomicity contract. Returns the covered
    /// WAL head.
    pub async fn build_full(&self, sub: &str) -> Result<u64, FsError> {
        let _guard = self.build_lock.lock().await;
        let head = self.wal.head().await?;
        // Converge the RAM mirror before the bulk scan (no-op unless
        // [database].mirror_master opted into the prototype).
        self.store.refresh_mirror().await?;

        let snap_prefix = format!(
            "snap-{}-{head}-{}",
            safe_sub(sub),
            &uuid::Uuid::now_v7().to_string()[..8]
        );
        let scratch = FsStore::new(crate::db::build_scratch_store(&snap_prefix).await);
        self.copy_filtered(sub, &scratch).await?;
        let mut new_map: HashMap<String, Vec<u8>> = scratch.dump_kvs().await?.into_iter().collect();
        new_map.insert(
            APPLIED_KEY.to_string(),
            serde_json::to_vec(&head).map_err(|e| FsError::Internal(e.to_string()))?,
        );
        let cur_map = self.read_live(sub).await?;

        let mut dels = Vec::new();
        for key in cur_map.keys() {
            if !new_map.contains_key(key) {
                dels.push(key.clone());
            }
        }
        let mut puts = Vec::new();
        for (key, value) in &new_map {
            if cur_map.get(key) != Some(value) {
                puts.push((key.clone(), value.clone()));
            }
        }
        if dels.is_empty() && puts.is_empty() {
            return Ok(head);
        }

        let writer = self.open_writer(sub).await?;
        let tx = writer.begin_tx().map_err(store_err)?;
        for key in &dels {
            tx.delete(key).await.map_err(store_err)?;
        }
        for (key, value) in &puts {
            tx.put_bytes(key, value).await.map_err(store_err)?;
        }
        tx.commit().await.map_err(store_err)?;
        Ok(head)
    }

    /// Replays WAL entries `applied+1..=head` for `sub` onto the live replica.
    ///
    /// Ops apply in order with visibility re-checked against current master
    /// state, then the coverage marker advances: re-applying converges, so a
    /// crash between ops heals on the next poll. Legacy policy marks (object
    /// only) and ranges over [`MAX_REPLAY_OPS`] entries fall back to a full
    /// recalc via `Err`; rich rule/group ops resync only the affected
    /// user/row (irrelevant users/objects skip, oversized fan-out falls
    /// back via `Err`).
    pub async fn replay(&self, head: u64, sub: &str) -> Result<u64, FsError> {
        let _guard = self.build_lock.lock().await;
        let Some(applied) = self.load_applied(sub).await? else {
            return Err(FsError::Internal("no base replica for replay".into()));
        };
        if applied >= head {
            return Ok(applied);
        }
        let entries = self.wal.range(applied + 1, head).await?;
        if entries.len() > MAX_REPLAY_OPS || entries.iter().any(|e| e.op.is_legacy_policy_mark()) {
            return Err(FsError::Internal(
                "replay needs full recalc (legacy policy mark or range too large)".into(),
            ));
        }
        let writer = self.open_writer(sub).await?;
        let dst = FsStore::new(writer.clone());
        for entry in &entries {
            self.apply_op(sub, &dst, &entry.op).await?;
        }
        writer
            .set_bytes(
                APPLIED_KEY,
                &serde_json::to_vec(&head).map_err(|e| FsError::Internal(e.to_string()))?,
            )
            .await
            .map_err(store_err)?;
        Ok(head)
    }

    /// Opens the replica writer (acquires/takes over the prefix epoch).
    async fn open_writer(&self, sub: &str) -> Result<oxkv::OxKvStore, FsError> {
        oxkv::OxKvStore::builder()
            .with_object_store(self.object_store.clone())
            .with_prefix(oxkv::ObjectPath::from(self.user_prefix(sub).as_str()))
            .skip_probe(self.skip_probe)
            .build_with_cache(self.sst_cache.clone())
            .await
            .map_err(|e| FsError::Store(e.to_string()))
    }

    /// Opens a read-only follower over the replica (no ownership taken).
    async fn open_reader(&self, sub: &str) -> Result<OxKvReader, FsError> {
        let base: std::sync::Arc<dyn object_store::ObjectStore> = self.object_store.clone();
        let storage: std::sync::Arc<dyn oxkv::Storage> = std::sync::Arc::new(base);
        oxkv::OxKvStore::builder()
            .with_store(storage)
            .with_prefix(oxkv::ObjectPath::from(self.user_prefix(sub).as_str()))
            .build_reader_with_cache(self.sst_cache.clone())
            .await
            .map_err(|e| FsError::Store(e.to_string()))
    }

    /// Dumps the live replica as a map, or empty when never built.
    async fn read_live(&self, sub: &str) -> Result<HashMap<String, Vec<u8>>, FsError> {
        use object_store::ObjectStore as _;

        let manifest =
            object_store::path::Path::from(format!("{}/manifest.json", self.user_prefix(sub)));
        match self.object_store.get(&manifest).await {
            Ok(_) => {}
            Err(object_store::Error::NotFound { .. }) => return Ok(HashMap::new()),
            Err(e) => return Err(FsError::Internal(e.to_string())),
        }
        let reader = self.open_reader(sub).await?;
        let tx = reader.begin_tx().map_err(store_err)?;
        let kvs = tx
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .map_err(store_err)?;
        tx.rollback().await.map_err(store_err)?;
        Ok(kvs.into_iter().map(|kv| (kv.key, kv.value)).collect())
    }

    /// Applies one WAL op onto a replica under construction.
    ///
    /// Visibility is re-checked against current master state, so applying
    /// is idempotent: files that vanished or turned unreadable are skipped.
    async fn apply_op(&self, sub: &str, dst: &FsStore, op: &WalOp) -> Result<(), FsError> {
        match op {
            WalOp::FileCreate { rec } => {
                if self.can_read(sub, &rec.id).await? {
                    dst.save_file(rec).await?;
                }
            }
            WalOp::FileDelete { file_id } => {
                dst.delete_file(file_id).await?;
            }
            WalOp::Attach {
                row_type,
                row_id,
                file_id,
            } => {
                if let Some(rec) = self.store.get_file(file_id).await?
                    && self.can_read(sub, file_id).await?
                {
                    dst.save_file(&rec).await?;
                    if self
                        .policy
                        .authorize_row(sub, row_type, row_id, Action::Read)
                        .await
                        .unwrap_or(false)
                    {
                        dst.attach(row_type, row_id, file_id).await?;
                    }
                }
            }
            WalOp::Detach {
                row_type,
                row_id,
                file_id,
            } => {
                dst.detach(row_type, row_id, file_id).await?;
            }
            WalOp::PolicyAdd { .. } | WalOp::PolicyRemove { .. } => {
                return Err(FsError::Internal(
                    "legacy policy op reached apply (needs full recalc)".into(),
                ));
            }
            WalOp::PolicyRuleAdd { sub, obj, act } | WalOp::PolicyRuleRemove { sub, obj, act } => {
                self.apply_rule_op(sub, &dst, sub, obj, act).await?;
            }
            WalOp::GroupAdd { user, group } | WalOp::GroupRemove { user, group } => {
                self.apply_membership_op(sub, &dst, user, group).await?;
            }
            WalOp::GroupDelete { group } => {
                self.apply_group_delete(sub, &dst, group).await?;
            }
        }
        Ok(())
    }

    /// Resyncs the single row a permission rule changed.
    ///
    /// Skips fast: non-`read` actions never affect read replicas,
    /// non-row objects (`rules`, `user_groups`, …) hold no files, direct
    /// rules for other users cannot match, and group rules skip when `sub`
    /// holds no current membership. Otherwise every file on the row is
    /// re-checked via [`Self::resync_file`] (idempotent: converge, never
    /// over-delete). Fan-out over [`MAX_POLICY_REPLAY_FILES`] falls back
    /// via `Err`.
    async fn apply_rule_op(
        &self,
        sub: &str,
        dst: &FsStore,
        rule_sub: &str,
        obj: &str,
        act: &str,
    ) -> Result<(), FsError> {
        if !act.eq_ignore_ascii_case("read") {
            return Ok(());
        }
        let Some((row_type, row_id)) = split_row_obj(obj) else {
            return Ok(());
        };
        if rule_sub != sub
            && !self
                .policy
                .get_groups_of_user(sub)
                .await
                .iter()
                .any(|g| g == rule_sub)
        {
            return Ok(());
        }
        let files = self.store.files_for_row(row_type, row_id).await?;
        if files.len() > MAX_POLICY_REPLAY_FILES {
            return Err(FsError::Internal(
                "replay needs full recalc (policy fan-out too large)".into(),
            ));
        }
        for file_id in files {
            self.resync_file(sub, dst, row_type, row_id, &file_id)
                .await?;
        }
        Ok(())
    }

    /// Resyncs rows a membership change can affect (only when `user == sub`).
    ///
    /// Drops through when the change is for another user. For `sub` itself,
    /// every `read` row the group grants is resynced; groups with no row
    /// reads (e.g. `superadmin` on `rules`/`user_groups`) are a no-op.
    /// Oversized fan-out falls back via `Err`.
    async fn apply_membership_op(
        &self,
        sub: &str,
        dst: &FsStore,
        user: &str,
        group: &str,
    ) -> Result<(), FsError> {
        if user != sub {
            return Ok(());
        }
        let rows = self.read_rows_for_group(group).await?;
        let mut total = 0usize;
        for (row_type, row_id) in rows {
            let files = self.store.files_for_row(&row_type, &row_id).await?;
            total += files.len();
            if total > MAX_POLICY_REPLAY_FILES {
                return Err(FsError::Internal(
                    "replay needs full recalc (policy fan-out too large)".into(),
                ));
            }
            for file_id in files {
                self.resync_file(sub, dst, &row_type, &row_id, &file_id)
                    .await?;
            }
        }
        Ok(())
    }

    /// Resyncs rows a deleted group could have exposed.
    ///
    /// Past membership is unknowable (links are already gone), so any group
    /// holding row `read` rules resyncs its rows: [`Self::resync_file`]
    /// re-checks current visibility, making over-application safe (files
    /// still visible via other rows stay, others converge to deleted).
    /// Groups with no row reads skip; oversized fan-out falls back via `Err`.
    async fn apply_group_delete(
        &self,
        sub: &str,
        dst: &FsStore,
        group: &str,
    ) -> Result<(), FsError> {
        let rows = self.read_rows_for_group(group).await?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut total = 0usize;
        for (row_type, row_id) in rows {
            let files = self.store.files_for_row(&row_type, &row_id).await?;
            total += files.len();
            if total > MAX_POLICY_REPLAY_FILES {
                return Err(FsError::Internal(
                    "replay needs full recalc (policy fan-out too large)".into(),
                ));
            }
            for file_id in files {
                self.resync_file(sub, dst, &row_type, &row_id, &file_id)
                    .await?;
            }
        }
        Ok(())
    }

    /// Converges one file on the replica after a policy change.
    ///
    /// Readable files are ensured present with the changed row attached
    /// (or detached when that row alone turned unreadable); files readable
    /// via no row are deleted. Missing master records delete the stale
    /// replica copy.
    async fn resync_file(
        &self,
        sub: &str,
        dst: &FsStore,
        row_type: &str,
        row_id: &str,
        file_id: &str,
    ) -> Result<(), FsError> {
        let Some(rec) = self.store.get_file(file_id).await? else {
            dst.delete_file(file_id).await?;
            return Ok(());
        };
        if !self.can_read(sub, file_id).await? {
            dst.delete_file(file_id).await?;
            return Ok(());
        }
        dst.save_file(&rec).await?;
        if self
            .policy
            .authorize_row(sub, row_type, row_id, Action::Read)
            .await
            .unwrap_or(false)
        {
            dst.attach(row_type, row_id, file_id).await?;
        } else {
            dst.detach(row_type, row_id, file_id).await?;
        }
        Ok(())
    }

    /// Row `(type, id)` pairs `group` currently grants `read` on.
    async fn read_rows_for_group(&self, group: &str) -> Result<Vec<(String, String)>, FsError> {
        let mut out = Vec::new();
        for (obj, act) in self.policy.rules_for_subject(group).await {
            if !act.eq_ignore_ascii_case("read") {
                continue;
            }
            if let Some((ty, rid)) = split_row_obj(&obj) {
                out.push((ty.to_string(), rid.to_string()));
            }
        }
        Ok(out)
    }

    async fn copy_filtered(&self, sub: &str, dst: &FsStore) -> Result<(), FsError> {
        // Single pass over the master listing: the record in hand answers
        // the owner check (no re-read), and one rows scan serves both the
        // visibility check and the attach loop. Previously each file cost
        // a re-read plus two full-store scans (one inside can_read, one
        // for attach) on top of the listing itself.
        for rec in self.store.list_files().await? {
            let rows = self.visible_rows(sub, &rec.id).await?;
            if rec.owner_sub != sub && rows.is_empty() {
                continue;
            }
            dst.save_file(&rec).await?;
            if self.store.get_ref_info(&rec.id).await?.count > 0 {
                for (ty, rid) in &rows {
                    dst.attach(ty, rid, &rec.id).await?;
                }
            }
        }
        Ok(())
    }

    /// Rows of `file_id` that `sub` may read (each authorized individually).

    async fn visible_rows(
        &self,
        sub: &str,
        file_id: &str,
    ) -> Result<Vec<(String, String)>, FsError> {
        let mut out = Vec::new();
        for (ty, rid) in self.store.rows_for_file(file_id).await? {
            if self
                .policy
                .authorize_row(sub, &ty, &rid, Action::Read)
                .await
                .unwrap_or(false)
            {
                out.push((ty, rid));
            }
        }
        Ok(out)
    }

    async fn can_read(&self, sub: &str, file_id: &str) -> Result<bool, FsError> {
        let Some(rec) = self.store.get_file(file_id).await? else {
            return Ok(false);
        };
        Ok(rec.owner_sub == sub || !self.visible_rows(sub, file_id).await?.is_empty())
    }
}

/// Maps oxkv errors into [`FsError`].
fn store_err(e: oxkv::StoreError) -> FsError {
    FsError::Store(e.to_string())
}

/// Splits a rule object into `(row_type, row_id)` when it names a row.
///
/// Row objects are `{type}:{id}`; control-plane objects (`rules`,
/// `user_groups`, …) contain no colon and return `None` so policy replay
/// can skip them without touching storage.
fn split_row_obj(obj: &str) -> Option<(&str, &str)> {
    let (ty, rid) = obj.split_once(':')?;
    if ty.is_empty() || rid.is_empty() {
        return None;
    }
    Some((ty, rid))
}

/// Maps a subject to a prefix-safe identifier.
///
/// Subjects are attacker-influenced (OIDC `sub`), so a lossy replace is
/// not enough: `a/b`, `a:b`, and `a_b` would all collide on one replica
/// prefix and leak data across users. The SHA-256 hex digest is
/// collision-resistant, fixed-length, and prefix-safe by construction
/// (lowercase hex only, no separators or traversal sequences).
fn safe_sub(sub: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(sub.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fs::store::FileRecord;
    use object_store::memory::InMemory;

    async fn test_manager() -> (SnapshotManager, std::sync::Arc<InMemory>) {
        let mem = std::sync::Arc::new(InMemory::new());
        let wal = Wal::new(crate::db::build_test_store("snap-test-wal").await);
        let store = FsStore::new(crate::db::build_test_store("snap-test-store").await);
        let policy = PolicyEngine::init_s3(crate::db::build_test_store("snap-test-policy").await)
            .await
            .unwrap();
        let mgr = SnapshotManager::new(
            wal,
            store,
            policy,
            mem.clone() as std::sync::Arc<dyn object_store::ObjectStore>,
            "test-db".into(),
            true,
        );
        (mgr, mem)
    }

    fn file_record(id: &str, owner: &str) -> FileRecord {
        FileRecord {
            id: id.into(),
            name: format!("{id}.txt"),
            mimetype: "text/plain".into(),
            size: 1,
            s3_key: format!("k/{id}"),
            owner_sub: owner.into(),
            created_at: 0,
        }
    }

    async fn open_reader(mem: &std::sync::Arc<InMemory>, prefix: &str) -> OxKvReader {
        let base: std::sync::Arc<dyn object_store::ObjectStore> = mem.clone();
        let storage: std::sync::Arc<dyn oxkv::Storage> = std::sync::Arc::new(base);
        OxKvReader::open(storage, oxkv::ObjectPath::from(prefix))
            .await
            .unwrap()
    }

    async fn replica_has(
        mem: &std::sync::Arc<InMemory>,
        mgr: &SnapshotManager,
        sub: &str,
        key: &str,
    ) -> bool {
        let reader = open_reader(mem, &mgr.user_prefix(sub)).await;
        let tx = reader.begin_tx().unwrap();
        let out = tx.get_bytes(key).await.unwrap().is_some();
        tx.rollback().await.unwrap();
        out
    }

    #[tokio::test]
    async fn build_full_filters_into_live_prefix() -> anyhow::Result<()> {
        let (mgr, mem) = test_manager().await;
        mgr.policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        let rec = file_record("f1", "alice");
        mgr.store.save_file(&rec).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.store.save_file(&file_record("f2", "bob")).await?;

        assert_eq!(mgr.build_full("alice").await?, 0);
        assert_eq!(mgr.load_applied("alice").await?, Some(0));

        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await);
        assert!(replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);
        Ok(())
    }

    #[tokio::test]
    async fn build_full_with_mirrored_master() -> anyhow::Result<()> {
        let (mut mgr, mem) = test_manager().await;
        mgr.policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        let rec = file_record("f1", "alice");
        mgr.store.save_file(&rec).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.store.save_file(&file_record("f2", "bob")).await?;
        mgr.store = mgr.store.mirrored_clone().await?;

        assert_eq!(mgr.build_full("alice").await?, 0);
        assert_eq!(mgr.load_applied("alice").await?, Some(0));

        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await);
        assert!(replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);
        Ok(())
    }

    #[tokio::test]
    async fn build_is_idempotent_without_new_manifest_cas() -> anyhow::Result<()> {
        use object_store::ObjectStore as _;

        let (mgr, mem) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;

        let manifest =
            object_store::path::Path::from(format!("{}/manifest.json", mgr.user_prefix("alice")));
        let etag_before = mem.get(&manifest).await?.meta.e_tag.unwrap();
        mgr.build_full("alice").await?;
        let etag_after = mem.get(&manifest).await?.meta.e_tag.unwrap();
        assert_eq!(etag_before, etag_after);
        Ok(())
    }

    #[tokio::test]
    async fn fresh_prefix_has_no_coverage() -> anyhow::Result<()> {
        let (mgr, _) = test_manager().await;
        assert_eq!(mgr.load_applied("alice").await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn replay_applies_file_delta() -> anyhow::Result<()> {
        let (mgr, mem) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;

        // Simulate the logged write path: master mutation + WAL entry.
        let f2 = file_record("f2", "alice");
        mgr.store.save_file(&f2).await?;
        mgr.wal.append(WalOp::FileCreate { rec: f2 }).await?;

        assert_eq!(mgr.replay(1, "alice").await?, 1);
        assert_eq!(mgr.load_applied("alice").await?, Some(1));
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await);
        Ok(())
    }

    #[tokio::test]
    async fn replay_detach_and_delete_converge() -> anyhow::Result<()> {
        let (mgr, mem) = test_manager().await;
        mgr.policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.build_full("alice").await?;
        assert!(replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);

        // Detach then delete on master, each logged like the engines do.
        mgr.store.detach("invoice", "1", "f1").await?;
        mgr.wal
            .append(WalOp::Detach {
                row_type: "invoice".into(),
                row_id: "1".into(),
                file_id: "f1".into(),
            })
            .await?;
        mgr.store.delete_file("f1").await?;
        mgr.wal
            .append(WalOp::FileDelete {
                file_id: "f1".into(),
            })
            .await?;

        assert_eq!(mgr.replay(2, "alice").await?, 2);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        Ok(())
    }

    #[tokio::test]
    async fn replay_bails_on_legacy_policy_marks() -> anyhow::Result<()> {
        let (mgr, _) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;
        mgr.wal
            .append(WalOp::PolicyAdd {
                obj: "invoice:1".into(),
            })
            .await?;
        assert!(mgr.replay(1, "alice").await.is_err());
        assert_eq!(mgr.load_applied("alice").await?, Some(0));
        Ok(())
    }

    #[tokio::test]
    async fn replay_skips_irrelevant_policy_ops() -> anyhow::Result<()> {
        let (mgr, mem) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;
        // Other user's membership, non-row object, and non-read action:
        // none can affect alice's read replica.
        mgr.wal
            .append(WalOp::GroupAdd {
                user: "bob".into(),
                group: "editors".into(),
            })
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleAdd {
                sub: "editors".into(),
                obj: "rules".into(),
                act: "read".into(),
            })
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleAdd {
                sub: "editors".into(),
                obj: "invoice:9".into(),
                act: "write".into(),
            })
            .await?;
        assert_eq!(mgr.replay(3, "alice").await?, 3);
        assert_eq!(mgr.load_applied("alice").await?, Some(3));
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        Ok(())
    }

    #[tokio::test]
    async fn replay_applies_rule_grant_then_revoke() -> anyhow::Result<()> {
        let (mgr, mem) = test_manager().await;
        // Bob's file on invoice:1; alice sees nothing yet.
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.build_full("alice").await?;
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);

        // Grant editors read on the row, add alice to editors (master
        // mutation first, WAL entries like the engines append).
        mgr.policy
            .add_rule("editors".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.policy
            .assign_group("alice".into(), "editors".into())
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleAdd {
                sub: "editors".into(),
                obj: "invoice:1".into(),
                act: "read".into(),
            })
            .await?;
        mgr.wal
            .append(WalOp::GroupAdd {
                user: "alice".into(),
                group: "editors".into(),
            })
            .await?;
        assert_eq!(mgr.replay(2, "alice").await?, 2);
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);

        // Revoke the rule: the file must leave the replica.
        mgr.policy
            .remove_rule("editors".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleRemove {
                sub: "editors".into(),
                obj: "invoice:1".into(),
                act: "read".into(),
            })
            .await?;
        assert_eq!(mgr.replay(3, "alice").await?, 3);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);
        Ok(())
    }

    #[tokio::test]
    async fn replay_group_remove_converges() -> anyhow::Result<()> {
        let (mgr, mem) = test_manager().await;
        mgr.policy
            .add_rule("editors".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.policy
            .assign_group("alice".into(), "editors".into())
            .await?;
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.build_full("alice").await?;
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);

        mgr.policy
            .remove_from_group("alice".into(), "editors".into())
            .await?;
        mgr.wal
            .append(WalOp::GroupRemove {
                user: "alice".into(),
                group: "editors".into(),
            })
            .await?;
        assert_eq!(mgr.replay(1, "alice").await?, 1);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        Ok(())
    }

    #[test]
    fn split_row_obj_rejects_control_plane_objects() {
        assert_eq!(split_row_obj("invoice:123"), Some(("invoice", "123")));
        assert_eq!(split_row_obj("rules"), None);
        assert_eq!(split_row_obj("user_groups"), None);
        assert_eq!(split_row_obj(":123"), None);
        assert_eq!(split_row_obj("invoice:"), None);
    }

    #[tokio::test]
    async fn prefixes_are_stable_and_safe() {
        let (mgr, _) = test_manager().await;
        // Stable and hex-only (prefix-safe by construction).
        let prefix = mgr.user_prefix("alice");
        assert_eq!(prefix, mgr.user_prefix("alice"));
        let digest = prefix.strip_prefix("test-db/u/").expect("prefix shape");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        // Former collisions now isolate: each maps to its own prefix.
        assert_ne!(mgr.user_prefix("a/b"), mgr.user_prefix("a:b"));
        assert_ne!(mgr.user_prefix("a/b"), mgr.user_prefix("a_b"));
        assert_ne!(mgr.user_prefix("alice"), mgr.user_prefix("bob"));
        // Gateway still confines reads to the replica prefix.
        assert!(mgr.resolve_object("alice", "../escape").is_err());
        assert!(mgr.resolve_object("alice", "a/../../escape").is_err());
        assert!(mgr.resolve_object("alice", "").is_err());
    }
}
