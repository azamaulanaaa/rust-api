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
//! re-apply (sentinel written last); policy changes and large ranges fall
//! back to full recalc. Served read-only via `/sync/db/`; wasm clients open
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
        }
    }

    /// Replica prefix for `sub` (`{db}/u/{sub}`).
    pub fn user_prefix(&self, sub: &str) -> String {
        format!(
            "{}/u/{}",
            self.db_prefix.trim_matches('/'),
            safe_sub(sub)
        )
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
        let out = match tx
            .get_bytes(APPLIED_KEY)
            .await
            .map_err(store_err)?
        {
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

        let snap_prefix = format!(
            "snap-{}-{head}-{}",
            safe_sub(sub),
            &uuid::Uuid::now_v7().to_string()[..8]
        );
        let scratch = FsStore::new(crate::db::build_scratch_store(&snap_prefix).await);
        self.copy_filtered(sub, &scratch).await?;
        let mut new_map: HashMap<String, Vec<u8>> =
            scratch.dump_kvs().await?.into_iter().collect();
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
    /// crash between ops heals on the next poll. Policy ops change
    /// visibility wholesale — any in range (or a range over 1000 entries)
    /// falls back to a full recalc via `Err`.
    pub async fn replay(&self, head: u64, sub: &str) -> Result<u64, FsError> {
        let _guard = self.build_lock.lock().await;
        let Some(applied) = self.load_applied(sub).await? else {
            return Err(FsError::Internal("no base replica for replay".into()));
        };
        if applied >= head {
            return Ok(applied);
        }
        let entries = self.wal.range(applied + 1, head).await?;
        if entries.len() > 1000
            || entries.iter().any(|e| {
                matches!(
                    e.op,
                    WalOp::PolicyAdd { .. } | WalOp::PolicyRemove { .. }
                )
            })
        {
            return Err(FsError::Internal(
                "replay needs full recalc (policy change or range too large)".into(),
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
            .build()
            .await
            .map_err(|e| FsError::Store(e.to_string()))
    }

    /// Opens a read-only follower over the replica (no ownership taken).
    async fn open_reader(&self, sub: &str) -> Result<OxKvReader, FsError> {
        let base: std::sync::Arc<dyn object_store::ObjectStore> =
            self.object_store.clone();
        let storage: std::sync::Arc<dyn oxkv::Storage> = std::sync::Arc::new(base);
        OxKvReader::open(
            storage,
            oxkv::ObjectPath::from(self.user_prefix(sub).as_str()),
        )
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
                    "policy op reached apply (should have bailed earlier)".into(),
                ));
            }
        }
        Ok(())
    }

    async fn copy_filtered(&self, sub: &str, dst: &FsStore) -> Result<(), FsError> {
        for rec in self.store.list_files().await? {
            if !self.can_read(sub, &rec.id).await? {
                continue;
            }
            dst.save_file(&rec).await?;
            let info = self.store.get_ref_info(&rec.id).await?;
            if info.count > 0 {
                // copy relations where row readable
                for (ty, rid) in self.store.rows_for_file(&rec.id).await? {
                    if self
                        .policy
                        .authorize_row(sub, &ty, &rid, Action::Read)
                        .await
                        .unwrap_or(false)
                    {
                        dst.attach(&ty, &rid, &rec.id).await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn can_read(&self, sub: &str, file_id: &str) -> Result<bool, FsError> {
        let Some(rec) = self.store.get_file(file_id).await? else {
            return Ok(false);
        };
        if rec.owner_sub == sub {
            return Ok(true);
        }
        for (ty, rid) in self.store.rows_for_file(file_id).await? {
            if self
                .policy
                .authorize_row(sub, &ty, &rid, Action::Read)
                .await
                .unwrap_or(false)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Maps oxkv errors into [`FsError`].
fn store_err(e: oxkv::StoreError) -> FsError {
    FsError::Store(e.to_string())
}

/// Makes a subject safe for embedding in an object prefix.
fn safe_sub(sub: &str) -> String {
    sub.replace(['/', ':'], "_")
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
    async fn replay_bails_on_policy_ops() -> anyhow::Result<()> {
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
    async fn prefixes_are_stable_and_safe() {
        let (mgr, _) = test_manager().await;
        assert_eq!(mgr.user_prefix("alice"), "test-db/u/alice");
        assert_eq!(
            mgr.resolve_object("a/b:c", "manifest.json").unwrap(),
            "test-db/u/a_b_c/manifest.json"
        );
        assert!(mgr.resolve_object("alice", "../escape").is_err());
        assert!(mgr.resolve_object("alice", "a/../../escape").is_err());
        assert!(mgr.resolve_object("alice", "").is_err());
    }
}
