//! `oxkv` persistence for upload sessions, file records, and relations.
//! Backed by [`oxkv::OxKvStore`] (LSM on S3). Keys: `fs:uploads:{id}:meta`, `fs:files:{id}:meta`, `fs:rel:{type}:{id}:{file}`, `fs:files:{id}:refs`.
//! Scales per-user: each OxKvStore is prefix-scoped (e.g. `oxkv/fs`) on the shared `ObjectStore`.

use std::sync::Arc;

use oxkv::{
    CachedOxKvStore, Direction, GetSet, KeyValue, OxKvStore, Store as _, Transaction as _, WarmMode,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::fencing::Latch;
use crate::fs::error::FsError;
use crate::fs::relation::{REL_PREFIX, RefInfo, refs_key, rel_key};

/// Key prefix under which finalized file records live.
const FILES_PREFIX: &str = "fs:files:";

/// Suffix marking the metadata half of a file record's key.
const FILE_META_SUFFIX: &str = ":meta";

/// In-flight multipart session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSession {
    /// File identifier (uuidv7).
    pub id: String,
    /// Total file size.
    pub file_size: u64,
    /// Part size.
    pub part_size: u64,
    /// Total parts declared at init.
    pub file_total_parts: u64,
    /// S3 multipart upload id (None for single-part PutObject).
    pub s3_upload_id: Option<String>,
    /// S3 object key.
    pub s3_key: String,
    /// Owner subject (`sub`).
    pub owner_sub: String,
    /// Creation timestamp (unix secs).
    pub created_at: i64,
    /// Per-part ETags (None = not yet uploaded).
    pub etags: Vec<Option<String>>,
    /// Per-part SHA256 checksums (base64, None = not provided).
    #[serde(default)]
    pub checksums: Vec<Option<String>>,
}

impl UploadSession {
    /// True when the session is older than `ttl_secs` at `now`.
    ///
    /// Takes the TTL as an argument so the retention policy stays with the
    /// sweeper ([`crate::fs::gc::TTL_SECS`]) rather than being baked into
    /// the record type.
    pub fn is_expired(&self, now: i64, ttl_secs: i64) -> bool {
        now - self.created_at > ttl_secs
    }
}

/// Durable S3-side multipart state: mirrors the client RAM map so
/// uploads survive restarts. The object-store `MultipartId` is a plain
/// string and staged `PartId`s rebuild from their content ids, so a
/// fresh client rehydrates purely from this record (see
/// `S3Client::restore_multipart`). Records live and die with their
/// session: created at init, updated per part, deleted on
/// complete/cancel/expiry via `delete_session` cascade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedMultipart {
    /// Engine-side alias (`ostore-…`, what sessions reference).
    pub upload_id: String,
    /// Bucket the S3 multipart targets.
    pub bucket: String,
    /// Key the S3 multipart targets.
    pub key: String,
    /// Backend upload id (real S3 `UploadId`).
    pub s3_upload_id: String,
    /// Part index (0-based) → staged content id.
    #[serde(default)]
    pub parts: std::collections::BTreeMap<usize, String>,
    /// Creation timestamp (unix secs) for age tracking.
    pub created_at: i64,
}

/// Persisted file record after `CompleteUpload`.
///
/// Re-exported from [`crate::records`], where it lives because
/// [`WalOp::FileCreate`](crate::records::WalOp::FileCreate) carries one and
/// `sync` has to read it without importing the whole `fs` module.
pub use crate::records::FileRecord;

/// What a metadata scan read, and what it could not read.
///
/// `fs:files:`/`fs:uploads:` is the only map from S3 bytes back to the rows
/// that reference them, so a row that fails to decode is not a harmless gap.
/// Any caller that reads "no record mentions this key" as "these bytes are
/// garbage" will delete the object of a record it merely could not parse,
/// and nothing else in the store can repair that: the metadata row survives
/// and every download 404s forever.
///
/// So the unread keys are carried out of the scan instead of being dropped
/// inside it. A caller that deletes based on absence can then refuse to act
/// while the set is non-empty.
#[derive(Debug, Clone)]
pub struct RecordScan<T> {
    /// Every record in the key family that decoded, in scan order.
    pub records: Vec<T>,
    /// Keys in the family whose value did not decode, in scan order.
    ///
    /// Already logged at `warn!`; kept here so a sweeper can act on the
    /// fact that the scan was incomplete.
    pub undecodable: Vec<String>,
}

/// Thin wrapper around an `oxkv` LSM store for FS keys.
#[derive(Clone)]
pub struct FsStore {
    inner: Arc<RwLock<OxKvStore>>,
    /// Lazily-warmed RAM mirror over the same handle (prototype).
    ///
    /// Reads route through the mirror when present; writes always go to
    /// `inner`. The mirror never takes an epoch (it wraps a clone that
    /// shares the session), so it cannot fence the writer.
    mirror: Option<CachedOxKvStore>,
    /// True when this store is the master `{db}/fs` prefix.
    ///
    /// Decides whether a lost epoch latches the process-wide fencing signal.
    /// The same `FsStore` type also backs per-user *replica* prefixes during
    /// a sync build, where losing a race is routine and resolved by adopting
    /// the winner's coverage -- so latching there would take a healthy server
    /// out of rotation over a non-event. Marking it explicitly at the one
    /// place that owns the master store ([`FsEngine::init`](crate::fs::FsEngine::init))
    /// keeps the distinction with the ownership rather than inferred from a
    /// key prefix.
    primary: bool,
    /// Where this store's fencing losses are recorded.
    ///
    /// The process-wide latch in production (see
    /// [`process_latch`](crate::fencing::process_latch)); a store's own in
    /// tests. Held as a field rather than reached for through
    /// [`note_primary_loss`](crate::fencing::note_primary_loss) because the
    /// process-wide latch is one-way and global: a test that tripped it
    /// could not tell its own write from any other test's.
    latch: &'static Latch,
}

impl FsStore {
    /// The master `{db}/fs` prefix, named in the fencing-loss log line.
    const FS_PREFIX: &str = "{db}/fs";

    /// Whether a failure on this store should latch the process-wide
    /// fencing signal.
    ///
    /// The rule is: only the master prefix, and only a lost epoch. Both
    /// halves are load-bearing and neither is obvious from the call site, so
    /// they live in one predicate.
    fn latches(&self, err: &FsError) -> bool {
        // A replica write that loses a build race is recovered from by
        // `sync` (adopting the winner's coverage), and latching it would
        // take a healthy server out of rotation over a non-event.
        self.primary && err.is_fencing_loss()
    }

    /// Maps oxkv errors into [`FsError`], latching a fencing loss when this
    /// store owns the master prefix.
    ///
    /// Latching here rather than in [`FsError`]'s own conversion is the whole
    /// point. The same `FsError` carries replica-write failures, and `sync`
    /// recovers from those by design. A mark on the one store that owns the
    /// primary prefix keeps the distinction with the ownership rather than
    /// inferred from a key prefix.
    fn store_err(&self, e: oxkv::StoreError) -> FsError {
        let err = FsError::from(e);
        if self.latches(&err) {
            self.latch.trip(Self::FS_PREFIX, err.detail());
        }
        err
    }

    /// Creates an FS store from an [`OxKvStore`] (per-user S3, scalable).
    ///
    /// Not the master store: see [`FsStore::primary`].
    pub fn new(s3_store: OxKvStore) -> Self {
        Self {
            inner: Arc::new(RwLock::new(s3_store)),
            mirror: None,
            primary: false,
            latch: crate::fencing::process_latch(),
        }
    }

    /// Creates the master `{db}/fs` store, whose fencing losses are terminal
    /// for this process.
    pub fn primary(s3_store: OxKvStore) -> Self {
        Self {
            primary: true,
            ..Self::new(s3_store)
        }
    }

    /// The master store, recording fencing losses on `latch` instead of the
    /// process-wide one.
    ///
    /// The latch is a one-way flag with no reset, so a test that wants to
    /// prove a write *trips* it cannot share the process-wide one: anything
    /// another test tripped first would satisfy the assertion whether or not
    /// the code under test latched at all.
    #[cfg(test)]
    pub(crate) fn primary_with_latch(s3_store: OxKvStore, latch: &'static Latch) -> Self {
        Self {
            primary: true,
            latch,
            ..Self::new(s3_store)
        }
    }

    /// Creates an FS store with a lazily-warmed RAM mirror (prototype).
    ///
    /// The mirror wraps a clone of `s3_store` (shared session/state, no
    /// new epoch), warms key-by-key on read misses, and stays correct on
    /// misses by falling through to the durable core. Call
    /// [`refresh_mirror`](Self::refresh_mirror) before bulk scans so one
    /// incremental WAL replay converges it instead of per-key misses.
    /// Measure with `RUST_LOG=debug` (refresh counts are logged).
    pub async fn new_mirrored(s3_store: OxKvStore) -> Result<Self, FsError> {
        let mirror = CachedOxKvStore::open_with_mode(s3_store.clone(), WarmMode::Lazy)
            .await
            .map_err(FsError::from)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(s3_store)),
            mirror: Some(mirror),
            primary: false,
            latch: crate::fencing::process_latch(),
        })
    }

    /// Test-only: mirror over a clone of this handle (shares session).
    #[cfg(test)]
    pub(crate) async fn mirrored_clone(&self) -> Result<Self, FsError> {
        Self::new_mirrored(self.inner.read().await.clone()).await
    }

    /// Converges the mirror with master writes since the last call.
    ///
    /// No-op without a mirror. Returns replayed entries: 0 means already
    /// converged (no I/O beyond the manifest check); a full re-warm only
    /// happens on epoch/SST-set change, never on steady writes.
    pub async fn refresh_mirror(&self) -> Result<usize, FsError> {
        let Some(mirror) = &self.mirror else {
            return Ok(0);
        };
        let applied = mirror.refresh().await.map_err(FsError::from)?;
        tracing::debug!(applied, "fs mirror refreshed");
        Ok(applied)
    }

    /// Point read through the single shared handle (mirror first).
    async fn get_one(&self, key: &str) -> Result<Option<Vec<u8>>, FsError> {
        if let Some(mirror) = &self.mirror {
            return mirror.get_bytes(key).await.map_err(FsError::from);
        }
        let g = self.inner.read().await;
        g.get_bytes(key).await.map_err(FsError::from)
    }

    /// Range scan bounded to keys under `prefix:`.
    ///
    /// Full-store scans (`(None, None)` cursors) materialize every key;
    /// bounding to the key-space prefix keeps each scan proportional to
    /// its own key family instead of the whole store.
    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<KeyValue>, FsError> {
        let cursor = (Some(prefix.to_string()), Some(prefix_scan_end(prefix)));
        if let Some(mirror) = &self.mirror {
            return mirror
                .gets_bytes(None, Direction::Next, cursor)
                .await
                .map_err(FsError::from);
        }
        let g = self.inner.read().await;
        g.gets_bytes(None, Direction::Next, cursor)
            .await
            .map_err(FsError::from)
    }

    fn session_key(id: &str) -> String {
        format!("fs:uploads:{id}:meta")
    }
    fn staged_key(id: &str, idx: u64) -> String {
        format!("fs:uploads:{id}:part:{idx}")
    }
    fn multipart_key(upload_id: &str) -> String {
        format!("fs:mp:{upload_id}")
    }
    fn file_key(id: &str) -> String {
        format!("{FILES_PREFIX}{id}{FILE_META_SUFFIX}")
    }

    /// Persists an upload session.
    pub async fn save_session(&self, s: &UploadSession) -> Result<(), FsError> {
        let key = Self::session_key(&s.id);
        let val = serde_json::to_vec(s).map_err(|e| FsError::Internal(e.to_string()))?;
        let g = self.inner.write().await;
        g.set_bytes(&key, &val)
            .await
            .map_err(|e| self.store_err(e))?;
        Ok(())
    }

    /// Loads an upload session by file id.
    pub async fn get_session(&self, id: &str) -> Result<Option<UploadSession>, FsError> {
        let key = Self::session_key(id);
        let Some(bytes) = self.get_one(&key).await? else {
            return Ok(None);
        };
        let s = serde_json::from_slice(&bytes).map_err(|e| FsError::Internal(e.to_string()))?;
        Ok(Some(s))
    }

    /// Deletes an upload session and any staged single-part chunks.
    pub async fn delete_session(&self, id: &str) -> Result<(), FsError> {
        let session = self.get_session(id).await?;
        let key = Self::session_key(id);
        {
            let g = self.inner.write().await;
            g.delete(&key).await.map_err(|e| self.store_err(e))?;
            if let Some(s) = session {
                for idx in 0..s.file_total_parts {
                    let k = Self::staged_key(id, idx);
                    let _ = g.delete(&k).await;
                }
                // Cascade: the multipart record lives and dies with its
                // session, so expiry/GC can never strand one.
                if let Some(upload_id) = s.s3_upload_id {
                    let _ = g.delete(&Self::multipart_key(&upload_id)).await;
                }
            }
        }
        Ok(())
    }

    /// Persists S3-side multipart state (created at init, updated per part).
    pub async fn save_multipart(&self, m: &PersistedMultipart) -> Result<(), FsError> {
        let key = Self::multipart_key(&m.upload_id);
        let val = serde_json::to_vec(m).map_err(|e| FsError::Internal(e.to_string()))?;
        let g = self.inner.write().await;
        g.set_bytes(&key, &val)
            .await
            .map_err(|e| self.store_err(e))?;
        Ok(())
    }

    /// Loads persisted multipart state by engine-side upload id.
    pub async fn load_multipart(
        &self,
        upload_id: &str,
    ) -> Result<Option<PersistedMultipart>, FsError> {
        let key = Self::multipart_key(upload_id);
        let Some(bytes) = self.get_one(&key).await? else {
            return Ok(None);
        };
        let m = serde_json::from_slice(&bytes).map_err(|e| FsError::Internal(e.to_string()))?;
        Ok(Some(m))
    }

    /// Deletes a persisted multipart record (complete/cancel path).
    pub async fn delete_multipart(&self, upload_id: &str) -> Result<(), FsError> {
        let key = Self::multipart_key(upload_id);
        let g = self.inner.write().await;
        g.delete(&key).await.map_err(|e| self.store_err(e))?;
        Ok(())
    }

    /// Stages a single-part chunk in the store (only for `total_parts == 1`).
    pub async fn save_staged_part(&self, id: &str, idx: u64, data: Vec<u8>) -> Result<(), FsError> {
        let key = Self::staged_key(id, idx);
        let g = self.inner.write().await;
        g.set_bytes(&key, &data)
            .await
            .map_err(|e| self.store_err(e))?;
        Ok(())
    }

    /// Loads a staged single-part chunk.
    pub async fn get_staged_part(&self, id: &str, idx: u64) -> Result<Option<Vec<u8>>, FsError> {
        let key = Self::staged_key(id, idx);
        self.get_one(&key).await
    }

    /// Persists a finalized file record.
    pub async fn save_file(&self, rec: &FileRecord) -> Result<(), FsError> {
        let key = Self::file_key(&rec.id);
        let val = serde_json::to_vec(rec).map_err(|e| FsError::Internal(e.to_string()))?;
        let g = self.inner.write().await;
        g.set_bytes(&key, &val)
            .await
            .map_err(|e| self.store_err(e))?;
        Ok(())
    }

    /// Loads a finalized file record.
    pub async fn get_file(&self, id: &str) -> Result<Option<FileRecord>, FsError> {
        let key = Self::file_key(id);
        let Some(bytes) = self.get_one(&key).await? else {
            return Ok(None);
        };
        let r = serde_json::from_slice(&bytes).map_err(|e| FsError::Internal(e.to_string()))?;
        Ok(Some(r))
    }

    /// Deletes a finalized file record, its ref-count entry, and every
    /// relation marker pointing at it, atomically. Markers left behind
    /// would otherwise accumulate as garbage once the record is gone.
    pub async fn delete_file(&self, id: &str) -> Result<(), FsError> {
        let key = Self::file_key(id);
        let refs = refs_key(id);
        let g = self.inner.write().await;
        let tx = g.begin_tx().map_err(|e| self.store_err(e))?;
        let suffix = format!(":{id}");
        let cursor = (
            Some(REL_PREFIX.to_string()),
            Some(prefix_scan_end(REL_PREFIX)),
        );
        let kvs = tx
            .gets_bytes(None, Direction::Next, cursor)
            .await
            .map_err(|e| self.store_err(e))?;
        for kv in &kvs {
            if kv.key.starts_with(REL_PREFIX) && kv.key.ends_with(&suffix) {
                tx.delete(&kv.key).await.map_err(|e| self.store_err(e))?;
            }
        }
        tx.delete(&key).await.map_err(|e| self.store_err(e))?;
        let _ = tx.delete(&refs).await;
        tx.commit().await.map_err(|e| self.store_err(e))?;
        Ok(())
    }

    /// Returns ref-count info for a file (0 if never attached).
    pub async fn get_ref_info(&self, file_id: &str) -> Result<RefInfo, FsError> {
        let key = refs_key(file_id);
        let Some(bytes) = self.get_one(&key).await? else {
            return Ok(RefInfo::default());
        };
        let info = serde_json::from_slice(&bytes).map_err(|e| FsError::Internal(e.to_string()))?;
        Ok(info)
    }

    /// Attaches a file to a row; idempotent.
    ///
    /// The relation marker and the ref-count update commit in one
    /// transaction: a crash can never leave one without the other.
    pub async fn attach(
        &self,
        row_type: &str,
        row_id: &str,
        file_id: &str,
    ) -> Result<u32, FsError> {
        let rel = rel_key(row_type, row_id, file_id);
        let refs = refs_key(file_id);
        let g = self.inner.write().await;
        let tx = g.begin_tx().map_err(|e| self.store_err(e))?;
        if tx
            .get_bytes(&rel)
            .await
            .map_err(|e| self.store_err(e))?
            .is_some()
        {
            let info = read_ref_info(&tx, file_id, self.latch, self.primary).await?;
            tx.rollback().await.map_err(|e| self.store_err(e))?;
            return Ok(info.count);
        }
        let mut info = read_ref_info(&tx, file_id, self.latch, self.primary).await?;
        info.count = info.count.saturating_add(1);
        info.orphan_since = None;
        tx.set_bytes(&rel, b"1")
            .await
            .map_err(|e| self.store_err(e))?;
        let val = serde_json::to_vec(&info).map_err(|e| FsError::Internal(e.to_string()))?;
        tx.set_bytes(&refs, &val)
            .await
            .map_err(|e| self.store_err(e))?;
        tx.commit().await.map_err(|e| self.store_err(e))?;
        Ok(info.count)
    }

    /// Detaches a file from a row; idempotent.
    ///
    /// Same atomicity contract as [`FsStore::attach`].
    pub async fn detach(
        &self,
        row_type: &str,
        row_id: &str,
        file_id: &str,
    ) -> Result<u32, FsError> {
        let rel = rel_key(row_type, row_id, file_id);
        let refs = refs_key(file_id);
        let g = self.inner.write().await;
        let tx = g.begin_tx().map_err(|e| self.store_err(e))?;
        if tx
            .get_bytes(&rel)
            .await
            .map_err(|e| self.store_err(e))?
            .is_none()
        {
            let info = read_ref_info(&tx, file_id, self.latch, self.primary).await?;
            tx.rollback().await.map_err(|e| self.store_err(e))?;
            return Ok(info.count);
        }
        let mut info = read_ref_info(&tx, file_id, self.latch, self.primary).await?;
        tx.delete(&rel).await.map_err(|e| self.store_err(e))?;
        info.count = info.count.saturating_sub(1);
        if info.count == 0 {
            info.orphan_since = Some(chrono::Utc::now().timestamp());
        }
        let val = serde_json::to_vec(&info).map_err(|e| FsError::Internal(e.to_string()))?;
        tx.set_bytes(&refs, &val)
            .await
            .map_err(|e| self.store_err(e))?;
        tx.commit().await.map_err(|e| self.store_err(e))?;
        Ok(info.count)
    }

    /// Lists rows referencing a file (scan bounded to `fs:rel:`).
    pub async fn rows_for_file(&self, file_id: &str) -> Result<Vec<(String, String)>, FsError> {
        let suffix = format!(":{file_id}");
        let kvs = self.scan_prefix(REL_PREFIX).await?;
        let mut out = Vec::new();
        for kv in kvs {
            if kv.key.starts_with(REL_PREFIX) && kv.key.ends_with(&suffix) {
                let rest = &kv.key[REL_PREFIX.len()..];
                if let Some((ty, rem)) = rest.split_once(':')
                    && let Some((rid, _)) = rem.split_once(':')
                {
                    out.push((ty.to_string(), rid.to_string()));
                }
            }
        }
        Ok(out)
    }

    /// Lists files attached to one row via a bounded `fs:rel:{type}:{id}:` scan.
    ///
    /// Used by incremental policy replay to resync only the row a rule
    /// changed, instead of scanning the whole store for a full rebuild.
    pub async fn files_for_row(
        &self,
        row_type: &str,
        row_id: &str,
    ) -> Result<Vec<String>, FsError> {
        let prefix = crate::fs::relation::rel_prefix_for_row(row_type, row_id);
        let kvs = self.scan_prefix(&prefix).await?;
        let mut out = Vec::new();
        for kv in kvs {
            if let Some(file_id) = kv.key.strip_prefix(&prefix)
                && !file_id.is_empty()
                && !file_id.contains(':')
            {
                out.push(file_id.to_string());
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Lists all finalized file records (scan bounded to `fs:files:`).
    ///
    /// A row that will not decode is skipped rather than fatal: one bad
    /// record must not stop a rebuild for every other file the user can
    /// see. It is *reported* rather than dropped, because the skip is
    /// invisible everywhere else -- a record missing from this list looks
    /// exactly like a record that was never written, and the orphan-byte
    /// sweeper deletes objects on precisely that inference.
    pub async fn list_files(&self) -> Result<RecordScan<FileRecord>, FsError> {
        let kvs = self.scan_prefix(FILES_PREFIX).await?;
        let mut out = RecordScan {
            records: Vec::new(),
            undecodable: Vec::new(),
        };
        for kv in kvs {
            if !kv.key.starts_with(FILES_PREFIX) || !kv.key.ends_with(FILE_META_SUFFIX) {
                continue;
            }
            match serde_json::from_slice::<FileRecord>(&kv.value) {
                Ok(r) => out.records.push(r),
                Err(e) => {
                    tracing::warn!(key = %kv.key, error = %e, "fs file metadata did not decode");
                    out.undecodable.push(kv.key);
                }
            }
        }
        Ok(out)
    }

    /// Lists all upload sessions (scan bounded to `fs:uploads:`).
    ///
    /// Skips and reports undecodable rows under the same contract as
    /// [`FsStore::list_files`]: a session that cannot be listed is a
    /// session the sweeper will never expire.
    pub async fn list_sessions(&self) -> Result<RecordScan<UploadSession>, FsError> {
        let kvs = self.scan_prefix("fs:uploads:").await?;
        let mut out = RecordScan {
            records: Vec::new(),
            undecodable: Vec::new(),
        };
        for kv in kvs {
            if !kv.key.starts_with("fs:uploads:") || !kv.key.ends_with(":meta") {
                continue;
            }
            match serde_json::from_slice::<UploadSession>(&kv.value) {
                Ok(s) => out.records.push(s),
                Err(e) => {
                    tracing::warn!(key = %kv.key, error = %e, "fs upload session did not decode");
                    out.undecodable.push(kv.key);
                }
            }
        }
        Ok(out)
    }

    /// Dumps every raw key-value pair for verbatim replica copies.
    ///
    /// The caller owns filtering: everything present is returned as-is.
    /// The next finalized file record in key order, or `None` at the end of
    /// `fs:files:`.
    ///
    /// Takes the walk rather than creating one so a caller can page through
    /// the whole keyspace while holding at most [`SCAN_PAGE`] records -- the
    /// replica rebuild filters records one at a time and keeps none of them.
    /// The prefix stays private here so the key layout has one owner.
    pub(crate) async fn next_file(
        &self,
        scan: &mut KvPages,
    ) -> Result<Option<FileRecord>, FsError> {
        while let Some(kv) = scan.next().await? {
            if !kv.key.starts_with(FILES_PREFIX) || !kv.key.ends_with(FILE_META_SUFFIX) {
                continue;
            }
            // A record that will not decode is skipped rather than fatal, the
            // same as `list_files`: one bad row must not stop a rebuild for
            // every other file the user can see. Logged for the same reason --
            // a skipped record is missing from the replica that this walk
            // builds, and nothing downstream can tell that from one that was
            // never written.
            match serde_json::from_slice::<FileRecord>(&kv.value) {
                Ok(rec) => return Ok(Some(rec)),
                Err(e) => tracing::warn!(
                    key = %kv.key,
                    error = %e,
                    "fs file metadata did not decode"
                ),
            }
        }
        Ok(None)
    }

    /// The underlying handle, for a paged scan of the whole keyspace.
    ///
    /// [`FsStore::pages`] needs the store itself rather than the `FsStore`
    /// wrapper so that a walk can outlive a method call -- the rebuild diff
    /// holds two walks open at once, one per side.
    pub(crate) fn kv_handle(&self) -> Arc<RwLock<OxKvStore>> {
        Arc::clone(&self.inner)
    }

    /// A key-ordered, paginated walk over the whole keyspace.
    pub(crate) fn pages(&self) -> KvPages {
        KvPages::new(self.kv_handle())
    }
}

/// Keys fetched per round trip during a [`KvPages`] walk.
///
/// The memory ceiling of a paged walk is this, not the keyspace. Large enough
/// that the inclusive-cursor resume below can never be handed back a page
/// containing only the duplicate key, small enough that a full scan of a large
/// replica is not one enormous allocation.
const SCAN_PAGE: u32 = 512;

/// A key-ordered walk over an oxkv store that holds one page at a time.
///
/// `gets_bytes` with a `None` limit returns the entire keyspace, so anything
/// built on it is O(keyspace) in memory no matter how carefully the caller
/// iterates. That is what made the replica rebuild hold roughly three copies
/// of a user's data: the master file list, the freshly-built scratch replica,
/// and the live replica it was diffed against, all as collections.
///
/// This walks in pages instead. The two sides of a rebuild diff are both
/// key-ordered by construction, so they can be merged in lockstep and compared
/// a record at a time.
pub(crate) struct KvPages {
    store: Arc<RwLock<OxKvStore>>,
    /// Inclusive resume point; `None` until the first page.
    cursor: Option<String>,
    buffer: std::vec::IntoIter<KeyValue>,
    exhausted: bool,
}

impl KvPages {
    /// Starts a walk over `store`, ascending from the first key.
    pub(crate) fn new(store: Arc<RwLock<OxKvStore>>) -> Self {
        Self {
            store,
            cursor: None,
            buffer: Vec::new().into_iter(),
            exhausted: false,
        }
    }

    /// Starts a walk over a handle this walk exclusively owns, for the replica
    /// side, which is not wrapped in an [`FsStore`].
    pub(crate) fn owned(handle: OxKvStore) -> Self {
        Self::new(Arc::new(RwLock::new(handle)))
    }

    /// The next key/value, or `None` at the end of the keyspace.
    pub(crate) async fn next(&mut self) -> Result<Option<KeyValue>, FsError> {
        if let Some(kv) = self.buffer.next() {
            return Ok(Some(kv));
        }
        if self.exhausted {
            return Ok(None);
        }

        let mut page: Vec<KeyValue> = {
            let g = self.store.read().await;
            g.gets_bytes(
                Some(SCAN_PAGE),
                Direction::Next,
                (self.cursor.clone(), None),
            )
            .await
            .map_err(FsError::from)?
            .into_iter()
            .collect()
        };

        // `gets_bytes` bounds are inclusive, so a resumed page comes back with
        // the resume key as its first entry. Dropping exactly that entry --
        // and nothing else -- is what stops the walk revisiting one key
        // forever. Nudging the key instead is not an option: keys are
        // arbitrary byte strings and "the next key after X" is not
        // expressible.
        if self
            .cursor
            .as_ref()
            .is_some_and(|resume| page.first().is_some_and(|kv| kv.key == *resume))
        {
            page.remove(0);
        }

        if page.is_empty() {
            // Either the keyspace is empty, or the previous page's last key was
            // the final one. `SCAN_PAGE > 1` is what makes that safe: a page
            // holding nothing but the resume key means there is nothing after
            // it, never that the limit clipped the result to a single entry.
            self.exhausted = true;
            return Ok(None);
        }

        self.cursor = page.last().map(|kv| kv.key.clone());
        self.buffer = page.into_iter();
        Ok(self.buffer.next())
    }
}

/// Reads ref-count info through any [`GetSet`] handle (store or
/// transaction); absent entries mean "never attached".
///
/// `primary` carries the owning store's mark, because a transaction is not
/// an `FsStore` and a fencing loss on this read still has to reach the
/// latch when the read is part of a master mutation.
async fn read_ref_info<T: GetSet>(
    tx: &T,
    file_id: &str,
    latch: &Latch,
    primary: bool,
) -> Result<RefInfo, FsError> {
    let key = refs_key(file_id);
    let bytes = tx.get_bytes(&key).await.map_err(|e| {
        let err = FsError::from(e);
        if primary && err.is_fencing_loss() {
            latch.trip(FsStore::FS_PREFIX, err.detail());
        }
        err
    })?;
    let Some(bytes) = bytes else {
        return Ok(RefInfo::default());
    };
    serde_json::from_slice(&bytes).map_err(|e| FsError::Internal(e.to_string()))
}

/// Exclusive upper bound for a `prefix:` range scan (`:` -> `;`).
///
/// Every key starting with `prefix:` sorts strictly below the bound, so
/// the engine can stop at the key family instead of walking the rest of
/// the store. No stored key ever equals the bare prefix itself.
fn prefix_scan_end(prefix: &str) -> String {
    debug_assert!(prefix.ends_with(':'));
    let mut end = prefix.to_string();
    end.pop();
    end.push(';');
    end
}

#[cfg(test)]
mod tests {
    use super::{FileRecord, FsStore, PersistedMultipart, SCAN_PAGE, UploadSession};
    use crate::db::build_test_store;
    use crate::fencing::Latch;
    use oxkv::GetSet as _;
    use std::sync::Arc;

    /// Which failures take this process out of rotation.
    ///
    /// The master/replica split is the whole point of the latch, and it is
    /// the half that can be asserted without touching the process-wide
    /// signal: a replica write that loses a build race is recovered from by
    /// `sync`, so latching it would pull a healthy server out of rotation
    /// over a non-event. A non-fencing failure on the master is a plain 500
    /// and must not latch either, or a flaky S3 would read as a lost lease.
    #[tokio::test]
    async fn only_a_fenced_master_write_latches() {
        use crate::fs::error::FsError;

        let master =
            FsStore::primary(build_test_store(&crate::db::test_prefix("latch-master")).await);
        let replica =
            FsStore::new(build_test_store(&crate::db::test_prefix("latch-replica")).await);

        let fenced = FsError::from(oxkv::StoreError::Fenced("epoch 2".into()));
        let other = FsError::from(oxkv::StoreError::Storage("bucket gone".into()));

        assert!(master.latches(&fenced), "a fenced master write is terminal");
        assert!(!replica.latches(&fenced), "a replica build race is not");
        assert!(!master.latches(&other), "a flaky store is not a lost epoch");
        assert!(!replica.latches(&other));
    }

    /// One write method, boxed so the table below can hold closures of
    /// different bodies.
    type WriteFn =
        fn(&FsStore) -> futures_util::future::BoxFuture<'_, Result<(), crate::fs::error::FsError>>;

    /// A master write that loses its epoch must latch, whatever method it
    /// went through.
    ///
    /// The predicate above is not enough, and that is the whole point of
    /// this one. Six of the nine write methods converted the `oxkv` error
    /// with a bare `map_err(FsError::from)`, so the classification was
    /// correct and the *report* never happened: `POST /fs/{id}/complete`
    /// 500'd on `save_file` before the WAL announce ran, while
    /// `fencing::primary_loss()` stayed false and `/ready` returned 200. The
    /// instance served traffic it could not write and no signal said so.
    ///
    /// This drives a real `oxkv` handle into `StoreError::Fenced` -- a second
    /// session over the same prefix takes the epoch -- and asserts each
    /// write's latch, on a private latch rather than the process-wide one.
    /// Asserting against the process-wide flag would pass vacuously: it is
    /// one-way with no reset, so `fencing::tests` tripping it first would
    /// satisfy this test even with every call site removed.
    #[tokio::test]
    async fn a_fenced_master_write_latches_whatever_method_it_went_through() {
        // Every write method that persists or removes a key, named so a
        // failure says which one stopped reporting.
        let writes: Vec<(&str, WriteFn)> = vec![
            ("save_session", |s| {
                Box::pin(async move { s.save_session(&sample_session("latch-sess")).await })
            }),
            ("delete_session", |s| {
                Box::pin(async move { s.delete_session("latch-sess").await })
            }),
            ("save_multipart", |s| {
                Box::pin(async move { s.save_multipart(&sample_multipart("latch-mp")).await })
            }),
            ("delete_multipart", |s| {
                Box::pin(async move { s.delete_multipart("latch-mp").await })
            }),
            ("save_staged_part", |s| {
                Box::pin(
                    async move { s.save_staged_part("latch-sess", 0, b"chunk".to_vec()).await },
                )
            }),
            ("save_file", |s| {
                Box::pin(async move { s.save_file(&sample_file("latch-file")).await })
            }),
            ("delete_file", |s| {
                Box::pin(async move { s.delete_file("latch-file").await })
            }),
            // `attach` on the row the seed already linked takes its idempotent
            // read-back path and never writes, so it gets a row of its
            // own; `detach` uses the seeded one.
            ("attach", |s| {
                Box::pin(async move { s.attach("invoice", "2", "latch-file").await.map(|_| ()) })
            }),
            ("detach", |s| {
                Box::pin(async move { s.detach("invoice", "1", "latch-file").await.map(|_| ()) })
            }),
        ];

        for (name, write) in writes {
            // A fresh latch per method, or the first one to trip would
            // satisfy every assertion after it and the list would only
            // prove its own head entry. `Box::leak` because the field is a
            // `&'static`, matching how a production store holds the
            // process-wide one.
            let latch: &'static Latch = Box::leak(Box::new(Latch::new()));
            let (store, _holder) = fenced_store("latch-site", latch, true).await;
            let err = write(&store)
                .await
                .expect_err(&format!("{name} on a fenced epoch must fail"));
            assert!(
                err.is_fencing_loss(),
                "{name} lost the epoch but reported {err:?}",
            );
            assert!(latch.is_tripped(), "{name} did not latch a fencing loss");
        }
    }

    /// A replica write that loses its build race must NOT latch.
    ///
    /// The other direction of the master/replica split, and the one that
    /// decides whether this mechanism is usable at all: `sync` recovers a
    /// replica race by adopting the winner's coverage, so latching it would
    /// take a healthy server out of rotation over a non-event.
    #[tokio::test]
    async fn a_fenced_replica_write_does_not_latch() {
        let latch: &'static Latch = Box::leak(Box::new(Latch::new()));
        let (store, _holder) = fenced_store("latch-replica-site", latch, false).await;

        let err = store
            .save_file(&sample_file("replica-fenced"))
            .await
            .expect_err("a fenced replica write must fail");
        assert!(err.is_fencing_loss(), "expected a lost epoch, got {err:?}");
        assert!(
            !latch.is_tripped(),
            "a replica build race must not take a healthy server out of rotation",
        );
    }

    /// A store that a second session has fenced, holding the keys every write
    /// above targets.
    ///
    /// The seeding comes first and matters: `oxkv`'s `delete` of a missing
    /// key is a read that returns `Ok(false)` without consulting
    /// `ownership.json`, so a delete against an empty store would succeed on
    /// a fenced handle and the test would be asserting nothing. A delete
    /// that has something to delete reaches the WAL put and is fenced
    /// there, as it is in production.
    ///
    /// Returns the fenced store and the session that fenced it. The holder
    /// has to outlive the store: an `oxkv` handle only fences another while
    /// it is alive, so dropping it would make the test assert nothing.
    async fn fenced_store(
        name: &str,
        latch: &'static Latch,
        primary: bool,
    ) -> (FsStore, oxkv::OxKvStore) {
        let prefix = crate::db::test_prefix(name);
        let inner =
            Arc::new(object_store::memory::InMemory::new()) as Arc<dyn object_store::ObjectStore>;
        let handle = crate::db::build_test_store_new_session(Arc::clone(&inner), &prefix).await;
        // A clone shares the session, so seeding through it is a write by
        // the handle under test.
        seed_delete_targets(&FsStore::primary(handle.clone())).await;

        // A second session over the same prefix CAS-bumps the epoch and
        // fences the first: exactly what an uncooperative second writer does.
        let holder = crate::db::build_test_store_new_session(inner, &prefix).await;

        let store = if primary {
            FsStore::primary_with_latch(handle, latch)
        } else {
            FsStore {
                latch,
                ..FsStore::new(handle)
            }
        };
        (store, holder)
    }

    /// Writes a session, a multipart record and an attached file, so the
    /// delete and detach paths have something to act on.
    async fn seed_delete_targets(store: &FsStore) {
        store
            .save_session(&sample_session("latch-sess"))
            .await
            .expect("seed session");
        store
            .save_multipart(&sample_multipart("latch-mp"))
            .await
            .expect("seed multipart");
        store
            .save_file(&sample_file("latch-file"))
            .await
            .expect("seed file");
        store
            .attach("invoice", "1", "latch-file")
            .await
            .expect("seed relation");
    }

    /// A paged walk must visit every key exactly once.
    ///
    /// `gets_bytes` takes *inclusive* cursor bounds, so resuming from the last
    /// key of a page hands that same key back as the first entry of the next
    /// one. Get that wrong and the walk either loops forever on one key or --
    /// worse, if the dedup is too eager -- silently skips keys, which for the
    /// replica rebuild means a user's file quietly never appears in their
    /// replica with no error anywhere.
    ///
    /// Spans several pages deliberately: the boundary is the only place the
    /// inclusive-cursor handling is exercised, and a single-page walk would
    /// pass with the dedup removed entirely.
    #[tokio::test]
    async fn paged_walk_visits_every_key_exactly_once() {
        /// More keys than `SCAN_PAGE`, so at least one page boundary falls
        /// strictly inside the keyspace.
        const KEYS: usize = SCAN_PAGE as usize * 3 + 7;

        let store = test_store().await;
        let expected: Vec<String> = (0..KEYS).map(|i| format!("k:{i:06}")).collect();
        for key in &expected {
            store
                .inner
                .write()
                .await
                .set_bytes(key, key.as_bytes())
                .await
                .unwrap();
        }

        let mut pages = store.pages();
        let mut seen: Vec<String> = Vec::new();
        while let Some(kv) = pages.next().await.expect("walk") {
            assert!(!seen.contains(&kv.key), "key {} visited twice", kv.key);
            seen.push(kv.key.clone());
        }

        assert_eq!(
            seen, expected,
            "walk did not reproduce the keyspace in order"
        );
    }

    /// An empty keyspace terminates instead of looping.
    #[tokio::test]
    async fn paged_walk_over_an_empty_store_terminates() {
        let store = test_store().await;
        let mut pages = store.pages();
        assert!(pages.next().await.expect("walk").is_none());
        assert!(pages.next().await.expect("walk").is_none());
    }

    /// A keyspace of exactly one page, and one page plus one, are the two
    /// sizes where an off-by-one in the boundary handling hides.
    #[tokio::test]
    async fn paged_walk_handles_exact_page_multiples() {
        for size in [
            SCAN_PAGE as usize,
            SCAN_PAGE as usize + 1,
            SCAN_PAGE as usize * 2,
        ] {
            let store = test_store().await;
            let expected: Vec<String> = (0..size).map(|i| format!("k:{i:06}")).collect();
            for key in &expected {
                store
                    .inner
                    .write()
                    .await
                    .set_bytes(key, key.as_bytes())
                    .await
                    .unwrap();
            }

            let mut pages = store.pages();
            let mut seen = Vec::new();
            while let Some(kv) = pages.next().await.expect("walk") {
                seen.push(kv.key.clone());
            }
            assert_eq!(seen, expected, "wrong walk for size {size}");
        }
    }

    async fn test_store() -> FsStore {
        let s3 = build_test_store(&crate::db::test_prefix("fs-store")).await;
        FsStore::new(s3)
    }

    fn sample_session(id: &str) -> UploadSession {
        UploadSession {
            id: id.to_string(),
            file_size: 1024,
            part_size: 1024,
            file_total_parts: 1,
            s3_upload_id: None,
            s3_key: format!("files/{id}"),
            owner_sub: "alice".to_string(),
            created_at: chrono::Utc::now().timestamp(),
            etags: vec![None],
            checksums: vec![None],
        }
    }

    fn sample_multipart(upload_id: &str) -> PersistedMultipart {
        PersistedMultipart {
            upload_id: upload_id.to_string(),
            bucket: "b".to_string(),
            key: "files/f".to_string(),
            s3_upload_id: "real-backend-id".to_string(),
            parts: [(0usize, "etag-0".to_string())].into_iter().collect(),
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    fn sample_file(id: &str) -> FileRecord {
        FileRecord {
            id: id.to_string(),
            name: "h.txt".to_string(),
            mimetype: "text/plain".to_string(),
            size: 1,
            s3_key: format!("files/{id}"),
            owner_sub: "bob".to_string(),
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    #[tokio::test]
    async fn multipart_record_roundtrip_and_session_cascade() -> anyhow::Result<()> {
        let store = test_store().await;
        assert!(store.load_multipart("up-1").await?.is_none());
        store.save_multipart(&sample_multipart("up-1")).await?;
        let loaded = store.load_multipart("up-1").await?.expect("should exist");
        assert_eq!(loaded.s3_upload_id, "real-backend-id");
        assert_eq!(loaded.parts.get(&0).map(String::as_str), Some("etag-0"));
        // The record lives and dies with its session.
        let mut sess = sample_session("sess-mp");
        sess.s3_upload_id = Some("up-1".to_string());
        store.save_session(&sess).await?;
        store.delete_session("sess-mp").await?;
        assert!(store.load_multipart("up-1").await?.is_none());
        store.delete_multipart("up-1").await?;
        Ok(())
    }

    #[tokio::test]
    async fn session_save_get_delete_roundtrip() -> anyhow::Result<()> {
        let store = test_store().await;
        let sess = sample_session("sess-1");
        store.save_session(&sess).await?;
        let loaded = store.get_session("sess-1").await?.expect("should exist");
        assert_eq!(loaded.id, "sess-1");
        assert_eq!(loaded.s3_key, "files/sess-1");
        store.delete_session("sess-1").await?;
        assert!(store.get_session("sess-1").await?.is_none());
        store.delete_session("sess-1").await?;
        Ok(())
    }

    #[tokio::test]
    async fn delete_session_cleans_staged_parts() -> anyhow::Result<()> {
        let store = test_store().await;
        let mut sess = sample_session("sess-2");
        sess.file_total_parts = 2;
        sess.etags = vec![None, None];
        sess.checksums = vec![None, None];
        store.save_session(&sess).await?;
        store
            .save_staged_part("sess-2", 0, b"chunk0".to_vec())
            .await?;
        store
            .save_staged_part("sess-2", 1, b"chunk1".to_vec())
            .await?;
        assert_eq!(
            store.get_staged_part("sess-2", 0).await?.unwrap(),
            b"chunk0"
        );
        assert_eq!(
            store.get_staged_part("sess-2", 1).await?.unwrap(),
            b"chunk1"
        );
        store.delete_session("sess-2").await?;
        assert!(store.get_session("sess-2").await?.is_none());
        assert!(store.get_staged_part("sess-2", 0).await?.is_none());
        assert!(store.get_staged_part("sess-2", 1).await?.is_none());
        assert!(store.get_staged_part("sess-2", 99).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn file_save_get_delete_roundtrip() -> anyhow::Result<()> {
        let store = test_store().await;
        let rec = FileRecord {
            id: "file-1".to_string(),
            name: "hello.txt".to_string(),
            mimetype: "text/plain".to_string(),
            size: 5,
            s3_key: "files/file-1".to_string(),
            owner_sub: "bob".to_string(),
            created_at: chrono::Utc::now().timestamp(),
        };
        store.save_file(&rec).await?;
        let loaded = store.get_file("file-1").await?.unwrap();
        assert_eq!(loaded.name, "hello.txt");
        assert_eq!(loaded.mimetype, "text/plain");
        store.delete_file("file-1").await?;
        assert!(store.get_file("file-1").await?.is_none());
        assert!(store.get_file("nonexistent").await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn delete_file_cleans_relations() -> anyhow::Result<()> {
        let store = test_store().await;
        let rec = FileRecord {
            id: "rel-file".to_string(),
            name: "r.txt".to_string(),
            mimetype: "text/plain".to_string(),
            size: 1,
            s3_key: "files/rel-file".to_string(),
            owner_sub: "bob".to_string(),
            created_at: 0,
        };
        store.save_file(&rec).await?;
        store.attach("invoice", "7", "rel-file").await?;
        store.attach("receipt", "9", "rel-file").await?;
        assert_eq!(store.rows_for_file("rel-file").await?.len(), 2);

        store.delete_file("rel-file").await?;
        assert!(store.get_file("rel-file").await?.is_none());
        // No dangling markers or ref-count left behind.
        assert!(store.rows_for_file("rel-file").await?.is_empty());
        assert_eq!(store.get_ref_info("rel-file").await?.count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn mirrored_store_serves_reads() -> anyhow::Result<()> {
        // Writes land before and after the mirror opens: pre-existing
        // keys arrive via fall-through/warm, later ones via refresh.
        let plain = test_store().await;
        let rec = FileRecord {
            id: "mirror-1".to_string(),
            name: "m.txt".to_string(),
            mimetype: "text/plain".to_string(),
            size: 5,
            s3_key: "files/mirror-1".to_string(),
            owner_sub: "bob".to_string(),
            created_at: 0,
        };
        plain.save_file(&rec).await?;
        plain.attach("invoice", "7", "mirror-1").await?;

        let mirrored = FsStore::new_mirrored(clone_handle(&plain).await).await?;
        // First refresh converges the pre-existing writes (WAL replay or
        // warm, depending on what compacted); reads then serve correctly.
        assert!(mirrored.refresh_mirror().await? > 0);
        assert_eq!(mirrored.get_file("mirror-1").await?.unwrap().name, "m.txt");
        assert_eq!(mirrored.list_files().await?.records.len(), 1);
        assert_eq!(
            mirrored.rows_for_file("mirror-1").await?,
            vec![("invoice".to_string(), "7".to_string())]
        );
        assert_eq!(mirrored.get_ref_info("mirror-1").await?.count, 1);

        // A write through the plain handle converges on refresh, and a
        // second refresh with no writes is a manifest-check no-op.
        plain.detach("invoice", "7", "mirror-1").await?;
        mirrored.refresh_mirror().await?;
        assert!(mirrored.rows_for_file("mirror-1").await?.is_empty());
        assert_eq!(mirrored.get_ref_info("mirror-1").await?.count, 0);
        assert_eq!(mirrored.refresh_mirror().await?, 0);
        Ok(())
    }

    /// Clones the underlying handle out for mirror tests (shares session).
    async fn clone_handle(store: &FsStore) -> oxkv::OxKvStore {
        store.inner.read().await.clone()
    }

    #[tokio::test]
    async fn list_sessions_filters_and_deserializes() -> anyhow::Result<()> {
        let store = test_store().await;
        assert!(store.list_sessions().await?.records.is_empty());
        let s1 = sample_session("list-a");
        let mut s2 = sample_session("list-b");
        s2.file_total_parts = 2;
        s2.etags = vec![None, None];
        s2.checksums = vec![None, None];
        store.save_session(&s1).await?;
        store.save_session(&s2).await?;
        let rec = FileRecord {
            id: "file-x".to_string(),
            name: "x".into(),
            mimetype: "x".into(),
            size: 1,
            s3_key: "k".into(),
            owner_sub: "o".into(),
            created_at: 0,
        };
        store.save_file(&rec).await?;
        let mut sessions = store.list_sessions().await?.records;
        sessions.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "list-a");
        assert_eq!(sessions[1].id, "list-b");
        Ok(())
    }

    #[tokio::test]
    async fn get_session_returns_none_when_missing() -> anyhow::Result<()> {
        let store = test_store().await;
        assert!(store.get_session("ghost").await?.is_none());
        assert!(store.get_staged_part("ghost", 0).await?.is_none());
        Ok(())
    }

    #[test]
    fn keys_are_namespaced_and_distinct() {
        assert_eq!(FsStore::session_key("abc"), "fs:uploads:abc:meta");
        assert_eq!(FsStore::staged_key("abc", 2), "fs:uploads:abc:part:2");
        assert_eq!(FsStore::file_key("abc"), "fs:files:abc:meta");
        assert_ne!(FsStore::session_key("x"), FsStore::file_key("x"));
        assert_ne!(FsStore::session_key("x"), FsStore::staged_key("x", 0));
        assert!(FsStore::staged_key("x", 0).contains(":part:"));
        assert!(FsStore::session_key("x").ends_with(":meta"));
        assert!(FsStore::file_key("x").ends_with(":meta"));
    }
}
