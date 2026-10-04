//! `oxkv` persistence for upload sessions, file records, and relations.
//! The store uses [`oxkv::OxKvStore`], which is an LSM tree on S3.
//! Keys: `fs:uploads:{id}:meta`, `fs:files:{id}:meta`, `fs:rel:{type}:{id}:{file}`, `fs:files:{id}:refs`.
//! The store scales per user. Each `OxKvStore` uses its own key prefix,
//! for example `oxkv/fs`, on the shared `ObjectStore`.

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
    /// True when the session is older than `ttl_secs` at the time `now`.
    ///
    /// The function takes the TTL as an argument.
    /// The retention policy then stays with the sweeper
    /// ([`crate::fs::gc::TTL_SECS`]) and not in the record type.
    pub fn is_expired(&self, now: i64, ttl_secs: i64) -> bool {
        now - self.created_at > ttl_secs
    }
}

/// Durable S3 state for a multipart upload.
/// It mirrors the client RAM map, so that uploads survive a restart.
/// The object-store `MultipartId` is a plain string, and the staged
/// `PartId`s rebuild from their content ids.
/// A new client loads this record only (see `S3Client::restore_multipart`).
/// A record lives and dies with its session.
/// The engine creates the record at init and updates it for each part.
/// The `delete_session` cascade deletes the record on complete, cancel, or
/// expiry.
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
/// The type is re-exported from [`crate::records`].
/// It lives there because [`WalOp::FileCreate`](crate::records::WalOp::FileCreate)
/// carries one, and `sync` must read it without importing the whole `fs`
/// module.
pub use crate::records::FileRecord;

/// What a metadata scan read and what it could not read.
///
/// `fs:files:` and `fs:uploads:` are the only map from S3 bytes back to
/// the rows that reference them.
/// A row that fails to decode is therefore not a harmless gap.
/// A caller that reads "no record mentions this key" as "these bytes are
/// garbage" deletes the object of a record that it cannot parse.
/// Nothing else in the store can repair that.
/// The metadata row survives, and every download then returns 404 for ever.
///
/// The scan therefore carries the unread keys out instead of dropping them
/// inside.
/// A caller that deletes on absence can then refuse to act while the set is
/// not empty.
#[derive(Debug, Clone)]
pub struct RecordScan<T> {
    /// Every record in the key family that decoded, in scan order.
    pub records: Vec<T>,
    /// Keys in the family whose value did not decode, in scan order.
    ///
    /// The engine already logged these keys at `warn!`.
    /// The scan keeps them so that a sweeper can act on the fact that the
    /// scan was incomplete.
    pub undecodable: Vec<String>,
}

/// One step of a paged `fs:files:` walk.
/// This type is the paged counterpart of [`RecordScan`].
///
/// [`FsStore::next_file`] pages instead of collecting, so it cannot return
/// the result for the whole key family in one value.
/// It still owes its caller what [`RecordScan`] owes the sweeper.
/// That duty is the difference between "this walk read everything" and
/// "this walk stopped early".
pub(crate) struct FileScan {
    /// The next file record in key order, or `None` at the end of the walk.
    pub record: Option<FileRecord>,
    /// Keys skipped in this step because their value did not decode.
    ///
    /// The function already logs each key at `warn!`. A caller that deletes
    /// on absence must sum these keys across the whole walk. The caller must
    /// refuse to act while they are non-empty.
    pub undecodable: Vec<String>,
}

/// Thin wrapper around an `oxkv` LSM store for FS keys.
#[derive(Clone)]
pub struct FsStore {
    inner: Arc<RwLock<OxKvStore>>,
    /// A RAM mirror over the same handle. The engine warms it lazily. This
    /// mirror is a prototype.
    ///
    /// A read uses the mirror when the mirror exists.
    /// A write always goes to `inner`.
    /// The mirror never takes an epoch.
    /// It wraps a clone that shares the session, so it cannot fence the
    /// writer.
    mirror: Option<CachedOxKvStore>,
    /// True when this store is the master `{db}/fs` prefix.
    ///
    /// This flag decides whether a lost epoch latches the process-wide
    /// fencing signal.
    /// The same `FsStore` type also backs a per-user *replica* prefix
    /// during a sync build.
    /// In a replica, a lost race is normal.
    /// The engine resolves it by adopting the coverage of the winner.
    /// A latch in a replica would take a healthy server out of rotation
    /// for an event that does not matter.
    /// The engine sets the flag at the one place that owns the master store
    /// ([`FsEngine::init`](crate::fs::FsEngine::init)).
    /// The flag therefore stays with the ownership, and is not inferred
    /// from a key prefix.
    primary: bool,
    /// Where this store records its fencing losses.
    ///
    /// In production the store uses the process-wide latch (see
    /// [`process_latch`](crate::fencing::process_latch)).
    /// A test uses the latch of its own store.
    /// The store holds the latch as a field instead of reaching it through
    /// [`note_primary_loss`](crate::fencing::note_primary_loss).
    /// The process-wide latch is one-way and global.
    /// A test that tripped it could not tell its own write from the write
    /// of another test.
    latch: &'static Latch,
}

impl FsStore {
    /// The master `{db}/fs` prefix, named in the fencing-loss log line.
    const FS_PREFIX: &str = "{db}/fs";

    /// True when a failure on this store must latch the process-wide
    /// fencing signal.
    ///
    /// The rule covers only the master prefix, and only a lost epoch.
    /// Both halves of the rule carry weight, and neither is clear from the
    /// call site.
    /// The two halves therefore live in one predicate.
    fn latches(&self, err: &FsError) -> bool {
        // `sync` recovers a replica write that loses a build race by
        // adopting the coverage of the winner.
        // A latch in that case would take a healthy server out of
        // rotation for an event that does not matter.
        self.primary && err.is_fencing_loss()
    }

    /// Maps an oxkv error into [`FsError`].
    /// The store latches a fencing loss when it owns the master prefix.
    ///
    /// The latch belongs here and not in the conversion in [`FsError`].
    /// The same `FsError` also carries replica write failures, and `sync`
    /// recovers from those by design.
    /// A mark on the one store that owns the primary prefix keeps the
    /// distinction with the ownership.
    /// The store does not infer the distinction from a key prefix.
    fn store_err(&self, e: oxkv::StoreError) -> FsError {
        let err = FsError::from(e);
        if self.latches(&err) {
            self.latch.trip(Self::FS_PREFIX, err.detail());
        }
        err
    }

    /// Creates an FS store from an [`OxKvStore`].
    /// The store uses a per-user S3 LSM store, and it scales per user.
    ///
    /// This store is not the master store. See [`FsStore::primary`].
    pub fn new(s3_store: OxKvStore) -> Self {
        Self {
            inner: Arc::new(RwLock::new(s3_store)),
            mirror: None,
            primary: false,
            latch: crate::fencing::process_latch(),
        }
    }

    /// Creates the master `{db}/fs` store.
    /// A fencing loss in this store ends the process.
    pub fn primary(s3_store: OxKvStore) -> Self {
        Self {
            primary: true,
            ..Self::new(s3_store)
        }
    }

    /// Creates the master store.
    /// The store records fencing losses on `latch` instead of the
    /// process-wide latch.
    ///
    /// The latch is a one-way flag with no reset.
    /// A test that must prove that a write *trips* the latch cannot share
    /// the process-wide latch.
    /// Anything that another test tripped first would satisfy the
    /// assertion, whether or not the code under test latched.
    #[cfg(test)]
    pub(crate) fn primary_with_latch(s3_store: OxKvStore, latch: &'static Latch) -> Self {
        Self {
            primary: true,
            latch,
            ..Self::new(s3_store)
        }
    }

    /// Creates an FS store with a lazily warmed RAM mirror.
    /// The mirror is a prototype.
    ///
    /// The mirror wraps a clone of `s3_store`.
    /// The clone shares the session and the state, and it takes no new
    /// epoch.
    /// The mirror warms one key at a time on a read miss.
    /// On a miss it falls through to the durable core, so that it stays
    /// correct.
    /// Call [`refresh_mirror`](Self::refresh_mirror) before a bulk scan.
    /// Then one incremental WAL replay converges the mirror, and the code
    /// avoids one miss per key.
    /// Set `RUST_LOG=debug` to measure this.
    /// The engine logs the refresh counts.
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

    /// Test only.
    /// Creates a mirror over a clone of this handle.
    /// The clone shares the session.
    #[cfg(test)]
    pub(crate) async fn mirrored_clone(&self) -> Result<Self, FsError> {
        Self::new_mirrored(self.inner.read().await.clone()).await
    }

    /// Converges the mirror with the master writes since the last call.
    ///
    /// The function does nothing when the store has no mirror.
    /// The function returns the number of replayed entries.
    /// The value 0 means the mirror is already converged.
    /// The engine then does no I/O except the manifest check.
    /// A full re-warm happens only when the epoch or the SST set changes,
    /// and never for steady writes.
    pub async fn refresh_mirror(&self) -> Result<usize, FsError> {
        let Some(mirror) = &self.mirror else {
            return Ok(0);
        };
        let applied = mirror.refresh().await.map_err(FsError::from)?;
        tracing::debug!(applied, "fs mirror refreshed");
        Ok(applied)
    }

    /// Reads one key through the single shared handle.
    /// The function reads from the mirror first.
    async fn get_one(&self, key: &str) -> Result<Option<Vec<u8>>, FsError> {
        if let Some(mirror) = &self.mirror {
            return mirror.get_bytes(key).await.map_err(FsError::from);
        }
        let g = self.inner.read().await;
        g.get_bytes(key).await.map_err(FsError::from)
    }

    /// Scans a key range that stops at the end of the `prefix:` family.
    ///
    /// A full-store scan (`(None, None)` cursors) loads every key into
    /// memory.
    /// Bounding the scan to a key prefix keeps the size of each scan
    /// proportional to its own key family, and not to the whole store.
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

    /// Deletes an upload session, the staged parts of its single-part chunks,
    /// and its multipart record in one transaction.
    ///
    /// The order of the deletes is the contract.
    /// The cascade rows go first. The session key goes last.
    /// The session row is the only thing that makes this cascade reachable
    /// again.
    /// `list_sessions` scans the `fs:uploads:` family.
    /// Nothing in the crate scans `fs:mp:`.
    /// If the engine deletes the session key first and a cascade delete
    /// fails, no later scan can find the record.
    /// A crash between the two deletes then leaves permanent KV garbage.
    /// That garbage holds a live backend `s3_upload_id`.
    /// No record anywhere says that the multipart record must live and die
    /// with its session.
    ///
    /// The function uses one transaction because half a cascade fails like
    /// no cascade.
    /// The transaction stages the deletes together, and they land together.
    /// The window in which the session row is gone and a cascade row
    /// survives does not exist.
    /// The function maps every cascade error like every other write here.
    /// Discarding those errors is what made this operation lossy.
    pub async fn delete_session(&self, id: &str) -> Result<(), FsError> {
        let session = self.get_session(id).await?;
        let g = self.inner.write().await;
        let tx = g.begin_tx().map_err(|e| self.store_err(e))?;
        if let Some(s) = &session {
            for idx in 0..s.file_total_parts {
                let k = Self::staged_key(id, idx);
                tx.delete(&k).await.map_err(|e| self.store_err(e))?;
            }
            // The multipart record lives and dies with its
            // session, so expiry and GC cannot strand one.
            if let Some(upload_id) = &s.s3_upload_id {
                let k = Self::multipart_key(upload_id);
                tx.delete(&k).await.map_err(|e| self.store_err(e))?;
            }
        }
        // The session key goes last.
        // A cascade failure above then leaves the session row in place,
        // and the engine retries the whole delete instead of applying
        // half of it.
        let key = Self::session_key(id);
        tx.delete(&key).await.map_err(|e| self.store_err(e))?;
        tx.commit().await.map_err(|e| self.store_err(e))?;
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
    /// relation marker that points at it in one transaction.
    /// Markers that remain accumulate as garbage after the record is gone.
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
        tx.delete(&refs).await.map_err(|e| self.store_err(e))?;
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

    /// Attaches a file to a row. The function is idempotent.
    ///
    /// The transaction commits the relation marker and the ref-count update
    /// together.
    /// A crash can never leave one without the other.
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

    /// Detaches a file from a row. The function is idempotent.
    ///
    /// The atomicity contract is the same as for [`FsStore::attach`].
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

    /// Lists the files attached to one row.
    /// The scan stays inside `fs:rel:{type}:{id}:`.
    ///
    /// Incremental policy replay uses this method to resync only the row
    /// that a rule changed.
    /// The method then avoids a scan of the whole store for a full
    /// rebuild.
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

    /// Lists all finalized file records. The scan stays inside `fs:files:`.
    ///
    /// A row that does not decode is skipped.
    /// One bad record must not stop a rebuild for every other file of the
    /// user.
    /// The scan *reports* a skipped record instead of dropping it.
    /// No other place shows the skip.
    /// A record that is missing from this list looks exactly like a record
    /// that was never written.
    /// The orphan-byte sweeper deletes objects on exactly that
    /// assumption.
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

    /// Lists all upload sessions. The scan stays inside `fs:uploads:`.
    ///
    /// The scan skips and reports rows that do not decode.
    /// It uses the same contract as [`FsStore::list_files`].
    /// A session that the scan cannot list is a session that the sweeper
    /// never expires.
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

    /// Reads every raw key-value pair for verbatim replica copies.
    ///
    /// The function returns one step of the walk.
    /// The step holds the next finalized file record in key order, and the
    /// keys that the step had to skip.
    /// The caller owns the filtering, and everything present is returned
    /// as-is.
    ///
    /// The function takes the walk instead of creating one.
    /// The caller can then page through the whole keyspace and hold at
    /// most [`SCAN_PAGE`] records.
    /// The replica rebuild filters the records one at a time and keeps
    /// none of them.
    /// The prefix stays private here, so the key layout has one owner.
    ///
    /// The unread keys are reported instead of dropped inside the walk,
    /// for the reason that [`RecordScan`] documents.
    /// A rebuild compares this walk with the live replica.
    /// A key that the walk cannot decode is then a key that the desired
    /// side does not have.
    /// The merge join reads that as "the master no longer has it", and it
    /// deletes the key from the replica.
    /// The caller cannot act on a walk that lost rows without saying so.
    pub(crate) async fn next_file(&self, scan: &mut KvPages) -> Result<FileScan, FsError> {
        let mut undecodable = Vec::new();
        while let Some(kv) = scan.next().await? {
            if !kv.key.starts_with(FILES_PREFIX) || !kv.key.ends_with(FILE_META_SUFFIX) {
                continue;
            }
            // A record that does not decode is skipped.
            // This is the same rule as in `list_files`.
            // One bad row must not stop a rebuild for every other file of
            // the user.
            // The engine logs the row for the same reason.
            // A skipped record is missing from the replica that this walk
            // builds, and nothing downstream can tell that from a record
            // that was never written.
            // The function returns the key for the same reason.
            // The one caller that acts on ABSENCE cannot act on a walk
            // that lost rows without saying so.
            match serde_json::from_slice::<FileRecord>(&kv.value) {
                Ok(rec) => {
                    return Ok(FileScan {
                        record: Some(rec),
                        undecodable,
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        key = %kv.key,
                        error = %e,
                        "fs file metadata did not decode"
                    );
                    undecodable.push(kv.key);
                }
            }
        }
        Ok(FileScan {
            record: None,
            undecodable,
        })
    }

    /// Returns the underlying handle, for a paged scan of the whole keyspace.
    ///
    /// [`FsStore::pages`] needs the store itself, and not the `FsStore`
    /// wrapper.
    /// Then a walk can outlive a method call.
    /// The rebuild diff holds two walks open at once, one for each side.
    pub(crate) fn kv_handle(&self) -> Arc<RwLock<OxKvStore>> {
        Arc::clone(&self.inner)
    }

    /// A key-ordered, paginated walk over the whole keyspace.
    pub(crate) fn pages(&self) -> KvPages {
        KvPages::new(self.kv_handle())
    }
}

/// The number of keys that a [`KvPages`] walk fetches per round trip.
///
/// This number is the memory ceiling of a paged walk, and not the
/// keyspace.
/// The value is large enough that the inclusive cursor resume below never
/// receives a page that holds only the duplicate key.
/// The value is small enough that a full scan of a large replica is not
/// one large allocation.
const SCAN_PAGE: u32 = 512;

/// A key-ordered walk over an oxkv store. The walk holds one page at a
/// time.
///
/// `gets_bytes` with a `None` limit returns the whole keyspace.
/// Anything built on that call uses memory that grows with the keyspace,
/// however carefully the caller iterates.
/// The replica rebuild therefore held about three copies of the data of
/// one user.
/// The copies were the master file list, the new scratch replica, and the
/// live replica that the code compared them with. Each copy was a
/// collection.
///
/// This walk uses pages instead.
/// Both sides of a rebuild diff are key-ordered, so the engine can merge
/// them together and compare them one record at a time.
pub(crate) struct KvPages {
    store: Arc<RwLock<OxKvStore>>,
    /// Inclusive resume point. The value is `None` until the first page.
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

    /// Starts a walk over a handle that only this walk owns.
    /// The replica side uses this call, because it is not wrapped in an
    /// [`FsStore`].
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

        // The bounds of `gets_bytes` are inclusive, so a page that
        // resumes returns the resume key as its first entry.
        // The walk drops exactly that entry, and nothing else, so that it
        // does not visit one key again.
        // The code cannot nudge the key instead.
        // Keys are arbitrary byte strings, and "the next key after X" is
        // not a key that the store can return.
        if self
            .cursor
            .as_ref()
            .is_some_and(|resume| page.first().is_some_and(|kv| kv.key == *resume))
        {
            page.remove(0);
        }

        if page.is_empty() {
            // The keyspace is empty, or the last key of the previous page
            // was the final key.
            // `SCAN_PAGE > 1` makes this case safe.
            // A page that holds only the resume key means that no key comes
            // after it.
            // The page never means that the limit cut the result to one
            // entry.
            self.exhausted = true;
            return Ok(None);
        }

        self.cursor = page.last().map(|kv| kv.key.clone());
        self.buffer = page.into_iter();
        Ok(self.buffer.next())
    }
}

/// Reads the ref-count info through any [`GetSet`] handle, which is a
/// store or a transaction.
/// An absent entry means "never attached".
///
/// `primary` carries the mark of the owning store, because a transaction
/// is not an `FsStore`.
/// A fencing loss on this read must still reach the latch when the read is
/// part of a master mutation.
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

/// The exclusive upper bound for a `prefix:` range scan (`:` -> `;`).
///
/// Every key that starts with `prefix:` sorts strictly below the bound.
/// The engine can then stop at the end of the key family, instead of
/// walking the rest of the store.
/// No stored key is ever equal to the bare prefix.
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
    /// The master and replica split is the whole point of the latch.
    /// This test checks the half that a test can assert without the
    /// process-wide signal.
    /// `sync` recovers a replica write that loses a build race, so a latch
    /// would pull a healthy server out of rotation for an event that does
    /// not matter.
    /// A failure on the master that is not a fencing loss is a plain 500.
    /// That failure must not latch either.
    /// Otherwise a flaky S3 would read as a lost lease.
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

    /// One write method.
    /// The type boxes the method, so that the table below can hold closures
    /// with different bodies.
    type WriteFn =
        fn(&FsStore) -> futures_util::future::BoxFuture<'_, Result<(), crate::fs::error::FsError>>;

    /// A master write that loses its epoch must latch, whichever method
    /// performs the write.
    ///
    /// The predicate above is not enough, and this test proves it.
    /// Six of the nine write methods converted the `oxkv` error with a
    /// bare `map_err(FsError::from)`.
    /// The classification was correct, and the *report* never happened.
    /// `POST /fs/{id}/complete` returned 500 on `save_file`, before the WAL
    /// announce ran.
    /// At the same time, `fencing::primary_loss()` stayed false and
    /// `/ready` returned 200.
    /// The instance served traffic that it could not write, and no signal
    /// reported it.
    ///
    /// This test drives a real `oxkv` handle into `StoreError::Fenced`.
    /// A second session over the same prefix takes the epoch.
    /// The test then checks the latch of each write on a private latch,
    /// and not on the process-wide latch.
    /// An assertion against the process-wide flag would pass with no code at
    /// all.
    /// The flag is one-way and has no reset, so `fencing::tests` trips it
    /// first.
    /// That would satisfy this test even if every call site were removed.
    #[tokio::test]
    async fn every_master_write_latches_on_a_lost_epoch() {
        // Every write method that stores or removes a key. The
        // name in the table says which method stopped reporting.
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
            // `attach` on the row that the seed already linked takes its
            // idempotent read-back path and never writes.
            // The test therefore gives `attach` a row of its own.
            // `detach` uses the seeded row.
            ("attach", |s| {
                Box::pin(async move { s.attach("invoice", "2", "latch-file").await.map(|_| ()) })
            }),
            ("detach", |s| {
                Box::pin(async move { s.detach("invoice", "1", "latch-file").await.map(|_| ()) })
            }),
        ];

        for (name, write) in writes {
            // Each method uses a new latch.
            // Otherwise the first latch that trips would satisfy every
            // assertion after it.
            // The list would then prove only its own first entry.
            // The code uses `Box::leak` because the field is a `&'static`.
            // This matches a production store that holds the process-wide
            // latch.
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
    /// This test checks the other direction of the master and replica
    /// split.
    /// This direction decides whether the mechanism is usable at all.
    /// `sync` recovers a replica race by adopting the coverage of the
    /// winner.
    /// A latch would take a healthy server out of rotation for an event
    /// that does not matter.
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

    /// A store that a second session has fenced.
    /// The store holds the keys that every write above targets.
    ///
    /// The seeding comes first, and the order matters.
    /// The `delete` of `oxkv` on a missing key is a read.
    /// That read returns `Ok(false)` without consulting `ownership.json`.
    /// A delete against an empty store would then succeed on a fenced
    /// handle, and the test would assert nothing.
    /// A delete that has something to delete reaches the WAL put, and it is
    /// fenced there, as it is in production.
    ///
    /// The function returns the fenced store and the session that fenced
    /// it.
    /// The holder must outlive the store.
    /// An `oxkv` handle fences another handle only while it is alive.
    /// Dropping the holder would make the test assert nothing.
    async fn fenced_store(
        name: &str,
        latch: &'static Latch,
        primary: bool,
    ) -> (FsStore, oxkv::OxKvStore) {
        let prefix = crate::db::test_prefix(name);
        let inner =
            Arc::new(object_store::memory::InMemory::new()) as Arc<dyn object_store::ObjectStore>;
        let handle = crate::db::build_test_store_new_session(Arc::clone(&inner), &prefix).await;
        // A clone shares the session, so a seed write through the
        // clone is a write by the handle under test.
        seed_delete_targets(&FsStore::primary(handle.clone())).await;

        // A second session over the same prefix runs a CAS on the
        // epoch and fences the first session.
        // This is exactly what an uncooperative second writer does.
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

    /// Writes a session, a multipart record, and an attached file.
    /// The delete and detach paths then have something to act on.
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
    /// `gets_bytes` takes *inclusive* cursor bounds.
    /// A walk that resumes from the last key of a page gets that same key
    /// back as the first entry of the next page.
    /// A wrong implementation then loops for ever on one key.
    /// If the removal of the duplicate is too eager, the walk skips keys
    /// instead.
    /// In the replica rebuild, a skipped key means that a file of the user
    /// never appears in the replica, and no error reports it.
    ///
    /// The test spans several pages on purpose.
    /// A page boundary is the only place that the inclusive cursor
    /// handling is tested.
    /// A single page walk would pass even with the removal of the
    /// duplicate gone.
    #[tokio::test]
    async fn paged_walk_visits_every_key_exactly_once() {
        /// The test uses more keys than `SCAN_PAGE`, so at least one page
        /// boundary falls strictly inside the keyspace.
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
    /// sizes where an off-by-one error in the boundary handling stays
    /// hidden.
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

    /// One `delete_session` deletes the session, its staged parts, and its
    /// multipart record.
    /// The raw keyspace then holds none of them.
    ///
    /// The raw reads matter because the order decides what a *later* scan
    /// can still find.
    /// `list_sessions` walks `fs:uploads:`.
    /// Nothing in the crate walks `fs:mp:`.
    /// A session row that is not deleted yet is then the only thing that
    /// makes a stranded multipart record reachable again.
    /// For that reason the row goes last, and the cascade must succeed
    /// before it goes.
    #[tokio::test]
    async fn one_delete_session_clears_the_row_and_every_cascade_row() -> anyhow::Result<()> {
        let store = test_store().await;
        let mut sess = sample_session("sess-cascade");
        sess.file_total_parts = 2;
        sess.etags = vec![None, None];
        sess.checksums = vec![None, None];
        sess.s3_upload_id = Some("up-cascade".into());
        store.save_session(&sess).await?;
        store
            .save_multipart(&sample_multipart("up-cascade"))
            .await?;
        store
            .save_staged_part("sess-cascade", 0, b"a".to_vec())
            .await?;
        store
            .save_staged_part("sess-cascade", 1, b"b".to_vec())
            .await?;

        store.delete_session("sess-cascade").await?;

        assert!(store.get_session("sess-cascade").await?.is_none());
        assert!(store.load_multipart("up-cascade").await?.is_none());
        let handle = store.inner.read().await;
        for key in [
            "fs:uploads:sess-cascade:meta",
            "fs:uploads:sess-cascade:part:0",
            "fs:uploads:sess-cascade:part:1",
            "fs:mp:up-cascade",
        ] {
            assert!(
                handle.get_bytes(key).await?.is_none(),
                "{key} survived the session delete"
            );
        }
        Ok(())
    }

    /// Every delete in `delete_file` reports its error.
    ///
    /// The doc above promises that the record, its ref-count entry, and
    /// every relation marker are removed "atomically".
    /// Five of the six deletes in the transaction mapped their error
    /// through `store_err`.
    /// The delete of the ref-count entry read `let _ = tx.delete(&refs).await`.
    /// A failure of that delete then committed the transaction anyway.
    /// `fs:files:{id}:refs` then held `count > 0` for a file whose record
    /// and relation markers were already gone.
    ///
    /// The damage is limited today.
    /// The ids are uuidv7 and are never reused, and `attach` requires the
    /// record to exist.
    /// The problem is therefore a possible inconsistency, and not current
    /// corruption.
    /// It is still an error that the code discards, and it affects the
    /// exact rule that an earlier commit claimed to be atomic.
    /// The cost of finding this later is that the claim was false.
    ///
    /// The test reads the source because the failure needs a delete that
    /// fails while its siblings in the same transaction succeed.
    /// A concrete `OxKvStore` does not do that on demand.
    /// The shape of the code is what regressed.
    /// A single-threaded test cannot observe the behaviour.
    #[test]
    fn delete_file_reports_every_delete_error() {
        let src = std::fs::read_to_string("src/fs/store.rs").expect("read store.rs");
        let body = src
            .split_once("pub async fn delete_file")
            .expect("delete_file exists")
            .1
            .split_once("\n    /// ")
            .expect("the next doc comment ends the body")
            .0;
        assert!(
            !body.contains("let _ ="),
            "a delete in delete_file still discards its error:\n{body}"
        );
        let mut rest = body;
        let mut deletes = 0;
        while let Some(at) = rest.find("tx.delete(") {
            deletes += 1;
            let statement = &rest[at..];
            let end = statement.find(';').expect("a delete statement ends");
            assert!(
                statement[..end].contains("store_err"),
                "a delete in delete_file does not report its error:\n{body}"
            );
            rest = &statement[end..];
        }
        assert_eq!(deletes, 3, "the record, the refs and the markers");
    }

    /// The cascade rows go first, and the session key last, in one
    /// transaction, and no result is discarded.
    ///
    /// The test reads the source because the failure that it guards needs a
    /// delete that fails partway through.
    /// A test cannot arrange such a failure.
    /// The store is a concrete `OxKvStore` over an in-memory backend.
    /// The validators of `HookStore` in `oxkv` reject `set_bytes` only,
    /// and never a `delete`.
    /// Fencing fails the first write, whatever the order.
    /// Fencing cannot tell the two orders apart.
    /// The old body is different only in its shape.
    /// The shape was one cascade key written before the session key,
    /// inside a transaction, with no `let _ =` in it.
    /// The shape is what regressed.
    ///
    /// The test `one_delete_session_clears_the_row_and_every_cascade_row`
    /// checks the behaviour.
    /// This test pins the order that a single-threaded test cannot
    /// observe, because the order matters only on the failure path.
    #[test]
    fn delete_session_cascades_before_the_row_and_discards_nothing() {
        let src = std::fs::read_to_string("src/fs/store.rs").expect("read store.rs");
        let body = src
            .split_once("pub async fn delete_session")
            .expect("delete_session exists")
            .1
            .split_once("\n    /// ")
            .expect("the next doc comment ends the body")
            .0;
        let at = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("`{needle}` is not in delete_session:\n{body}"))
        };

        assert!(
            body.contains("begin_tx") && body.contains("tx.commit()"),
            "the cascade and the session key must commit together:\n{body}"
        );
        assert!(
            !body.contains("let _ ="),
            "a cascade result is still discarded:\n{body}"
        );
        for cascade in ["Self::staged_key", "Self::multipart_key"] {
            assert!(
                at(cascade) < at("Self::session_key"),
                "{cascade} must be deleted before the session key, which is what makes the \
                 cascade findable again:\n{body}"
            );
        }
        assert!(
            at("Self::session_key") < at("tx.commit()"),
            "the session key must be staged last, before the single commit:\n{body}"
        );
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
        // No marker and no ref-count entry stays behind.
        assert!(store.rows_for_file("rel-file").await?.is_empty());
        assert_eq!(store.get_ref_info("rel-file").await?.count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn mirrored_store_serves_reads() -> anyhow::Result<()> {
        // The writes land before and after the mirror opens.
        // A key that already exists arrives through fall-through and warm.
        // A later key arrives through refresh.
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
        // The first refresh converges the writes that already existed.
        // The engine uses WAL replay or warm, depending on what compacted.
        // The reads then give correct results.
        assert!(mirrored.refresh_mirror().await? > 0);
        assert_eq!(mirrored.get_file("mirror-1").await?.unwrap().name, "m.txt");
        assert_eq!(mirrored.list_files().await?.records.len(), 1);
        assert_eq!(
            mirrored.rows_for_file("mirror-1").await?,
            vec![("invoice".to_string(), "7".to_string())]
        );
        assert_eq!(mirrored.get_ref_info("mirror-1").await?.count, 1);

        // A write through the plain handle converges on the next refresh.
        // A second refresh with no writes does nothing except check the
        // manifest.
        plain.detach("invoice", "7", "mirror-1").await?;
        mirrored.refresh_mirror().await?;
        assert!(mirrored.rows_for_file("mirror-1").await?.is_empty());
        assert_eq!(mirrored.get_ref_info("mirror-1").await?.count, 0);
        assert_eq!(mirrored.refresh_mirror().await?, 0);
        Ok(())
    }

    /// Clones the underlying handle for the mirror tests.
    /// The clone shares the session.
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
