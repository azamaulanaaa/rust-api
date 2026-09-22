//! `oxkv` persistence for upload sessions, file records, and relations.
//! Backed by [`oxkv::OxKvStore`] (LSM on S3). Keys: `fs:uploads:{id}:meta`, `fs:files:{id}:meta`, `fs:rel:{type}:{id}:{file}`, `fs:files:{id}:refs`.
//! Scales per-user: each OxKvStore is prefix-scoped (e.g. `oxkv/fs`) on the shared `ObjectStore`.

use std::sync::Arc;

use oxkv::{
    CachedOxKvStore, Direction, GetSet, KeyValue, OxKvStore, Store as _, Transaction as _, WarmMode,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::fs::error::FsError;
use crate::fs::relation::{REL_PREFIX, RefInfo, refs_key, rel_key};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    /// File identifier.
    pub id: String,
    /// Original filename.
    pub name: String,
    /// MIME type.
    pub mimetype: String,
    /// Size in bytes.
    pub size: u64,
    /// S3 key.
    pub s3_key: String,
    /// Owner subject.
    pub owner_sub: String,
    /// Creation timestamp.
    pub created_at: i64,
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
}

impl FsStore {
    /// Creates an FS store from an [`OxKvStore`] (per-user S3, scalable).
    pub fn new(s3_store: OxKvStore) -> Self {
        Self {
            inner: Arc::new(RwLock::new(s3_store)),
            mirror: None,
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
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(RwLock::new(s3_store)),
            mirror: Some(mirror),
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
        let applied = mirror
            .refresh()
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        tracing::debug!(applied, "fs mirror refreshed");
        Ok(applied)
    }

    /// Point read through the single shared handle (mirror first).
    async fn get_one(&self, key: &str) -> Result<Option<Vec<u8>>, FsError> {
        if let Some(mirror) = &self.mirror {
            return mirror
                .get_bytes(key)
                .await
                .map_err(|e| FsError::Store(e.to_string()));
        }
        let g = self.inner.read().await;
        g.get_bytes(key)
            .await
            .map_err(|e| FsError::Store(e.to_string()))
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
                .map_err(|e| FsError::Store(e.to_string()));
        }
        let g = self.inner.read().await;
        g.gets_bytes(None, Direction::Next, cursor)
            .await
            .map_err(|e| FsError::Store(e.to_string()))
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
        format!("fs:files:{id}:meta")
    }

    /// Persists an upload session.
    pub async fn save_session(&self, s: &UploadSession) -> Result<(), FsError> {
        let key = Self::session_key(&s.id);
        let val = serde_json::to_vec(s).map_err(|e| FsError::Internal(e.to_string()))?;
        let g = self.inner.write().await;
        g.set_bytes(&key, &val)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
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
            g.delete(&key)
                .await
                .map_err(|e| FsError::Store(e.to_string()))?;
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
            .map_err(|e| FsError::Store(e.to_string()))?;
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
        g.delete(&key)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(())
    }

    /// Stages a single-part chunk in the store (only for `total_parts == 1`).
    pub async fn save_staged_part(&self, id: &str, idx: u64, data: Vec<u8>) -> Result<(), FsError> {
        let key = Self::staged_key(id, idx);
        let g = self.inner.write().await;
        g.set_bytes(&key, &data)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(())
    }

    /// Loads a staged single-part chunk.
    pub async fn get_staged_part(&self, id: &str, idx: u64) -> Result<Option<Vec<u8>>, FsError> {
        let key = Self::staged_key(id, idx);
        Ok(self.get_one(&key).await?)
    }

    /// Persists a finalized file record.
    pub async fn save_file(&self, rec: &FileRecord) -> Result<(), FsError> {
        let key = Self::file_key(&rec.id);
        let val = serde_json::to_vec(rec).map_err(|e| FsError::Internal(e.to_string()))?;
        let g = self.inner.write().await;
        g.set_bytes(&key, &val)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
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
        let tx = g.begin_tx().map_err(store_err)?;
        let suffix = format!(":{id}");
        let cursor = (
            Some(REL_PREFIX.to_string()),
            Some(prefix_scan_end(REL_PREFIX)),
        );
        let kvs = tx
            .gets_bytes(None, Direction::Next, cursor)
            .await
            .map_err(store_err)?;
        for kv in &kvs {
            if kv.key.starts_with(REL_PREFIX) && kv.key.ends_with(&suffix) {
                tx.delete(&kv.key).await.map_err(store_err)?;
            }
        }
        tx.delete(&key).await.map_err(store_err)?;
        let _ = tx.delete(&refs).await;
        tx.commit().await.map_err(store_err)?;
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
        let tx = g.begin_tx().map_err(store_err)?;
        if tx.get_bytes(&rel).await.map_err(store_err)?.is_some() {
            let info = read_ref_info(&tx, file_id).await?;
            tx.rollback().await.map_err(store_err)?;
            return Ok(info.count);
        }
        let mut info = read_ref_info(&tx, file_id).await?;
        info.count = info.count.saturating_add(1);
        info.orphan_since = None;
        tx.set_bytes(&rel, b"1").await.map_err(store_err)?;
        let val = serde_json::to_vec(&info).map_err(|e| FsError::Internal(e.to_string()))?;
        tx.set_bytes(&refs, &val).await.map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
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
        let tx = g.begin_tx().map_err(store_err)?;
        if tx.get_bytes(&rel).await.map_err(store_err)?.is_none() {
            let info = read_ref_info(&tx, file_id).await?;
            tx.rollback().await.map_err(store_err)?;
            return Ok(info.count);
        }
        let mut info = read_ref_info(&tx, file_id).await?;
        tx.delete(&rel).await.map_err(store_err)?;
        info.count = info.count.saturating_sub(1);
        if info.count == 0 {
            info.orphan_since = Some(chrono::Utc::now().timestamp());
        }
        let val = serde_json::to_vec(&info).map_err(|e| FsError::Internal(e.to_string()))?;
        tx.set_bytes(&refs, &val).await.map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(info.count)
    }

    /// Lists rows referencing a file (scan bounded to `fs:rel:`).
    pub async fn rows_for_file(&self, file_id: &str) -> Result<Vec<(String, String)>, FsError> {
        let suffix = format!(":{file_id}");
        let kvs = self.scan_prefix(crate::fs::relation::REL_PREFIX).await?;
        let mut out = Vec::new();
        for kv in kvs {
            if kv.key.starts_with(crate::fs::relation::REL_PREFIX) && kv.key.ends_with(&suffix) {
                let rest = &kv.key[crate::fs::relation::REL_PREFIX.len()..];
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
    pub async fn list_files(&self) -> Result<Vec<FileRecord>, FsError> {
        let kvs = self.scan_prefix("fs:files:").await?;
        let mut out = Vec::new();
        for kv in kvs {
            if kv.key.starts_with("fs:files:")
                && kv.key.ends_with(":meta")
                && let Ok(r) = serde_json::from_slice::<FileRecord>(&kv.value)
            {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// Lists all upload sessions (scan bounded to `fs:uploads:`).
    pub async fn list_sessions(&self) -> Result<Vec<UploadSession>, FsError> {
        let kvs = self.scan_prefix("fs:uploads:").await?;
        let mut out = Vec::new();
        for kv in kvs {
            if kv.key.starts_with("fs:uploads:")
                && kv.key.ends_with(":meta")
                && let Ok(s) = serde_json::from_slice::<UploadSession>(&kv.value)
            {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Dumps every raw key-value pair for verbatim replica copies.
    ///
    /// The caller owns filtering: everything present is returned as-is.
    pub(crate) async fn dump_kvs(&self) -> Result<Vec<(String, Vec<u8>)>, FsError> {
        use oxkv::Direction;
        let g = self.inner.read().await;
        let kvs = g
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(kvs.into_iter().map(|kv| (kv.key, kv.value)).collect())
    }
}

/// Maps oxkv errors into [`FsError`].
fn store_err(e: oxkv::StoreError) -> FsError {
    FsError::Store(e.to_string())
}

/// Reads ref-count info through any [`GetSet`] handle (store or
/// transaction); absent entries mean "never attached".
async fn read_ref_info<T: GetSet>(tx: &T, file_id: &str) -> Result<RefInfo, FsError> {
    let key = refs_key(file_id);
    let Some(bytes) = tx.get_bytes(&key).await.map_err(store_err)? else {
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
mod store_tests {
    use super::{FileRecord, FsStore, PersistedMultipart, UploadSession};
    use crate::db::build_test_store;

    async fn test_store() -> FsStore {
        let prefix = {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            format!(
                "test-fs-{}-{}",
                std::process::id(),
                URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
            )
        };
        let s3 = build_test_store(&prefix).await;
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
        assert_eq!(mirrored.list_files().await?.len(), 1);
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
        assert!(store.list_sessions().await?.is_empty());
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
        let mut sessions = store.list_sessions().await?;
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
}

#[cfg(test)]
mod key_tests {
    use super::FsStore;

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
