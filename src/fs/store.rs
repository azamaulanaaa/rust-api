//! `oxkv` persistence for upload sessions, file records, and relations.
//! Backed by [`oxkv::S3Store`] (LSM on S3). Keys: `fs:uploads:{id}:meta`, `fs:files:{id}:meta`, `fs:rel:{type}:{id}:{file}`, `fs:files:{id}:refs`.
//! Scales per-user: each S3Store is prefix-scoped (e.g. `oxkv/fs`) on the shared `ObjectStore`; no per-user Redb file.

use std::sync::Arc;

use oxkv::{GetSet, S3Store};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::fs::error::FsError;
use crate::fs::relation::{RefInfo, refs_key, rel_key};

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

/// Persisted file record after `CompleteUpload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Thin wrapper around an `oxkv` S3 store for FS keys.
#[derive(Clone)]
pub struct FsStore {
    inner: Arc<RwLock<S3Store>>,
}

impl FsStore {
    /// Creates an FS store from an [`S3Store`] (per-user S3, scalable).
    pub fn new(s3_store: S3Store) -> Self {
        Self {
            inner: Arc::new(RwLock::new(s3_store)),
        }
    }

    fn session_key(id: &str) -> String {
        format!("fs:uploads:{id}:meta")
    }
    fn staged_key(id: &str, idx: u64) -> String {
        format!("fs:uploads:{id}:part:{idx}")
    }
    fn file_key(id: &str) -> String {
        format!("fs:files:{id}:meta")
    }

    /// Persists an upload session.
    pub async fn save_session(&self, s: &UploadSession) -> Result<(), FsError> {
        let key = Self::session_key(&s.id);
        let val = serde_json::to_vec(s).map_err(|e| FsError::Internal(e.to_string()))?;
        let mut g = self.inner.write().await;
        g.set_bytes(&key, &val)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(())
    }

    /// Loads an upload session by file id.
    pub async fn get_session(&self, id: &str) -> Result<Option<UploadSession>, FsError> {
        let key = Self::session_key(id);
        let g = self.inner.read().await;
        let Some(bytes) = g
            .get_bytes(&key)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?
        else {
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
            let mut g = self.inner.write().await;
            g.delete(&key)
                .await
                .map_err(|e| FsError::Store(e.to_string()))?;
            if let Some(s) = session {
                for idx in 0..s.file_total_parts {
                    let k = Self::staged_key(id, idx);
                    let _ = g.delete(&k).await;
                }
            }
        }
        Ok(())
    }

    /// Stages a single-part chunk in the store (only for `total_parts == 1`).
    pub async fn save_staged_part(&self, id: &str, idx: u64, data: Vec<u8>) -> Result<(), FsError> {
        let key = Self::staged_key(id, idx);
        let mut g = self.inner.write().await;
        g.set_bytes(&key, &data)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(())
    }

    /// Loads a staged single-part chunk.
    pub async fn get_staged_part(&self, id: &str, idx: u64) -> Result<Option<Vec<u8>>, FsError> {
        let key = Self::staged_key(id, idx);
        let g = self.inner.read().await;
        let Some(bytes) = g
            .get_bytes(&key)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?
        else {
            return Ok(None);
        };
        Ok(Some(bytes))
    }

    /// Persists a finalized file record.
    pub async fn save_file(&self, rec: &FileRecord) -> Result<(), FsError> {
        let key = Self::file_key(&rec.id);
        let val = serde_json::to_vec(rec).map_err(|e| FsError::Internal(e.to_string()))?;
        let mut g = self.inner.write().await;
        g.set_bytes(&key, &val)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(())
    }

    /// Loads a finalized file record.
    pub async fn get_file(&self, id: &str) -> Result<Option<FileRecord>, FsError> {
        let key = Self::file_key(id);
        let g = self.inner.read().await;
        let Some(bytes) = g
            .get_bytes(&key)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?
        else {
            return Ok(None);
        };
        let r = serde_json::from_slice(&bytes).map_err(|e| FsError::Internal(e.to_string()))?;
        Ok(Some(r))
    }

    /// Deletes a finalized file record and its ref-count entry.
    pub async fn delete_file(&self, id: &str) -> Result<(), FsError> {
        let key = Self::file_key(id);
        let refs = refs_key(id);
        let mut g = self.inner.write().await;
        g.delete(&key)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        let _ = g.delete(&refs).await;
        Ok(())
    }

    /// Returns ref-count info for a file (0 if never attached).
    pub async fn get_ref_info(&self, file_id: &str) -> Result<RefInfo, FsError> {
        let key = refs_key(file_id);
        let g = self.inner.read().await;
        let Some(bytes) = g
            .get_bytes(&key)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?
        else {
            return Ok(RefInfo::default());
        };
        let info = serde_json::from_slice(&bytes).map_err(|e| FsError::Internal(e.to_string()))?;
        Ok(info)
    }

    /// Attaches a file to a row; idempotent.
    pub async fn attach(
        &self,
        row_type: &str,
        row_id: &str,
        file_id: &str,
    ) -> Result<u32, FsError> {
        let rel = rel_key(row_type, row_id, file_id);
        let refs = refs_key(file_id);
        let mut g = self.inner.write().await;
        if g.get_bytes(&rel)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?
            .is_some()
        {
            let info = self.get_ref_info_inner(&g, file_id).await?;
            return Ok(info.count);
        }
        let mut info = self.get_ref_info_inner(&g, file_id).await?;
        info.count = info.count.saturating_add(1);
        info.orphan_since = None;
        g.set_bytes(&rel, b"1")
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        let val = serde_json::to_vec(&info).map_err(|e| FsError::Internal(e.to_string()))?;
        g.set_bytes(&refs, &val)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(info.count)
    }

    /// Detaches a file from a row; idempotent.
    pub async fn detach(
        &self,
        row_type: &str,
        row_id: &str,
        file_id: &str,
    ) -> Result<u32, FsError> {
        let rel = rel_key(row_type, row_id, file_id);
        let refs = refs_key(file_id);
        let mut g = self.inner.write().await;
        if g.get_bytes(&rel)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?
            .is_none()
        {
            let info = self.get_ref_info_inner(&g, file_id).await?;
            return Ok(info.count);
        }
        let mut info = self.get_ref_info_inner(&g, file_id).await?;
        g.delete(&rel)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        info.count = info.count.saturating_sub(1);
        if info.count == 0 {
            info.orphan_since = Some(chrono::Utc::now().timestamp());
        }
        let val = serde_json::to_vec(&info).map_err(|e| FsError::Internal(e.to_string()))?;
        g.set_bytes(&refs, &val)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(info.count)
    }

    async fn get_ref_info_inner(&self, g: &S3Store, file_id: &str) -> Result<RefInfo, FsError> {
        let key = refs_key(file_id);
        let Some(bytes) = g
            .get_bytes(&key)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?
        else {
            return Ok(RefInfo::default());
        };
        serde_json::from_slice(&bytes).map_err(|e| FsError::Internal(e.to_string()))
    }

    /// Lists rows referencing a file.
    pub async fn rows_for_file(&self, file_id: &str) -> Result<Vec<(String, String)>, FsError> {
        use oxkv::Direction;
        let suffix = format!(":{file_id}");
        let g = self.inner.read().await;
        let kvs = g
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
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

    /// Lists all finalized file records.
    pub async fn list_files(&self) -> Result<Vec<FileRecord>, FsError> {
        use oxkv::Direction;
        let g = self.inner.read().await;
        let kvs = g
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
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

    /// Lists all upload sessions (scans `fs:uploads:*:meta`).
    pub async fn list_sessions(&self) -> Result<Vec<UploadSession>, FsError> {
        use oxkv::Direction;
        let g = self.inner.read().await;
        let kvs = g
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
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
}

#[cfg(test)]
mod store_tests {
    use super::{FileRecord, FsStore, UploadSession};
    use crate::db::build_test_store;
    use crate::unwrap_ext::UnwrapExt;

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

    #[tokio::test]
    async fn session_save_get_delete_roundtrip() -> anyhow::Result<()> {
        let store = test_store().await;
        let sess = sample_session("sess-1");
        store.save_session(&sess).await?;
        let loaded = store.get_session("sess-1").await?.expect_or_panic("should exist");
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
            store.get_staged_part("sess-2", 0).await?.unwrap_or_panic(),
            b"chunk0"
        );
        assert_eq!(
            store.get_staged_part("sess-2", 1).await?.unwrap_or_panic(),
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
        let loaded = store.get_file("file-1").await?.unwrap_or_panic();
        assert_eq!(loaded.name, "hello.txt");
        assert_eq!(loaded.mimetype, "text/plain");
        store.delete_file("file-1").await?;
        assert!(store.get_file("file-1").await?.is_none());
        assert!(store.get_file("nonexistent").await?.is_none());
        Ok(())
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
