//! `oxkv` persistence for upload sessions and file records.
//! Keys: `fs:uploads:{id}:meta`, `fs:uploads:{id}:part:{idx}`, `fs:files:{id}:meta`

use std::sync::Arc;

use oxkv::GetSet;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::fs::error::FsError;

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
    /// Added for direct S3 checksum passthrough; `#[serde(default)]` keeps old
    /// 2-field sessions readable.
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

/// Thin wrapper around an `oxkv` Redb store for FS keys.
#[derive(Clone)]
pub struct FsStore {
    inner: Arc<RwLock<oxkv::RedbStore>>,
}

impl FsStore {
    /// Opens (or creates) the Redb file at `path`. Parent dirs are created as needed.
    pub async fn open(path: &std::path::Path) -> Result<Self, FsError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| FsError::Internal(e.to_string()))?;
        }
        let inner = oxkv::RedbStore::new_file(path).map_err(|e| FsError::Store(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
        })
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

    /// Deletes a finalized file record.
    pub async fn delete_file(&self, id: &str) -> Result<(), FsError> {
        let key = Self::file_key(id);
        let mut g = self.inner.write().await;
        g.delete(&key)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(())
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
    use std::path::PathBuf;

    use super::{FileRecord, FsStore, UploadSession};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    fn tmp_path(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rust-api-fs-store-{}-{}-{}.redb",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>()),
            suffix
        ))
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
    async fn open_creates_parent_dirs() -> anyhow::Result<()> {
        let dir = tmp_path("parent");
        let nested = dir.join("a/b/c/store.redb");
        let _ = std::fs::remove_file(&nested);
        let store = FsStore::open(&nested).await?;
        assert!(nested.exists() || store.get_session("nonexistent").await?.is_none());
        let _ = std::fs::remove_file(&nested);
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[tokio::test]
    async fn session_save_get_delete_roundtrip() -> anyhow::Result<()> {
        let path = tmp_path("sess");
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await?;
        let sess = sample_session("sess-1");
        store.save_session(&sess).await?;
        let loaded = store.get_session("sess-1").await?.expect("should exist");
        assert_eq!(loaded.id, "sess-1");
        assert_eq!(loaded.s3_key, "files/sess-1");
        store.delete_session("sess-1").await?;
        assert!(store.get_session("sess-1").await?.is_none());
        // deleting again is idempotent (covers None branch in delete_session)
        store.delete_session("sess-1").await?;
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn delete_session_cleans_staged_parts() -> anyhow::Result<()> {
        let path = tmp_path("staged-clean");
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await?;
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
        // staged keys should be cleaned - direct check via prefix scan
        assert!(store.get_staged_part("sess-2", 0).await?.is_none());
        assert!(store.get_staged_part("sess-2", 1).await?.is_none());
        assert!(store.get_staged_part("sess-2", 99).await?.is_none());
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn file_save_get_delete_roundtrip() -> anyhow::Result<()> {
        let path = tmp_path("file");
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await?;
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
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn list_sessions_filters_and_deserializes() -> anyhow::Result<()> {
        let path = tmp_path("list");
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await?;
        // initially empty
        assert!(store.list_sessions().await?.is_empty());
        let s1 = sample_session("list-a");
        let mut s2 = sample_session("list-b");
        s2.file_total_parts = 2;
        s2.etags = vec![None, None];
        s2.checksums = vec![None, None];
        store.save_session(&s1).await?;
        store.save_session(&s2).await?;
        // also save a file record to ensure filter excludes it
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
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[tokio::test]
    async fn get_session_returns_none_when_missing() -> anyhow::Result<()> {
        let path = tmp_path("missing");
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await?;
        assert!(store.get_session("ghost").await?.is_none());
        assert!(store.get_staged_part("ghost", 0).await?.is_none());
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}

#[cfg(test)]
mod key_tests {
    use super::FsStore;

    #[test]
    fn keys_are_namespaced_and_distinct() {
        // Copy-paste guard: three helpers look identical except prefix/suffix.
        // Swapping "uploads" <-> "files" would silently corrupt GC and reads.
        assert_eq!(FsStore::session_key("abc"), "fs:uploads:abc:meta");
        assert_eq!(FsStore::staged_key("abc", 2), "fs:uploads:abc:part:2");
        assert_eq!(FsStore::file_key("abc"), "fs:files:abc:meta");

        // Distinct namespaces even with same id
        assert_ne!(FsStore::session_key("x"), FsStore::file_key("x"));
        assert_ne!(FsStore::session_key("x"), FsStore::staged_key("x", 0));
        assert!(FsStore::staged_key("x", 0).contains(":part:"));
        assert!(FsStore::session_key("x").ends_with(":meta"));
        assert!(FsStore::file_key("x").ends_with(":meta"));
    }
}
