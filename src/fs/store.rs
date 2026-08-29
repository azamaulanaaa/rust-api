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
            if kv.key.starts_with("fs:uploads:") && kv.key.ends_with(":meta") {
                if let Ok(s) = serde_json::from_slice::<UploadSession>(&kv.value) {
                    out.push(s);
                }
            }
        }
        Ok(out)
    }
}
