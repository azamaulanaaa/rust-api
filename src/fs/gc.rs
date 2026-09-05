//! GC for abandoned uploads and orphaned files.
//!
//! Sessions and temp/orphaned files older than 24h are removed.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::interval;

use crate::fs::FsEngine;

/// TTL for abandoned sessions and orphaned files.
pub const TTL_SECS: i64 = 24 * 3600;

/// Spawn sweeper that runs every hour.
pub fn spawn(engine: Arc<FsEngine>) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            if let Err(e) = sweep_once(&engine).await {
                tracing::warn!("fs gc sweep failed: {e}");
            }
        }
    });
}

/// Single sweep: sessions and orphaned files.
#[tracing::instrument(skip(engine), err)]
pub async fn sweep_once(engine: &FsEngine) -> Result<usize, crate::fs::error::FsError> {
    let now = chrono::Utc::now().timestamp();
    let mut cleaned = 0;

    // sessions
    for s in engine.store.list_sessions().await? {
        if now - s.created_at <= TTL_SECS {
            continue;
        }
        tracing::info!(
            "fs gc expiring upload {} (age {}s)",
            s.id,
            now - s.created_at
        );
        if let Some(upload_id) = s.s3_upload_id.as_deref() {
            let _ = engine
                .s3
                .abort_multipart_upload(&engine.bucket, &s.s3_key, upload_id)
                .await
                .map_err(|e| {
                    tracing::warn!("gc abort {} failed: {e}", s.id);
                    e
                });
        } else {
            let _ = engine.s3.delete_object(&engine.bucket, &s.s3_key).await;
        }
        engine.store.delete_session(&s.id).await?;
        cleaned += 1;
    }

    // orphaned / temp files
    for f in engine.store.list_files().await? {
        let info = engine.store.get_ref_info(&f.id).await?;
        if info.count != 0 {
            continue;
        }
        let age = info.orphan_since.unwrap_or(f.created_at);
        if now - age <= TTL_SECS {
            continue;
        }
        tracing::info!("fs gc expiring file {} (age {}s)", f.id, now - age);
        let _ = engine.s3.delete_object(&engine.bucket, &f.s3_key).await;
        engine.store.delete_file(&f.id).await?;
        cleaned += 1;
    }

    if cleaned > 0 {
        tracing::info!("fs gc cleaned {cleaned} items");
    }
    Ok(cleaned)
}

impl crate::fs::store::UploadSession {
    /// Check if expired at `now`.
    pub fn is_expired(&self, now: i64) -> bool {
        now - self.created_at > TTL_SECS
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::fs::FsEngine;
    use crate::fs::error::FsError;
    use crate::fs::object_store::ObjectStoreClient;
    use crate::fs::s3::S3Client;
    use crate::fs::store::{FileRecord, FsStore, UploadSession};
    use crate::policy::PolicyEngine;
    use bytes::Bytes;

    fn tmp_path(label: &str) -> std::path::PathBuf {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        std::env::temp_dir().join(format!(
            "rust-api-gc-{}-{}-{}.redb",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>()),
            label
        ))
    }

    async fn make_engine() -> FsEngine {
        let path = tmp_path("store");
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await.unwrap();
        let policy_path = tmp_path("policy");
        let _ = std::fs::remove_file(&policy_path);
        let policy = PolicyEngine::init(&policy_path).await.unwrap();
        let s3 = ObjectStoreClient::in_memory();
        FsEngine::from_parts(store, s3, "test-bucket".into(), policy)
    }

    fn session_with_age(id: &str, age_secs: i64, multipart: bool) -> UploadSession {
        UploadSession {
            id: id.to_string(),
            file_size: 1024,
            part_size: 1024,
            file_total_parts: 1,
            s3_upload_id: if multipart {
                Some(format!("upload-{id}"))
            } else {
                None
            },
            s3_key: format!("files/{id}"),
            owner_sub: "alice".into(),
            created_at: chrono::Utc::now().timestamp() - age_secs,
            etags: vec![None],
            checksums: vec![None],
        }
    }

    #[test]
    fn is_expired_boundary() {
        let now = 1_000_000;
        let s = UploadSession {
            id: "x".into(),
            file_size: 1,
            part_size: 1,
            file_total_parts: 1,
            s3_upload_id: None,
            s3_key: "k".into(),
            owner_sub: "o".into(),
            created_at: now - TTL_SECS,
            etags: vec![None],
            checksums: vec![None],
        };
        assert!(!s.is_expired(now));
        assert!(s.is_expired(now + 1));
    }

    #[tokio::test]
    async fn sweep_cleans_only_expired() -> anyhow::Result<()> {
        let engine = make_engine().await;
        engine
            .store
            .save_session(&session_with_age("fresh", 3600, true))
            .await?;
        engine
            .store
            .save_session(&session_with_age("old-mp", TTL_SECS + 3600, true))
            .await?;
        engine
            .store
            .save_session(&session_with_age("old-single", TTL_SECS + 3600, false))
            .await?;
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 2);
        assert!(engine.store.get_session("fresh").await?.is_some());
        assert!(engine.store.get_session("old-mp").await?.is_none());
        assert!(engine.store.get_session("old-single").await?.is_none());
        assert_eq!(sweep_once(&engine).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn sweep_cleans_orphaned_files() -> anyhow::Result<()> {
        let engine = make_engine().await;
        // fresh temp file stays
        let fresh = FileRecord {
            id: "fresh-file".into(),
            name: "a.txt".into(),
            mimetype: "text/plain".into(),
            size: 10,
            s3_key: "files/fresh-file".into(),
            owner_sub: "alice".into(),
            created_at: chrono::Utc::now().timestamp() - 3600,
        };
        engine.store.save_file(&fresh).await?;
        // old temp (never attached, refs 0, age > TTL)
        let old = FileRecord {
            id: "old-file".into(),
            name: "b.txt".into(),
            mimetype: "text/plain".into(),
            size: 10,
            s3_key: "files/old-file".into(),
            owner_sub: "alice".into(),
            created_at: chrono::Utc::now().timestamp() - TTL_SECS - 3600,
        };
        engine.store.save_file(&old).await?;
        engine
            .s3
            .put_object(
                "test-bucket",
                &old.s3_key,
                Bytes::from_static(b"data"),
                None,
                None,
            )
            .await?;
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 1);
        assert!(engine.store.get_file("fresh-file").await?.is_some());
        assert!(engine.store.get_file("old-file").await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn sweep_empty_store_returns_zero() -> anyhow::Result<()> {
        let engine = make_engine().await;
        assert_eq!(sweep_once(&engine).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn sweep_abort_failure_is_swallowed() -> anyhow::Result<()> {
        struct FailS3;
        #[async_trait::async_trait]
        impl S3Client for FailS3 {
            async fn create_multipart_upload(
                &self,
                _: &str,
                _: &str,
                _: Option<String>,
            ) -> Result<String, FsError> {
                Ok("u".into())
            }
            async fn upload_part(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: i32,
                _: Bytes,
                _: Option<String>,
            ) -> Result<String, FsError> {
                Ok("e".into())
            }
            async fn complete_multipart_upload(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: Vec<String>,
            ) -> Result<(), FsError> {
                Ok(())
            }
            async fn abort_multipart_upload(
                &self,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<(), FsError> {
                Err(FsError::Internal("abort failed".into()))
            }
            async fn put_object(
                &self,
                _: &str,
                _: &str,
                _: Bytes,
                _: Option<String>,
                _: Option<String>,
            ) -> Result<(), FsError> {
                Ok(())
            }
            async fn get_object(&self, _: &str, _: &str) -> Result<Bytes, FsError> {
                Err(FsError::NotFound("no".into()))
            }
            async fn delete_object(&self, _: &str, _: &str) -> Result<(), FsError> {
                Ok(())
            }
        }
        let path = tmp_path("fail");
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await?;
        let policy_path = tmp_path("failp");
        let _ = std::fs::remove_file(&policy_path);
        let policy = PolicyEngine::init(&policy_path).await?;
        let engine = FsEngine::from_parts(store, Arc::new(FailS3), "b".into(), policy);
        engine
            .store
            .save_session(&session_with_age("old-fail", TTL_SECS + 10, true))
            .await?;
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 1);
        assert!(engine.store.get_session("old-fail").await?.is_none());
        Ok(())
    }
}
