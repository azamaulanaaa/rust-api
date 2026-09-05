//! GC/TTL sweeper for abandoned multipart uploads.
//! Expires sessions older than 24h, aborts S3 multipart and cleans oxkv.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::interval;

use crate::fs::{FsEngine, store::UploadSession};

/// TTL for abandoned upload sessions.
pub const TTL_SECS: i64 = 24 * 3600;

/// Spawn background sweeper that runs every hour.
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

/// Single sweep: abort expired sessions.
#[tracing::instrument(skip(engine), fields(cleaned), err)]
pub async fn sweep_once(engine: &FsEngine) -> Result<usize, crate::fs::error::FsError> {
    let now = chrono::Utc::now().timestamp();
    let sessions = engine.store.list_sessions().await?;
    let mut expired = Vec::new();
    for s in sessions {
        if now - s.created_at > TTL_SECS {
            expired.push(s);
        }
    }
    let mut cleaned = 0;
    for s in expired {
        tracing::info!(
            "fs gc expiring upload {} (age {}s)",
            s.id,
            now - s.created_at
        );
        // abort S3 side (no-op for single-part Put without uploadId)
        if let Some(upload_id) = s.s3_upload_id.as_deref() {
            let res = engine
                .s3
                .abort_multipart_upload(&engine.bucket, &s.s3_key, upload_id)
                .await;
            if let Err(e) = res {
                tracing::warn!("gc abort {} failed: {e}", s.id);
            }
        } else {
            // single-part PutObject was already done; best-effort delete orphan object
            let _ = engine.s3.delete_object(&engine.bucket, &s.s3_key).await;
        }
        engine.store.delete_session(&s.id).await?;
        cleaned += 1;
    }
    if cleaned > 0 {
        tracing::info!("fs gc cleaned {cleaned} expired uploads");
    }
    Ok(cleaned)
}

impl UploadSession {
    /// For testing: check if expired.
    pub fn is_expired(&self, now: i64) -> bool {
        now - self.created_at > TTL_SECS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::fs::FsEngine;
    use crate::fs::error::FsError;
    use crate::fs::object_store::ObjectStoreClient;
    use crate::fs::s3::S3Client;
    use crate::fs::store::{FsStore, UploadSession};
    use crate::policy::{Action, PolicyEngine};
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
        // grant so engine can be used if needed, though gc does not check policy
        policy
            .assign_group("alice".into(), "writers".into())
            .await
            .unwrap();
        policy
            .add_rule("writers".into(), "fs".into(), Action::Write)
            .await
            .unwrap();
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
        assert!(!s.is_expired(now)); // exactly TTL not expired
        assert!(s.is_expired(now + 1));
    }

    #[tokio::test]
    async fn sweep_cleans_only_expired() -> anyhow::Result<()> {
        let engine = make_engine().await;
        // fresh (1h old) should stay
        engine
            .store
            .save_session(&session_with_age("fresh", 3600, true))
            .await?;
        // expired multipart (25h)
        engine
            .store
            .save_session(&session_with_age("old-mp", TTL_SECS + 3600, true))
            .await?;
        // expired single-part (no upload_id)
        engine
            .store
            .save_session(&session_with_age("old-single", TTL_SECS + 3600, false))
            .await?;
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 2);
        assert!(engine.store.get_session("fresh").await?.is_some());
        assert!(engine.store.get_session("old-mp").await?.is_none());
        assert!(engine.store.get_session("old-single").await?.is_none());
        // second sweep is idempotent
        assert_eq!(sweep_once(&engine).await?, 0);
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
        // S3 that fails abort but sweep should still clean session and return count
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
