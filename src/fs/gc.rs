//! GC for abandoned uploads and orphaned files.
//!
//! Sessions and temp/orphaned files older than 24h are removed.
//! Expired files are logged to the WAL (when the engine has one wired)
//! so replicas replay the deletion instead of keeping stale copies.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::interval;

use crate::fs::FsEngine;

/// Object prefix holding file bytes (`UploadSession`/`FileRecord` keys
/// are `files/{id}`); the orphan-byte pass lists exactly this scope so
/// oxkv prefixes sharing the bucket are never touched.
const FILE_BYTES_PREFIX: &str = "files/";

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

/// Single sweep: sessions, orphaned files, and orphan S3 bytes.
#[tracing::instrument(skip(engine), err)]
pub async fn sweep_once(engine: &FsEngine) -> Result<usize, crate::fs::error::FsError> {
    let now = chrono::Utc::now().timestamp();
    let mut cleaned = 0;

    let sessions = engine.store.list_sessions().await?;
    let files = engine.store.list_files().await?;

    // sessions
    for s in &sessions {
        if now - s.created_at <= TTL_SECS {
            continue;
        }
        tracing::info!(
            "fs gc expiring upload {} (age {}s)",
            s.id,
            now - s.created_at
        );
        // S3 first via the engine (restores post-restart state, tolerates
        // already-gone): on failure the session is kept so the next
        // sweep retries instead of leaking bytes no record points at.
        if engine.abort_session_upload(s).await.is_err() {
            tracing::warn!("fs gc keeping upload {} for retry", s.id);
            continue;
        }
        engine.store.delete_session(&s.id).await?;
        cleaned += 1;
    }

    // orphaned / temp files
    for f in &files {
        let info = engine.store.get_ref_info(&f.id).await?;
        if info.count != 0 {
            continue;
        }
        let age = info.orphan_since.unwrap_or(f.created_at);
        if now - age <= TTL_SECS {
            continue;
        }
        tracing::info!("fs gc expiring file {} (age {}s)", f.id, now - age);
        // Same retain-on-failure contract as sessions above.
        if engine
            .s3
            .delete_object(&engine.bucket, &f.s3_key)
            .await
            .map_err(|e| {
                tracing::warn!("gc delete {} failed: {e}", f.id);
                e
            })
            .is_err()
        {
            tracing::warn!("fs gc keeping file {} for retry", f.id);
            continue;
        }
        engine.store.delete_file(&f.id).await?;
        engine
            .append_wal(crate::sync::wal::WalOp::FileDelete {
                file_id: f.id.clone(),
            })
            .await?;
        cleaned += 1;
    }

    // orphan S3 bytes: listed keys no session or file record references.
    // Crash windows between byte and metadata writes strand such keys;
    // only reap them past the TTL so in-flight uploads always survive.
    // A listing failure skips just this pass (metadata work above stands).
    let mut live: HashSet<&str> = HashSet::new();
    for s in &sessions {
        live.insert(s.s3_key.as_str());
    }
    for f in &files {
        live.insert(f.s3_key.as_str());
    }
    let listed = match engine.s3.list_keys(&engine.bucket, FILE_BYTES_PREFIX).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!("fs gc orphan-byte listing failed: {e}; skipping pass");
            Vec::new()
        }
    };
    for entry in listed {
        if live.contains(entry.key.as_str()) || now - entry.last_modified <= TTL_SECS {
            continue;
        }
        tracing::info!("fs gc expiring orphan bytes {}", entry.key);
        if engine
            .s3
            .delete_object(&engine.bucket, &entry.key)
            .await
            .map_err(|e| {
                tracing::warn!("gc delete {} failed: {e}", entry.key);
                e
            })
            .is_err()
        {
            tracing::warn!("fs gc keeping orphan bytes {} for retry", entry.key);
            continue;
        }
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

    use crate::db::build_test_store;
    use crate::fs::FsEngine;
    use crate::fs::error::FsError;
    use crate::fs::object_store::ObjectStoreClient;
    use crate::fs::s3::S3Client;
    use crate::fs::store::{FileRecord, FsStore, PersistedMultipart, UploadSession};
    use crate::policy::PolicyEngine;
    use bytes::Bytes;

    async fn make_engine() -> FsEngine {
        use crate::db::build_test_store;
        let prefix = {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            format!(
                "test-gc-{}-{}",
                std::process::id(),
                URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
            )
        };
        let store = FsStore::new(build_test_store(&prefix).await);
        let policy_store = build_test_store(&format!("{prefix}-policy")).await;
        let policy = PolicyEngine::init_s3(policy_store).await.unwrap();
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

    /// Wraps one buffered part as the chunk stream the engine now takes.
    fn once_body(body: Vec<u8>) -> impl futures_util::Stream<Item = Result<Bytes, FsError>> {
        futures_util::stream::once(async move { Ok(Bytes::from(body)) })
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
    async fn sweep_logs_orphan_deletes_to_wal() -> anyhow::Result<()> {
        use crate::sync::wal::{Wal, WalOp};

        let wal_prefix = format!("test-gc-wal-{}-{}", std::process::id(), {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
        });
        let wal = Wal::new(build_test_store(&wal_prefix).await);
        let engine = make_engine().await.with_wal(wal.clone());
        let old = FileRecord {
            id: "gc-wal-file".into(),
            name: "b.txt".into(),
            mimetype: "text/plain".into(),
            size: 10,
            s3_key: "files/gc-wal-file".into(),
            owner_sub: "alice".into(),
            created_at: chrono::Utc::now().timestamp() - TTL_SECS - 3600,
        };
        engine.store.save_file(&old).await?;
        assert_eq!(sweep_once(&engine).await?, 1);
        assert_eq!(wal.head().await?, 1);
        let entries = wal.range(1, 1).await?;
        assert!(
            matches!(&entries[0].op, WalOp::FileDelete { file_id } if file_id == "gc-wal-file")
        );
        // Second sweep finds nothing and logs nothing.
        assert_eq!(sweep_once(&engine).await?, 0);
        assert_eq!(wal.head().await?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn sweep_keeps_live_and_fresh_s3_keys() -> anyhow::Result<()> {
        let engine = make_engine().await;
        // Live single-part session: bytes exist, session still open.
        let file_id = engine
            .init_upload(
                crate::fs::model::InitRequest {
                    file_size: 1024,
                    part_size: 1024,
                    file_total_parts: 1,
                },
                "alice",
            )
            .await?;
        engine
            .upload_part(&file_id, 0, once_body(vec![9u8; 1024]), None, None, "alice")
            .await?;
        // Fresh stray bytes (e.g. crash between put and metadata write).
        engine
            .s3
            .put_object("test-bucket", "files/stray", Bytes::from_static(b"x"), None, None)
            .await?;

        assert_eq!(sweep_once(&engine).await?, 0);
        assert!(engine.store.get_session(&file_id).await?.is_some());
        assert!(engine.s3.get_object("test-bucket", "files/stray").await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn sweep_reaps_aged_orphan_bytes() -> anyhow::Result<()> {
        use crate::fs::s3::ListedKey;

        struct ListS3 {
            listed: Vec<ListedKey>,
            deleted: std::sync::Mutex<Vec<String>>,
        }
        #[async_trait::async_trait]
        impl S3Client for ListS3 {
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
                Ok(())
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
            async fn delete_object(&self, _: &str, key: &str) -> Result<(), FsError> {
                self.deleted.lock().expect("delete log").push(key.to_string());
                Ok(())
            }
            async fn list_keys(&self, _: &str, _: &str) -> Result<Vec<ListedKey>, FsError> {
                Ok(self.listed.clone())
            }
        }

        let now = chrono::Utc::now().timestamp();
        let s3 = Arc::new(ListS3 {
            listed: vec![
                ListedKey {
                    key: "files/old-stray".into(),
                    last_modified: now - TTL_SECS - 3600,
                },
                ListedKey {
                    key: "files/fresh-stray".into(),
                    last_modified: now - 60,
                },
                ListedKey {
                    key: "files/live-key".into(),
                    last_modified: now - TTL_SECS - 3600,
                },
            ],
            deleted: std::sync::Mutex::new(Vec::new()),
        });
        let orphan_prefix = {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            format!(
                "test-gc-orphan-{}-{}",
                std::process::id(),
                URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
            )
        };
        let store = FsStore::new(build_test_store(&orphan_prefix).await);
        let policy =
            PolicyEngine::init_s3(build_test_store(&format!("{orphan_prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, s3.clone(), "b".into(), policy);
        // Fresh session referencing live-key: aged but live, must survive.
        let mut sess = session_with_age("sess-live", 60, false);
        sess.s3_key = "files/live-key".into();
        engine.store.save_session(&sess).await?;

        assert_eq!(sweep_once(&engine).await?, 1);
        assert_eq!(
            *s3.deleted.lock().expect("delete log"),
            vec!["files/old-stray".to_string()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn sweep_reaps_restarted_multipart_session() -> anyhow::Result<()> {
        use object_store::memory::InMemory;

        // One backend surviving the "restart"; client RAM does not (S3
        // buckets outlive process restarts, so the backend upload id
        // stays addressable while the pre-restart RAM map is gone).
        let inner = std::sync::Arc::new(InMemory::new());
        let prefix = {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            format!(
                "test-gc-restart-{}-{}",
                std::process::id(),
                URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
            )
        };
        let store = FsStore::new(build_test_store(&prefix).await);
        let policy =
            PolicyEngine::init_s3(build_test_store(&format!("{prefix}-policy")).await).await?;
        let pre: std::sync::Arc<dyn S3Client> =
            std::sync::Arc::new(ObjectStoreClient::new_combined(inner.clone()));
        let engine_pre =
            FsEngine::from_parts(store.clone(), pre, "test-bucket".into(), policy.clone());
        // Real multipart upload: backend id + durable record exist.
        let file_id = engine_pre
            .init_upload(
                crate::fs::model::InitRequest {
                    file_size: 2048,
                    part_size: 1024,
                    file_total_parts: 2,
                },
                "alice",
            )
            .await?;
        // Age it past the TTL.
        let mut sess = engine_pre
            .store
            .get_session(&file_id)
            .await?
            .expect("session exists");
        let upload_id = sess.s3_upload_id.clone().expect("multipart session");
        sess.created_at -= TTL_SECS + 100;
        engine_pre.store.save_session(&sess).await?;
        drop(engine_pre); // restart: RAM multipart states gone.
        let post: std::sync::Arc<dyn S3Client> =
            std::sync::Arc::new(ObjectStoreClient::new_combined(inner));
        let engine_post = FsEngine::from_parts(store, post, "test-bucket".into(), policy);
        // GC restores the backend upload from the record, aborts it for
        // real, and converges the session plus its record.
        assert_eq!(sweep_once(&engine_post).await?, 1);
        assert!(engine_post.store.get_session(&file_id).await?.is_none());
        assert!(engine_post.store.load_multipart(&upload_id).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn sweep_empty_store_returns_zero() -> anyhow::Result<()> {
        let engine = make_engine().await;
        assert_eq!(sweep_once(&engine).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn sweep_retains_session_when_abort_fails() -> anyhow::Result<()> {
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
                Err(FsError::Internal("delete failed".into()))
            }
            async fn list_keys(
                &self,
                _: &str,
                _: &str,
            ) -> Result<Vec<crate::fs::s3::ListedKey>, FsError> {
                Ok(Vec::new())
            }
        }
        let fail_prefix = {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            format!(
                "test-gc-fail-{}-{}",
                std::process::id(),
                URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
            )
        };
        let store = FsStore::new(build_test_store(&fail_prefix).await);
        let policy =
            PolicyEngine::init_s3(build_test_store(&format!("{fail_prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, Arc::new(FailS3), "b".into(), policy);
        engine
            .store
            .save_session(&session_with_age("old-fail", TTL_SECS + 10, true))
            .await?;
        // Durable record present so expiry reaches the S3 abort (which
        // fails) instead of taking the no-record early return.
        engine
            .store
            .save_multipart(&PersistedMultipart {
                upload_id: "upload-old-fail".into(),
                bucket: "b".into(),
                key: "files/old-fail".into(),
                s3_upload_id: "real-fail".into(),
                parts: Default::default(),
                created_at: chrono::Utc::now().timestamp() - TTL_SECS - 10,
            })
            .await?;
        engine
            .store
            .save_file(&FileRecord {
                id: "old-fail-file".into(),
                name: "f.txt".into(),
                mimetype: "text/plain".into(),
                size: 1,
                s3_key: "files/old-fail-file".into(),
                owner_sub: "alice".into(),
                created_at: chrono::Utc::now().timestamp() - TTL_SECS - 10,
            })
            .await?;
        // S3 failure keeps sessions and files for the next sweep instead
        // of leaking bytes no record points at.
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 0);
        assert!(engine.store.get_session("old-fail").await?.is_some());
        assert!(engine.store.get_file("old-fail-file").await?.is_some());
        Ok(())
    }
}
