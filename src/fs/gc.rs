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
