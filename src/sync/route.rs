//! On-demand per-user clone endpoint.

use actix_web::{HttpResponse, Responder, get, web};

use crate::http::{ApiModule, middleware::jwt::{Claims, JwtClaimsMiddleware, Validated}};
use crate::sync::snapshot::SnapshotManager;

/// Module exposing `GET /sync/clone`.
pub struct SyncApiModule {
    manager: SnapshotManager,
    jwt: JwtClaimsMiddleware<Claims>,
}

impl SyncApiModule {
    /// Create the module.
    pub fn new(manager: SnapshotManager, jwt: JwtClaimsMiddleware<Claims>) -> Self {
        Self { manager, jwt }
    }
}

impl ApiModule for SyncApiModule {
    fn configure(&self, cfg: &mut web::ServiceConfig) {
        let mgr = web::Data::new(self.manager.clone());
        let jwt = self.jwt.clone();
        cfg.service(
            web::scope("/sync")
                .app_data(mgr)
                .wrap(jwt)
                .service(clone_handler),
        );
    }
}

/// Returns presigned `S3` URL or builds snapshot on demand.
/// Falls back to full recalc when far behind or `WAL` missing.
#[get("/clone")]
async fn clone_handler(
    manager: web::Data<SnapshotManager>,
    claims: Validated<Claims>,
) -> Result<impl Responder, crate::fs::error::FsError> {
    let sub = &claims.sub;
    let meta = manager.load_meta(sub).await?;
    let head = manager.wal.head().await?;
    let need_full = match meta {
        None => true,
        Some(ref m) if head.saturating_sub(m.applied_seq) > 1000 => true,
        Some(_) => false,
    };
    let meta = if need_full {
        manager.build_full(sub).await?
    } else {
        // Try replay; on any error fallback to full
        match replay(head, &manager, sub).await {
            Ok(m) => m,
            Err(_) => manager.build_full(sub).await?,
        }
    };
    let key = SnapshotManager::snapshot_key(sub, meta.version);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "key": key,
        "version": meta.version,
        "applied_seq": meta.applied_seq
    })))
}

async fn replay(
    _head: u64,
    _manager: &SnapshotManager,
    _sub: &str,
) -> Result<crate::sync::snapshot::SnapshotMeta, crate::fs::error::FsError> {
    // TODO: download snapshot, apply wal range filtered, re-upload
    Err(crate::fs::error::FsError::Internal("not implemented".into()))
}
