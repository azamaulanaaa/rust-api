//! On-demand per-user replica endpoint plus the replica object gateway.
//!
//! `GET /sync/clone` returns the replica pointer (`prefix`, `applied_seq`)
//! with an `ETag` so repeat polls are a cheap `304`. Every object inside the
//! replica prefix is individually addressable at `GET /sync/db/{object}`
//! with backend `ETag` passthrough and `If-None-Match` support: clients
//! check for changes through headers and download only what moved.
//! Engine files are immutable by construction (`Cache-Control: immutable`);
//! only `manifest.json` is revalidated per commit.

use actix_web::{
    HttpRequest, HttpResponse, get,
    http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH},
    web,
};

use crate::http::{
    ApiModule,
    middleware::jwt::{Claims, JwtClaimsMiddleware, Validated},
};
use crate::sync::snapshot::SnapshotManager;

/// Module exposing `GET /sync/clone` and `GET /sync/db/{object}`.
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
                .service(clone_handler)
                .service(object_handler),
        );
    }
}

/// Quoted `ETag` for a coverage point (coverage only moves forward, so the
/// sequence alone identifies the content).
fn snapshot_etag(applied: u64) -> String {
    format!("\"snap-{applied}\"")
}

/// True when `If-None-Match` permits skipping the body (weak comparison,
/// plus `*`).
fn etag_matches(header: &str, etag: &str) -> bool {
    if header.trim() == "*" {
        return true;
    }
    let want = normalize_etag(etag);
    header.split(',').any(|tag| normalize_etag(tag) == want)
}

/// Strips weak prefix and quotes for opaque-tag comparison.
fn normalize_etag(tag: &str) -> &str {
    let tag = tag.trim();
    let tag = tag.strip_prefix("W/").unwrap_or(tag).trim();
    tag.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(tag)
}

/// Returns the replica pointer for `sub`, building or replaying on demand.
///
/// Fresh pointers (`applied >= head`) return without touching storage
/// beyond the marker read. Otherwise small file/relation deltas replay and
/// anything else falls back to a full rebuild; a lost fencing race adopts
/// the winner's pointer instead of failing.
#[get("/clone")]
async fn clone_handler(
    manager: web::Data<SnapshotManager>,
    claims: Validated<Claims>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let sub = &claims.sub;
    let head = manager.wal.head().await?;
    let applied = manager.load_applied(sub).await?;
    let built: Result<u64, crate::fs::error::FsError> = match applied {
        Some(a) if a >= head => Ok(a),
        _ => match manager.replay(head, sub).await {
            Ok(a) => Ok(a),
            Err(_) => manager.build_full(sub).await,
        },
    };
    // A lost fencing race means a concurrent builder just published:
    // adopt their coverage instead of failing.
    let applied = match built {
        Ok(a) => a,
        Err(e) if is_fenced(&e) => manager.load_applied(sub).await?.ok_or(e)?,
        Err(e) => return Err(e),
    };
    let etag = snapshot_etag(applied);
    if let Some(header) = req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        && etag_matches(header, &etag)
    {
        return Ok(HttpResponse::NotModified()
            .insert_header((ETAG, etag))
            .finish());
    }
    Ok(HttpResponse::Ok()
        .insert_header((ETAG, etag))
        .json(serde_json::json!({
            "prefix": manager.user_prefix(sub),
            "applied_seq": applied,
        })))
}

/// Serves one object from the replica with `ETag` passthrough.
///
/// `sub` always comes from the JWT, never the path, so callers can only
/// read their own replica. Missing objects are `404`; `If-None-Match`
/// matches are `304` without a body.
#[get("/db/{object:.*}")]
async fn object_handler(
    manager: web::Data<SnapshotManager>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    use object_store::ObjectStore as _;

    let tail = path.into_inner();
    let key = manager.resolve_object(&claims.sub, &tail)?;

    let store = manager.object_store.clone();
    let object_path = object_store::path::Path::from(key.as_str());
    let out = if let Some(header) = req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        let opts = object_store::GetOptions {
            if_none_match: Some(header.to_string()),
            ..Default::default()
        };
        match store.get_opts(&object_path, opts).await {
            Ok(out) => out,
            Err(object_store::Error::NotFound { .. }) => {
                return Ok(HttpResponse::NotFound().finish());
            }
            Err(object_store::Error::NotModified { .. }) => {
                return Ok(HttpResponse::NotModified().finish());
            }
            Err(e) => return Err(crate::fs::error::FsError::Internal(e.to_string())),
        }
    } else {
        match store.get(&object_path).await {
            Ok(out) => out,
            Err(object_store::Error::NotFound { .. }) => {
                return Ok(HttpResponse::NotFound().finish());
            }
            Err(e) => return Err(crate::fs::error::FsError::Internal(e.to_string())),
        }
    };

    let mut resp = HttpResponse::Ok();
    if let Some(ref etag) = out.meta.e_tag {
        resp.insert_header((ETAG, etag.as_str()));
    }
    if tail == "manifest.json" {
        resp.insert_header((CACHE_CONTROL, "no-cache"));
        resp.insert_header((CONTENT_TYPE, "application/json"));
    } else {
        resp.insert_header((CACHE_CONTROL, "public, max-age=31536000, immutable"));
        resp.insert_header((CONTENT_TYPE, "application/octet-stream"));
    }
    let bytes = out
        .bytes()
        .await
        .map_err(|e| crate::fs::error::FsError::Internal(e.to_string()))?;
    Ok(resp.body(bytes))
}

/// True when `e` is an oxkv fencing loss (another writer won the epoch).
fn is_fenced(e: &crate::fs::error::FsError) -> bool {
    e.to_string().contains("fenced")
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, http};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use crate::fs::store::{FileRecord, FsStore};
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::http::middleware::jwt::JwtClaimsMiddleware;
    use crate::policy::PolicyEngine;
    use crate::sync::wal::{Wal, WalOp};

    const KID: &str = "sync-route-test-kid";
    const AUD: &str = "test-aud";

    struct Fixture {
        server: wiremock::MockServer,
        enc: EncodingKey,
        manager: SnapshotManager,
    }

    impl Fixture {
        fn issuer(&self) -> String {
            self.server.uri()
        }
        fn token(&self, sub: &str) -> anyhow::Result<String> {
            sign_rs256(
                &json!({"sub": sub, "iss": self.issuer(), "aud": AUD, "exp": 2000000000u64}),
                KID,
                &self.enc,
            )
        }
    }

    async fn fixture() -> anyhow::Result<Fixture> {
        let (key, enc) = rsa_key(KID)?;
        let jwks = json!({"keys": [key]});
        let server = spawn_jwks(jwks).await;
        let tag = format!(
            "test-sync-route-{}-{}",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
        );
        let mem = std::sync::Arc::new(object_store::memory::InMemory::new());
        let wal = Wal::new(crate::db::build_test_store(&format!("{tag}-wal")).await);
        let backing = FsStore::new(crate::db::build_test_store(&format!("{tag}-store")).await);
        backing
            .save_file(&FileRecord {
                id: "f1".into(),
                name: "a.txt".into(),
                mimetype: "text/plain".into(),
                size: 1,
                s3_key: "k/f1".into(),
                owner_sub: "alice".into(),
                created_at: 0,
            })
            .await?;
        let policy =
            PolicyEngine::init_s3(crate::db::build_test_store(&format!("{tag}-policy")).await)
                .await?;
        let manager = SnapshotManager::new(
            wal,
            backing,
            policy,
            mem.clone() as std::sync::Arc<dyn object_store::ObjectStore>,
            "test-db".into(),
            true,
        );
        manager.build_full("alice").await?;
        Ok(Fixture {
            server,
            enc,
            manager,
        })
    }

    async fn setup(fx: &Fixture) -> anyhow::Result<JwtClaimsMiddleware<Claims>> {
        JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await
    }

    #[test]
    fn snapshot_etag_is_quoted_and_stable() {
        assert_eq!(snapshot_etag(3), "\"snap-3\"");
    }

    #[test]
    fn etag_matches_weak_and_list_forms() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("W/\"abc\"", "\"abc\""));
        assert!(etag_matches("\"x\", \"abc\"", "\"abc\""));
        assert!(etag_matches("*", "\"abc\""));
        assert!(!etag_matches("\"other\"", "\"abc\""));
        assert!(!etag_matches("", "\"abc\""));
    }

    #[test]
    fn is_fenced_matches_oxkv_fencing() {
        assert!(is_fenced(&crate::fs::error::FsError::Store(
            "fenced: epoch 2 superseded".into()
        )));
        assert!(!is_fenced(&crate::fs::error::FsError::Internal(
            "boom".into()
        )));
    }

    #[actix_web::test]
    async fn unauthenticated_clone_is_401() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/clone")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[actix_web::test]
    async fn clone_returns_pointer_and_supports_304() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/clone")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let etag = res
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(etag, "\"snap-0\"");
        let body = actix_web::test::read_body(res).await;
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["applied_seq"], 0);
        assert!(json["prefix"].as_str().unwrap_or_default().contains("u/alice"));

        // Fresh client gets 304 with no body.
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/clone")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .insert_header((IF_NONE_MATCH, etag))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_MODIFIED);
        Ok(())
    }

    #[actix_web::test]
    async fn clone_skips_commit_when_fresh() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        // Manifest ETag is stable across a fresh re-poll: no commit ran.
        let fetch_manifest_etag = || async {
            let res = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri("/sync/db/manifest.json")
                    .insert_header(("Cookie", format!("auth_token={token}")))
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK);
            res.headers()
                .get(ETAG)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let before = fetch_manifest_etag().await;
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/clone")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let after = fetch_manifest_etag().await;
        assert_eq!(before, after);
        Ok(())
    }

    #[actix_web::test]
    async fn clone_advances_via_replay() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let f2 = FileRecord {
            id: "f2".into(),
            name: "b.txt".into(),
            mimetype: "text/plain".into(),
            size: 2,
            s3_key: "k/f2".into(),
            owner_sub: "alice".into(),
            created_at: 0,
        };
        fx.manager.store.save_file(&f2).await?;
        fx.manager
            .wal
            .append(WalOp::FileCreate { rec: f2 })
            .await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/clone")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body = actix_web::test::read_body(res).await;
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["applied_seq"], 1);

        // The replayed prefix is served through the gateway.
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/db/manifest.json")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        Ok(())
    }

    #[actix_web::test]
    async fn object_serves_manifest_and_missing_is_404() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/db/manifest.json")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(actix_web::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        // InMemory supplies ETags, so the conditional roundtrip below runs.
        let etag = res
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .expect("object responses must carry an ETag");
        {
            let res = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri("/sync/db/manifest.json")
                    .insert_header(("Cookie", format!("auth_token={token}")))
                    .insert_header((IF_NONE_MATCH, etag))
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::NOT_MODIFIED);
        }

        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/db/does-not-exist.json")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        Ok(())
    }
}
