//! On-demand per-user clone endpoints over versioned replicas.
//!
//! `GET /sync/clone` returns the replica pointer (`version`, `applied_seq`,
//! `prefix`) with an `ETag` so repeat polls are a cheap `304`.
//! Every object inside the version prefix is individually addressable at
//! `GET /sync/db/{seq}/{object}` with backend `ETag` passthrough and
//! `If-None-Match` support: clients check for changes through headers and
//! download only what moved. Version-scoped engine files are immutable, so
//! they are marked `Cache-Control: immutable`; only `manifest.json` is
//! revalidated per version.

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

/// Module exposing `GET /sync/clone` and `GET /sync/db/{seq}/{object}`.
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

/// Quoted `ETag` for a snapshot version (versions are immutable, so the
/// version alone identifies the content).
fn version_etag(version: u64) -> String {
    format!("\"snap-{version}\"")
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

/// Returns the replica pointer for `sub`, building a fresh replica on demand.
///
/// The response carries an `ETag` over the version; clients re-poll with
/// `If-None-Match` and get `304` while the version is unchanged. When the
/// stored pointer already covers the WAL head the handler returns it
/// without building anything; otherwise it falls back to full recalc when
/// far behind or `WAL` missing.
#[get("/clone")]
async fn clone_handler(
    manager: web::Data<SnapshotManager>,
    claims: Validated<Claims>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let sub = &claims.sub;
    let meta = manager.load_meta(sub).await?;
    let head = manager.wal.head().await?;
    // Fresh pointer: the replica already covers the WAL head, so return it
    // without building or replaying anything.
    let meta = match meta {
        Some(m) if m.applied_seq >= head => m,
        stale => {
            let need_full = match stale {
                None => true,
                Some(ref m) if head.saturating_sub(m.applied_seq) > 1000 => true,
                Some(_) => false,
            };
            if need_full {
                manager.build_full(sub).await?
            } else {
                // Try replay; on any error fallback to full
                match replay(head, &manager, sub).await {
                    Ok(m) => m,
                    Err(_) => manager.build_full(sub).await?,
                }
            }
        }
    };
    let etag = version_etag(meta.version);
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
            "prefix": manager.user_prefix(sub, meta.version),
            "version": meta.version,
            "applied_seq": meta.applied_seq
        })))
}

/// Serves one object from a version replica with `ETag` passthrough.
///
/// `sub` always comes from the JWT, never the path, so callers can only
/// read their own replicas. Missing objects are `404`; `If-None-Match`
/// matches are `304` without a body.
#[get("/db/{seq}/{object:.*}")]
async fn object_handler(
    manager: web::Data<SnapshotManager>,
    claims: Validated<Claims>,
    path: web::Path<(String, String)>,
    req: HttpRequest,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    use object_store::ObjectStore as _;

    let (seq_raw, tail) = path.into_inner();
    let seq: u64 = seq_raw
        .parse()
        .map_err(|_| crate::fs::error::FsError::BadRequest("invalid snapshot version".into()))?;
    let key = manager.resolve_object(&claims.sub, seq, &tail)?;

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

async fn replay(
    _head: u64,
    _manager: &SnapshotManager,
    _sub: &str,
) -> Result<crate::sync::snapshot::SnapshotMeta, crate::fs::error::FsError> {
    // TODO: download snapshot, apply wal range filtered, re-upload
    Err(crate::fs::error::FsError::Internal(
        "not implemented".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, http};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use crate::fs::object_store::ObjectStoreClient;
    use crate::fs::store::{FileRecord, FsStore};
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::http::middleware::jwt::JwtClaimsMiddleware;
    use crate::policy::PolicyEngine;
    use crate::sync::wal::Wal;
    use object_store::ObjectStore as _;

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
        let s3 = ObjectStoreClient::in_memory();
        let manager = SnapshotManager::new(
            wal,
            backing,
            policy,
            s3,
            "b".into(),
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
    fn version_etag_is_quoted_and_stable() {
        assert_eq!(version_etag(3), "\"snap-3\"");
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
        assert_eq!(json["version"], 0);
        assert!(
            json["prefix"]
                .as_str()
                .unwrap_or_default()
                .contains("u/alice")
        );

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
    async fn clone_skips_rebuild_when_fresh() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        // Remove the built manifest: a rebuild would recreate it, the
        // fresh-pointer path below must not.
        let manifest_key = format!("{}/manifest.json", fx.manager.user_prefix("alice", 0));
        fx.manager
            .object_store
            .delete(&object_store::path::Path::from(manifest_key.as_str()))
            .await
            .unwrap();

        // Pointer is fresh (applied_seq 0 >= head 0): returned as-is.
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
        assert_eq!(json["version"], 0);

        // Manifest is still gone: no rebuild ran.
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/db/0/manifest.json")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
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
                .uri("/sync/db/0/manifest.json")
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
        let body = actix_web::test::read_body(res).await;
        let manifest: serde_json::Value = serde_json::from_slice(&body)?;
        assert!(manifest.get("version").is_some());

        // Conditional GET on the object: fresh clients get 304 when the
        // backend supplies an ETag, 200 otherwise.
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/db/0/manifest.json")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
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
                    .uri("/sync/db/0/manifest.json")
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
                .uri("/sync/db/0/does-not-exist.json")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        Ok(())
    }
}
