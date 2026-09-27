//! Per-user replica pointer plus the replica object gateway.
//!
//! `GET /sync/status` returns the replica pointer (`prefix`, `applied_seq`,
//! `head`) with an `ETag` so repeat polls are a cheap `304`; it never
//! builds. `POST /sync/sync` advances the replica toward the WAL head
//! (short-circuit, replay, or full recalc) and returns the new pointer.
//! Every object inside the replica prefix is individually addressable at `GET /sync/db/{object}`
//! with backend `ETag` passthrough and `If-None-Match` support: clients
//! check for changes through headers and download only what moved.
//! Engine files are immutable by construction (`Cache-Control: immutable`);
//! only `manifest.json` is revalidated per commit.

use actix_web::{
    HttpRequest, HttpResponse, get,
    http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_NONE_MATCH},
    post, web,
};

use crate::fs::error::FsError;
use crate::http::{
    ApiModule, logged_body,
    middleware::jwt::{Claims, JwtClaimsMiddleware, Validated},
};
use crate::sync::snapshot::SnapshotManager;

/// Module exposing status/sync pointer endpoints and `GET /sync/db/{object}`.
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
    fn prefix(&self) -> &str {
        "/sync"
    }

    fn configure(&self, cfg: &mut web::ServiceConfig) {
        let mgr = web::Data::new(self.manager.clone());
        let jwt = self.jwt.clone();
        cfg.service(
            web::scope("/sync")
                .app_data(mgr)
                .wrap(jwt)
                .service(status_handler)
                .service(sync_handler)
                .service(object_handler),
        );
    }
}

/// Replica pointer returned by `GET /sync/status`.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct SyncStatusResponse {
    /// Replica prefix for the caller (`{db}/u/{sha256-hex(sub)}`).
    pub prefix: String,
    /// WAL sequence covered by the replica (`None` when never built).
    pub applied_seq: Option<u64>,
    /// Current WAL head.
    pub head: u64,
}

/// Replica pointer returned by `POST /sync/sync`.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct SyncAdvanceResponse {
    /// Replica prefix for the caller (`{db}/u/{sha256-hex(sub)}`).
    pub prefix: String,
    /// WAL sequence covered by the replica.
    ///
    /// May be below the WAL head even on a 200: see
    /// [`pending`](Self::pending).
    pub applied_seq: u64,
    /// True when a full rebuild is queued or already running, so
    /// `applied_seq` is what the replica covered *before* it.
    ///
    /// A rebuild scans the whole master, so it is queued rather than run
    /// inside the request; keep polling `GET /sync/status` and advancing until
    /// this is false. Additive to the response, so existing clients keep
    /// working -- but a client that assumed one `POST /sync/sync` always
    /// converged would now need to read this.
    pub pending: bool,
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

/// Returns the replica pointer for `sub` without building.
///
/// Pure read: reports the current coverage (`applied_seq`, `None` when the
/// replica was never built) alongside the WAL `head`, so clients can decide
/// whether a `POST /sync/sync` is worthwhile. Never touches the replica
/// beyond the coverage-marker read.
#[utoipa::path(get, path = "/sync/status", tag = "sync", responses((status = 200, body = SyncStatusResponse), (status = 304, description = "not modified"), (status = 401, body = crate::http::error::ErrorBody)))]
#[get("/status")]
async fn status_handler(
    manager: web::Data<SnapshotManager>,
    claims: Validated<Claims>,
    req: HttpRequest,
) -> Result<HttpResponse, FsError> {
    let sub = &claims.sub;
    let head = manager.wal.head().await?;
    let applied = manager.load_applied(sub).await?;
    let etag = applied
        .map(snapshot_etag)
        .unwrap_or_else(|| "\"snap-none\"".to_string());
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
        .json(SyncStatusResponse {
            prefix: manager.user_prefix(sub),
            applied_seq: applied,
            head,
        }))
}

/// Advances the replica for `sub` toward the WAL head and returns the pointer.
///
/// Fresh pointers (`applied >= head`) return without touching storage
/// beyond the marker read. Otherwise small file/relation deltas and rich
/// rule/group ops replay (irrelevant users/objects skip); legacy policy
/// marks and oversized ranges fall back to a full rebuild. A lost fencing
/// race adopts the winner's pointer instead of failing.
#[utoipa::path(post, path = "/sync/sync", tag = "sync", responses((status = 200, body = SyncAdvanceResponse), (status = 304, description = "not modified"), (status = 401, body = crate::http::error::ErrorBody)))]
#[post("/sync")]
async fn sync_handler(
    manager: web::Data<SnapshotManager>,
    claims: Validated<Claims>,
    req: HttpRequest,
) -> Result<HttpResponse, FsError> {
    let sub = &claims.sub;
    let outcome = manager.advance(sub).await?;
    let etag = snapshot_etag(outcome.applied_seq);
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
        .json(SyncAdvanceResponse {
            prefix: manager.user_prefix(sub),
            applied_seq: outcome.applied_seq,
            pending: outcome.pending,
        }))
}

/// Serves one object from the replica with `ETag` passthrough.
///
/// `sub` always comes from the JWT, never the path, so callers can only
/// read their own replica. Missing objects are `404`; `If-None-Match`
/// matches are `304` without a body.
#[utoipa::path(get, path = "/sync/db/{object}", tag = "sync", params(("object" = String, Path, description = "object key inside the replica prefix (e.g. manifest.json)")), responses((status = 200, description = "replica object bytes", content_type = "application/octet-stream"), (status = 304, description = "not modified"), (status = 401, body = crate::http::error::ErrorBody), (status = 404, description = "object not found")))]
#[get("/db/{object:.*}")]
async fn object_handler(
    manager: web::Data<SnapshotManager>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, FsError> {
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
            Err(e) => return Err(FsError::Internal(e.to_string())),
        }
    } else {
        match store.get(&object_path).await {
            Ok(out) => out,
            Err(object_store::Error::NotFound { .. }) => {
                return Ok(HttpResponse::NotFound().finish());
            }
            Err(e) => return Err(FsError::Internal(e.to_string())),
        }
    };

    // Read the head off `out` before `into_stream` consumes it.
    let etag = out.meta.e_tag.clone();
    let size = out.range.end.saturating_sub(out.range.start);
    object_response(out, &tail, etag, size)
}

/// The `200` response for one replica object, streaming `out`.
///
/// Split out from [`object_handler`] so the streaming property is testable:
/// the caller has to hand over a [`GetResult`] it has not read yet, and the
/// only way to build the response is to consume it as a stream.
///
/// A replica prefix holds oxkv's own files, and an SST segment is sized for
/// compaction throughput rather than for a browser -- tens to hundreds of
/// megabytes. Collecting it would put that segment in resident memory once
/// per in-flight request, on every worker, for a payload the client is
/// going to buffer anyway. `Content-Length` is taken from the range
/// `object_store` already resolved, so clients still see the size up front
/// and the immutability caching still behaves.
fn object_response(
    out: object_store::GetResult,
    tail: &str,
    etag: Option<String>,
    size: u64,
) -> Result<HttpResponse, FsError> {
    let mut resp = HttpResponse::Ok();
    if let Some(ref etag) = etag {
        resp.insert_header((ETAG, etag.as_str()));
    }
    if tail == "manifest.json" {
        resp.insert_header((CACHE_CONTROL, "no-cache"));
        resp.insert_header((CONTENT_TYPE, "application/json"));
    } else {
        resp.insert_header((CACHE_CONTROL, "public, max-age=31536000, immutable"));
        resp.insert_header((CONTENT_TYPE, "application/octet-stream"));
    }
    Ok(resp
        .insert_header((CONTENT_LENGTH, size))
        .streaming(logged_body(out.into_stream())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::ChangeSink;
    use actix_web::{App, http};
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use crate::fs::store::{FileRecord, FsStore};
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::http::middleware::jwt::JwtClaimsMiddleware;
    use crate::policy::PolicyEngine;
    use crate::records::WalOp;
    use crate::sync::wal::Wal;

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
        let tag = crate::db::test_prefix("sync-route");
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
            crate::sync::snapshot::SnapshotDeps {
                wal,
                store: backing,
                policy: policy.authorizer(),
                object_store: mem.clone() as std::sync::Arc<dyn object_store::ObjectStore>,
                builds: crate::sync::snapshot::BuildQueue::new().0,
            },
            "test-db",
            crate::sync::snapshot::ReplicaBackend::InMemory,
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

    /// The replica object response is built without reading the body.
    ///
    /// This is the guard for the memory property, and it works because
    /// [`object_response`] takes a `GetResult` it has not touched. The
    /// stream handed in yields one chunk and then fails: an implementation
    /// that collected the body would read past that failure, surface it as
    /// a handler error instead of a `200`, and record a poll. So a revert
    /// to `out.bytes()` fails fast here rather than quietly passing.
    ///
    /// Resident memory is not directly observable from a unit test. What is
    /// observable -- and what keeps a 256 MB SST out of the heap once per
    /// in-flight request -- is that not one byte of the segment is read
    /// before the response exists.
    #[test]
    fn object_response_does_not_read_the_body() {
        use object_store::{GetResult, GetResultPayload, ObjectMeta};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const SEGMENT: u64 = 256 * 1024 * 1024;

        let polls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&polls);
        let payload =
            GetResultPayload::Stream(Box::pin(futures_util::stream::unfold(0u8, move |step| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Some((
                        match step {
                            // One good chunk...
                            0 => Ok(bytes::Bytes::from_static(b"partial")),
                            // ...then a mid-stream failure that a collecting
                            // implementation cannot avoid running into.
                            _ => Err(object_store::Error::NotFound {
                                path: "seg-0001.sst".into(),
                                source: "stream aborted".into(),
                            }),
                        },
                        step + 1,
                    ))
                }
            })));

        let out = GetResult {
            payload,
            meta: ObjectMeta {
                location: "seg-0001.sst".into(),
                last_modified: chrono::Utc::now(),
                size: SEGMENT,
                e_tag: Some("\"v1\"".into()),
                version: None,
            },
            range: 0..SEGMENT,
            attributes: object_store::Attributes::new(),
        };

        let resp = object_response(out, "seg-0001.sst", Some("\"v1\"".into()), SEGMENT)
            .expect("building the response must not read the body");

        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "the body was read before the response existed"
        );
        assert_eq!(
            resp.headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(SEGMENT.to_string().as_str()),
            "a streamed body must declare its length up front"
        );
        assert_eq!(
            resp.headers().get(ETAG).and_then(|v| v.to_str().ok()),
            Some("\"v1\"")
        );
        assert_eq!(
            resp.headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=31536000, immutable")
        );
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
    fn lost_fencing_race_is_recognised_from_the_typed_variant() {
        // Regression: this used to be `detail.contains("fenced")`, so a
        // rewording in oxkv would have turned a recoverable race into a
        // 500 for every client. Now it is a typed variant produced by
        // `From<oxkv::StoreError>`.
        assert!(
            FsError::from(oxkv::StoreError::Fenced("epoch 2 superseded".into())).is_fencing_loss()
        );
        // A generic store failure is not a fencing loss and must not be
        // treated as one.
        assert!(!FsError::from(oxkv::StoreError::Storage("disk".into())).is_fencing_loss());
        assert!(!FsError::Internal("fenced: looks like it".into()).is_fencing_loss());
    }

    #[actix_web::test]
    async fn unauthenticated_status_and_sync_are_401() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/status")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/sync/sync")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[actix_web::test]
    async fn status_returns_pointer_and_supports_304() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/status")
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
        assert_eq!(json["head"], 0);
        assert!(
            json["prefix"]
                .as_str()
                .unwrap_or_default()
                .starts_with("test-db/u/")
        );

        // Fresh client gets 304 with no body.
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/status")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .insert_header((IF_NONE_MATCH, etag))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_MODIFIED);
        Ok(())
    }

    #[actix_web::test]
    async fn status_never_builds() -> anyhow::Result<()> {
        let fx = fixture().await?;
        // Make the replica stale the way the engines do: master mutation
        // plus WAL entry, with no advance.
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
        fx.manager.wal.append(WalOp::FileCreate { rec: f2 }).await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        // Manifest ETag is stable across status polls: no commit runs.
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
        // Status reports the gap but never closes it.
        for _ in 0..2 {
            let res = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri("/sync/status")
                    .insert_header(("Cookie", format!("auth_token={token}")))
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK);
            let body = actix_web::test::read_body(res).await;
            let json: serde_json::Value = serde_json::from_slice(&body)?;
            assert_eq!(json["applied_seq"], 0);
            assert_eq!(json["head"], 1);
        }
        let after = fetch_manifest_etag().await;
        assert_eq!(before, after);
        Ok(())
    }

    /// A rebuild that cannot be replayed is queued, not run inside the
    /// request, and the response says so.
    ///
    /// The `200` with `pending: true` is the contract change to be careful
    /// about: a caller that issued one `POST /sync/sync` and expected to read
    /// its replica immediately would now see coverage from before the rebuild.
    /// The field is what makes that visible rather than silent, and
    /// `GET /sync/status` is the poll that watches it move.
    #[actix_web::test]
    async fn a_needed_rebuild_is_reported_as_pending() -> anyhow::Result<()> {
        use crate::records::WalOp;

        let fx = fixture().await?;
        let module = SyncApiModule::new(fx.manager.clone(), setup(&fx).await?);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        // The fixture has already built the replica, so a plain advance is a
        // no-op. A legacy policy mark is the one delta that cannot be
        // replayed incrementally -- it carries no rule, only an object name --
        // and forces the full-recalculate path.
        fx.manager
            .wal
            .append(WalOp::PolicyAdd {
                obj: "invoice:1".into(),
            })
            .await?;

        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/sync/sync")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let json: serde_json::Value =
            serde_json::from_slice(&actix_web::test::read_body(res).await)?;
        assert_eq!(json["pending"], true, "a full rebuild was queued: {json}");
        assert_eq!(
            json["applied_seq"], 0,
            "coverage reported is from before the rebuild: {json}"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn sync_advances_via_replay() -> anyhow::Result<()> {
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
        fx.manager.wal.append(WalOp::FileCreate { rec: f2 }).await?;
        let mw = setup(&fx).await?;
        let module = SyncApiModule::new(fx.manager.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/sync/sync")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body = actix_web::test::read_body(res).await;
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["applied_seq"], 1);
        // A bounded replay runs inline, so the caller is not left pending.
        assert_eq!(json["pending"], false);

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
        // The body is streamed, so its length has to be declared up front.
        // A chunked response would still be correct for a client, but
        // `manifest.json` is what a client polls to discover what changed,
        // and a known length is what lets it fail fast on a truncated read.
        let declared = res
            .headers()
            .get(actix_web::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .expect("streamed replica objects must declare Content-Length");
        // InMemory supplies ETags, so the conditional roundtrip below runs.
        let etag = res
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .expect("object responses must carry an ETag");
        let body = actix_web::test::read_body(res).await;
        assert_eq!(
            body.len(),
            declared,
            "declared length must match the bytes actually streamed"
        );
        serde_json::from_slice::<serde_json::Value>(&body)
            .expect("streamed manifest is still valid JSON");
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
