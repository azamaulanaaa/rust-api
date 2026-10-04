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
    /// Caps concurrent replica downloads.
    ///
    /// This is the control that matters for this module: `/sync/db/{object}`
    /// can serve an oxkv SST segment, so N concurrent readers is N segments
    /// of bandwidth and object-store egress. A request-rate limit does not
    /// bound that, since the allowed rate can still be in flight all at once.
    gate: crate::limits::ConcurrencyGate,
}

impl SyncApiModule {
    /// Create the module.
    pub fn new(manager: SnapshotManager, jwt: JwtClaimsMiddleware<Claims>) -> Self {
        Self {
            manager,
            jwt,
            gate: crate::limits::ConcurrencyGate::new(0),
        }
    }

    /// The module's download gate, for a caller that needs to reason about
    /// the same slots -- tests, or a host app composing its own routes.
    pub fn gate(&self) -> crate::limits::ConcurrencyGate {
        self.gate.clone()
    }

    /// Create the module with a cap on concurrent replica downloads.
    ///
    /// `max_concurrent` of `0` disables the gate.
    pub fn with_download_gate(
        manager: SnapshotManager,
        jwt: JwtClaimsMiddleware<Claims>,
        max_concurrent: usize,
    ) -> Self {
        Self {
            gate: crate::limits::ConcurrencyGate::new(max_concurrent),
            ..Self::new(manager, jwt)
        }
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
                .app_data(web::Data::new(self.gate.clone()))
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

/// The one replica object that is revalidated per commit.
///
/// Engine files are immutable by construction; this one is rewritten by
/// every build, so caching it is how a client ends up pinned to a replica
/// state that no longer exists.
const MANIFEST_OBJECT: &str = "manifest.json";

/// Quoted `ETag` for a `GET /sync/status` body.
///
/// Covers every field the body exposes: coverage (`applied`), the never-
/// built case (`none`), and `head`. `head` was the omission that mattered --
/// the WAL is shared across subjects (`snapshot.rs` reads one
/// `manager.wal.head()`), so it moves for reasons that have nothing to do
/// with the caller, and the 304 fired exactly when there was new work.
///
/// `Option` rather than a sentinel so "never built" cannot collide with a
/// real sequence, the way an `applied.unwrap_or(0)` would.
fn status_etag(applied: Option<u64>, head: u64) -> String {
    match applied {
        Some(a) => format!("\"snap-{a}-h{head}\""),
        None => format!("\"snap-none-h{head}\""),
    }
}

/// Quoted `ETag` for a `POST /sync/sync` body.
///
/// Covers `applied_seq` and `pending`, because `pending` is how a client
/// learns a rebuild was queued, and a validator that omitted it made the
/// documented recovery loop unreachable.
///
/// The failure this closes: the replica is at `applied_seq 0` and the
/// client caches `200 {applied_seq: 0, pending: false}` with ETag
/// `"snap-0"`. A legacy policy mark lands, so the replica now needs a full
/// rebuild -- a state this module documents, where `applied_seq` "may be
/// below the WAL head even on a 200". The client re-POSTs with
/// `If-None-Match: "snap-0"`. Coverage did not move, so the validator is
/// byte-identical, the server answers 304 and suppresses the body, and the
/// client still believes `pending: false` and never polls again.
fn advance_etag(applied_seq: u64, pending: bool) -> String {
    format!("\"snap-{applied_seq}-p{}\"", u8::from(pending))
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
    let etag = status_etag(applied, head);
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
    let etag = advance_etag(outcome.applied_seq, outcome.pending);
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
    gate: web::Data<crate::limits::ConcurrencyGate>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, FsError> {
    use object_store::ObjectStore as _;

    let tail = path.into_inner();
    let key = manager.resolve_object(&claims.sub, &tail)?;

    // Cache policy follows the RESOLVED key, not the raw tail. The route is
    // `@get("/db/{object:.*}")` and actix-router does not collapse repeated
    // slashes, so `GET /sync/db//manifest.json` arrives with
    // `tail == "/manifest.json"` while resolving to the very same object as
    // the canonical URL -- `object_store`'s `Path::from` drops empty
    // segments, and `/db/{object:.*}` is matched on the raw path. Keying
    // `tail == "manifest.json"` therefore served the one object this module
    // documents as revalidated per commit with
    // `Cache-Control: public, max-age=31536000, immutable`: a browser or CDN
    // would keep it for a year and never revalidate, permanently pinning the
    // client to whatever replica state existed at first fetch while every
    // client on the canonical URL converged.
    //
    // `resolve_object` now rejects empty segments as well, so the alias does
    // not exist at all; deriving from the resolved key is the second of two
    // independent defences and the one that cannot be routed around by any
    // other spelling of the path. `filename()` is the last segment of the
    // resolved key, so it can only name `manifest.json` for an object that
    // genuinely IS the manifest -- no non-manifest can be served `no-cache`
    // by forging it, and the manifest cannot be served immutable by hiding a
    // slash.
    let object_path = object_store::path::Path::from(key.as_str());
    let is_manifest = object_path.filename() == Some(MANIFEST_OBJECT);

    // Taken before the object store is touched, so a refused request costs one
    // `get` at most rather than a whole segment read.
    let permit = gate.acquire();
    if permit.is_none() && !gate.is_disabled() {
        return Err(FsError::TooManyRequests);
    }

    let store = manager.object_store.clone();
    // A plain `get` rather than pushing `If-None-Match` into the backend's
    // `GetOptions`. Both are a single metadata request and neither reads the
    // body -- `GetResult`'s payload is lazy until `into_stream` -- but only
    // this one leaves the `ETag` in hand, and a `304` that omits the
    // validator the corresponding `200` would have sent is what RFC 9110
    // 15.4.5 asks a `304` to carry.
    let out = match store.get(&object_path).await {
        Ok(out) => out,
        Err(object_store::Error::NotFound { .. }) => {
            return Ok(HttpResponse::NotFound().finish());
        }
        Err(e) => return Err(FsError::Internal(e.to_string())),
    };

    // Read the head off `out` before `into_stream` consumes it.
    let etag = out.meta.e_tag.clone();
    let size = out.range.end.saturating_sub(out.range.start);
    if let Some(header) = req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        && etag
            .as_deref()
            .is_some_and(|current| etag_matches(header, current))
    {
        // Dropping `out` abandons the unread payload, which is the point: a
        // not-modified answer has no body to send.
        drop(out);
        return Ok(object_not_modified(etag.as_deref(), is_manifest));
    }
    object_response(out, is_manifest, etag, size, permit)
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
    is_manifest: bool,
    etag: Option<String>,
    size: u64,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<HttpResponse, FsError> {
    let mut resp = HttpResponse::Ok();
    if let Some(ref etag) = etag {
        resp.insert_header((ETAG, etag.as_str()));
    }
    let mut resp = object_cache_headers(resp, is_manifest);
    Ok(resp
        .insert_header((CONTENT_LENGTH, size))
        // The permit travels with the body, so the slot is held until the
        // download finishes or the client goes away -- not merely until this
        // handler returns.
        .streaming(crate::limits::GatedStream::new(
            logged_body(out.into_stream()),
            permit,
        )))
}

/// The caching and content-type headers for one replica object.
///
/// Split out because the `304` for the same object must carry the same
/// ones: RFC 9110 15.4.5 asks a `304` to generate the header fields a `200`
/// would have sent, and the object `304` here used to send carried neither
/// `Cache-Control` nor `ETag` while every other `304` in this file re-attached
/// its validator. A client that revalidates on `Cache-Control` alone -- which
/// is exactly what a manifest client does, since the manifest is the only
/// object it fetches without an `If-None-Match` -- learns nothing about how
/// long the copy it already holds stays good.
fn object_cache_headers(
    mut resp: actix_web::HttpResponseBuilder,
    is_manifest: bool,
) -> actix_web::HttpResponseBuilder {
    if is_manifest {
        resp.insert_header((CACHE_CONTROL, "no-cache"));
        resp.insert_header((CONTENT_TYPE, "application/json"));
    } else {
        resp.insert_header((CACHE_CONTROL, "public, max-age=31536000, immutable"));
        resp.insert_header((CONTENT_TYPE, "application/octet-stream"));
    }
    resp
}

/// The `304` for a replica object, carrying the headers a `200` would have.
fn object_not_modified(etag: Option<&str>, is_manifest: bool) -> HttpResponse {
    let mut resp = HttpResponse::NotModified();
    if let Some(etag) = etag {
        resp.insert_header((ETAG, etag));
    }
    object_cache_headers(resp, is_manifest).finish()
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

        let resp = object_response(out, false, Some("\"v1\"".into()), SEGMENT, None)
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

    /// The validators are quoted, stable, and cover every field the body
    /// exposes.
    ///
    /// Each function is paired with the route that serves it because the
    /// bodies carry DIFFERENT fields: `GET /sync/status` reports `head`, and
    /// `POST /sync/sync` reports `pending`. A single validator built from
    /// `applied_seq` alone was correct for neither once either of those
    /// moved -- see the functions' docs for the two failure paths. The two
    /// assertions that would have caught it are the cross-route ones: the
    /// same coverage at a different head, and the same coverage with a
    /// different `pending`, must NOT share a validator.
    #[test]
    fn snapshot_etags_cover_every_field_the_body_exposes() {
        assert_eq!(status_etag(Some(3), 9), "\"snap-3-h9\"");
        assert_eq!(status_etag(None, 9), "\"snap-none-h9\"");

        assert_eq!(advance_etag(3, false), "\"snap-3-p0\"");
        assert_eq!(advance_etag(3, true), "\"snap-3-p1\"");

        // `head` moves for reasons unrelated to this caller, so it must be in
        // the status validator.
        assert_ne!(status_etag(Some(3), 9), status_etag(Some(3), 10));
        // A never-built replica is not coverage zero.
        assert_ne!(status_etag(None, 9), status_etag(Some(0), 9));
        // `pending` is how a client learns a rebuild was queued, so it must
        // be in the sync validator even when coverage did not move.
        assert_ne!(advance_etag(0, false), advance_etag(0, true));
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
        assert_eq!(etag, "\"snap-0-h0\"");
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

    /// A transition INTO `pending` must answer 200 with the body, never 304.
    ///
    /// The regression this pins: the validator was built from `applied_seq`
    /// alone, so a client that cached `200 {applied_seq: 0, pending: false}`
    /// and then re-POSTed with that ETag got a byte-identical validator back
    /// -- coverage did not move, only `pending` did. The server answered 304
    /// and suppressed the body, and the client kept believing `pending:
    /// false`, so it never polled again. The module's documented recovery
    /// loop ("keep polling `GET /sync/status` and advancing until this is
    /// false") was unreachable for any client using the ETag the endpoint
    /// hands it.
    ///
    /// Asserted in both directions: the repeat poll that changes nothing is
    /// still a 304, so the fix is not "stop sending validators".
    #[actix_web::test]
    async fn a_pending_transition_returns_the_body_not_304() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = SyncApiModule::new(fx.manager.clone(), setup(&fx).await?);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let sync = |if_none_match: Option<String>| async {
            let mut req = actix_web::test::TestRequest::post()
                .uri("/sync/sync")
                .insert_header(("Cookie", format!("auth_token={token}")));
            if let Some(tag) = if_none_match {
                req = req.insert_header((IF_NONE_MATCH, tag));
            }
            actix_web::test::call_service(&app, req.to_request()).await
        };

        // The replica is already built and the feed is empty, so this is the
        // settled state a client caches.
        let res = sync(None).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let settled = res
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .expect("every sync response carries a validator");
        let json: serde_json::Value =
            serde_json::from_slice(&actix_web::test::read_body(res).await)?;
        assert_eq!(json["pending"], false, "nothing to rebuild yet: {json}");

        // A legacy policy mark makes the replica need a full rebuild --
        // exactly the state whose doc says `applied_seq` may be below the
        // head even on a 200.
        fx.manager
            .wal
            .append(WalOp::PolicyAdd {
                obj: "invoice:1".into(),
            })
            .await?;

        // Coverage is still 0. Only `pending` changed.
        let res = sync(Some(settled.clone())).await;
        assert_eq!(
            res.status(),
            http::StatusCode::OK,
            "a transition into pending must not be suppressed as not-modified"
        );
        let again = res
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .expect("the 200 carries its own validator");
        let json: serde_json::Value =
            serde_json::from_slice(&actix_web::test::read_body(res).await)?;
        assert_eq!(
            json["pending"], true,
            "the client must be told a rebuild was queued: {json}"
        );

        // A repeat poll that changes nothing is still a 304.
        assert_ne!(
            again, settled,
            "the validator must move when pending does, or the 304 above was \
             a coincidence of a different bug"
        );
        assert_eq!(
            sync(Some(again)).await.status(),
            http::StatusCode::NOT_MODIFIED
        );
        Ok(())
    }

    /// The replica gateway refuses rather than reading a segment it has no
    /// room for.
    ///
    /// `/sync/db/{object}` can serve an oxkv SST segment, so this is the one
    /// place in the crate where a single request's cost is unbounded by the
    /// request. A rate limit does not cover it: a client allowed a hundred
    /// reads a minute can have a hundred of these in flight at once.
    ///
    /// The gate shares its semaphore across clones, so the test can hold the
    /// only slot against the *real* module and then drive the real handler --
    /// no stand-in route and no hand-built response.
    #[actix_web::test]
    async fn a_full_download_gate_refuses_rather_than_reading() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = SyncApiModule::with_download_gate(fx.manager.clone(), setup(&fx).await?, 1);
        let gate = module.gate();
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let read = || async {
            actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri("/sync/db/manifest.json")
                    .insert_header(("Cookie", format!("auth_token={token}")))
                    .to_request(),
            )
            .await
            .status()
        };

        // A free slot serves.
        assert_eq!(read().await, http::StatusCode::OK);

        // Hold the only slot: the next read must be refused, not served.
        let held = gate.acquire().expect("the only slot is free");
        assert_eq!(read().await, http::StatusCode::TOO_MANY_REQUESTS);

        // And the refusal is inside the uniform envelope, not actix's default.
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/sync/db/manifest.json")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        let json: serde_json::Value =
            serde_json::from_slice(&actix_web::test::read_body(res).await)?;
        assert_eq!(json["error"], "too many requests", "{json}");

        // Releasing the slot restores service.
        drop(held);
        assert_eq!(read().await, http::StatusCode::OK);
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
                    .insert_header((IF_NONE_MATCH, etag.clone()))
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::NOT_MODIFIED);
            // RFC 9110 15.4.5: a 304 carries the header fields the
            // corresponding 200 would have sent. This one used to carry
            // neither the validator nor the caching contract, while every
            // other 304 in this file re-attached its own.
            assert_eq!(
                res.headers().get(ETAG).and_then(|v| v.to_str().ok()),
                Some(etag.as_str()),
                "a 304 must re-attach the ETag the 200 carried"
            );
            assert_eq!(
                res.headers()
                    .get(CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-cache"),
                "a 304 must re-attach the Cache-Control the 200 carried"
            );
            assert_eq!(
                res.headers()
                    .get(actix_web::http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some("application/json")
            );
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

    /// The manifest alias must not be served immutable.
    ///
    /// The failure this pins: the cache-control branch keyed off the RAW
    /// path tail, and `resolve_object` rejected only an empty tail or a
    /// `..` segment -- an empty INTERIOR segment passed, while
    /// `object_store`'s `Path::from` drops empty segments when splitting on
    /// `/`. So `GET /sync/db//manifest.json` resolved to the same
    /// per-commit-MUTABLE object as the canonical URL, with
    /// `tail == "/manifest.json"`, which is not `"manifest.json"`: a `200`
    /// with `Cache-Control: public, max-age=31536000, immutable`. A browser
    /// or CDN keeps that for a year and never revalidates, permanently
    /// pinning the client to whatever replica state existed at first fetch
    /// while every client on the canonical URL converges -- the module's own
    /// contract at the top of this file, inverted for one URL.
    ///
    /// Both halves of the fix are asserted. `resolve_object` now rejects
    /// empty segments, so the alias does not exist; and the branch is
    /// derived from the resolved key, so the manifest cannot be served
    /// immutable by any other spelling of the path either.
    #[actix_web::test]
    async fn the_manifest_alias_is_not_served_immutable() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = SyncApiModule::new(fx.manager.clone(), setup(&fx).await?);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let fetch = |uri: &'static str| async {
            actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri(uri)
                    .insert_header(("Cookie", format!("auth_token={token}")))
                    .to_request(),
            )
            .await
        };
        let cache = |res: &actix_web::dev::ServiceResponse| {
            res.headers()
                .get(CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };

        // The alias resolves to nothing: `resolve_object` rejects the empty
        // interior segment.
        assert_eq!(
            fetch("/sync/db//manifest.json").await.status(),
            http::StatusCode::BAD_REQUEST,
            "an empty interior segment must not address a replica object"
        );

        // And the canonical URL is unchanged.
        let res = fetch("/sync/db/manifest.json").await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(cache(&res).as_deref(), Some("no-cache"));
        Ok(())
    }

    /// The resolved key, not the path tail, decides the caching contract.
    ///
    /// Structural because the property is about a branch that cannot be
    /// reached with the alias gone: `object_handler` must derive
    /// `is_manifest` from `Path::filename()` of the RESOLVED key. Keying it
    /// off the raw tail is what made `/manifest.json` immutable, and
    /// deleting the alias alone would leave the same inversion reachable by
    /// any future path spelling that `Path::from` normalises.
    ///
    /// It also pins the direction that matters for safety: a key whose
    /// filename is not `manifest.json` must NOT be served `no-cache`, so the
    /// resolved-key derivation cannot be used to hand a non-manifest the
    /// weaker policy.
    #[test]
    fn cache_control_follows_the_resolved_key() {
        for (key, expect_manifest) in [
            ("test-db/u/abc/manifest.json", true),
            // An alias the backend normalises to the same object.
            ("test-db/u/abc//manifest.json", true),
            ("test-db/u/abc/sst/seg-0001.sst", false),
            ("test-db/u/abc/not-manifest.json", false),
            ("test-db/u/abc/manifest.json.bak", false),
        ] {
            let path = object_store::path::Path::from(key);
            assert_eq!(
                path.filename() == Some(MANIFEST_OBJECT),
                expect_manifest,
                "{key}"
            );
        }
    }
}
