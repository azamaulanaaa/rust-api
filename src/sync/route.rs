//! Per-user replica pointer plus the replica object gateway.
//!
//! `GET /sync/status` returns the replica pointer (`prefix`, `applied_seq`,
//! `head`) with an `ETag`, so repeat polls cost a cheap `304`. The route
//! never builds. `POST /sync/sync` advances the replica toward the WAL
//! head (short-circuit, replay, or full recalc) and returns the new
//! pointer. Every object inside the replica prefix has its own address at
//! `GET /sync/db/{object}`. That route passes the backend `ETag` through
//! and supports `If-None-Match`. A client then checks for changes through
//! headers and downloads only the objects that moved. Three names inside the
//! prefix change under one name (`manifest.json`, `ownership.json`,
//! `probe/canary`) and are revalidated (`Cache-Control: no-cache`). The
//! append-only and content-addressed classes (`e{epoch}/sst/*`,
//! `e{epoch}/wal/*`, `e{epoch}/blob/*`) are immutable by construction
//! (`Cache-Control: public, max-age=31536000, immutable`).

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
    /// This is the control that matters for this module. The route
    /// `/sync/db/{object}` can serve an oxkv SST segment. Each concurrent
    /// reader then uses one segment of bandwidth and object-store egress. A
    /// request-rate limit does not bound that, because the allowed rate can
    /// be in flight all at once.
    gate: crate::limits::ConcurrencyGate,
}

impl SyncApiModule {
    /// Creates the module.
    pub fn new(manager: SnapshotManager, jwt: JwtClaimsMiddleware<Claims>) -> Self {
        Self {
            manager,
            jwt,
            gate: crate::limits::ConcurrencyGate::new(0),
        }
    }

    /// The download gate of the module. A caller uses it to reason about the
    /// same slots. Such a caller is a test, or a host app that composes its
    /// own routes.
    pub fn gate(&self) -> crate::limits::ConcurrencyGate {
        self.gate.clone()
    }

    /// Creates the module with a cap on concurrent replica downloads.
    ///
    /// A `max_concurrent` of `0` disables the gate.
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
    /// `applied_seq` shows what the replica covered *before* that rebuild.
    ///
    /// A rebuild scans the whole master, so the code queues it instead of
    /// running it inside the request. The client must then keep polling
    /// `GET /sync/status` and advancing until this field is false. The field
    /// adds data to the response, so existing clients keep working. A client
    /// that assumed one `POST /sync/sync` always converged must now read
    /// this field.
    pub pending: bool,
}

/// The replica object that the engine rewrites on every commit.
///
/// The engine bumps this object with a compare-and-set on every commit.
/// Caching it is how a client ends up pinned to a replica state that no
/// longer exists.
const MANIFEST_OBJECT: &str = "manifest.json";

/// The replica object that the engine rewrites on every writer build.
///
/// The engine acquires ownership of a prefix by writing this object with a
/// compare-and-set that raises the epoch. The code opens a writer for every
/// build. The object therefore changes under one name on every rebuild.
const OWNERSHIP_OBJECT: &str = "ownership.json";

/// The replica object that the storage probe rewrites under one name.
///
/// The storage probe writes this object with `Create` and then with `Update`,
/// and the two puts carry different bytes. The probe removes the object when
/// it ends. A reader that asks for the object during a build sees it, so the
/// code revalidates it.
const PROBE_CANARY_OBJECT: &str = "probe/canary";

/// The objects of a replica prefix that change under one name.
///
/// The engine writes these three names at the top level of the prefix. The
/// engine never writes any other name twice with different bytes. It refuses
/// to overwrite a segment object or a log object that holds other bytes. The
/// name of a blob object is the SHA-256 of its value.
const MUTABLE_OBJECTS: &[&str] = &[MANIFEST_OBJECT, OWNERSHIP_OBJECT, PROBE_CANARY_OBJECT];

/// The objects of a replica prefix that hold a JSON document.
const JSON_OBJECTS: &[&str] = &[MANIFEST_OBJECT, OWNERSHIP_OBJECT];

/// Quoted `ETag` for a `GET /sync/status` body.
///
/// The value covers every field that the body exposes: the coverage
/// (`applied`), the never-built case (`none`), and `head`. The earlier code
/// left out `head`, and that omission mattered. The WAL is shared across
/// subjects, because `snapshot.rs` reads one `manager.wal.head()`. The head
/// then moves for reasons that have nothing to do with the caller, and the
/// 304 fired exactly when there was new work.
///
/// The function uses `Option` instead of a sentinel, so that "never built"
/// cannot collide with a real sequence the way an `applied.unwrap_or(0)`
/// would.
fn status_etag(applied: Option<u64>, head: u64) -> String {
    match applied {
        Some(a) => format!("\"snap-{a}-h{head}\""),
        None => format!("\"snap-none-h{head}\""),
    }
}

/// Quoted `ETag` for a `POST /sync/sync` body.
///
/// The value covers `applied_seq` and `pending`. A client learns from
/// `pending` that the code queued a rebuild. A validator that left out
/// `pending` made the documented recovery loop unreachable.
///
/// The earlier failure that this closes: the replica is at `applied_seq 0`,
/// and the client caches `200 {applied_seq: 0, pending: false}` with ETag
/// `"snap-0"`. A legacy policy mark lands, so the replica now needs a full
/// rebuild. The module documents that state, in which `applied_seq` "may be
/// below the WAL head even on a 200". The client sends a new POST with
/// `If-None-Match: "snap-0"`. The coverage did not move, so the validator is
/// byte-identical. The server answers 304 and suppresses the body. The
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

/// Strips the weak prefix and the quotes, so that the code can compare two
/// opaque tags.
fn normalize_etag(tag: &str) -> &str {
    let tag = tag.trim();
    let tag = tag.strip_prefix("W/").unwrap_or(tag).trim();
    tag.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(tag)
}

/// Returns the replica pointer for `sub` without building.
///
/// The function only reads. It reports the current coverage (`applied_seq`,
/// `None` when the replica was never built) next to the WAL `head`, so that
/// a client can decide whether a `POST /sync/sync` is worthwhile. The
/// function never touches the replica beyond the coverage-marker read.
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
/// A fresh pointer (`applied >= head`) returns without touching storage
/// beyond the marker read. Otherwise small file and relation deltas and rich
/// rule or group ops replay. Irrelevant users and objects skip. Legacy
/// policy marks and oversized ranges select a full rebuild. A lost
/// fencing race adopts the pointer of the winner instead of returning an
/// error.
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
/// The value `sub` always comes from the JWT, never from the path. A caller
/// can therefore read only its own replica. A missing object returns 404. A
/// match on `If-None-Match` returns 304 without a body.
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

    // The cache policy follows the RESOLVED key, not the raw tail. The route
    // is `@get("/db/{object:.*}")`, and actix-router does not collapse
    // repeated slashes. So `GET /sync/db//manifest.json` arrives with
    // `tail == "/manifest.json"` while resolving to the same object as the
    // canonical URL. `object_store`'s `Path::from` drops empty segments, and
    // `/db/{object:.*}` matches on the raw path. Keying the cache policy on
    // `tail == "manifest.json"` therefore served an object that the engine
    // rewrites on every commit with this header:
    // `Cache-Control: public, max-age=31536000, immutable`: a browser or CDN
    // would then keep that header for a year and never revalidate. The
    // client would stay pinned to the replica state at its first fetch, while
    // every client on the canonical URL converged.
    //
    // `resolve_object` now rejects empty segments as well, so the alias does
    // not exist. Deriving the cache policy from the resolved key is the second
    // of two independent defences. It is the defence that no other spelling
    // of the path can go around. The code compares the resolved key with the
    // replica prefix of the caller, followed by one name from
    // `MUTABLE_OBJECTS`. Only an object that is genuinely one of those names
    // receives `no-cache`. No other object receives `no-cache` by forging a
    // name. No mutable object receives the immutable header through any
    // spelling of the path.
    let object_path = object_store::path::Path::from(key.as_str());
    let replica_prefix = object_store::path::Path::from(manager.user_prefix(&claims.sub).as_str());
    let is_mutable = is_mutable_object_key(&object_path, &replica_prefix);
    let is_json = is_json_object_key(&object_path, &replica_prefix);

    // The code takes the permit before it touches the object store. A refused
    // request then costs at most one `get`.
    let permit = gate.acquire();
    if permit.is_none() && !gate.is_disabled() {
        return Err(FsError::TooManyRequests);
    }

    let store = manager.object_store.clone();
    // The code sends a plain `get` instead of pushing `If-None-Match` into
    // the `GetOptions` of the backend. Both calls make one metadata request,
    // and neither one reads the body. The payload of `GetResult` stays lazy
    // until `into_stream`. Only the plain `get` leaves the `ETag` in hand. A
    // `304` that omits the validator of the matching `200` would break what
    // RFC 9110 15.4.5 asks a `304` to carry.
    let out = match store.get(&object_path).await {
        Ok(out) => out,
        Err(object_store::Error::NotFound { .. }) => {
            return Ok(HttpResponse::NotFound().finish());
        }
        Err(e) => return Err(FsError::Internal(e.to_string())),
    };

    // Read the head of `out` before `into_stream` consumes it.
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
        // Dropping `out` abandons the unread payload, and that is the point.
        // A not-modified answer has no body to send.
        drop(out);
        return Ok(object_not_modified(etag.as_deref(), is_mutable, is_json));
    }
    object_response(out, is_mutable, is_json, etag, size, permit)
}

/// Whether this object changes under one name inside the replica prefix.
///
/// The function derives the answer from the RESOLVED key and from the replica
/// prefix of the caller. It never reads the raw request tail. The resolved key
/// and the raw tail can disagree. `resolve_object` used to accept an empty
/// interior segment, so `GET /sync/db//manifest.json` reached the real manifest
/// through a different spelling. Keying the mutable and immutable decision on
/// the raw tail then served that manifest with `immutable, max-age=31536000`.
/// `resolve_object` now rejects empty segments as well. Deriving from the
/// resolved key is the property that actually holds, and this function is the
/// only place where that property lives.
///
/// `Path::from` drops empty segments and normalises separators. Therefore
/// the comparison sees the key that the backend will actually serve.
///
/// The engine writes the objects of a replica prefix under these names:
/// `manifest.json`, `ownership.json`, `probe/canary`, `e*/sst/*`, `e*/wal/*`,
/// and `e*/blob/*`. The first three change under one name. The engine never
/// writes any other name twice with different bytes.
fn is_mutable_object_key(
    path: &object_store::path::Path,
    replica_prefix: &object_store::path::Path,
) -> bool {
    is_one_object_of(path, replica_prefix, MUTABLE_OBJECTS)
}

/// Whether this object holds a JSON document.
///
/// The function uses the same derivation as [`is_mutable_object_key`]. The
/// storage probe canary holds the bytes of the probe, so it is served as an
/// octet stream even though the code revalidates it.
fn is_json_object_key(
    path: &object_store::path::Path,
    replica_prefix: &object_store::path::Path,
) -> bool {
    is_one_object_of(path, replica_prefix, JSON_OBJECTS)
}

/// Whether `path` is `replica_prefix` followed by one name from `names`.
///
/// The function builds the candidate key as one string. `Path::child` treats
/// a `/` inside its argument as a legal character of a single segment, so it
/// cannot build the two segment name of the storage probe canary.
fn is_one_object_of(
    path: &object_store::path::Path,
    replica_prefix: &object_store::path::Path,
    names: &[&str],
) -> bool {
    names.iter().any(|name| {
        path == &object_store::path::Path::from(format!("{}/{name}", replica_prefix.as_ref()))
    })
}

/// The `200` response for one replica object, streaming `out`.
///
/// The function is separate from [`object_handler`] so that a test can check
/// the streaming property. The caller must hand over a [`GetResult`] that it
/// has not read yet. The only way to build the response is to consume the
/// result as a stream.
///
/// A replica prefix holds the files of oxkv itself. The code sizes an SST
/// segment for compaction throughput, not for a browser. A segment reaches
/// tens or hundreds of megabytes. Collecting the segment would put it in
/// resident memory once per in-flight request, on every worker, for a
/// payload that the client buffers anyway. The code takes `Content-Length`
/// from the range that `object_store` already resolved. Clients therefore see
/// the size up front, and the immutability caching still works.
fn object_response(
    out: object_store::GetResult,
    is_mutable: bool,
    is_json: bool,
    etag: Option<String>,
    size: u64,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<HttpResponse, FsError> {
    let mut resp = HttpResponse::Ok();
    if let Some(ref etag) = etag {
        resp.insert_header((ETAG, etag.as_str()));
    }
    let mut resp = object_cache_headers(resp, is_mutable, is_json);
    Ok(resp
        .insert_header((CONTENT_LENGTH, size))
        // The permit travels with the body, so the code holds the slot until
        // the download finishes or the client goes away. The code does not
        // release the slot when this handler returns.
        .streaming(crate::limits::GatedStream::new(
            logged_body(out.into_stream()),
            permit,
        )))
}

/// The caching and content-type headers for one replica object.
///
/// The function is separate because the `304` for the same object must carry
/// the same headers. RFC 9110 15.4.5 asks a `304` to generate the header
/// fields that a `200` would have sent. The `304` for an object used to carry
/// neither `Cache-Control` nor `ETag`. Every other `304` in this file
/// re-attaches its validator. A client that revalidates on `Cache-Control`
/// alone learns nothing about how long the copy it already holds stays good.
/// A manifest client does exactly that, because the manifest is the only
/// object that it fetches without an `If-None-Match`.
fn object_cache_headers(
    mut resp: actix_web::HttpResponseBuilder,
    is_mutable: bool,
    is_json: bool,
) -> actix_web::HttpResponseBuilder {
    if is_mutable {
        resp.insert_header((CACHE_CONTROL, "no-cache"));
    } else {
        resp.insert_header((CACHE_CONTROL, "public, max-age=31536000, immutable"));
    }
    if is_json {
        resp.insert_header((CONTENT_TYPE, "application/json"));
    } else {
        resp.insert_header((CONTENT_TYPE, "application/octet-stream"));
    }
    resp
}

/// The `304` for a replica object, carrying the headers a `200` would have.
fn object_not_modified(etag: Option<&str>, is_mutable: bool, is_json: bool) -> HttpResponse {
    let mut resp = HttpResponse::NotModified();
    if let Some(etag) = etag {
        resp.insert_header((ETAG, etag));
    }
    object_cache_headers(resp, is_mutable, is_json).finish()
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
    /// This test guards the memory property. It works because
    /// [`object_response`] takes a `GetResult` that it has not touched. The
    /// stream handed to the function yields one chunk, then fails. An
    /// implementation that collects the body would read past that failure.
    /// That implementation would then surface the failure as a handler error
    /// instead of a `200`, and would record a poll. So a revert to
    /// `out.bytes()` fails fast here instead of passing quietly.
    ///
    /// A unit test cannot observe resident memory directly. The test can
    /// observe the property that keeps a 256 MB SST out of the heap once per
    /// in-flight request. No byte of the segment is read before the response
    /// exists.
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
                            // implementation cannot avoid.
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

        let resp = object_response(out, false, false, Some("\"v1\"".into()), SEGMENT, None)
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

    /// The validators are quoted, stable, and cover every field that the body
    /// exposes.
    ///
    /// Each function is paired with the route that serves it, because the
    /// bodies carry DIFFERENT fields. `GET /sync/status` reports `head`, and
    /// `POST /sync/sync` reports `pending`. A single validator built from
    /// `applied_seq` alone was correct for neither route once either field
    /// moved. See the docs of the functions for the two failure paths. Two
    /// assertions would have caught that fault. They are the cross-route
    /// ones. The same coverage at a different head, and the same coverage
    /// with a different `pending`, must NOT share a validator.
    #[test]
    fn snapshot_etags_cover_every_field_the_body_exposes() {
        assert_eq!(status_etag(Some(3), 9), "\"snap-3-h9\"");
        assert_eq!(status_etag(None, 9), "\"snap-none-h9\"");

        assert_eq!(advance_etag(3, false), "\"snap-3-p0\"");
        assert_eq!(advance_etag(3, true), "\"snap-3-p1\"");

        // `head` moves for reasons that are unrelated to this caller, so the
        // status validator must contain it.
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
    fn lost_fencing_race_is_a_typed_variant() {
        // The test guards against a past fault. The old code called
        // `detail.contains("fenced")`. A new wording in oxkv would then turn
        // a recoverable race into a 500 for every client. The value is now a
        // typed variant that `From<oxkv::StoreError>` produces.
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
        // Make the replica stale the way the engines do. The code changes the
        // master and appends a WAL entry, and no code calls advance.
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

        // The manifest ETag stays the same across status polls. No commit
        // runs.
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

    /// A rebuild that the code cannot replay is queued, and the response says
    /// so.
    ///
    /// The `200` with `pending: true` is the contract change to be careful
    /// about. A caller that sent one `POST /sync/sync` and expected to read
    /// its replica immediately now sees the coverage from before the rebuild.
    /// The field makes that visible instead of silent. `GET /sync/status` is
    /// the poll that watches the coverage move.
    #[actix_web::test]
    async fn a_needed_rebuild_is_reported_as_pending() -> anyhow::Result<()> {
        use crate::records::WalOp;

        let fx = fixture().await?;
        let module = SyncApiModule::new(fx.manager.clone(), setup(&fx).await?);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        // The fixture already built the replica, so a plain advance does
        // nothing. A legacy policy mark is the one delta that the code cannot
        // replay incrementally. The mark carries no rule, only an object name.
        // The mark therefore forces the full-recalculate path.
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
    /// The test pins the fault that this fixes. The earlier validator was
    /// built from `applied_seq` alone. A client that cached `200
    /// {applied_seq: 0, pending: false}` and then sent a new POST with that
    /// ETag received a byte-identical validator. The coverage did not move.
    /// Only `pending` moved. The server answered 304 and suppressed the body.
    /// The client then kept believing `pending: false`, so it never polled
    /// again. The documented recovery loop ("keep polling `GET /sync/status`
    /// and advancing until this is false") was unreachable for any client that
    /// used the ETag that the endpoint hands it.
    ///
    /// The test checks both directions. A repeat poll that changes nothing is
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
        // settled state that a client caches.
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

        // A legacy policy mark makes the replica need a full rebuild. This is
        // exactly the state whose doc says that `applied_seq` may be below
        // the head even on a 200.
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

    /// The replica gateway refuses a request instead of reading a segment
    /// that has no room for it.
    ///
    /// The route `/sync/db/{object}` can serve an oxkv SST segment. This is
    /// the only place in the crate where the cost of one request has no
    /// bound from the request. A rate limit does not cover it. A client that
    /// the rate limit allows a hundred reads a minute can still have a
    /// hundred of these in flight at once.
    ///
    /// The gate shares its semaphore across clones. The test can then hold
    /// the only slot against the *real* module and drive the real handler.
    /// The test uses no stand-in route and no hand-built response.
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

        // Hold the only slot. The next read must be refused, not served.
        let held = gate.acquire().expect("the only slot is free");
        assert_eq!(read().await, http::StatusCode::TOO_MANY_REQUESTS);

        // The refusal uses the uniform envelope, not the actix default.
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
        // A bounded replay runs inline, so the caller does not wait as
        // pending.
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
        // The body streams, so the response must declare its length up front.
        // A chunked response is still correct for a client. But
        // `manifest.json` is what a client polls to discover what changed. A
        // known length lets the client fail fast on a truncated read.
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
            // RFC 9110 15.4.5 requires a 304 to carry the header fields of
            // the matching 200. This 304 used to carry neither the validator
            // nor the caching contract, while every other 304 in this file
            // re-attached its own.
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

    /// The manifest alias must not receive the immutable cache header.
    ///
    /// The test pins the fault that it fixes. The cache-control branch keyed
    /// on the RAW path tail. `resolve_object` rejected only an empty tail or
    /// a `..` segment. An empty INTERIOR segment passed, while `object_store`'s
    /// `Path::from` drops empty segments when it splits on `/`. So `GET
    /// /sync/db//manifest.json` resolved to the same per-commit-MUTABLE
    /// object as the canonical URL. The tail at that moment was
    /// `/manifest.json`, which is not `manifest.json`. The response was then a
    /// `200` with this header:
    /// `Cache-Control: public, max-age=31536000, immutable`. A browser or
    /// CDN keeps that header for a year and never revalidates. The client
    /// then stays pinned to the replica state at its first fetch, while every
    /// client on the canonical URL converges. The module contract at the top
    /// of this file was inverted for one URL.
    ///
    /// The test checks both halves of the fix. `resolve_object` now rejects
    /// empty segments, so the alias does not exist. The branch also derives
    /// its value from the resolved key, so the manifest cannot receive the
    /// immutable header through any other spelling of the path.
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

        // The alias resolves to nothing. `resolve_object` rejects the empty
        // interior segment.
        assert_eq!(
            fetch("/sync/db//manifest.json").await.status(),
            http::StatusCode::BAD_REQUEST,
            "an empty interior segment must not address a replica object"
        );

        // The canonical URL does not change.
        let res = fetch("/sync/db/manifest.json").await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(cache(&res).as_deref(), Some("no-cache"));
        Ok(())
    }

    /// The resolved key, not the path tail, decides the caching contract.
    ///
    /// The test is structural, because the property applies to a branch that
    /// the alias can no longer reach. `object_handler` must derive
    /// `is_mutable` from the RESOLVED key and from the replica prefix.
    /// Keying it on the raw tail is what made `/manifest.json` immutable.
    /// Deleting the alias alone would leave the same inversion reachable
    /// through any future path spelling that `Path::from` normalises.
    ///
    /// The test covers every object class that the engine writes into a
    /// prefix. The three mutable names must not receive the immutable header,
    /// because the engine rewrites each of them under one name. The segment,
    /// log, and blob names must keep the one-year max-age, because the engine
    /// never writes other bytes under one of those names.
    ///
    /// The test also pins the direction that matters for safety. An object
    /// that is not a mutable name must NOT receive `no-cache`, even when it
    /// carries a mutable name below its own prefix. The derivation from the
    /// resolved key must not hand a forged name the weaker policy.
    #[test]
    fn cache_control_follows_the_resolved_key() {
        let digest = "a".repeat(64);
        let prefix = object_store::path::Path::from(format!("test-db/u/{digest}"));
        for (key, expect_mutable) in [
            (format!("test-db/u/{digest}/manifest.json"), true),
            (format!("test-db/u/{digest}/ownership.json"), true),
            (format!("test-db/u/{digest}/probe/canary"), true),
            (
                format!("test-db/u/{digest}/e000007/sst/L0/000000042.sst"),
                false,
            ),
            (
                format!("test-db/u/{digest}/e000007/wal/00000042.log"),
                false,
            ),
            (
                format!("test-db/u/{digest}/e000007/blob/{}", "b".repeat(64)),
                false,
            ),
            // An alias that the backend normalises to the same object.
            (format!("test-db/u/{digest}//manifest.json"), true),
            (format!("test-db/u/{digest}/manifest.json.bak"), false),
            (format!("test-db/u/{digest}/not-manifest.json"), false),
            // A mutable name below a class directory is a forged name.
            (format!("test-db/u/{digest}/blob/manifest.json"), false),
            // A mutable name under another subject's prefix is not mutable
            // for me. This row pins the prefix half of the rule: the
            // candidate key comes from the caller's own replica prefix, so a
            // revert that drops that argument fails here.
            (
                format!("test-db/u/{}/ownership.json", "c".repeat(64)),
                false,
            ),
        ] {
            // Through the SAME function that `object_handler` calls, so a
            // revert of the derivation in production fails this test instead
            // of leaving it green while the inversion returns.
            let path = object_store::path::Path::from(key.as_str());
            assert_eq!(
                is_mutable_object_key(&path, &prefix),
                expect_mutable,
                "{key}"
            );
        }

        // The two JSON objects hold a JSON document. The probe canary holds
        // the bytes of the probe, so it stays an octet stream.
        for (key, expect_json) in [
            (format!("test-db/u/{digest}/manifest.json"), true),
            (format!("test-db/u/{digest}/ownership.json"), true),
            (format!("test-db/u/{digest}/probe/canary"), false),
            (
                format!("test-db/u/{digest}/e000007/sst/L0/000000042.sst"),
                false,
            ),
        ] {
            let path = object_store::path::Path::from(key.as_str());
            assert_eq!(is_json_object_key(&path, &prefix), expect_json, "{key}");
        }
    }

    /// Every mutable object of a prefix asks the client to revalidate.
    ///
    /// The test drives the real handler through the real gateway. It writes
    /// one object of each class into the object store, because the engine
    /// writes `ownership.json` and the probe canary only for a backend that
    /// supports conditional writes.
    ///
    /// The test pins the fault that it fixes. The branch asked only one
    /// question, and the answer was "is this the manifest". Every other
    /// object then received `public, max-age=31536000, immutable`. The
    /// ownership record is one of those objects, and the engine rewrites it
    /// on every writer build with a higher epoch. A client or an intermediary
    /// that honours the header keeps a stale ownership record for a year.
    #[actix_web::test]
    async fn every_mutable_object_is_revalidated_and_engine_files_are_not() -> anyhow::Result<()> {
        use object_store::PutPayload;

        let fx = fixture().await?;
        let prefix = fx.manager.user_prefix("alice");
        let store = fx.manager.object_store.clone();
        for (name, bytes) in [
            ("manifest.json", &b"{}"[..]),
            ("ownership.json", &b"{\"epoch\":1}"[..]),
            ("probe/canary", &b"probe-ok"[..]),
            ("e000007/sst/L0/000000042.sst", &b"segment"[..]),
            ("e000007/wal/00000042.log", &b"log"[..]),
        ] {
            store
                .put(
                    &object_store::path::Path::from(format!("{prefix}/{name}")),
                    PutPayload::from(bytes.to_vec()),
                )
                .await?;
        }

        let module = SyncApiModule::new(fx.manager.clone(), setup(&fx).await?);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        for (name, expect_cache, expect_type) in [
            ("manifest.json", "no-cache", "application/json"),
            ("ownership.json", "no-cache", "application/json"),
            ("probe/canary", "no-cache", "application/octet-stream"),
            (
                "e000007/sst/L0/000000042.sst",
                "public, max-age=31536000, immutable",
                "application/octet-stream",
            ),
            (
                "e000007/wal/00000042.log",
                "public, max-age=31536000, immutable",
                "application/octet-stream",
            ),
        ] {
            let res = actix_web::test::call_service(
                &app,
                actix_web::test::TestRequest::get()
                    .uri(&format!("/sync/db/{name}"))
                    .insert_header(("Cookie", format!("auth_token={token}")))
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK, "{name}");
            assert_eq!(
                res.headers()
                    .get(CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some(expect_cache),
                "{name}"
            );
            assert_eq!(
                res.headers()
                    .get(actix_web::http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some(expect_type),
                "{name}"
            );
        }
        Ok(())
    }
}
