//! Actix routes for the S3-backed FS module.

use std::sync::Arc;

use actix_web::{HttpResponse, delete, get, post, put, web};
use bytes::Bytes;
use futures_util::TryStreamExt as _;

use crate::fs::FsEngine;
use crate::fs::model::{CompleteRequest, InitRequest, InitResponse};
use crate::http::ApiModule;
use crate::http::middleware::jwt::{Claims, JwtClaimsMiddleware, Validated};

/// API module exposing `/fs` routes, protected by JWT validation.
pub struct FsApiModule {
    engine: Arc<FsEngine>,
    jwt: JwtClaimsMiddleware<Claims>,
}

impl FsApiModule {
    /// Creates the module from an engine and JWT middleware.
    pub fn new(engine: FsEngine, jwt: JwtClaimsMiddleware<Claims>) -> Self {
        Self {
            engine: Arc::new(engine),
            jwt,
        }
    }
}

impl ApiModule for FsApiModule {
    fn configure(&self, cfg: &mut web::ServiceConfig) {
        let engine = web::Data::from(self.engine.clone());
        let jwt = self.jwt.clone();
        let scope = web::scope("/fs")
            .app_data(engine)
            .wrap(jwt)
            .service(init_upload)
            .service(upload_part)
            .service(complete_upload)
            .service(cancel_upload)
            .service(get_progress)
            .service(get_metadata)
            .service(get_file)
            .service(delete_file);
        cfg.service(scope);
    }
}

#[utoipa::path(post, path = "/fs/uploads", tag = "fs", request_body = InitRequest, responses((status=201, body=InitResponse), (status=401, body=crate::http::error::ErrorBody)))]
#[post("/uploads")]
async fn init_upload(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    body: web::Json<InitRequest>,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let file_id = engine.init_upload(body.into_inner(), &claims.sub).await?;
    Ok(HttpResponse::Created().json(serde_json::json!({ "file_id": file_id })))
}

#[utoipa::path(put, path = "/fs/uploads/{id}/parts/{idx}", tag = "fs", params(("id" = String, Path), ("idx" = u64, Path)), request_body(content = Vec<u8>, content_type = "application/octet-stream"), responses((status=204, description="part stored"), (status=401, body=crate::http::error::ErrorBody)))]
#[put("/uploads/{id}/parts/{idx}")]
async fn upload_part(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    path: web::Path<(String, u64)>,
    body: Bytes,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let (id, idx) = path.into_inner();
    // Checksum passthrough: S3 validates, we just forward base64 SHA256 if provided
    let checksum_sha256 = req
        .headers()
        .get("x-checksum-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            req.headers()
                .get("checksum-sha256")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        });
    engine
        .upload_part(&id, idx, body, checksum_sha256, &claims.sub)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(post, path = "/fs/uploads/{id}/complete", tag = "fs", params(("id" = String, Path)), request_body = CompleteRequest, responses((status=200, body=InitResponse), (status=401, body=crate::http::error::ErrorBody)))]
#[post("/uploads/{id}/complete")]
async fn complete_upload(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    body: web::Json<CompleteRequest>,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    body.validate()?;
    let id = path.into_inner();
    engine
        .complete_upload(&id, body.into_inner(), &claims.sub)
        .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "file_id": id })))
}

#[utoipa::path(delete, path = "/fs/uploads/{id}", tag = "fs", params(("id" = String, Path)), responses((status=204, description="cancelled")))]
#[delete("/uploads/{id}")]
async fn cancel_upload(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let id = path.into_inner();
    engine.cancel_upload(&id, &claims.sub).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(get, path = "/fs/uploads/{id}", tag = "fs", params(("id" = String, Path)), responses((status=200, body=crate::fs::model::ProgressResponse)))]
#[get("/uploads/{id}")]
async fn get_progress(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let id = path.into_inner();
    let prog = engine.get_progress(&id, &claims.sub).await?;
    Ok(HttpResponse::Ok().json(prog))
}

#[utoipa::path(get, path = "/fs/files/{id}/meta", tag = "fs", params(("id" = String, Path)), responses((status=200, body=crate::fs::model::FileMetadata)))]
#[get("/files/{id}/meta")]
async fn get_metadata(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let id = path.into_inner();
    let meta = engine.get_metadata(&id, &claims.sub).await?;
    Ok(HttpResponse::Ok().json(meta))
}

#[utoipa::path(get, path = "/fs/files/{id}", tag = "fs", params(("id" = String, Path), ("Range" = Option<String>, Header)), responses((status=200, description="binary"), (status=206, description="partial binary"), (status=416, description="range not satisfiable")))]
#[get("/files/{id}")]
async fn get_file(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    use actix_web::http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};

    let id = path.into_inner();
    // Metadata first: one cheap cached read gives auth plus the total
    // the range validates against, so exactly one S3 call follows.
    let meta = engine.get_metadata(&id, &claims.sub).await?;
    let header = req.headers().get(RANGE).and_then(|v| v.to_str().ok());
    match parse_range(header, meta.size) {
        RangeOutcome::Full => {
            let (rec, obj) = engine.get_object(&id, &claims.sub).await?;
            Ok(HttpResponse::Ok()
                .content_type(rec.mimetype)
                .insert_header((
                    "Content-Disposition",
                    format!("inline; filename=\"{}\"", sanitize_filename(&rec.name)),
                ))
                .insert_header((ACCEPT_RANGES, "bytes"))
                .insert_header((CONTENT_LENGTH, obj.size))
                .streaming(logged_stream(obj.stream)))
        }
        RangeOutcome::Ranged(r) => {
            let (rec, obj) = engine
                .get_object_range(&id, &claims.sub, r.start..r.end_inclusive + 1)
                .await?;
            // Headers describe what is actually streamed, not just what
            // was asked: identical in every non-adversarial case.
            let end = r.start + obj.size.saturating_sub(1);
            Ok(HttpResponse::PartialContent()
                .content_type(rec.mimetype)
                .insert_header((
                    "Content-Disposition",
                    format!("inline; filename=\"{}\"", sanitize_filename(&rec.name)),
                ))
                .insert_header((ACCEPT_RANGES, "bytes"))
                .insert_header((CONTENT_LENGTH, obj.size))
                .insert_header((
                    CONTENT_RANGE,
                    format!("bytes {}-{}/{}", r.start, end, meta.size),
                ))
                .streaming(logged_stream(obj.stream)))
        }
        RangeOutcome::Unsatisfiable => Ok(HttpResponse::build(
            actix_web::http::StatusCode::RANGE_NOT_SATISFIABLE,
        )
        .insert_header((CONTENT_RANGE, format!("bytes */{}", meta.size)))
        .finish()),
    }
}

/// Logs mid-stream download failures server-side (headers are already
/// sent by then, so the client just sees a truncated body).
fn logged_stream(
    stream: crate::fs::s3::ByteStream,
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, crate::fs::error::FsError>> {
    stream.map_err(|e| {
        tracing::warn!("file download stream failed: {e:?}");
        e
    })
}

/// A satisfiable single byte range (inclusive end).
struct ByteRange {
    start: u64,
    end_inclusive: u64,
}

/// Outcome of interpreting a `Range` header against a known total.
enum RangeOutcome {
    /// No (usable) header: serve the whole object (200).
    Full,
    /// Serve `start..=end_inclusive` (206).
    Ranged(ByteRange),
    /// Valid syntax past the end of the object (416).
    Unsatisfiable,
}

/// Interprets a `Range` header against `total`.
///
/// Single `bytes=` ranges only; anything else (missing header, foreign
/// unit, multi-range, malformed syntax, reversed bounds) falls back to a
/// full 200 response per RFC 9110 §14.2. An empty object satisfies
/// nothing, so any range on it is 416.
fn parse_range(header: Option<&str>, total: u64) -> RangeOutcome {
    let Some(spec) = header
        .map(str::trim)
        .and_then(|h| h.strip_prefix("bytes="))
    else {
        return RangeOutcome::Full;
    };
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeOutcome::Full;
    };
    if total == 0 {
        return RangeOutcome::Unsatisfiable;
    }
    if start_s.is_empty() {
        // Suffix range: the last N bytes.
        let Ok(n) = end_s.parse::<u64>() else {
            return RangeOutcome::Full;
        };
        if n == 0 {
            return RangeOutcome::Full;
        }
        let len = n.min(total);
        return RangeOutcome::Ranged(ByteRange {
            start: total - len,
            end_inclusive: total - 1,
        });
    }
    let Ok(start) = start_s.parse::<u64>() else {
        return RangeOutcome::Full;
    };
    if start >= total {
        return RangeOutcome::Unsatisfiable;
    }
    let end_inclusive = match end_s {
        "" => total - 1,
        s => match s.parse::<u64>() {
            Ok(e) => e.min(total - 1),
            Err(_) => return RangeOutcome::Full,
        },
    };
    if end_inclusive < start {
        return RangeOutcome::Full;
    }
    RangeOutcome::Ranged(ByteRange {
        start,
        end_inclusive,
    })
}

/// Sanitizes a user-supplied filename for `Content-Disposition`.
///
/// `name` arrives from `CompleteRequest` (only non-empty validated), so it
/// may carry quotes, backslashes, path segments, or control characters —
/// each a header-injection or traversal vector. Keeps the basename,
/// replaces `"`/`\` with `_`, drops control characters, truncates to 100
/// chars, and falls back to `"file"` when nothing safe remains.
fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '"' | '\\' => '_',
            c => c,
        })
        .collect();
    let truncated: String = cleaned.trim().chars().take(100).collect();
    let truncated = truncated.trim();
    if truncated.is_empty() {
        "file".to_string()
    } else {
        truncated.to_string()
    }
}

#[utoipa::path(delete, path = "/fs/files/{id}", tag = "fs", params(("id" = String, Path)), responses((status=204, description="deleted")))]
#[delete("/files/{id}")]
async fn delete_file(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let id = path.into_inner();
    engine.delete_file(&id, &claims.sub).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::{App, http, test};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use crate::fs::object_store::ObjectStoreClient;
    use crate::fs::store::FsStore;
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::policy::{Action, PolicyEngine};

    const KID: &str = "fs-route-test-kid";
    const AUD: &str = "test-aud";

    struct Fixture {
        server: wiremock::MockServer,
        enc: EncodingKey,
        engine: FsEngine,
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
    async fn fixture(grant_alice: bool) -> anyhow::Result<Fixture> {
        use crate::db::build_test_store;
        let (key, enc) = rsa_key(KID)?;
        let jwks = json!({"keys": [key]});
        let server = spawn_jwks(jwks).await;
        let policy_prefix = format!(
            "fs-route-policy-{}-{}",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
        );
        let policy_store = build_test_store(&policy_prefix).await;
        let policy = PolicyEngine::init_s3(policy_store).await?;
        if grant_alice {
            policy
                .assign_group("alice".into(), "writers".into())
                .await?;
            policy
                .add_rule("writers".into(), "fs".into(), Action::Write)
                .await?;
            policy
                .add_rule("writers".into(), "fs".into(), Action::Read)
                .await?;
            policy
                .add_rule("writers".into(), "fs".into(), Action::Delete)
                .await?;
        }
        let fs_prefix = format!(
            "fs-route-store-{}-{}",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
        );
        let store = FsStore::new(build_test_store(&fs_prefix).await);
        let s3 = ObjectStoreClient::in_memory();
        let engine = FsEngine::from_parts(store, s3, "test-bucket".into(), policy);
        Ok(Fixture {
            server,
            enc,
            engine,
        })
    }

    #[actix_web::test]
    async fn sanitize_filename_blocks_injection() {
        assert_eq!(sanitize_filename("hello.txt"), "hello.txt");
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("a\\b\"c"), "b_c");
        assert_eq!(sanitize_filename("a\r\nb"), "ab");
        assert_eq!(sanitize_filename("\"\""), "__");
        assert_eq!(sanitize_filename("   "), "file");
        assert_eq!(sanitize_filename(""), "file");
        assert_eq!(sanitize_filename(&"x".repeat(200)).len(), 100);
    }

    fn ranged(header: Option<&str>, total: u64) -> (u64, u64, bool, bool) {
        match parse_range(header, total) {
            RangeOutcome::Full => (0, 0, false, false),
            RangeOutcome::Ranged(r) => (r.start, r.end_inclusive, true, false),
            RangeOutcome::Unsatisfiable => (0, 0, false, true),
        }
    }

    #[actix_web::test]
    async fn parse_range_covers_http_semantics() {
        // No header or foreign/multi/malformed units fall back to full.
        assert_eq!(ranged(None, 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("items=0-99"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bytes=0-99,200-299"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bananas"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bytes=abc-def"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bytes=5-3"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bytes=-0"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bytes=-"), 1000), (0, 0, false, false));
        // Bounded, open, and clamped ends.
        assert_eq!(ranged(Some("bytes=0-99"), 1000), (0, 99, true, false));
        assert_eq!(ranged(Some("bytes=900-"), 1000), (900, 999, true, false));
        assert_eq!(ranged(Some("bytes=0-9999"), 1000), (0, 999, true, false));
        // Suffix: last N bytes, capped at the total.
        assert_eq!(ranged(Some("bytes=-100"), 1000), (900, 999, true, false));
        assert_eq!(ranged(Some("bytes=-5000"), 1000), (0, 999, true, false));
        // Past-the-end starts are unsatisfiable, including on empty files.
        assert_eq!(ranged(Some("bytes=1000-"), 1000), (0, 0, false, true));
        assert_eq!(ranged(Some("bytes=2000-3000"), 1000), (0, 0, false, true));
        assert_eq!(ranged(Some("bytes=0-0"), 0), (0, 0, false, true));
    }

    #[actix_web::test]
    async fn unauthenticated_is_401() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = FsApiModule::new(fx.engine.clone(), mw);
        let app = test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fs/uploads")
                .set_json(json!({"file_size": 1024, "part_size": 1024, "file_total_parts": 1}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[actix_web::test]
    async fn temp_upload_allowed_without_policy() -> anyhow::Result<()> {
        let fx = fixture(false).await?; // no fs policy needed for temp uploads
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = FsApiModule::new(fx.engine.clone(), mw);
        let app = test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fs/uploads")
                .insert_header(("Cookie", format!("auth_token={}", fx.token("alice")?)))
                .set_json(json!({"file_size": 1024, "part_size": 1024, "file_total_parts": 1}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);
        Ok(())
    }

    #[actix_web::test]
    async fn init_upload_validation_rejects_bad_body() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = FsApiModule::new(fx.engine.clone(), mw);
        let app = test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fs/uploads")
                .insert_header(("Cookie", format!("auth_token={}", fx.token("alice")?)))
                .set_json(json!({"file_size": 0, "part_size": 1024, "file_total_parts": 1}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[actix_web::test]
    async fn full_single_part_flow_via_http() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = FsApiModule::new(fx.engine.clone(), mw);
        let app = test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        // init
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fs/uploads")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"file_size": 1024, "part_size": 1024, "file_total_parts": 1}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);
        let body: serde_json::Value = test::read_body_json(res).await;
        let file_id = body["file_id"].as_str().unwrap().to_string();
        // upload part with x-checksum-sha256 header
        let res = test::call_service(
            &app,
            test::TestRequest::put()
                .uri(&format!("/fs/uploads/{file_id}/parts/0"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .insert_header(("x-checksum-sha256", "abc123="))
                .set_payload(vec![1u8; 1024])
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        // progress
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/fs/uploads/{file_id}"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let prog: serde_json::Value = test::read_body_json(res).await;
        assert_eq!(prog["uploaded_parts"], json!([0]));
        // complete
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!("/fs/uploads/{file_id}/complete"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"name":"hello.txt","mimetype":"text/plain"}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        // get metadata
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/fs/files/{file_id}/meta"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let meta: serde_json::Value = test::read_body_json(res).await;
        assert_eq!(meta["name"], "hello.txt");
        // get file body + headers
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/fs/files/{file_id}"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(res.headers().get("content-type").unwrap(), "text/plain");
        assert!(
            res.headers()
                .get("content-disposition")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("hello.txt")
        );
        let body = test::read_body(res).await;
        assert_eq!(body.len(), 1024);
        // delete file
        let res = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri(&format!("/fs/files/{file_id}"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        // multi-part cancel path also
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fs/uploads")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"file_size": 524288, "part_size": 262144, "file_total_parts": 2}))
                .to_request(),
        )
        .await;
        let body: serde_json::Value = test::read_body_json(res).await;
        let file_id2 = body["file_id"].as_str().unwrap().to_string();
        let res = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri(&format!("/fs/uploads/{file_id2}"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        Ok(())
    }

    #[actix_web::test]
    async fn checksum_alias_header_forwarded() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = FsApiModule::new(fx.engine.clone(), mw);
        let app = test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fs/uploads")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"file_size": 1024, "part_size": 1024, "file_total_parts": 1}))
                .to_request(),
        )
        .await;
        let body: serde_json::Value = test::read_body_json(res).await;
        let file_id = body["file_id"].as_str().unwrap();
        // use legacy alias checksum-sha256
        let res = test::call_service(
            &app,
            test::TestRequest::put()
                .uri(&format!("/fs/uploads/{file_id}/parts/0"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .insert_header(("checksum-sha256", "alias123="))
                .set_payload(vec![2u8; 1024])
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        Ok(())
    }

    #[actix_web::test]
    async fn complete_validates_body_and_requires_all_parts() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = FsApiModule::new(fx.engine.clone(), mw);
        let app = test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fs/uploads")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"file_size": 524288, "part_size": 262144, "file_total_parts": 2}))
                .to_request(),
        )
        .await;
        let body: serde_json::Value = test::read_body_json(res).await;
        let file_id = body["file_id"].as_str().unwrap();
        // empty name -> 400
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!("/fs/uploads/{file_id}/complete"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"name":"","mimetype":"text/plain"}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        // not all parts uploaded -> 400
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!("/fs/uploads/{file_id}/complete"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"name":"f","mimetype":"text/plain"}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[actix_web::test]
    async fn multipart_http_flow_with_two_parts() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = FsApiModule::new(fx.engine.clone(), mw);
        let app = test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fs/uploads")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"file_size": 524288, "part_size": 262144, "file_total_parts": 2}))
                .to_request(),
        )
        .await;
        let body: serde_json::Value = test::read_body_json(res).await;
        let file_id = body["file_id"].as_str().unwrap();
        for idx in 0..2 {
            let res = test::call_service(
                &app,
                test::TestRequest::put()
                    .uri(&format!("/fs/uploads/{file_id}/parts/{idx}"))
                    .insert_header(("Cookie", format!("auth_token={token}")))
                    .set_payload(vec![9u8; 262144])
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        }
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!("/fs/uploads/{file_id}/complete"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"name":"big.bin","mimetype":"application/octet-stream"}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/fs/files/{file_id}"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(test::read_body(res).await.len(), 524288);
        Ok(())
    }

    #[actix_web::test]
    async fn ranged_download_serves_206_and_416() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = FsApiModule::new(fx.engine.clone(), mw);
        let app = test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let body: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();

        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/fs/uploads")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"file_size": 8192, "part_size": 8192, "file_total_parts": 1}))
                .to_request(),
        )
        .await;
        let init: serde_json::Value = test::read_body_json(res).await;
        let file_id = init["file_id"].as_str().unwrap();
        let res = test::call_service(
            &app,
            test::TestRequest::put()
                .uri(&format!("/fs/uploads/{file_id}/parts/0"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_payload(body.clone())
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!("/fs/uploads/{file_id}/complete"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"name":"r.bin","mimetype":"application/octet-stream"}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let get = |range: Option<&str>| {
            let mut req = test::TestRequest::get()
                .uri(&format!("/fs/files/{file_id}"))
                .insert_header(("Cookie", format!("auth_token={token}")));
            if let Some(r) = range {
                req = req.insert_header(("Range", r));
            }
            test::call_service(&app, req.to_request())
        };
        let header = |res: &actix_web::dev::ServiceResponse, name: &str| {
            res.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string()
        };

        // Full download advertises ranges.
        let res = get(None).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(header(&res, "accept-ranges"), "bytes");
        assert_eq!(header(&res, "content-length"), "8192");
        assert_eq!(test::read_body(res).await.to_vec(), body);

        // Bounded, open, and suffix ranges.
        for (range, content_range, expected) in [
            ("bytes=0-99", "bytes 0-99/8192", body[0..100].to_vec()),
            ("bytes=8000-", "bytes 8000-8191/8192", body[8000..].to_vec()),
            ("bytes=-100", "bytes 8092-8191/8192", body[8092..].to_vec()),
        ] {
            let res = get(Some(range)).await;
            assert_eq!(res.status(), http::StatusCode::PARTIAL_CONTENT, "{range}");
            assert_eq!(header(&res, "content-range"), content_range);
            assert_eq!(header(&res, "accept-ranges"), "bytes");
            assert_eq!(test::read_body(res).await.to_vec(), expected);
        }

        // Past-the-end range: 416 with the total for retries.
        let res = get(Some("bytes=9000-9999")).await;
        assert_eq!(res.status(), http::StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(header(&res, "content-range"), "bytes */8192");

        // Malformed range: ignored per RFC, full body.
        let res = get(Some("bananas")).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(test::read_body(res).await.to_vec(), body);
        Ok(())
    }
}
