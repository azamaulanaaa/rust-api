//! Actix routes for the S3 backed FS module.

use std::sync::Arc;

use actix_web::{HttpResponse, delete, get, post, put, web};
use futures_util::TryStreamExt as _;

use crate::fs::FsEngine;
use crate::fs::error::FsError;
use crate::fs::model::{CompleteRequest, InitRequest, InitResponse};
use crate::http::middleware::jwt::{Claims, JwtClaimsMiddleware, Validated};
use crate::http::{ApiModule, ValidatedJson, logged_body};

/// The API module that exposes the `/fs` routes. The module requires JWT validation.
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
    fn prefix(&self) -> &str {
        "/fs"
    }

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
    body: ValidatedJson<InitRequest>,
) -> Result<HttpResponse, FsError> {
    let file_id = engine.init_upload(body.into_inner(), &claims.sub).await?;
    Ok(HttpResponse::Created().json(serde_json::json!({ "file_id": file_id })))
}

#[utoipa::path(put, path = "/fs/uploads/{id}/parts/{idx}", tag = "fs", params(("id" = String, Path), ("idx" = u64, Path)), request_body(content = Vec<u8>, content_type = "application/octet-stream"), responses((status=204, description="part stored"), (status=401, body=crate::http::error::ErrorBody)))]
#[put("/uploads/{id}/parts/{idx}")]
async fn upload_part(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    path: web::Path<(String, u64)>,
    payload: web::Payload,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, FsError> {
    let (id, idx) = path.into_inner();
    // The code passes the checksum through. S3 validates the checksum. The
    // code only forwards the base64 SHA256 value if the request has one.
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
    // The declared length lets the engine reject a mismatch before the engine
    // reads one byte of the body. A value that is not a number falls back to
    // counting the chunks.
    let declared_len = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let stream = payload.map_err(|_| FsError::BadRequest("request body interrupted".into()));
    engine
        .upload_part(&id, idx, stream, declared_len, checksum_sha256, &claims.sub)
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
) -> Result<HttpResponse, FsError> {
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
) -> Result<HttpResponse, FsError> {
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
) -> Result<HttpResponse, FsError> {
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
) -> Result<HttpResponse, FsError> {
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
) -> Result<HttpResponse, FsError> {
    use actix_web::http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, RANGE};

    let id = path.into_inner();
    // The code reads the metadata first. One cheap cached read gives the
    // authorization result and the total that the range check uses. Therefore
    // exactly one S3 call follows.
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
                .streaming(logged_body(obj.stream)))
        }
        RangeOutcome::Ranged(r) => {
            let (rec, obj) = engine
                .get_object_range(&id, &claims.sub, r.start..r.end_inclusive + 1)
                .await?;
            // The headers describe what the code streams. They do not only
            // describe what the client asked for. The values are the same in
            // every case without an adversary.
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
                .streaming(logged_body(obj.stream)))
        }
        RangeOutcome::Unsatisfiable => Ok(HttpResponse::build(
            actix_web::http::StatusCode::RANGE_NOT_SATISFIABLE,
        )
        .insert_header((CONTENT_RANGE, format!("bytes */{}", meta.size)))
        .finish()),
    }
}

/// A byte range that the server can send. The end value is inclusive.
struct ByteRange {
    start: u64,
    end_inclusive: u64,
}

/// The result of comparing a `Range` header with a known total size.
enum RangeOutcome {
    /// The header is missing or not usable. The server sends the whole object
    /// with status 200.
    Full,
    /// The server sends `start..=end_inclusive` with status 206.
    Ranged(ByteRange),
    /// The syntax is valid but the range is past the end of the object. The
    /// server returns status 416.
    Unsatisfiable,
}

/// Compares a `Range` header with the total size `total`.
///
/// The function accepts one `bytes=` range only. Every other input falls
/// back to a full 200 response, as RFC 9110 §14.2 requires. The other
/// inputs are a missing header, a foreign unit, a multi range value, bad
/// syntax, and bounds in reverse order. An empty object satisfies no
/// range, so any range on it returns 416.
fn parse_range(header: Option<&str>, total: u64) -> RangeOutcome {
    let Some(spec) = header.map(str::trim).and_then(|h| h.strip_prefix("bytes=")) else {
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

/// Sanitizes a filename from the user for the `Content-Disposition` header.
///
/// `name` arrives from `CompleteRequest`. That request only checks that the
/// value is not empty. Therefore `name` may carry quotes, backslashes, path
/// segments, or control characters. Each of these is a header injection
/// vector or a traversal vector. The function keeps the base name. It
/// replaces `"` and `\` with `_`. It removes the control characters. It cuts
/// the name to 100 characters. It returns `"file"` when no safe name remains.
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
) -> Result<HttpResponse, FsError> {
    let id = path.into_inner();
    engine.delete_file(&id, &claims.sub).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::{App, http, test};
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
        let policy_prefix = crate::db::test_prefix("fs-route-policy");
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
        let fs_prefix = crate::db::test_prefix("fs-route-store");
        let store = FsStore::new(build_test_store(&fs_prefix).await);
        let s3 = ObjectStoreClient::in_memory();
        let engine = FsEngine::from_parts(store, s3, "test-bucket".into(), policy.authorizer());
        Ok(Fixture {
            server,
            enc,
            engine,
        })
    }

    /// Every route that the OpenAPI document lists for `/fs` is mounted.
    ///
    /// The `configure` function of this module is one of five builder chains
    /// that are almost the same. Each chain lists its own services. A service
    /// that one chain leaves out is invisible. The code compiles. The
    /// specification still lists the path. The only symptom is a `404` on a
    /// documented endpoint. This is the same failure as the `/auth`
    /// shadowing bug. This module had the widest exposure to that bug. Seven
    /// of its eight routes had no route level test. Therefore a forgotten
    /// `.service(...)` call would have reached production unnoticed.
    ///
    /// The status code cannot tell the two cases apart. The test asks these
    /// handlers for resources that do not exist. A mounted handler answers
    /// `404` with the uniform envelope. The default service of actix answers
    /// `404` with a bare text body. Therefore the assertion checks the body.
    /// A routed request is always answered by the error rendering of this
    /// crate.
    #[actix_web::test]
    async fn every_documented_route_is_mounted() {
        let fx = fixture(true).await.expect("fixture");
        let module = FsApiModule::new(
            fx.engine.clone(),
            JwtClaimsMiddleware::<Claims>::new_with_jks(
                &format!("{}/jwks", fx.issuer()),
                AUD,
                &fx.issuer(),
            )
            .await
            .expect("middleware"),
        );
        // The real composition includes `apply_limits`. The macro `wired_app!`
        // applies it before the modules. It installs the uniform envelope for
        // a body with bad JSON. Without it, actix answers with a bare text
        // 400. Two of these routes return that status when the request has
        // no body.
        let app = test::init_service(
            crate::http::apply_limits(App::new()).configure(|cfg| module.configure(cfg)),
        )
        .await;
        let token = fx.token("alice").expect("token");

        let mut unrouted: Vec<String> = Vec::new();
        for (method, uri) in [
            (http::Method::POST, "/fs/uploads"),
            (http::Method::PUT, "/fs/uploads/up_1/parts/1"),
            (http::Method::POST, "/fs/uploads/up_1/complete"),
            (http::Method::DELETE, "/fs/uploads/up_1"),
            (http::Method::GET, "/fs/uploads/up_1"),
            (http::Method::GET, "/fs/files/f_1/meta"),
            (http::Method::GET, "/fs/files/f_1"),
            (http::Method::DELETE, "/fs/files/f_1"),
        ] {
            let res = test::call_service(
                &app,
                test::TestRequest::default()
                    .method(method.clone())
                    .uri(uri)
                    .insert_header(("Cookie", format!("auth_token={token}")))
                    .to_request(),
            )
            .await;
            let status = res.status();
            let body = test::read_body(res).await;
            if serde_json::from_slice::<crate::http::error::ErrorBody>(&body).is_err() {
                unrouted.push(format!("{method} {uri} -> {status} (no error envelope)"));
            }
        }
        assert!(
            unrouted.is_empty(),
            "documented in the OpenAPI document but not served by the module: {unrouted:?}"
        );
    }

    #[actix_web::test]
    async fn sanitize_filename_removes_injection_characters() {
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
        // A missing header, a foreign unit, a multi range value, and bad
        // syntax each select the full object.
        assert_eq!(ranged(None, 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("items=0-99"), 1000), (0, 0, false, false));
        assert_eq!(
            ranged(Some("bytes=0-99,200-299"), 1000),
            (0, 0, false, false)
        );
        assert_eq!(ranged(Some("bananas"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bytes=abc-def"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bytes=5-3"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bytes=-0"), 1000), (0, 0, false, false));
        assert_eq!(ranged(Some("bytes=-"), 1000), (0, 0, false, false));
        // Bounded, open, and clamped ends.
        assert_eq!(ranged(Some("bytes=0-99"), 1000), (0, 99, true, false));
        assert_eq!(ranged(Some("bytes=900-"), 1000), (900, 999, true, false));
        assert_eq!(ranged(Some("bytes=0-9999"), 1000), (0, 999, true, false));
        // A suffix range gives the last N bytes. The total size caps the result.
        assert_eq!(ranged(Some("bytes=-100"), 1000), (900, 999, true, false));
        assert_eq!(ranged(Some("bytes=-5000"), 1000), (0, 999, true, false));
        // A start past the end of the object is not satisfiable. This applies
        // to an empty file too.
        assert_eq!(ranged(Some("bytes=1000-"), 1000), (0, 0, false, true));
        assert_eq!(ranged(Some("bytes=2000-3000"), 1000), (0, 0, false, true));
        assert_eq!(ranged(Some("bytes=0-0"), 0), (0, 0, false, true));
    }

    #[actix_web::test]
    async fn request_without_a_token_returns_401() -> anyhow::Result<()> {
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
        let fx = fixture(false).await?; // A temp upload needs no fs policy.
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
        // The test starts the upload.
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
        // The test uploads the part with the x-checksum-sha256 header.
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
        // The test reads the progress.
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
        // The test completes the upload.
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
        // The test reads the metadata.
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
        // The test reads the file body and the headers.
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
        // The test deletes the file.
        let res = test::call_service(
            &app,
            test::TestRequest::delete()
                .uri(&format!("/fs/files/{file_id}"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        // The test also checks the cancel path for a multipart upload.
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
        // The test uses the legacy alias checksum-sha256.
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
        // An empty name returns 400.
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
        // A request that does not list every part returns 400.
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
            res.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };

        // A full download advertises the range support.
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

        // A range past the end of the object returns 416. The response gives
        // the total size so that the client can retry.
        let res = get(Some("bytes=9000-9999")).await;
        assert_eq!(res.status(), http::StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(header(&res, "content-range"), "bytes */8192");

        // A range with bad syntax is ignored, as the RFC requires. The response
        // contains the full body.
        let res = get(Some("bananas")).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(test::read_body(res).await.to_vec(), body);
        Ok(())
    }

    #[actix_web::test]
    async fn oversize_part_is_rejected_with_413() -> anyhow::Result<()> {
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
        let init: serde_json::Value = test::read_body_json(res).await;
        let file_id = init["file_id"].as_str().unwrap();
        // The payload is twice the declared part size. The declared Content-Length
        // already exceeds the limit. Therefore the request fails before the
        // server streams the body.
        let res = test::call_service(
            &app,
            test::TestRequest::put()
                .uri(&format!("/fs/uploads/{file_id}/parts/0"))
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_payload(vec![0u8; 2048])
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
        let err: serde_json::Value = test::read_body_json(res).await;
        assert_eq!(err["error"], "payload too large");
        Ok(())
    }
}
