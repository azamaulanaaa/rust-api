//! Actix routes for the S3-backed FS module.

use std::sync::Arc;

use actix_web::{HttpResponse, delete, get, post, put, web};
use bytes::Bytes;

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

#[utoipa::path(get, path = "/fs/files/{id}", tag = "fs", params(("id" = String, Path)), responses((status=200, description="binary")))]
#[get("/files/{id}")]
async fn get_file(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let id = path.into_inner();
    let (rec, body) = engine.get_object(&id, &claims.sub).await?;
    Ok(HttpResponse::Ok()
        .content_type(rec.mimetype)
        .insert_header((
            "Content-Disposition",
            format!("inline; filename=\"{}\"", rec.name),
        ))
        .body(body))
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
        let (key, enc) = rsa_key(KID)?;
        let jwks = json!({"keys": [key]});
        let server = spawn_jwks(jwks).await;
        let policy_path = std::env::temp_dir().join(format!(
            "fs-route-policy-{}-{}.redb",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
        ));
        let _ = std::fs::remove_file(&policy_path);
        let policy = PolicyEngine::init(&policy_path).await?;
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
        let fs_path = std::env::temp_dir().join(format!(
            "fs-route-store-{}-{}.redb",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
        ));
        let _ = std::fs::remove_file(&fs_path);
        let store = FsStore::open(&fs_path).await?;
        let s3 = ObjectStoreClient::in_memory();
        let engine = FsEngine::from_parts(store, s3, "test-bucket".into(), policy);
        Ok(Fixture { server, enc, engine })
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
    async fn forbidden_without_policy() -> anyhow::Result<()> {
        let fx = fixture(false).await?; // alice has no grant
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
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);
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
}
