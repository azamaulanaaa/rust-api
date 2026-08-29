//! Actix routes for the S3-backed FS module.

use std::sync::Arc;

use actix_web::{HttpResponse, delete, get, post, put, web};
use bytes::Bytes;

use crate::endpoint::ApiModule;
use crate::endpoint::middleware::jwt::{Claims, JwtClaimsMiddleware, Validated};
use crate::fs::FsEngine;
use crate::fs::model::{CompleteRequest, InitRequest, InitResponse};

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

#[utoipa::path(post, path = "/fs/uploads", tag = "fs", request_body = InitRequest, responses((status=201, body=InitResponse), (status=401, body=crate::endpoint::error::ErrorBody)))]
#[post("/uploads")]
async fn init_upload(
    engine: web::Data<FsEngine>,
    claims: Validated<Claims>,
    body: web::Json<InitRequest>,
) -> Result<HttpResponse, crate::fs::error::FsError> {
    let file_id = engine.init_upload(body.into_inner(), &claims.sub).await?;
    Ok(HttpResponse::Created().json(serde_json::json!({ "file_id": file_id })))
}

#[utoipa::path(put, path = "/fs/uploads/{id}/parts/{idx}", tag = "fs", params(("id" = String, Path), ("idx" = u64, Path)), request_body(content = Vec<u8>, content_type = "application/octet-stream"), responses((status=204, description="part stored"), (status=401, body=crate::endpoint::error::ErrorBody)))]
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

#[utoipa::path(post, path = "/fs/uploads/{id}/complete", tag = "fs", params(("id" = String, Path)), request_body = CompleteRequest, responses((status=200, body=InitResponse), (status=401, body=crate::endpoint::error::ErrorBody)))]
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
