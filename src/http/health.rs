use actix_web::{HttpResponse, Responder, get};

/// Liveness probe endpoint returning `200 OK` with an empty body.
#[utoipa::path(get, path = "/health", tag = "health", responses((status = 200, description = "OK")))]
#[get("/health")]
pub async fn health() -> impl Responder {
    HttpResponse::Ok().finish()
}
