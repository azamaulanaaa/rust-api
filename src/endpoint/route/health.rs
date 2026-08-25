use actix_web::{HttpResponse, Responder, get};

/// Liveness probe endpoint returning `200 OK` with an empty body.
#[get("/health")]
pub async fn health() -> impl Responder {
    HttpResponse::Ok().finish()
}
