use std::sync::Arc;

use actix_web::{HttpResponse, Responder, get, web};

/// Synchronous dependency check backing `/ready`.
///
/// Runs on every probe poll, so implementations must be cheap and
/// non-blocking (e.g. a lock `try_read`, never I/O). `true` means ready.
pub type ReadyCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// Readiness probe: `200` when the injected [`ReadyCheck`] passes,
/// `503` when dependencies are wedged, `200` when no check is wired
/// (startup already gates on S3/OIDC/JWKS before binding).
#[utoipa::path(get, path = "/ready", tag = "health", responses((status = 200, description = "ready"), (status = 503, description = "not ready")))]
#[get("/ready")]
pub async fn ready(check: Option<web::Data<ReadyCheck>>) -> impl Responder {
    match check {
        Some(c) if !c() => HttpResponse::ServiceUnavailable().finish(),
        _ => HttpResponse::Ok().finish(),
    }
}

/// Liveness probe endpoint returning `200 OK` with an empty body.
#[utoipa::path(get, path = "/health", tag = "health", responses((status = 200, description = "OK")))]
#[get("/health")]
pub async fn health() -> impl Responder {
    HttpResponse::Ok().finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test};

    #[actix_web::test]
    async fn health_returns_200() {
        let app = test::init_service(App::new().service(health)).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn ready_without_check_is_200() {
        let app = test::init_service(App::new().service(ready)).await;
        let resp = test::call_service(&app, test::TestRequest::get().uri("/ready").to_request())
            .await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn ready_reflects_check() {
        let passing: ReadyCheck = Arc::new(|| true);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(passing))
                .service(ready),
        )
        .await;
        let resp = test::call_service(&app, test::TestRequest::get().uri("/ready").to_request())
            .await;
        assert_eq!(resp.status(), 200);

        let failing: ReadyCheck = Arc::new(|| false);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(failing))
                .service(ready),
        )
        .await;
        let resp = test::call_service(&app, test::TestRequest::get().uri("/ready").to_request())
            .await;
        assert_eq!(resp.status(), 503);
    }
}
