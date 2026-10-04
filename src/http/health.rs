//! The liveness probe and the readiness probe.
//!
//! [`health`](crate::http::health::health) always returns 200, so a stuck
//! dependency cannot fail the liveness check.
//! [`ready`](crate::http::health::ready) reflects the injected
//! [`ReadyCheck`](crate::http::health::ReadyCheck).

use std::sync::Arc;

use actix_web::{HttpResponse, Responder, get, web};

/// The synchronous dependency check that backs `/ready`.
///
/// The server runs the check on every probe poll, so an implementation must
/// be cheap and must not block. A lock `try_read` is acceptable. I/O is not
/// acceptable. `true` means ready.
pub type ReadyCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// The readiness probe returns `200` when the injected [`ReadyCheck`]
/// passes. It returns `503` when the dependencies are stuck. It returns `200`
/// when no check is wired, because startup already waits for S3/OIDC/JWKS
/// before it binds the listener.
#[utoipa::path(get, path = "/ready", tag = "health", responses((status = 200, description = "ready"), (status = 503, description = "not ready")))]
#[get("/ready")]
pub async fn ready(check: Option<web::Data<ReadyCheck>>) -> impl Responder {
    match check {
        Some(c) if !c() => HttpResponse::ServiceUnavailable().finish(),
        _ => HttpResponse::Ok().finish(),
    }
}

/// The liveness probe endpoint returns `200 OK` with an empty body.
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
    async fn ready_returns_200_when_no_check_is_wired() {
        let app = test::init_service(App::new().service(ready)).await;
        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn ready_reflects_the_result_of_the_check() {
        let passing: ReadyCheck = Arc::new(|| true);
        let app =
            test::init_service(App::new().app_data(web::Data::new(passing)).service(ready)).await;
        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(resp.status(), 200);

        let failing: ReadyCheck = Arc::new(|| false);
        let app =
            test::init_service(App::new().app_data(web::Data::new(failing)).service(ready)).await;
        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(resp.status(), 503);
    }
}
