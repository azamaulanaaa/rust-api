//! Middleware that stops a shared cache from storing a response.
//!
//! The middleware sets `Cache-Control: no-store` and `Pragma: no-cache` on
//! every response. A proxy must not store an authentication response. A
//! stored response can give one user the session of another user.

use std::{
    future::{Ready, ready},
    rc::Rc,
};

use actix_web::{
    Error,
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{self, HeaderValue},
};
use futures_util::future::LocalBoxFuture;

/// The middleware factory that adds the no-cache headers.
///
/// Register the middleware on the `/auth` scope only. An unrelated route
/// still uses the normal cache rules.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCache;

impl<S, B> Transform<S, ServiceRequest> for NoCache
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = NoCacheService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(NoCacheService {
            service: Rc::new(service),
        }))
    }
}

/// The middleware service for one worker.
pub struct NoCacheService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for NoCacheService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            let mut res = service.call(req).await?;
            let headers = res.headers_mut();
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{HttpResponse, http::StatusCode, test, web};

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    #[actix_web::test]
    async fn response_carries_the_no_cache_headers() {
        let app = test::init_service(
            actix_web::App::new()
                .wrap(NoCache)
                .route("/auth/thing", web::get().to(ok)),
        )
        .await;
        let res = test::call_service(
            &app,
            test::TestRequest::get().uri("/auth/thing").to_request(),
        )
        .await;

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            res.headers()
                .get("pragma")
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
    }

    /// A response from an error path must also stay out of a shared cache.
    #[actix_web::test]
    async fn error_response_carries_the_no_cache_headers() {
        let app = test::init_service(actix_web::App::new().wrap(NoCache).route(
            "/auth/fail",
            web::get().to(|| async {
                HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}))
            }),
        ))
        .await;
        let res = test::call_service(
            &app,
            test::TestRequest::get().uri("/auth/fail").to_request(),
        )
        .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            res.headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            res.headers()
                .get("pragma")
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
    }
}
