//! Middleware that adds the server time to every response.
//!
//! The middleware writes `X-Server-Time-Ms`. The value is an integer UTC
//! timestamp in milliseconds. The standard `Date` header stays in place as
//! the fallback for clients that do not read the new header.

use std::{
    future::{Ready, ready},
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

use actix_web::{
    Error,
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{HeaderName, HeaderValue},
};
use futures_util::future::LocalBoxFuture;

/// The response header that carries the server time in UTC milliseconds.
pub const SERVER_TIME_HEADER: &str = "x-server-time-ms";

/// Returns the current UTC time in milliseconds since the Unix epoch.
///
/// A clock before the Unix epoch returns `0`. The header value must always
/// be a valid non-negative integer.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The middleware factory that adds [`SERVER_TIME_HEADER`] to each response.
///
/// Register the middleware as the outermost layer. It then also covers
/// responses from the rate limiter and other middleware.
#[derive(Debug, Default, Clone, Copy)]
pub struct ServerTimeMiddleware;

impl<S, B> Transform<S, ServiceRequest> for ServerTimeMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = ServerTimeMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ServerTimeMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

/// The middleware service for one worker.
pub struct ServerTimeMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for ServerTimeMiddlewareService<S>
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
            match HeaderValue::from_str(&now_ms().to_string()) {
                Ok(value) => {
                    res.headers_mut()
                        .insert(HeaderName::from_static(SERVER_TIME_HEADER), value);
                }
                Err(error) => {
                    // The value is a decimal integer, so this branch is not
                    // reachable. The server logs the error instead of a panic
                    // if the header rules change.
                    tracing::warn!("server time header value is invalid: {error}");
                }
            }
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
    async fn normal_response_carries_the_header() {
        let app = test::init_service(
            actix_web::App::new()
                .wrap(ServerTimeMiddleware)
                .route("/ok", web::get().to(ok)),
        )
        .await;
        let res = test::call_service(&app, test::TestRequest::get().uri("/ok").to_request()).await;

        assert_eq!(res.status(), StatusCode::OK);
        let value = res
            .headers()
            .get(SERVER_TIME_HEADER)
            .expect("server time header");
        let millis = value.to_str().expect("ascii header").parse::<u64>();
        assert!(millis.expect("integer milliseconds") > 0);
    }

    #[actix_web::test]
    async fn error_response_carries_the_header() {
        let app = test::init_service(actix_web::App::new().wrap(ServerTimeMiddleware).route(
            "/fail",
            web::get().to(|| async {
                Err::<HttpResponse, _>(actix_web::error::ErrorUnauthorized(
                    "authentication required",
                ))
            }),
        ))
        .await;
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/fail").to_request()).await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().contains_key(SERVER_TIME_HEADER));
    }

    #[actix_web::test]
    async fn unmatched_route_carries_the_header() {
        let app = test::init_service(
            actix_web::App::new()
                .wrap(ServerTimeMiddleware)
                .route("/ok", web::get().to(ok)),
        )
        .await;
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/missing").to_request()).await;

        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.headers().contains_key(SERVER_TIME_HEADER));
    }
}
