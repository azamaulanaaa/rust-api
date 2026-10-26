//! Middleware that generates or echoes an `X-Request-Id` for each request.
//!
//! The middleware reads an inbound `X-Request-Id` header. The middleware
//! echoes the value on the response. The middleware generates a UUIDv7 when
//! the header is absent. The middleware stores the value in the request
//! extensions. The middleware also records the value on the current
//! tracing span.

use std::{
    future::{Ready, ready},
    rc::Rc,
};

use actix_web::{
    Error, HttpMessage,
    body::BoxBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{HeaderName, HeaderValue},
};
use futures_util::future::LocalBoxFuture;
use uuid::Uuid;

/// The request identifier that [`RequestIdMiddleware`] stores in the request
/// extensions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(pub String);

impl RequestId {
    /// Wraps an arbitrary identifier string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Generates a fresh UUIDv7 identifier.
    pub fn generate() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::ops::Deref for RequestId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for RequestId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Alias for [`RequestId`].
pub type RequestID = RequestId;
/// Alias for [`RequestIdMiddleware`].
pub type RequestIDMiddleware = RequestIdMiddleware;

/// The middleware factory that propagates `X-Request-Id`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestIdMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RequestIdMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = RequestIdMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestIdMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

/// The middleware service for one worker, which [`RequestIdMiddleware`] creates.
pub struct RequestIdMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestIdMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        // Read the inbound id. A missing or unusable value leads to a
        // generated UUIDv7.
        let provided = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());

        let id = match provided {
            Some(s) if HeaderValue::from_str(&s).is_ok() => s,
            _ => Uuid::now_v7().to_string(),
        };

        let request_id = RequestId(id.clone());

        req.extensions_mut().insert(request_id.clone());
        req.extensions_mut().insert(id.clone());
        if let Ok(uuid) = Uuid::parse_str(&id) {
            req.extensions_mut().insert(uuid);
        }

        let span = tracing::Span::current();
        span.record("request.id", id.as_str());
        span.record("request_id", id.as_str());
        span.record("http.request.id", id.as_str());

        let header_value = match HeaderValue::from_str(&id) {
            Ok(value) => value,
            Err(_) => HeaderValue::from_static("invalid-request-id"),
        };

        Box::pin(async move {
            match svc.call(req).await {
                Ok(res) => {
                    let mut res = res.map_into_boxed_body();
                    res.headers_mut()
                        .insert(HeaderName::from_static("x-request-id"), header_value);
                    Ok(res)
                }
                Err(err) => Err(err),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};

    #[actix_web::test]
    async fn request_id_middleware_echoes_a_provided_id() {
        let app = test::init_service(
            App::new()
                .wrap(RequestIdMiddleware)
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/")
            .insert_header(("X-Request-Id", "provided-id-123"))
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(
            res.headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok()),
            Some("provided-id-123")
        );
    }

    #[actix_web::test]
    async fn request_id_middleware_generates_an_id_when_absent() {
        let app = test::init_service(
            App::new()
                .wrap(RequestIdMiddleware)
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let res = test::call_service(&app, req).await;
        let value = res
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .expect("generated request id present");
        assert!(!value.is_empty());
    }

    #[actix_web::test]
    async fn request_id_middleware_echoes_on_error_responses() {
        let app =
            test::init_service(App::new().wrap(RequestIdMiddleware).route(
                "/",
                web::get().to(|| async {
                    Err::<HttpResponse, _>(actix_web::error::ErrorBadRequest("bad"))
                }),
            ))
            .await;

        let req = test::TestRequest::get()
            .uri("/")
            .insert_header(("X-Request-Id", "error-id-456"))
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), 400);
        assert_eq!(
            res.headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok()),
            Some("error-id-456")
        );
    }
}
