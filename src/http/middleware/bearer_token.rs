use std::{
    future::{Ready, ready},
    rc::Rc,
};

use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header,
};
use futures_util::future::LocalBoxFuture;

/// Actix transform that extracts a Bearer token from the
/// `Authorization: Bearer <token>` header and stores it in request
/// extensions for downstream services to consume.
pub struct BearerTokenMiddleware;

impl<S, B> Transform<S, ServiceRequest> for BearerTokenMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = BearerTokenMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    /// Wraps `service` so every request passing through it gets its Bearer
    /// token extracted into extensions.
    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(BearerTokenMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

/// Newtype around the raw Bearer token string, inserted into request
/// extensions by [`BearerTokenMiddleware`].
#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

/// The instantiated per-worker middleware service produced by
/// [`BearerTokenMiddleware`].
pub struct BearerTokenMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for BearerTokenMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        if let Some(token) = extract_bearer_token(&req) {
            req.extensions_mut().insert(token);
        }

        Box::pin(async move { svc.call(req).await })
    }
}

fn extract_bearer_token(req: &ServiceRequest) -> Option<BearerToken> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()
        .and_then(parse_bearer_token)
}

fn parse_bearer_token(auth_str: &str) -> Option<BearerToken> {
    let mut parts = auth_str.splitn(2, ' ');
    match (parts.next(), parts.next()) {
        (Some(scheme), Some(token)) if scheme.eq_ignore_ascii_case("Bearer") => {
            if token.trim().is_empty() {
                None
            } else {
                Some(BearerToken(token.to_string()))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bearer_token_accepts_valid() {
        assert_eq!(parse_bearer_token("Bearer abc123").unwrap().0, "abc123");
        assert_eq!(parse_bearer_token("bearer XYZ").unwrap().0, "XYZ");
        assert_eq!(
            parse_bearer_token("BEARER token-with-dash_123").unwrap().0,
            "token-with-dash_123"
        );
    }

    #[test]
    fn parse_bearer_token_rejects_invalid() {
        assert!(parse_bearer_token("Basic abc123").is_none());
        assert!(parse_bearer_token("Bearer").is_none());
        assert!(parse_bearer_token("Bearer ").is_none());
        assert!(parse_bearer_token("Bearer   ").is_none());
        assert!(parse_bearer_token("").is_none());
        assert!(parse_bearer_token("   ").is_none());
    }

    #[test]
    fn parse_bearer_token_preserves_raw_token() {
        // Token is stored verbatim (no trim) — downstream validation decides.
        assert_eq!(parse_bearer_token("Bearer  abc").unwrap().0, " abc");
    }
}
