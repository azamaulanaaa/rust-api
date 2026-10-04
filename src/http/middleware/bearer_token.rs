//! Actix middleware that extracts the `Authorization: Bearer <token>`
//! header.
//!
//! The middleware runs globally, and it is deliberately permissive. It
//! parses the header and puts the raw string into the request extensions.
//! It leaves every accept or reject decision to the downstream
//! [`JwtClaimsMiddleware`](crate::http::middleware::jwt::JwtClaimsMiddleware).
//! A request that sends no header passes through unchanged.

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

/// The Actix transform that extracts a bearer token from the
/// `Authorization: Bearer <token>` header. The transform puts the token
/// into the request extensions, so a downstream service can use it.
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

    /// Wraps `service` so that every request that passes through it has its
    /// bearer token extracted into the extensions.
    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(BearerTokenMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

/// A newtype around the raw bearer token string.
/// [`BearerTokenMiddleware`] puts this value into the request
/// extensions.
#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

/// The middleware service for one worker, which
/// [`BearerTokenMiddleware`] creates.
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

/// Reads the bearer token from the `Authorization` header, if the header
/// contains one.
///
/// The function returns `None` for a missing header, for a value that is not
/// UTF-8, and for a scheme other than `Bearer`. [`parse_bearer_token`]
/// rejects the same cases.
fn extract_bearer_token(req: &ServiceRequest) -> Option<BearerToken> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()
        .and_then(parse_bearer_token)
}

/// Splits `auth_str` into its scheme and its token. The function accepts
/// any casing of `Bearer`, as RFC 7235 requires.
///
/// The function returns the token exactly as it received it, and does not
/// trim it. Therefore a value such as `"Bearer  abc"` keeps its leading
/// space. Only the validator can decide whether such a value is acceptable,
/// not the extractor.
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
    fn parse_bearer_token_accepts_a_valid_value() {
        assert_eq!(parse_bearer_token("Bearer abc123").unwrap().0, "abc123");
        assert_eq!(parse_bearer_token("bearer XYZ").unwrap().0, "XYZ");
        assert_eq!(
            parse_bearer_token("BEARER token-with-dash_123").unwrap().0,
            "token-with-dash_123"
        );
    }

    #[test]
    fn parse_bearer_token_rejects_an_invalid_value() {
        assert!(parse_bearer_token("Basic abc123").is_none());
        assert!(parse_bearer_token("Bearer").is_none());
        assert!(parse_bearer_token("Bearer ").is_none());
        assert!(parse_bearer_token("Bearer   ").is_none());
        assert!(parse_bearer_token("").is_none());
        assert!(parse_bearer_token("   ").is_none());
    }

    #[test]
    fn parse_bearer_token_keeps_the_raw_token() {
        // The code keeps the token exactly as it received it and does not
        // trim it. The downstream validation decides.
        assert_eq!(parse_bearer_token("Bearer  abc").unwrap().0, " abc");
    }
}
