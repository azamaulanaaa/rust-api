//! Request middleware shared by the server and by every
//! [`ApiModule`](crate::http::ApiModule).
//!
//! [`bearer_token`](crate::http::middleware::bearer_token) runs globally
//! and only extracts the `Authorization` header;
//! [`jwt`](crate::http::middleware::jwt) does the actual validation and is
//! applied per module scope, since its claims type is module-specific.
//! [`jwks`](crate::http::middleware::jwks) backs it with a
//! refresh-on-rotation key store, and
//! [`request_tracing`](crate::http::middleware::request_tracing) wraps
//! every request in a server span.

/// Bearer-token request authentication middleware.
pub mod bearer_token;
/// JWKS-backed signing key store with refresh-on-rotation.
pub mod jwks;

/// JWKS-backed JWT claims validation middleware.
pub mod jwt;
/// Per-request OpenTelemetry-compatible tracing spans.
pub mod request_tracing;
