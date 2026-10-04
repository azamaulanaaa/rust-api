//! The request middleware that the server and every
//! [`ApiModule`] share.
//!
//! [`bearer_token`](crate::http::middleware::bearer_token) runs globally
//! and only extracts the `Authorization` header.
//! [`jwt`](crate::http::middleware::jwt) does the validation, and the code
//! applies it per module scope, because its claims type is specific to one
//! module. [`jwks`](crate::http::middleware::jwks) backs the validation with
//! a key store that refreshes after a key rotation, and
//! [`request_tracing`](crate::http::middleware::request_tracing) puts every
//! request inside a server span.

/// The middleware that extracts a bearer token for request authentication.
pub mod bearer_token;
/// The signing key store that uses JWKS and refreshes after a key rotation.
pub mod jwks;

/// The middleware that validates JWT claims against a JWKS key store.
pub mod jwt;
/// The tracing span that the code creates for each request. The spans work
/// with OpenTelemetry.
pub mod request_tracing;
