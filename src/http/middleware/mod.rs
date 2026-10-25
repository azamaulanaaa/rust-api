//! The request middleware that the server and every
//! [`ApiModule`] share.
//!
//! [`bearer_token`](crate::http::middleware::bearer_token) runs globally.
//! It only extracts the `Authorization` header.
//! [`jwt`](crate::http::middleware::jwt) does the validation. The code
//! applies it per module scope. Its claims type is specific to one
//! module. [`jwks`](crate::http::middleware::jwks) backs the validation with
//! a key store. The key store refreshes after a key rotation.
//! [`request_tracing`](crate::http::middleware::request_tracing) puts every
//! request inside a server span.

/// The middleware that extracts a bearer token for request authentication.
pub mod bearer_token;
/// The signing key store that uses JWKS. It refreshes after a key rotation.
pub mod jwks;

/// The middleware that validates JWT claims against a JWKS key store.
pub mod jwt;
/// The tracing span that the code creates for each request. The spans work
/// with OpenTelemetry.
pub mod request_tracing;
