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
//! [`request_id`](crate::http::middleware::request_id) generates or echoes
//! an `X-Request-Id` for each request.

/// The middleware that extracts a bearer token for request authentication.
pub mod bearer_token;
/// The signing key store that uses JWKS. It refreshes after a key rotation.
pub mod jwks;

/// The middleware that validates JWT claims against a JWKS key store.
pub mod jwt;
/// The middleware that generates or echoes `X-Request-Id`.
pub mod request_id;
/// The tracing span that the code creates for each request. The spans work
/// with OpenTelemetry.
pub mod request_tracing;

pub use request_id::RequestID;
pub use request_id::RequestIDMiddleware;
/// Re-exported request id types for ergonomic access.
pub use request_id::RequestId;
pub use request_id::RequestIdMiddleware;

/// Alias module name for [`request_id`].
pub use request_id as requestid;
/// Alias module name for [`request_id`].
pub use request_id as request_ids;
