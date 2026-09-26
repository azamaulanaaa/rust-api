//! A starter-kit REST API server providing pluggable modules for
//! OIDC authentication, JWT session validation, and Casbin-based
//! authorization, built on Actix Web.
//!
//! The crate is intentionally business-logic free: applications compose
//! [`http::ApiModule`] implementations onto an [`http::ApiService`]
//! to build their own API surface on top of the shared auth/policy plumbing.

// `unwrap_used`/`expect_used` are denied package-wide via [lints.clippy]
// in Cargo.toml, so the level is declared once and applies to every
// target. This attribute only opens the test escape hatch, which is why
// individual `#[cfg(test)]` modules do not need their own `#[allow]`.
//
// Public items must carry rustdoc comments; that lint is enforced the
// same way, via [lints.rust] in Cargo.toml.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// HTTP server scaffolding: modular service registry plus request
/// middleware (bearer-token extraction, JWKS-backed JWT validation).
pub mod http;

/// OpenID Connect client and login/callback routes implementing the
/// authorization-code flow with PKCE, CSRF state, and nonce validation.
pub mod oidc;

/// Casbin RBAC policy engine backed by prefix-scoped OxKV stores on S3,
/// with management routes for permission rules and group membership.
pub mod policy;

/// Object-store file storage via `object_store` (AmazonS3 for S3/MinIO/R2,
/// InMemory for tests) with multipart upload over REST.
pub mod fs;

/// OpenAPI specification composed from all `utoipa::path` modules.
pub mod docs;

/// Per-user filtered replicas on stable OxKvStore prefixes.
pub mod sync;

/// Shared change-feed vocabulary: [`FileRecord`](records::FileRecord),
/// [`WalOp`](records::WalOp), and the
/// [`ChangeSink`](records::ChangeSink) seam.
///
/// The pivot that lets `fs`/`policy` (which emit changes) and `sync`
/// (which consumes them) depend on this module instead of on each other.
/// Depends on nothing else in the crate.
pub mod records;

/// OxKV store factory (prefix-scoped inside configured S3 bucket) plus the
/// single-writer lease that guards a `[database].prefix` scope.
pub mod db;

/// Single-writer lease: makes a second process on the same
/// `[database].prefix` observable at startup instead of a silent
/// divergence.
pub mod lease;

/// Process-wide latch for a lost primary write session, covering the
/// uncooperative case the lease cannot see.
pub mod fencing;

/// Telemetry bootstrap: global [`tracing`] subscriber installation and
/// OpenTelemetry wiring.
pub mod telemetry;
