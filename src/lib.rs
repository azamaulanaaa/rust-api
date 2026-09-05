//! A starter-kit REST API server providing pluggable modules for
//! OIDC authentication, JWT session validation, and Casbin-based
//! authorization, built on Actix Web.
//!
//! The crate is intentionally business-logic free: applications compose
//! [`http::ApiModule`] implementations onto an [`http::ApiService`]
//! to build their own API surface on top of the shared auth/policy plumbing.

// Public items must carry rustdoc comments; the lint is enforced
// package-wide via [lints.rust] in Cargo.toml.

/// HTTP server scaffolding: modular service registry plus request
/// middleware (bearer-token extraction, JWKS-backed JWT validation).
pub mod http;

/// OpenID Connect client and login/callback routes implementing the
/// authorization-code flow with PKCE, CSRF state, and nonce validation.
pub mod oidc;

/// Casbin RBAC policy engine backed by Postgres, with management routes
/// for permission rules and group membership.
pub mod policy;

/// Object-store file storage via `object_store` (AmazonS3 for S3/MinIO/R2,
/// InMemory for tests) with chunked upload, mirroring the IndexedDB
/// worker FS API (`src/worker/fs/index.ts`) over REST.
pub mod fs;

/// OpenAPI specification composed from all `utoipa::path` modules.
pub mod docs;

/// Telemetry bootstrap: global [`tracing`] subscriber installation and
/// OpenTelemetry wiring.
pub mod telemetry;
