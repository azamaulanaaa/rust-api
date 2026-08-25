//! A starter-kit REST API server providing pluggable modules for
//! OIDC authentication, JWT session validation, and Casbin-based
//! authorization, built on Actix Web.
//!
//! The crate is intentionally business-logic free: applications compose
//! [`endpoint::ApiModule`] implementations onto an [`endpoint::ApiService`]
//! to build their own API surface on top of the shared auth/policy plumbing.

// Require rustdoc comments on every public item of the library API.
#![deny(missing_docs)]

/// HTTP server scaffolding: modular service registry plus request
/// middleware (bearer-token extraction, JWKS-backed JWT validation).
pub mod endpoint;

/// OpenID Connect client and login/callback routes implementing the
/// authorization-code flow with PKCE, CSRF state, and nonce validation.
pub mod oidc;

/// Casbin RBAC policy engine backed by Postgres, with management routes
/// for permission rules and group membership.
pub mod policy;
