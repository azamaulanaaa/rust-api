# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- OIDC authentication with PKCE, CSRF state, and nonce validation.
- JWT validation via JWKS with a refreshable multi-algorithm key store.
- Casbin RBAC on OxKV stores backed by S3.
- Validated policy rule writes before any transaction opens.
- Single-live-handle-per-prefix fencing for OxKv stores.
- Modular row-level authorization through `RowAuthorizer`.
- Temp per-user file scope with refcount relations.
- Durable multipart upload state that rehydrates after restart.
- Capability tokens as short-lived HMAC JWTs.
- Garbage collection for orphans in two separate scopes.
- Per-user filtered replicas with WAL.
- Single-writer lease enforcement on the database prefix.
- WAL-instrumented mutations for `FsEngine` and `PolicyEngine`.
- Transactional replica builds with crash safety.
- Modular `ApiModule` composition on `ApiService`.
- Structured logging and optional OpenTelemetry export.
- OpenAPI 3.1 document and Swagger UI.
- Health and readiness probes.
- Policy export and import commands.
- CLI with `serve`, `policy export`, and `policy import`.
- Conventional Commits style for commit messages.
