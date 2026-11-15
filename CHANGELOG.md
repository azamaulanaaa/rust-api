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
- Transaction-level conditional writes for entity versions, schema publish, rule upsert, replica head and generation, file relation ref-counts, WAL sequence, and policy rule claims.
- Policy export through a read-only follower, so export does not fence the writer.
- Entity-attribute-value (EAV) subsystem with versioned schemas, validated entities, attribute and unique indexes, rule conditions and script actions, timers, a change feed, and per-user chunked replicas.

### Changed

- Migrated to oxkv 0.12.1.
- Family scans read keys only and stop at a bounded page.
- Blind writes use `put_bytes` and skip the old-value read.

### Fixed

- A schema publish rejects a default that does not match its type, including a non-finite float default.
- Revalidation and migration apply schema defaults, then check unique values and references.
- A patch with `null` removes an optional defaulted attribute, and a required defaulted attribute returns an error.
- Create and update reject NaN and infinite float values.
- Unique and attribute-index facts use the attribute name across schemas, including a permanent unique name marker.
- A removed index returns `400` for a query, and an entity on an older indexed version stays queryable.
- A delete enforces `expected_version` at commit, and an effect plan rejects update or delete after delete.
- The replica build keeps the 64 MiB byte cap and the 100,000-entity cap.
- Nested script conditions run at every level of `All`, `Any`, and `Not`.
- A failed rule does not stop later rules, and each failed rule writes a dead letter with `rule_id`.
- A script-action marker commits in the entity store, and marker cleanup removes rule-store and entity-store markers.
- `host.find` requires an indexed key, and a script action filters its context with the read set.
- A timer event carries the causation id and depth, and a timer chain stops at `max_causation_depth`.
- The snapshot accepts a pinned `head`, sets no `ETag`, and bounds a cursor scan to four raw pages.
- `/eav` responses set `no-store`, and CORS exposes the four `X-Replica-*` headers.
- An empty replica returns chunk 0 with `chunks: 0`, and an unknown schema returns `404` on the children route.
- A list page omits `next_offset` when the next offset would pass the cap.
- EAV loop failures are tracked per loop, clear after a successful pass, and shutdown waits for all four loops.
- A queue lease token carries a generation, a batch renews each reserved lease, and completion is recorded only after an ack.
- Webhook delivery disables system proxies, matches a no-port allowlist entry to the scheme default port, and classifies retryable responses.
