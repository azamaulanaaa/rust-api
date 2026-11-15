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
- Exact-value unique claims with a SHA-256 hash and a SHA-512 fingerprint, so a deliberate hash collision does not create a false duplicate.
- Portable EAV export, import, resumable index rebuild, and restore validation through `eav export`, `eav import`, `eav rebuild-index`, and `eav validate`.
- `eav reset-cursor` operator command for the durable rule cursor.
- Dead-letter browse and retry routes, and an entity referrers route.
- EAV metrics for entity writes, deletes, conflicts, dead letters, feed lag, outbox age, and replica builds.
- One bounded SST cache shared across OxKV handles, with a process-wide size from `[database].sst_cache_mb`.
- Timestamped webhook signature and a replay verifier for receivers.
- Bounded rule-match cache with invalidation on upsert, delete, and enable.

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
- A unique claim keys on the exact value, so a deliberate SHA-256 collision does not create a false duplicate.
- A migration dry run checks unique values across every entity that pins the target schema, and its metadata write uses compare-and-set with `409` on a concurrent update.
- `list_by_schema_page` enforces the offset cap at the store layer.
- A timer event goes through the outbox, and the fired marker, time-row delete, pending counter, and outbox row commit in one transaction.
- An unrelated update keeps the stored time-row causation, and a timestamp change writes the new cause.
- A `schema_removed` rule trigger returns `400`, and a stored rule whose only trigger is `schema_removed` stays inert.
- A condition script applies the rule read set and runs on a blocking thread.
- The rule runner reports progress after a cursor advance, a dead-letter move, or a healthy caught-up poll, and the runtime clears its failure flag only on that signal.
- The snapshot cursor scans raw pages until the visible page fills, so a sparse grant set reaches every visible row.
- Malformed query and path values return the standard error envelope.
- `GET /eav/rules` hides `after` from OpenAPI and still returns `400` for it.
- A rule enable uses compare-and-set, repeats the author grants, and returns `409` for a stale toggle or upsert.
- A queue lease expiry uses unix milliseconds, and a sub-second lease keeps its full duration.
- `queue.lease_lost` counts a rejected ack, nack, or extend, and `queue.failed` counts job failures.
- The durable queue keeps a due index and sweeps at most 256 due entries.
- A webhook signs `X-Signature-Timestamp` and `X-Signature-V2` over `timestamp.body`, and the legacy `X-Signature` stays body-only.
- The log action redacts secret-like parameter keys and URL user information and query values.
- A full replica read above `[limits].max_full_replica_bytes` returns `400`.
- A WAL range read uses one scan and keeps sequence order.
