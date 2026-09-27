# rust-api

A starter-kit REST API server providing pluggable modules for OIDC authentication, JWT session validation, and Casbin-based authorization, built on [Actix Web](https://actix.rs/).

The crate is intentionally business-logic free: applications compose `ApiModule` implementations onto an `ApiService` to build their own API surface on top of the shared auth/policy plumbing.

## Features

- **OIDC authentication** — authorization-code flow with PKCE, CSRF state, and nonce validation against any spec-compliant identity provider (Keycloak, Entra ID, Auth0, …)
- **JWT validation via JWKS** — refreshable multi-algorithm key store with rotation support; unknown `kid` triggers a debounced re-fetch of the provider's keys
- **Casbin RBAC on OxKV stores** — permission rules and group membership backed by a prefix-scoped [`oxkv::OxKvStore`](https://docs.rs/oxkv) (`{prefix}/policy` inside the configured S3 bucket via `object_store::aws::AmazonS3`); one `OxKvStore` per domain sharing a single `AmazonS3Builder` setup (`db.rs`); no local Redb file required
- **Validated persistence** — every rule write is validated through `policy::adapter::encode_rule` / `PolicyRuleValidator` (`{sec}:{ptype}:{hash}` key shape, JSON array value, arity 3 for `p` / 2 for `g`) before any transaction opens; malformed rules fail at the API boundary instead of poisoning startup
- **Single-live-handle-per-prefix** — each `OxKvStore` owns a fencing session (memtable/WAL buffer); two live handles on the same prefix can fence/diverge on real S3 — share via `Arc` instead of building a second one (`db::build_s3_store` docs); the crate's own tests use `InMemory`-backed `OxKvStore` with `skip_probe(true)` and a new session for single-threaded reopen, via `#[cfg(test)]`-gated helpers in `db.rs` that are deliberately not public API (a store with no conditional-write probe is the right choice for a test backend and the wrong one for anything else)
- **Modular row-level authorization** — business rows authorize as `{type}:{id}` objects via `policy::row::RowAuthorizer`; files delegate to owning rows instead of a coarse `fs` gate
- **Temp per-user file scope with refcount relations** — uploads start as temp owned by `owner_sub` (`refs==0`), `attach`/`detach` to rows via `fs:rel:{type}:{id}:{file}` increments/decrements `fs:files:{id}:refs` inside the `{prefix}/fs` `OxKvStore`; editing a row swaps relations, never deletes the underlying S3 object immediately; durable S3-side multipart state (`fs:mp:{upload_id}` → `PersistedMultipart`) rehydrates the client after restarts so `upload_part`/`complete`/`cancel`/GC keep working. Part count is capped at S3's 10,000 (≈4.9 GiB at the 512 KiB part cap) and enforced at init, not complete
- **Capability tokens** — short-lived HMAC JWT (`fs/token.rs`, 5m) available via `FsEngine::mint_token` / `verify_token` after row authorization, without extra policy hits; `kid`-keyed rotation (`secret` mints, `previous_secret` verifies-only, see `[capability]`) with ephemeral per-boot fallback. Note: the current `/fs/*` routes authenticate with the OIDC JWT (`claims.sub` + `can_access`) and do not consume capability tokens yet — the engine API is ready for direct `PUT`/`GET` delegation.
- **GC for orphans** — hourly sweeper removes abandoned upload sessions and temp/orphaned files (`refs==0` and `age>24h` or `orphan_since>24h`), plus a third pass that lists `files/` object bytes and reaps bytes with no live session/file key older than 24h.
- **Per-user filtered replicas with WAL (S3, oxkv manifest)** — WAL lives as `wal:{seq:020}` + `wal:seq` inside an `OxKvStore`; each user owns one replica prefix (`{db}/u/{sha256-hex(sub)}/`) holding their filtered file set with its own oxkv `manifest.json` (the segment list); `GET /sync/status` reports the pointer (`prefix`, `applied_seq`, `head`) with an `ETag` (repeat polls get `304`) without building, and every object inside the prefix is individually cached at `GET /sync/db/{object}` with backend `ETag` passthrough and `If-None-Match` support — mutable manifest plus immutable, forever-cacheable segments: `manifest.json` is served `no-cache`, every other replica object is `public, max-age=31536000, immutable`. `POST /sync/sync` short-circuits when coverage already meets the WAL head; deltas of ≤1000 file/relation ops replay onto the live prefix, while policy changes, larger deltas, or fencing losses fall back to full recalc (or adopt the winner's coverage).
- **Single-writer enforcement** — the server claims a lease on `[database].prefix` before opening any store and refuses to start if another live process holds it; the holder renews at a third of the TTL, releases on clean shutdown, and reports `/ready` 503 if a successor ever takes over (see [Single-writer enforcement](#single-writer-enforcement))
- **WAL-instrumented mutations** — `FsEngine` (complete/attach/detach/delete) and `PolicyEngine` (rule/group changes, including `policy import`) append to one shared `Wal` after each mutation commits (fail-closed: a logging failure fails the whole operation, so the WAL never silently misses a write); concurrent appends serialize on a mutex shared by all handles. Engines without a wired WAL log nothing (tests).
- **Transactional replica builds** — snapshots filter into a scratch store, diff against the live replica as a streaming merge-join, and commit the diff plus the coverage marker in one transaction: a crash before commit leaves the old state untouched (oxkv replays only listed WALs on open), and an empty diff commits nothing — mid-broken writes are handled by the engine, not app scaffolding. The diff holds one key per side, not the replica: see [Per-user replicas](#per-user-replicas-wal).
- **Modular composition** — implement the `ApiModule` trait and register onto `ApiService`; JWT auth middleware is applied per module scope (global middleware is bearer-token extraction + request tracing)
- **Observability** — structured console logging through the `tracing` facade (`RUST_LOG` syntax), plus optional OpenTelemetry span/metric export over OTLP (gRPC with `otlp-grpc` feature, HTTP with default `otlp-http` feature) with W3C Trace Context propagation

## API endpoints

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/health` | Liveness probe | none |
| GET | `/ready` | Readiness probe (policy-lock check) | none |
| GET | `/auth/login` | Start OIDC login (redirects to provider) | none |
| GET | `/auth/callback` | OIDC authorization-code callback | none |
| GET | `/auth/me` | Session probe (`sub`, `iss`, `aud`, `exp`) | Bearer token |
| POST | `/auth/logout` | Clear the session cookie (always `204`) | none |
| POST | `/setup/admin` | One-time bootstrap: assign caller the `superadmin` role | Bearer token |
| GET | `/policy/rules` | List policy rules | Bearer token |
| POST | `/policy/rules` | Add a policy rule | Bearer token |
| DELETE | `/policy/rules` | Remove a policy rule | Bearer token |
| GET | `/policy/groups` | List all groups with member counts | Bearer token |
| DELETE | `/policy/groups/{group_name}` | Delete a group and all its memberships | Bearer token |
| GET | `/policy/groups/{user_id}` | List groups of a user | Bearer token |
| GET | `/policy/groups/{group_name}/users` | List users of a group | Bearer token |
| POST | `/policy/groups` | Assign a user to a group | Bearer token |
| DELETE | `/policy/groups/{group_name}/users/{user_id}` | Remove a user from a group | Bearer token |
| GET | `/policy/users` | List all subjects with their groups | Bearer token |
| POST | `/fs/uploads` | Start a multipart upload (temp, owned by caller) | Bearer token |
| PUT | `/fs/uploads/{id}/parts/{idx}` | Upload one part (raw bytes, owner only) | Bearer token |
| POST | `/fs/uploads/{id}/complete` | Complete the upload (assembles parts in S3) | Bearer token |
| DELETE | `/fs/uploads/{id}` | Cancel an in-progress upload (owner only) | Bearer token |
| GET | `/fs/uploads/{id}` | Upload progress (owner only) | Bearer token |
| GET | `/fs/files/{id}/meta` | File metadata (owner or row Read) | Bearer token |
| GET | `/fs/files/{id}` | Download file content (owner or row Read; `Range` → `206`/`416`) | Bearer token |
| DELETE | `/fs/files/{id}` | Delete file (owner when temp, or row Delete) | Bearer token |
| GET | `/sync/status` | Replica pointer + coverage ETag (`prefix`, `applied_seq`, `head`; never builds) | Bearer token |
| POST | `/sync/sync` | Advance replica toward WAL head (short-circuit, replay, or full recalc) | Bearer token |
| GET | `/sync/db/{object}` | One replica object (manifest/SST/WAL) with ETag + `If-None-Match` | Bearer token |
| GET | `/openapi.json` | Generated OpenAPI 3.1 document (served from `src/docs.rs`) | none |
| GET | `/swagger-ui/` | Swagger UI for the spec above | none |

Protected routes accept either an explicit `Authorization: Bearer <token>` header (preferred) or the session cookie set by `/auth/callback`. Requests without valid credentials get `401`; insufficient permissions get `403`. `/policy/*` additionally requires Casbin permissions (`rules` + `read`/`write` for rule endpoints, `user_groups` + `read`/`write` for group/user endpoints) — a merely valid token is not enough. `/setup/admin` requires a valid JWT but no policy check (one-time bootstrap). Errors use a `{"error": "<message>"}` envelope with a stable, non-sensitive message per status (`"forbidden"`, `"not found"`, `"internal server error"`, …); server-side causes are logged, never serialized. Two deliberate exceptions use their own bodies: `/auth/callback` returns an `AuthResponse` envelope (`success`/`token`/`error`) because the SPA reads the token from it, and the OpenAPI/Swagger routes return spec documents.

Every served route is in the OpenAPI spec: `src/docs.rs` (`/openapi.json` + `/swagger-ui/`) covers `/health`, `/ready`, `/auth/*`, `/setup/admin`, `/fs/*`, `/policy/*`, and `/sync/*` — generate the SPA client from it instead of hand-writing fetch shapes. `spec_covers_all_served_routes` fails the build if a route is added to a module without appearing in the spec, and each module's own test checks the reverse: that every path the spec lists for it is actually mounted (`fs::route::tests::every_documented_route_is_mounted`). A service left out of a `configure` chain used to be invisible — it compiles, the spec still lists the path, and the only symptom is a `404` on a documented endpoint.

Errors render as `{"error": "<stable message>"}` from a single construction site (`http::error::ApiError::envelope`), including a body that fails to parse: actix's own JSON-extractor failure is a bare `400` in `text/plain`, so `http::apply_limits` installs an error handler that answers inside the envelope. The extractor's message names the offending field and is logged, never sent. The only responses outside the envelope are `/auth/callback`'s browser redirects, `/openapi.json`, and `/swagger-ui/*`, none of which are API errors.

### First-run bootstrap

A fresh deployment boots with an empty policy store, so nobody can pass the self-authorization checks on `/policy` routes yet. Log in through `/auth/login`, then call `POST /setup/admin` **once** with your token: the first authenticated subject to do so becomes `superadmin` (`201`); every later call returns `409`, including after restarts. From there, grant permissions to groups and manage membership via the normal policy endpoints.

### Browser clients (SPA/PWA)

Cross-origin SPAs set `[http].allowed_origins` (or `RUST_API_ALLOWED_ORIGINS`) to their origin(s); credentials are always allowed. Auth flow: `GET /auth/login` → provider → `/auth/callback` (sets the `auth_token` cookie and returns the token) → `GET /auth/me` as the guard/session probe → `POST /auth/logout` to clear the cookie. Poll `GET /sync/status` (coverage `ETag`, `304` on repeat) and advance with `POST /sync/sync`, then read replica objects via `GET /sync/db/{object}` (`manifest.json` is `no-cache`, segments are immutable). Replica objects are streamed with a declared `Content-Length` rather than buffered, so a multi-hundred-megabyte SST segment does not have to fit in the heap once per in-flight request. Generate the client from `/openapi.json` — it covers every route.

## Architecture

```
src/
├── main.rs              binary entry point: config → telemetry → OIDC/policy/fs/sync wiring → listener
├── lib.rs               crate root and documentation
├── config.rs            TOML configuration model ([database].prefix + mirror_master, [s3], [observability], [capability], [http].allowed_origins + RUST_API_ALLOWED_ORIGINS; binary-private `mod config`)
├── db.rs                OxKV store factory — one AmazonS3Builder for file bytes + OxKvStore; build_s3_store / build_object_store / build_scratch_store / default_sst_cache; single-live-handle-per-prefix contract (the test-only builders build_test_store* / test_prefix are `#[cfg(test)]`, not API)
├── lease.rs             single-writer lease on [database].prefix (startup refusal + renewal + release)
├── fencing.rs           process-wide latch for a fenced *primary* prefix; gates /ready alongside the lease
├── telemetry.rs         tracing subscriber + OTLP span/metric export bootstrap (otlp-grpc / otlp-http features)
├── docs.rs              utoipa OpenAPI `ApiDoc` (all routes; served via http/docs.rs as /openapi.json + /swagger-ui/)
├── records.rs           shared change-feed vocabulary — FileRecord, WalOp/WalEntry, ChangeSink/ChangeError; the leaf that breaks the fs↔sync cycle (see Layering)
├── http/                HTTP scaffolding shared by all modules
│   ├── mod.rs           ApiService registry + ApiModule trait (declared route prefix, duplicate-prefix check) + CORS builder
│   ├── error.rs         ApiError enum and uniform JSON error envelope
│   ├── health.rs        /health + /ready (readiness: policy-lock check)
│   ├── docs.rs          mounts /openapi.json + /swagger-ui/*
│   └── middleware/      bearer_token, jwks (debounced refresh), jwt (JWKS-backed claims + Validated extractor), request_tracing
├── oidc/                OIDC client: /auth/* (code flow, PKCE, session probe)
│   ├── mod.rs           OidcClient, OidcConfig, PKCE/nonce/state helpers
│   └── route.rs         OidcApiModule owns all of /auth (login/callback/logout/me) and seeds JwtClaimsMiddleware
├── policy/              Casbin engine, oxkv adapter + validator, management routes
│   ├── adapter.rs       OxkvAdapter<S: Store> + PolicyRuleValidator + encode_rule() (validates before tx)
│   ├── admin.rs         export_s3 / import_s3 (OxKvStore, not file)
│   ├── mod.rs           PolicyEngine::init_s3 / init_with_store (prefix-scoped OxKvStore)
│   ├── row.rs           RowAuthorizer trait for {type}:{id} objects
│   ├── route.rs         /policy/* handlers (rules + groups + users, self-authorized)
│   └── setup.rs         /setup/admin one-time superadmin claim
├── sync/                Per-user replicas (stable OxKvStore prefixes + manifest, WAL-backed)
│   ├── mod.rs           module re-exports
│   ├── wal.rs           Wal on OxKvStore — the durable `ChangeSink` (wal:{seq:020} + wal:seq, serialized appends); op types live in `records.rs`
│   ├── snapshot.rs      SnapshotManager — one filtered replica per user ({db}/u/{sha256-hex(sub)} + sync:applied marker), tx-atomic rebuilds, idempotent replay
│   └── route.rs         GET /sync/status (pointer + ETag, no build) + POST /sync/sync (advance) + GET /sync/db/{object} (segments + ETags)
└── fs/                  Object-store file storage (AmazonS3/MinIO/R2 via object_store, InMemory for tests)
    ├── mod.rs           FsEngine (temp per-user, row delegation, token mint/verify)
    ├── model.rs         request/response DTOs (InitRequest, CompleteRequest, FileMetadata, ...)
    ├── error.rs         FsError mapping to ApiError
    ├── relation.rs      RefInfo + fs:rel:{type}:{id}:{file} + fs:files:{id}:refs
    ├── token.rs         FsClaims HMAC JWT (5m)
    ├── store.rs         FsStore on OxKvStore (fs:uploads:{id}:meta, fs:files:{id}:meta, staged parts, fs:mp:{upload_id} persisted multipart)
    ├── gc.rs            hourly sweep for sessions + orphaned files (refs==0, 24h TTL) + orphaned files/ bytes
    ├── s3.rs            S3Client trait + S3ClientConfig (+ backend_upload_id/restore_multipart for restart resume)
    ├── object_store.rs  ObjectStoreClient + shared s3_builder() for OxKvStore + file bytes (propagates abort errors; GC retains session on failure)
    └── route.rs         /fs/uploads/* and /fs/files/* handlers
```

Modules implement [`ApiModule`](src/http/mod.rs) and are registered onto `ApiService`; each module brings its own middleware stack (e.g. `/policy/*` requires validated JWT claims).

## How authorization works

The Casbin RBAC model is:

```ini
p = sub, obj, act        # permission rule: subject may act on object
g = _, _                 # group membership: user belongs to group
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

A request is authorized when its subject either holds a matching `p`-rule directly or belongs to a group (`g`-link) that does. Typical setup: grant permissions to *groups* via `POST /policy/rules`, then manage membership via the `/policy/groups` endpoints.

Rules persist to a prefix-scoped [`oxkv::OxKvStore`](https://docs.rs/oxkv) under `{database.prefix}/policy` inside the configured S3 bucket (one `ObjectStore` + one `AmazonS3Builder` shared with the file-byte store via `db::build_s3_store` / `fs::object_store::s3_builder`). Each rule is one key-value pair (`{sec}:{ptype}:{hash}` → JSON array) written transactionally. Validation is enforced on every write path through `adapter::encode_rule` / `PolicyRuleValidator` — wrong-arity rules, non-JSON payloads, or unknown sections fail before any transaction opens. The adapter validates directly instead of requiring callers to wrap their store in a `HookStore`.

> **Single-live-handle-per-prefix:** each `OxKvStore` owns a fresh fencing session (memtable/WAL buffer). Two live handles on the same prefix can fence each other or diverge on real S3. Share the handle via `Arc` — do not build a second one. This crate's own tests use a fresh `InMemory` per prefix, and a new session over the same `InMemory` for single-threaded reopen (the new session supersedes the previous one). Exception: the `policy export` / `policy import` CLI subcommands open a short-lived second handle on `{prefix}/policy` (and `{prefix}/wal` for import) — never run them concurrently with a live server on the same prefix.

### Single-writer enforcement

`oxkv` acquires a prefix by CAS-bumping `ownership.json`: last writer wins, and the loser is fenced at write time (`StoreError::Fenced`, which oxkv documents as "the current process must stop writing and restart"). That is a correct *takeover* protocol and a useless *detection* protocol — nothing in it distinguishes "my predecessor is still serving traffic" from "my predecessor crashed". A second replica pointed at the same prefix would start cleanly, serve writes that silently diverge, and only fail later and elsewhere.

So the server claims an explicit **writer lease** (`src/lease.rs`) on `{prefix}/_rust-api-writer-lease.json`, covering every prefix-scoped store: `policy`, `fs`, `wal`, and each per-user replica. It is claimed *before* any store is opened, because opening a store is what takes the epoch.

| Situation | Behavior |
|---|---|
| Second process starts, lease live | **Refuses to start**, naming the holder, its pid, and how long until the lease goes stale |
| Predecessor crashed | Lease goes stale after `writer_lease_ttl_secs`; the next start takes over automatically and logs who it displaced |
| Predecessor stalls past the TTL | Successor takes over; the predecessor notices on its next renewal, logs an error, and `/ready` turns **503** so the orchestrator drains it |
| Orderly shutdown | Lease is released, so a rolling restart hands over without waiting out the TTL |
| Record unparseable | Refused, never overwritten — guessing the owner is the failure this exists to prevent |

The lease only sees writers that take it. `src/fencing.rs` covers the uncooperative case: if a primary prefix (`{db}/fs`, `{db}/policy`, `{db}/wal`) is fenced anyway — an older build, a `writer_lease_ttl_secs = 0` deployment, an operator running `policy import` against a live prefix — the loss latches a process-wide signal that `/ready` also reports, and the log gets one `error` line naming the prefix. Every subsequent write on that handle fails the same way, so only the first is logged at `error` and the repeats drop to `debug`.

A **replica** fencing loss deliberately does not latch. Losing a build race is routine and `sync` resolves it by adopting the winner's coverage, so `FsStore` carries an explicit primary mark (`FsStore::primary` vs `FsStore::new`) that decides whether a failure is terminal; `sync`'s replica stores are never marked. A latch in the shared `oxkv::StoreError → FsError` conversion would have pulled a healthy server out of rotation every time two workers raced to build one user's replica.

The process is **not** terminated on a fencing loss. It is already read-only, so it can no longer diverge, and exiting immediately means zero healthy writers if the successor is not serving yet — marking the instance unready drains it through the load balancer instead, and leaves the restart to an operator who has the log line saying the handle is terminal.

The lease cannot stop a network partition from splitting the prefix; nothing lease-based can. What it buys is that the losing side *finds out* and stops taking traffic rather than discovering it through corrupted data.

> **Set `writer_lease_ttl_secs = 0` only where exactly one process can ever reach the bucket** (a laptop, a single container). It disables enforcement and logs a warning at startup. The TTL must otherwise exceed your worst-case pause between renewals — a long GC pause or a slow S3 round trip — or a healthy process gets displaced by its own peer. Renewal runs at a third of the TTL, so two consecutive missed renewals still leave a full TTL of headroom.

`/ready` reports 503 when the lease is lost **or** a primary prefix is fenced (see below), so this composes with an existing readiness probe rather than requiring a new one.

### Fencing losses are typed, not string-matched

A store whose epoch was lost surfaces as `FsError::Fenced`, classified in one place — `From<oxkv::StoreError>` — and detected with `FsError::is_fencing_loss()`. It used to be a `detail.contains("fenced")` search on the flattened store message, so any rewording in `oxkv` would have silently turned the recoverable path in `POST /sync/sync` (adopt the concurrent builder's coverage) into a 500 for every client.

Keeping that correct means every `oxkv::StoreError` → `FsError` conversion has to route through `From`, including the private `store_err` helpers in `fs::store` and `sync::snapshot`; those are one-liners for exactly that reason. The reason string is operator-facing: it is logged at `error` level (a lost epoch is terminal for that handle, not a blip) and never serialized.

Policy writes reach the store through casbin, whose `Adapter` trait is written in `casbin::Error`, so there the `oxkv::StoreError` arrives boxed inside `AdapterError` and the classification has to be redone at the boundary: `From<casbin::Error> for PolicyError` downcasts that box and lifts the epoch loss into `PolicyError::Fenced`, which `PolicyError::is_fencing_loss()` detects. Without it a stale writer's policy write produced

```text
Casbin(AdapterError(AdapterError(Fenced("epoch 7 superseded"))))
```

— a 500 indistinguishable from any other store failure, on the same prefix and the same condition `FsError::Fenced` already reports. `PolicyError::Fenced` deliberately renders the same text as `FsError::Fenced` ("store epoch lost to another writer …"), so one log query finds a fencing loss on either store, and the client still only ever sees `{"error":"internal server error"}`. `policy::adapter::tests::a_fenced_policy_write_is_typed_as_a_fencing_loss` drives this through a real casbin enforcer over a store whose `commit` reports a lost epoch, so it also pins the assumption that casbin preserves the box rather than flattening it to a string.

### Row-level and file delegation

Business rows authorize as `{row_type}:{row_id}` via `RowAuthorizer` (`policy/row.rs`). Files are not gated by a coarse `fs` object; instead:

- `POST /fs/uploads` creates a temp file owned by `owner_sub` (`refs==0`) in the `{prefix}/fs` `OxKvStore` (`fs:uploads:{id}:meta`, staged parts `fs:uploads:{id}:part:{idx}`, durable `fs:mp:{upload_id}` multipart record for multipart uploads). Part intake is stream-capped at the expected part size (oversize → `413`, declared-length mismatch → `400` before reading).

**Upload size limits.** `InitRequest` is validated against the same constraints as the worker-side `Schema.filter`, plus S3's per-upload part cap:

| Field | Constraint |
|---|---|
| `file_total_parts` | 1 for a single-part upload, else 1–10,000 (S3's hard limit) |
| `part_size` | a multiple of 1 KiB, ≤ 512 KiB |
| single-part `file_size` | ≤ 10 MiB, and must equal `part_size` |
| multipart `file_size` | must equal `file_total_parts × part_size` exactly |
| **resulting multipart ceiling** | **10,000 × 512 KiB ≈ 4.9 GiB** |

The part cap is enforced at `init`, not at `complete`, so a client learns its split is illegal before uploading anything rather than after. It also bounds the per-session `etags`/`checksums` vectors the engine allocates from the declared count. Files larger than ~4.9 GiB need a larger `part_size` cap or a different upload strategy.
- `FsEngine::attach(row_type,row_id,file_id,caller)` requires `Write` on `{row_type}:{row_id}` and increments `fs:files:{id}:refs` + writes `fs:rel:{type}:{id}:{file}`.
- `FsEngine::detach` decrements and sets `orphan_since` when `refs==0`.
- Reads/deletes check `owner_sub == caller` (temp) or any owning row grants `Read`/`Delete`. Editing a row is `detach(old)+create new+attach(new)` — the old S3 object becomes orphan and is removed by GC after 24h.
- `FsEngine::mint_token` / `verify_token` (`fs/token.rs`) implement short-lived HMAC delegation without extra policy hits, but no `/fs/*` route consumes them today — keep using the OIDC JWT for file ops. File bytes live in S3 via `object_store` (`AmazonS3` in production, `InMemory` in tests). Multipart state survives restarts via the `fs:mp:{upload_id}` record (`restore_multipart` before `upload_part`/`complete`/`cancel`/GC; sessions predating the record fail with a restart-this-upload `400`). Cancel/GC abort S3 first and retain the session on failure so the next sweep retries instead of leaking staged bytes.

### Per-user replicas (WAL)

The master `FsStore` and `Wal` both live on prefix-scoped `OxKvStore`s and remain the sole write path. `Wal` appends `wal:{seq:020}` entries plus a `wal:seq` head. The op vocabulary (`WalOp::{PolicyRuleAdd/Remove,GroupAdd/Remove/Delete,Attach,Detach,FileCreate,FileDelete}` plus legacy `PolicyAdd/Remove` marks) and the `FileRecord` it carries live in `src/records.rs`, not in `sync/` — see [Layering](#layering). Each user owns one replica prefix (`{db}/u/{sha256-hex(sub)}/`) holding their filtered file set with its own oxkv `manifest.json` (the segment list): builds filter through `RowAuthorizer`/`owner==sub` into a scratch store, diff against the live replica, and commit the diff plus the `sync:applied` coverage marker in a single transaction — so a crash before commit leaves the old state untouched and an empty diff commits nothing at all. The diff is a **merge-join of two key-ordered paged walks** (`fs::store::KvPages`), not a comparison of two collections: both sides are ordered by construction, so the rebuild holds one key per side instead of a map of the whole replica. That is what keeps a full rebuild's peak memory independent of how much data the user can see; what still scales with the size of a *change* is the single commit transaction, which is normally far smaller and is why committing in chunks (which would cap that too) was rejected — it would give up the all-or-nothing crash behaviour above. Replica prefixes hash the subject (`SHA-256 hex`) so attacker-influenced OIDC `sub` values cannot traverse or collide. `GET /sync/status` returns the replica pointer with a coverage `ETag` (repeat polls get `304` without touching storage beyond the marker read, and it never builds), `POST /sync/sync` advances it, and `GET /sync/db/{object}` serves one replica object with backend `ETag` passthrough and `If-None-Match` support — non-manifest engine files are immutable by construction (`Cache-Control: public, max-age=31536000, immutable`), only `manifest.json` is revalidated (`Cache-Control: no-cache`). Replicas hold filtered file/relation metadata; file bytes stay in S3. Wasm clients open an `OxKvReader` over the prefix and follow the live manifest.

Every master mutation is also announced to the shared change feed (`{db}/wal`): file creates/deletes and attach/detach from `FsEngine`, rich rule/group changes from `PolicyEngine` (including `policy import`), each after the mutation commits — a logging failure fails the whole operation, and concurrent appends serialize on a mutex shared by all engine handles. `POST /sync/sync` short-circuits when coverage already meets the WAL head; otherwise deltas of ≤1000 ops replay onto the live prefix (file/relation ops re-applied with visibility re-checked; rule/group ops resync only the affected user/row with irrelevant users/objects skipped, marker last — a crash heals on the next poll), while legacy policy marks, oversized fan-out, larger deltas, or fencing losses fall back to full recalc — or adopt the winner's coverage on a lost build race. No version GC is needed: there is only ever one prefix per user, maintained by oxkv's own WAL GC and compaction.

### Layering

`fs` and `policy` *emit* changes; `sync` *consumes* them. The vocabulary both sides need — `FileRecord`, `WalOp`, and the `ChangeSink` trait — lives in `src/records.rs`, which depends on nothing else in the crate:

```text
       records
       /     \
  fs, policy   sync
       \     /
   (fs::store, the replica write path)
```

`FsEngine::with_change_sink` and `PolicyEngine::with_change_sink` take `Arc<dyn ChangeSink>`, so neither names `sync` and the graph is a DAG. `sync::wal::Wal` is the durable implementation.

This is enforced, not just documented: `records::tests::producers_do_not_depend_on_the_consumer` fails if any production `use` in `fs/` or `policy/` names `crate::sync`, and `this_module_depends_on_nothing_in_the_crate` keeps `records` a leaf. Rust permits module cycles, so nothing else would notice the edge creeping back.

## Configuration

The server is configured with a TOML file passed via `--config`:

```toml
public_address = "http://localhost:8080"   # public base URL used to build OIDC redirects
listen_port = 8080                          # TCP port to bind

[authorization]
client_id = "rust-api"
client_secret = "secret"
issuer_url = "https://idp.example.com"      # base URL of the OIDC discovery document

[database]
prefix = "oxkv"                             # object prefix inside the S3 bucket for OxKV keys (default "oxkv")
                                            # policy → {prefix}/policy, fs → {prefix}/fs, wal → {prefix}/wal,
                                            # replicas → {prefix}/u/{sha256-hex(sub)}; no local file
# writer_lease_ttl_secs = 60                 # single-writer lease TTL (default 60; 0 disables enforcement)
# mirror_master = false                     # prototype: keep a lazily-warmed in-RAM mirror of the master fs
                                            # store to serve full replica rebuild scans from memory after the
                                            # first pass (costs one master key set in RAM; only with single writer)

[s3]
bucket = "my-bucket"                          # S3 bucket (AmazonS3 via object_store; InMemory for tests)
region = "us-east-1"
# endpoint_url = "http://localhost:9000"      # MinIO/R2 endpoint; omit for AWS
# force_path_style = true                       # required for MinIO
# access_key_id = "minioadmin"
# secret_access_key = "minioadmin"

# Optional — omit the whole section to disable span export.
# Backend is selected by cargo feature: default `otlp-http` uses OTLP/HTTP,
# `otlp-grpc` uses OTLP/gRPC (see Cargo.toml [features]).
[observability]
service_name = "rust-api"                   # resource attribute on exported telemetry
otlp_endpoint = "http://localhost:4317"     # OTLP collector endpoint (gRPC default port; HTTP uses /v1/traces)
sample_ratio = 1.0                          # fraction of traces sampled (0.0–1.0, default 1.0)

# Optional — file-delegation (capability token) signing keys.
# Omit the section and the server mints an ephemeral OS-RNG key per boot
# (tokens die with the process — fine for dev, a warning in prod).
# Generate: python3 -c "import secrets; print(secrets.token_hex(32))"
# Rotate: move the current secret to previous_secret, deploy the new secret
# as secret — tokens minted under either key verify until the old
# generation expires (5-minute TTL).
# [capability]
# secret = "<64 hex chars>"                 # current key: mints tokens
# previous_secret = "<64 hex chars>"       # old key: verifies only, during rotation

# Optional — browser CORS origins (deny-by-default: empty serves no
# Access-Control-Allow-Origin, i.e. same-origin only). List each SPA origin
# explicitly when served cross-origin; credentials are always allowed so the
# auth_token cookie and bearer header work.
# [http]
# allowed_origins = ["https://app.example.com", "http://localhost:5173"]
```

Single bucket, prefix-scoped stores: `db::build_s3_store` builds one `AmazonS3` `ObjectStore` from `[s3]` and wraps it with `OxKvStore::builder().with_object_store(...).with_prefix("oxkv/policy")` etc. via the shared `fs::object_store::s3_builder`. Breaking change since `988873c`: `[database].path` (Redb file) is gone — use `[database].prefix`; old `*.redb` files are no longer read (no automatic migration).

Secrets via environment (win over the file when present and non-empty, for secret managers): `RUST_API_CLIENT_SECRET`, `RUST_API_S3_ACCESS_KEY_ID`, `RUST_API_S3_SECRET_ACCESS_KEY`, `RUST_API_CAPABILITY_SECRET`, `RUST_API_CAPABILITY_SECRET_PREV`, `RUST_API_ALLOWED_ORIGINS` (comma-separated).

## Production hardening

The binary enforces no rate limits: per-IP throttling on the
credential and control-plane routes is delegated to the load balancer
in front of it. The routes that need it are `/auth/*` (login/callback
are unauthenticated and each callback fans out to JWKS + token
exchange), `/setup/*` (one-time bootstrap), and `/policy/*` (every
write is Casbin evaluation work). Data-plane `/fs` and `/sync` reads
can stay generous. Example for nginx:

```nginx
# 10 req/s burst 20 for auth + setup, 30 req/s burst 50 for policy writes.
limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=policy:10m rate=30r/s;

server {
    listen 443 ssl;
    location ~ ^/(auth|setup)/ {
        limit_req zone=auth burst=20 nodelay;
        proxy_pass http://rust-api:8080;
    }
    location /policy/ {
        limit_req zone=policy burst=50 nodelay;
        proxy_pass http://rust-api:8080;
    }
    location / {
        proxy_pass http://rust-api:8080;
    }
}
```

Tune the rates to your IdP latency and admin headcount; the numbers
above assume an interactive login flow, not machine-to-machine token
churn. Never expose the binary directly to the internet without this
(or an equivalent WAF/ingress) layer.

## Running

```bash
# install toolchain (Rust stable via mise)
mise install

cargo run -- serve --config config.toml
```

### Logging & tracing

Console output is always enabled. Log level follows `RUST_LOG` when set, otherwise derives from `--verbose` (debug) vs default (info):

```bash
RUST_LOG="debug" cargo run -- serve --config config.toml
```

When `observability.otlp_endpoint` is configured, one span is emitted per request (method, route template, status code, latency; 5xx marked as error) and batch-exported to any OTLP collector (HTTP with the default `otlp-http` feature, gRPC with `otlp-grpc`). Inbound `traceparent` headers are extracted through the globally registered W3C Trace Context propagator, so requests from upstream instrumented services continue the same distributed trace. For example, with the Grafana LGTM stack:

```bash
docker run -p 4317:4317 grafana/otel-lgtm
```

## Policy data management

Policies can be exported to JSON for backups and re-imported into a fresh store (e.g. when moving hosts). Both commands take `--config` (provides `[s3]` + `[database].prefix`) — not a file path:

```bash
rust-api policy export --config config.toml --out backup.json
rust-api policy import --config config.toml --input backup.json
```

Under the hood these call `admin::export_s3` / `admin::import_s3` on the `{prefix}/policy` `OxKvStore`. Imports are idempotent — already-present rules are skipped — and every entry passes the same `PolicyRuleValidator` as live API writes. Added rules are also appended to the WAL (production wires it through), so replicas replay the import instead of only discovering it via full recalc.

## Extending the API

Implement `ApiModule` and register it on the service:

```rust
use rust_api::http::ApiModule;

struct MyModule;

impl ApiModule for MyModule {
    // The one prefix this module owns. Declaring it is what lets
    // `ApiService` refuse a set that mounts `/my-scope` twice.
    fn prefix(&self) -> &str {
        "/my-scope"
    }

    fn configure(&self, cfg: &mut actix_web::web::ServiceConfig) {
        cfg.service(actix_web::web::scope("/my-scope")
            .service(my_handler));
    }
}
```

A module owns exactly one prefix. Actix matches a scope by its whole prefix and tries services in registration order, so a module cannot contribute a route to a prefix another module already claimed — it would be silently unreachable.

Handlers can extract validated JWT claims via the `Validated<C>` extractor (returns 401 automatically when claims are absent). See the crate documentation (`cargo doc --no-deps --open`) for details.

### Mounting inside your own server

`ApiService::start` owns the listener. To keep it, register your modules and apply the same global stack yourself — every piece is public:

```rust
use actix_web::App;
use rust_api::http::{
    self, middleware::{bearer_token::BearerTokenMiddleware,
                      request_tracing::RequestTracingMiddleware},
};

let app = http::apply_limits(App::new())
    .wrap(http::cors(&allowed_origins))
    .wrap(RequestTracingMiddleware)
    .wrap(BearerTokenMiddleware)
    .configure(http::health_routes)
    .configure(|cfg| svc.configure(cfg))?   // your modules + readiness probe
    .configure(http::docs::config);         // /openapi.json + /swagger-ui
HttpServer::new(move || app.clone()).run().await?;
```

`svc.configure` returns `Result<_, DuplicateRoutePrefix>`: each `ApiModule` declares the single prefix it owns, and a set that mounts the same prefix twice is refused before anything is registered. Actix itself cannot report this — a scope matches its whole prefix and services are tried in registration order, so a second module on the same prefix has its routes silently ignored while its `/prefix/*` requests are answered by the first module.

`http::docs::config` is mounted **last** on purpose: a catch-all mount registered ahead of your modules can shadow them.

> There is deliberately no `ApiService::build() -> App`. actix-web exposes no nameable public type for an assembled `App` (`BoxedHttpServiceFactory` is crate-private), so such a signature would either leak an unnameable `impl` bound that `HttpServer::new` rejects, or force a dynamic factory per worker. Configuring an `App` you already own is expressible and cheaper.

## Development

```bash
mise install                              # toolchain (Rust stable, zig, cargo-deny, cargo-dist, …)
mise run test                             # run tests (wiremock-based integration tests included; FsStore/PolicyEngine use InMemory-backed OxKvStore)
mise exec -- cargo clippy --all-targets   # lint (all targets, -D warnings; unwrap/expect denied in non-test code)
mise exec -- cargo doc --no-deps          # generate docs (CI runs this too; missing_docs + broken links are errors)
mise run licenses                         # verify dependency licenses stay compatible
mise run advisories
mise run bans
mise run cov                              # coverage via cargo llvm-cov
```

`mise run build` / `run` / `test` link with zig for local cross builds; CI uses plain `cargo`. The `licenses`/`advisories`/`bans`/`cov` tasks call the underlying cargo plugins directly.

Every public item must carry rustdoc — enforced at compile time via `[lints.rust] missing_docs = "deny"` in `Cargo.toml`, and by a `cargo doc --no-deps` step in CI so unresolved intra-doc links also fail.

The composition root is covered too: `http::tests` builds the real served application in-process (via `wired_app!`) and asserts that built-in routes, CORS, the readiness probe, the OpenAPI document, and a registered module's routes are all reachable — no socket required. `docs::tests` additionally checks that every declared path is *mounted*, not merely present in the spec.
Dependency licensing is enforced via [`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) (`deny.toml`: `licenses` + `advisories` + `bans`); all three run in CI. Note that `bans` is configured with `multiple-versions = "warn"`, so duplicate transitive versions (currently `rand` ×3, `base64` ×3) are reported but do not fail the job.
`oxkv` 0.7 (`oxkv` + `oxkv-s3` features) + `object_store` 0.12 (shared `AmazonS3Builder` for file bytes and `OxKvStore`).

### Known unfixable advisories

`mise run advisories` is green, and it is green because of six **documented suppressions** in `deny.toml` — not because the findings are gone. Every one is blocked on a dependency we do not control, so each is recorded with the blocker and the compensating control rather than left to fail the build forever. An advisory that is *not* in that list still fails the check, and `lib::tests::every_ignore_is_justified` fails if an entry is added without a substantive reason (a bare link does not pass).

| Advisory | Crate | Why the fix is not taken | Exposure today |
|---|---|---|---|
| RUSTSEC-2026-0258 | `h2` 0.3.27 | Fixed in `h2 >= 0.4.16`, but every `actix-http` through 3.18.12 requires `h2 ^0.3.27` — no actix-web release can take it | **Real.** `h2` is compiled in (actix-web enables `http2` by default) and reachable by any client speaking `h2c`. Terminate HTTP/2 in front of this process, or bound memory |
| RUSTSEC-2026-0194 | `quick-xml` 0.38.4 | Fixed in `>= 0.41.0`. Reached only via `object_store`, and `oxkv` 0.7.0 (latest) pins `object_store ^0.12` in its public API | Low — response-parsing DoS; needs a crafted XML body from the S3 origin, which is a configured trusted endpoint |
| RUSTSEC-2026-0195 | `quick-xml` 0.38.4 | Same `oxkv` pin | Low — unbounded allocation on the same response path |
| RUSTSEC-2023-0071 | `rsa` 0.9.10 | **No patched version exists.** | None — the Marvin attack needs RSA *private-key decryption*. We only verify RS256 against JWKS public keys; no RSA signing outside tests, no encrypted ID tokens, no `private_key_jwt` |
| RUSTSEC-2025-0134 | `rustls-pemfile` 2.2.0 | Unmaintained, not a vulnerability; same `oxkv` pin | None — a forwarding shim over `rustls-pki-types` per the advisory |
| RUSTSEC-2026-0249 | `smartstring` 1.0.1 | Unmaintained; via `casbin` → `rhai`, and `casbin` 2.20.0 is latest | None — `rhai` only ever evaluates `RBAC_MODEL`, a compile-time constant, so no request-derived expression reaches the parser |

Two of these are worth an operational note rather than a code change. The `h2` finding is the one to act on: it is genuinely reachable, and the mitigation is deployment-side. And the `rsa` entry is load-bearing on a property of this crate — authorization-code flow with PKCE, no client-assertion signing. Adding `private_key_jwt` would make it live, and this table is where that should be noticed.

Re-examine this list whenever `oxkv`, `actix-web`, or `casbin` moves; the `oxkv` pin is the single blocker holding three of the six.

## Releases

Release archives are built with [cargo-dist](https://opensource.axo.dev/cargo-dist/), configured in `dist-workspace.toml` (version 0.30.2, `ci = "github"`, no installers) against the `[profile.dist]` in `Cargo.toml`. Targets: `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`.

```bash
mise run dist-plan     # print the artifact plan without building
mise run dist-build    # build the archives locally into dist/
```

The `cargo-dist` tool pin in `mise.toml` must track `cargo-dist-version` in `dist-workspace.toml`. The GitHub release workflow is generated by cargo-dist rather than checked in; run `cargo dist init --ci=github` to (re)create it at the pinned version.

Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/) style without scopes (e.g. `feat:`, `fix:`, `docs:`).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
