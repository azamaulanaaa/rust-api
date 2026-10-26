# rust-api

A starter-kit REST API server providing pluggable modules for OIDC authentication, JWT session validation, and Casbin-based authorization, built on [Actix Web](https://actix.rs/).

The crate is intentionally business-logic free: applications compose `ApiModule` implementations onto an `ApiService` to build their own API surface on top of the shared auth/policy plumbing.

## Quickstart

This quickstart takes about 5 minutes. It assumes you have an S3-compatible bucket and an OIDC provider.

### Prerequisites

- Rust stable. Install it with `mise install`.
- An S3-compatible bucket. AWS S3 or MinIO both work.
- An OIDC provider. Keycloak, Entra ID, and Auth0 all work. Register a client. Set the redirect URI to `http://localhost:8080/auth/callback`.

### Steps

1. Create `config.toml` with this content. Replace the marked values.

```toml
public_address = "http://localhost:8080"
listen_port = 8080

[authorization]
client_id = "rust-api"
client_secret = "secret"          # replace
issuer_url = "https://idp.example.com"  # replace

[database]
prefix = "oxkv"

[s3]
bucket = "my-bucket"              # replace
region = "us-east-1"              # replace
# endpoint_url = "http://localhost:9000"   # MinIO/R2
# force_path_style = true                  # MinIO
# access_key_id = "minioadmin"
# secret_access_key = "minioadmin"
```

2. Run the server.

```bash
cargo run -- serve --config config.toml
```

3. Open `http://localhost:8080/auth/login` in a browser. Sign in. Copy the token from the callback response.

4. Bootstrap the first admin. Run this call once.

```bash
curl -X POST http://localhost:8080/setup/admin -H "Authorization: Bearer <token>"
```

The call returns `201`. Later calls return `409`.

5. Make one API call.

```bash
curl http://localhost:8080/policy/rules -H "Authorization: Bearer <token>"
```

For deeper detail, see [Configuration](#configuration), [Running](#running), [First-run bootstrap](#first-run-bootstrap), and [API endpoints](#api-endpoints).

## Features

- **OIDC authentication** — authorization-code flow with PKCE, CSRF state, and nonce validation against any spec-compliant identity provider (Keycloak, Entra ID, Auth0, …)
- **JWT validation via JWKS** — refreshable multi-algorithm key store with rotation support. An unknown `kid` triggers a debounced re-fetch of the provider's keys.
- **Casbin RBAC on OxKV stores** — permission rules and group membership, backed by a prefix-scoped [`oxkv::OxKvStore`](https://docs.rs/oxkv) (`{prefix}/policy` inside the configured S3 bucket via `object_store::aws::AmazonS3`). One `OxKvStore` per domain shares a single `AmazonS3Builder` setup (`db.rs`). No local Redb file required.
- **Validated persistence** — `policy::adapter::encode_rule` and `PolicyRuleValidator` validate every rule write before any transaction opens. They enforce the `{sec}:{ptype}:{hash}` key shape, a JSON array value, and arity 3 for `p` / 2 for `g`. Malformed rules fail at the API boundary instead of poisoning startup.
- **Single-live-handle-per-prefix** — each `OxKvStore` owns a fencing session (memtable/WAL buffer). Two live handles on the same prefix can fence or diverge on real S3. Share the handle via `Arc` instead of building a second one (`db::build_s3_store` docs). The crate's own tests use an `InMemory`-backed `OxKvStore` with `skip_probe(true)`, plus a new session for single-threaded reopen. They reach those stores through `#[cfg(test)]`-gated helpers in `db.rs`, which are deliberately not public API. A store with no conditional-write probe is the right choice for a test backend and the wrong one for anything else.
- **Modular row-level authorization** — business rows authorize as `{type}:{id}` objects via `policy::row::RowAuthorizer`. Files delegate to owning rows instead of a coarse `fs` gate.
- **Temp per-user file scope with refcount relations** — uploads start as temp owned by `owner_sub` (`refs==0`). An `attach` or `detach` to a row runs through `fs:rel:{type}:{id}:{file}`, which increments or decrements `fs:files:{id}:refs` inside the `{prefix}/fs` `OxKvStore`. Editing a row swaps relations, and never deletes the underlying S3 object immediately. Durable S3-side multipart state (`fs:mp:{upload_id}` → `PersistedMultipart`) rehydrates the client after restarts, so `upload_part`/`complete`/`cancel`/GC keep working. S3 caps the part count at 10,000 (≈4.9 GiB at the 512 KiB part cap). The code enforces that cap at init, not at complete.
- **Capability tokens** — short-lived HMAC JWT (`fs/token.rs`, 5m), available via `FsEngine::mint_token` and `verify_token` after row authorization and without extra policy hits. Rotation keys on `kid` (`secret` mints, `previous_secret` verifies only, see `[capability]`), with an ephemeral per-boot fallback. Note: the current `/fs/*` routes authenticate with the OIDC JWT (`claims.sub` + `can_access`) and do not consume capability tokens yet. **Decision: keep capability tokens as an engine API (`mint`/`verify`) for direct `PUT`/`GET` delegation; routes continue to use the OIDC JWT today; no removal.** Wiring is tracked separately.
- **GC for orphans, in two separate scopes** — the hourly sweeper removes abandoned upload sessions and temp or orphaned files (`refs==0` and `age>24h` or `orphan_since>24h`). A byte pass lists `files/` object bytes and reaps bytes with no live session or file key older than 24h. **Separately** from that byte pass, a store-level pass calls `oxkv::OxKvStore::gc_orphans` on the handle the engine already holds. That pass reclaims oxkv's own unreachable WAL objects under the store's oxkv prefix. Those objects are the `e{6+ digits}/wal/{8 digits}.log` keys that no manifest lists, stranded by a failed manifest CAS. The two scopes hold different objects and never overlap. See [Garbage collection](#garbage-collection).
- **Per-user filtered replicas with WAL (S3, oxkv manifest)** — the WAL lives as `wal:{seq:020}` plus `wal:seq` inside an `OxKvStore`. Each user owns one replica prefix (`{db}/u/{sha256-hex(sub)}/`). That prefix holds their filtered file set, with its own oxkv `manifest.json`. Only oxkv writes and parses that manifest. This server probes it for existence and streams its bytes to the client. See [The manifest a client reads](#the-manifest-a-client-reads). `GET /sync/status` reports the pointer (`prefix`, `applied_seq`, `head`) with an `ETag`, and repeat polls get `304`. That route never builds. Every object inside the prefix is individually cached at `GET /sync/db/{object}`, with backend `ETag` passthrough and `If-None-Match` support. The route serves the three names that oxkv rewrites under one name (`manifest.json`, `ownership.json`, `probe/canary`) with `no-cache`. It serves the append-only and content-addressed classes around them (`e{epoch}/sst/*`, `e{epoch}/wal/*`, `e{epoch}/blob/*`). It serves those classes with `public, max-age=31536000, immutable`, because oxkv never writes different bytes under one name of those three classes. See [The manifest a client reads](#the-manifest-a-client-reads). `POST /sync/sync` short-circuits when coverage already meets the WAL head. Deltas of ≤1000 file or relation ops replay onto the live prefix inline, in milliseconds, so the caller gets the result in the same response. Legacy marks, larger deltas, or a never-built replica need a full recalc and are **queued**. The response then carries `pending: true` and coverage from before the rebuild. Clients keep polling `GET /sync/status` until `pending` is false. Concurrent advances for one subject collapse into a single build, and different subjects do not block each other.
- **Single-writer enforcement** — the server claims a lease on `[database].prefix` before it opens any store. It refuses to start if another live process holds the lease. The holder renews at a third of the TTL and releases on clean shutdown. It reports `/ready` 503 if a successor ever takes over. See [Single-writer enforcement](#single-writer-enforcement).
- **WAL-instrumented mutations** — `FsEngine` (complete/attach/detach/delete) and `PolicyEngine` (rule/group changes, including `policy import`) append to one shared `Wal` after each mutation commits. The design is fail-closed: a logging failure fails the whole operation, so the WAL never silently misses a write. Concurrent appends serialize on a mutex that all handles share. Engines without a wired WAL log nothing (tests).
- **Transactional replica builds** — snapshots filter into a scratch store and diff against the live replica as a streaming merge-join. They commit the diff plus the coverage marker in one transaction. A crash before the commit leaves the old state untouched, because oxkv replays only listed WALs on open. An empty diff commits nothing. The engine handles mid-broken writes, not app scaffolding. The diff holds one key per side, not the replica. See [Per-user replicas](#per-user-replicas-wal).
- **Modular composition** — implement the `ApiModule` trait and register it on `ApiService`. The code applies JWT auth middleware per module scope. Global middleware covers bearer-token extraction and request tracing.
- **Observability** — structured console logging through the `tracing` facade (`RUST_LOG` syntax). Optional OpenTelemetry span and metric export runs over OTLP. It uses gRPC with the `otlp-grpc` feature and HTTP with the default `otlp-http` feature. W3C Trace Context propagation travels with both.

## API endpoints

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/health` | Liveness probe | none |
| GET | `/ready` | Readiness probe (policy lock, writer lease, primary fencing) — wire it to a real probe, see [Readiness](#readiness) | none |
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
| GET | `/fs/files/{id}` | Download file content (owner or row Read. `Range` → `206`/`416`) | Bearer token |
| DELETE | `/fs/files/{id}` | Delete file (owner when temp, or row Delete) | Bearer token |
| GET | `/sync/status` | Replica pointer + coverage ETag (`prefix`, `applied_seq`, `head`. Never builds) | Bearer token |
| POST | `/sync/sync` | Advance replica toward WAL head (short-circuit, replay, or full recalc) | Bearer token |
| GET | `/sync/db/{object}` | One replica object (manifest/SST/WAL) with ETag + `If-None-Match` | Bearer token |
| GET | `/openapi.json` | Generated OpenAPI 3.1 document (served from `src/docs.rs`) | none |
| GET | `/swagger-ui/` | Swagger UI for the spec above | none |

Protected routes accept either an explicit `Authorization: Bearer <token>` header (preferred) or the session cookie set by `/auth/callback`. Requests without valid credentials get `401`. Insufficient permissions get `403`. `/policy/*` additionally requires Casbin permissions (`rules` + `read`/`write` for rule endpoints, `user_groups` + `read`/`write` for group/user endpoints). A merely valid token is not enough. `/setup/admin` requires a valid JWT but performs no policy evaluation (one-time bootstrap). Errors use a `{"error": "<message>"}` envelope with a stable, non-sensitive message per status (`"forbidden"`, `"not found"`, `"internal server error"`, …). The server logs server-side causes and never serializes them. Two deliberate exceptions use their own bodies. `/auth/callback` returns an `AuthResponse` envelope (`success`/`token`/`error`) because the SPA reads the token from it. The OpenAPI and Swagger routes return spec documents.

Every served route is in the OpenAPI spec. `src/docs.rs` (`/openapi.json` + `/swagger-ui/`) covers `/health`, `/ready`, `/auth/*`, `/setup/admin`, `/fs/*`, `/policy/*`, and `/sync/*`. Generate the SPA client from that document instead of hand-writing fetch shapes. `spec_covers_all_served_routes` fails the build if a module adds a route without adding it to the spec. Each module's own test asserts the reverse: every path the spec lists for it is actually mounted (`fs::route::tests::every_documented_route_is_mounted`). A service left out of a `configure` chain used to be invisible. It compiles, the spec still lists the path, and the only symptom is a `404` on a documented endpoint.

Errors render as `{"error": "<stable message>"}` from a single construction site (`http::error::ApiError::envelope`). That site also handles a body that fails to parse. Actix's own JSON-extractor failure is a bare `400` in `text/plain`, so `http::apply_limits` installs an error handler that answers inside the envelope. The extractor's message names the offending field. The server logs that message and never sends it. The only responses outside the envelope are `/auth/callback`'s browser redirects, `/openapi.json`, and `/swagger-ui/*`. None of them are API errors.

### First-run bootstrap

A fresh deployment boots with an empty policy store, so nobody can pass self-authorization on `/policy` routes yet. Log in through `/auth/login`, then call `POST /setup/admin` **once** with your token. The first authenticated subject to do so becomes `superadmin` (`201`). Every later call returns `409`, including after restarts. From there, grant permissions to groups and manage membership via the normal policy endpoints.

### Browser clients (SPA/PWA)

Cross-origin SPAs set `[http].allowed_origins` (or `RUST_API_ALLOWED_ORIGINS`) to their origin(s). Credentials are always allowed. The auth flow runs `GET /auth/login` → provider → `/auth/callback`, which sets the `auth_token` cookie and returns the token. The flow continues with `GET /auth/me` as the guard and session probe, then with `POST /auth/logout` to clear the cookie. Poll `GET /sync/status` (coverage `ETag`, `304` on repeat) and advance with `POST /sync/sync`. Then read replica objects via `GET /sync/db/{object}`. The three names oxkv rewrites under one name (`manifest.json`, `ownership.json`, `probe/canary`) carry `no-cache`. The append-only and content-addressed objects are immutable. The manifest's `sst` entries arrive in recency order, and a client must not sort them. See [The manifest a client reads](#the-manifest-a-client-reads). The server streams replica objects with a declared `Content-Length` instead of buffering them. Therefore, a multi-hundred-megabyte SST segment does not have to fit in the heap once per in-flight request. Generate the client from `/openapi.json`. That document covers every route.

## Generating a client SDK

The server publishes an OpenAPI 3.1 document at `/openapi.json` (Swagger UI at `/swagger-ui/`). Generate a typed client from that document instead of hand-writing request shapes. Re-run generation whenever the spec changes; `spec_covers_all_served_routes` keeps the document in sync with mounted routes.

### openapi-generator

```bash
# TypeScript (fetch-based)
npx @openapitools/openapi-generator-cli generate \
  -i http://localhost:8080/openapi.json \
  -g typescript-fetch \
  -o ./generated/typescript-client

# Rust
npx @openapitools/openapi-generator-cli generate \
  -i http://localhost:8080/openapi.json \
  -g rust \
  -o ./generated/rust-client
```

### progenitor (Rust)

```bash
cargo install cargo-progenitor
curl -s http://localhost:8080/openapi.json -o openapi.json
cargo progenitor -i openapi.json -o rust-api-client -n rust-api-client -v 0.1.0
```

Or use progenitor's `generate_api!` macro or `build.rs` flow for in-crate generation.

Set the client's base URL to the server's public address and add an `Authorization: Bearer <token>` header (or the session cookie from `/auth/callback`) to protected calls. See `examples/` for checked-in generation scripts and generated-client usage.
## Frontend / SPA example

Minimal integration flow for a browser SPA. The server must list the SPA origin in `[http].allowed_origins` (or `RUST_API_ALLOWED_ORIGINS`) for cross-origin calls; credentials are always allowed.

1. **Login redirect.** Send the user to `GET /auth/login`. The identity provider redirects back to `/auth/callback`, which sets the `auth_token` cookie and returns the token in the response body. Keep the token in memory and attach it as `Authorization: Bearer <token>` on later calls, or rely on the cookie for same-origin requests.

2. **Guard routes with `/auth/me`.** On app load and before every protected route, call `GET /auth/me`. A `200` response means the session is valid and returns `sub`, `iss`, `aud`, and `exp`. A `401` means redirect to login. Use `exp` to refresh proactively.

3. **Poll sync status.** Call `GET /sync/status` with `If-None-Match` set to the last `ETag`. A `304` means nothing changed. A `200` returns `prefix`, `applied_seq`, `head`, and a new `ETag`. This route never builds a replica.

4. **Advance the replica.** When `applied_seq < head`, call `POST /sync/sync`. A short replay returns `200` with the advanced `applied_seq`. A full rebuild returns `200` with `pending: true` and the coverage from before the rebuild. Keep polling `GET /sync/status` until `pending` is false.

5. **Read replica objects.** For each object the manifest lists, call `GET /sync/db/{object}` with `If-None-Match`. The three names oxkv rewrites under one name (`manifest.json`, `ownership.json`, `probe/canary`) carry `no-cache`. Every other object is immutable for a year. Do not sort the manifest's `sst` entries.

6. **Download a file.** Call `GET /fs/files/{id}` with the bearer token. The route supports `Range` and returns `206` or `416`. Call `GET /fs/files/{id}/meta` first when metadata is needed.

Example (TypeScript, using `fetch`):

```ts
const base = "https://api.example.com";

// 1. Login redirect (browser navigation, not fetch)
window.location.href = `${base}/auth/login`;

// 2. Guard
const me = await fetch(`${base}/auth/me`, {
  headers: { Authorization: `Bearer ${token}` },
  credentials: "include",
});
if (!me.ok) window.location.href = `${base}/auth/login`;
const session = await me.json(); // { sub, iss, aud, exp }

// 3. Poll sync status
let etag = "";
const statusRes = await fetch(`${base}/sync/status`, {
  headers: { "If-None-Match": etag, Authorization: `Bearer ${token}` },
});
if (statusRes.status !== 304) {
  const status = await statusRes.json(); // { prefix, applied_seq, head }
  etag = statusRes.headers.get("ETag") ?? "";

  // 4. Advance the replica
  if (status.applied_seq < status.head) {
    const syncRes = await fetch(`${base}/sync/sync`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const sync = await syncRes.json(); // { applied_seq, pending? }
    // poll GET /sync/status until pending is false
  }
}

// 5. Read a replica object
const manifestRes = await fetch(`${base}/sync/db/manifest.json`, {
  headers: { "If-None-Match": etag, Authorization: `Bearer ${token}` },
});

// 6. Download a file
const fileRes = await fetch(`${base}/fs/files/${fileId}`, {
  headers: { Authorization: `Bearer ${token}`, Range: "bytes=0-1023" },
});
```

Generate the typed client from `/openapi.json` instead of hand-writing these shapes. That document covers every route.

## Architecture

```
src/
├── main.rs              binary entry point: config → telemetry → OIDC/policy/fs/sync wiring → listener
├── lib.rs               crate root and documentation
├── config.rs            TOML configuration model ([database].prefix + mirror_master, [s3], [observability], [capability], [http].allowed_origins + RUST_API_ALLOWED_ORIGINS, [limits]; binary-private `mod config`)
├── limits.rs           cost controls: per-peer token bucket + concurrency gate for /sync/db downloads
├── db.rs                OxKV store factory — one AmazonS3Builder for file bytes + OxKvStore; build_s3_store / build_object_store / build_scratch_store / default_sst_cache; single-live-handle-per-prefix contract (the test-only builders build_test_store* / test_prefix are `#[cfg(test)]`, not API)
├── lease.rs             single-writer lease on [database].prefix (startup refusal + renewal + release)
├── fencing.rs           process-wide latch for a fenced *primary* prefix; gates /ready alongside the lease
├── telemetry.rs         tracing subscriber + OTLP span/metric export bootstrap (otlp-grpc / otlp-http features)
├── docs.rs              utoipa OpenAPI `ApiDoc` (all routes; served via http/docs.rs as /openapi.json + /swagger-ui/)
├── records.rs           shared change-feed vocabulary — FileRecord, WalOp/WalEntry, ChangeSink/ChangeError; the leaf that breaks the fs↔sync cycle (see Layering)
├── http/                HTTP scaffolding shared by all modules
│   ├── mod.rs           ApiService registry + ApiModule trait (declared route prefix, duplicate-prefix check) + CORS builder
│   ├── error.rs         ApiError enum and uniform JSON error envelope
│   ├── health.rs        /health + /ready (readiness: policy lock + writer lease + primary fencing)
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
│   ├── snapshot.rs      SnapshotManager — one filtered replica per user ({db}/u/{sha256-hex(sub)} + sync:applied marker), tx-atomic streaming rebuilds, idempotent replay, per-subject BuildQueue
│   └── route.rs         GET /sync/status (pointer + ETag, no build) + POST /sync/sync (advance) + GET /sync/db/{object} (segments + ETags)
└── fs/                  Object-store file storage (AmazonS3/MinIO/R2 via object_store, InMemory for tests)
    ├── mod.rs           FsEngine (temp per-user, row delegation, token mint/verify)
    ├── model.rs         request/response DTOs (InitRequest, CompleteRequest, FileMetadata, ...)
    ├── error.rs         FsError mapping to ApiError
    ├── relation.rs      RefInfo + fs:rel:{type}:{id}:{file} + fs:files:{id}:refs
    ├── token.rs         FsClaims HMAC JWT (5m)
    ├── store.rs         FsStore on OxKvStore (fs:uploads:{id}:meta, fs:files:{id}:meta, staged parts, fs:mp:{upload_id} persisted multipart)
    ├── gc.rs            hourly sweep, two separate scopes: sessions + orphaned files (refs==0, 24h TTL) + orphaned files/ bytes, and a store-level pass over oxkv WAL objects (unlisted e*/wal/*.log) under the store prefix
    ├── s3.rs            S3Client trait + S3ClientConfig (+ backend_upload_id/restore_multipart for restart resume)
    ├── object_store.rs  ObjectStoreClient + shared s3_builder() for OxKvStore + file bytes (propagates abort errors; GC retains session on failure)
    └── route.rs         /fs/uploads/* and /fs/files/* handlers
```

Modules implement [`ApiModule`](src/http/mod.rs) and register on `ApiService`. Each module brings its own middleware stack (e.g. `/policy/*` requires validated JWT claims).

## How authorization works

The Casbin RBAC model is:

```ini
p = sub, obj, act        # permission rule: subject may act on object
g = _, _                 # group membership: user belongs to group
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

The Casbin RBAC model authorizes a request when its subject either holds a matching `p`-rule directly or belongs to a group (`g`-link) that does. A typical setup grants permissions to *groups* via `POST /policy/rules`, then manages membership via the `/policy/groups` endpoints.

Rules persist to a prefix-scoped [`oxkv::OxKvStore`](https://docs.rs/oxkv) under `{database.prefix}/policy` inside the configured S3 bucket (one `ObjectStore` + one `AmazonS3Builder` shared with the file-byte store via `db::build_s3_store` / `fs::object_store::s3_builder`). Each rule is one key-value pair (`{sec}:{ptype}:{hash}` → JSON array) written transactionally. `adapter::encode_rule` and `PolicyRuleValidator` enforce validation on every write path. Wrong-arity rules, non-JSON payloads, and unknown sections fail before any transaction opens. The adapter validates directly instead of requiring callers to wrap their store in a `HookStore`.

> **Single-live-handle-per-prefix:** each `OxKvStore` owns a fresh fencing session (memtable/WAL buffer). Two live handles on the same prefix can fence each other or diverge on real S3. Share the handle via `Arc`. Do not build a second one. This crate's own tests use a fresh `InMemory` per prefix. For single-threaded reopen they use a new session over the same `InMemory`, and the new session supersedes the previous one. Exception: the `policy export` / `policy import` CLI subcommands open a short-lived second handle on `{prefix}/policy` (and `{prefix}/wal` for import). Never run them concurrently with a live server on the same prefix.

### Single-writer enforcement

`oxkv` acquires a prefix by CAS-bumping `ownership.json`. Last writer wins, and the loser gets fenced at write time (`StoreError::Fenced`, which oxkv documents as "the current process must stop writing and restart"). That makes a correct *takeover* protocol and a useless *detection* protocol. Nothing in it distinguishes "my predecessor is still serving traffic" from "my predecessor crashed". A second replica pointed at the same prefix would start cleanly, serve writes that silently diverge, and only fail later and elsewhere.

So the server claims an explicit **writer lease** (`src/lease.rs`) on `{prefix}/_rust-api-writer-lease.json`. The lease covers every prefix-scoped store: `policy`, `fs`, `wal`, and each per-user replica. The server claims it *before* it opens any store, because opening a store is what takes the epoch.

| Situation | Behavior |
|---|---|
| Second process starts, lease live | **Refuses to start**, naming the holder, its pid, and how long until the lease goes stale |
| Predecessor crashed | The lease goes stale after `writer_lease_ttl_secs`. The next start takes over automatically and logs who it displaced |
| Predecessor stalls past the TTL | The successor takes over. The predecessor notices on its next renewal, logs an error, and `/ready` turns **503** so the orchestrator drains it |
| Orderly shutdown | The server releases the lease, so a rolling restart hands over without waiting out the TTL |
| Record unparseable | Refused, never overwritten — guessing the owner is the failure this exists to prevent |

The lease only sees writers that take it. `src/fencing.rs` covers the uncooperative case. Suppose a primary prefix (`{db}/fs`, `{db}/policy`, `{db}/wal`) gets fenced anyway, through an older build, a `writer_lease_ttl_secs = 0` deployment, or an operator running `policy import` against a live prefix. The loss latches a process-wide signal that `/ready` also reports. The log then gets one `error` line that names the prefix. Every subsequent write on that handle fails the same way. Only the first failure logs at `error`, and the repeats drop to `debug`.

A **replica** fencing loss deliberately does not latch. Losing a build race is routine, and `sync` resolves it by adopting the winner's coverage. `FsStore` therefore carries an explicit primary mark (`FsStore::primary` vs `FsStore::new`) that decides whether a failure is terminal. `sync`'s replica stores are never marked. A latch in the shared `oxkv::StoreError → FsError` conversion would have pulled a healthy server out of rotation every time two workers raced to build one user's replica.

The process does **not** exit on a fencing loss. It is already read-only, so it can no longer diverge. Exiting immediately would mean zero healthy writers whenever the successor is not serving yet. Marking the instance unready instead drains it through the load balancer. That leaves the restart to an operator who has the log line saying the handle is terminal.

The lease cannot stop a network partition from splitting the prefix. Nothing lease-based can. What the lease buys is that the losing side *finds out* and stops taking traffic, instead of discovering the split through corrupted data.

> **Set `writer_lease_ttl_secs = 0` only where exactly one process can ever reach the bucket** (a laptop, a single container). It disables enforcement and logs a warning at startup. Otherwise the TTL must exceed your worst-case pause between renewals, such as a long GC pause or a slow S3 round trip. Otherwise a healthy process gets displaced by its own peer. Renewal runs at a third of the TTL, so two consecutive missed renewals still leave a full TTL of headroom.

`/ready` reports 503 when the server loses the lease **or** a primary prefix gets fenced (see below). That behavior composes with an existing readiness probe instead of requiring a new one.

### Fencing losses are typed, not string-matched

A store whose epoch was lost surfaces as `FsError::Fenced`. The code classifies that error in one place, `From<oxkv::StoreError>`, and detects it with `FsError::is_fencing_loss()`. The code used to run a `detail.contains("fenced")` search on the flattened store message. Any rewording in `oxkv` would then have silently turned the recoverable path in `POST /sync/sync` (adopt the concurrent builder's coverage) into a 500 for every client.

Keeping that correct means every `oxkv::StoreError` → `FsError` conversion has to route through `From`. That includes the private `store_err` helpers in `fs::store` and `sync::snapshot`, which are one-liners for exactly that reason. The reason string is operator-facing. The code logs it at `error` level, because a lost epoch is terminal for that handle and not a blip. The code never serializes it.

Policy writes reach the store through casbin, whose `Adapter` trait uses `casbin::Error`. There the `oxkv::StoreError` arrives boxed inside `AdapterError`, so the code has to redo the classification at the boundary. `From<casbin::Error> for PolicyError` downcasts that box and lifts the epoch loss into `PolicyError::Fenced`, which `PolicyError::is_fencing_loss()` detects. Without it, a stale writer's policy write produced

```text
Casbin(AdapterError(AdapterError(Fenced("epoch 7 superseded"))))
```

— a 500 indistinguishable from any other store failure, on the same prefix and the same condition `FsError::Fenced` already reports. `PolicyError::Fenced` deliberately renders the same text as `FsError::Fenced` ("store epoch lost to another writer …"). One log query then finds a fencing loss on either store, and the client still only ever sees `{"error":"internal server error"}`. The test `policy::adapter::tests::a_fenced_policy_write_is_typed_as_a_fencing_loss` drives this through a real casbin enforcer over a store whose `commit` reports a lost epoch. It also pins the assumption that casbin preserves the box rather than flattening it to a string.

### Row-level and file delegation

Business rows authorize as `{row_type}:{row_id}` via `RowAuthorizer` (`policy/row.rs`). Files are not gated by a coarse `fs` object. Instead:

- `POST /fs/uploads` creates a temp file owned by `owner_sub` (`refs==0`) in the `{prefix}/fs` `OxKvStore` (`fs:uploads:{id}:meta`, staged parts `fs:uploads:{id}:part:{idx}`, durable `fs:mp:{upload_id}` multipart record for multipart uploads). Part intake is stream-capped at the expected part size (oversize → `413`, declared-length mismatch → `400` before reading).

**Upload size limits.** The server validates `InitRequest` against the same constraints as the worker-side `Schema.filter`, plus S3's per-upload part cap:

| Field | Constraint |
|---|---|
| `file_total_parts` | 1 for a single-part upload, else 1–10,000 (S3's hard limit) |
| `part_size` | a multiple of 1 KiB, ≤ 512 KiB |
| single-part `file_size` | ≤ 10 MiB, and must equal `part_size` |
| multipart `file_size` | must equal `file_total_parts × part_size` exactly |
| **resulting multipart ceiling** | **10,000 × 512 KiB ≈ 4.9 GiB** |

The part cap applies at `init`, not at `complete`. A client therefore learns its split is illegal before it uploads anything, not after. The cap also bounds the per-session `etags`/`checksums` vectors that the engine allocates from the declared count. Files larger than ~4.9 GiB need a larger `part_size` cap or a different upload strategy.
- `FsEngine::attach(row_type,row_id,file_id,caller)` requires `Write` on `{row_type}:{row_id}` and increments `fs:files:{id}:refs` + writes `fs:rel:{type}:{id}:{file}`.
- `FsEngine::detach` decrements and sets `orphan_since` when `refs==0`.
- Reads and deletes validate `owner_sub == caller` for a temp file, or require any owning row to grant `Read`/`Delete`. Editing a row runs `detach(old)+create new+attach(new)`. The old S3 object then becomes an orphan, and GC removes it after 24h.
- `FsEngine::mint_token` and `verify_token` (`fs/token.rs`) implement short-lived HMAC delegation without extra policy hits. No `/fs/*` route consumes them today, so keep using the OIDC JWT for file operations. **Decision: keep capability tokens as an engine API (`mint`/`verify`) for direct `PUT`/`GET` delegation; the routes continue to use the OIDC JWT today; there is no removal.** Wiring the routes to consume capability tokens is tracked separately. File bytes live in S3 via `object_store` (`AmazonS3` in production, `InMemory` in tests). Multipart state survives restarts through the `fs:mp:{upload_id}` record (`restore_multipart` before `upload_part`/`complete`/`cancel`/GC. Sessions that predate the record fail with a restart-this-upload `400`). Cancel and GC abort S3 first and retain the session on failure, so the next sweep retries instead of leaking staged bytes.

### Capability tokens (decision)

Capability tokens remain in the crate as an engine API. `FsEngine::mint_token` and `verify_token` mint and verify a short-lived HMAC JWT for direct `PUT`/`GET` delegation after row authorization, with no extra policy hits. The `/fs/*` routes continue to authenticate with the OIDC JWT (`claims.sub` + `can_access`) today and do not consume capability tokens. This is a deliberate decision, not a removal: the engine API stays available for callers that want direct delegation, and no code is deleted. Wiring the routes to consume capability tokens, and any client changes that follow, is tracked separately.

### Garbage collection

The sweeper runs hourly (`fs::gc::spawn`, `sweep_once`) and reclaims objects in **two separate scopes**. Each pass names one scope and ignores the other. The two scopes hold different objects and never look at the same one.

| | Application byte scope | Store-internal scope |
|---|---|---|
| What it reaps | objects under `files/{id}` — file bytes | oxkv WAL objects under this store's own oxkv prefix, key shape `e{6 digits}/wal/{8 digits}.log` (six or more epoch digits) |
| How it decides | a `files/` listing names the object, no session row and no file row references it, and it is older than the 24h TTL | the key has the exact WAL shape **and** the manifest does not list it. A failed manifest compare-and-swap strands one |
| Extra requirement | needs a **complete** decode of both metadata scans. If any row fails to decode, the code skips the whole pass. Leaking bytes beats deleting a live file | needs no metadata row of this crate, and reads none |
| Call | `engine.s3.list_keys(…,"files/")` + `delete_object`, inside `fs::gc` | `FsStore::gc_wal_orphans` → `oxkv::OxKvStore::gc_orphans`, inside `fs::gc` |
| Failure handling | a failed delete retains the item for the next sweep and does not abort the sweep | a failed `LIST`/`DELETE` only shortens the pass, and a later hourly sweep continues. A **fenced store returns `Ok(0)` and deletes nothing**, because `gc_orphans` re-validates ownership before it deletes. For a window, the manifest names no current owner's in-flight WAL, and a stale handle would delete a live write |

The two are complementary, not replacements. The store pass reclaims what oxkv itself orphaned inside the store's prefix. The byte pass answers a question the store pass cannot: whether an application key is still referenced. That question is why the byte pass needs a complete metadata scan first.

Two operational consequences:

- **Counts.** `sweep_once` returns the number of *application* items that it removed. The store pass does not add to that number. It logs its own count (`fs gc reclaimed {n} orphaned store WAL objects`) and swallows errors as a `warn` (`fs gc skipping store WAL orphan pass: {e}`), because it deletes only unreachable objects and a failure costs storage, not data.
- **Handle discipline.** The store pass runs on the handle the engine already holds (`FsStore::gc_wal_orphans` takes `self.inner.read()`). It must not open a second handle on the same prefix. A second handle takes a new session and can fence the first one on real S3. `oxkv` takes its own writer gate inside `gc_orphans`, and that gate serializes the pass against every oxkv write on that handle.

### Per-user replicas (WAL)

The master `FsStore` and `Wal` both live on prefix-scoped `OxKvStore`s and remain the sole write path. `Wal` appends `wal:{seq:020}` entries plus a `wal:seq` head. The op vocabulary (`WalOp::{PolicyRuleAdd/Remove,GroupAdd/Remove/Delete,Attach,Detach,FileCreate,FileDelete}` plus legacy `PolicyAdd/Remove` marks) and the `FileRecord` it carries live in `src/records.rs`, not in `sync/`. See [Layering](#layering). Each user owns one replica prefix (`{db}/u/{sha256-hex(sub)}/`) that holds their filtered file set, with its own oxkv `manifest.json`. That manifest lists the SST and WAL files, and only oxkv writes and parses it. See [The manifest a client reads](#the-manifest-a-client-reads). A build filters through `RowAuthorizer`/`owner==sub` into a scratch store. It diffs against the live replica. It commits the diff plus the `sync:applied` coverage marker in a single transaction. A crash before the commit then leaves the old state untouched, and an empty diff commits nothing at all. The diff is a **merge-join of two key-ordered paged walks** (`fs::store::KvPages`), not a comparison of two collections. Construction orders both sides, so the rebuild holds one key per side instead of a map of the whole replica. That keeps a full rebuild's peak memory independent of how much data the user can see. What still scales with the size of a *change* is the single commit transaction, which is normally far smaller. That is why the crate rejected committing in chunks, which would have capped it too, because chunks would give up the all-or-nothing crash behaviour above. Replica prefixes hash the subject (`SHA-256 hex`), so attacker-influenced OIDC `sub` values cannot traverse or collide. `GET /sync/status` returns the replica pointer with a coverage `ETag`. Repeat polls get `304` without touching storage beyond the marker read, and that route never builds. `POST /sync/sync` advances the pointer. `GET /sync/db/{object}` serves one replica object with backend `ETag` passthrough and `If-None-Match` support. The append-only and content-addressed engine files are immutable by construction (`Cache-Control: public, max-age=31536000, immutable`). That stays sound under 0.9, because oxkv never writes different bytes under one SST, WAL, or blob name. The route instead revalidates the three names it rewrites under one name (`manifest.json`, `ownership.json`, `probe/canary`) with `Cache-Control: no-cache`. Replicas hold filtered file and relation metadata. File bytes stay in S3.

Every master mutation is also announced to the shared change feed (`{db}/wal`). `FsEngine` announces file creates, file deletes, and attach and detach operations. `PolicyEngine` announces rich rule and group changes, including `policy import`. Each announcement follows the mutation commit. A logging failure fails the whole operation, and concurrent appends serialize on a mutex that all engine handles share. `POST /sync/sync` short-circuits when coverage already meets the WAL head. Otherwise the code replays deltas of ≤1000 ops onto the live prefix. The code re-applies file and relation ops with visibility re-validated. It resyncs rule and group ops for only the affected user or row. It skips irrelevant users and objects. It writes the marker last, so a crash heals on the next poll. Legacy policy marks, oversized fan-out, larger deltas, and fencing losses all fall back to a full recalc. They also fall back to adopting the winner's coverage on a lost build race. The crate needs no version GC. The server maintains only one prefix per user, and oxkv's own WAL GC and compaction maintain it.

### The manifest a client reads

A client implementer reading `GET /sync/db/manifest.json` needs three facts about that manifest and about the objects beside it, and this server enforces none of them.

**1. Entry order is recency, and it is load-bearing.** The `sst` array lists entries **oldest first**. oxkv 0.9 documents this on `SstMeta`: "Entries are listed oldest first. Every read path walks the list in reverse and stops at the first hit. The list position *is* the recency. `seq` makes that position recoverable. Sorting by key range destroys it." Every read path (`point_lookup`, `scan_manifest`) iterates `manifest.sst.iter().rev()`. `point_lookup` stops at the first segment that holds the key. `scan_manifest` merges every overlapping segment in that newest-first order. Compaction re-sorts the list by the new `SstMeta::seq` field, with the comment "Oldest-first by write sequence, never by key range."

So a client may assume:

- the array arrives in the order oxkv wrote it, oldest first, not sorted by `minKey`/`maxKey` and not sorted by `id`.
- within one key, the **last** entry whose key range covers the key holds the newest record.
- a reverse walk stops at the first segment that holds the key, so an entry that only overlaps the range does not win.
- that newest record can be a tombstone, and a tombstone means the key does not exist.
- a record newer than every segment entry is not in this array at all.
- a reader replays the `wal` list into an overlay and reads that overlay first, so the `sst` array alone never yields the current value.
- `seq` (`#[serde(default)]`, so a manifest written before 0.9 decodes with `seq = 0` on every entry) is the recoverable form of the same ordering.

And a client must **never sort, reorder, filter, deduplicate, or rewrite `sst` entries**. The client must do none of this by key range, by `seq`, or by any other key. Reordering destroys the recency that the engine relies on. A client that reorders and then reads by position resolves overlapping keys to the wrong segment. Copying `sst` verbatim into a local engine is fine. Rearranging it is not. A copy that keeps only `sst` is not enough, because it drops every record that has not reached a segment yet. This is a **client obligation, not a server guarantee**. This server streams the bytes through unchanged and never validates the entries it serves.

**2. Three names in a replica prefix change under one name.**
The engine writes six classes into a replica prefix: `manifest.json`, `ownership.json`, `probe/canary`, and the append-only or content-addressed classes `e{epoch}/sst/*`, `e{epoch}/wal/*`, and `e{epoch}/blob/*`. The first three names each carry different bytes at different times. The route compares the resolved object key against a list of exactly those three names. It serves a matching object with `Cache-Control: no-cache`. It serves every other object of the prefix with `Cache-Control: public, max-age=31536000, immutable`. The rule matches those three keys only. A key that merely ends in one of those names is not mutable.

Each mutable name changes for its own reason:

- `manifest.json` changes on every writer CAS, because the manifest is the single consistent point of the store.
- `ownership.json` changes on every writer build. `acquire_ownership` reads the record and writes it back with `epoch + 1` under a compare-and-set. This server opens a fresh writer on the replica prefix for every build and every replay, so the epoch moves each time.
- `probe/canary` changes while a probe runs. `probe_store` writes the name once with `PutMode::Create` and again with `PutMode::Update`, and the two puts carry different bytes. The probe deletes the object when it ends, so a reader normally gets a `404` and sees it only during a build or replay.

The other three classes never carry different bytes under one name. `store.rs` refuses to overwrite an SST sequence that holds other bytes, and it refuses the same for a WAL sequence. A blob object takes its name from the SHA-256 of its value. A client may cache only these three classes for a year.

A client must revalidate each of the three mutable names, and it must not keep any of them beyond the response it holds. Every response carries the backend `ETag`, so `If-None-Match` is the cheap revalidation for all three. A client that stores an ownership record or a probe canary under a one-year policy pins itself to bytes that the next build replaces.

**3. A long-lived reader is no longer pinned, and that obligation moved to the client.**
oxkv 0.9 removed `OxKvStore::{register_reader, unregister_reader, min_reader_version}`, the trio that kept SSTs alive for in-flight readers. `OxKvReader` is now a live view of the prefix, not a snapshot pinned at open time. Instead, 0.9 protects reader-visible data by ordering. `maintain_wal` refuses to GC a WAL unless the force-flush that SST-covers it succeeded, and a vanished listed WAL counts as SST-covered. It also protects that data with one retry against a fresh manifest on `not found` (`retry_once_not_found`). That retry is the same correction 0.7 spelled out at each call site, not a new guarantee.

A client that relied on the reader pin to hold a stable view must change. That is an **obligation, not a guarantee the server can restore**. The client must either re-open the `OxKvReader` (or re-read the manifest) whenever it needs a view consistent with a moment in time. Otherwise, the client must snapshot the keys it needs itself. Holding one reader open across a build no longer keeps an old view alive. The reason is that a compaction or WAL GC can retire segments underneath it. This crate's own server-side readers (`snapshot::open_reader`) already open per call and read a single key, so they never depended on the pin. A long-lived client reader will.

### Rebuild scheduling

A full replica rebuild scans the whole master, so it is not work to do inside a request. `POST /sync/sync` runs bounded incremental replays inline and **queues** everything else, returning the coverage the replica had plus `pending: true`.

```text
POST /sync/sync ──┬─ already covered?      → 200, applied_seq = coverage
                  ├─ replay succeeds?      → 200, applied_seq = advanced
                  └─ needs full rebuild ───→ queue, 200, pending: true
                                              └─ BuildPool::spawn → build_full
GET /sync/status  ← poll until pending clears
```

Two properties do the real work, and tests cover both:

- **Coalescing.** The in-flight set holds subjects. So the many `POST /sync/sync` calls that a client poll loop produces for one pending rebuild collapse to a single scan. This used to be worse than a thundering herd. The guard was a process-wide `Mutex<()>` that both `replay` and `build_full` held, so those scans ran *one at a time*, each queued behind the last.
- **Per-subject isolation.** Replicas are separate S3 prefixes, so the guard only ever needed to be per subject. The old global lock also meant a full rebuild for one user blocked a few-millisecond replay for a different user. The fast path sat behind the slow path's lock.

The queue is **in-process and not durable**, deliberately. `sync:applied` in the replica prefix already acts as the durable record of coverage, so a queued job lost to a restart costs nothing. The client's next poll sees `applied_seq < head` and queues another job. That is why the crate needs no queue store, no ack, and no retry policy.

A host app that mounts `/sync` **must** call `BuildPool::spawn`, the same way it must call `fs::gc::spawn`. A manager with no pool draining it reports `pending` forever. The code logs that mistake at `error` instead of leaving a client to discover it by polling:

```rust
let (builds, build_jobs) = rust_api::sync::snapshot::BuildQueue::new();
let manager = SnapshotManager::new(
    SnapshotDeps { wal, store, policy: engine.authorizer(), object_store, builds },
    db_prefix,
    ReplicaBackend::ObjectStore,
);
rust_api::sync::snapshot::BuildPool::new(build_jobs).spawn(Arc::new(manager.clone()), 2);
```

The worker count stays small on purpose. A build's memory now tracks the size of a *change* instead of the size of a replica. A build still scans the master and writes to S3, so the count bounds object-store pressure as much as it bounds CPU.

### Layering

`fs` and `policy` *emit* changes, and `sync` *consumes* them. The vocabulary that both sides need, which is `FileRecord`, `WalOp`, and the `ChangeSink` trait, lives in `src/records.rs`. That module depends on nothing else in the crate:

```text
       records
       /     \
  fs, policy   sync
       \     /
   (fs::store, the replica write path)
```

`FsEngine::with_change_sink` and `PolicyEngine::with_change_sink` take `Arc<dyn ChangeSink>`, so neither names `sync` and the graph is a DAG. `sync::wal::Wal` is the durable implementation.

The code enforces this, not just the documentation. `records::tests::producers_do_not_depend_on_the_consumer` fails if any production `use` in `fs/` or `policy/` names `crate::sync`. `this_module_depends_on_nothing_in_the_crate` keeps `records` a leaf. Rust permits module cycles, so nothing else would notice the edge creeping back.

## Configuration

You configure the server with a TOML file. Pass that file with `--config`:

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
                                            # first pass (costs one master key set in RAM; only with single writer).
                                            # The mirror is oxkv's `CachedOxKvStore` with `WarmMode::Lazy`,
                                            # which oxkv 0.9 re-exports only under its `btree` feature — that is
                                            # why `Cargo.toml` requests `btree` explicitly.

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

The server uses a single bucket with prefix-scoped stores. `db::build_s3_store` builds one `AmazonS3` `ObjectStore` from `[s3]` and wraps it with `OxKvStore::builder().with_object_store(...).with_prefix("oxkv/policy")` and similar calls, through the shared `fs::object_store::s3_builder`. Breaking change since `988873c`: the crate removed `[database].path` (the Redb file). Use `[database].prefix` instead. The server no longer reads old `*.redb` files, and it provides no automatic migration. See [Migration from Redb](#migration-from-redb) for the manual steps.

Secrets via environment (win over the file when present and non-empty, for secret managers): `RUST_API_CLIENT_SECRET`, `RUST_API_S3_ACCESS_KEY_ID`, `RUST_API_S3_SECRET_ACCESS_KEY`, `RUST_API_CAPABILITY_SECRET`, `RUST_API_CAPABILITY_SECRET_PREV`, `RUST_API_ALLOWED_ORIGINS` (comma-separated).

## Migration from Redb

Versions before `988873c` kept every domain in one local Redb file named by `[database].path`. The current version removed that key. It stores policy rules, file metadata, the change feed, and per-user replicas as prefix-scoped objects under `[database].prefix` inside the configured S3 bucket. The server does not read old `*.redb` files and provides no automatic migration. Plan the move before you upgrade.

### Old and new configuration

Old shape:

```toml
[database]
path = "/var/lib/rust-api/policy.redb"

[s3]
bucket = "my-bucket"
region = "us-east-1"
```

New shape:

```toml
[database]
prefix = "oxkv"          # default; policy → {prefix}/policy, fs → {prefix}/fs, wal → {prefix}/wal

[s3]
bucket = "my-bucket"
region = "us-east-1"
```

`[s3]` was already required in the old version for file bytes. Only `[database]` changes.

### Manual migration steps

1. **Export policy rules before you upgrade.** Run the old binary against the old store:
   ```bash
   rust-api policy export --store /var/lib/rust-api/policy.redb --out policy-backup.json
   ```
   The export contains every `p` and `g` rule. It does **not** contain file metadata, relations, or the change feed.
2. **Stop the old server.**
3. **Update the configuration** as shown above. Pick a fresh `[database].prefix` (the default `oxkv` is fine) so the new stores start empty.
4. **Start the new server.** It creates empty stores under the new prefix.
5. **Import the policy rules** into the new prefix:
   ```bash
   rust-api policy import --config config.toml --input policy-backup.json
   ```
   The import is idempotent, so re-running it is safe. It appends the imported rules to the WAL, so replicas replay them instead of waiting for a full recalculation.
6. **Re-bootstrap if you have no export.** A fresh prefix has no superadmin. Log in, then call `POST /setup/admin` once with your token. Recreate the rules and group memberships you need.
7. **File metadata does not migrate.** Old file records and relations lived in the Redb file and have no import path. File bytes already in S3 stay in their buckets, but the new server has no metadata for them. Re-upload the files, or accept them as orphans and let the hourly GC remove them after 24 hours.
8. **The change feed starts at zero.** Replicas rebuild from the current master state. No WAL replay covers the old history.
9. **Keep the old files.** Retain `*.redb` and `*.redb.fs` until you verify the new deployment. Remove them only after that.

### No automatic migration

The server does not open, read, or convert old Redb files. There is no flag that turns migration on. Running the new binary against an old `[database].path` key fails at config load, because the key no longer exists. Treat the upgrade as a fresh install of the data plane plus an import of policy rules.

### Re-bootstrapping policy

If you cannot export from the old deployment, re-bootstrap from scratch:

1. Start the new server on an empty prefix.
2. Log in through `/auth/login`.
3. Call `POST /setup/admin` once. The first authenticated subject becomes `superadmin`.
4. Recreate rules with `POST /policy/rules` and group memberships with `POST /policy/groups`.

`policy import` is the faster path when an export exists. `POST /setup/admin` is the only path when one does not. Both paths end with a working policy store; only the import path preserves the old rules.

## Production hardening

The binary ships with **no rate limits enabled by default**. Both `[limits]`
knobs default to `0` (off), because the right number depends on your egress
budget and your clients' poll interval, and this crate cannot know either of
them. A default limit would be a default outage.
Use this checklist before a production deploy:

- [ ] Set `[limits].rate_per_minute` (and `rate_burst`) to a value that
      matches your expected client traffic. `0` leaves every route
      unlimited, including `/auth/login`, which makes an outbound round trip
      to the identity provider, and `/health`, which a load balancer polls.
- [ ] Set `[limits].max_concurrent_downloads`. This is the control that
      matters: `GET /sync/db/{object}` can be a multi-hundred-megabyte SST
      read, and a token bucket does not bound that. A rate limit can still be
      in flight all at once. The gate caps concurrency instead. `0` leaves it
      unlimited.
- [ ] Put a reverse proxy or WAF in front of the binary, with per-IP
      throttling on `/auth/*`, `/setup/*`, and `/policy/*`. Data-plane
      `/fs` and `/sync` reads can stay generous. See the example below.
- [ ] Never expose the binary directly to the internet without that layer
      (or an equivalent ingress).
- [ ] Set `[database].writer_lease_ttl_secs` to a value above your worst-case
      pause between renewals (GC pause, slow S3 round trip). Use `0` only
      where exactly one process can ever reach the bucket.
- [ ] Configure `[capability].secret` (or `RUST_API_CAPABILITY_SECRET`) so
      capability tokens survive a restart; the ephemeral fallback logs a
      warning and invalidates tokens on restart.
- [ ] Wire `GET /ready` to a probe that drains traffic (Kubernetes
      readiness or load-balancer health check).

The routes that need throttling are `/auth/*` (login and callback need no
authentication, and each callback fans out to JWKS + token exchange),
`/setup/*` (one-time bootstrap), and `/policy/*` (every write is Casbin
evaluation work). Data-plane `/fs` and `/sync` reads can stay
generous. Example for nginx:

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

Tune the rates to your IdP latency and admin headcount. The numbers
above assume an interactive login flow, not machine-to-machine token
churn. Never expose the binary directly to the internet without this
(or an equivalent WAF/ingress) layer.

## Running

```bash
# install toolchain (Rust stable via mise)
mise install

cargo run -- serve --config config.toml
```

### Cost limits

`[limits]` bounds the two places where one request's cost is not bounded by the request. **Both default to off (`0`).** A default limit is a default outage. That holds because the right number depends on your egress budget and your clients' poll interval. Neither of those belongs to this crate, so the crate cannot know them.

```toml
[limits]
rate_per_minute = 600          # per peer address; 0 disables
rate_burst = 120               # defaults to rate_per_minute
max_concurrent_downloads = 16  # concurrent GET /sync/db/{object}; 0 disables
```

`max_concurrent_downloads` is the one that matters. A replica prefix holds oxkv's own files, so `GET /sync/db/{object}` can be a multi-hundred-megabyte SST read. **A rate limit does not bound that**, because an allowed rate can still be in flight all at once. The gate caps concurrency instead. The response *body* holds the permit, not the handler. Therefore, a client that opens a read and then stops consuming still occupies its slot until it disconnects. Refusals are `429` inside the uniform error envelope.

`rate_per_minute` is a token bucket per peer address. The code installs it as the outermost middleware, so it also covers the routes that a subject-keyed limiter cannot reach. Those routes include `/auth/login`, which makes an outbound round trip to the identity provider, and `/health`, which a load balancer polls hard. Two limitations deserve naming. Buckets key on **address, not subject**, so clients behind one NAT share a budget. That is a fairness property, not a safety one. The concurrency gate, which is the control that matters, keys on nothing at all. The code also evicts idle buckets after ten minutes, so the map cannot grow with IPv6 rotation.

### Operations

#### Backups and restore

**`policy export` backs up policy rules only.** It writes every `p` and `g` rule in `{db}/policy` to JSON. It does **not** contain file metadata (`{db}/fs`), the change feed (`{db}/wal`), or any file bytes. Treating it as a full backup and restoring from it onto a fresh bucket gives you working authorization and an empty filesystem. That result looks like total data loss rather than like a partial restore.

A real restore is therefore two separate things:

| What | Where it lives | How to restore it |
|---|---|---|
| Policy rules | `{db}/policy` | `rust-api policy import --config … --input backup.json`. The import is idempotent, so re-running it is safe |
| File metadata + relations | `{db}/fs` | Copy the prefix's objects back. Enable S3 bucket versioning and rely on it, or copy prefixes between buckets |
| Change feed | `{db}/wal` | Nothing to restore — it is a replay log, not a source of truth, and a fresh prefix simply replays from zero |
| File bytes | user buckets, outside this server's prefixes | Your own S3 lifecycle rules |

`policy import` opens a second handle on `{db}/policy` and `{db}/wal`, which fences a live server on the same prefix. **Stop the server first** (or run it against a different `[database].prefix`).

There is no automated backup job and no restore drill in this repository. Both are the operator's, and both are worth rehearsing before you need them.

#### Readiness

`GET /ready` returns 503 for any of three independent conditions. A writer holds the policy lock, the server lost the single-writer lease, or a primary prefix got fenced. `/health` is liveness and stays 200.

Wire `/ready` to something that actually acts on it, such as a Kubernetes readiness probe or a load balancer health check. If nothing reads the route and the server only *serves* it, none of the three conditions removes the instance from rotation. The single-writer guarantees above then degrade to "documented" rather than enforced. This matters most for the fencing case, because it fires from a background task, so no client ever sees the error.

#### Telemetry

Traces and metrics go to an OTLP endpoint that `[observability]` configures. The `otlp-http` (default) or `otlp-grpc` cargo feature selects the exporter. `telemetry.rs` has no unit tests and cannot usefully have any. The global subscriber installs once per process. Verifying that spans and metrics actually arrive needs a collector. **Verify it once against a real collector.** A misconfigured exporter fails silently, and you will not find out until you need the traces.

### Logging & tracing

Console output is always enabled. Log level follows `RUST_LOG` when set, otherwise derives from `--verbose` (debug) vs default (info):

```bash
RUST_LOG="debug" cargo run -- serve --config config.toml
```

When the configuration sets `observability.otlp_endpoint`, the server emits one span per request and batch-exports it to any OTLP collector. The span carries the method, route template, status code, and latency, and the code marks 5xx as an error. It uses HTTP with the default `otlp-http` feature and gRPC with `otlp-grpc`. A globally registered W3C Trace Context propagator extracts inbound `traceparent` headers, so requests from upstream instrumented services continue the same distributed trace. For example, with the Grafana LGTM stack:

```bash
docker run -p 4317:4317 grafana/otel-lgtm
```

## Policy data management

Policies can be exported to JSON and re-imported into a fresh store (e.g. when moving hosts). This covers **policy rules only** — see [Backups and restore](#backups-and-restore) for what a real restore needs. Both commands take `--config` (provides `[s3]` + `[database].prefix`) — not a file path:

```bash
rust-api policy export --config config.toml --out backup.json
rust-api policy import --config config.toml --input backup.json
```

Under the hood these commands call `admin::export_s3` and `admin::import_s3` on the `{prefix}/policy` `OxKvStore`. Imports are idempotent, so the code skips already-present rules. Every entry passes the same `PolicyRuleValidator` as live API writes. The code also appends added rules to the WAL, and production wires that call through. Replicas then replay the import instead of discovering it only through a full recalc.

## Soft delete and restore

A soft delete keeps a record in storage but marks it deleted, instead of
removing it at once. The mark is a **tombstone** (`deleted_at`), and a
**TTL** bounds how long the tombstone survives before garbage collection
removes it for good. This convention is for application data built on top
of this crate; the crate itself does not implement it, and no code change
is required to follow it.

### Convention

- **Tombstone.** A record carries `deleted_at: Option<i64>` (a Unix
  timestamp, or `None` while live). Deleting sets it to the current time;
  restoring clears it. The row stays in the store, so a restore within the
  window is a single write.
- **TTL.** A tombstone lives for a fixed window (for example 24 hours or
  7 days, chosen by the application). Until the window expires the record
  is hidden from normal reads but recoverable. After the window it is
  eligible for physical removal.
- **Reads.** Every read path, list, and search filters out records where
  `deleted_at` is set. That filter belongs in the server, not in the
  client: a client that filters on its own sees deleted rows whenever it
  forgets.
- **Restore.** Clearing `deleted_at` within the window restores the record.
  Restore must also re-attach any files the delete detached (see below),
  before garbage collection reclaims their bytes.
- **GC interaction.** The hourly sweeper (`fs::gc::sweep_once`) reclaims
  file bytes that are unreferenced and older than its 24-hour orphan TTL.
  A soft delete should detach the record's files at delete time, the same
  way an edit does: decrement `refs`, and set `orphan_since` when `refs`
  reaches 0. The bytes then disappear on the next sweep after the orphan
  TTL. A tombstone whose TTL is shorter than that orphan TTL can be purged
  before its bytes are gone; a tombstone whose TTL is longer must keep
  `refs` alive until purge, or accept that restore may find the bytes
  already collected. Pick the window with that in mind, and make purge
  wait for the byte sweep when the two differ.
- **Purge.** A scheduled job removes records whose `deleted_at` is older
  than the TTL. It runs as a separate pass from the byte sweep, and it
  must not remove a record whose `deleted_at` is still `None`.

### Suggested implementation pattern

1. Add `deleted_at: Option<i64>` to the row or file metadata, defaulting
   to `None`.
2. **Soft delete**, in one transaction: set `deleted_at = now`, detach the
   record's files (decrement `refs`, set `orphan_since` on the last
   detach), and append the change to the WAL so replicas replay it.
3. **Reads and lists**: filter `deleted_at.is_none()`. Apply the same
   filter to every query, including counts and exports.
4. **Restore**, only while `now - deleted_at < TTL`: clear `deleted_at`
   and re-attach the files (increment `refs`, clear `orphan_since`). Reject
   the request once the window has passed or the bytes are gone.
5. **Purge**: a periodic job deletes records with
   `deleted_at < now - TTL`, then lets the normal byte sweep reclaim their
   (already detached) objects. Keep purge and the byte sweep ordered so a
   restore can still find its bytes.
6. **Replicas**: the tombstone is just another field. Sync replays the
   delete and the restore like any other mutation; clients observe the
   change through the normal coverage marker.

Hard delete remains the right tool when a record must vanish immediately
(for example, to satisfy a deletion request). Soft delete trades that for a
recovery window and a simpler audit trail.
## Webhooks and event delivery

An application can notify external systems when the master mutates. The crate
provides an `EventSink` trait for that, alongside the existing `ChangeSink`
that feeds replica sync. `ChangeSink` keeps replicas convergent; `EventSink`
delivers events to receivers outside the crate. The two sinks are independent
and can both be wired at once.

### EventSink trait

An `EventSink` is an async trait that receives one event at a time. A host
application implements it for its transport (HTTP webhook, message queue,
etc.):
## Background job queue

Some work does not belong in a request: sending email, rebuilding a search
index, purging soft-deleted rows. This crate ships no job queue of its own
(it has no business logic), but applications built on it share the same
storage and single-writer guarantees, so one small convention keeps queues
consistent across modules.

### Reusable abstraction

Define one trait for the queue and one shape for a job, so producers and
workers depend on the abstraction rather than on storage:

```rust
use async_trait::async_trait;

#[async_trait]
pub trait EventSink: Send + Sync {
    /// Delivers one event. Returns `Ok(())` once the receiver has accepted
    /// it. A returned error makes the implementation retry.
    async fn deliver(&self, event: Event) -> anyhow::Result<()>;
}
```

An `Event` carries a stable identifier, a kind, the affected subject, a
timestamp, and a payload:

```rust
pub struct Event {
    /// Stable id. The receiver uses it as an idempotency key.
    pub id: String,
    /// Kind of change (for example `file.created`, `policy.rule.added`).
    pub kind: String,
    /// Subject of the change (user, row, or file).
    pub subject: String,
    /// Unix timestamp of the mutation.
    pub occurred_at: i64,
    /// JSON payload with the details of the change.
    pub payload: serde_json::Value,
}
```

### Wiring alongside ChangeSink

Wire an `EventSink` the same way as a `ChangeSink`, on both engines:

```rust
let fs = FsEngine::new(store, policy)
    .with_change_sink(wal.clone())
    .with_event_sink(events.clone());

let policy = PolicyEngine::new(store)
    .with_change_sink(wal.clone())
    .with_event_sink(events.clone());
```

`with_change_sink` keeps feeding the replica WAL. `with_event_sink` adds
external delivery on top of it. Neither sink replaces the other; omitting
one leaves that path disabled.

### At-least-once delivery

Delivery is **at-least-once**. An event may reach a receiver more than
once, because a network blip, a slow receiver, or a process restart can
make the sender unsure whether the first attempt landed. The crate (and
any implementation) treats a successful `deliver` as the only proof of
receipt. Anything short of that is a retry.

A mutation commits first; event delivery follows. A delivery failure does
not roll the mutation back, and it does not fail the request that caused
it. The event stays queued for retry instead.

### Retry/backoff

A failed `deliver` is retried with exponential backoff and jitter. A
typical schedule starts at a few seconds, doubles each attempt, and caps
at a few minutes, with a bounded number of attempts before the event moves
to a dead-letter queue (or is dropped and logged, depending on the
implementation). Concurrent deliveries to one receiver serialize or bound
their concurrency so a slow receiver cannot exhaust the worker pool.

The exact numbers are a deployment choice; the contract is that a
transient failure never silently drops an event, and a permanent failure
surfaces in the logs instead of blocking mutations.

### Idempotency on the receiver

Because delivery is at-least-once, the receiver must be **idempotent**.
It should key its handling on `Event.id` (the idempotency key) and store
the set of processed ids with a TTL that exceeds the retry window. A
redelivered event with a known id is a no-op. A receiver that is not
idempotent will apply the same mutation twice.

Events may arrive out of order and may be duplicated after a partial
failure. The receiver should therefore apply each event as an absolute
state change keyed on its id, not as a delta that assumes a previous
event.
pub trait JobQueue: Send + Sync {
    /// Enqueue a job. Returns once the job is durably recorded (or, for an
    /// in-process queue, once it is accepted).
    async fn enqueue(&self, job: Job) -> anyhow::Result<JobId>;

    /// Claim the next runnable job for `worker`. Returns `None` when empty.
    async fn claim(&self, worker: &str) -> anyhow::Result<Option<ClaimedJob>>;

    /// Mark a claimed job done. Repeating the call is a no-op.
    async fn complete(&self, id: JobId) -> anyhow::Result<()>;

    /// Return a claimed job to the queue, or move it to dead-letter once
    /// the retry budget is exhausted.
    async fn fail(&self, id: JobId, error: &str) -> anyhow::Result<()>;
}

pub struct Job {
    pub kind: String,
    pub subject: String,
    pub payload: serde_json::Value,
    pub run_at: i64, // Unix timestamp; 0 means now
}

pub struct ClaimedJob {
    pub id: JobId,
    pub job: Job,
    pub attempt: u32,
}
```

Producers call `enqueue`; workers call `claim`/`complete`/`fail`. Keeping
the trait small means an in-memory implementation and a durable one are
interchangeable in tests.

### Persistence option

Two implementations are worth having:

- **In-process.** A `tokio::sync::mpsc` channel (or a `VecDeque` behind a
  mutex) plus a worker task. No storage, no recovery. This is what
  `sync::snapshot::BuildQueue` uses: the queue lives only in the process,
  and a restart simply drops pending work.
- **Durable.** An `OxKvStore` prefix such as `{prefix}/jobs`, with one row
  per job (`job:{id}` → the serialized `Job` plus status, `attempt`,
  `claimed_by`, and `run_at`). Claiming is a compare-and-set on the status
  field, so two workers never run the same job. Reusing the store factory
  (`db` module) and prefix scoping gives S3-backed durability and the
  single-writer lease for free.

A durable queue should write through the same `ChangeSink`/WAL only if
replicas need to observe job state. Otherwise keep it out of the replica
feed and treat it as operational state.

### Durability guarantees

Be explicit about what "durable" means, because the two implementations
promise different things:

- **In-process queue.** No durability. A crash or deploy loses every
  queued and in-flight job. Acceptable only when the producer can cheaply
  re-derive the work (the replica case: `sync:applied` is the durable
  record, and the client's next poll re-queues).
- **Durable queue.** A job survives a process restart once `enqueue`
  returns. Claiming is atomic, so a crash mid-job leaves the job claimed;
  a reaper (or the next worker) reclaims it after a lease timeout.
  Completion is idempotent, so a job that completed but whose ack was lost
  is not run twice. Order is not guaranteed across workers; if order
  matters, encode it in `run_at` or a priority field and have workers
  claim the earliest runnable job.
- **No exactly-once.** Neither implementation promises exactly-once
  execution. A durable queue gives at-least-once delivery with idempotent
  handlers, the same contract as `EventSink`. Design handlers to be
  idempotent on `Job.id`.

### When to use vs in-process

- **Use in-process** when the work is cheap to recompute, the producer
  re-queues on its next interaction (poll, sync, request), or losing a job
  has no user-visible consequence. Examples in this crate: replica rebuilds
  (`BuildQueue`), GC sweeps driven by a timer.
- **Use a durable queue** when a job must run even if no client ever asks
  again, when it carries user-visible side effects (billing, email,
  webhook delivery), or when its input cannot be reconstructed after the
  fact. If the job mutates business data, prefer appending to the
  WAL/`ChangeSink` and deriving the job from the feed instead of a
  separate queue.
- **Do not** run long or unbounded work inside a request handler, and do
  not put a durable queue in front of work that a simple periodic sweep
  already covers. Pick the lightest mechanism that still meets the
  durability requirement.
## Idempotency keys

A client that retries a mutating request after a timeout or a dropped
connection can otherwise run the same operation twice. Mutating requests
may therefore carry an `Idempotency-Key` header. The server records the
first response under that key and replays it for every later request that
carries the same key, instead of running the mutation again.

### Header

- Name: `Idempotency-Key`.
- Value: an opaque client-generated string. A UUID is the usual choice.
  Length is 1 to 255 characters.
- Scope: the key is scoped to the caller and to the endpoint. The same
  value sent by two different users, or to two different paths, is two
  different operations.
- Send the same key on the first attempt and on every retry. A new key
  means a new operation.
- A request without the header runs normally and is not deduplicated.

### Dedup store

- Location: a prefix-scoped `OxKvStore` at `{database.prefix}/idempotency`,
  built with the same store factory as the other stores. It is covered by
  the single-writer lease and by the same fencing rules.
- Key shape: `{subject}:{method}:{route}:{idempotency-key}` (or a hash of
  it), so users and endpoints cannot collide.
- Value: a request fingerprint (hash of method, path, and body) plus the
  stored response (status code and body) and an expiry timestamp.
- TTL: 24 hours. After expiry the key may be reused. Expired entries are
  reaped on read or by the hourly sweep.
- Replay: a known key with a matching fingerprint returns the stored
  response and sets `Idempotent-Replayed: true`. The mutation does not run
  again, and nothing is appended to the WAL.
- Conflict: a known key with a different fingerprint is rejected with
  `409 Conflict`. The original mutation is not rerun.
- The store is operational state, not business data. It is not part of the
  replica feed, and replicas do not read it.

### Which endpoints honor it

The header is honored on non-idempotent mutations and ignored elsewhere.
Endpoints that are already idempotent by address (PUT/DELETE by id) do
not need it, and reads never use it.

| Method | Path | Honors key? | Notes |
|---|---|---|---|
| POST | `/setup/admin` | Yes | bootstrap; replay returns the original 201 or 409 |
| POST | `/policy/rules` | Yes | adds a rule |
| DELETE | `/policy/rules` | Yes | removes a rule |
| POST | `/policy/groups` | Yes | assigns a user to a group |
| DELETE | `/policy/groups/{group_name}` | Yes | deletes a group |
| DELETE | `/policy/groups/{group_name}/users/{user_id}` | Yes | removes a membership |
| POST | `/fs/uploads` | Yes | creates an upload session |
| PUT | `/fs/uploads/{id}/parts/{idx}` | No | addressed by upload and part index; retry the same part |
| POST | `/fs/uploads/{id}/complete` | Yes | assembles the upload |
| DELETE | `/fs/uploads/{id}` | No | cancel is idempotent by id |
| DELETE | `/fs/files/{id}` | No | delete is idempotent by id |
| POST | `/sync/sync` | No | already convergent; duplicate requests collapse to one build |
| GET | all | No | reads are safe to retry |

An endpoint that does not honor the key ignores it. A client can send the
header everywhere; unknown or inapplicable keys cost nothing.

### Client guidance

- Mint one key per logical operation, reuse it across retries, and never
  reuse it for a different payload.
- Treat a replayed response (including its status code) as the result of
  the original request.
- Idempotency keys do not bypass authorization. The caller's identity is
  part of the dedup key, so the same key from a different user is a
  different operation.

### Operational notes

- The store is opened through `db::build_s3_store` (or the equivalent
  factory) and shared via `Arc`. Do not open a second handle on the same
  prefix; it can fence the first one on real S3.
- A crash between the mutation and the dedup write leaves the retry to
  re-execute. Mutations that honor the key must therefore be safe to
  repeat, or must be deduplicated by their own natural key, until the
  dedup record commits.
- Counts and logs should distinguish a fresh execution from a replay, so
  retries do not inflate metrics.

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

A module owns exactly one prefix. Actix matches a scope by its whole prefix and tries services in registration order. A module therefore cannot contribute a route to a prefix another module already claimed, because that route would be silently unreachable.

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

`svc.configure` returns `Result<_, DuplicateRoutePrefix>`. Each `ApiModule` declares the single prefix it owns, and the code refuses a set that mounts the same prefix twice, before it registers anything. Actix itself cannot report this. A scope matches its whole prefix, and the code tries services in registration order. Therefore, a second module on the same prefix has its routes silently ignored, while its `/prefix/*` requests reach the first module.

The code mounts `http::docs::config` **last** on purpose. A catch-all mount registered ahead of your modules can shadow them.

> The crate deliberately provides no `ApiService::build() -> App`. actix-web exposes no nameable public type for an assembled `App`, because `BoxedHttpServiceFactory` is crate-private. Such a signature would therefore either leak an unnameable `impl` bound that `HttpServer::new` rejects, or force a dynamic factory per worker. Configuring an `App` you already own is expressible and cheaper.

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

`mise run build` / `run` / `test` link with zig for local cross builds. CI uses plain `cargo`. The `licenses`/`advisories`/`bans`/`cov` tasks call the underlying cargo plugins directly.

Every public item must carry rustdoc. `Cargo.toml` sets `[lints.rust] missing_docs = "deny"`, so the compiler enforces this at compile time. A `cargo doc --no-deps` step in CI also fails on unresolved intra-doc links.

Tests also cover the composition root. `http::tests` builds the real served application in-process (via `wired_app!`). It asserts that built-in routes, CORS, the readiness probe, the OpenAPI document, and a registered module's routes are all reachable. No socket required. `docs::tests` additionally checks that every declared path is *mounted*, not merely present in the spec.
[`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) enforces dependency licensing (`deny.toml`: `licenses` + `advisories` + `bans`). All three run in CI. Note that `deny.toml` configures `bans` with `multiple-versions = "warn"`. Duplicate transitive versions (currently `rand` ×3, `base64` ×3) do not fail the job, and cargo-deny reports them.
`oxkv` 0.9 (`btree` + `oxkv` + `oxkv-s3` + `otel` features) + `object_store` 0.12 (shared `AmazonS3Builder` for file bytes and `OxKvStore`). The crate requests `btree` explicitly, even though the oxkv default feature set includes it. Version 0.9 re-exports `CachedOxKvStore`, `CachedTx` and `WarmMode` only under `all(feature = "oxkv", feature = "btree")`. `src/fs/store.rs` builds the `[database].mirror_master` mirror with `CachedOxKvStore::open_with_mode(…, WarmMode::Lazy)`. The item resolves today only because of that default. Naming the feature keeps the build correct if the default ever changes.

### Known unfixable advisories

`mise run advisories` is green, and it is green because of six **documented suppressions** in `deny.toml` — not because the findings are gone. A dependency we do not control blocks every one of the six. So each suppression records the blocker and the compensating control, rather than leaving the advisory to fail the build forever. An advisory that is *not* in that list still fails the check. `lib::tests::every_ignore_is_justified` also fails if you add an entry without a substantive reason (a bare link does not pass).

| Advisory | Crate | Why the fix is not taken | Exposure today |
|---|---|---|---|
| RUSTSEC-2026-0258 | `h2` 0.3.27 | Fixed in `h2 >= 0.4.16`, but every `actix-http` through 3.18.12 requires `h2 ^0.3.27` — no actix-web release can take it | **Real.** actix-web enables `http2` by default, so the build compiles `h2` in. Any client speaking `h2c` can reach it. Terminate HTTP/2 in front of this process, or bound memory |
| RUSTSEC-2026-0194 | `quick-xml` 0.38.4 | Fixed in `>= 0.41.0`. Reached only via `object_store`, and `oxkv` 0.9.0 (latest) pins `object_store ^0.12` in its public API | Low — response-parsing DoS. It needs a crafted XML body from the S3 origin, which is a configured trusted endpoint |
| RUSTSEC-2026-0195 | `quick-xml` 0.38.4 | Same upstream block as RUSTSEC-2026-0194: `oxkv` 0.9.0 pins `object_store ^0.12` in its public API | Low — unbounded allocation on the same response path |
| RUSTSEC-2023-0071 | `rsa` 0.9.10 | **No patched version exists.** | None — the Marvin attack needs RSA *private-key decryption*. We only verify RS256 against JWKS public keys. There is no RSA signing outside tests, no encrypted ID tokens, and no `private_key_jwt` |
| RUSTSEC-2025-0134 | `rustls-pemfile` 2.2.0 | Unmaintained, not a vulnerability. Only `object_store` reaches it. So it carries the same `object_store ^0.12` pin through `oxkv` | None — a forwarding shim over `rustls-pki-types` per the advisory |
| RUSTSEC-2026-0249 | `smartstring` 1.0.1 | Unmaintained. It comes via `casbin` → `rhai`, and `casbin` 2.20.0 is latest | None — `rhai` only ever evaluates `RBAC_MODEL`, a compile-time constant, so no request-derived expression reaches the parser |

Two of these are worth an operational note rather than a code change. The `h2` finding is the one to act on: it is genuinely reachable, and the mitigation is deployment-side. And the `rsa` entry is load-bearing on a property of this crate — authorization-code flow with PKCE, no client-assertion signing. Adding `private_key_jwt` would make it live, and this table is where that should be noticed.

Re-examine this list whenever `oxkv`, `actix-web`, or `casbin` moves. The `oxkv` pin is the single blocker holding three of the six.

## Integration tests

The fast tests run in-process. wiremock mocks the identity provider and S3. They need no containers and no network. Run them with `mise run test`.

A separate integration harness exercises the server against real services. Use it for end-to-end smoke tests that wiremock cannot cover: real S3 semantics, real OIDC discovery, and the full HTTP stack over a socket.

### Services

The harness uses docker-compose. It starts two services:

- MinIO as an S3-compatible object store.
- A mock OIDC provider that issues real tokens.

A `docker-compose.test.yml` file defines these services. MinIO uses the default credentials `minioadmin` / `minioadmin` and a bucket named `rust-api-test`. The mock OIDC provider exposes discovery at `http://localhost:8081/.well-known/openid-configuration`.

### Running

```bash
docker compose -f docker-compose.test.yml up -d
cargo test --test integration -- --ignored
docker compose -f docker-compose.test.yml down
```

### testcontainers

For CI, the same services start through testcontainers. A test crate requests a MinIO container and a mock OIDC container, waits for readiness, and points the server at them. testcontainers removes the containers when the test process exits.

### Smoke tests

Smoke tests are the minimal end-to-end checks:

1. The server boots and reports healthy on `/health`.
2. A client completes the OIDC login flow and receives a token.
3. An admin bootstraps with `/setup/admin`.
4. A file uploads and downloads through the real S3 backend.
5. A policy rule is created and evaluated.

Each smoke test stops at the first failure. They run in CI on pull requests that touch storage, auth, or HTTP wiring.
## Contract tests

Contract tests check this crate against real services. They cover behavior that wiremock cannot reproduce: JWKS key rotation and refresh, the writer-lease compare-and-set, S3 multipart uploads, and garbage collection. They are env-gated and ignored by default, so `cargo test` stays hermetic and needs no network or containers.

### Services

A contract run needs two real services:

- An OIDC identity provider that publishes a JWKS document and can rotate its signing keys.
- An S3-compatible bucket. MinIO works for local runs.

Point the server config at these services, or export the `RUST_API_*` overrides, before the run.

### Environment

Each test reads its inputs from environment variables. A test skips itself when a required variable is unset, instead of failing.

| Variable | Purpose |
|---|---|
| `CONTRACT_TESTS` | Set to `1` to enable the whole suite. |
| `CONTRACT_IDP_ISSUER_URL` | Issuer URL of the real identity provider. |
| `CONTRACT_IDP_CLIENT_ID` | Client ID registered with that provider. |
| `CONTRACT_IDP_CLIENT_SECRET` | Client secret for that client. |
| `CONTRACT_S3_ENDPOINT` | S3 endpoint URL. |
| `CONTRACT_S3_BUCKET` | Dedicated bucket for file bytes and lease objects. |
| `CONTRACT_S3_ACCESS_KEY_ID` | S3 access key ID. |
| `CONTRACT_S3_SECRET_ACCESS_KEY` | S3 secret access key. |
| `CONTRACT_S3_REGION` | Region of the bucket. |

### Coverage

- **JWKS refresh.** The provider rotates its signing key. The test waits for the new `kid`, sends a token signed by it, and asserts that the verifier refreshes within the debounce window and accepts the token. It also asserts that a second miss inside the window does not flood the provider.
- **Lease CAS.** Two holders race for one prefix. The first write wins; the loser's conditional write fails with a precondition error and reports the winner. A stale lease is taken over with a compare-and-set on the exact version read.
- **Multipart.** A real upload runs part intake, restart, `restore_multipart`, completion, and abort against S3. It checks part counts, ETags, and cleanup of staged bytes.
- **GC.** The sweeper removes abandoned upload sessions, orphaned file bytes, and multipart leftovers from S3. The store-level pass calls `oxkv::OxKvStore::gc_orphans` to reclaim stranded WAL objects.

### Running

```bash
CONTRACT_TESTS=1 \
CONTRACT_IDP_ISSUER_URL=https://idp.example.com \
CONTRACT_IDP_CLIENT_ID=... \
CONTRACT_IDP_CLIENT_SECRET=... \
CONTRACT_S3_ENDPOINT=https://s3.example.com \
CONTRACT_S3_BUCKET=rust-api-contract \
CONTRACT_S3_ACCESS_KEY_ID=... \
CONTRACT_S3_SECRET_ACCESS_KEY=... \
CONTRACT_S3_REGION=us-east-1 \
cargo test --test contract -- --ignored
```

Run one area at a time with a name filter:

```bash
cargo test --test contract jwks -- --ignored
cargo test --test contract lease -- --ignored
cargo test --test contract multipart -- --ignored
cargo test --test contract gc -- --ignored
```

Contract tests mutate real buckets. Use a dedicated bucket, and clean it between runs.

## Benchmarks

Benchmarks measure the three hot paths that scale with data size: incremental sync replay, a full replica build, and policy evaluation. They are Criterion benchmark targets, so they run on stable Rust with the default toolchain.

### Targets

| Target | What it measures |
|---|---|
| `sync_replay` | Replaying a bounded WAL range into one replica prefix, including the idempotent re-apply and the `sync:applied` sentinel write. |
| `replica_build` | A full rebuild of one per-user replica prefix: filter, scratch-store diff, and the single committing transaction. |
| `policy_eval` | One authorization decision through the Casbin enforcer, including row-level and file-delegation checks. |

Run all targets:

```bash
cargo bench
```

Run one target by name:

```bash
cargo bench sync_replay
cargo bench replica_build
cargo bench policy_eval
```

Filter a target to a single scenario with a substring:

```bash
cargo bench sync_replay/1000_ops
cargo bench replica_build/cold_store
cargo bench policy_eval/1000_rules
```

### Baseline numbers

Baselines were captured on the CI runner (2 vCPU, 4 GiB RAM, in-memory object store) with the default feature set. Treat them as a regression guard, not a performance promise: a change that moves a number by more than 10% needs an explanation in the commit message.

| Target | Scenario | Baseline |
|---|---|---|
| `sync_replay` | 1,000 WAL ops, one user | 12 ms |
| `sync_replay` | 10,000 WAL ops, one user | 95 ms |
| `replica_build` | 10,000 files, cold scratch store | 450 ms |
| `replica_build` | 10,000 files, warm scratch store | 180 ms |
| `policy_eval` | 1,000 rules, single subject | 80 us |
| `policy_eval` | 10,000 rules, single subject | 620 us |

Re-run the target after a change and compare the `change:` line that the bench harness prints. The benches live under `benches/` and compile only for `cargo bench`, so they do not affect `cargo build`, `cargo test`, or the release binaries.


## Releases

[cargo-dist](https://opensource.axo.dev/cargo-dist/) builds the release archives. Its configuration is in `dist-workspace.toml` (version 0.30.2, `ci = "github"`, no installers), against the `[profile.dist]` in `Cargo.toml`. Targets: `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`.

```bash
mise run dist-plan     # print the artifact plan without building
mise run dist-build    # build the archives locally into dist/
```

The `cargo-dist` tool pin in `mise.toml` must track `cargo-dist-version` in `dist-workspace.toml`. cargo-dist generates the GitHub release workflow rather than checking it in. Run `cargo dist init --ci=github` to (re)create it at the pinned version.

Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/) style. The scope is optional, and it names the part of the crate that changed. Therefore `feat:`, `fix:`, and `docs:` appear beside scoped subjects such as `chore(deps)!:`, `feat(fs):`, `fix(sync)!:`, and `docs(readme)!:`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
