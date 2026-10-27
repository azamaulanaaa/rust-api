# rust-api

A business-logic-free starter kit for REST APIs on [Actix Web](https://actix.rs/). It provides OIDC authentication, JWT sessions, Casbin authorization, S3-backed file uploads, and per-user sync replicas. Applications implement `ApiModule` and compose their own API surface on the shared plumbing.

For module documentation, run `cargo doc --no-deps --open`. Start with [`http`](src/http/mod.rs), [`oidc`](src/oidc/mod.rs), [`policy`](src/policy/mod.rs), [`fs`](src/fs/mod.rs), and [`sync`](src/sync/mod.rs).

## At a glance

- Log in with any OIDC provider. Use a session cookie or a bearer token.
- Authorize with Casbin rules and groups. Bootstrap one superadmin.
- Upload multipart files to S3, attach them to business rows, and let hourly GC remove orphans.
- Serve each user a filtered replica and sync it with ETags.
- Run one writer safely with a lease, fencing, and readiness probes.
- Generate a typed client from the OpenAPI 3.1 document.
- Extend the server with modules, jobs, reactive hooks, and OTLP telemetry.

## Contents

| Section | What it covers |
|---|---|
| [Quickstart](#quickstart) | Zero to a working API call |
| [Concepts](#concepts) | Modules, auth, files, sync, queues, and hooks |
| [API reference](#api-reference) | Endpoints, errors, OpenAPI, versioning, renewal |
| [Client integration](#client-integration) | SPA flow, TypeScript example, sync contract |
| [Configuration](#configuration) | Config file, environment overrides, limits |
| [Operations](#operations) | Lease, readiness, backups, GC, telemetry, migration |
| [Extending the server](#extending-the-server) | Custom modules and embedding |
| [Development](#development) | Tests, benchmarks, releases |
| [License](#license) | License terms |

## Quickstart

This quickstart takes about five minutes. It assumes you have an S3-compatible bucket and an OIDC provider.

### Prerequisites

- Rust 1.88 or newer. `mise install` installs the declared toolchain.
- An S3-compatible bucket. AWS S3, MinIO, and Cloudflare R2 work.
- An OIDC provider. Keycloak, Entra ID, and Auth0 work. Register a client and set the redirect URI to `http://localhost:8080/auth/callback`.

### Configure

Create `config.toml`:

```toml
public_address = "http://localhost:8080"
listen_port = 8080

[authorization]
client_id = "rust-api"
client_secret = "replace-me"
issuer_url = "https://idp.example.com"

[database]
prefix = "oxkv"

[s3]
bucket = "my-bucket"
region = "us-east-1"
```

Replace `client_secret`, `issuer_url`, `bucket`, and `region`. For MinIO or R2, add `endpoint_url` and set `force_path_style = true` under `[s3]`.

You can keep secrets out of the file. Set `RUST_API_CLIENT_SECRET`, `RUST_API_S3_ACCESS_KEY_ID`, and `RUST_API_S3_SECRET_ACCESS_KEY` instead. A non-empty environment value wins over the file.

The database prefix defaults to `oxkv`. See [Configuration](#configuration) and [config.example.toml](config.example.toml) for every field.

### Run

```bash
mise install
cargo run -- serve --config config.toml
```

The server listens on port 8080. Confirm readiness:

```bash
curl http://localhost:8080/ready
```

### Sign in

Open `http://localhost:8080/auth/login` in a browser. Sign in at the provider. The callback returns an `AuthResponse` JSON body and sets the `auth_token` cookie. Copy the `token` value.

### Bootstrap the first admin

Run this call once:

```bash
curl -X POST http://localhost:8080/setup/admin \
  -H "Authorization: Bearer <token>"
```

The call returns `201` and grants the caller the `superadmin` role. Later calls return `409`.

### Make the first call

```bash
curl http://localhost:8080/policy/rules \
  -H "Authorization: Bearer <token>"
```

### Next steps

- [API reference](#api-reference) for every route and error behavior.
- [Configuration](#configuration) for limits, CORS, telemetry, and signing keys.
- [Operations](#operations) before a production deploy.

## Concepts

### Modules and composition

An `ApiModule` owns exactly one route prefix. `ApiService` registers modules and refuses a set that mounts one prefix twice, before it registers anything. Actix matches a scope by its whole prefix, so a second module on the same prefix would otherwise be silently unreachable.

Each module brings its own middleware. Modules that need a subject require validated JWT claims. The global stack covers bearer extraction, JWT validation, request tracing, body limits, CORS, and rate limiting.

`ApiService` also owns the listener. To keep your own listener, configure an `App` yourself. See [Extending the server](#extending-the-server).

| Module | Role |
|---|---|
| `http` | `ApiService`, `ApiModule`, middleware, errors, CORS, health, body limits, validation, OpenAPI mount |
| `oidc` | OIDC client and `/auth/*`: login, callback, refresh, logout, me |
| `policy` | Casbin engine, S3 adapter, `/policy/*`, `/setup/admin`, row authorizer, policy export/import |
| `fs` | Multipart uploads, temp files, relations, capability tokens, garbage collection |
| `sync` | Replica manager, WAL, `/sync/*` |
| `records` | Change-feed types: `FileRecord`, `WalOp`, `ChangeSink` |
| `queue` | Queue traits, memory and durable backends, worker, RabbitMQ seam |
| `reactive` | Extension point for store hooks and background services |
| `audit` | `AuditEvent`, `AuditSink`, and a tracing sink |
| `retry` | Exponential-backoff helper for transient failures |
| `db` | S3-backed `OxKvStore` factory |
| `lease`, `fencing` | Single-writer lease and lost-epoch latch |
| `limits`, `telemetry` | Rate and concurrency limits, and OTLP setup |
| `docs`, `config` | OpenAPI document and binary configuration loader |

### Authentication and sessions

`GET /auth/login` starts the OIDC authorization-code flow with PKCE, CSRF state, and a nonce. The provider redirects to `/auth/callback`. The callback validates the response and sets the session cookies:

- `auth_token`: the ID token. `HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS, seven-day lifetime.
- `refresh_token`: present only when the provider issues one. `HttpOnly`, `SameSite=Lax`, 30-day lifetime.

The callback also returns the token in its JSON body, so a SPA can keep it in memory.

Protected routes accept `Authorization: Bearer <token>` or the `auth_token` cookie. The header wins when both are present. An expired or invalid cookie does not block `/auth/*`. The request continues as anonymous, the protected handler returns `401`, and the response clears the stale cookie.

`GET /auth/me` returns `sub`, `iss`, `aud`, and `exp`. Use it as the session guard. `POST /auth/logout` clears the `auth_token` cookie and always returns `204`.

See module `oidc` and module `http::middleware` in the rustdoc.

### Authorization

The Casbin RBAC model is:

```ini
p = sub, obj, act        # subject may act on object
g = _, _                 # user belongs to group
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

A request is allowed when the subject holds a matching `p` rule, directly or through a group. Grant permissions to groups, then manage membership through `/policy/groups`.

A fresh policy store has no roles. `POST /setup/admin` grants the first caller the `superadmin` role and the rules that role needs. Later calls return `409`.

Business rows authorize as `{type}:{id}` objects through `RowAuthorizer`. Files do not use a coarse `fs` gate. A file delegates to the rows it is attached to. See module `policy` in the rustdoc.

### Files and uploads

An upload starts as a temp file owned by the caller. The upload session and its parts live in the `fs` store. Multipart state survives a restart, so `upload_part`, `complete`, `cancel`, and GC keep working.

`attach(row_type, row_id, file_id, caller)` requires `write` on the row. It adds a relation and increments the file reference count. `detach` decrements the count and marks the file as an orphan when the count reaches zero. Reads and deletes allow the temp owner, or a row that grants `read` or `delete`. Editing a row detaches the old file and attaches the new one. The old S3 object then becomes an orphan, and GC removes it after 24 hours.

Upload size limits apply at `init`, before the client sends any data:

| Field | Limit |
|---|---|
| `part_size` | Multiple of 1 KiB, at most 512 KiB |
| `file_total_parts` | 1 for a single-part upload, otherwise at most 10,000 |
| Single-part `file_size` | At most 10 MiB, and equal to `part_size` |
| Multipart `file_size` | Exactly `file_total_parts × part_size` |
| Maximum multipart upload | About 4.9 GiB |

Capability tokens are a short-lived HMAC JWT for direct file delegation. `FsEngine::mint_token` and `verify_token` are available to applications. The `/fs/*` routes authenticate with the OIDC JWT and do not consume capability tokens.

### Sync replicas

The master store and the WAL are the only write path. Each user owns one replica prefix, `{db}/u/{sha256-hex(sub)}/`, that holds the files and relations the user can read.

| Route | Behavior |
|---|---|
| `GET /sync/status` | Returns `prefix`, `applied_seq`, and `head` with an `ETag`. Repeat polls get `304`. Never builds. |
| `POST /sync/sync` | Advances the replica. Small deltas replay inline. A full rebuild is queued and returns `pending: true` with the old coverage. |
| `GET /sync/db/{object}` | Streams one replica object with the backend `ETag` and `If-None-Match` support. |

`applied_seq` is null before the first build. Clients poll `/sync/status` until `applied_seq` reaches `head`. If a `POST /sync/sync` returned `pending: true`, repeat that call until it returns `pending: false`. `pending` is on the sync response, not the status response.

Replica builds are in-process. A host application that mounts `/sync` must spawn `sync::snapshot::BuildPool`. Without it, a queued rebuild stays pending forever.

See module `sync::snapshot` in the rustdoc for build and replay internals.

### Change feed, events, jobs, audit, and reactive hooks

`FsEngine` and `PolicyEngine` announce every committed mutation to the shared change feed. A logging failure fails the mutation, so the feed cannot silently miss a write. Replicas consume the feed. The vocabulary lives in `records`. The durable implementation is `sync::wal::Wal`.

The job queue lives in `src/queue.rs`. It provides `MemoryQueue` for tests, `DurableQueue` over an OxKV handle, and `QueueWorker`, which reserves jobs, dispatches by `kind`, acknowledges success, and retries or dead-letters failures. Delivery is at least once, so handlers must be idempotent. `RabbitMqQueue` is a feature-gated seam behind `queue-rabbitmq`. The broker wiring is not implemented, and its operations return an unsupported error. Metrics cover depth, enqueue, reserve, completion, failure, dead-letter, and processing time. See `examples/job_queue.rs`.

`reactive::ReactiveService` gives an application a place to attach `oxkv` hooks and run background work. `register` runs once at startup and must stay cheap. `run` ends when the cancellation token fires. Hooks are read-only, run on the writer path, and their watch channels are bounded and lossy. See `examples/reactive_service.rs` and module `reactive`.

`audit::AuditEvent` and `audit::AuditSink` record mutations. `TracingAuditSink` writes each event at info level. The binary does not install a sink. `retry::retry_with_backoff` retries transient failures with exponential backoff.

The crate does not ship external event delivery (webhooks), idempotency-key storage, or soft delete. If an application adds them, deliver events at least once and make receivers idempotent on a stable event id. Replay the stored response for a repeated idempotency key, and reject a different payload with the same key as a conflict. Detach files when a row is soft-deleted, and keep the tombstone TTL and the 24-hour orphan TTL ordered, so a restore does not find the bytes already collected.

## API reference

### Endpoints

`session` means a valid bearer token or the `auth_token` cookie.

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/health` | Liveness probe. Always `200`. | none |
| GET | `/ready` | Readiness probe: policy lock, writer lease, fencing, and dependency probes | none |
| GET | `/auth/login` | Start OIDC login and redirect to the provider | none |
| GET | `/auth/callback` | OIDC authorization-code callback | none |
| GET | `/auth/me` | Session probe: `sub`, `iss`, `aud`, `exp` | session |
| POST | `/auth/logout` | Clear the `auth_token` cookie. Always `204`. | none |
| POST | `/auth/refresh` | Renew the session from the `refresh_token` cookie | refresh cookie |
| POST | `/setup/admin` | One-time bootstrap: grant the caller `superadmin` | session |
| GET | `/policy/rules` | List policy rules | session |
| POST | `/policy/rules` | Add a policy rule | session |
| DELETE | `/policy/rules` | Remove a policy rule | session |
| GET | `/policy/groups` | List groups with member counts | session |
| DELETE | `/policy/groups/{group_name}` | Delete a group and its memberships | session |
| GET | `/policy/groups/{user_id}` | List the groups of a user | session |
| GET | `/policy/groups/{group_name}/users` | List the users of a group | session |
| POST | `/policy/groups` | Assign a user to a group | session |
| DELETE | `/policy/groups/{group_name}/users/{user_id}` | Remove a user from a group | session |
| GET | `/policy/users` | List subjects with their groups | session |
| POST | `/fs/uploads` | Start a multipart upload, owned by the caller | session |
| PUT | `/fs/uploads/{id}/parts/{idx}` | Upload one part as raw bytes | session |
| POST | `/fs/uploads/{id}/complete` | Complete the upload and assemble the parts | session |
| DELETE | `/fs/uploads/{id}` | Cancel an upload | session |
| GET | `/fs/uploads/{id}` | Upload progress | session |
| GET | `/fs/files/{id}/meta` | File metadata | session |
| GET | `/fs/files/{id}` | Download content. Supports `Range`, `206`, and `416`. | session |
| DELETE | `/fs/files/{id}` | Delete a file | session |
| GET | `/sync/status` | Replica pointer and coverage `ETag` | session |
| POST | `/sync/sync` | Advance the replica toward the WAL head | session |
| GET | `/sync/db/{object}` | One replica object with `ETag` and `If-None-Match` | session |
| GET | `/openapi.json` | OpenAPI 3.1 document | none |
| GET | `/swagger-ui/` | Swagger UI for the document | none |

### Auth and errors

Missing or invalid credentials return `401`. A valid subject without permission returns `403`. `/policy/*` requires Casbin permissions in addition to a valid token: `rules` with `read` or `write` for rule endpoints, and `user_groups` with `read` or `write` for group and user endpoints.

Errors use one body shape:

```json
{"error": "stable message"}
```

The server logs the cause and never serializes it. A malformed JSON body also uses this envelope.

Some routes answer outside the envelope. `/auth/login` redirects to the provider. `/auth/callback` and `/auth/refresh` return an `AuthResponse`, because the SPA reads the token from it. `/openapi.json` and `/swagger-ui/*` return documents.

### OpenAPI and client generation

Every API route is in the OpenAPI document at `/openapi.json`, with Swagger UI at `/swagger-ui/`. Generate a client from that document instead of hand-writing request shapes.

```bash
# TypeScript
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

For Rust with progenitor:

```bash
cargo install cargo-progenitor
curl -s http://localhost:8080/openapi.json -o openapi.json
cargo progenitor -i openapi.json -o rust-api-client -n rust-api-client -v 0.1.0
```

Set the client base URL to `public_address`. Send a bearer token or the session cookie on protected calls.

The test `spec_covers_all_served_routes` checks a hand-maintained route list against the document. Add each new route to that list. The `fs` route test checks the reverse for its own paths. Composition tests build the served application in-process and check that the routes answer.

### API versioning

The API is unversioned. Every route uses its bare path, and the OpenAPI document describes that same surface.

The `/v1` prefix is deferred until a breaking change exists. At that point, mount the new contract under `/v1` and keep the unversioned routes serving the previous contract for a deprecation window. Publish the window end date in the changelog and the OpenAPI document. Remove the unversioned routes after the window closes. No client migration is needed before that change.

### Session renewal

`POST /auth/refresh` reads the `refresh_token` cookie and calls the provider refresh grant. On success it returns `200` with an `AuthResponse`, sets a new `auth_token` cookie for seven days, and sets a rotated `refresh_token` cookie when the provider sends one. A missing cookie or a rejected refresh returns `401` with an `AuthResponse`.

The login flow requests the `offline_access` scope, so the provider can issue a refresh token. If it does not, the client must run `/auth/login` again when the ID token expires. Call `/auth/refresh` before `exp` from `/auth/me`. If the call fails, redirect to login.

## Client integration

For a cross-origin SPA, list its origin in `[http].allowed_origins` or `RUST_API_ALLOWED_ORIGINS`. Credentials are always allowed.

### SPA and PWA flow

1. Send the browser to `GET /auth/login`. The callback sets the cookie and returns the token.
2. Call `GET /auth/me` on app load. `200` means the session works. `401` means the session expired. Call `POST /auth/refresh` before `exp`. If refresh fails, redirect to login.
3. Poll `GET /sync/status` with `If-None-Match`. `304` means nothing changed. `200` returns `prefix`, `applied_seq`, `head`, and a new `ETag`.
4. When `applied_seq < head`, call `POST /sync/sync`. If it returns `pending: true`, repeat the call until `pending` is false. Poll `/sync/status` between calls when you need the current coverage.
5. Read `GET /sync/db/manifest.json`, then fetch the objects it lists. Revalidate mutable names.
6. Download files with `GET /fs/files/{id}`. Use `GET /fs/files/{id}/meta` when metadata is needed.

### TypeScript example

```ts
const base = "https://api.example.com";
let token = ""; // from /auth/callback, or rely on the auth_token cookie

// 1. Login is a browser navigation, not fetch.
window.location.href = `${base}/auth/login`;

// 2. Session guard. Refresh before exp when the token is near expiry.
const me = await fetch(`${base}/auth/me`, {
  headers: { Authorization: `Bearer ${token}` },
  credentials: "include",
});
if (!me.ok) window.location.href = `${base}/auth/login`;
const session = await me.json(); // { sub, iss, aud, exp }

// 3. Poll the replica pointer.
let etag = "";
const statusRes = await fetch(`${base}/sync/status`, {
  headers: { "If-None-Match": etag, Authorization: `Bearer ${token}` },
  credentials: "include",
});
if (statusRes.status !== 304) {
  const status = await statusRes.json(); // { prefix, applied_seq, head }
  etag = statusRes.headers.get("ETag") ?? "";

  // 4. Advance the replica.
  if (status.applied_seq < status.head) {
    const syncRes = await fetch(`${base}/sync/sync`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      credentials: "include",
    });
    const sync = await syncRes.json(); // { applied_seq, pending }
    // Repeat POST /sync/sync until pending is false.
  }
}

// 5. Read a replica object.
let manifestEtag = "";
const manifestRes = await fetch(`${base}/sync/db/manifest.json`, {
  headers: { "If-None-Match": manifestEtag, Authorization: `Bearer ${token}` },
  credentials: "include",
});
manifestEtag = manifestRes.headers.get("ETag") ?? "";

// 6. Download a file.
const fileRes = await fetch(`${base}/fs/files/${fileId}`, {
  headers: { Authorization: `Bearer ${token}`, Range: "bytes=0-1023" },
  credentials: "include",
});
```

### Sync client contract

A client that reads a replica must follow these rules. The client owns them. The server streams the bytes unchanged and does not enforce them.

- The `sst` array in `manifest.json` is oldest first. The order is load-bearing.
- Never sort, reorder, filter, deduplicate, or rewrite `sst` entries, by key range or by `seq`.
- Within one key, the last entry whose range covers the key holds the newest record. A reverse walk stops at the first segment that holds the key.
- A tombstone means the key does not exist. A record newer than every segment is not in the `sst` array.
- Replay the `wal` list into an overlay and read the overlay first. The `sst` array alone never yields the current value.
- `seq` is the recoverable form of the order. A manifest written before the field existed decodes with `seq = 0`.
- Three top-level names change under one name: `manifest.json`, `ownership.json`, and `probe/canary`. Revalidate each with `If-None-Match`. Each response carries `Cache-Control: no-cache`.
- The `e{epoch}/sst/*`, `e{epoch}/wal/*`, and `e{epoch}/blob/*` classes are immutable. Cache them with `public, max-age=31536000, immutable`.
- Only these exact names are mutable. A key that merely ends in `manifest.json` is not.
- `oxkv` 0.10 removed the reader pin. Re-open the reader or re-read the manifest when a client needs a view consistent with a moment in time, or snapshot the keys itself.
- `/sync/db/{object}` streams with `Content-Length`. A large SST segment does not need to fit in the server heap.

## Configuration

The server reads one TOML file. Pass it with `--config`.

[config.example.toml](config.example.toml) is the full annotated reference. Module `config` in the rustdoc describes field semantics and validation. The minimal file is in [Configure](#configure).

Optional sections:

```toml
[observability]
service_name = "rust-api"
otlp_endpoint = "http://localhost:4318/v1/traces"
sample_ratio = 1.0

[capability]
secret = "<64 hex chars>"
previous_secret = "<64 hex chars>"

[http]
allowed_origins = ["https://app.example.com", "http://localhost:5173"]

[limits]
rate_per_minute = 600
rate_burst = 120
max_concurrent_downloads = 16
```

The `[database]` section is required. Its fields default to `prefix = "oxkv"`, `writer_lease_ttl_secs = 60`, and `mirror_master = false`. `mirror_master` is a prototype for replica rebuild scans. Use it only with one writer.

Every store uses the one `[s3].bucket`, under `[database].prefix`: `policy`, `fs`, `wal`, and the per-user replicas. The server keeps no local database file.

For local development without S3, set `[s3].backend = "memory"`. The server disables the writer lease for that backend and logs a warning.

The OTLP transport follows the cargo feature. The default `otlp-http` needs an HTTP endpoint such as `http://localhost:4318/v1/traces`. `otlp-grpc` needs a gRPC address such as `http://localhost:4317`.

To rotate a capability key, move the current `secret` to `previous_secret` and deploy a new `secret`. Tokens under either key verify until the five-minute token TTL expires.

### Environment overrides

A variable that is present and not empty wins over the file.

| Variable | Overrides |
|---|---|
| `RUST_API_CLIENT_SECRET` | `authorization.client_secret` |
| `RUST_API_S3_ACCESS_KEY_ID` | `s3.access_key_id` |
| `RUST_API_S3_SECRET_ACCESS_KEY` | `s3.secret_access_key` |
| `RUST_API_CAPABILITY_SECRET` | `capability.secret` |
| `RUST_API_CAPABILITY_SECRET_PREV` | `capability.previous_secret` |
| `RUST_API_ALLOWED_ORIGINS` | `http.allowed_origins`, comma-separated |
| `RUST_API_RABBITMQ_URL` | `rabbitmq.url`, with the `queue-rabbitmq` feature |

### Limits

All limits default to off (`0`). Choose values for your egress budget and client poll interval. A default limit would be a default outage.

| Key | Default | Effect |
|---|---|---|
| `rate_per_minute` | `0` | Token bucket per peer address, applied to every route. Refusals are `429`. |
| `rate_burst` | `0` | Burst capacity. `0` uses `rate_per_minute`. |
| `max_concurrent_downloads` | `0` | Concurrent `GET /sync/db/{object}` requests. |

`max_concurrent_downloads` is the control that matters. One replica object can be a multi-hundred-megabyte SST read. A rate limit does not bound concurrent reads. The response body holds the permit, so a client that stops reading keeps its slot until it disconnects.

The rate limiter keys on the peer address, not the subject. Clients behind one NAT share a budget. See module `limits` in the rustdoc.

## Operations

### Single-writer lease and fencing

The server claims a lease on `[database].prefix` before it opens any store. The lease covers the policy, file, WAL, and replica stores.

| Situation | What happens |
|---|---|
| A second process starts while the lease is live | It refuses to start and names the holder, pid, and wait time. |
| The predecessor crashed | The lease goes stale after `writer_lease_ttl_secs`. The next start takes over and logs the displacement. |
| The predecessor stalls past the TTL | The successor takes over. The predecessor logs an error and `/ready` returns `503`. |
| The server shuts down cleanly | It releases the lease, so a rolling restart hands over without a TTL wait. |
| The lease record cannot be parsed | The server refuses to start. It never overwrites the record. |

The lease renews at one third of the TTL. Set the TTL above the worst pause between renewals, such as a long GC pause or a slow S3 round trip. Set `writer_lease_ttl_secs = 0` only where exactly one process can reach the bucket. The server logs a warning when enforcement is off.

If a primary prefix is fenced anyway, the process latches the loss and `/ready` returns `503`. The server does not exit. The first failure logs one error line that names the prefix. A fenced replica does not latch, because losing a build race is routine.

See modules `lease` and `fencing` in the rustdoc for the protocol.

### Readiness and health

`GET /health` is liveness and always returns `200`. `GET /ready` returns `503` for any of these conditions:

- A writer holds the policy lock.
- The server lost the writer lease.
- A primary prefix was fenced.
- The last background probe of S3 or OIDC failed.

Wire `/ready` to a Kubernetes readiness probe or a load balancer health check. A route that nothing reads does not remove the instance from rotation. This matters most for fencing, because no client sees that error.

### Backups and restore

`policy export` backs up policy rules only. It writes every `p` and `g` rule to JSON. It does not contain file metadata, the change feed, or file bytes. Restoring only policy onto a fresh bucket gives working authorization and an empty filesystem. That looks like total data loss.

| What | Where it lives | How to restore it |
|---|---|---|
| Policy rules | `{db}/policy` | `rust-api policy import` (see [Policy export and import](#policy-export-and-import)). The import is idempotent. |
| File metadata and relations | `{db}/fs` | Copy the prefix objects back. Use S3 bucket versioning, or copy prefixes between buckets. |
| Change feed | `{db}/wal` | Nothing. It is a replay log. A fresh prefix replays from zero. |
| File bytes | User buckets | Your own S3 lifecycle rules. |

There is no automated backup job and no restore drill in this repository. Rehearse both.

### Policy export and import

```bash
rust-api policy export --config config.toml --out backup.json
rust-api policy import --config config.toml --input backup.json
```

Both commands take `--config`, which provides `[s3]` and `[database].prefix`. An import skips rules that already exist. Every entry passes the same validator as a live API write. An import appends its rules to the WAL, so replicas replay them.

Both commands claim the writer lease before they open a store. If a live server holds the lease, the command fails and names the holder. Stop the server first, or wait for the lease to expire.

### Garbage collection

The sweeper runs every hour and reclaims two separate scopes. The scopes hold different objects and never overlap.

| Scope | Reaps | Rule | On failure |
|---|---|---|---|
| Application bytes | Objects under `files/{id}` | No upload session and no file row reference the object, and it is older than 24 hours. A metadata decode failure skips the whole pass. | A failed delete keeps the item for the next sweep. |
| Store WAL | `e{6+ digits}/wal/{8 digits}.log` objects under the store prefix | The manifest does not list the object. A failed manifest compare-and-swap can strand one. | A failed list or delete shortens the pass. A fenced store deletes nothing. |

The sweep returns the count of application items it removed. The store pass logs its own count. A store-pass failure is a warning, because it deletes only unreachable objects and a failure costs storage, not data.

### Telemetry and logging

Console logging is always on. `RUST_LOG` sets the filter. Without it, `--verbose` selects debug and the default selects info.

```bash
RUST_LOG=debug cargo run -- serve --config config.toml
```

When `observability.otlp_endpoint` is set, the server exports one span per request and batch-exports metrics. A span carries the method, route template, status code, and latency. A `5xx` marks the span as an error. W3C Trace Context propagates inbound `traceparent` headers.

Verify the exporter once against a real collector. A misconfigured exporter fails silently. For example:

```bash
docker run -p 4317:4317 -p 4318:4318 grafana/otel-lgtm
```

Use port 4317 with the `otlp-grpc` feature and port 4318 with the default `otlp-http` feature.

### Production checklist

- [ ] Set `[limits].rate_per_minute` and `rate_burst` for your client traffic.
- [ ] Set `[limits].max_concurrent_downloads`. A rate limit does not bound large SST reads.
- [ ] Put a reverse proxy or WAF in front of the binary. Throttle `/auth/*`, `/setup/*`, and `/policy/*` per IP. Keep `/fs` and `/sync` reads generous.
- [ ] Never expose the binary directly to the internet without that layer.
- [ ] Set `[database].writer_lease_ttl_secs` above the worst pause between renewals. Use `0` only for a single process.
- [ ] Configure `[capability].secret` or `RUST_API_CAPABILITY_SECRET`, so capability tokens survive a restart.
- [ ] Wire `/ready` to a probe that drains traffic.

Example nginx limits:

```nginx
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

Tune the rates to your provider latency and admin headcount.

### Migration from Redb

Versions before `988873c` kept every domain in one local Redb file named by `[database].path`. The current version removed that key. It stores policy, file metadata, the change feed, and replicas as prefix-scoped objects under `[database].prefix`. The server does not read old `*.redb` files and provides no automatic migration.

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
prefix = "oxkv"

[s3]
bucket = "my-bucket"
region = "us-east-1"
```

Only `[database]` changes. `[s3]` was already required for file bytes.

Manual steps:

1. Export the old policy rules with the old binary:
   ```bash
   rust-api policy export --store /var/lib/rust-api/policy.redb --out policy-backup.json
   ```
   The export contains every `p` and `g` rule. It does not contain file metadata, relations, or the change feed.
2. Stop the old server.
3. Update the configuration. Pick a fresh `[database].prefix`.
4. Import the rules into the new prefix:
   ```bash
   rust-api policy import --config config.toml --input policy-backup.json
   ```
   The import creates the policy store and appends the rules to the WAL, so replicas replay them. It is idempotent.
5. Start the new server. It creates the other stores under the new prefix.
6. If you have no export, skip step 4. After step 5, log in, call `POST /setup/admin` once, then recreate rules and group memberships.
7. File metadata does not migrate. Old file records and relations have no import path. File bytes already in S3 stay in their buckets, but the new server has no metadata for them. Re-upload the files, or let the hourly GC remove the orphan bytes after 24 hours.
8. The change feed starts at zero. Replicas rebuild from the current master state.
9. Keep the old `*.redb` and `*.redb.fs` files until the new deployment works. Remove them after that.

The new binary ignores a leftover `[database].path` key and uses `[database].prefix`. It never opens the old file. Treat the upgrade as a fresh data plane plus an import of policy rules.

### Security advisories

`mise run advisories` passes because `deny.toml` contains documented suppressions for ten advisories. An advisory outside that list fails the check. `lib::tests::every_ignore_is_justified` fails an entry without a substantive reason. Re-examine the list when `oxkv`, `actix-web`, or `casbin` moves.

One suppression is reachable: `h2` 0.3 is compiled in because actix-web enables HTTP/2, and no actix-web release can take the fix yet. Terminate HTTP/2 in front of this process, or bound memory. The others are low exposure, unmaintained, or have no patched version.

See [deny.toml](deny.toml) for each reason and [SECURITY.md](SECURITY.md) for the reporting policy.

## Extending the server

Implement `ApiModule` and register it on `ApiService`:

```rust
use rust_api::http::ApiModule;

struct MyModule;

impl ApiModule for MyModule {
    fn prefix(&self) -> &str {
        "/my-scope"
    }

    fn configure(&self, cfg: &mut actix_web::web::ServiceConfig) {
        cfg.service(
            actix_web::web::scope("/my-scope").route("", actix_web::web::get().to(my_handler)),
        );
    }
}
```

A module owns one prefix. `ApiService` refuses a duplicate prefix before it registers anything. Handlers extract validated claims with `Validated<C>`, which returns `401` when claims are absent.

Examples:

- [examples/sample_module.rs](examples/sample_module.rs): a complete module. Build with `cargo build --example sample_module`.
- [examples/job_queue.rs](examples/job_queue.rs): a memory queue and worker.
- [examples/reactive_service.rs](examples/reactive_service.rs): a reactive service with an `oxkv` observer.

### Mount inside your own server

`ApiService::start` owns the listener. To keep your own listener, apply the same global stack yourself:

```rust
use std::sync::Arc;
use actix_web::{App, HttpServer};
use rust_api::http;

// svc is your ApiService. allowed_origins and bucket come from the config.
let svc = Arc::new(svc);
HttpServer::new(move || {
    let svc = Arc::clone(&svc);
    http::apply_limits(App::new())
        .wrap(http::cors(&allowed_origins))
        .wrap(http::middleware::request_id::RequestIdMiddleware)
        .wrap(actix_web::middleware::Compress::default())
        .wrap(http::middleware::request_tracing::RequestTracingMiddleware)
        .wrap(http::middleware::bearer_token::BearerTokenMiddleware)
        .wrap(rust_api::limits::RateLimit::new(bucket.clone()))
        .configure(http::health_routes)
        .configure(move |cfg| svc.configure(cfg).expect("duplicate route prefix"))
        .configure(http::docs::config) // /openapi.json + /swagger-ui
})
.run()
.await?;
```

`svc.configure` returns `Result<_, DuplicateRoutePrefix>`. The actix configure closure returns `()`, so handle the error at that point. Build one `App` per worker, as `HttpServer::new` does here. Mount `http::docs::config` last. A catch-all mount registered earlier can shadow your modules.

## Development

Build, test, lint, documentation, and commit rules are in [CONTRIBUTING.md](CONTRIBUTING.md). This section covers only the test suites, benchmarks, and releases.

### Integration tests

The fast tests run in-process. wiremock mocks the identity provider and S3, so they need no containers and no network. Run them with `mise run test`.

A separate harness runs against MinIO and a mock OIDC provider over the full HTTP stack:

```bash
docker compose -f docker-compose.test.yml up -d
cargo test --test integration -- --ignored
docker compose -f docker-compose.test.yml down
```

The smoke tests cover boot and `/health`, login, `/setup/admin`, a real S3 upload and download, and a policy rule.

### Contract tests

Contract tests check behavior that wiremock cannot reproduce: JWKS rotation, lease compare-and-set, S3 multipart restart, and GC. They are env-gated and ignored by default.

The suite needs a real OIDC provider that publishes a JWKS document, and an S3-compatible bucket. Set `CONTRACT_TESTS=1` plus `CONTRACT_IDP_ISSUER_URL`, `CONTRACT_IDP_CLIENT_ID`, `CONTRACT_IDP_CLIENT_SECRET`, `CONTRACT_S3_ENDPOINT`, `CONTRACT_S3_BUCKET`, `CONTRACT_S3_ACCESS_KEY_ID`, `CONTRACT_S3_SECRET_ACCESS_KEY`, and `CONTRACT_S3_REGION`. A test skips itself when a required variable is unset.

```bash
CONTRACT_TESTS=1 \
CONTRACT_IDP_ISSUER_URL=https://idp.example.com \
CONTRACT_IDP_CLIENT_ID=client-id \
CONTRACT_IDP_CLIENT_SECRET=client-secret \
CONTRACT_S3_ENDPOINT=https://s3.example.com \
CONTRACT_S3_BUCKET=rust-api-contract \
CONTRACT_S3_ACCESS_KEY_ID=access-key \
CONTRACT_S3_SECRET_ACCESS_KEY=secret-key \
CONTRACT_S3_REGION=us-east-1 \
cargo test --test contract -- --ignored
```

Run one area with a name filter:

```bash
cargo test --test contract jwks -- --ignored
cargo test --test contract lease -- --ignored
cargo test --test contract multipart -- --ignored
cargo test --test contract gc -- --ignored
```

Contract tests mutate real buckets. Use a dedicated bucket and clean it between runs.

### Benchmarks

Criterion benchmarks measure the three hot paths that scale with data size:

- `sync_replay`: replay a bounded WAL range into one replica.
- `replica_build`: filter, diff, and commit one full replica.
- `policy_eval`: one Casbin decision, including row and file checks.

```bash
cargo bench
cargo bench sync_replay
cargo bench replica_build/1000_ops
cargo bench policy_eval/1000_rules
```

CI baselines on 2 vCPU, 4 GiB RAM, and an in-memory store: `sync_replay` 12 ms at 1,000 ops and 95 ms at 10,000 ops, `replica_build` 450 ms cold and 180 ms warm at 10,000 files, and `policy_eval` 80 µs at 1,000 rules and 620 µs at 10,000 rules. A change above 10% needs an explanation in the commit message.

### Releases

[cargo-dist](https://opensource.axo.dev/cargo-dist/) builds the release archives. Its configuration is in `dist-workspace.toml` at version 0.32.0, with `ci = "github"` and no installers. Targets are `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`, and `x86_64-pc-windows-msvc`.

```bash
mise run dist-plan     # print the artifact plan
mise run dist-build    # build the archives into dist/
```

The `cargo-dist` pin in `mise.toml` must track `cargo-dist-version` in `dist-workspace.toml`. The generated workflow is checked in at `.github/workflows/release.yml`. Run `dist init --ci=github` to regenerate it at the pinned version. That command overwrites the local edits in the file.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
