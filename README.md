# rust-api

A starter-kit REST API server providing pluggable modules for OIDC authentication, JWT session validation, and Casbin-based authorization, built on [Actix Web](https://actix.rs/).

The crate is intentionally business-logic free: applications compose `ApiModule` implementations onto an `ApiService` to build their own API surface on top of the shared auth/policy plumbing.

## Features

- **OIDC authentication** — authorization-code flow with PKCE, CSRF state, and nonce validation against any spec-compliant identity provider (Keycloak, Entra ID, Auth0, …)
- **JWT validation via JWKS** — refreshable multi-algorithm key store with rotation support; unknown `kid` triggers a debounced re-fetch of the provider's keys
- **Casbin RBAC on OxKV OxKvStore** — permission rules and group membership backed by a prefix-scoped [`oxkv::OxKvStore`](https://docs.rs/oxkv) (`{prefix}/policy` inside the configured S3 bucket via `object_store::aws::AmazonS3`); one `OxKvStore` per domain sharing a single `AmazonS3Builder` setup (`db.rs`); no local Redb file required
- **Validated persistence** — every rule write is validated through `policy::adapter::encode_rule` / `PolicyRuleValidator` (`{sec}:{ptype}:{hash}` key shape, JSON array value, arity 3 for `p` / 2 for `g`) before any transaction opens; malformed rules fail at the API boundary instead of poisoning startup
- **Single-live-handle-per-prefix** — each `OxKvStore` owns a fencing session (memtable/WAL buffer); two live handles on the same prefix can fence/diverge on real S3 — share via `Arc` instead of building a second one (`db::build_s3_store` docs); tests use `InMemory`-backed `OxKvStore` with `skip_probe(true)` and `build_test_store_new_session` for single-threaded reopen
- **Modular row-level authorization** — business rows authorize as `{type}:{id}` objects via `policy::row::RowAuthorizer`; files delegate to owning rows instead of a coarse `fs` gate
- **Temp per-user file scope with refcount relations** — uploads start as temp owned by `owner_sub` (`refs==0`), `attach`/`detach` to rows via `fs:rel:{type}:{id}:{file}` increments/decrements `fs:files:{id}:refs` inside the `{prefix}/fs` `OxKvStore`; editing a row swaps relations, never deletes the underlying S3 object immediately
- **Capability tokens** — short-lived HMAC JWT (`fs/token.rs`, 5m) minted after row authorization, verified on file ops without extra policy hits
- **GC for orphans** — hourly sweeper removes abandoned upload sessions and temp/orphaned files (`refs==0` and `age>24h` or `orphan_since>24h`).
- **Per-user filtered replicas with WAL (S3, oxkv manifest)** — WAL lives as `wal:{seq:020}` + `wal:seq` inside an `OxKvStore`; each user owns one replica prefix (`{db}/u/{sub}/`) holding their filtered file set with its own oxkv `manifest.json` (the segment list); `GET /sync/clone` returns the replica pointer with an `ETag` (repeat polls get `304`), and every object inside the prefix is individually cached at `GET /sync/db/{object}` with backend `ETag` passthrough and `If-None-Match` support — DASH-style: manifest plus immutable segments. `clone` short-circuits when coverage already meets the WAL head; deltas of ≤1000 file/relation ops replay onto the live prefix, while policy changes, larger deltas, or fencing losses fall back to full recalc (or adopt the winner's coverage).
- **WAL-instrumented mutations** — `FsEngine` (complete/attach/detach/delete) and `PolicyEngine` (rule/group changes, including `policy import`) append to one shared `Wal` after each mutation commits (fail-closed: a logging failure fails the whole operation, so the WAL never silently misses a write); concurrent appends serialize on a mutex shared by all handles. Engines without a wired WAL log nothing (tests).
- **Transactional replica builds** — snapshots filter into a RAM scratch store, diff against the live replica, and commit the diff plus the coverage marker in one transaction: a crash before commit leaves the old state untouched (oxkv replays only listed WALs on open), and an empty diff commits nothing — mid-broken writes are handled by the engine, not app scaffolding.
- **Modular composition** — implement the `ApiModule` trait and register onto `ApiService`; auth middleware is applied per module scope
- **Observability** — structured console logging through the `tracing` facade (`RUST_LOG` syntax), plus optional OpenTelemetry span export over OTLP/gRPC with W3C Trace Context propagation

## API endpoints

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/health` | Liveness probe | none |
| GET | `/auth/login` | Start OIDC login (redirects to provider) | none |
| GET | `/auth/callback` | OIDC authorization-code callback | none |
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
| GET | `/fs/files/{id}` | Download file content (owner or row Read) | Bearer token |
| DELETE | `/fs/files/{id}` | Delete file (owner when temp, or row Delete) | Bearer token |
| GET | `/sync/clone` | Replica pointer + coverage ETag (short-circuit, replay, or full recalc) | Bearer token |
| GET | `/sync/db/{object}` | One replica object (manifest/SST/WAL/blob) with ETag + `If-None-Match` | Bearer token |

Protected routes accept either an explicit `Authorization: Bearer <token>` header (preferred) or the session cookie set by `/auth/callback`. Requests without valid credentials get `401`; insufficient permissions get `403`. All errors use a uniform JSON envelope: `{"error": "<message>"}`.

### First-run bootstrap

A fresh deployment boots with an empty policy store, so nobody can pass the self-authorization checks on `/policy` routes yet. Log in through `/auth/login`, then call `POST /setup/admin` **once** with your token: the first authenticated subject to do so becomes `superadmin` (`201`); every later call returns `409`, including after restarts. From there, grant permissions to groups and manage membership via the normal policy endpoints.

## Architecture

```
src/
├── main.rs              binary entry point: config → telemetry → OIDC/policy/fs/sync wiring → listener
├── lib.rs               crate root and documentation
├── config.rs            TOML configuration model ([database].prefix, [s3] bucket/prefix)
├── db.rs                OxKV OxKvStore factory — one AmazonS3Builder for file bytes + OxKvStore; build_s3_store / build_test_store / build_test_store_new_session / build_scratch_store; single-live-handle-per-prefix contract
├── telemetry.rs         tracing subscriber + OTLP span export bootstrap
├── http/                HTTP scaffolding shared by all modules
│   ├── mod.rs           ApiService registry + ApiModule trait
│   ├── error.rs         ApiError enum and uniform JSON error envelope
│   ├── health.rs        /health
│   └── middleware/      bearer_token, jwt (JWKS-backed claims), request_tracing
├── oidc/                OIDC client: /auth/login + /auth/callback (code flow, PKCE)
├── policy/              Casbin engine, oxkv adapter + validator, management routes
│   ├── adapter.rs       OxkvAdapter<S: Store> + PolicyRuleValidator + encode_rule() (validates before tx)
│   ├── admin.rs         export_s3 / import_s3 (OxKvStore, not file)
│   ├── mod.rs           PolicyEngine::init_s3 / init_with_store (prefix-scoped OxKvStore)
│   ├── row.rs           RowAuthorizer trait for {type}:{id} objects
│   ├── route.rs         /policy/* handlers
│   └── setup.rs         /setup/admin one-time superadmin claim
├── sync/                Per-user replicas (stable OxKvStore prefixes + manifest, WAL-backed)
│   ├── wal.rs           Wal on OxKvStore — WalOp::{PolicyAdd,PolicyRemove,Attach,Detach,FileCreate,FileDelete}, wal:{seq:020} + wal:seq, serialized appends
│   ├── snapshot.rs      SnapshotManager — one filtered replica per user ({db}/u/{sub} + sync:applied marker), tx-atomic rebuilds, idempotent replay
│   └── route.rs         GET /sync/clone (pointer + ETag) + GET /sync/db/{object} (segments + ETags)
└── fs/                  Object-store file storage (AmazonS3/MinIO/R2 via object_store, InMemory for tests)
    ├── mod.rs           FsEngine (temp per-user, row delegation, token mint/verify)
    ├── relation.rs      RefInfo + fs:rel:{type}:{id}:{file} + fs:files:{id}:refs
    ├── token.rs         FsClaims HMAC JWT (5m)
    ├── store.rs         FsStore on OxKvStore (fs:uploads:{id}:meta, fs:files:{id}:meta, staged parts)
    ├── gc.rs            hourly sweep for sessions + orphaned files (refs==0, 24h TTL)
    ├── s3.rs            S3Client trait + S3ClientConfig
    ├── object_store.rs  ObjectStoreClient + shared s3_builder() for OxKvStore + file bytes
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

> **Single-live-handle-per-prefix:** each `OxKvStore` owns a fresh fencing session (memtable/WAL buffer). Two live handles on the same prefix can fence each other or diverge on real S3. Share the handle via `Arc` — do not build a second one. Tests use `db::build_test_store` (fresh `InMemory` per prefix) and `build_test_store_new_session` for single-threaded reopen (new session superseding the previous one).

### Row-level and file delegation

Business rows authorize as `{row_type}:{row_id}` via `RowAuthorizer` (`policy/row.rs`). Files are not gated by a coarse `fs` object; instead:

- `POST /fs/uploads` creates a temp file owned by `owner_sub` (`refs==0`) in the `{prefix}/fs` `OxKvStore` (`fs:uploads:{id}:meta`, staged parts `fs:uploads:{id}:part:{idx}`).
- `FsEngine::attach(row_type,row_id,file_id,caller)` requires `Write` on `{row_type}:{row_id}` and increments `fs:files:{id}:refs` + writes `fs:rel:{type}:{id}:{file}`.
- `FsEngine::detach` decrements and sets `orphan_since` when `refs==0`.
- Reads/deletes check `owner_sub == caller` (temp) or any owning row grants `Read`/`Delete`. Editing a row is `detach(old)+create new+attach(new)` — the old S3 object becomes orphan and is removed by GC after 24h.
- After row authorization, a short-lived HMAC token (`fs/token.rs`) can be minted for direct `PUT`/`GET` without extra policy hits. File bytes live in S3 via `object_store` (`AmazonS3` in production, `InMemory` in tests).

### Per-user replicas (WAL)

The master `FsStore` and `Wal` both live on prefix-scoped `OxKvStore`s and remain the sole write path. `Wal` appends `wal:{seq:020}` entries plus `wal:seq` head (`sync/wal.rs`, `WalOp::{PolicyAdd,PolicyRemove,Attach,Detach,FileCreate,FileDelete}`). Each user owns one replica prefix (`{db}/u/{sub}/`) holding their filtered file set with its own oxkv `manifest.json` (the segment list): builds filter through `RowAuthorizer`/`owner==sub` into a RAM scratch store, diff against the live replica, and commit the diff plus the `sync:applied` coverage marker in a single transaction — so a crash before commit leaves the old state untouched and an empty diff commits nothing at all. `GET /sync/clone` returns the replica pointer with a coverage `ETag` (repeat polls get `304` without touching storage beyond the marker read), and `GET /sync/db/{object}` serves one replica object with backend `ETag` passthrough and `If-None-Match` support — engine files are immutable by construction (`Cache-Control: immutable`), only `manifest.json` is revalidated. Wasm clients open an `OxKvReader` over the prefix and follow the live manifest.

Every master mutation is also appended to the shared `Wal` (`{db}/wal`): file creates/deletes and attach/detach from `FsEngine`, rule/group changes from `PolicyEngine` (including `policy import`), each after the mutation commits — a logging failure fails the whole operation, and concurrent appends serialize on a mutex shared by all engine handles. `GET /sync/clone` short-circuits when coverage already meets the WAL head; otherwise deltas of ≤1000 file/relation ops replay onto the live prefix (ops re-applied with visibility re-checked, marker last — a crash heals on the next poll), while policy changes, larger deltas, or fencing losses fall back to full recalc — or adopt the winner's coverage on a lost build race. No version GC is needed: there is only ever one prefix per user, maintained by oxkv's own WAL GC and compaction.

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
                                            # replicas → {prefix}/u/{sub}; no local file

[s3]
bucket = "my-bucket"                          # S3 bucket (AmazonS3 via object_store; InMemory for tests)
region = "us-east-1"
# endpoint_url = "http://localhost:9000"      # MinIO/R2 endpoint; omit for AWS
# force_path_style = true                       # required for MinIO
# access_key_id = "minioadmin"
# secret_access_key = "minioadmin"

# Optional — omit the whole section to disable span export.
[observability]
service_name = "rust-api"                   # resource attribute on exported telemetry
otlp_endpoint = "http://localhost:4317"     # OTLP/gRPC collector endpoint
sample_ratio = 1.0                          # fraction of traces sampled (0.0–1.0, default 1.0)
```

Single bucket, prefix-scoped stores: `db::build_s3_store` builds one `AmazonS3` `ObjectStore` from `[s3]` and wraps it with `OxKvStore::builder().with_object_store(...).with_prefix("oxkv/policy")` etc. via the shared `fs::object_store::s3_builder`. Breaking change since `988873c`: `[database].path` (Redb file) is gone — use `[database].prefix`; old `*.redb` files are no longer read (no automatic migration).

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

When `observability.otlp_endpoint` is configured, one span is emitted per request (method, route template, status code, latency; 5xx marked as error) and batch-exported to any OTLP/gRPC collector. Inbound `traceparent` headers are extracted through the globally registered W3C Trace Context propagator, so requests from upstream instrumented services continue the same distributed trace. For example, with the Grafana LGTM stack:

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
    fn configure(&self, cfg: &mut actix_web::web::ServiceConfig) {
        cfg.service(actix_web::web::scope("/my-scope")
            .service(my_handler));
    }
}
```

Handlers can extract validated JWT claims via the `Validated<C>` extractor (returns 401 automatically when claims are absent). See the crate documentation (`cargo doc --no-deps --open`) for details.
## Development

```bash
mise exec -- cargo test                 # run tests (wiremock-based integration tests included; FsStore/PolicyEngine use InMemory-backed OxKvStore)
mise exec -- cargo clippy --all-targets # lint (all targets, -D warnings; unwrap/expect denied in non-test code)
mise exec -- cargo doc --no-deps        # generate docs
mise exec -- cargo deny check licenses  # verify dependency licenses stay compatible
mise exec -- cargo deny check advisories
mise exec -- cargo deny check bans
mise run cov                            # coverage via cargo llvm-cov (mise task)
```

Every public item must carry rustdoc — enforced at compile time via `[lints.rust] missing_docs = "deny"` in `Cargo.toml`.
Dependency licensing is enforced via [`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) (`deny.toml`: `licenses` + `advisories` + `bans`); any new dependency whose license is not permissive fails the check.
`oxkv` 0.7 (`oxkv` + `oxkv-s3` features) + `object_store` 0.12 (shared `AmazonS3Builder` for file bytes and `OxKvStore`).

Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/) style without scopes (e.g. `feat:`, `fix:`, `docs:`).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
