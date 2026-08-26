# rust-api

A starter-kit REST API server providing pluggable modules for OIDC authentication, JWT session validation, and Casbin-based authorization, built on [Actix Web](https://actix.rs/).

The crate is intentionally business-logic free: applications compose `ApiModule` implementations onto an `ApiService` to build their own API surface on top of the shared auth/policy plumbing.

## Features

- **OIDC authentication** — authorization-code flow with PKCE, CSRF state, and nonce validation against any spec-compliant identity provider (Keycloak, Entra ID, Auth0, …)
- **JWT validation via JWKS** — refreshable multi-algorithm key store with rotation support; unknown `kid` triggers a debounced re-fetch of the provider's keys
- **Casbin RBAC on an embedded oxkv database** — permission rules and group membership management backed by a transactional key-value store persisted to a single file; no external database server required
- **Modular composition** — implement the `ApiModule` trait and register onto `ApiService`; auth middleware is applied per module scope
- **Observability** — structured console logging through the `tracing` facade (`RUST_LOG` syntax), plus optional OpenTelemetry span export over OTLP/gRPC with W3C Trace Context propagation

## API endpoints

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/health` | Liveness probe | none |
| GET | `/auth/login` | Start OIDC login (redirects to provider) | none |
| GET | `/auth/callback` | OIDC authorization-code callback | none |
| GET | `/policy/rules` | List policy rules | Bearer token |
| POST | `/policy/rules` | Add a policy rule | Bearer token |
| DELETE | `/policy/rules` | Remove a policy rule | Bearer token |
| GET | `/policy/groups/{user_id}` | List groups of a user | Bearer token |
| GET | `/policy/groups/{group_name}/users` | List users of a group | Bearer token |
| POST | `/policy/groups` | Assign a user to a group | Bearer token |
| DELETE | `/policy/groups/{group_name}/users/{user_id}` | Remove a user from a group | Bearer token |

Protected routes accept either an explicit `Authorization: Bearer <token>` header (preferred) or the session cookie set by `/auth/callback`. Requests without valid credentials get `401`; insufficient permissions get `403`. All errors use a uniform JSON envelope: `{"error": "<message>"}`.

## Architecture

```
src/
├── main.rs              binary entry point: config → telemetry → OIDC/policy wiring → listener
├── lib.rs               crate root and documentation
├── config.rs            TOML configuration model
├── telemetry.rs         tracing subscriber + OTLP span export bootstrap
├── endpoint/            HTTP scaffolding shared by all modules
│   ├── mod.rs           ApiService registry + ApiModule trait
│   ├── error.rs         ApiError enum and uniform JSON error envelope
│   ├── middleware/      bearer_token, jwt (JWKS-backed claims), request_tracing
│   └── route/           /health
├── oidc/                OIDC client: /auth/login + /auth/callback (code flow, PKCE)
└── policy/              Casbin engine, oxkv adapter + validator, management routes
```

Modules implement [`ApiModule`](src/endpoint/mod.rs) and are registered onto `ApiService`; each module brings its own middleware stack (e.g. `/policy/*` requires validated JWT claims).

## How authorization works

The Casbin RBAC model is:

```ini
p = sub, obj, act        # permission rule: subject may act on object
g = _, _                 # group membership: user belongs to group
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

A request is authorized when its subject either holds a matching `p`-rule directly or belongs to a group (`g`-link) that does. Typical setup: grant permissions to *groups* via `POST /policy/rules`, then manage membership via the `/policy/groups` endpoints.

Rules persist to the embedded [oxkv](https://docs.rs/oxkv) store (`[database].path`) as one key-value pair per rule, written transactionally. An oxkv validation hook rejects malformed writes at the API boundary — wrong-arity rules, non-JSON payloads, or unknown sections fail immediately instead of sitting in storage until they poison startup.

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
path = "data/rust-api.redb"                 # embedded oxkv policy store (created if missing)

# Optional — omit the whole section to disable span export.
[observability]
service_name = "rust-api"                   # resource attribute on exported telemetry
otlp_endpoint = "http://localhost:4317"     # OTLP/gRPC collector endpoint
```

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

Policies can be exported to JSON for backups and re-imported into a fresh store (e.g. when moving hosts):

```bash
rust-api policy export --store data/rust-api.redb --out backup.json
rust-api policy import --store data/rust-api.redb --in backup.json
```

Imports are idempotent — already-present rules are skipped — and every entry passes the same validation hook as live API writes.

## Extending the API

Implement `ApiModule` and register it on the service:

```rust
use rust_api::endpoint::ApiModule;

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
mise exec -- cargo test                 # run tests (wiremock-based integration tests included)
mise exec -- cargo clippy --all-targets # lint
mise exec -- cargo doc --no-deps        # generate docs
mise exec -- cargo deny check licenses  # verify dependency licenses stay compatible
```

Every public item must carry rustdoc — enforced at compile time via `[lints.rust] missing_docs = "deny"` in `Cargo.toml`.
Dependency license compatibility is enforced via [`cargo-deny`](https://embarkstudios.github.io/cargo-deny/) (`deny.toml`): any new dependency whose license is not permissive fails the check.

Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/) style without scopes (e.g. `feat:`, `fix:`, `docs:`).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
