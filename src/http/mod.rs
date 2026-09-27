//! HTTP server scaffolding: a modular service registry plus the request
//! middleware every module builds on (bearer-token extraction, JWKS-backed
//! JWT validation, per-request tracing) and the shared body-size limits.
//!
//! [`ApiService`](crate::http::ApiService) composes
//! [`ApiModule`](crate::http::ApiModule) implementations into one Actix
//! application; [`cors`](crate::http::cors) and
//! [`health`](crate::http::health) hold the edge settings and probes that
//! are not module-specific.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{App, HttpServer, web};

/// OpenAPI JSON + Swagger UI.
pub mod docs;
/// Shared error type rendering a uniform JSON error envelope.
pub mod error;

use error::ApiError;
/// Built-in liveness probe shared by every deployment.
pub mod health;
/// Request middleware for token extraction and validation.
pub mod middleware;

/// Maximum raw request body: covers 10 MiB single-part uploads plus
/// headroom. Without this the `Bytes` extractor falls back to actix's
/// 256 KiB default and rejects every documented part size with 413.
/// Shared with the FS part intake, which streams `Payload` directly and
/// must enforce the same absolute ceiling chunk by chunk.
pub(crate) const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Maximum JSON body: control-plane payloads (policy rules, upload
/// metadata) are small; anything larger is a misuse or abuse signal.
const MAX_JSON_BYTES: usize = 1024 * 1024;

/// Grace period for in-flight requests to finish during shutdown.
const SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// Slow-client guard: time allowed to send request headers/body.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Applies the shared body-size limits to an Actix application.
///
/// Split out so the limits are unit-testable, and public so a host app
/// mounting the API in its own `App` can apply the same ceilings — see
/// [`ApiService::configure`] for the full recipe.
pub fn apply_limits<T>(app: App<T>) -> App<T>
where
    T: actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Error = actix_web::Error,
            InitError = (),
        >,
{
    app.app_data(web::PayloadConfig::new(MAX_PAYLOAD_BYTES))
        .app_data(
            web::JsonConfig::default()
                .limit(MAX_JSON_BYTES)
                .error_handler(|err, _| {
                    // Actix's default for a malformed body is a bare `400 Bad
                    // Request` in text/plain, which is the one way a documented
                    // route can answer outside the uniform envelope -- and it is
                    // reached by any client that sends a truncated or mistyped
                    // payload, i.e. routinely. The extractor's message names the
                    // offending field and the expected type, so it is logged and
                    // not sent, same contract as every other cause in this crate.
                    tracing::debug!("malformed JSON body: {err}");
                    ApiError::BadRequest.into()
                }),
        )
}

/// Logs a mid-stream response body failure server-side.
///
/// By the time a body chunk fails, the response head is already on the
/// wire and the status cannot be changed: the client sees a truncated
/// body and nothing else. This is the only place the operator finds out
/// why, so every streaming body should pass through it.
///
/// Generic over the error type because the two streaming sources report
/// different ones -- [`FsError`](crate::fs::error::FsError) for file
/// downloads, `object_store::Error` for raw replica objects -- and neither
/// should be translated just to be logged.
pub fn logged_body<S, E>(stream: S) -> impl futures_util::Stream<Item = Result<bytes::Bytes, E>>
where
    S: futures_util::Stream<Item = Result<bytes::Bytes, E>>,
    E: std::fmt::Debug,
{
    use futures_util::TryStreamExt as _;
    stream.map_err(|e| {
        tracing::warn!("response body stream failed: {e:?}");
        e
    })
}

/// Registers the built-in probe routes shared by every deployment.
pub fn health_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(health::health);
    cfg.service(health::ready);
}

/// Builds the CORS middleware for browser clients.
///
/// Empty `allowed_origins` disables CORS responses (same-origin only).
/// Each origin must be an exact `http(s)` origin without trailing slash;
/// credentials are always allowed so the `auth_token` cookie and
/// `Authorization` bearer header work cross-origin. `ETag` and range
/// headers are exposed so `/sync/db/*` conditional polls and `/fs`
/// ranged downloads work from the browser.
pub fn cors(allowed_origins: &[String]) -> actix_cors::Cors {
    use actix_web::http::header;
    let mut cors = actix_cors::Cors::default()
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::IF_NONE_MATCH,
            header::RANGE,
            header::CONTENT_LENGTH,
        ])
        .allowed_header("x-checksum-sha256")
        .allowed_header("checksum-sha256")
        .expose_headers(vec![
            header::ETAG,
            header::CONTENT_RANGE,
            header::ACCEPT_RANGES,
        ])
        .supports_credentials()
        .max_age(3600);
    for origin in allowed_origins {
        cors = cors.allowed_origin(origin);
    }
    cors
}

/// A self-contained unit of the API surface: a set of routes plus its own
/// app data and middleware. Implement this to plug business functionality
/// into an [`ApiService`].
pub trait ApiModule: Send + Sync {
    /// The single route prefix this module owns, e.g. `/fs`.
    ///
    /// Declared so [`ApiService::configure`] can refuse to mount two
    /// modules on the same prefix. Actix matches services in registration
    /// order and a scope matches its whole prefix rather than the paths it
    /// declares, so the second module's routes are not merged with the
    /// first's -- they are unreachable, and the symptom is a `404` on a
    /// route that is documented, present in the OpenAPI document, and
    /// covered by a passing unit test that happens to mount the module
    /// alone.
    ///
    /// Return the empty string for a module that mounts only top-level
    /// routes (`/health`, `/openapi.json`); such a module still conflicts
    /// with any other empty-prefix module.
    fn prefix(&self) -> &str;

    /// Registers this module's scopes, services, and app data on the Actix
    /// application configuration.
    fn configure(&self, cfg: &mut web::ServiceConfig);
}

/// Two modules declared the same [`ApiModule::prefix`].
#[derive(Debug, thiserror::Error)]
#[error(
    "two API modules both claim the route prefix `{prefix}`: the first \
     registered answers every `{prefix}`/* request and the second's routes \
     are unreachable. Merge them into one module, or give one a different prefix."
)]
pub struct DuplicateRoutePrefix {
    /// The contested prefix.
    pub prefix: String,
}

/// Rejects a module set in which two modules claim the same
/// [`ApiModule::prefix`].
///
/// Called before anything is mounted, so a rejected composition leaves no
/// half-registered routes behind.
fn check_prefixes(modules: &[Box<dyn ApiModule>]) -> Result<(), DuplicateRoutePrefix> {
    let mut seen: Vec<&str> = Vec::with_capacity(modules.len());
    for module in modules {
        let prefix = module.prefix();
        if seen.contains(&prefix) {
            return Err(DuplicateRoutePrefix {
                prefix: prefix.to_string(),
            });
        }
        seen.push(prefix);
    }
    Ok(())
}

/// Mounts the modules and readiness probe onto a `ServiceConfig`.
///
/// Infallible by contract: [`check_prefixes`] has already rejected
/// collisions, and both call sites run it first.
///
/// Shared by [`ApiService::configure`] and [`wired_app!`] so the public
/// composable path and the served path cannot drift.
fn register_modules(
    modules: &[Box<dyn ApiModule>],
    readiness: &Option<health::ReadyCheck>,
    cfg: &mut web::ServiceConfig,
) {
    for module in modules {
        module.configure(cfg);
    }
    if let Some(check) = readiness {
        cfg.app_data(web::Data::new(check.clone()));
    }
}

/// Expands the full application wiring at the call site:
/// `wired_app!(&modules, &readiness, &cors_origins)`.
///
/// A macro rather than a function for one specific reason: actix-web's
/// assembled `App` has no nameable public type, so a function can only
/// return an opaque `impl` bound, and `HttpServer::new` rejects that
/// because the bound is weaker than the `IntoServiceFactory` impl it
/// needs. Expanding at the call site gives each site the concrete type
/// inference it requires while keeping a single description of the
/// middleware order and the registered app data.
///
/// Crate-internal, and the only thing that mounts without threading a
/// `Result` through actix's `configure` closures, which return `()`. Both
/// call sites run [`check_prefixes`] first and surface the error properly;
/// the assertion here is unreachable, and turning it into a startup panic
/// beats silently shadowing a module.
macro_rules! wired_app {
    ($modules:expr, $readiness:expr, $cors_origins:expr, $bucket:expr) => {{
        apply_limits(App::new())
            .wrap(cors($cors_origins))
            .wrap(middleware::request_tracing::RequestTracingMiddleware)
            .wrap(middleware::bearer_token::BearerTokenMiddleware)
            // Outermost, so it also bounds the routes a subject-keyed limiter
            // could not reach -- `/auth/login`, which is an outbound round trip
            // to the identity provider, and `/health`, which a load balancer
            // polls hard. A zero limit leaves it installed but inert, costing
            // one atomic load per request.
            .wrap(crate::limits::RateLimit::new($bucket.clone()))
            .configure(health_routes)
            .configure(|cfg| {
                if let Err(e) = check_prefixes($modules) {
                    panic!("{e}");
                }
                register_modules($modules, $readiness, cfg);
            })
            // Mounted last on purpose. The API modules are the surface that
            // matters, and anything catch-all mounted ahead of them can
            // shadow them -- which is exactly what a `web::scope("")`
            // around the spec routes used to do.
            .configure(docs::config)
    }};
}

/// Resolves when the process should shut down: Ctrl-C everywhere, plus
/// SIGTERM on unix (container orchestrators). Separated for testability
/// of the wiring in [`ApiService::start`].
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = term.recv() => {},
                }
            }
            Err(e) => {
                tracing::warn!("SIGTERM handler install failed ({e}); watching Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The HTTP server: composes [`ApiModule`]s into a single Actix Web
/// application and binds it to a socket address.
pub struct ApiService {
    modules: Vec<Box<dyn ApiModule>>,
    readiness: Option<health::ReadyCheck>,
    cors_origins: Vec<String>,
    /// Request-rate bucket, keyed by peer address. Disabled at `0`.
    bucket: crate::limits::TokenBucket,
}

impl Default for ApiService {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiService {
    /// Creates an empty service with no registered modules.
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            readiness: None,
            cors_origins: Vec::new(),
            bucket: crate::limits::TokenBucket::new(0, 0),
        }
    }

    /// Sets the browser origins allowed by CORS (empty = same-origin only).
    ///
    /// Pass `config.http.allowed_origins`; each entry must be an exact
    /// `http(s)` origin. Credentials are always allowed.
    pub fn with_cors_origins(mut self, origins: Vec<String>) -> Self {
        self.cors_origins = origins;
        self
    }

    /// Adds a module to the service. Modules are mounted in registration
    /// order; use builder-style chaining to register several.
    pub fn register_module(mut self, module: Box<dyn ApiModule>) -> Self {
        self.modules.push(module);
        self
    }

    /// Sets the request-rate limit, per peer address.
    ///
    /// `per_minute == 0` disables it, which is the default. Installed as the
    /// outermost middleware, so it also bounds the routes a subject-keyed
    /// limiter could not reach.
    pub fn with_rate_limit(mut self, bucket: crate::limits::TokenBucket) -> Self {
        self.bucket = bucket;
        self
    }

    /// Injects the dependency check backing `GET /ready`. The check runs
    /// on every probe poll, so it must be cheap and non-blocking. When
    /// absent `/ready` still returns 200 once startup (which gates on
    /// S3/OIDC/JWKS) has bound the listener.
    pub fn with_readiness_check(mut self, check: health::ReadyCheck) -> Self {
        self.readiness = Some(check);
        self
    }

    /// Registers this service's modules and readiness probe onto an
    /// existing `web::ServiceConfig`.
    ///
    /// The composable half of [`start`](Self::start), and the piece a host
    /// app needs to mount this API inside its own `App` rather than giving
    /// up the listener. Pair it with the global middleware this module
    /// already exposes — [`cors`],
    /// [`RequestTracingMiddleware`](middleware::request_tracing::RequestTracingMiddleware),
    /// [`BearerTokenMiddleware`](middleware::bearer_token::BearerTokenMiddleware) —
    /// plus [`apply_limits`], [`health_routes`], and [`docs::config`], and
    /// the result is exactly what `start` serves.
    ///
    /// Fails with [`DuplicateRoutePrefix`] if two registered modules declare
    /// the same [`ApiModule::prefix`]. Checked before anything is mounted.
    ///
    /// Note what is deliberately *not* offered: a method returning the
    /// assembled `App`. actix-web exposes no nameable public type for it
    /// (`BoxedHttpServiceFactory` is crate-private), so such a signature
    /// would either leak an unnameable `impl` bound that `HttpServer::new`
    /// rejects, or force a dynamic factory per worker. Configuring an `App`
    /// the caller already owns is both expressible and cheaper.
    pub fn configure(&self, cfg: &mut web::ServiceConfig) -> Result<(), DuplicateRoutePrefix> {
        check_prefixes(&self.modules)?;
        register_modules(&self.modules, &self.readiness, cfg);
        Ok(())
    }

    /// Binds the composed application to `addr` and serves it until a
    /// shutdown signal (Ctrl-C / SIGTERM) arrives, then drains
    /// connections within the shutdown timeout before returning.
    pub async fn start(self, addr: SocketAddr) -> anyhow::Result<()> {
        // Before the listener exists, so a bad composition is a startup
        // error naming the prefix rather than a running server with a
        // module whose routes 404.
        check_prefixes(&self.modules)?;

        let modules = Arc::new(self.modules);
        let readiness = self.readiness.clone();
        let cors_origins = self.cors_origins.clone();
        let bucket = self.bucket.clone();

        let server =
            HttpServer::new(move || wired_app!(&modules, &readiness, &cors_origins, &bucket))
                .shutdown_timeout(SHUTDOWN_TIMEOUT_SECS)
                .client_request_timeout(CLIENT_TIMEOUT)
                .client_disconnect_timeout(CLIENT_TIMEOUT)
                .bind(addr)?
                .run();
        let handle = server.handle();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received; draining connections");
            handle.stop(true).await;
        });
        server.await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{HttpResponse, http::StatusCode, http::header::CONTENT_TYPE, post, test, web};

    /// A module that exists only to prove the composition root mounts what
    /// it is given, in a *scope* — the shape every real module uses.
    struct PingModule;

    impl ApiModule for PingModule {
        fn prefix(&self) -> &str {
            "/ping"
        }

        fn configure(&self, cfg: &mut web::ServiceConfig) {
            cfg.service(
                web::scope("/ping")
                    .route(
                        "",
                        web::get().to(|| async { HttpResponse::Ok().body("pong") }),
                    )
                    .route(
                        "/deep",
                        web::get().to(|| async { HttpResponse::Ok().body("deep") }),
                    ),
            );
        }
    }

    /// Builds the real served application in-process — no socket, no
    /// shutdown signal.
    ///
    /// This is what `wired_app!` exists for. Before it, the composition
    /// root (CORS, middleware order, readiness, module mounting) was only
    /// reachable through `start()`, so none of it could be asserted.
    ///
    /// A macro rather than a helper fn because `test::init_service` returns
    /// a service over actix-http's own `Request` type, which the crate does
    /// not depend on directly and so cannot name in a signature. Expanding
    /// here keeps the concrete type inferred at each use.
    macro_rules! served {
        ($service:expr) => {{
            test::init_service(wired_app!(
                &$service.modules,
                &$service.readiness,
                &$service.cors_origins,
                &$service.bucket
            ))
            .await
        }};
    }

    #[actix_web::test]
    async fn composition_root_serves_health_and_registered_modules() {
        let service = ApiService::new().register_module(Box::new(PingModule));
        let app = served!(service);

        // Built-in routes survive composition.
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
        assert_eq!(res.status(), 200);

        // And so does a registered module's route.
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/ping").to_request()).await;
        assert_eq!(res.status(), 200);
        assert_eq!(test::read_body(res).await, "pong");

        // The OpenAPI document is mounted by the same wiring.
        let res = test::call_service(
            &app,
            test::TestRequest::get().uri("/openapi.json").to_request(),
        )
        .await;
        assert_eq!(res.status(), 200);
    }

    #[actix_web::test]
    async fn composition_root_applies_cors_and_readiness() {
        // CORS reaches the composed app, not just a hand-built one.
        let origins = vec!["https://app.example.com".to_string()];
        let service = ApiService::new().with_cors_origins(origins);
        let app = served!(service);
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/health")
                .insert_header(("Origin", "https://app.example.com"))
                .to_request(),
        )
        .await;
        assert_eq!(
            res.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://app.example.com")
        );

        // A failing readiness check must surface through the composed app.
        let failing: health::ReadyCheck = Arc::new(|| false);
        let service = ApiService::new().with_readiness_check(failing);
        let app = served!(service);
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(res.status(), 503);
    }

    /// `ApiService::configure` is the documented way for a host app to mount
    /// the API into its own `App`, so the two paths must produce the same
    /// routes.
    #[actix_web::test]
    async fn configure_matches_the_served_wiring() {
        let service = ApiService::new().register_module(Box::new(PingModule));
        let app = test::init_service(
            apply_limits(App::new())
                .configure(health_routes)
                .configure(|cfg| service.configure(cfg).expect("no prefix collision")),
        )
        .await;
        for uri in ["/health", "/ping"] {
            let res =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            assert_eq!(res.status(), 200, "{uri} missing from the configured app");
        }
    }

    /// A module set that mounts two of the same prefix is a composition
    /// error, and it has to surface as one.
    ///
    /// Actix does not report it: a scope matches its whole prefix and
    /// services are tried in registration order, so the second module's
    /// routes are simply never consulted. The result is a server that
    /// starts cleanly and 404s a documented route. `OidcApiModule` and
    /// `OidcSessionModule` both claiming `/auth` is exactly what happened.
    #[actix_web::test]
    async fn two_modules_on_one_prefix_is_rejected() {
        let service = ApiService::new()
            .register_module(Box::new(PingModule))
            .register_module(Box::new(PingModule));

        // Captured out of the closure because actix's `configure` takes an
        // infallible `FnOnce(&mut ServiceConfig)`.
        let outcome = std::cell::RefCell::new(None);
        let app = test::init_service(apply_limits(App::new()).configure(|cfg| {
            *outcome.borrow_mut() = Some(service.configure(cfg).err());
        }))
        .await;

        let err = outcome
            .into_inner()
            .expect("configure ran")
            .expect("duplicate /ping should be refused");
        assert_eq!(err.prefix, "/ping");
        // The message has to name the prefix and say what happened,
        // because this is the only diagnostic a host app gets.
        let rendered = err.to_string();
        assert!(rendered.contains("/ping"), "{rendered}");
        assert!(rendered.contains("unreachable"), "{rendered}");

        // Prefixes are checked before anything is mounted, so the refused
        // set left no half-registered routes behind.
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/ping").to_request()).await;
        assert_eq!(res.status(), 404);
    }

    /// The same set through the served path, which is where a bad
    /// composition would otherwise bind a socket and serve a broken API.
    #[actix_web::test]
    async fn start_refuses_a_duplicate_prefix_before_binding() {
        let service = ApiService::new()
            .register_module(Box::new(PingModule))
            .register_module(Box::new(PingModule));
        // Port 0 is never bound because validation runs first.
        let err = service
            .start("127.0.0.1:0".parse().expect("literal addr"))
            .await
            .expect_err("start should refuse a duplicate prefix");
        assert!(err.to_string().contains("/ping"), "unexpected error: {err}");
    }

    /// Regression: a `web::scope("")` around the spec routes matched every
    /// request and shadowed every service registered after it. Because the
    /// spec was mounted before the API modules, every `/fs`, `/policy`,
    /// `/auth`, `/sync`, and `/setup` route 404'd in the real server while
    /// `/health`, `/ready`, and `/openapi.json` still answered — so the
    /// server looked healthy and served nothing.
    ///
    /// `docs::tests` only ever checked that paths were *declared*; nothing
    /// asserted they were *mounted*. These two do.
    #[actix_web::test]
    async fn spec_routes_do_not_shadow_module_routes() {
        let service = ApiService::new().register_module(Box::new(PingModule));
        let app = served!(service);
        for uri in ["/ping", "/ping/deep", "/openapi.json"] {
            let res =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            assert_eq!(res.status(), 200, "{uri} is shadowed by another mount");
        }
    }

    /// Raw-bytes echo handler exercising the `Bytes` extractor limit.
    async fn echo(body: web::Bytes) -> HttpResponse {
        HttpResponse::Ok().body(body)
    }

    /// A malformed JSON body answers inside the envelope.
    ///
    /// Actix's default for a body that will not deserialize is a bare
    /// `400 Bad Request` in `text/plain`, so a documented route could answer
    /// outside the uniform envelope -- and would, routinely, for any client
    /// that sends a truncated or mistyped payload. This pins the fix to
    /// `apply_limits`, which is the one place the `JsonConfig` lives, so a
    /// host app following the documented recipe inherits it.
    #[actix_web::test]
    async fn malformed_json_answers_inside_the_envelope() {
        #[post("/thing")]
        async fn thing(_body: web::Json<serde_json::Value>) -> HttpResponse {
            HttpResponse::Ok().finish()
        }

        // Control: without `apply_limits`, actix's own text 400.
        let bare = test::init_service(App::new().service(thing)).await;
        let res = test::call_service(
            &bare,
            test::TestRequest::post()
                .uri("/thing")
                .insert_header((CONTENT_TYPE, "application/json"))
                .set_payload("{not json")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let raw = test::read_body(res).await;
        assert!(
            serde_json::from_slice::<error::ErrorBody>(&raw).is_err(),
            "control: actix's default is not the envelope"
        );

        // With it, the same request is answered by this crate.
        let wrapped = test::init_service(apply_limits(App::new()).service(thing)).await;
        let res = test::call_service(
            &wrapped,
            test::TestRequest::post()
                .uri("/thing")
                .insert_header((CONTENT_TYPE, "application/json"))
                .set_payload("{not json")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let parsed: error::ErrorBody =
            serde_json::from_slice(&test::read_body(res).await).expect("envelope");
        assert_eq!(parsed.error, "bad request");
    }

    /// 300 KiB exceeds actix's 256 KiB `Bytes` default: without the shared
    /// limits it must 413, with them it must pass. Guards the documented
    /// 512 KiB parts / 10 MiB single-part uploads against a silent 413.
    #[actix_web::test]
    async fn payload_limit_covers_documented_part_sizes() {
        use actix_web::web::Bytes;

        let payload = || {
            test::TestRequest::put()
                .uri("/echo")
                .set_payload(Bytes::from(vec![7u8; 300_000]))
                .to_request()
        };

        // Control: actix's 256 KiB default rejects the body.
        let svc = test::init_service(App::new().route("/echo", web::put().to(echo))).await;
        let res = test::call_service(&svc, payload()).await;
        assert_eq!(res.status(), 413, "control: default limit must reject");

        // With the shared limits the same body passes through untouched.
        let svc =
            test::init_service(apply_limits(App::new()).route("/echo", web::put().to(echo))).await;
        let res = test::call_service(&svc, payload()).await;
        assert_eq!(res.status(), 200);
        assert_eq!(test::read_body(res).await.len(), 300_000);
    }

    /// CORS echoes an explicitly allowed browser origin (with credentials)
    /// and stays silent otherwise: empty origins mean same-origin only.
    #[actix_web::test]
    async fn cors_allows_configured_origin_only() {
        async fn ok() -> HttpResponse {
            HttpResponse::Ok().finish()
        }

        let svc = test::init_service(
            App::new()
                .wrap(cors(&["https://app.example.com".to_string()]))
                .route("/ping", web::get().to(ok)),
        )
        .await;
        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/ping")
                .insert_header(("Origin", "https://app.example.com"))
                .to_request(),
        )
        .await;
        assert_eq!(
            res.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://app.example.com")
        );

        // Unlisted origin gets no CORS headers.
        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/ping")
                .insert_header(("Origin", "https://evil.example.com"))
                .to_request(),
        )
        .await;
        assert!(res.headers().get("access-control-allow-origin").is_none());

        // Empty origins: deny-by-default, no CORS headers at all.
        let svc =
            test::init_service(App::new().wrap(cors(&[])).route("/ping", web::get().to(ok))).await;
        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/ping")
                .insert_header(("Origin", "https://app.example.com"))
                .to_request(),
        )
        .await;
        assert!(res.headers().get("access-control-allow-origin").is_none());
    }
}
