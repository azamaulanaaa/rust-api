//! HTTP server scaffolding. The crate provides a modular service registry.
//! The crate provides the request middleware that every module uses. That
//! middleware covers bearer token extraction. It covers JWKS-based JWT
//! validation. It covers tracing for each request. The crate provides
//! shared body size limits.
//!
//! [`ApiService`](crate::http::ApiService) combines
//! [`ApiModule`](crate::http::ApiModule) implementations into one Actix
//! application. [`cors`](crate::http::cors) holds the edge settings.
//! [`health`](crate::http::health) holds the probes that are not specific
//! to one module.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{App, HttpServer, web};

/// OpenAPI JSON and Swagger UI.
pub mod docs;
/// Shared error type rendering a uniform JSON error envelope.
pub mod error;

use error::ApiError;
/// Built-in liveness probe shared by every deployment.
pub mod health;
/// Request middleware for token extraction and validation.
pub mod middleware;

/// The maximum size of a raw request body. The limit covers 10 MiB
/// single-part uploads plus headroom. Without this limit, the `Bytes`
/// extractor uses the actix default of 256 KiB. It rejects every documented
/// part size with 413. The FS part intake shares this limit. That code
/// streams `Payload` directly. It enforces the same absolute ceiling
/// chunk by chunk.
pub(crate) const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// The maximum size of a JSON body. Control-plane payloads (policy rules,
/// upload metadata) are small. A larger body is a misuse or abuse signal.
const MAX_JSON_BYTES: usize = 1024 * 1024;

/// The grace period for in-flight requests to finish during shutdown.
const SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// The time a slow client has to send the request headers and body.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Applies the shared body-size limits to an Actix application.
///
/// The function is separate so that unit tests can check the limits. The
/// function is public. A host app that mounts the API in its own `App`
/// can apply the same limits. See [`ApiService::configure`] for the full
/// recipe.
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
                    // The actix default for a malformed body is a bare
                    // `400 Bad Request` in text/plain. This is the one way a
                    // documented route can answer outside the uniform
                    // envelope. Any client that sends a truncated or mistyped
                    // payload reaches this path, so it happens often. The
                    // extractor message names the offending field and the
                    // expected type. The server logs the message and does not
                    // send it. This is the same contract as every other cause
                    // in this crate.
                    tracing::debug!("malformed JSON body: {err}");
                    ApiError::BadRequest.into()
                }),
        )
}

/// Logs a failure that occurs during a streamed response body.
///
/// The response head is already on the wire when a body chunk fails. The
/// server cannot change the status code. The client then sees a truncated
/// body and nothing else. This is the only place where the operator can
/// learn the cause. Every streaming body must use this function.
///
/// The function is generic over the error type. The two streaming sources
/// report different error types.
/// [`FsError`](crate::fs::error::FsError) reports the errors of file
/// downloads. `object_store::Error` reports the errors of raw replica
/// objects. The function logs both error types without translation.
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
/// An empty `allowed_origins` disables CORS responses. Only same-origin
/// requests then succeed. Each origin must be an exact `http(s)` origin
/// without a trailing slash. The function always allows credentials. The
/// `auth_token` cookie and the `Authorization` bearer header work across
/// origins. The function exposes the `ETag` and range headers. The
/// `/sync/db/*` conditional polls and the `/fs` ranged downloads work from
/// the browser.
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

/// A self-contained unit of the API surface. The unit holds a set of routes.
/// The unit holds app data. The unit holds middleware. Implement this trait
/// to add business functions to an [`ApiService`].
pub trait ApiModule: Send + Sync {
    /// The one route prefix that this module owns, for example `/fs`.
    ///
    /// [`ApiService::configure`] uses this value to refuse two modules on
    /// the same prefix. Actix matches services in registration order. A
    /// scope matches its whole prefix. It does not match the paths that it
    /// declares. The first module does not merge the routes of the second
    /// module. The routes of the second module are unreachable. The result
    /// is a `404` on a route that the OpenAPI document describes. A unit
    /// test covers that route when the test mounts only this module.
    ///
    /// Return the empty string for a module that mounts only top-level
    /// routes (`/health`, `/openapi.json`). Such a module still conflicts
    /// with any other module that uses an empty prefix.
    fn prefix(&self) -> &str;

    /// Registers the scopes, services, and app data of this module on the
    /// Actix application configuration.
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
    /// The prefix that both modules claim.
    pub prefix: String,
}

/// Rejects a module set in which two modules claim the same
/// [`ApiModule::prefix`].
///
/// The function runs before anything is mounted. A rejected composition
/// leaves no half-registered routes behind.
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

/// Mounts the modules and the readiness probe onto a `ServiceConfig`.
///
/// The function cannot fail. [`check_prefixes`] has already rejected all
/// collisions. Both call sites run it first.
///
/// [`ApiService::configure`] and [`wired_app!`] share this function. The
/// public path and the served path cannot differ.
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
/// The code is a macro, not a function, for one specific reason. The
/// actix-web `App` type has no nameable public type. A function can
/// return only an opaque `impl` bound. `HttpServer::new` rejects that
/// bound. The bound is weaker than the `IntoServiceFactory` impl that it
/// needs. Expansion at the call site gives each site the concrete type
/// inference that it requires. It also keeps one description of the
/// middleware order and the app data.
///
/// The macro is internal to this crate. Only this macro mounts the modules
/// without passing a `Result` through the actix `configure` closures.
/// Those closures return `()`. Both call sites run [`check_prefixes`]
/// first. Both report the error correctly. The assertion in this macro is
/// therefore unreachable. A startup panic is better than a module that is
/// hidden without a message.
macro_rules! wired_app {
    ($modules:expr, $readiness:expr, $cors_origins:expr, $bucket:expr) => {{
        apply_limits(App::new())
            .wrap(cors($cors_origins))
            .wrap(middleware::request_id::RequestIdMiddleware)
            .wrap(actix_web::middleware::Compress::default())
            .wrap(middleware::request_tracing::RequestTracingMiddleware)
            .wrap(middleware::bearer_token::BearerTokenMiddleware)
            // Outermost, so it also limits the routes that a limiter keyed on
            // the subject cannot reach. These routes are `/auth/login`, which
            // makes an outbound call to the identity provider, and `/health`,
            // which a load balancer polls often. A zero limit leaves the
            // limiter installed but inactive. It costs one atomic load for
            // each request.
            .wrap(crate::limits::RateLimit::new($bucket.clone()))
            .configure(health_routes)
            .configure(|cfg| {
                if let Err(e) = check_prefixes($modules) {
                    panic!("{e}");
                }
                register_modules($modules, $readiness, cfg);
            })
            // Mounted last on purpose. The API modules are the surface that
            // matters. Any catch-all scope that is mounted before them can
            // hide them. A `web::scope("")` around the spec routes used to
            // do exactly this.
            .configure(docs::config)
    }};
}

/// Completes when the process must stop. The signal is Ctrl-C on all
/// platforms. On unix the signal is also SIGTERM. Container orchestrators
/// send SIGTERM. The function is separate so that the wiring in
/// [`ApiService::start`] is testable.
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

/// The HTTP server. The server combines [`ApiModule`] instances into one
/// Actix Web application. It binds the application to a socket address.
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

    /// Sets the browser origins that CORS allows. An empty list allows
    /// same-origin requests only.
    ///
    /// Pass `config.http.allowed_origins`. Each entry must be an exact
    /// `http(s)` origin. The service always allows credentials.
    pub fn with_cors_origins(mut self, origins: Vec<String>) -> Self {
        self.cors_origins = origins;
        self
    }

    /// Adds a module to the service. The service mounts the modules in
    /// registration order. Use builder-style chaining to register several
    /// modules.
    pub fn register_module(mut self, module: Box<dyn ApiModule>) -> Self {
        self.modules.push(module);
        self
    }

    /// Sets the request-rate limit for each peer address.
    ///
    /// A value of `per_minute == 0` disables the limit. That value is the
    /// default. The middleware is installed as the outermost middleware. It
    /// also limits the routes that a limiter keyed on the subject cannot
    /// reach.
    pub fn with_rate_limit(mut self, bucket: crate::limits::TokenBucket) -> Self {
        self.bucket = bucket;
        self
    }

    /// Injects the dependency check that backs `GET /ready`. The server runs
    /// the check on every probe poll. The check must be cheap. The check
    /// must not block. If no check is present, `/ready` still returns 200
    /// after startup has bound the listener. Startup waits for S3/OIDC/JWKS.
    pub fn with_readiness_check(mut self, check: health::ReadyCheck) -> Self {
        self.readiness = Some(check);
        self
    }

    /// Registers the modules and the readiness probe of this service onto
    /// an existing `web::ServiceConfig`.
    ///
    /// This method is the composable half of [`start`](Self::start). A host
    /// app needs this method to mount this API inside its own `App`. The
    /// host app keeps the listener. Use this method with the global
    /// middleware that this module already exposes. That middleware is
    /// [`cors`],
    /// [`actix_web::middleware::Compress`],
    /// [`RequestTracingMiddleware`](middleware::request_tracing::RequestTracingMiddleware),
    /// and [`BearerTokenMiddleware`](middleware::bearer_token::BearerTokenMiddleware).
    /// Add [`apply_limits`], [`health_routes`], and [`docs::config`] as
    /// well. The result is exactly what `start` serves.
    ///
    /// The method fails with [`DuplicateRoutePrefix`] if two registered
    /// modules declare the same [`ApiModule::prefix`]. The check runs before
    /// anything is mounted.
    ///
    /// The service deliberately does not offer a method that returns the
    /// assembled `App`. actix-web exposes no nameable public type for it.
    /// `BoxedHttpServiceFactory` is crate-private. Such a signature would
    /// expose an unnameable `impl` bound. `HttpServer::new` rejects that
    /// bound. The other option is one dynamic factory for each worker.
    /// Configuring an `App` that the caller already owns is possible. It is
    /// cheaper.
    pub fn configure(&self, cfg: &mut web::ServiceConfig) -> Result<(), DuplicateRoutePrefix> {
        check_prefixes(&self.modules)?;
        register_modules(&self.modules, &self.readiness, cfg);
        Ok(())
    }

    /// Binds the composed application to `addr`. The method serves the
    /// application until a shutdown signal arrives (Ctrl-C or SIGTERM). The
    /// method then drains the connections within the shutdown timeout. It
    /// returns after that.
    pub async fn start(self, addr: SocketAddr) -> anyhow::Result<()> {
        // The check runs before the listener exists, so a bad composition is
        // a startup error that names the prefix. Otherwise the server runs
        // with a module whose routes return 404.
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
    /// it is given, in a *scope*. Every real module uses this shape.
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

    /// Builds the real served application in-process. There is no socket.
    /// There is no shutdown signal.
    ///
    /// `wired_app!` exists for this purpose. Before it, only `start()` could
    /// reach the composition root. The composition root sets CORS. It sets
    /// the middleware order. It sets readiness. It sets the mounted
    /// modules. No test could check any of it.
    ///
    /// The code is a macro, not a helper function. `test::init_service`
    /// returns a service. That service uses the `Request` type of
    /// actix-http. This crate does not depend on actix-http directly. It
    /// cannot name that type in a signature. Expansion here keeps the
    /// concrete type inferred at each use.
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

        // The composition keeps the built-in routes.
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
        assert_eq!(res.status(), 200);

        // The composition keeps the route of a registered module too.
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/ping").to_request()).await;
        assert_eq!(res.status(), 200);
        assert_eq!(test::read_body(res).await, "pong");

        // The same wiring mounts the OpenAPI document.
        let res = test::call_service(
            &app,
            test::TestRequest::get().uri("/openapi.json").to_request(),
        )
        .await;
        assert_eq!(res.status(), 200);
    }

    #[actix_web::test]
    async fn composition_root_applies_cors_and_readiness() {
        // CORS reaches the composed app, and not only an app that the
        // test builds by hand.
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

        // The composed app must report a readiness check that fails.
        let failing: health::ReadyCheck = Arc::new(|| false);
        let service = ApiService::new().with_readiness_check(failing);
        let app = served!(service);
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(res.status(), 503);
    }

    /// The documentation names `ApiService::configure` as the way for a host
    /// app to mount the API into its own `App`. Therefore the two paths must
    /// produce the same routes.
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

    /// A module set that mounts two modules on the same prefix is a
    /// composition error. The code must report it as an error.
    ///
    /// Actix does not report the error. A scope matches its whole prefix.
    /// The server tries the services in registration order. Therefore the
    /// server never consults the routes of the second module. The result is
    /// a server that starts normally and returns 404 for a documented route.
    /// `OidcApiModule` and `OidcSessionModule` both claimed `/auth`, and
    /// this is what happened.
    #[actix_web::test]
    async fn two_modules_on_one_prefix_is_rejected() {
        let service = ApiService::new()
            .register_module(Box::new(PingModule))
            .register_module(Box::new(PingModule));

        // The result is stored outside the closure, because actix `configure`
        // takes an infallible `FnOnce(&mut ServiceConfig)`.
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
        // The message must name the prefix and must describe what happened.
        // It is the only diagnostic that a host app receives.
        let rendered = err.to_string();
        assert!(rendered.contains("/ping"), "{rendered}");
        assert!(rendered.contains("unreachable"), "{rendered}");

        // The code checks the prefixes before it mounts anything, so the
        // refused set left no half-registered routes behind.
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/ping").to_request()).await;
        assert_eq!(res.status(), 404);
    }

    /// The code sends the same set through the served path. On that path, a
    /// bad composition would otherwise bind a socket and serve a broken API.
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

    /// Regression test. A `web::scope("")` around the spec routes matched
    /// every request. It also hid every service that was registered after
    /// it. The spec was mounted before the API modules. Therefore every
    /// `/fs`, `/policy`, `/auth`, `/sync`, and `/setup` route returned 404 on
    /// the real server. Only `/health`, `/ready`, and `/openapi.json` still
    /// answered. The server appeared healthy and served nothing.
    ///
    /// `docs::tests` only checked that the paths were *declared*. No test
    /// asserted that the paths were *mounted*. This test asserts it.
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

    /// A handler that echoes raw bytes. The handler tests the limit of the
    /// `Bytes` extractor.
    async fn echo(body: web::Bytes) -> HttpResponse {
        HttpResponse::Ok().body(body)
    }

    /// A malformed JSON body returns a response inside the envelope.
    ///
    /// The actix default for a body that cannot be deserialized is a bare
    /// `400 Bad Request` in `text/plain`. Therefore a documented route can
    /// answer outside the uniform envelope. Any client that sends a truncated
    /// or mistyped payload reaches this case, so it happens often. This test
    /// fixes the behaviour to `apply_limits`. That function holds the only
    /// `JsonConfig` in the crate. A host app that follows the documented
    /// recipe therefore inherits the same behaviour.
    #[actix_web::test]
    async fn malformed_json_answers_inside_the_envelope() {
        #[post("/thing")]
        async fn thing(_body: web::Json<serde_json::Value>) -> HttpResponse {
            HttpResponse::Ok().finish()
        }

        // Control case. Without `apply_limits`, actix returns its own text
        // 400.
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

        // With `apply_limits`, this crate answers the same request.
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

    /// A 300 KiB body is larger than the actix default of 256 KiB for
    /// `Bytes`. Without the shared limits, the request must return 413. With
    /// the limits, the request must pass. The test protects the documented
    /// upload sizes of 512 KiB parts and 10 MiB single-part uploads from a
    /// silent 413.
    #[actix_web::test]
    async fn payload_limit_covers_documented_part_sizes() {
        use actix_web::web::Bytes;

        let payload = || {
            test::TestRequest::put()
                .uri("/echo")
                .set_payload(Bytes::from(vec![7u8; 300_000]))
                .to_request()
        };

        // Control case. The actix default of 256 KiB rejects the body.
        let svc = test::init_service(App::new().route("/echo", web::put().to(echo))).await;
        let res = test::call_service(&svc, payload()).await;
        assert_eq!(res.status(), 413, "control: default limit must reject");

        // With the shared limits, the same body passes through unchanged.
        let svc =
            test::init_service(apply_limits(App::new()).route("/echo", web::put().to(echo))).await;
        let res = test::call_service(&svc, payload()).await;
        assert_eq!(res.status(), 200);
        assert_eq!(test::read_body(res).await.len(), 300_000);
    }

    /// CORS returns the allowed origin for a browser origin that the list
    /// permits explicitly, and it allows credentials. CORS returns nothing
    /// for any other origin. An empty list of origins allows same-origin
    /// requests only.
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

        // An origin that is not in the list gets no CORS headers.
        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/ping")
                .insert_header(("Origin", "https://evil.example.com"))
                .to_request(),
        )
        .await;
        assert!(res.headers().get("access-control-allow-origin").is_none());

        // An empty list of origins denies the request by default and returns
        // no CORS headers.
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
