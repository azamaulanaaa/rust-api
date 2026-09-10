use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{App, HttpServer, web};

/// OpenAPI JSON + Swagger UI.
pub mod docs;
/// Shared error type rendering a uniform JSON error envelope.
pub mod error;
/// Built-in liveness probe shared by every deployment.
pub mod health;
/// Request middleware for token extraction and validation.
pub mod middleware;

/// Maximum raw request body: covers 10 MiB single-part uploads plus
/// headroom. Without this the `Bytes` extractor falls back to actix's
/// 256 KiB default and rejects every documented part size with 413.
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Maximum JSON body: control-plane payloads (policy rules, upload
/// metadata) are small; anything larger is a misuse or abuse signal.
const MAX_JSON_BYTES: usize = 1024 * 1024;

/// Grace period for in-flight requests to finish during shutdown.
const SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// Slow-client guard: time allowed to send request headers/body.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Applies the shared body-size limits to an Actix application.
///
/// Split out so the limits are unit-testable: the production server and
/// the regression test below both go through this one function.
fn apply_limits<T>(app: App<T>) -> App<T>
where
    T: actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Error = actix_web::Error,
        InitError = (),
    >,
{
    app.app_data(web::PayloadConfig::new(MAX_PAYLOAD_BYTES))
        .app_data(web::JsonConfig::default().limit(MAX_JSON_BYTES))
}

/// Registers the built-in routes shared by every deployment.
fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(health::health);
}

/// A self-contained unit of the API surface: a set of routes plus its own
/// app data and middleware. Implement this to plug business functionality
/// into an [`ApiService`].
pub trait ApiModule: Send + Sync {
    /// Registers this module's scopes, services, and app data on the Actix
    /// application configuration.
    fn configure(&self, cfg: &mut web::ServiceConfig);
}

/// The HTTP server: composes [`ApiModule`]s into a single Actix Web
/// application and binds it to a socket address.
pub struct ApiService {
    modules: Vec<Box<dyn ApiModule>>,
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
        }
    }

    /// Adds a module to the service. Modules are mounted in registration
    /// order; use builder-style chaining to register several.
    pub fn register_module(mut self, module: Box<dyn ApiModule>) -> Self {
        self.modules.push(module);
        self
    }

    /// Binds the composed application to `addr` and serves it until a
    /// shutdown signal (Ctrl-C / SIGTERM) arrives, then drains
    /// connections within the shutdown timeout before returning.
    pub async fn start(self, addr: SocketAddr) -> anyhow::Result<()> {
        let modules = Arc::new(self.modules);

        let server = HttpServer::new(move || {
            let mut app = apply_limits(App::new())
                .wrap(middleware::request_tracing::RequestTracingMiddleware)
                .wrap(middleware::bearer_token::BearerTokenMiddleware)
                .configure(config)
                .configure(docs::config);

            for module in modules.iter() {
                app = app.configure(move |cfg| module.configure(cfg));
            }

            app
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{HttpResponse, test};

    /// Raw-bytes echo handler exercising the `Bytes` extractor limit.
    async fn echo(body: web::Bytes) -> HttpResponse {
        HttpResponse::Ok().body(body)
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
            test::init_service(apply_limits(App::new()).route("/echo", web::put().to(echo)))
                .await;
        let res = test::call_service(&svc, payload()).await;
        assert_eq!(res.status(), 200);
        assert_eq!(test::read_body(res).await.len(), 300_000);
    }
}
