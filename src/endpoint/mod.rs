use std::{net::SocketAddr, sync::Arc};

use actix_web::{App, HttpServer, web};

/// Request middleware for token extraction and validation.
pub mod middleware;
/// Built-in routes shared by every deployment (health checks).
pub mod route;

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

    /// Binds the composed application to `addr` and serves it until the
    /// process is stopped.
    pub async fn start(self, addr: SocketAddr) -> anyhow::Result<()> {
        let modules = Arc::new(self.modules);

        HttpServer::new(move || {
            let mut app = App::new()
                .wrap(middleware::bearer_token::BearerTokenMiddleware)
                .configure(route::config);

            for module in modules.iter() {
                app = app.configure(move |cfg| module.configure(cfg));
            }

            app
        })
        .bind(addr)?
        .run()
        .await?;

        Ok(())
    }
}
