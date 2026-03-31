use std::{net::SocketAddr, sync::Arc};

use actix_web::{App, HttpServer, web};

use crate::oidc::OidcClient;

pub mod middleware;
pub mod route;

pub trait ApiModule: Send + Sync {
    fn configure(&self, cfg: &mut web::ServiceConfig);
}

pub struct ApiService {
    oidc_client: OidcClient,
    modules: Vec<Box<dyn ApiModule>>,
}

impl ApiService {
    pub async fn init(oidc_client: OidcClient) -> anyhow::Result<Self> {
        Ok(Self {
            oidc_client: oidc_client,
            modules: Vec::new(),
        })
    }

    pub fn register_module(mut self, module: Box<dyn ApiModule>) -> Self {
        self.modules.push(module);
        self
    }

    pub async fn start(self, addr: SocketAddr) -> anyhow::Result<()> {
        let jwt_middleware: middleware::jwt::JwtClaimsMiddleware<middleware::jwt::Claims> =
            middleware::jwt::JwtClaimsMiddleware::new_with_jks(
                self.oidc_client.jwks_uri().as_str(),
                self.oidc_client.issuer().as_str(),
                self.oidc_client.client_id().as_str(),
            )
            .await?;
        let oidc_client = web::Data::new(self.oidc_client);
        let modules = Arc::new(self.modules);

        HttpServer::new(move || {
            let mut app = App::new()
                .app_data(oidc_client.clone())
                .wrap(jwt_middleware.clone())
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
