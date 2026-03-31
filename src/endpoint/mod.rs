use std::net::SocketAddr;

use actix_web::{App, HttpServer, web};

use crate::oidc::OidcClient;

pub mod middleware;
pub mod route;

pub struct ApiService {
    oidc_client: web::Data<OidcClient>,
    jwt_middleware: middleware::jwt::JwtClaimsMiddleware<middleware::jwt::Claims>,
}

impl ApiService {
    pub async fn init(oidc_client: OidcClient) -> anyhow::Result<Self> {
        let jwt_middleware = middleware::jwt::JwtClaimsMiddleware::new_with_jks(
            oidc_client.jwks_uri().as_str(),
            oidc_client.issuer().as_str(),
            oidc_client.client_id().as_str(),
        )
        .await?;

        Ok(Self {
            oidc_client: web::Data::new(oidc_client),
            jwt_middleware,
        })
    }

    pub async fn start(self, addr: SocketAddr) -> anyhow::Result<()> {
        HttpServer::new(move || {
            App::new()
                .app_data(self.oidc_client.clone())
                .wrap(self.jwt_middleware.clone())
                .wrap(middleware::bearer_token::BearerTokenMiddleware)
                .configure(route::config)
        })
        .bind(addr)?
        .run()
        .await?;

        Ok(())
    }
}
