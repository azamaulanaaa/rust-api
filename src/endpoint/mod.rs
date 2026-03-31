use std::{net::SocketAddr, sync::Arc};

use actix_web::{App, HttpServer, web};

pub mod middleware;
pub mod route;

pub trait ApiModule: Send + Sync {
    fn configure(&self, cfg: &mut web::ServiceConfig);
}

pub struct ApiService {
    modules: Vec<Box<dyn ApiModule>>,
}

impl ApiService {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    pub fn register_module(mut self, module: Box<dyn ApiModule>) -> Self {
        self.modules.push(module);
        self
    }

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
