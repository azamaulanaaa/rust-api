//! Example: a custom [`ApiModule`] mounted on an [`ApiService`].
//!
//! Build with `cargo build --example sample_module`.
//! Run with `cargo run --example sample_module`.

use actix_web::{HttpResponse, web};
use rust_api::http::{ApiModule, ApiService};

/// A minimal module that owns the `/sample` prefix.
struct SampleModule;

impl ApiModule for SampleModule {
    fn prefix(&self) -> &str {
        "/sample"
    }

    fn configure(&self, cfg: &mut web::ServiceConfig) {
        cfg.service(
            web::scope("/sample")
                .route(
                    "",
                    web::get().to(|| async { HttpResponse::Ok().body("sample") }),
                )
                .route("/hello", web::get().to(hello)),
        );
    }
}

async fn hello() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "message": "hello from /sample" }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = ApiService::new().register_module(Box::new(SampleModule));

    let addr: std::net::SocketAddr = "127.0.0.1:8080"
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid listen address: {e}"))?;

    service.start(addr).await
}
