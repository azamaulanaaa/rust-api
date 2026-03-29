use std::{
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::Path,
};

use actix_web::{App, HttpServer, web};
use anyhow::Context;
use clap::Parser;
use simple_logger::SimpleLogger;
use url::Url;

mod config;
mod middleware;
mod oidc;
mod route;

#[derive(clap::Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long, help = "Path of config file")]
    config: String,
    #[arg(long, default_value_t = false, help = "enable verbose")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::try_parse()?;

    init_logger(args.verbose)?;
    let config = config::Config::try_from(Path::new(&args.config))?;

    let listen_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.listen_port);
    let listener =
        TcpListener::bind(listen_addr).context(format!("Failed to bind at {:?}", listen_addr))?;

    let base = Url::parse(&config.public_address).context("Invalid public_address in config")?;

    let oidc_client = oidc::OidcClient::new(oidc::OidcConfig {
        client_id: config.authorization.client_id.clone(),
        client_secret: config.authorization.client_secret,
        issuer_url: config.authorization.issuer_url,
        redirect_url: base
            .join("auth/callback")
            .context("Failed to build redirect URL")?
            .to_string(),
    })
    .await?;

    let jwt_middleware =
        middleware::jwt::JwtClaimsMiddleware::<middleware::jwt::Claims>::new_with_jks(
            &oidc_client.jwks_uri().to_string(),
            &oidc_client.issuer().to_string(),
            &config.authorization.client_id,
        )
        .await?;

    let oidc_data = web::Data::new(oidc_client);

    HttpServer::new(move || {
        App::new()
            .app_data(oidc_data.clone())
            .wrap(jwt_middleware.clone())
            .wrap(middleware::bearer_token::BearerTokenMiddleware)
            .configure(route::config)
    })
    .listen(listener)?
    .run()
    .await?;

    Ok(())
}

fn init_logger(verbose: bool) -> anyhow::Result<()> {
    let log_level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    SimpleLogger::new().with_level(log_level).init()?;

    Ok(())
}
