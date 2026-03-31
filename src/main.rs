use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
};

use anyhow::Context;
use clap::Parser;
use simple_logger::SimpleLogger;
use url::Url;

use rust_api::{
    endpoint::{ApiService, middleware::jwt::Claims},
    oidc::{OidcClient, OidcConfig, route::OidcApiModule},
    policy::{PolicyEngine, route::PolicyApiModule},
};

mod config;

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

    let base = Url::parse(&config.public_address).context("Invalid public_address in config")?;

    let oidc_client = OidcClient::new(OidcConfig {
        client_id: config.authorization.client_id.clone(),
        client_secret: config.authorization.client_secret,
        issuer_url: config.authorization.issuer_url,
        redirect_url: base
            .join("auth/callback")
            .context("Failed to build redirect URL")?
            .to_string(),
    })
    .await?;
    let oidc_api_module = OidcApiModule::<Claims>::init(oidc_client).await?;

    let policy_engine = PolicyEngine::init(&config.database_url).await?;
    let policy_api_module = PolicyApiModule::new(policy_engine, oidc_api_module.middleware());

    let listen_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.listen_port);
    ApiService::new()
        .register_module(Box::new(oidc_api_module))
        .register_module(Box::new(policy_api_module))
        .start(listen_addr.into())
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
