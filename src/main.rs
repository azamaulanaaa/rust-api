use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::Path,
};

use actix_web::{App, HttpServer};
use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use simple_logger::SimpleLogger;

mod config;
mod middleware;
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

    let (keys, validation) = prep_jwt_middleware(
        &config.authorization.jwks_url,
        &config.authorization.issuer,
        &config.authorization.audience,
    )
    .await?;

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::jwt::JwtClaimsMiddleware::<Claims>::new(
                keys.clone(),
                validation.clone(),
            ))
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

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multi(Vec<String>),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    pub iss: String,         // Issuer
    pub sub: String,         // Subject (User ID)
    pub aud: Audience,       // Handle both String and [String]
    pub exp: u64,            // Expiration (u64 for 2038+ safety)
    pub nbf: Option<u64>,    // Not Before
    pub iat: Option<u64>,    // Issued At
    pub jti: Option<String>, // JWT ID (Good for revocation)
}

pub async fn prep_jwt_middleware(
    jwks_url: &str,
    audience: &str,
    issuer: &str,
) -> anyhow::Result<(
    HashMap<String, middleware::jwt::DecodingKey>,
    middleware::jwt::Validation,
)> {
    let jwks: middleware::jwt::JwkSet = reqwest::get(jwks_url).await?.json().await?;
    let keys = jwks
        .keys
        .iter()
        .map(|jwk| {
            let kid = jwk
                .common
                .key_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("JWK missing key_id"))?;

            let decoding_key = middleware::jwt::DecodingKey::from_jwk(jwk)?;

            Ok((kid, decoding_key))
        })
        .collect::<anyhow::Result<HashMap<_, _>>>()?;

    if keys.is_empty() {
        anyhow::bail!("No valid keys found in JWKS at {}", jwks_url);
    }

    let mut validation = middleware::jwt::Validation::new(middleware::jwt::Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[issuer]);

    Ok((keys, validation))
}
