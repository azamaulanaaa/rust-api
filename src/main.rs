//! Executable entry point for the rust-api starter-kit server.
//!
//! `serve` loads TOML configuration, initializes the OIDC client and Casbin
//! policy engine, registers their API modules onto an
//! [`rust_api::endpoint::ApiService`], and starts the HTTP listener. The
//! `policy export/import` subcommands manage policy data as JSON for
//! backups and migrations.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
};

use anyhow::Context;
use clap::{Parser, Subcommand};
use url::Url;

use rust_api::{
    endpoint::{ApiService, middleware::jwt::Claims},
    oidc::{OidcClient, OidcConfig, route::OidcApiModule},
    policy::{PolicyEngine, admin, route::PolicyApiModule},
    telemetry,
};

mod config;

/// Command-line interface for the rust-api server binary.
#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The available subcommands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Run the HTTP server.
    Serve {
        /// Path of the TOML configuration file to load at startup.
        #[arg(short, long)]
        config: String,
        /// Enable debug-level logging.
        #[arg(long, default_value_t = false)]
        verbose: bool,
    },
    /// Export or import policy data (backups and migrations).
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

/// Policy-store management actions.
#[derive(Subcommand, Debug)]
enum PolicyAction {
    /// Write every stored policy rule to a JSON file.
    Export {
        /// Path of the embedded policy store.
        #[arg(long)]
        store: PathBuf,
        /// Output JSON file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Load policy rules from a JSON file into a store.
    Import {
        /// Path of the embedded policy store.
        #[arg(long)]
        store: PathBuf,
        /// Input JSON file.
        #[arg(long)]
        input: PathBuf,
    },
}

/// Bootstraps the server: loads configuration, initializes the OIDC client
/// and policy engine, registers their API modules, and starts listening.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { config, verbose } => serve(Path::new(&config), verbose).await,
        Command::Policy { action } => match action {
            PolicyAction::Export { store, out } => {
                let dump = admin::export(&store).await?;
                std::fs::write(
                    &out,
                    serde_json::to_vec_pretty(&dump).context("serialize policy dump")?,
                )?;
                println!(
                    "exported {} permission rules and {} group memberships to {}",
                    dump.p.len(),
                    dump.g.len(),
                    out.display()
                );
                Ok(())
            }
            PolicyAction::Import { store, input } => {
                let bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                let dump: rust_api::policy::admin::PolicyDump =
                    serde_json::from_slice(&bytes).context("parse policy dump")?;
                let report = admin::import(&store, &dump).await?;
                println!(
                    "imported {} rules and {} group memberships \
                     ({} duplicates skipped) into {}",
                    report.rules_added,
                    report.groups_added,
                    report.duplicates,
                    store.display()
                );
                Ok(())
            }
        },
    }
}

/// Runs the HTTP listener until stopped.
async fn serve(config_path: &Path, verbose: bool) -> anyhow::Result<()> {
    let config = config::Config::try_from(config_path)?;

    let telemetry = telemetry::init(
        verbose,
        &config.observability.service_name,
        config.observability.otlp_endpoint.as_deref(),
        config.observability.sample_ratio,
    )?;

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

    let policy_engine = PolicyEngine::init(Path::new(&config.database.path)).await?;
    let policy_api_module = PolicyApiModule::new(policy_engine, oidc_api_module.middleware());

    let listen_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.listen_port);
    ApiService::new()
        .register_module(Box::new(oidc_api_module))
        .register_module(Box::new(policy_api_module))
        .start(listen_addr.into())
        .await?;

    // Explicit flush on the normal exit path: pending spans and metric
    // points are delivered, and failures are surfaced instead of silently
    // dropped (the Drop fallback remains for early-error paths).
    telemetry.shutdown()?;

    Ok(())
}
