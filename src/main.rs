//! Executable entry point for the rust-api starter-kit server.
//!
//! `serve` loads TOML configuration, initializes the OIDC client and Casbin
//! policy engine, registers their API modules onto an
//! [`rust_api::http::ApiService`], and starts the HTTP listener. The
//! `policy export/import` subcommands manage policy data as JSON for
//! backups and migrations.

#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use clap::{Parser, Subcommand};
use url::Url;

use rust_api::{
    fs::{FsEngine, route::FsApiModule, s3::S3ClientConfig, store::FsStore},
    http::{ApiService, middleware::jwt::Claims},
    oidc::{OidcClient, OidcConfig, route::OidcApiModule},
    policy::{PolicyEngine, admin, route::PolicyApiModule, setup::SetupApiModule},
    sync::{route::SyncApiModule, snapshot::SnapshotManager, wal::Wal},
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

/// Policy-store management actions (S3-only).
#[derive(Subcommand, Debug)]
enum PolicyAction {
    /// Write every stored policy rule to a JSON file (S3 prefix from --config).
    Export {
        /// Path of the TOML config file (provides [s3] + [database].prefix).
        #[arg(long)]
        config: PathBuf,
        /// Output JSON file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Load policy rules from a JSON file into a store (S3 prefix from --config).
    Import {
        /// Path of the TOML config file (provides [s3] + [database].prefix).
        #[arg(long)]
        config: PathBuf,
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
            PolicyAction::Export { config, out } => {
                let cfg = config::Config::try_from(config.as_path())?;
                let s3_cfg = S3ClientConfig {
                    bucket: cfg.s3.bucket.clone(),
                    region: cfg.s3.region.clone(),
                    endpoint_url: cfg.s3.endpoint_url.clone(),
                    force_path_style: cfg.s3.force_path_style,
                    access_key_id: cfg.s3.access_key_id.clone(),
                    secret_access_key: cfg.s3.secret_access_key.clone(),
                };
                let store = rust_api::db::build_s3_store(
                    &s3_cfg,
                    &format!("{}/policy", cfg.database.prefix.trim_matches('/')),
                )
                .await?;
                let dump = admin::export_s3(store).await?;
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
            PolicyAction::Import { config, input } => {
                let cfg = config::Config::try_from(config.as_path())?;
                let s3_cfg = S3ClientConfig {
                    bucket: cfg.s3.bucket.clone(),
                    region: cfg.s3.region.clone(),
                    endpoint_url: cfg.s3.endpoint_url.clone(),
                    force_path_style: cfg.s3.force_path_style,
                    access_key_id: cfg.s3.access_key_id.clone(),
                    secret_access_key: cfg.s3.secret_access_key.clone(),
                };
                let store = rust_api::db::build_s3_store(
                    &s3_cfg,
                    &format!("{}/policy", cfg.database.prefix.trim_matches('/')),
                )
                .await?;
                let bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                let dump: rust_api::policy::admin::PolicyDump =
                    serde_json::from_slice(&bytes).context("parse policy dump")?;
                let report = admin::import_s3(store, &dump).await?;
                println!(
                    "imported {} rules and {} group memberships \
                     ({} duplicates skipped) into {}",
                    report.rules_added, report.groups_added, report.duplicates, cfg.database.prefix
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

    let s3_client_config = S3ClientConfig {
        bucket: config.s3.bucket.clone(),
        region: config.s3.region.clone(),
        endpoint_url: config.s3.endpoint_url.clone(),
        force_path_style: config.s3.force_path_style,
        access_key_id: config.s3.access_key_id.clone(),
        secret_access_key: config.s3.secret_access_key.clone(),
    };
    // Single bucket, prefix-scoped OxKvStores per domain (scalable, no local files).
    let policy_store = rust_api::db::build_s3_store(
        &s3_client_config,
        &format!("{}/policy", config.database.prefix.trim_matches('/')),
    )
    .await
    .map_err(|e| anyhow::anyhow!("build policy OxKvStore: {e}"))?;
    let fs_s3_store = rust_api::db::build_s3_store(
        &s3_client_config,
        &format!("{}/fs", config.database.prefix.trim_matches('/')),
    )
    .await
    .map_err(|e| anyhow::anyhow!("build fs OxKvStore: {e}"))?;
    let policy_engine = PolicyEngine::init_s3(policy_store).await?;
    let setup_api_module = SetupApiModule::new(policy_engine.clone(), oidc_api_module.middleware());
    let policy_api_module =
        PolicyApiModule::new(policy_engine.clone(), oidc_api_module.middleware());
    let fs_engine = FsEngine::init(
        fs_s3_store.clone(),
        &s3_client_config,
        policy_engine.clone(),
    )
    .await?;
    // GC: expire abandoned multipart uploads every hour (24h TTL)
    rust_api::fs::gc::spawn(std::sync::Arc::new(fs_engine.clone()));
    let fs_api_module = FsApiModule::new(fs_engine, oidc_api_module.middleware());

    // Per-user replica snapshots: master stays the write path, versioned
    // `{prefix}/u/{sub}/{seq}` prefixes are filtered read replicas served
    // over `/sync/db/` for oxkv readers (see `sync::snapshot`).
    let db_prefix = config.database.prefix.trim_matches('/').to_string();
    let wal_store = rust_api::db::build_s3_store(&s3_client_config, &format!("{db_prefix}/wal"))
        .await
        .map_err(|e| anyhow::anyhow!("build wal OxKvStore: {e}"))?;
    let replica_objects: Arc<dyn object_store::ObjectStore> = Arc::new(
        rust_api::fs::object_store::s3_builder(&s3_client_config)
            .build()
            .context("build snapshot object store")?,
    );
    let snapshot_s3 = rust_api::fs::s3::build_s3_client(&s3_client_config)
        .await
        .map_err(|e| anyhow::anyhow!("build snapshot S3 client: {e}"))?;
    let snapshot_manager = SnapshotManager::new(
        Wal::new(wal_store),
        FsStore::new(fs_s3_store.clone()),
        policy_engine.clone(),
        snapshot_s3,
        config.s3.bucket.clone(),
        replica_objects,
        db_prefix,
        false,
    );
    let sync_api_module = SyncApiModule::new(snapshot_manager, oidc_api_module.middleware());

    let listen_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.listen_port);
    ApiService::new()
        .register_module(Box::new(oidc_api_module))
        .register_module(Box::new(setup_api_module))
        .register_module(Box::new(policy_api_module))
        .register_module(Box::new(fs_api_module))
        .register_module(Box::new(sync_api_module))
        .start(listen_addr.into())
        .await?;

    // Explicit flush on the normal exit path: pending spans and metric
    // points are delivered, and failures are surfaced instead of silently
    // dropped (the Drop fallback remains for early-error paths).
    telemetry.shutdown()?;

    Ok(())
}
