//! Executable entry point for the rust-api starter-kit server.
//!
//! `serve` loads TOML configuration, initializes the OIDC client and Casbin
//! policy engine, registers their API modules onto an
//! [`rust_api::http::ApiService`], and starts the HTTP listener. The
//! `policy export/import` subcommands manage policy data as JSON for
//! backups and migrations.

// The deny level comes from [lints.clippy] in Cargo.toml (it applies to
// this target too); this attribute only opens the test escape hatch.
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
    fs::{FsEngine, TokenKeys, route::FsApiModule, s3::S3ClientConfig, store::FsStore},
    http::{ApiService, middleware::jwt::Claims},
    oidc::{
        OidcClient, OidcConfig,
        route::{OidcApiModule, OidcSessionModule},
    },
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
        config: PathBuf,
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

/// Resolves capability-token signing keys from `[capability]`.
///
/// Config validation already rejected malformed hex; a missing secret
/// falls back to an ephemeral OS-RNG key with a warning (tokens die
/// with the process — acceptable for dev, a misconfiguration in prod).
fn resolve_token_keys(config: &config::Config) -> anyhow::Result<TokenKeys> {
    match &config.capability.secret {
        Some(current) => TokenKeys::from_hex(current, config.capability.previous_secret.as_deref())
            .map_err(|e| anyhow::anyhow!("capability secret: {e}")),
        None => {
            tracing::warn!(
                "capability.secret not configured: using an ephemeral signing key; capability tokens will invalidate on restart"
            );
            Ok(TokenKeys::ephemeral())
        }
    }
}

/// Policy-store management actions (S3-only).
#[derive(Subcommand, Debug)]
enum PolicyAction {
    /// Write every stored policy rule to a JSON file (S3 prefix from --config).
    Export {
        /// Path of the TOML config file (provides [s3] + [database].prefix).
        #[arg(short, long)]
        config: PathBuf,
        /// Output JSON file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Load policy rules from a JSON file into a store (S3 prefix from --config).
    Import {
        /// Path of the TOML config file (provides [s3] + [database].prefix).
        #[arg(short, long)]
        config: PathBuf,
        /// Input JSON file.
        #[arg(long)]
        input: PathBuf,
    },
}

/// Projects the config's `[s3]` section into the storage-agnostic
/// [`S3ClientConfig`] the engine and store factory consume.
///
/// The binary keeps its own [`config::S3Config`] so the library stays
/// decoupled from the config file format; this is the single place the
/// two are translated.
fn s3_client_config(cfg: &config::Config) -> S3ClientConfig {
    S3ClientConfig {
        bucket: cfg.s3.bucket.clone(),
        region: cfg.s3.region.clone(),
        endpoint_url: cfg.s3.endpoint_url.clone(),
        force_path_style: cfg.s3.force_path_style,
        access_key_id: cfg.s3.access_key_id.clone(),
        secret_access_key: cfg.s3.secret_access_key.clone(),
    }
}

/// Object prefix for one domain under the configured `[database].prefix`.
///
/// `db_prefix` is the already-trimmed root prefix. Every store the server
/// builds is `{db_prefix}/{domain}` in the single configured bucket:
/// `policy`, `fs`, `wal`, and (under
/// [`SnapshotManager`](rust_api::sync::snapshot::SnapshotManager))
/// `u/{sha256-hex(sub)}` per user.
fn domain_prefix(db_prefix: &str, domain: &str) -> String {
    format!("{db_prefix}/{domain}")
}

/// Bootstraps the server: loads configuration, initializes the OIDC client
/// and policy engine, registers their API modules, and starts listening.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { config, verbose } => serve(&config, verbose).await,
        Command::Policy { action } => match action {
            PolicyAction::Export { config, out } => {
                let cfg = config::Config::try_from(config.as_path())?;
                let db_prefix = cfg.database.prefix.trim_matches('/').to_string();
                let store = rust_api::db::build_s3_store(
                    &s3_client_config(&cfg),
                    &domain_prefix(&db_prefix, "policy"),
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
                let s3_cfg = s3_client_config(&cfg);
                let db_prefix = cfg.database.prefix.trim_matches('/').to_string();
                let store =
                    rust_api::db::build_s3_store(&s3_cfg, &domain_prefix(&db_prefix, "policy"))
                        .await?;
                let wal_store =
                    rust_api::db::build_s3_store(&s3_cfg, &domain_prefix(&db_prefix, "wal"))
                        .await?;
                let wal_for_import = rust_api::sync::wal::Wal::new(wal_store);
                let bytes =
                    std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
                let dump: rust_api::policy::admin::PolicyDump =
                    serde_json::from_slice(&bytes).context("parse policy dump")?;
                let report = admin::import_s3(store, &dump, Some(Arc::new(wal_for_import))).await?;
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
    // Resolve everything that borrows `config` before it is partially moved
    // into the module configs below.
    let token_keys = resolve_token_keys(&config)?;
    let s3_client_config = s3_client_config(&config);
    let db_prefix = config.database.prefix.trim_matches('/').to_string();
    let mirror_master = config.database.mirror_master;
    let lease_ttl = config.database.writer_lease_ttl_secs;

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

    // Claim the prefix BEFORE building any store: opening an OxKvStore
    // takes an epoch, so a check afterwards would already have displaced
    // the incumbent. Every prefix-scoped store built below (policy, fs,
    // wal, and each per-user replica) then lives under this one lease.
    // `_lease_guard` is held for the rest of `serve`, so the lease is
    // renewed while serving and released on the way out.
    let (lease_lost, _lease_guard) =
        claim_writer_lease(&s3_client_config, &db_prefix, lease_ttl).await?;

    // Single bucket, prefix-scoped OxKvStores per domain (scalable, no local files).
    let policy_store =
        rust_api::db::build_s3_store(&s3_client_config, &domain_prefix(&db_prefix, "policy"))
            .await
            .map_err(|e| anyhow::anyhow!("build policy OxKvStore: {e}"))?;
    let fs_s3_store =
        rust_api::db::build_s3_store(&s3_client_config, &domain_prefix(&db_prefix, "fs"))
            .await
            .map_err(|e| anyhow::anyhow!("build fs OxKvStore: {e}"))?;
    let wal_store =
        rust_api::db::build_s3_store(&s3_client_config, &domain_prefix(&db_prefix, "wal"))
            .await
            .map_err(|e| anyhow::anyhow!("build wal OxKvStore: {e}"))?;
    let wal = Wal::new(wal_store);
    let policy_engine = PolicyEngine::init_s3(policy_store)
        .await?
        .with_change_sink(Arc::new(wal.clone()));
    let setup_api_module = SetupApiModule::new(policy_engine.clone(), oidc_api_module.middleware());
    let policy_api_module =
        PolicyApiModule::new(policy_engine.clone(), oidc_api_module.middleware());
    let fs_engine = FsEngine::init(
        fs_s3_store.clone(),
        &s3_client_config,
        policy_engine.clone(),
    )
    .await?
    .with_token_keys(token_keys)
    .with_change_sink(Arc::new(wal.clone()));
    // GC: expire abandoned multipart uploads every hour (24h TTL)
    rust_api::fs::gc::spawn(std::sync::Arc::new(fs_engine.clone()));
    let fs_api_module = FsApiModule::new(fs_engine, oidc_api_module.middleware());

    // Per-user replica snapshots: master stays the write path, versioned
    // `{prefix}/u/{sub}/{seq}` prefixes are filtered read replicas served
    // over `/sync/db/` for oxkv readers (see `sync::snapshot`).
    let replica_objects: Arc<dyn object_store::ObjectStore> = Arc::new(
        rust_api::fs::object_store::s3_builder(&s3_client_config)
            .build()
            .context("build snapshot object store")?,
    );
    let master_store = if mirror_master {
        FsStore::new_mirrored(fs_s3_store.clone())
            .await
            .map_err(|e| anyhow::anyhow!("open fs mirror: {e}"))?
    } else {
        FsStore::new(fs_s3_store.clone())
    };
    let snapshot_manager = SnapshotManager::new(
        wal.clone(),
        master_store,
        // Replicas only read policy, so hand over the read-only view.
        policy_engine.authorizer(),
        replica_objects,
        db_prefix,
        false,
    );
    let sync_api_module =
        SyncApiModule::new(snapshot_manager.clone(), oidc_api_module.middleware());

    let listen_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.listen_port);
    // Readiness fails when the policy lock is wedged (a writer stuck
    // holding it) or when the single-writer lease is lost, which means a
    // successor now owns the prefix and this process must stop taking
    // traffic. Startup itself already gates on S3/OIDC/JWKS/lease.
    let readiness: rust_api::http::health::ReadyCheck = Arc::new({
        let policy_engine = policy_engine.clone();
        move || {
            policy_engine.is_unlocked() && !lease_lost.load(std::sync::atomic::Ordering::Relaxed)
        }
    });
    let session_api_module = OidcSessionModule::new(oidc_api_module.middleware());
    ApiService::new()
        .with_cors_origins(config.http.allowed_origins.clone())
        .with_readiness_check(readiness)
        .register_module(Box::new(oidc_api_module))
        .register_module(Box::new(session_api_module))
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

/// Claims the single-writer lease for `db_prefix` and starts renewing it.
///
/// Returns the flag to gate `/ready` on plus a guard that must be held for
/// the server's lifetime: dropping the guard stops renewal and releases the
/// lease, which is what makes a rolling restart hand the prefix over without
/// a TTL wait.
///
/// A `ttl_secs` of `0` disables the lease (documented single-node escape
/// hatch) and yields a flag that is never set.
async fn claim_writer_lease(
    s3_cfg: &S3ClientConfig,
    db_prefix: &str,
    ttl_secs: u64,
) -> anyhow::Result<(
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    Option<rust_api::lease::LeaseGuard>,
)> {
    use std::sync::atomic::AtomicBool;

    if ttl_secs == 0 {
        tracing::warn!(
            prefix = %db_prefix,
            "[database].writer_lease_ttl_secs is 0: single-writer enforcement is DISABLED. \
             Two processes on this prefix will silently diverge."
        );
        return Ok((Arc::new(AtomicBool::new(false)), None));
    }
    let store = rust_api::db::build_object_store(s3_cfg)
        .context("build object store for the single-writer lease")?;
    let lease = rust_api::lease::WriterLease::acquire(store, db_prefix, ttl_secs)
        .await
        .with_context(|| format!("claim single-writer lease for prefix {db_prefix:?}"))?;
    tracing::info!(
        instance = lease.instance(),
        ttl_secs,
        "holding single-writer lease for {db_prefix:?}"
    );
    // Renew at a third of the TTL: two consecutive missed renewals still
    // leave a full TTL of headroom before a peer would consider us stale.
    let (lost, guard) = rust_api::lease::spawn_renewer(
        lease,
        std::time::Duration::from_secs(ttl_secs / 3).max(std::time::Duration::from_secs(1)),
    );
    Ok((lost, Some(guard)))
}
