//! Executable entry point for the rust-api starter kit server.
//!
//! `serve` loads the TOML configuration. It starts the OIDC client and the
//! Casbin policy engine. It registers their API modules on an
//! [`rust_api::http::ApiService`]. It starts the HTTP listener. The
//! `policy export` and `policy import` subcommands manage policy data as
//! JSON, for backups and migrations. The `eav reset-cursor` subcommand
//! rewinds the durable rule cursor, for operator recovery.

// The root Cargo.toml sets the deny level through [workspace.lints.clippy].
// The level applies to this target too. This attribute only opens the test
// escape hatch.
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
    eav::{
        entity::EntityStore,
        portable::{self, ValidationReport},
        route::EavApiModule,
        schema::SchemaRegistry,
    },
    fs::{FsEngine, TokenKeys, route::FsApiModule, s3::S3ClientConfig, store::FsStore},
    http::{ApiService, middleware::jwt::Claims},
    oidc::{OidcClient, OidcConfig, route::OidcApiModule},
    policy::{PolicyEngine, admin, route::PolicyApiModule, setup::SetupApiModule},
    queue::{QueueWorker, durable::DurableQueue},
    rules::builtin::{LogAction, NoopAction},
    rules::store::RuleStore,
    rules::webhook::WebhookAction,
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
    /// Operator recovery and data management tools for the EAV stores.
    Eav {
        #[command(subcommand)]
        action: EavAction,
    },
}

/// Resolves the signing keys of the capability token from `[capability]`.
///
/// The check of the config already refused a secret that is not hex. A
/// secret that is absent falls back to a key from the OS random number
/// generator. That key lives only in this run of the process. The server
/// writes a warning. The tokens die with the process, which is fine in
/// development and a mistake in production.
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

/// Actions that manage the policy store. The store must be S3.
#[derive(Subcommand, Debug)]
enum PolicyAction {
    /// Writes every stored policy rule to a JSON file. The S3 prefix comes
    /// from `--config`.
    Export {
        /// Path of the TOML config file. It provides `[s3]` and
        /// `[database].prefix`.
        #[arg(short, long)]
        config: PathBuf,
        /// Path of the output JSON file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Reads policy rules from a JSON file and loads them into a store. The
    /// S3 prefix comes from `--config`.
    Import {
        /// Path of the TOML config file. It provides `[s3]` and
        /// `[database].prefix`.
        #[arg(short, long)]
        config: PathBuf,
        /// Path of the input JSON file.
        #[arg(long)]
        input: PathBuf,
    },
}

/// Actions that manage or recover the EAV stores. The store must be S3.
#[derive(Subcommand, Debug)]
enum EavAction {
    /// Sets the durable rule cursor to an earlier feed sequence.
    ///
    /// Stop the server first. The command takes the writer lease.
    /// It refuses to run while another process holds that lease.
    ResetCursor {
        /// Path of the TOML config file. It provides `[s3]` and
        /// `[database].prefix`.
        #[arg(short, long)]
        config: PathBuf,
        /// The feed sequence to write as the new cursor.
        ///
        /// The value must be at or below the feed head.
        #[arg(long)]
        to: u64,
    },
    /// Writes every stored schema, entity, and rule to a JSON file.
    Export {
        /// Path of the TOML config file. It provides `[s3]` and
        /// `[database].prefix`.
        #[arg(short, long)]
        config: PathBuf,
        /// Path of the output JSON file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Reads a JSON file into an empty EAV prefix and checks the restore.
    Import {
        /// Path of the TOML config file. It provides `[s3]` and
        /// `[database].prefix`.
        #[arg(short, long)]
        config: PathBuf,
        /// Path of the input JSON file.
        #[arg(long = "in")]
        input: PathBuf,
    },
    /// Rewrites the EAV index rows from the stored entities.
    RebuildIndex {
        /// Path of the TOML config file. It provides `[s3]` and
        /// `[database].prefix`.
        #[arg(short, long)]
        config: PathBuf,
        /// Rebuild only the entities that pin this schema id.
        #[arg(long)]
        schema: Option<String>,
    },
    /// Checks the pinned schemas, the unique claims, and the references.
    Validate {
        /// Path of the TOML config file. It provides `[s3]` and
        /// `[database].prefix`.
        #[arg(short, long)]
        config: PathBuf,
    },
}

/// Turns the `[s3]` section of the config into the [`S3ClientConfig`] that
/// the engine and the store factory use.
///
/// The binary keeps its own [`config::S3Config`]. That keeps the library
/// separate from the format of the config file. This function is the only
/// place where the code translates between the two.
fn s3_client_config(cfg: &config::Config) -> S3ClientConfig {
    S3ClientConfig {
        bucket: cfg.s3.bucket.clone(),
        region: cfg.s3.region.clone(),
        endpoint_url: cfg.s3.endpoint_url.clone(),
        force_path_style: cfg.s3.force_path_style,
        access_key_id: cfg.s3.access_key_id.clone(),
        secret_access_key: cfg.s3.secret_access_key.clone(),
        backend: cfg.s3.backend,
    }
}

/// Object prefix for one domain, under the `[database].prefix` of the config.
///
/// `db_prefix` is the root prefix, already trimmed. Every store that the
/// server builds is `{db_prefix}/{domain}` in the one configured bucket.
/// The domains are `policy`, `fs`, and `wal`. For each user, the domain is
/// `u/{sha256-hex(sub)}`. The user domains come from
/// [`SnapshotManager`](rust_api::sync::snapshot::SnapshotManager).
fn domain_prefix(db_prefix: &str, domain: &str) -> String {
    format!("{db_prefix}/{domain}")
}

/// Starts the server. The function loads the configuration. It starts the
/// OIDC client and the policy engine. It registers their API modules. It
/// starts the listener.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Serve { config, verbose } => serve(&config, verbose).await,
        Command::Policy { action } => run_policy_command(action).await,
        Command::Eav { action } => run_eav_command(action).await,
    }
}

/// One line that names the action which asks for the lease. The line goes
/// into the failure message when another process already holds the lease.
fn policy_action_name(action: &PolicyAction) -> &'static str {
    match action {
        PolicyAction::Export { .. } => "policy export",
        PolicyAction::Import { .. } => "policy import",
    }
}

/// Runs `policy export` or `policy import` on the configured prefix.
///
/// `policy import` writes to the prefix. It builds an `OxKvStore`, which does
/// a CAS bump on `ownership.json` and takes an epoch. The server does the same
/// operation at startup. So the import *fences* a running server. The server
/// finds out at its next write to the policy. That write fails with
/// `StoreError::Fenced`. The write calls `note_primary_loss`, which sets a
/// latch that nothing clears. Then `/ready`, which checks
/// `!fencing::primary_loss()`, returns 503. The instance stays out of the
/// rotation.
///
/// So `import` claims the writer lease first. It does so before it builds any
/// store, in the same way as `serve`. When a live server holds the lease, the
/// command refuses. The message then names the prefix and the instance. That
/// replaces a quiet displacement of a healthy writer.
///
/// `policy export` only reads. It uses `build_s3_reader`, which opens an
/// `OxKvReader`. A reader takes no epoch and writes no `ownership.json`. So an
/// export does not fence the writer, and it does not need the lease.
async fn run_policy_command(action: PolicyAction) -> anyhow::Result<()> {
    let purpose = policy_action_name(&action);
    // Both values appear before the match that takes the action. So
    // each branch below uses the path that it was given, instead of an
    // `Option` that the code builds again from the enum.
    let file = match &action {
        PolicyAction::Export { out, .. } => out.clone(),
        PolicyAction::Import { input, .. } => input.clone(),
    };
    let cfg = match &action {
        PolicyAction::Export { config, .. } | PolicyAction::Import { config, .. } => {
            config::Config::try_from(config.as_path())?
        }
    };
    let s3_cfg = s3_client_config(&cfg);
    let db_prefix = cfg.database.prefix.trim_matches('/').to_string();
    rust_api::db::configure_sst_cache_bytes(cfg.database.sst_cache_mb.saturating_mul(1024 * 1024));

    match action {
        PolicyAction::Export { .. } => export_policy(&s3_cfg, &db_prefix, &file).await,
        PolicyAction::Import { .. } => {
            // This happens BEFORE the code builds any store. Opening a store
            // takes an epoch. So a check after that point would already have
            // fenced the process that holds the lease. No renewer task starts
            // here. This process ends soon. The guard below gives the lease
            // straight back.
            let (_lost, guard) = claim_writer_lease(
                &s3_cfg,
                &db_prefix,
                cfg.database.writer_lease_ttl_secs,
                purpose,
            )
            .await?;

            let result = import_policy(&s3_cfg, &db_prefix, &file).await;

            // Give the prefix back, even when the work failed. Otherwise a
            // failed import makes the next one wait out the TTL.
            if let Some(guard) = guard {
                guard.release().await;
            }
            result
        }
    }
}

/// Runs one EAV command.
async fn run_eav_command(action: EavAction) -> anyhow::Result<()> {
    if let EavAction::ResetCursor { config, to } = &action {
        return reset_eav_cursor(config, *to).await;
    }

    let purpose = eav_action_name(&action);
    let config = match &action {
        EavAction::ResetCursor { config, .. }
        | EavAction::Export { config, .. }
        | EavAction::Import { config, .. }
        | EavAction::RebuildIndex { config, .. }
        | EavAction::Validate { config } => config,
    };
    let cfg = config::Config::try_from(config.as_path())?;
    let s3_cfg = s3_client_config(&cfg);
    let db_prefix = cfg.database.prefix.trim_matches('/').to_string();
    // Set the cache budget before the first EAV store is built.
    rust_api::db::configure_sst_cache_bytes(cfg.database.sst_cache_mb.saturating_mul(1024 * 1024));

    let (_lost, guard) = claim_writer_lease(
        &s3_cfg,
        &db_prefix,
        cfg.database.writer_lease_ttl_secs,
        purpose,
    )
    .await?;

    let result = run_eav_action(&action, &s3_cfg, &db_prefix).await;

    if let Some(guard) = guard {
        guard.release().await;
    }
    result
}

/// Refuses a cursor above the feed head.
///
/// The rule runner fails at startup when the cursor is ahead of the head.
/// The check here turns that late failure into a clear refusal.
fn check_reset_target(to: u64, head: u64) -> anyhow::Result<()> {
    if to > head {
        return Err(anyhow::anyhow!(
            "cannot reset the rule cursor to {to}: the change-feed head is {head}. \
             Use a sequence at or below the head."
        ));
    }
    Ok(())
}

/// Resets the durable rule cursor under the configured prefix.
///
/// The function claims the writer lease before it builds any store. The
/// lease refuses a prefix that a live writer owns. The function then reads
/// the feed head and the rule store. It writes the new cursor and prints the
/// old and new values.
///
/// The caller must stop the server first. A reset behind the cursor replays
/// feed entries. Execution markers stop duplicate actions inside the
/// retention window.
async fn reset_eav_cursor(config_path: &Path, to: u64) -> anyhow::Result<()> {
    let cfg = config::Config::try_from(config_path)?;
    let s3_cfg = s3_client_config(&cfg);
    let db_prefix = cfg.database.prefix.trim_matches('/').to_string();
    // Set the cache budget before the first EAV store is built.
    rust_api::db::configure_sst_cache_bytes(cfg.database.sst_cache_mb.saturating_mul(1024 * 1024));
    let (_lost, guard) = claim_writer_lease(
        &s3_cfg,
        &db_prefix,
        cfg.database.writer_lease_ttl_secs,
        "eav reset-cursor",
    )
    .await?;

    let result = reset_eav_cursor_with_store(&s3_cfg, &db_prefix, to).await;

    if let Some(guard) = guard {
        guard.release().await;
    }
    result
}

/// Reads the feed head and resets the rule cursor.
///
/// The caller claims the writer lease before this call.
async fn reset_eav_cursor_with_store(
    s3_cfg: &S3ClientConfig,
    db_prefix: &str,
    to: u64,
) -> anyhow::Result<()> {
    let wal_store = rust_api::db::build_s3_store(s3_cfg, &domain_prefix(db_prefix, "wal")).await?;
    let wal = Wal::new(wal_store);
    let head = wal.head().await.context("read the change-feed head")?;
    check_reset_target(to, head)?;

    let rule_store = rust_api::db::build_s3_store(
        s3_cfg,
        &rust_api::eav::runtime::rule_store_prefix(db_prefix),
    )
    .await?;
    let rules = rust_api::rules::store::RuleStore::new(rule_store);
    let (old, new) = rules
        .reset_cursor(to)
        .await
        .context("reset the rule cursor")?;
    println!("rule cursor reset from {old} to {new}");
    Ok(())
}

/// Writes every stored policy rule to `out` as JSON.
///
/// The function reads through `build_s3_reader`. The reader takes no epoch.
/// So an export against a live prefix does not fence the server.
async fn export_policy(s3_cfg: &S3ClientConfig, db_prefix: &str, out: &Path) -> anyhow::Result<()> {
    let reader = rust_api::db::build_s3_reader(s3_cfg, &domain_prefix(db_prefix, "policy")).await?;
    let dump = admin::export_s3(reader).await?;
    std::fs::write(
        out,
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

/// Loads the policy rules from `input` into the store. The function announces
/// them on the change feed, so that the replicas that run converge.
///
/// The function builds a writer store. `run_policy_command` claims the writer
/// lease before it calls this function, so a live server is not fenced.
async fn import_policy(
    s3_cfg: &S3ClientConfig,
    db_prefix: &str,
    input: &Path,
) -> anyhow::Result<()> {
    let store = rust_api::db::build_s3_store(s3_cfg, &domain_prefix(db_prefix, "policy")).await?;
    let wal_store = rust_api::db::build_s3_store(s3_cfg, &domain_prefix(db_prefix, "wal")).await?;
    let wal_for_import = rust_api::sync::wal::Wal::new(wal_store);
    let bytes = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let dump: rust_api::policy::admin::PolicyDump =
        serde_json::from_slice(&bytes).context("parse policy dump")?;
    let report = admin::import_s3(store, &dump, Some(Arc::new(wal_for_import))).await?;
    println!(
        "imported {} rules and {} group memberships ({} duplicates skipped) into {}",
        report.rules_added, report.groups_added, report.duplicates, db_prefix
    );
    Ok(())
}

/// One line that names the action which asks for the lease.
fn eav_action_name(action: &EavAction) -> &'static str {
    match action {
        EavAction::ResetCursor { .. } => "eav reset-cursor",
        EavAction::Export { .. } => "eav export",
        EavAction::Import { .. } => "eav import",
        EavAction::RebuildIndex { .. } => "eav rebuild-index",
        EavAction::Validate { .. } => "eav validate",
    }
}

/// Returns the store prefix for one EAV domain.
///
/// An empty root omits the leading slash.
/// The server uses the same layout.
fn eav_domain_prefix(db_prefix: &str, domain: &str) -> String {
    let root = db_prefix.trim_matches('/');
    if root.is_empty() {
        format!("eav/{domain}")
    } else {
        format!("{root}/eav/{domain}")
    }
}

/// Builds the three EAV stores at the prefixes of the server.
async fn build_eav_stores(
    s3_cfg: &S3ClientConfig,
    db_prefix: &str,
) -> anyhow::Result<(SchemaRegistry, EntityStore, RuleStore)> {
    let schema_store =
        rust_api::db::build_s3_store(s3_cfg, &eav_domain_prefix(db_prefix, "schema"))
            .await
            .context("build the EAV schema store")?;
    let entity_store =
        rust_api::db::build_s3_store(s3_cfg, &eav_domain_prefix(db_prefix, "entity"))
            .await
            .context("build the EAV entity store")?;
    let rule_store = rust_api::db::build_s3_store(s3_cfg, &eav_domain_prefix(db_prefix, "rules"))
        .await
        .context("build the EAV rule store")?;
    let schemas = SchemaRegistry::new(schema_store);
    let entities = EntityStore::new(entity_store, schemas.clone());
    let rules = RuleStore::new(rule_store);
    Ok((schemas, entities, rules))
}

/// Builds the stores and runs the selected `eav` action.
async fn run_eav_action(
    action: &EavAction,
    s3_cfg: &S3ClientConfig,
    db_prefix: &str,
) -> anyhow::Result<()> {
    let (schemas, entities, rules) = build_eav_stores(s3_cfg, db_prefix).await?;
    match action {
        EavAction::ResetCursor { to, .. } => {
            reset_eav_cursor_with_store(s3_cfg, db_prefix, *to).await?;
        }
        EavAction::Export { out, .. } => {
            let file =
                std::fs::File::create(out).with_context(|| format!("create {}", out.display()))?;
            let mut writer = std::io::BufWriter::new(file);
            let report = portable::export(&schemas, &entities, &rules, &mut writer).await?;
            println!(
                "exported {} schema records, {} entity records, and {} rule records to {}",
                report.schemas,
                report.entities,
                report.rules,
                out.display()
            );
        }
        EavAction::Import { input, .. } => {
            let file =
                std::fs::File::open(input).with_context(|| format!("read {}", input.display()))?;
            let reader = std::io::BufReader::new(file);
            let report = portable::import(&schemas, &entities, &rules, reader).await?;
            println!(
                "imported {} schema records, {} entity records, and {} rule records into {db_prefix}",
                report.schemas, report.entities, report.rules
            );
            let validation = portable::validate(&schemas, &entities, &rules).await?;
            print_validation_report(&validation);
            if !validation.is_ok() {
                anyhow::bail!("restore validation failed");
            }
        }
        EavAction::RebuildIndex { schema, .. } => {
            let report = portable::rebuild_indexes(&entities, schema.as_deref()).await?;
            println!(
                "rebuilt {} entities in {} pages: {} attribute rows, {} unique claims, {} time rows, and {} name markers",
                report.entities,
                report.pages,
                report.attribute_rows,
                report.unique_claims,
                report.time_rows,
                report.name_markers
            );
        }
        EavAction::Validate { .. } => {
            let report = portable::validate(&schemas, &entities, &rules).await?;
            print_validation_report(&report);
            if !report.is_ok() {
                anyhow::bail!("restore validation failed");
            }
        }
    }
    Ok(())
}

/// Prints the counts and the problems of one restore check.
fn print_validation_report(report: &ValidationReport) {
    println!(
        "checked {} schemas, {} entities, and {} rules",
        report.schemas, report.entities, report.rules
    );
    for issue in &report.missing_schemas {
        println!(
            "entity {} pins missing schema {} version {}",
            issue.entity_id, issue.schema_id, issue.version
        );
    }
    for issue in &report.dangling_refs {
        println!(
            "entity {} attribute {} references missing entity {}",
            issue.entity_id, issue.attribute, issue.target
        );
    }
    for issue in &report.unique_claim_issues {
        println!("unique attribute {}: {}", issue.attribute, issue.detail);
    }
    for issue in &report.schema_conflicts {
        println!("schema conflict: {issue}");
    }
}

/// Inputs that decide whether this instance can serve writes.
struct ReadinessInputs {
    /// The policy lock is free.
    policy_unlocked: bool,
    /// The single-writer lease was lost.
    lease_lost: bool,
    /// A primary prefix was fenced.
    primary_loss: bool,
    /// The last dependency probe succeeded.
    dependencies_healthy: bool,
    /// An EAV background loop is failed.
    eav_failed: bool,
}

/// Returns `true` when this instance can serve writes.
///
/// Readiness stays false until a later pass succeeds after an EAV failure.
fn readiness_state(input: ReadinessInputs) -> bool {
    input.policy_unlocked
        && !input.lease_lost
        && !input.primary_loss
        && input.dependencies_healthy
        && !input.eav_failed
}

/// Returns the job kinds that a client may submit.
///
/// Only `entity.create` is submittable. The webhook delivery kind is a
/// worker-only kind and stays private.
fn submittable_kinds() -> Result<rust_api::jobs::SubmittableKinds, rust_api::jobs::JobKindsError> {
    rust_api::jobs::SubmittableKinds::from_names(["entity.create"])
}

/// Runs the HTTP listener until stopped.
async fn serve(config_path: &Path, verbose: bool) -> anyhow::Result<()> {
    let config = config::Config::try_from(config_path)?;
    // One SST cache serves every OxKV handle. Set its budget before the code
    // builds the first handle.
    rust_api::db::configure_sst_cache_bytes(
        config.database.sst_cache_mb.saturating_mul(1024 * 1024),
    );
    // Resolve every value that borrows `config`, before the code moves
    // parts of `config` into the configs of the modules below.
    let s3_client_config = s3_client_config(&config);
    let db_prefix = config.database.prefix.trim_matches('/').to_string();
    let mirror_master = config.database.mirror_master;
    let lease_ttl = config.database.writer_lease_ttl_secs;
    // Read the EAV settings before the code moves other config fields.
    let eav_config = config.eav.runtime_config();
    let eav_max_causation_depth = config.eav.max_causation_depth;
    let webhook_signing_secret = config.eav.webhook_signing_secret.clone();
    let webhook_max_attempts = config.eav.webhook_max_attempts;
    let webhook_allow_private_hosts = config.eav.webhook_allow_private_hosts;
    let setup_token = config.authorization.setup_token.clone();

    let telemetry = telemetry::init(
        if verbose {
            telemetry::LogVerbosity::Verbose
        } else {
            telemetry::LogVerbosity::Normal
        },
        &config.observability.service_name,
        config.observability.otlp_endpoint.as_deref(),
        config.observability.sample_ratio,
    )?;

    // The subscriber now exists. Warnings that startup raised before this
    // point are visible only when they are logged here.
    for warning in config.startup_warnings() {
        tracing::warn!(field = warning.field, "{}", warning.message);
    }
    let token_keys = resolve_token_keys(&config)?;

    let base = Url::parse(&config.public_address).context("Invalid public_address in config")?;

    // Keep the discovery URL for the dependency probe. `OidcClient::new`
    // moves `issuer_url` into the client, so the probe needs its own copy.
    let oidc_discovery_url = format!(
        "{}/.well-known/openid-configuration",
        config.authorization.issuer_url.trim_end_matches('/')
    );

    let oidc_client = OidcClient::new(OidcConfig {
        client_id: config.authorization.client_id.clone(),
        client_secret: config.authorization.client_secret,
        issuer_url: config.authorization.issuer_url,
        redirect_url: base
            .join("auth/callback")
            .context("Failed to build redirect URL")?
            .to_string(),
        allowed_tenants: config.authorization.allowed_tenants.clone(),
    })
    .await?;
    let oidc_api_module = OidcApiModule::<Claims>::init(oidc_client).await?;

    // Claim the prefix BEFORE the code builds any store. Opening an
    // OxKvStore takes an epoch. So a check after that point would already
    // have displaced the process that holds the lease. Every store that is
    // built below, which covers policy, fs, wal, and each replica of a user,
    // then lives under this one lease.
    //
    // `serve` holds `lease_guard` until the function returns. So the lease
    // renews while the server serves traffic. The function also releases it
    // at the end. See the await after `start` below.
    let (lease_lost, lease_guard) =
        claim_writer_lease(&s3_client_config, &db_prefix, lease_ttl, "serve").await?;

    // One bucket. The OxKVStores use one prefix per domain, so they can
    // grow. The server keeps no local files.
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
    // A crash can leave a committed policy change in the outbox with no
    // feed entry. The feed is wired now, so deliver those rows before the
    // server accepts traffic. A failed drain stops startup instead of
    // leaving replicas behind.
    policy_engine.drain_outbox().await?;
    let setup_api_module = SetupApiModule::new(
        policy_engine.clone(),
        oidc_api_module.middleware(),
        setup_token,
    );
    let policy_api_module =
        PolicyApiModule::new(policy_engine.clone(), oidc_api_module.middleware());
    let fs_engine = FsEngine::init(
        fs_s3_store.clone(),
        &s3_client_config,
        // `fs` only reads the policy, so it gets the read-only handle. It
        // is the same handle that the manager of the replica snapshots
        // already takes.
        policy_engine.authorizer(),
    )
    .await?
    .with_token_keys(token_keys)
    .with_change_sink(Arc::new(wal.clone()));
    // Cancellation token shared by every background task. The token is
    // cancelled after the server stops serving, so the tasks exit instead
    // of being dropped mid-flight.
    let cancel = tokio_util::sync::CancellationToken::new();

    // Start the EAV runtime and API module. The runtime is always on. A host
    // that does not want EAV removes this wiring in code and rebuilds. The
    // binary registers the built-in `noop` and `log` actions. A host
    // application adds its own actions through `EavRuntime::build`. The module
    // and the background loops share one runtime handle.
    // The webhook worker uses one durable queue under `{prefix}/eav-queue`.
    let queue_store =
        rust_api::db::build_s3_store(&s3_client_config, &domain_prefix(&db_prefix, "eav-queue"))
            .await
            .map_err(|e| anyhow::anyhow!("build EAV queue OxKvStore: {e}"))?;
    let queue: Arc<dyn rust_api::queue::JobQueue> = Arc::new(DurableQueue::new(Arc::new(
        tokio::sync::RwLock::new(queue_store),
    )));
    let signing_secret = webhook_signing_secret
        .as_ref()
        .map(|secret| secret.as_bytes().to_vec());
    let webhook = WebhookAction::new(config.eav.webhook_allowed_hosts.clone())
        .allow_private_hosts(webhook_allow_private_hosts)
        .with_queue(queue.clone(), signing_secret, webhook_max_attempts);
    // Capture the webhook handler before the runtime takes the action.
    let webhook_handler: Arc<dyn rust_api::queue::JobHandler> = Arc::new(webhook.job_handler());
    let runtime = rust_api::eav::runtime::EavRuntime::build(
        &s3_client_config,
        &db_prefix,
        wal.clone(),
        vec![Arc::new(NoopAction), Arc::new(LogAction), Arc::new(webhook)],
        if config.eav.check_entity_refs {
            rust_api::eav::runtime::RefCheck::On
        } else {
            rust_api::eav::runtime::RefCheck::Off
        },
        eav_max_causation_depth,
        if config.eav.script_enabled {
            rust_api::eav::runtime::Scripts::Enabled
        } else {
            rust_api::eav::runtime::Scripts::Disabled
        },
    )
    .await
    .context("build the EAV runtime")?;
    let runtime = runtime.with_full_replica_limit(config.limits.max_full_replica_bytes);

    // The HTTP job routes share the queue with the worker, so clone it
    // before the worker takes ownership. Build the handler list one time,
    // then validate the worker kinds. The route uses a separate
    // submittable set, so a worker-only kind stays private.
    let handlers: Vec<Arc<dyn rust_api::queue::JobHandler>> = vec![
        webhook_handler,
        Arc::new(rust_api::jobs::entity::EntityCreateHandler::new(
            runtime.entities().clone(),
            wal.clone(),
            policy_engine.authorizer(),
        )),
    ];
    let worker_kinds = rust_api::jobs::WorkerKinds::from_handlers(&handlers)?;
    let submittable = submittable_kinds()?;
    submittable.ensure_subset_of(&worker_kinds)?;
    let job_stream_gate =
        rust_api::limits::ConcurrencyGate::new(config.limits.max_job_event_streams());
    let job_stream_max_duration =
        std::time::Duration::from_secs(config.limits.job_event_stream_max_secs());
    let jobs_api_module = rust_api::jobs::JobsApiModule::new(
        queue.clone(),
        oidc_api_module.middleware(),
        policy_engine.authorizer(),
        submittable,
    )
    .with_stream_gate(job_stream_gate)
    .with_stream_max_duration(job_stream_max_duration);
    let worker = QueueWorker::new(queue, handlers, "eav-jobs".to_string());
    let worker_cancel = cancel.clone();
    let webhook_worker = tokio::spawn(async move { worker.run(worker_cancel).await });
    let eav_api_module = EavApiModule::new(
        runtime.clone(),
        policy_engine.authorizer(),
        oidc_api_module.middleware(),
    );
    let eav_handle = runtime.spawn(cancel.clone(), eav_config);
    let eav_failures = runtime.loop_failures();

    // Applications append their own reactive services here. The starter kit
    // ships none, so the list stays empty. Each entry implements
    // `rust_api::reactive::ReactiveService`.
    let reactive_services: Vec<Arc<dyn rust_api::reactive::ReactiveService>> = vec![];

    // `fs_engine` is moved into `FsApiModule` below. Clone it first, as the
    // context keeps its own handle.
    let reactive_context = rust_api::reactive::ReactiveContext {
        policy: Arc::new(policy_engine.clone()),
        fs: Arc::new(fs_engine.clone()),
        wal: Arc::new(wal.clone()),
        db_prefix: db_prefix.clone(),
        s3: s3_client_config.clone(),
        cancel: cancel.clone(),
    };

    let reactive_handles = rust_api::reactive::spawn_services(&reactive_services, reactive_context);

    // Garbage collection. The server removes multipart uploads that
    // were never finished, every hour. The TTL is 24 hours.
    rust_api::fs::gc::spawn(std::sync::Arc::new(fs_engine.clone()), cancel.clone());
    let fs_api_module = FsApiModule::new(fs_engine, oidc_api_module.middleware());

    // Snapshots of the replica of each user. The master stays the write
    // path. The versioned prefixes `{prefix}/u/{sub}/{seq}` are read replicas
    // that filter the data. The server serves them through `/sync/db/` for
    // the oxkv readers. See `sync::snapshot`.
    let replica_objects: Arc<dyn object_store::ObjectStore> =
        if s3_client_config.backend == rust_api::fs::s3::S3Backend::Memory {
            rust_api::db::build_object_store(&s3_client_config)
                .context("build snapshot object store")?
        } else {
            Arc::new(
                rust_api::fs::object_store::s3_builder(&s3_client_config)
                    .build()
                    .context("build snapshot object store")?,
            )
        };
    // Cheap, non-blocking dependency probes. The flags start healthy;
    // startup already verified S3 and OIDC before the listener bound. A
    // background task refreshes them, so `/ready` can report a dependency
    // that went away without blocking the probe.
    let dependency_health = rust_api::http::health::DependencyHealth::new();
    dependency_health.spawn_probes(replica_objects.clone(), oidc_discovery_url, cancel.clone());
    let master_store = if mirror_master {
        FsStore::new_mirrored(fs_s3_store.clone())
            .await
            .map_err(|e| anyhow::anyhow!("open fs mirror: {e}"))?
    } else {
        FsStore::new(fs_s3_store.clone())
    };
    // The function creates the queue of rebuilds here, so that a pool
    // of workers can empty it. `POST /sync/sync` runs a bounded set of
    // incremental replays in the request, and it *queues* the full rebuilds.
    // Without the pool, a subject that needs a new calculation would report
    // `pending` forever. It would never converge.
    let (builds, build_jobs) = rust_api::sync::snapshot::BuildQueue::new();
    let snapshot_manager = SnapshotManager::new(
        rust_api::sync::snapshot::SnapshotDeps {
            wal: wal.clone(),
            store: master_store,
            // Replicas only read the policy, so the code gives them the
            // read-only view.
            policy: policy_engine.authorizer(),
            object_store: replica_objects,
            builds,
        },
        db_prefix,
        rust_api::sync::snapshot::ReplicaBackend::ObjectStore,
    );
    // The size is small on purpose. Each build sends its own set of
    // changes, so the memory use follows the size of a change and not the
    // size of a replica. The build still reads the master and writes to S3.
    // So this size limits the load on the object store as much as it limits
    // the use of the CPU.
    rust_api::sync::snapshot::BuildPool::new(build_jobs).spawn(
        std::sync::Arc::new(snapshot_manager.clone()),
        2,
        cancel.clone(),
    );
    let sync_api_module = SyncApiModule::with_download_gate(
        snapshot_manager.clone(),
        oidc_api_module.middleware(),
        config.limits.max_concurrent_downloads,
    );

    let listen_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.listen_port);
    // The readiness check fails when the policy lock is stuck, which
    // happens when a writer still holds it. It also fails when the
    // single-writer lease is lost. A lost lease means that a successor now
    // owns the prefix. This process must stop taking traffic. The startup of
    // the server already checks S3, OIDC, JWKS, and the lease. The check also
    // fails when an EAV background loop is failed.
    let readiness: rust_api::http::health::ReadyCheck = Arc::new({
        let policy_engine = policy_engine.clone();
        let dependency_health = dependency_health.clone();
        let eav_failures = eav_failures.clone();
        move || {
            // Five separate reasons mean that this instance cannot serve
            // writes. Any one of them is enough to take it out of the
            // rotation:
            //
            // - The policy lock is held, so reads would block.
            // - The single-writer lease was lost. A peer took the prefix
            //   with the agreement of both sides.
            // - A primary prefix was fenced without agreement. This is the
            //   same condition in another form. An older build causes it. So
            //   does a deployment with `writer_lease_ttl_secs = 0`. So does
            //   an operator who runs `policy import` against a prefix that
            //   is live. The check of the lease cannot see this, so
            //   `fencing` reports it on its own.
            // - An external dependency (S3 or OIDC) failed its last
            //   background probe.
            // - An EAV background loop is failed. Entity events may not flow.
            //   Readiness stays false until a pass succeeds.
            readiness_state(ReadinessInputs {
                policy_unlocked: policy_engine.is_unlocked(),
                lease_lost: lease_lost.load(std::sync::atomic::Ordering::Relaxed),
                primary_loss: rust_api::fencing::primary_loss(),
                dependencies_healthy: dependency_health.is_healthy(),
                eav_failed: eav_failures.failed(),
            })
        }
    });
    // The function builds the server first, so that it can start the
    // listener as the last step that can fail. Anything that fails after
    // the lease is claimed and before the server listens takes the path of
    // the early error. On that path, the best-effort release of the `Drop`
    // of the guard is all that there is.
    let service = ApiService::new()
        .with_cors_origins(config.http.allowed_origins.clone())
        .with_docs(config.http.expose_docs)
        .with_rate_limit(rust_api::limits::TokenBucket::new(
            config.limits.burst_or_rate(),
            config.limits.rate_per_minute,
        ))
        .with_readiness_check(readiness)
        .register_module(Box::new(oidc_api_module))
        .register_module(Box::new(setup_api_module))
        .register_module(Box::new(policy_api_module))
        .register_module(Box::new(fs_api_module))
        .register_module(Box::new(sync_api_module))
        .register_module(Box::new(eav_api_module))
        .register_module(Box::new(jobs_api_module));
    let served = service.start(listen_addr.into()).await;

    // This is the orderly release, and the code awaits it. `start` returns
    // on SIGTERM, which is the path that drains the server. So this is the
    // place where the lease must return. Dropping the guard only *makes*
    // the release runnable. The runtime that would poll the release is about
    // to be dropped too. Code that skipped this left the record in place. So
    // a replacement pod read it as a live lease. The pod then entered
    // CrashLoopBackOff until the TTL expired. That happened on every clean
    // shutdown. It also defeated the handover on a rolling restart, which is
    // the one thing that this lease exists for.
    //
    // Stop the background tasks before releasing the lease. The tasks
    // observe the token and exit their loops instead of being dropped.
    cancel.cancel();

    // Stop reactive services before releasing the lease. They observe the
    // token and exit their loops instead of being dropped.
    for handle in reactive_handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(?error, "reactive service failed"),
            Err(error) => tracing::error!(?error, "reactive service task failed"),
        }
    }

    // Stop the EAV runtime with the other background tasks.
    match eav_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::error!(?error, "EAV runtime failed"),
        Err(error) => tracing::error!(?error, "EAV runtime task failed"),
    }

    // The worker observes the shared token and exits after one poll.
    match webhook_worker.await {
        Ok(()) => {}
        Err(error) => tracing::error!(?error, "webhook worker task failed"),
    }

    // This runs before the flush of the telemetry, so that the log lines of
    // the release reach the collector.
    if let Some(guard) = lease_guard {
        guard.release().await;
    }

    served?;

    // This flushes the telemetry on the normal exit path. The spans and
    // the metric points that are still pending are then delivered. A
    // failure is reported, instead of being dropped without a word. The
    // `Drop` fallback remains, for the paths that end in an error.
    telemetry.shutdown()?;

    Ok(())
}

/// Why the writer lease could not be claimed. The text goes to the operator
/// who runs `purpose` against a prefix that a live server already owns.
///
/// The failure that the message prevents is invisible from the command
/// line. The command opens a second writer handle. The server is fenced.
///    The server drains on its next write to the policy, through a latch that
/// nothing clears. A command that exits with a non-zero status and prints
/// this text changes nothing.
fn lease_refused_message(purpose: &str, db_prefix: &str) -> String {
    format!(
        "cannot run `{purpose}`: it opens a second writer handle on \
         [database].prefix {db_prefix:?}, which fences the process already \
         writing there until it restarts. Stop it first, or wait for its \
         lease to go stale."
    )
}

/// Claims the single-writer lease for `db_prefix` and starts the renewal.
///
/// The function returns the flag for the check of `/ready`. It also
/// returns a guard that the caller must hold for the run of the server.
/// Releasing the guard stops the renewal.
/// [`LeaseGuard::release`](rust_api::lease::LeaseGuard::release) gives the
/// prefix back. That is what lets a rolling restart hand the prefix over
/// without a wait for the TTL. A caller must await the release. It must
/// not drop the guard. The docs of the guard say what dropping does at the
/// end of the process.
///
/// A `ttl_secs` of `0` disables the lease. That is the documented way to
/// run one node. The flag that the function returns then never gets set.
///
/// `purpose` names the caller in the failure message. The policy
/// subcommands and `eav reset-cursor` pass their own name. The text "another
/// writer holds `oxkv`" is hard to read while a backup runs. It is also hard
/// to read while the server serves traffic.
async fn claim_writer_lease(
    s3_cfg: &S3ClientConfig,
    db_prefix: &str,
    ttl_secs: u64,
    purpose: &str,
) -> anyhow::Result<(
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    Option<rust_api::lease::LeaseGuard>,
)> {
    use std::sync::atomic::AtomicBool;

    if ttl_secs == 0 || s3_cfg.backend == rust_api::fs::s3::S3Backend::Memory {
        tracing::warn!(
            prefix = %db_prefix,
            "single-writer enforcement is DISABLED (memory backend or ttl 0)."
        );
        return Ok((Arc::new(AtomicBool::new(false)), None));
    }
    let store = rust_api::db::build_object_store(s3_cfg)
        .context("build object store for the single-writer lease")?;
    claim_writer_lease_on(store, db_prefix, ttl_secs, purpose).await
}

/// Claims the single-writer lease on one object store.
///
/// This function holds the part of [`claim_writer_lease`] that a test can
/// call with an in-memory object store.
/// The caller supplies a store that is not the memory backend of the config.
/// The function starts the renewal and returns the same values as
/// [`claim_writer_lease`].
async fn claim_writer_lease_on(
    store: std::sync::Arc<dyn object_store::ObjectStore>,
    db_prefix: &str,
    ttl_secs: u64,
    purpose: &str,
) -> anyhow::Result<(
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    Option<rust_api::lease::LeaseGuard>,
)> {
    let lease = rust_api::lease::WriterLease::acquire(store, db_prefix, ttl_secs)
        .await
        .with_context(|| lease_refused_message(purpose, db_prefix))?;
    tracing::info!(
        instance = lease.instance(),
        ttl_secs,
        "holding single-writer lease for {db_prefix:?}"
    );
    // Renew at one third of the TTL. Two renewals that fail in a row
    // still leave a whole TTL of time before a peer sees this process
    // as stale.
    let (lost, guard) = rust_api::lease::spawn_renewer(
        lease,
        std::time::Duration::from_secs(ttl_secs / 3).max(std::time::Duration::from_secs(1)),
    );
    Ok((lost, Some(guard)))
}

/// The main code of the crate had no test. So the code most likely to fail
/// without a report sat in the three pure functions here. Those functions
/// had no test at all.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// Builds a `Config` from a TOML document.
    ///
    /// The function parses the real document. It does not build a struct in
    /// the code. So these tests also cover the path of the deserialization
    /// that the binary uses. That covers every field name, every
    /// `#[serde(default)]`, and the check that refuses to start on a bad
    /// value.
    ///
    /// The function calls [`Config::parse_toml`], not `Config::try_from`.
    /// That is the one deliberate exception. `try_from` overlays the
    /// process environment variables `RUST_API_*`, and `cargo test` inherits
    /// the shell of the developer. The run instructions in the README export
    /// `RUST_API_CLIENT_SECRET`. So `capability_keys_prefer_the_configured_
    /// secret` and `every_s3_field_reaches_the_store_config` both failed for
    /// anyone who followed those instructions. The check of the configured
    /// secret then read the secret of the environment instead of the secret
    /// of the test data. The check of the projection then read `env-ak`
    /// instead of the `key` of the test data. This was checked. With
    /// `RUST_API_S3_ACCESS_KEY_ID=env-ak`, both tests fail with the old test
    /// data and pass with the new test data.
    ///
    /// The loader itself still has a test. That test is
    /// `config::tests::the_loader_reads_a_file_and_applies_the_overlay`. It
    /// checks only the fields that have no environment variable, so it
    /// applies whatever the shell holds.
    fn config_from(toml: &str) -> Config {
        Config::parse_toml(toml).expect("config parses")
    }

    const BASE: &str = r#"
public_address = "https://example.test"
listen_port = 8080
[authorization]
client_id = "cid"
client_secret = "csecret"
issuer_url = "https://idp.test"
[database]
prefix = "oxkv"
[s3]
bucket = "my-bucket"
region = "eu-west-1"
endpoint_url = "http://localhost:9000"
access_key_id = "key"
secret_access_key = "secret"
force_path_style = true
"#;

    /// Every store is `{db_prefix}/{domain}` in one bucket.
    ///
    /// The test pins this because a slash in the wrong place makes a
    /// *different* prefix instead of an error. The server would then open a
    /// new policy store or file store that is empty. It would appear to have
    /// lost all data.
    #[test]
    fn every_store_prefix_starts_with_the_configured_root() {
        assert_eq!(domain_prefix("oxkv", "policy"), "oxkv/policy");
        assert_eq!(domain_prefix("oxkv", "fs"), "oxkv/fs");
        assert_eq!(domain_prefix("oxkv", "wal"), "oxkv/wal");
    }

    /// The submittable set holds `entity.create` and not `webhook.deliver`.
    #[test]
    fn the_submittable_kind_set_holds_entity_create_only() -> anyhow::Result<()> {
        let submittable = submittable_kinds()?;
        let create = rust_api_model::CommandKind::parse("entity.create")?;
        let webhook = rust_api_model::CommandKind::parse("webhook.deliver")?;
        assert!(submittable.contains(&create));
        assert!(!submittable.contains(&webhook));
        Ok(())
    }

    /// A failed EAV loop takes the instance out of the rotation.
    ///
    /// The test reads a shared flag, so it covers the same path that the
    /// readiness closure uses. The EAV flag is always part of the check.
    #[test]
    fn a_failed_eav_loop_makes_the_instance_not_ready() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let latch = Arc::new(AtomicBool::new(false));
        let read = |latch: &Arc<AtomicBool>| latch.load(Ordering::Relaxed);

        let inputs =
            |policy_unlocked, lease_lost, primary_loss, dependencies_healthy| ReadinessInputs {
                policy_unlocked,
                lease_lost,
                primary_loss,
                dependencies_healthy,
                eav_failed: read(&latch),
            };
        assert!(readiness_state(inputs(true, false, false, true)));
        latch.store(true, Ordering::Relaxed);
        assert!(!readiness_state(inputs(true, false, false, true)));

        // A healthy EAV runtime does not change the other reasons.
        latch.store(false, Ordering::Relaxed);
        assert!(!readiness_state(inputs(false, false, false, true)));
        assert!(!readiness_state(inputs(true, true, false, true)));
        assert!(!readiness_state(inputs(true, false, true, true)));
        assert!(!readiness_state(inputs(true, false, false, false)));
    }

    /// The `[s3]` section of the config file becomes the type that the engine
    /// uses.
    ///
    /// This is the only point of the translation. So a field that is added on
    /// one side and left out on the other shows up here. It shows up as a
    /// default value instead of as an error at compile time. The fields
    /// `endpoint_url` and `force_path_style` matter most in practice. A MinIO
    /// deployment that loses them points at the AWS service.
    #[test]
    fn every_s3_field_reaches_the_store_config() {
        let projected = s3_client_config(&config_from(BASE));
        assert_eq!(projected.bucket, "my-bucket");
        assert_eq!(projected.region, "eu-west-1");
        assert_eq!(
            projected.endpoint_url.as_deref(),
            Some("http://localhost:9000")
        );
        assert!(projected.force_path_style);
        assert_eq!(projected.access_key_id.as_deref(), Some("key"));
        assert_eq!(projected.secret_access_key.as_deref(), Some("secret"));
    }

    /// A secret from the config is the secret that the keys sign with. A secret
    /// that is absent falls back to a key that lives for one run of the
    /// process. The server does not refuse to start.
    ///
    /// The fallback is a real behaviour, not a mistake. A laptop with no
    /// `[capability].secret` must run. The cost is that the tokens stop
    /// working after a restart.
    ///
    /// The test used to check `resolve_token_keys(...).is_ok()` in both cases.
    /// That call cannot fail in the way that the name of the test claims.
    /// `TokenKeys` has no accessor for its `kid` or for its `secret`. So there
    /// was nothing to compare. The failure is not rare. Replace the whole
    /// body of `resolve_token_keys` with this:
    ///
    ///     Ok(TokenKeys::ephemeral())
    ///
    /// That change drops the configured secret. It also drops the rotation
    /// value `previous_secret`. Both `is_ok()` checks still pass. Every
    /// deployment then signs its capability tokens with a new random key on
    /// each start. So every delegated file URL that the server gave out before
    /// a restart stops verifying after the restart. Nothing reports the
    /// failure, because the tokens carry no error until a client tries to
    /// use one.
    ///
    /// So the test checks a behaviour instead. It makes a token with the keys
    /// that `resolve_token_keys` returned. It checks that token against keys
    /// that it builds itself from the configured secret. A token that only
    /// the configured secret verifies is the observable form of "the
    /// configured secret was used".
    ///
    /// The test does not check one case. A secret with the wrong form is not
    /// tested here. `Config::parse` checks it. So this function never sees a
    /// bad secret. The loader enforces the rule. The test
    /// `config::tests::validate_rejects_bad_values` covers it. A check here
    /// would pin a path that cannot run. The failure that the check would
    /// guard against is already prevented at the loader. That failure is a
    /// bad secret that the server accepts as an ephemeral key. It would turn
    /// an error in the config into tokens that stop verifying for no clear
    /// reason.
    #[test]
    fn capability_keys_prefer_the_configured_secret() {
        use rust_api::fs::TokenKeys as Keys;
        use rust_api::policy::Action;

        let configured = "ab".repeat(32);
        let rotated_away = "cd".repeat(32);
        let with_secrets = |secret: &str, previous: Option<&str>| {
            let mut toml = format!("{BASE}\n[capability]\nsecret = \"{secret}\"\n");
            if let Some(previous) = previous {
                toml.push_str(&format!("previous_secret = \"{previous}\"\n"));
            }
            config_from(&toml)
        };

        // A token that the resolved keys made is a token that the
        // configured secret verifies. A key that lives for one run of
        // the process would make a token that no configured secret
        // accepts.
        let keys = resolve_token_keys(&with_secrets(&configured, None))
            .expect("a configured secret resolves");
        let expected = Keys::from_hex(&configured, None).expect("the same secret, built directly");
        let minted = keys
            .mint("alice", "file-1", Action::Read)
            .expect("minting through the resolved keys");
        assert!(
            expected.verify(&minted, "file-1", Action::Read).is_ok(),
            "the resolved keys must sign with the CONFIGURED secret; an \
             ephemeral key here invalidates every capability token on restart"
        );

        // The token must use that exact secret, not any secret that has
        // the right form.
        let other = Keys::from_hex(&rotated_away, None).expect("a different valid secret");
        assert!(
            other.verify(&minted, "file-1", Action::Read).is_err(),
            "a token must not validate under an unrelated secret, or the \
             assertion above proves nothing"
        );

        // During a rotation, the PREVIOUS secret is wired for the check. So
        // a token that was made before the rotation still works. The
        // loss of `previous_secret` is the other half of the same quiet
        // failure.
        let rotating = resolve_token_keys(&with_secrets(&configured, Some(&rotated_away)))
            .expect("rotation resolves");
        let old_token = Keys::from_hex(&rotated_away, None)
            .expect("the retired secret")
            .mint("alice", "file-2", Action::Write)
            .expect("mint under the retired secret");
        assert!(
            rotating.verify(&old_token, "file-2", Action::Write).is_ok(),
            "previous_secret must verify during rotation, or every delegated \
             URL minted before the deploy stops working"
        );
        // The new secret still makes tokens.
        let new_token = rotating
            .mint("alice", "file-3", Action::Read)
            .expect("mint under the current secret");
        assert!(
            Keys::from_hex(&configured, None)
                .expect("the current secret")
                .verify(&new_token, "file-3", Action::Read)
                .is_ok(),
            "the current secret mints through a rotating key set too"
        );

        // The fallback for an absent secret still starts the server. The key
        // really lives for one run of the process. So a token from one
        // resolution does not survive the next. That is the documented
        // cost. The test checks it instead of assuming it.
        let ephemeral = resolve_token_keys(&config_from(BASE))
            .expect("an absent secret still boots, on an ephemeral key");
        let boot_one = ephemeral
            .mint("alice", "file-4", Action::Read)
            .expect("mint under an ephemeral key");
        let boot_two = resolve_token_keys(&config_from(BASE))
            .expect("second boot")
            .mint("alice", "file-4", Action::Read)
            .expect("mint under a second ephemeral key");
        assert!(
            ephemeral.verify(&boot_two, "file-4", Action::Read).is_err(),
            "an unconfigured deployment must get a FRESH key per boot, not a \
             stable one -- otherwise the fallback is silently a hardcoded secret"
        );
        assert!(
            ephemeral.verify(&boot_one, "file-4", Action::Read).is_ok(),
            "control: the token it did mint is still its own"
        );
    }

    /// `policy import` claims the lease. `policy export` reads through a
    /// reader.
    ///
    /// Building an `OxKvStore` does a CAS bump on `ownership.json` and takes
    /// an epoch. An import writes, so it still claims the writer lease before
    /// the first store build. An export reads through `build_s3_reader`. A
    /// reader takes no epoch, so it cannot fence the writer. So an export does
    /// not claim the lease.
    ///
    /// The test reads the source. It does not call the command. The *order*
    /// of the steps is what matters. For import, the claim must come before
    /// the first `build_s3_store`. A check after that point means that the
    /// process which held the lease was already fenced.
    #[test]
    fn import_claims_the_lease_and_export_uses_a_reader() {
        let src = std::fs::read_to_string("src/main.rs").expect("readable");

        // Take only the body of `run_policy_command`.
        let body = src
            .split_once("async fn run_policy_command")
            .expect("run_policy_command exists")
            .1
            .split_once("\nasync fn ")
            .expect("run_policy_command is terminated by the next fn")
            .0;

        // The last `PolicyAction::Import` is the match arm. The earlier one
        // selects the input path.
        let import_at = body
            .rfind("PolicyAction::Import")
            .expect("run_policy_command dispatches import");
        let import_arm = &body[import_at..];
        let claim = import_arm
            .find("claim_writer_lease(")
            .expect("import must claim the writer lease");
        // The store builds live in the helper that this arm calls. So
        // "before any store" means "before the call to the helper".
        let dispatch = import_arm
            .find("import_policy(")
            .expect("the import arm calls import_policy");
        assert!(
            claim < dispatch,
            "the lease is claimed at offset {claim} but `import_policy` runs \
             at {dispatch}: checking after opening a store means the live \
             writer is already fenced",
        );

        // The export arm starts at the last `PolicyAction::Export` and ends
        // at the import arm.
        let export_at = body
            .rfind("PolicyAction::Export")
            .expect("run_policy_command dispatches export");
        let export_arm = &body[export_at..import_at];
        assert!(
            !export_arm.contains("claim_writer_lease("),
            "export must not claim the writer lease: an OxKvReader takes no \
             epoch and cannot fence the writer",
        );

        // The export helper must open a reader, not a writer.
        let export_body = src
            .split_once("async fn export_policy")
            .expect("export_policy exists")
            .1
            .split_once("\nasync fn ")
            .expect("export_policy is terminated by the next fn")
            .0;
        assert!(
            export_body.contains("build_s3_reader("),
            "export_policy must read through build_s3_reader",
        );
        assert!(
            !export_body.contains("build_s3_store("),
            "export_policy must not open a writer store, because that fences \
             a live server",
        );

        // The import helper must still open a writer store.
        let import_body = src
            .split_once("async fn import_policy")
            .expect("import_policy exists")
            .1
            .split_once("\nasync fn ")
            .expect("import_policy is terminated by the next fn")
            .0;
        assert!(
            import_body.contains("build_s3_store("),
            "import_policy opens no writer store, so the lease guards nothing",
        );
        assert!(
            !import_body.contains("claim_writer_lease("),
            "import_policy claims the lease itself; the claim belongs once, \
             in run_policy_command, before any store is opened",
        );
    }

    /// A refusal must name the prefix. It must also say what to do about it.
    ///
    /// The whole cost of this change is the move from a quiet drain to a
    /// message that the operator sees. So a message that does not say
    /// *which* prefix is in dispute, and *what* to stop, leaves the operator
    /// where the operator started. The instance that holds the lease comes
    /// from `LeaseError::Held` under this context. So the two parts join into
    /// one message for the operator.
    #[test]
    fn a_refused_policy_command_says_which_prefix_and_what_to_stop() {
        let message = lease_refused_message("policy import", "prod/data");
        assert!(message.contains("policy import"), "{message}");
        assert!(message.contains("prod/data"), "{message}");
        assert!(
            message.contains("fences"),
            "must say what the command would do to the live writer: {message}",
        );

        // The message joins with the Held error of the lease. That error
        // carries the identity of the holder and the time to wait.
        let held = rust_api::lease::LeaseError::Held {
            prefix: "prod/data".to_string(),
            instance: "host-b:0192...".to_string(),
            pid: 4242,
            age: 3,
            ttl: 60,
            wait: 57,
        };
        let rendered = format!("{message}\n{held}");
        assert!(rendered.contains("host-b:0192..."), "{rendered}");
        assert!(rendered.contains("wait 57s"), "{rendered}");
    }

    /// Each subcommand names itself in the failure, so that "another writer" is
    /// not unclear between serving traffic and taking a backup.
    #[test]
    fn each_policy_subcommand_names_itself() {
        let export = PolicyAction::Export {
            config: PathBuf::from("c.toml"),
            out: PathBuf::from("b.json"),
        };
        let import = PolicyAction::Import {
            config: PathBuf::from("c.toml"),
            input: PathBuf::from("b.json"),
        };
        assert_eq!(policy_action_name(&export), "policy export");
        assert_eq!(policy_action_name(&import), "policy import");
    }

    /// The recovery command takes a config path and one target sequence.
    #[test]
    fn reset_cursor_parses_its_config_and_target() {
        let cli = Cli::try_parse_from([
            "rust-api",
            "eav",
            "reset-cursor",
            "--config",
            "prod.toml",
            "--to",
            "42",
        ])
        .expect("the command parses");

        match cli.command {
            Command::Eav {
                action: EavAction::ResetCursor { config, to },
            } => {
                assert_eq!(config, PathBuf::from("prod.toml"));
                assert_eq!(to, 42);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let short = Cli::try_parse_from([
            "rust-api",
            "eav",
            "reset-cursor",
            "-c",
            "prod.toml",
            "--to",
            "0",
        ])
        .expect("the short config flag parses");
        assert!(matches!(
            short.command,
            Command::Eav {
                action: EavAction::ResetCursor { to: 0, .. }
            }
        ));
    }

    /// The target sequence must be present.
    #[test]
    fn reset_cursor_requires_a_target_sequence() {
        assert!(
            Cli::try_parse_from(["rust-api", "eav", "reset-cursor", "--config", "prod.toml",])
                .is_err()
        );
    }

    /// A cursor above the feed head is a late runner failure. The command
    /// refuses it before the write.
    #[test]
    fn a_reset_target_above_the_head_is_refused() {
        assert!(check_reset_target(0, 0).is_ok());
        assert!(check_reset_target(7, 7).is_ok());

        let error = check_reset_target(8, 7).expect_err("a cursor above the head fails");

        let message = error.to_string();
        assert!(message.contains('8'), "{message}");
        assert!(message.contains('7'), "{message}");
        assert!(message.contains("at or below the head"), "{message}");
    }

    /// The recovery command does not touch a prefix that a live writer owns.
    #[tokio::test]
    async fn reset_cursor_lease_refuses_a_live_writer() -> anyhow::Result<()> {
        let store: std::sync::Arc<dyn object_store::ObjectStore> =
            std::sync::Arc::new(object_store::memory::InMemory::new());
        let (_lost, guard) =
            claim_writer_lease_on(store.clone(), "prod/data", 60, "eav reset-cursor").await?;

        let error = claim_writer_lease_on(store, "prod/data", 60, "eav reset-cursor")
            .await
            .expect_err("a second writer must fail");
        let rendered = format!("{error:#}");

        assert!(rendered.contains("eav reset-cursor"), "{rendered}");
        assert!(rendered.contains("prod/data"), "{rendered}");
        assert!(rendered.contains("already holds"), "{rendered}");
        guard
            .expect("the first claim holds the lease")
            .release()
            .await;
        Ok(())
    }

    /// The lease claim comes before the first store build. A check after that
    /// point means that the live writer is already fenced.
    #[test]
    fn reset_cursor_claims_the_lease_before_it_opens_a_store() {
        let src = std::fs::read_to_string("src/main.rs").expect("readable");

        let body = src
            .split_once("async fn reset_eav_cursor(")
            .expect("reset_eav_cursor exists")
            .1
            .split_once("\nasync fn ")
            .expect("reset_eav_cursor is terminated by the next fn")
            .0;
        let claim = body
            .find("claim_writer_lease(")
            .expect("reset_eav_cursor claims the writer lease");
        let open = body
            .find("reset_eav_cursor_with_store(")
            .expect("reset_eav_cursor calls its store helper");
        assert!(
            claim < open,
            "the lease is claimed at offset {claim} but the store helper runs \
             at {open}: checking after opening a store means the live writer \
             is already fenced",
        );

        let helper = src
            .split_once("async fn reset_eav_cursor_with_store(")
            .expect("reset_eav_cursor_with_store exists")
            .1
            .split_once("\nasync fn ")
            .expect("the helper is terminated by the next fn")
            .0;
        assert!(
            helper.contains("build_s3_store("),
            "the helper must open the rule store",
        );
        assert!(
            !helper.contains("claim_writer_lease("),
            "the claim belongs once, in reset_eav_cursor, before any store",
        );
    }

    /// The EAV commands name themselves and use the prefixes of the server.
    ///
    /// A wrong prefix opens an empty store.
    /// The command then reports no data instead of an error.
    #[test]
    fn each_eav_subcommand_names_itself_and_uses_the_server_prefixes() {
        let export = EavAction::Export {
            config: PathBuf::from("c.toml"),
            out: PathBuf::from("b.json"),
        };
        let import = EavAction::Import {
            config: PathBuf::from("c.toml"),
            input: PathBuf::from("b.json"),
        };
        let rebuild = EavAction::RebuildIndex {
            config: PathBuf::from("c.toml"),
            schema: Some("person".to_string()),
        };
        let validate = EavAction::Validate {
            config: PathBuf::from("c.toml"),
        };
        assert_eq!(eav_action_name(&export), "eav export");
        assert_eq!(eav_action_name(&import), "eav import");
        assert_eq!(eav_action_name(&rebuild), "eav rebuild-index");
        assert_eq!(eav_action_name(&validate), "eav validate");

        assert_eq!(eav_domain_prefix("oxkv", "schema"), "oxkv/eav/schema");
        assert_eq!(eav_domain_prefix("/oxkv/", "entity"), "oxkv/eav/entity");
        assert_eq!(eav_domain_prefix("", "rules"), "eav/rules");
    }

    /// Each EAV command claims the lease before it opens a store.
    ///
    /// Building an `OxKvStore` takes an epoch.
    /// A claim after that point already fenced the live writer.
    #[test]
    fn each_eav_command_claims_the_lease_before_a_store() {
        let src = std::fs::read_to_string("src/main.rs").expect("readable");
        let body = src
            .split_once("async fn run_eav_command")
            .expect("run_eav_command exists")
            .1
            .split_once("\nasync fn ")
            .expect("run_eav_command is terminated by the next fn")
            .0;
        let claim = body
            .find("claim_writer_lease(")
            .expect("the EAV command claims the writer lease");
        let dispatch = body
            .find("run_eav_action(")
            .expect("the EAV command dispatches an action");
        assert!(
            claim < dispatch,
            "the lease is claimed at offset {claim} but the action runs at \
             {dispatch}: a claim after a store build already fenced the writer",
        );
    }

    /// Each EAV command applies `[database].sst_cache_mb` before a store.
    ///
    /// The first OxKV handle fixes the process-wide cache size. A call after
    /// that point changes a stored number and nothing else.
    #[test]
    fn each_eav_command_configures_the_sst_cache_before_a_store() {
        let src = std::fs::read_to_string("src/main.rs").expect("readable");

        let run = src
            .split_once("async fn run_eav_command")
            .expect("run_eav_command exists")
            .1
            .split_once("\nasync fn ")
            .expect("run_eav_command is terminated by the next fn")
            .0;
        let configure = run
            .find("configure_sst_cache_bytes(")
            .expect("the EAV command configures the SST cache");
        let claim = run
            .find("claim_writer_lease(")
            .expect("the EAV command claims the writer lease");
        let dispatch = run
            .find("run_eav_action(")
            .expect("the EAV command dispatches an action");
        assert!(
            configure < claim,
            "the SST cache is configured at offset {configure} but the lease is claimed at \
             {claim}: the cache size must apply before the first store"
        );
        assert!(
            configure < dispatch,
            "the SST cache is configured at offset {configure} but the action runs at \
             {dispatch}: the cache size must apply before the first store"
        );

        let reset = src
            .split_once("async fn reset_eav_cursor")
            .expect("reset_eav_cursor exists")
            .1
            .split_once("\nasync fn ")
            .expect("reset_eav_cursor is terminated by the next fn")
            .0;
        let configure = reset
            .find("configure_sst_cache_bytes(")
            .expect("reset_eav_cursor configures the SST cache");
        let claim = reset
            .find("claim_writer_lease(")
            .expect("reset_eav_cursor claims the writer lease");
        let work = reset
            .find("reset_eav_cursor_with_store(")
            .expect("reset_eav_cursor resets through the store helper");
        assert!(
            configure < claim,
            "the SST cache is configured at offset {configure} but the lease is claimed at \
             {claim}: the cache size must apply before the first store"
        );
        assert!(
            configure < work,
            "the SST cache is configured at offset {configure} but the store is built at \
             {work}: the cache size must apply before the first store"
        );
    }
}
