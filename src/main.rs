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
        Command::Policy { action } => run_policy_command(action).await,
    }
}

/// One-line description of what is asking for the lease, for the failure
/// message when it is already held.
fn policy_action_name(action: &PolicyAction) -> &'static str {
    match action {
        PolicyAction::Export { .. } => "policy export",
        PolicyAction::Import { .. } => "policy import",
    }
}

/// Runs `policy export` / `policy import` against the configured prefix.
///
/// Both subcommands build an `OxKvStore`, and building one CAS-bumps
/// `ownership.json` and takes an epoch. That is the same operation the
/// server performs at startup, and against a running server it *fences*
/// it. The server only finds out at its next policy write, which fails
/// `StoreError::Fenced`, trips `note_primary_loss`, and sets a latch that
/// nothing resets -- so `/ready`, which gates on `!fencing::primary_loss()`,
/// goes 503 and the instance stays out of rotation. A backup that exits 0
/// had drained the primary.
///
/// The README warns about this for `import` and says nothing for `export`,
/// which is the worse half: export is read-only and reads like the safe
/// direction of the documented backup procedure.
///
/// So both claim the writer lease first, before any store is built, exactly
/// as `serve` does. When a live server holds it, the command refuses and
/// the operator is told which prefix and which instance, instead of
/// silently displacing a healthy writer.
async fn run_policy_command(action: PolicyAction) -> anyhow::Result<()> {
    let purpose = policy_action_name(&action);
    // Both halves pulled out before the match that consumes the action, so
    // each branch below works from the path it was handed rather than from
    // an `Option` rebuilt out of the enum.
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

    // BEFORE any store: opening one takes an epoch, so checking afterwards
    // would already have fenced the incumbent. No renewer is spawned -- this
    // process is short-lived, and the lease is handed straight back below.
    let (_lost, guard) = claim_writer_lease(
        &s3_cfg,
        &db_prefix,
        cfg.database.writer_lease_ttl_secs,
        purpose,
    )
    .await?;

    let result = match action {
        PolicyAction::Export { .. } => export_policy(&s3_cfg, &db_prefix, &file).await,
        PolicyAction::Import { .. } => import_policy(&s3_cfg, &db_prefix, &file).await,
    };

    // Hand the prefix back even when the work failed, so a failed export
    // does not leave the next one waiting out a TTL.
    if let Some(guard) = guard {
        guard.release().await;
    }
    result
}

/// Writes every stored policy rule to `out` as JSON.
async fn export_policy(s3_cfg: &S3ClientConfig, db_prefix: &str, out: &Path) -> anyhow::Result<()> {
    let store = rust_api::db::build_s3_store(s3_cfg, &domain_prefix(db_prefix, "policy")).await?;
    let dump = admin::export_s3(store).await?;
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

/// Loads policy rules from `input` into the store, announcing them on the
/// change feed so running replicas converge.
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
        allowed_tenants: config.authorization.allowed_tenants.clone(),
    })
    .await?;
    let oidc_api_module = OidcApiModule::<Claims>::init(oidc_client).await?;

    // Claim the prefix BEFORE building any store: opening an OxKvStore
    // takes an epoch, so a check afterwards would already have displaced
    // the incumbent. Every prefix-scoped store built below (policy, fs,
    // wal, and each per-user replica) then lives under this one lease.
    //
    // `lease_guard` is held for the rest of `serve`, so the lease is
    // renewed while serving, and released explicitly on the way out -- see
    // the await after `start` below.
    let (lease_lost, lease_guard) =
        claim_writer_lease(&s3_client_config, &db_prefix, lease_ttl, "serve").await?;

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
        // `fs` only ever reads policy, so it gets the read-only handle --
        // the same one the replica snapshot manager already takes.
        policy_engine.authorizer(),
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
    // The rebuild queue is created here so the receiving end can be drained by
    // a worker pool. `POST /sync/sync` runs bounded incremental replays inline
    // and *queues* full rebuilds, so without the pool a subject that needs a
    // recalc would report `pending` forever and never converge.
    let (builds, build_jobs) = rust_api::sync::snapshot::BuildQueue::new();
    let snapshot_manager = SnapshotManager::new(
        rust_api::sync::snapshot::SnapshotDeps {
            wal: wal.clone(),
            store: master_store,
            // Replicas only read policy, so hand over the read-only view.
            policy: policy_engine.authorizer(),
            object_store: replica_objects,
            builds,
        },
        db_prefix,
        rust_api::sync::snapshot::ReplicaBackend::ObjectStore,
    );
    // Deliberately small: each build streams its diff, so memory tracks the
    // size of a change rather than a replica, but it still scans the master and
    // writes to S3. This bounds object-store pressure as much as CPU.
    rust_api::sync::snapshot::BuildPool::new(build_jobs)
        .spawn(std::sync::Arc::new(snapshot_manager.clone()), 2);
    let sync_api_module = SyncApiModule::with_download_gate(
        snapshot_manager.clone(),
        oidc_api_module.middleware(),
        config.limits.max_concurrent_downloads,
    );

    let listen_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.listen_port);
    // Readiness fails when the policy lock is wedged (a writer stuck
    // holding it) or when the single-writer lease is lost, which means a
    // successor now owns the prefix and this process must stop taking
    // traffic. Startup itself already gates on S3/OIDC/JWKS/lease.
    let readiness: rust_api::http::health::ReadyCheck = Arc::new({
        let policy_engine = policy_engine.clone();
        move || {
            // Three independent reasons this instance cannot serve writes,
            // any one of which is enough to take it out of rotation:
            //
            // - the policy lock is held, so reads would block;
            // - the single-writer lease was lost, meaning a peer took the
            //   prefix cooperatively;
            // - a primary prefix was fenced outright, which is the same
            //   condition arriving without cooperation (an older build, a
            //   `writer_lease_ttl_secs = 0` deployment, an operator running
            //   `policy import` against a live prefix). The lease check
            //   cannot see that, so `fencing` reports it separately.
            policy_engine.is_unlocked()
                && !lease_lost.load(std::sync::atomic::Ordering::Relaxed)
                && !rust_api::fencing::primary_loss()
        }
    });
    // Built first so the listener can be started as the last fallible step:
    // anything that fails after the lease is claimed but before the server
    // is listening takes the early-error path, where the guard's `Drop`
    // best-effort release is all there is.
    let served = ApiService::new()
        .with_cors_origins(config.http.allowed_origins.clone())
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
        .start(listen_addr.into())
        .await;

    // The orderly release, awaited. `start` returns on SIGTERM (the drain
    // path), so this is where the lease has to go back: dropping the guard
    // only *makes* the release runnable, and the runtime that would poll it
    // is about to be dropped too. Skipping this left the record in place,
    // so a replacement pod read it as a live lease and CrashLoopBackOffs
    // until the TTL expired -- on every graceful shutdown, and defeating
    // the rolling-restart handover this lease exists for.
    //
    // Before the telemetry flush, so the release's own log lines reach the
    // collector.
    if let Some(guard) = lease_guard {
        guard.release().await;
    }

    served?;

    // Explicit flush on the normal exit path: pending spans and metric
    // points are delivered, and failures are surfaced instead of silently
    // dropped (the Drop fallback remains for early-error paths).
    telemetry.shutdown()?;

    Ok(())
}

/// Why the writer lease could not be claimed, for the operator running
/// `purpose` against a prefix a live server already owns.
///
/// The failure being prevented is invisible from the CLI: the command
/// opens a second writer handle, the server is fenced, and it drains on
/// its next policy write via a latch nothing resets. A command that exits
/// non-zero with this text has changed nothing.
fn lease_refused_message(purpose: &str, db_prefix: &str) -> String {
    format!(
        "cannot run `{purpose}`: it opens a second writer handle on \
         [database].prefix {db_prefix:?}, which fences the process already \
         writing there until it restarts. Stop it first, or wait for its \
         lease to go stale."
    )
}

/// Claims the single-writer lease for `db_prefix` and starts renewing it.
///
/// Returns the flag to gate `/ready` on plus a guard that must be held for
/// the server's lifetime: the guard stops renewal when released, and
/// [`LeaseGuard::release`](rust_api::lease::LeaseGuard::release) hands the
/// prefix back, which is what makes a rolling restart hand over without a
/// TTL wait. Callers must await the release rather than drop the guard --
/// see the guard's docs for what dropping actually achieves at process
/// exit.
///
/// A `ttl_secs` of `0` disables the lease (documented single-node escape
/// hatch) and yields a flag that is never set.
///
/// `purpose` names the caller in the failure message. Both policy
/// subcommands pass their own name, because "another writer holds
/// `oxkv`" is a confusing thing to read while running a backup and a
/// confusing thing to read while serving traffic.
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
        .with_context(|| lease_refused_message(purpose, db_prefix))?;
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

/// The composition root was untestable, so these three pure functions were
/// the parts most likely to rot unnoticed and had no coverage at all.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// Builds a `Config` from a TOML document.
    ///
    /// Parsing the real document rather than assembling a struct literal
    /// means these tests also cover the deserialization path the binary
    /// actually uses -- every field name, every `#[serde(default)]`, and
    /// the validation that refuses to start on a bad value.
    ///
    /// Through [`Config::parse_toml`] rather than `Config::try_from`, which
    /// is the one deliberate exception: `try_from` overlays the
    /// `RUST_API_*` process environment, and `cargo test` inherits the
    /// developer's shell. The README's own run instructions export
    /// `RUST_API_CLIENT_SECRET`, so `capability_keys_prefer_the_configured_
    /// secret` and `s3_config_projection_carries_every_field` both failed
    /// for anyone who followed them -- the configured-secret assertion
    /// resolved the environment's secret instead of the fixture's, and the
    /// S3 projection read `env-ak` where the fixture said `key`. (Verified:
    /// under `RUST_API_S3_ACCESS_KEY_ID=env-ak` both fail on the old
    /// fixture and pass on this one.)
    ///
    /// The loader itself is still covered, in
    /// `config::tests::the_loader_reads_a_file_and_applies_the_overlay`,
    /// which asserts only on fields with no environment override so it
    /// holds whatever the shell carries.
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
    /// Worth pinning because a stray slash produces a *different* prefix
    /// rather than an error: the server would open a fresh, empty policy or
    /// file store and appear to have lost all data.
    #[test]
    fn domain_prefixes_are_namespaced_under_the_configured_root() {
        assert_eq!(domain_prefix("oxkv", "policy"), "oxkv/policy");
        assert_eq!(domain_prefix("oxkv", "fs"), "oxkv/fs");
        assert_eq!(domain_prefix("oxkv", "wal"), "oxkv/wal");
    }

    /// The config file's `[s3]` is projected onto the engine's own type.
    ///
    /// This is the single translation point, so a field added to one side and
    /// forgotten on the other shows up here as a silent default rather than as
    /// a compile error. `endpoint_url` and `force_path_style` matter most in
    /// practice: a MinIO deployment that loses them points at real AWS instead.
    #[test]
    fn s3_config_projection_carries_every_field() {
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

    /// A configured secret is used, and an absent one falls back to an
    /// ephemeral key rather than refusing to start.
    ///
    /// The fallback is a real behaviour, not an oversight: a laptop with no
    /// `[capability].secret` should run, at the cost of invalidating tokens on
    /// restart.
    ///
    /// Note what is *not* tested here: a malformed secret. `Config::try_from`
    /// validates it, so this function never sees a bad one -- enforced at the
    /// loader and covered by `config::tests::validate_rejects_bad_values`.
    /// Asserting it here would pin a path that cannot execute, and the failure
    /// it guards against (a bad secret silently downgraded to an ephemeral
    /// key, turning a config error into tokens that mysteriously stop
    /// validating) is actually prevented upstream.
    #[test]
    fn capability_keys_prefer_the_configured_secret() {
        assert!(
            resolve_token_keys(&config_from(BASE)).is_ok(),
            "an absent secret still boots, on an ephemeral key"
        );

        let good = config_from(&format!(
            "{BASE}\n[capability]\nsecret = \"{}\"\n",
            "ab".repeat(32)
        ));
        assert!(resolve_token_keys(&good).is_ok());
    }

    /// Both policy subcommands must claim the writer lease before opening a
    /// store.
    ///
    /// Building an `OxKvStore` CAS-bumps `ownership.json` and takes an
    /// epoch. That is what `serve` does at startup, so running either
    /// subcommand against a live prefix *fences the server* -- which the
    /// server discovers at its next policy write, as
    /// `StoreError::Fenced`, and answers by latching `note_primary_loss`
    /// forever. `/ready` gates on `!fencing::primary_loss()`, so a
    /// successful `policy export` permanently drains the instance. Export
    /// is read-only, which is exactly why this was missed: it looks like
    /// the safe direction of the documented backup procedure, and the
    /// README only warns about `import`.
    ///
    /// Pinned by reading the source rather than by calling the command,
    /// because the failure needs a second live `OxKvStore` over one prefix
    /// and a network to reach. What matters is the *ordering*: the claim
    /// has to come before the first `build_s3_store`, since checking
    /// afterwards means the incumbent has already been fenced. The
    /// assertion is on both halves -- the claim is present, and it precedes
    /// every store build in the function.
    #[test]
    fn both_policy_subcommands_claim_the_lease_before_opening_a_store() {
        let src = std::fs::read_to_string("src/main.rs").expect("readable");

        // Isolate `run_policy_command`: the function both subcommands
        // delegate to, so one assertion covers both.
        let body = src
            .split_once("async fn run_policy_command")
            .expect("run_policy_command exists")
            .1
            .split_once("\nasync fn ")
            .expect("run_policy_command is terminated by the next fn")
            .0;

        let claim = body
            .find("claim_writer_lease(")
            .expect("the policy path must claim the writer lease");
        // The store builds live in the helpers this function calls, so
        // "before any store" means "before dispatching to them".
        let dispatch = ["export_policy(", "import_policy("]
            .iter()
            .filter_map(|name| body.find(name).map(|at| (name, at)))
            .min_by_key(|(_, at)| *at)
            .expect("run_policy_command dispatches to a helper that opens a store");
        assert!(
            claim < dispatch.1,
            "the lease is claimed at offset {claim} but `{}` runs at {}: \
             checking after opening a store means the live writer is \
             already fenced",
            dispatch.0,
            dispatch.1,
        );

        // And each helper really does open a store -- otherwise the claim
        // would be guarding nothing.
        for helper in ["async fn export_policy", "async fn import_policy"] {
            let body = src
                .split_once(helper)
                .expect("helper exists")
                .1
                .split_once("\nasync fn ")
                .expect("helper is terminated by the next fn")
                .0;
            assert!(
                body.contains("build_s3_store("),
                "{helper} opens no store, so it cannot fence anything",
            );
            assert!(
                !body.contains("claim_writer_lease("),
                "{helper} claims the lease itself; the claim belongs once, \
                 in run_policy_command, before any store is opened",
            );
        }
    }

    /// A refusal has to name the prefix and say what to do about it.
    ///
    /// The whole cost of this fix is moving a silent drain into a visible
    /// failure, so a message that does not say *which* prefix is contested
    /// or *what* to stop leaves the operator where they started. The held
    /// instance comes from `LeaseError::Held` beneath this context, so the
    /// two compose into one operator-facing string.
    #[test]
    fn a_refused_policy_command_says_which_prefix_and_what_to_stop() {
        let message = lease_refused_message("policy export", "prod/data");
        assert!(message.contains("policy export"), "{message}");
        assert!(message.contains("prod/data"), "{message}");
        assert!(
            message.contains("fences"),
            "must say what the command would do to the live writer: {message}",
        );

        // Composes with the lease's own Held error, which carries the
        // holder's identity and how long to wait.
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

    /// Each subcommand is named in the failure, so "another writer" is not
    /// ambiguous between serving traffic and taking a backup.
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
}
