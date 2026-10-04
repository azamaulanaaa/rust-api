//! TOML configuration model for the server binary.
//!
//! Secrets may also arrive via the environment (secret managers inject
//! them there): a present, non-empty variable wins over the file value.
//! See [`ENV_CLIENT_SECRET`], [`ENV_S3_ACCESS_KEY_ID`],
//! [`ENV_S3_SECRET_ACCESS_KEY`].

use std::{fs, path::Path};

use anyhow::Context;
use serde::Deserialize;

/// Top-level server configuration loaded from the path given via `--config`.
#[derive(Deserialize, Debug)]
pub struct Config {
    /// Public base URL of this deployment (used to build the OIDC redirect).
    pub public_address: String,
    /// TCP port the HTTP listener binds to.
    pub listen_port: u16,
    /// Identity-provider connection settings.
    pub authorization: ConfigAuthorization,
    /// Embedded policy-database settings.
    pub database: DatabaseConfig,
    /// S3-compatible object storage settings for file uploads.
    pub s3: S3Config,
    /// Capability-token signing keys; ephemeral when omitted.
    #[serde(default)]
    pub capability: CapabilityConfig,
    /// Telemetry settings; defaults apply when the section is omitted.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// HTTP edge settings (CORS); defaults apply when omitted.
    #[serde(default)]
    pub http: HttpConfig,
    /// Cost limits; all off by default (see [`LimitsConfig`]).
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Environment override for the OIDC client secret.
///
/// Present and non-empty wins over `authorization.client_secret`.
pub const ENV_CLIENT_SECRET: &str = "RUST_API_CLIENT_SECRET";

/// Environment override for the S3 access key id.
///
/// Present and non-empty wins over `s3.access_key_id`.
pub const ENV_S3_ACCESS_KEY_ID: &str = "RUST_API_S3_ACCESS_KEY_ID";

/// Environment override for the S3 secret access key.
///
/// Present and non-empty wins over `s3.secret_access_key`.
pub const ENV_S3_SECRET_ACCESS_KEY: &str = "RUST_API_S3_SECRET_ACCESS_KEY";

/// Environment override for the capability-token signing secret.
///
/// Present and non-empty wins over `capability.secret`.
pub const ENV_CAPABILITY_SECRET: &str = "RUST_API_CAPABILITY_SECRET";

/// Environment override for the previous capability-token secret.
///
/// Present and non-empty wins over `capability.previous_secret`.
pub const ENV_CAPABILITY_SECRET_PREV: &str = "RUST_API_CAPABILITY_SECRET_PREV";

/// Environment override for the browser origins allowed by CORS.
///
/// Comma-separated origins (e.g. `https://app.example.com,http://localhost:5173`);
/// present and non-empty wins over `http.allowed_origins`.
pub const ENV_ALLOWED_ORIGINS: &str = "RUST_API_ALLOWED_ORIGINS";

impl TryFrom<&Path> for Config {
    type Error = anyhow::Error;

    /// Reads and parses a TOML config file from `value`, then overlays the
    /// environment onto it.
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        if !value.is_file() {
            return Err(anyhow::anyhow!(
                "Given path '{:?}' is not a file",
                value.to_str()
            ));
        }

        let content = fs::read_to_string(value).context("Failed to read config file")?;
        let mut config = Self::parse_toml(&content)?;
        apply_env_overrides(&mut config);
        // Re-validate: an environment value reaches the config from outside
        // the file, and nothing about a `RUST_API_*` variable was checked by
        // the TOML parser.
        config.validate().context("Invalid config values")?;

        Ok(config)
    }
}

impl Config {
    /// Parses and validates a TOML document with NO environment overlay.
    ///
    /// The split from the loader is deliberate, and it is what makes file
    /// parsing a pure function of its input. [`TryFrom`] reads
    /// `RUST_API_CLIENT_SECRET`, `RUST_API_S3_ACCESS_KEY_ID`,
    /// `RUST_API_CAPABILITY_SECRET` and the rest out of the process
    /// environment, so a caller that wants only the file's values has to be
    /// able to ask for them without first unsetting six variables -- which
    /// it cannot do safely, because the environment is process-wide and
    /// shared with every other thread.
    ///
    /// For tests that distinction is the whole point: `cargo test` inherits
    /// the developer's shell, and the README's own run instructions export
    /// `RUST_API_CLIENT_SECRET`. A fixture asserting on the file's value
    /// then fails for anyone who followed them, which is a test bug wearing
    /// a production costume.
    pub fn parse_toml(content: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(content).context("Failed to parse config file")?;
        config.validate().context("Invalid config values")?;
        Ok(config)
    }
}

/// Overlays secret values from the environment onto a parsed config.
///
/// Split from file parsing so precedence is unit-testable without
/// mutating the process environment (see `prefer_env` tests). The lookup
/// itself is injected for the same reason: `std::env::set_var` is
/// process-wide, so a test that sets one races every other test thread
/// reading the same variable -- and is `unsafe` in Rust 2024 besides.
fn apply_env_overrides(config: &mut Config) {
    apply_overrides_from(config, |name| std::env::var(name).ok());
}

/// [`apply_env_overrides`] with the variable lookup supplied by the caller.
///
/// `var` returns the raw value for `name`, or `None` when unset -- the same
/// shape `std::env::var(..).ok()` produces.
fn apply_overrides_from(config: &mut Config, var: impl Fn(&str) -> Option<String>) {
    config.authorization.client_secret = prefer_env(
        var(ENV_CLIENT_SECRET),
        std::mem::take(&mut config.authorization.client_secret),
    );
    config.s3.access_key_id =
        prefer_env_opt(var(ENV_S3_ACCESS_KEY_ID), config.s3.access_key_id.take());
    config.s3.secret_access_key = prefer_env_opt(
        var(ENV_S3_SECRET_ACCESS_KEY),
        config.s3.secret_access_key.take(),
    );
    config.capability.secret =
        prefer_env_opt(var(ENV_CAPABILITY_SECRET), config.capability.secret.take());
    config.capability.previous_secret = prefer_env_opt(
        var(ENV_CAPABILITY_SECRET_PREV),
        config.capability.previous_secret.take(),
    );
    if let Some(raw) = var(ENV_ALLOWED_ORIGINS)
        && !raw.trim().is_empty()
    {
        config.http.allowed_origins = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
}

/// Effective required value: the env value wins when present and
/// non-empty, otherwise the file value stands.
fn prefer_env(env: Option<String>, file: String) -> String {
    match env {
        Some(v) if !v.is_empty() => v,
        _ => file,
    }
}

/// Effective optional value: same precedence as [`prefer_env`].
fn prefer_env_opt(env: Option<String>, file: Option<String>) -> Option<String> {
    match env {
        Some(v) if !v.is_empty() => Some(v),
        _ => file,
    }
}

impl Config {
    /// Rejects values that would fail obscurely deep in startup (bad
    /// URLs, empty bucket/credentials, out-of-range sampling, or a
    /// prefix that escapes its bucket scope).
    fn validate(&self) -> anyhow::Result<()> {
        for (name, url) in [
            ("public_address", &self.public_address),
            ("authorization.issuer_url", &self.authorization.issuer_url),
        ] {
            let parsed: url::Url = url
                .parse()
                .map_err(|e| anyhow::anyhow!("{name} is not a valid URL ({url:?}): {e}"))?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                anyhow::bail!("{name} must use http(s), got {:?}", parsed.scheme());
            }
        }
        if self.authorization.client_id.trim().is_empty() {
            anyhow::bail!("authorization.client_id must not be empty");
        }
        if self.authorization.client_secret.trim().is_empty() {
            anyhow::bail!(
                "authorization.client_secret must not be empty (or set RUST_API_CLIENT_SECRET)"
            );
        }
        if self.authorization.issuer_url.contains("{tenantid}") {
            if self
                .authorization
                .allowed_tenants
                .iter()
                .any(|t| t.trim().is_empty())
            {
                anyhow::bail!("authorization.allowed_tenants must not contain empty entries");
            }
            if self.authorization.allowed_tenants.is_empty() {
                anyhow::bail!(
                    "authorization.issuer_url is a multi-tenant template, so \
                     authorization.allowed_tenants must list every tenant this deployment \
                     trusts; without it the expected issuer is derived from the token's own tid \
                     claim and any consenting tenant would be accepted"
                );
            }
        }
        if self.database.prefix.trim().is_empty() {
            anyhow::bail!("database.prefix must not be empty");
        }
        if self
            .database
            .prefix
            .split('/')
            .any(|seg| seg == ".." || seg == ".")
        {
            anyhow::bail!(
                "database.prefix must not contain '.' or '..' segments (got {:?})",
                self.database.prefix
            );
        }
        if self.database.writer_lease_ttl_secs > i64::MAX as u64 {
            anyhow::bail!(
                "database.writer_lease_ttl_secs is {}, which is above i64::MAX. \
                 The lease compares a record's age against its TTL, and a TTL \
                 that large would read as already stale, so every second writer \
                 would take the prefix over from a live holder and the \
                 single-writer guarantee would be silently off.",
                self.database.writer_lease_ttl_secs
            );
        }
        if self.s3.bucket.trim().is_empty() {
            anyhow::bail!("s3.bucket must not be empty");
        }
        if self.s3.region.trim().is_empty() {
            anyhow::bail!("s3.region must not be empty");
        }
        if let Some(secret) = &self.capability.secret {
            rust_api::fs::token::parse_secret_hex(secret).map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        if let Some(secret) = &self.capability.previous_secret {
            rust_api::fs::token::parse_secret_hex(secret).map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        if !(0.0..=1.0).contains(&self.observability.sample_ratio) {
            anyhow::bail!(
                "observability.sample_ratio must be within 0.0..=1.0 (got {})",
                self.observability.sample_ratio
            );
        }
        for origin in &self.http.allowed_origins {
            let parsed: url::Url = origin.parse().map_err(|e| {
                anyhow::anyhow!("http.allowed_origins entry {origin:?} is not a valid URL: {e}")
            })?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                anyhow::bail!(
                    "http.allowed_origins entry {origin:?} must use http(s), got {:?}",
                    parsed.scheme()
                );
            }
        }
        Ok(())
    }
}

/// Identity-provider connection settings for the OIDC client.
#[derive(Deserialize, Debug)]
pub struct ConfigAuthorization {
    /// OAuth2 client identifier registered at the provider.
    pub client_id: String,
    /// OAuth2 client secret registered at the provider.
    pub client_secret: String,
    /// Base URL of the provider's OIDC discovery document.
    pub issuer_url: String,
    /// Tenant identifiers this deployment accepts, required when
    /// `issuer_url` is a multi-tenant template such as
    /// `https://login.microsoftonline.com/{tenantid}/v2.0`.
    ///
    /// A templated issuer cannot be pinned statically: the expected issuer has
    /// to be derived from each token's own `tid` claim, which proves nothing
    /// about *which* tenant minted it. A multi-tenant app registration also
    /// publishes one JWKS covering every consenting tenant, so an unknown
    /// tenant's token verifies against keys this server already trusts, and
    /// `aud` is the shared client ID rather than a tenant discriminator. This
    /// list is therefore the only tenant gate, and validation below refuses to
    /// start a templated issuer without it.
    ///
    /// Ignored for a single-tenant issuer, where the issuer is pinned
    /// statically.
    #[serde(default)]
    pub allowed_tenants: Vec<String>,
}

/// Telemetry/observability settings.
#[derive(Debug, Deserialize, Clone)]
pub struct ObservabilityConfig {
    /// Service name attached to every exported telemetry resource.
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// OTLP collector endpoint. Span export is disabled when absent.
    ///
    /// The transport follows the compiled cargo feature, not this string:
    /// the default `otlp-http` expects an HTTP/protobuf endpoint
    /// (`http://localhost:4318/v1/traces`), `otlp-grpc` expects a gRPC
    /// collector address (`http://localhost:4317`). See
    /// [`telemetry::init`](crate::telemetry::init).
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// Fraction of traces sampled, between 0.0 and 1.0 (default 1.0 = all).
    /// Root spans decide via trace-ID ratio; child spans follow their
    /// parent's decision.
    #[serde(default = "default_sample_ratio")]
    pub sample_ratio: f64,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: default_service_name(),
            otlp_endpoint: None,
            sample_ratio: default_sample_ratio(),
        }
    }
}

fn default_sample_ratio() -> f64 {
    1.0
}

fn default_service_name() -> String {
    "rust-api".to_string()
}

/// Embedded policy-database settings.
#[derive(Deserialize, Debug)]
pub struct DatabaseConfig {
    /// Object prefix inside the S3 bucket for OxKV keys (e.g. `"oxkv"`).
    /// Defaults to `"oxkv"`.
    #[serde(default = "default_db_prefix")]
    pub prefix: String,
    /// Mirror the master fs store in RAM for replica rebuilds.
    ///
    /// Prototype: when true, the snapshot manager keeps a lazily-warmed
    /// [`oxkv::CachedOxKvStore`] mirror over the master fs prefix, so
    /// full rebuilds serve bulk scans from memory after the first pass.
    /// Costs one master key set in RAM; safe only while serve() holds
    /// the single writer for the prefix. Defaults to false.
    #[serde(default)]
    pub mirror_master: bool,
    /// Seconds a single-writer lease stays valid without a renewal.
    ///
    /// The server claims a lease on `[database].prefix` at startup and
    /// refuses to start if another process holds a live one, because two
    /// writers on one prefix silently diverge (see
    /// [`rust_api::lease`]). It must exceed the worst-case pause between
    /// renewals -- a long GC pause or a slow S3 round trip -- or a healthy
    /// process will be displaced by its own peer.
    ///
    /// Set to `0` to disable the lease entirely. Only safe when exactly one
    /// process can ever reach the bucket, e.g. a laptop; a disabled lease
    /// puts split brain back on the operator.
    ///
    /// Must fit in the signed range the lease compares in: a TTL above
    /// `i64::MAX` reads as already stale, which silently disables
    /// single-writer enforcement. Rejected at validation.
    #[serde(default = "default_writer_lease_ttl_secs")]
    pub writer_lease_ttl_secs: u64,
}

fn default_db_prefix() -> String {
    "oxkv".to_string()
}

fn default_writer_lease_ttl_secs() -> u64 {
    rust_api::lease::DEFAULT_LEASE_TTL_SECS
}

/// HTTP edge settings for browser clients.
///
/// CORS is deny-by-default: empty `allowed_origins` serves API responses
/// without `Access-Control-Allow-Origin` (same-origin only). List each
/// browser origin explicitly when the SPA is served cross-origin; origins
/// must be `http(s)` URLs without trailing slash. Credentials are always
/// allowed so the `auth_token` cookie and `Authorization` bearer header
/// work across origins.
#[derive(Deserialize, Debug, Default, Clone)]
pub struct HttpConfig {
    /// Browser origins allowed by CORS (e.g. `["https://app.example.com"]`).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// Cost limits for requests whose work a single request does not bound.
///
/// Both default to off (`0`) rather than to a guessed number. A default
/// limit is a default outage: too low and a legitimate burst gets 429s, too
/// high and it is not a limit. The values a deployment wants depend on its
/// egress budget and its client poll interval, neither of which this crate
/// can know.
#[derive(Deserialize, Debug, Default, Clone)]
pub struct LimitsConfig {
    /// Requests per minute per peer address, after an initial burst of the
    /// same size. `0` disables the bucket.
    #[serde(default)]
    pub rate_per_minute: u32,

    /// Peak burst allowed before the refill rate applies. `0` means "same as
    /// `rate_per_minute`", so a plain rate limit needs one number.
    #[serde(default)]
    pub rate_burst: u32,

    /// Concurrent `/sync/db/{object}` downloads. `0` disables the gate.
    ///
    /// This is the one that bounds real cost: a replica prefix holds oxkv
    /// files, so one of these requests can be a multi-hundred-megabyte SST
    /// read. A rate limit does not bound that, since an allowed rate can still
    /// be in flight all at once.
    #[serde(default)]
    pub max_concurrent_downloads: usize,
}

impl LimitsConfig {
    /// Burst to use when none is configured.
    pub fn burst_or_rate(&self) -> u32 {
        if self.rate_burst == 0 {
            self.rate_per_minute
        } else {
            self.rate_burst
        }
    }
}

/// Capability-token (file delegation JWT) signing keys.
///
/// 64-char hex (32 bytes); generate with
/// `python3 -c "import secrets; print(secrets.token_hex(32))"`.
/// Omitted entirely means an ephemeral OS-RNG key per boot (tokens
/// die with the process — fine for dev, logged as a warning).
/// Rotate by moving the current secret to `previous_secret` and
/// deploying the new one as `secret`: tokens minted under either key
/// verify until the old generation expires (5-minute TTL).
#[derive(Deserialize, Debug, Default)]
pub struct CapabilityConfig {
    /// Current signing secret: mints tokens.
    #[serde(default)]
    pub secret: Option<String>,
    /// Previous signing secret: verifies only, during rotation.
    #[serde(default)]
    pub previous_secret: Option<String>,
}

/// Object-store settings (AmazonS3 via object_store; InMemory for tests).
///
/// Backed by `object_store::aws::AmazonS3` for S3-compatible providers
/// (AWS, MinIO, R2) and `object_store::memory::InMemory` in tests.
#[derive(Deserialize, Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name.
    pub bucket: String,
    /// AWS region (e.g. `us-east-1`).
    pub region: String,
    /// Custom endpoint URL for S3-compatible providers (MinIO, R2). Omit for AWS.
    #[serde(default)]
    pub endpoint_url: Option<String>,
    /// Whether to use path-style addressing (required for MinIO).
    #[serde(default)]
    pub force_path_style: bool,
    /// Access key ID (falls back to env/instance profile when absent).
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// Secret access key.
    #[serde(default)]
    pub secret_access_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Parses and validates a TOML document, with no environment overlay.
    ///
    /// Every file-parsing test in this module goes through here rather than
    /// through [`Config::try_from`], because `try_from` reads
    /// `RUST_API_CLIENT_SECRET`, `RUST_API_S3_ACCESS_KEY_ID`,
    /// `RUST_API_CAPABILITY_SECRET`, `RUST_API_CAPABILITY_SECRET_PREV`,
    /// `RUST_API_S3_SECRET_ACCESS_KEY` and `RUST_API_ALLOWED_ORIGINS` out of
    /// the process environment.
    ///
    /// That is not a theoretical hazard. `cargo test` inherits the
    /// developer's shell and the README's own run instructions export
    /// `RUST_API_CLIENT_SECRET`, so a fixture asserting on the file's value
    /// fails for anyone who followed them: with the variable set,
    /// `validate_rejects_bad_values`' empty-`client_secret` case is
    /// revalidated against the environment value, validation PASSES, and
    /// `validation_error`'s `unwrap_err()` panics. The same applies to the
    /// `[capability] secret = "deadbeef"` case under
    /// `RUST_API_CAPABILITY_SECRET`, and to
    /// `parses_full_config_with_overrides`' `access_key_id == "ak"` under
    /// `RUST_API_S3_ACCESS_KEY_ID`.
    ///
    /// The alternative -- mutating the environment from a test -- is worse:
    /// `set_var` is process-wide, so it races every other test thread under
    /// cargo's default parallelism and is `unsafe` in Rust 2024. Hence a
    /// pure entry point instead, which is the same split
    /// `apply_env_overrides` already claimed to exist "so precedence is
    /// unit-testable without mutating the process environment". The
    /// file-parsing tests had simply never been given the same treatment.
    fn parse(toml: &str) -> anyhow::Result<Config> {
        Config::parse_toml(toml)
    }

    fn tmp_toml(content: &str) -> std::path::PathBuf {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let path = std::env::temp_dir().join(format!(
            "rust-api-config-{}-{}.toml",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
        ));
        let mut f = std::fs::File::create(&path).expect("create temp toml");
        f.write_all(content.as_bytes()).expect("write toml");
        path
    }

    #[test]
    fn try_from_rejects_not_a_file() {
        let dir = std::env::temp_dir();
        let err = Config::try_from(dir.as_path()).unwrap_err().to_string();
        assert!(err.contains("is not a file"));
        let ghost = std::path::Path::new("/tmp/rust-api-ghost-config-xyz-999.toml");
        let err = Config::try_from(ghost).unwrap_err().to_string();
        assert!(err.contains("is not a file"));
    }

    #[test]
    fn try_from_fails_on_invalid_toml() {
        // Kept on the loader rather than `parse_toml`: the message is
        // asserted, and the loader is what an operator hits.
        let path = tmp_toml("not = toml [[[ ");
        let err = Config::try_from(path.as_path()).unwrap_err().to_string();
        assert!(err.contains("Failed to parse config file"));
        let _ = std::fs::remove_file(&path);

        // The same document through the pure entry point, which the file
        // tests below use: identical message, so the two really do share
        // the parse.
        let err = parse("not = toml [[[ ").unwrap_err().to_string();
        assert!(err.contains("Failed to parse config file"));
    }

    #[test]
    fn parses_minimal_config() {
        let toml = r#"
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
            region = "us-east-1"
        "#;
        let cfg = parse(toml).expect("should parse");
        assert_eq!(cfg.public_address, "https://example.test");
        assert_eq!(cfg.listen_port, 8080);
        assert_eq!(cfg.authorization.client_id, "cid");
        assert_eq!(cfg.s3.bucket, "my-bucket");
        assert_eq!(cfg.s3.region, "us-east-1");
        assert!(cfg.s3.endpoint_url.is_none());
        assert!(!cfg.s3.force_path_style);
        assert!(cfg.s3.access_key_id.is_none());
        // new prefix defaults to "oxkv" when omitted
        assert_eq!(cfg.database.prefix, "oxkv");
        // observability defaults when omitted
        assert_eq!(cfg.observability.service_name, "rust-api");
        assert!(cfg.observability.otlp_endpoint.is_none());
        assert_eq!(cfg.observability.sample_ratio, 1.0);
    }

    #[test]
    fn parses_full_config_with_overrides() {
        let toml = r#"
            public_address = "https://example.test"
            listen_port = 3000
            [authorization]
            client_id = "cid2"
            client_secret = "s2"
            issuer_url = "https://idp.test"
            [database]
            prefix = "oxkv"
            [s3]
            bucket = "b2"
            region = "eu-west-1"
            endpoint_url = "http://localhost:9000"
            force_path_style = true
            access_key_id = "ak"
            secret_access_key = "sk"
            [observability]
            service_name = "my-service"
            otlp_endpoint = "http://localhost:4317"
            sample_ratio = 0.5
        "#;
        let cfg = parse(toml).unwrap();
        assert_eq!(
            cfg.s3.endpoint_url.as_deref(),
            Some("http://localhost:9000")
        );
        assert!(cfg.s3.force_path_style);
        assert_eq!(cfg.s3.access_key_id.as_deref(), Some("ak"));
        assert_eq!(cfg.database.prefix, "oxkv");
        assert_eq!(cfg.observability.service_name, "my-service");
        assert_eq!(cfg.observability.sample_ratio, 0.5);
        assert_eq!(
            cfg.observability.otlp_endpoint.as_deref(),
            Some("http://localhost:4317")
        );
    }

    #[test]
    fn parses_database_prefix_override() {
        let toml = r#"
            public_address = "https://example.test"
            listen_port = 8080
            [authorization]
            client_id = "cid"
            client_secret = "s"
            issuer_url = "https://idp.test"
            [database]
            prefix = "custom/prefix"
            [s3]
            bucket = "b"
            region = "us-east-1"
        "#;
        let cfg = parse(toml).unwrap();
        assert_eq!(cfg.database.prefix, "custom/prefix");
    }

    fn minimal_toml() -> String {
        r#"
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
            region = "us-east-1"
        "#
        .to_string()
    }

    /// A templated issuer cannot be pinned statically, so the expected issuer
    /// has to come from each token's own `tid`. Without an allowlist that is
    /// no gate at all: any tenant that consented to a multi-tenant app
    /// registration mints a token that verifies against the shared JWKS and
    /// carries our client ID as `aud`. Refuse to start instead.
    #[test]
    fn a_templated_issuer_requires_an_allowed_tenant() {
        let templated = minimal_toml().replace(
            "issuer_url = \"https://idp.test\"",
            "issuer_url = \"https://login.test/{tenantid}/v2.0\"",
        );
        let err = validation_error(&templated);
        assert!(
            err.contains("allowed_tenants"),
            "a templated issuer without an allowlist must be rejected, got: {err}"
        );

        // With an allowlist the same config starts. The key belongs to the
        // [authorization] table, so it goes next to client_secret rather
        // than at the end of the file.
        let allowed = templated.replace(
            "client_secret = \"csecret\"",
            "client_secret = \"csecret\"\n            allowed_tenants = [\"tenant-a\"]",
        );
        let cfg = parse(&allowed).expect("an allowlisted tenant should validate");
        assert_eq!(cfg.authorization.allowed_tenants, vec!["tenant-a"]);
    }

    /// An entry that is present but blank would resolve an issuer to the
    /// placeholder's surroundings with nothing substituted, so reject it
    /// rather than silently accept a degenerate tenant id.
    #[test]
    fn a_templated_issuer_rejects_a_blank_allowed_tenant() {
        let templated = minimal_toml().replace(
            "issuer_url = \"https://idp.test\"",
            "issuer_url = \"https://login.test/{tenantid}/v2.0\"\n            allowed_tenants = [\"tenant-a\", \"\"]",
        );
        let err = validation_error(&templated);
        assert!(
            err.contains("empty entries"),
            "a blank allowlist entry must be rejected, got: {err}"
        );
    }

    /// The allowlist only means something for a templated issuer, and a
    /// single-tenant issuer must still start without one.
    #[test]
    fn a_single_tenant_issuer_needs_no_allowlist() {
        parse(&minimal_toml()).expect("single-tenant issuer needs no allowlist");
    }

    fn validation_error(toml: &str) -> String {
        let err = parse(toml).unwrap_err();
        // Debug renders the anyhow context chain, Display only the outer.
        format!("{err:?}")
    }

    #[test]
    fn validate_rejects_bad_values() {
        // sample_ratio out of range (telemetry used to clamp silently).
        let err = validation_error(&minimal_toml().replace(
            "region = \"us-east-1\"",
            "region = \"us-east-1\"\n[observability]\nsample_ratio = 1.5",
        ));
        assert!(err.contains("sample_ratio"), "unexpected: {err}");

        // Prefix escaping its bucket scope.
        let err = validation_error(
            &minimal_toml().replace("prefix = \"oxkv\"", "prefix = \"../escape\""),
        );
        assert!(err.contains("database.prefix"), "unexpected: {err}");

        // Empty bucket / region.
        let err =
            validation_error(&minimal_toml().replace("bucket = \"my-bucket\"", "bucket = \"\""));
        assert!(err.contains("s3.bucket"), "unexpected: {err}");
        let err =
            validation_error(&minimal_toml().replace("region = \"us-east-1\"", "region = \"\""));
        assert!(err.contains("s3.region"), "unexpected: {err}");

        // Non-URL addresses.
        let err =
            validation_error(&minimal_toml().replace("https://example.test", "not a url !!!"));
        assert!(err.contains("public_address"), "unexpected: {err}");
        let err = validation_error(&minimal_toml().replace("https://idp.test", "ftp://idp.test"));
        assert!(
            err.contains("authorization.issuer_url"),
            "unexpected: {err}"
        );

        // Empty credentials.
        let err = validation_error(
            &minimal_toml().replace("client_secret = \"csecret\"", "client_secret = \"\""),
        );
        assert!(err.contains("client_secret"), "unexpected: {err}");

        // Truncated/non-hex capability secrets (weak HMAC material).
        let err = validation_error(&minimal_toml().replace(
            "region = \"us-east-1\"",
            "region = \"us-east-1\"\n[capability]\nsecret = \"deadbeef\"",
        ));
        assert!(err.contains("64 hex chars"), "unexpected: {err}");
        let err = validation_error(&minimal_toml().replace(
            "region = \"us-east-1\"",
            &format!(
                "region = \"us-east-1\"\n[capability]\nsecret = \"{}\"\nprevious_secret = \"zz\"",
                "ab".repeat(32)
            ),
        ));
        assert!(err.contains("64 hex chars"), "unexpected: {err}");
        // A well-formed secret passes validation.
        let ok = minimal_toml().replace(
            "region = \"us-east-1\"",
            &format!(
                "region = \"us-east-1\"\n[capability]\nsecret = \"{}\"",
                "ab".repeat(32)
            ),
        );
        assert!(parse(&ok).is_ok());
    }

    /// A TTL too large for the comparison the lease performs must be
    /// refused at startup, not discovered later.
    ///
    /// `[database].writer_lease_ttl_secs` is an unvalidated `u64` and the
    /// lease compared `age < ttl_secs as i64`. A TTL at or above 2^63 casts
    /// to a negative `i64`, so `age < negative` is false for *every* live
    /// holder: every second writer is told the lease is stale and takes the
    /// prefix over from a running server, and the only symptom is a
    /// `warn!` nobody reads. The single-writer guard is silently off, which
    /// is the one thing this crate exists to prevent.
    #[test]
    fn a_lease_ttl_too_large_for_the_comparison_is_refused() {
        // One past the signed range: the exact value that casts negative.
        let too_large = minimal_toml().replace(
            "prefix = \"oxkv\"",
            "prefix = \"oxkv\"\nwriter_lease_ttl_secs = 9223372036854775808",
        );
        let err = validation_error(&too_large);
        assert!(
            err.contains("writer_lease_ttl_secs"),
            "an out-of-range lease TTL must be rejected, got: {err}"
        );
        assert!(
            err.contains("single-writer"),
            "the message must say what it costs, not just what failed: {err}",
        );

        // The largest accepted value still starts: the bound is at the
        // comparison's limit, not an arbitrary round number below it.
        let at_limit = minimal_toml().replace(
            "prefix = \"oxkv\"",
            "prefix = \"oxkv\"\nwriter_lease_ttl_secs = 9223372036854775807",
        );
        let cfg = parse(&at_limit).expect("i64::MAX is a valid TTL");
        assert_eq!(cfg.database.writer_lease_ttl_secs, i64::MAX as u64);
    }

    #[test]
    fn http_allowed_origins_default_empty_and_validate() {
        // Omitted [http] section means same-origin only.
        let cfg = parse(&minimal_toml()).expect("should parse");
        assert!(cfg.http.allowed_origins.is_empty());

        // Explicit origins parse.
        let toml = minimal_toml().replace(
            "region = \"us-east-1\"",
            "region = \"us-east-1\"\n[http]\nallowed_origins = [\"https://app.example.com\", \"http://localhost:5173\"]",
        );
        let cfg = parse(&toml).expect("should parse");
        assert_eq!(
            cfg.http.allowed_origins,
            vec![
                "https://app.example.com".to_string(),
                "http://localhost:5173".to_string()
            ]
        );

        // Non-http(s) origins fail at startup, not obscurely in the browser.
        let err = validation_error(&minimal_toml().replace(
            "region = \"us-east-1\"",
            "region = \"us-east-1\"\n[http]\nallowed_origins = [\"ftp://app.example.com\"]",
        ));
        assert!(err.contains("http.allowed_origins"), "unexpected: {err}");
        let err = validation_error(&minimal_toml().replace(
            "region = \"us-east-1\"",
            "region = \"us-east-1\"\n[http]\nallowed_origins = [\"not a url\"]",
        ));
        assert!(err.contains("http.allowed_origins"), "unexpected: {err}");
    }

    /// The same TOML parses to the same config twice.
    ///
    /// Trivial for a pure parser, which is exactly why it is worth pinning:
    /// it is the property that stopped being true the moment file parsing
    /// grew an environment overlay. `Config::try_from` reads six
    /// `RUST_API_*` variables, so under `RUST_API_CLIENT_SECRET=...` two
    /// parses of the same document could legitimately disagree -- and did,
    /// for every test asserting on a file value. Nothing about "the config
    /// file says X" survives an overlay whose input the test does not
    /// control.
    ///
    /// `Config` is not `PartialEq`, so the fields the overlay touches are
    /// compared directly.
    #[test]
    fn parsing_the_same_toml_twice_gives_the_same_result() {
        let toml = minimal_toml().replace(
            "region = \"us-east-1\"",
            &format!(
                "region = \"us-east-1\"\naccess_key_id = \"ak\"\n[capability]\nsecret = \"{}\"",
                "ab".repeat(32)
            ),
        );
        let first = parse(&toml).expect("parses");
        let second = parse(&toml).expect("parses");

        assert_eq!(
            first.authorization.client_secret,
            second.authorization.client_secret
        );
        assert_eq!(first.s3.access_key_id, second.s3.access_key_id);
        assert_eq!(first.s3.secret_access_key, second.s3.secret_access_key);
        assert_eq!(first.capability.secret, second.capability.secret);
        assert_eq!(
            first.capability.previous_secret,
            second.capability.previous_secret
        );
        assert_eq!(first.http.allowed_origins, second.http.allowed_origins);
        // And the values are the FILE's, which is the half the overlay used
        // to change out from under the assertions.
        assert_eq!(first.s3.access_key_id.as_deref(), Some("ak"));
        assert_eq!(first.authorization.client_secret, "csecret");
    }

    /// A plain parse is not an overlay in disguise: the environment cannot
    /// reach it.
    ///
    /// Proven without touching the process environment, which is the whole
    /// point -- `set_var` is process-wide and would race every other test
    /// thread. The overlay is driven through the same injected-lookup entry
    /// point `apply_env_overrides` uses, with every variable populated, and
    /// `parse_toml` is shown to be unaffected by construction because it
    /// never calls it. Asserting on the RESULT rather than on the absence
    /// of a call: the overlay is applied to a config parsed the same way,
    /// and every field it claims to own comes back different.
    #[test]
    fn env_overrides_do_not_leak_into_a_plain_parse() {
        let toml = minimal_toml().replace(
            "region = \"us-east-1\"",
            "region = \"us-east-1\"\naccess_key_id = \"ak\"\nsecret_access_key = \"sk\"\n\
             [http]\nallowed_origins = [\"https://file.example.com\"]",
        );
        let secret = "ab".repeat(32);

        // With every variable populated, the overlay changes all six fields.
        let mut overlaid = parse(&toml).expect("parses");
        apply_overrides_from(&mut overlaid, |name| match name {
            ENV_CLIENT_SECRET => Some("from-env".into()),
            ENV_S3_ACCESS_KEY_ID => Some("env-ak".into()),
            ENV_S3_SECRET_ACCESS_KEY => Some("env-sk".into()),
            ENV_CAPABILITY_SECRET => Some(secret.clone()),
            ENV_CAPABILITY_SECRET_PREV => Some(secret.clone()),
            ENV_ALLOWED_ORIGINS => Some("https://env.example.com, https://env2.example.com".into()),
            other => panic!("unexpected override for {other}"),
        });
        assert_eq!(overlaid.authorization.client_secret, "from-env");
        assert_eq!(overlaid.s3.access_key_id.as_deref(), Some("env-ak"));
        assert_eq!(overlaid.s3.secret_access_key.as_deref(), Some("env-sk"));
        assert_eq!(overlaid.capability.secret.as_deref(), Some(secret.as_str()));
        assert_eq!(
            overlaid.capability.previous_secret.as_deref(),
            Some(secret.as_str())
        );
        assert_eq!(
            overlaid.http.allowed_origins,
            vec!["https://env.example.com", "https://env2.example.com"]
        );

        // A plain parse of the SAME document is untouched by any of it.
        let plain = parse(&toml).expect("parses");
        assert_eq!(plain.authorization.client_secret, "csecret");
        assert_eq!(plain.s3.access_key_id.as_deref(), Some("ak"));
        assert_eq!(plain.s3.secret_access_key.as_deref(), Some("sk"));
        assert!(plain.capability.secret.is_none());
        assert!(plain.capability.previous_secret.is_none());
        assert_eq!(plain.http.allowed_origins, vec!["https://file.example.com"]);
    }

    /// The overlay is what production reads, and the loader is the only
    /// caller that goes through the real process environment.
    ///
    /// The one test here that still uses `Config::try_from`, deliberately:
    /// the file-parsing tests above must not, and something has to keep
    /// covering the loader itself. What it asserts is chosen to be
    /// environment-INDEPENDENT -- `public_address`, `listen_port` and
    /// `s3.bucket` have no `RUST_API_*` override -- so it holds whatever the
    /// developer's shell happens to carry.
    #[test]
    fn the_loader_reads_a_file_and_applies_the_overlay() {
        let path = tmp_toml(&minimal_toml());
        let cfg = Config::try_from(path.as_path()).expect("the loader accepts a valid file");
        let _ = std::fs::remove_file(&path);

        assert_eq!(cfg.public_address, "https://example.test");
        assert_eq!(cfg.listen_port, 8080);
        assert_eq!(cfg.s3.bucket, "my-bucket");
    }

    #[test]
    fn env_precedence_prefers_non_empty() {
        assert_eq!(prefer_env(Some("e".into()), "f".into()), "e");
        assert_eq!(prefer_env(None, "f".into()), "f");
        assert_eq!(prefer_env(Some("".into()), "f".into()), "f");
        assert_eq!(
            prefer_env_opt(Some("e".into()), Some("f".into())),
            Some("e".into())
        );
        assert_eq!(prefer_env_opt(None, Some("f".into())), Some("f".into()));
        assert_eq!(
            prefer_env_opt(Some("".into()), Some("f".into())),
            Some("f".into())
        );
        assert_eq!(prefer_env_opt(None, None), None);
    }

    #[test]
    fn observability_defaults() {
        let d = ObservabilityConfig::default();
        assert_eq!(d.service_name, "rust-api");
        assert!(d.otlp_endpoint.is_none());
        assert_eq!(d.sample_ratio, 1.0);
        assert_eq!(default_service_name(), "rust-api");
        assert_eq!(default_sample_ratio(), 1.0);
    }

    /// The lease TTL is the knob that decides how long a crashed writer
    /// blocks its replacement, so the default has to be a real value rather
    /// than zero -- zero silently disables single-writer enforcement.
    #[test]
    fn writer_lease_ttl_defaults_on_and_can_be_disabled() {
        let cfg = parse(&minimal_toml()).expect("should parse");
        assert_eq!(cfg.database.writer_lease_ttl_secs, 60);
        assert_eq!(
            cfg.database.writer_lease_ttl_secs,
            default_writer_lease_ttl_secs()
        );

        // Must land in the [database] table, not after `region` (which
        // sits in [s3] -- serde ignores unknown keys there, so the test
        // would silently assert the default).
        let toml = minimal_toml().replace(
            "prefix = \"oxkv\"",
            "prefix = \"oxkv\"\nwriter_lease_ttl_secs = 0",
        );
        let cfg = parse(&toml).expect("should parse");
        assert_eq!(
            cfg.database.writer_lease_ttl_secs, 0,
            "0 disables the lease"
        );
    }
}
