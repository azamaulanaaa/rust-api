//! TOML configuration model for the server binary.
//!
//! Secrets may also arrive through environment variables, because secret
//! managers inject them there. A variable that is present and not empty wins
//! over the value in the file. See [`ENV_CLIENT_SECRET`],
//! [`ENV_S3_ACCESS_KEY_ID`], and [`ENV_S3_SECRET_ACCESS_KEY`].

use std::{fs, path::Path};

use anyhow::Context;
use serde::Deserialize;

/// Top-level server configuration. The server loads it from the path that
/// `--config` gives.
#[derive(Deserialize, Debug)]
pub struct Config {
    /// Public base URL of this deployment. The server uses it to build the
    /// OIDC redirect.
    pub public_address: String,
    /// TCP port that the HTTP listener binds to.
    pub listen_port: u16,
    /// Identity provider connection settings.
    pub authorization: ConfigAuthorization,
    /// Settings of the embedded policy database.
    pub database: DatabaseConfig,
    /// S3-compatible object storage settings for file uploads.
    pub s3: S3Config,
    /// Capability-token signing keys. They are ephemeral when the section is
    /// omitted.
    #[serde(default)]
    pub capability: CapabilityConfig,
    /// Telemetry settings. The defaults apply when the section is omitted.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// HTTP edge settings, for CORS. The defaults apply when the section is
    /// omitted.
    #[serde(default)]
    pub http: HttpConfig,
    /// Cost limits. Each limit is off by default. See [`LimitsConfig`].
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Environment variable that overrides the OIDC client secret.
///
/// A value that is present and not empty wins over
/// `authorization.client_secret`.
pub const ENV_CLIENT_SECRET: &str = "RUST_API_CLIENT_SECRET";

/// Environment variable that overrides the S3 access key ID.
///
/// A value that is present and not empty wins over `s3.access_key_id`.
pub const ENV_S3_ACCESS_KEY_ID: &str = "RUST_API_S3_ACCESS_KEY_ID";

/// Environment variable that overrides the S3 secret access key.
///
/// A value that is present and not empty wins over `s3.secret_access_key`.
pub const ENV_S3_SECRET_ACCESS_KEY: &str = "RUST_API_S3_SECRET_ACCESS_KEY";

/// Environment variable that overrides the capability-token signing secret.
///
/// A value that is present and not empty wins over `capability.secret`.
pub const ENV_CAPABILITY_SECRET: &str = "RUST_API_CAPABILITY_SECRET";

/// Environment variable that overrides the previous capability-token secret.
///
/// A value that is present and not empty wins over
/// `capability.previous_secret`.
pub const ENV_CAPABILITY_SECRET_PREV: &str = "RUST_API_CAPABILITY_SECRET_PREV";

/// Environment variable that overrides the browser origins allowed by CORS.
///
/// The value is a comma-separated list of origins, for example
/// `https://app.example.com,http://localhost:5173`. A value that is present
/// and not empty wins over `http.allowed_origins`.
pub const ENV_ALLOWED_ORIGINS: &str = "RUST_API_ALLOWED_ORIGINS";

impl TryFrom<&Path> for Config {
    type Error = anyhow::Error;

    /// Reads and parses the TOML config file at `value`. The function then
    /// overlays the environment onto the result.
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        Self::try_from_with(value, |name| std::env::var(name).ok())
    }
}

impl Config {
    /// Parses and validates a TOML document. The function applies no
    /// environment overlay.
    ///
    /// The split from the loader is deliberate. The split makes file parsing
    /// a pure function of its input. [`TryFrom`] reads `RUST_API_CLIENT_SECRET`,
    /// `RUST_API_S3_ACCESS_KEY_ID`, `RUST_API_CAPABILITY_SECRET`, and other
    /// variables out of the process environment. A caller that wants only the
    /// values in the file must therefore be able to ask for them without
    /// unsetting six variables first. The caller cannot do that safely,
    /// because the environment is process-wide and is shared with every
    /// other thread.
    ///
    /// For tests, this distinction is the whole point. `cargo test` inherits
    /// the developer's shell, and the run instructions in the README export
    /// `RUST_API_CLIENT_SECRET`. A fixture that asserts on the value in the
    /// file then fails for anyone who followed them. Such a failure is a test
    /// bug in production clothes.
    pub fn parse_toml(content: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(content).context("Failed to parse config file")?;
        config.validate().context("Invalid config values")?;
        Ok(config)
    }

    /// Runs the whole loader: read the file, parse it, overlay the
    /// environment, then validate again. The caller supplies the variable
    /// lookup instead of the function reading the process.
    ///
    /// [`TryFrom`] runs this logic with the real environment, and it is the
    /// only production caller. This function exists so that the loader can be
    /// tested from start to end without `std::env::set_var`. That call is
    /// process-wide, `unsafe` in Rust 2024, and races with every other test
    /// thread that reads the same variable.
    ///
    /// The injection matters for more than the assertions. Validation runs
    /// again and reads the overlaid values. So a hostile `RUST_API_*` value in
    /// the developer's shell makes a loader test fail inside `validate()`
    /// before any assertion runs. See `the_loader_reads_a_file_and_applies_the_overlay`.
    pub fn try_from_with(
        value: &Path,
        var: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        if !value.is_file() {
            return Err(anyhow::anyhow!(
                "Given path '{:?}' is not a file",
                value.to_str()
            ));
        }

        let content = fs::read_to_string(value).context("Failed to read config file")?;
        let mut config = Self::parse_toml(&content)?;
        apply_overrides_from(&mut config, var);
        // Validate again, because an environment value reaches the config
        // from outside the file. The TOML parser checked no `RUST_API_*`
        // variable.
        config.validate().context("Invalid config values")?;

        Ok(config)
    }
}

/// Overlays secret values from the environment onto a parsed config. The
/// caller supplies the variable lookup.
///
/// The function is separate from file parsing so that a test can check
/// precedence without changing the process environment. See the `prefer_env`
/// tests. The lookup is injected for the same reason. A call to
/// `std::env::set_var` is process-wide, so a test that sets a variable races
/// with every other test thread that reads the same variable. The call is
/// also `unsafe` in Rust 2024.
///
/// Production code reads the real environment through
/// `std::env::var(..).ok()`. [`Config::try_from_with`] supplies that lookup,
/// and it is the only call site of this function.
///
/// `var` returns the raw value for `name`. It returns `None` when the
/// variable is unset, which is the same shape `std::env::var(..).ok()`
/// produces.
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

/// Effective required value. The environment value wins when it is present
/// and not empty. Otherwise the value in the file applies.
fn prefer_env(env: Option<String>, file: String) -> String {
    match env {
        Some(v) if !v.is_empty() => v,
        _ => file,
    }
}

/// Effective optional value. It uses the same precedence as [`prefer_env`].
fn prefer_env_opt(env: Option<String>, file: Option<String>) -> Option<String> {
    match env {
        Some(v) if !v.is_empty() => Some(v),
        _ => file,
    }
}

impl Config {
    /// Rejects values that would otherwise fail later inside startup. Examples
    /// are bad URLs, an empty bucket, empty credentials, a sample ratio out
    /// of range, and a prefix that leaves its bucket scope.
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

/// Identity provider connection settings for the OIDC client.
#[derive(Deserialize, Debug)]
pub struct ConfigAuthorization {
    /// OAuth2 client identifier that is registered at the provider.
    pub client_id: String,
    /// OAuth2 client secret that is registered at the provider.
    pub client_secret: String,
    /// Base URL of the OIDC discovery document at the provider.
    pub issuer_url: String,
    /// Tenant identifiers that this deployment accepts. The field is
    /// required when `issuer_url` is a template for more than one tenant,
    /// such as `https://login.microsoftonline.com/{tenantid}/v2.0`.
    ///
    /// A templated issuer cannot be pinned statically. The expected issuer
    /// must come from the `tid` claim of each token. That claim says nothing
    /// about *which* tenant made the token. An app registration for more than
    /// one tenant also publishes one JWKS for every tenant that agreed. So a
    /// token from an unknown tenant verifies with keys that this server
    /// already trusts. The `aud` value is then the shared client ID, not a
    /// tenant. This list is therefore the only tenant check, and validation
    /// below refuses to start a templated issuer without it.
    ///
    /// The field is ignored for a single-tenant issuer, because the issuer
    /// is pinned statically.
    #[serde(default)]
    pub allowed_tenants: Vec<String>,
}

/// Telemetry and observability settings.
#[derive(Debug, Deserialize, Clone)]
pub struct ObservabilityConfig {
    /// Service name that is attached to every exported telemetry resource.
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// OTLP collector endpoint. Span export is off when the field is absent.
    ///
    /// The transport follows the compiled cargo feature, not this string.
    /// The default `otlp-http` feature needs an HTTP and protobuf endpoint,
    /// such as `http://localhost:4318/v1/traces`. The `otlp-grpc` feature
    /// needs the address of a gRPC collector, such as `http://localhost:4317`.
    /// See [`telemetry::init`](crate::telemetry::init).
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// Fraction of traces to sample, between 0.0 and 1.0. The default 1.0
    /// samples all traces. A root span decides through the ratio of the trace
    /// ID. A child span follows the decision of its parent.
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

/// Settings of the embedded policy database.
#[derive(Deserialize, Debug)]
pub struct DatabaseConfig {
    /// Object prefix inside the S3 bucket for OxKV keys, for example
    /// `"oxkv"`. The default is `"oxkv"`.
    #[serde(default = "default_db_prefix")]
    pub prefix: String,
    /// Mirrors the master fs store in RAM for replica rebuilds.
    ///
    /// This setting is a prototype. When the field is true, the snapshot
    /// manager keeps a [`oxkv::CachedOxKvStore`] mirror over the master fs
    /// prefix. The mirror warms up on first use. Full rebuilds then serve
    /// bulk scans from memory after the first pass. The setting costs one
    /// master key set in RAM. It is safe only while serve() holds the single
    /// writer for the prefix. The default is false.
    #[serde(default)]
    pub mirror_master: bool,
    /// Seconds that a single-writer lease stays valid without a renewal.
    ///
    /// The server claims a lease on `[database].prefix` at startup. It
    /// refuses to start if another process holds a live lease, because two
    /// writers on one prefix diverge in a way that no tool reports. See
    /// [`rust_api::lease`]. The TTL must exceed the longest pause between
    /// renewals. Examples of such a pause are a long GC pause and a slow S3
    /// round trip. Otherwise a peer displaces a healthy process.
    ///
    /// Set the value to `0` to disable the lease. This setting is safe only
    /// if exactly one process can reach the bucket, such as on a laptop. A
    /// disabled lease gives split brain back to the operator.
    ///
    /// The value must fit in the signed range that the lease compares in. A
    /// TTL above `i64::MAX` reads as already stale, which silently disables
    /// single-writer enforcement. Validation rejects that value.
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
/// CORS is off by default. An empty `allowed_origins` serves API responses
/// without `Access-Control-Allow-Origin`, so only the same origin is
/// allowed. List each browser origin when the SPA is served from another
/// origin. Each origin must be an `http(s)` URL without a trailing slash.
/// Credentials are always allowed, so that the `auth_token` cookie and the
/// `Authorization` bearer header work across origins.
#[derive(Deserialize, Debug, Default, Clone)]
pub struct HttpConfig {
    /// Browser origins that CORS allows, for example
    /// `["https://app.example.com"]`.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// Cost limits for requests whose work a single request does not bound.
///
/// Both limits default to off, which means `0`, not to a number that the
/// crate guesses. A default limit is a default outage. If the limit is too
/// low, a valid burst gets 429 responses. If the limit is too high, it does
/// not limit anything. The values that a deployment needs depend on its
/// egress budget and its client poll interval. This crate knows neither.
#[derive(Deserialize, Debug, Default, Clone)]
pub struct LimitsConfig {
    /// Requests per minute for each peer address, after an initial burst of the
    /// same size. A value of `0` disables the bucket.
    #[serde(default)]
    pub rate_per_minute: u32,

    /// Highest burst that is allowed before the refill rate applies. A value of
    /// `0` means "the same as `rate_per_minute`", so a plain rate limit needs
    /// only one number.
    #[serde(default)]
    pub rate_burst: u32,

    /// Downloads of `/sync/db/{object}` that may run at the same time. A value
    /// of `0` disables the gate.
    ///
    /// This limit is the one that bounds real cost. A replica prefix holds
    /// oxkv files, so one such request can read an SST of hundreds of
    /// megabytes. A rate limit does not bound that cost, because requests at
    /// an allowed rate can still run at the same time.
    #[serde(default)]
    pub max_concurrent_downloads: usize,
}

impl LimitsConfig {
    /// Burst to use when the config sets none.
    pub fn burst_or_rate(&self) -> u32 {
        if self.rate_burst == 0 {
            self.rate_per_minute
        } else {
            self.rate_burst
        }
    }
}

/// Signing keys for the capability token, which is a file delegation JWT.
///
/// Each key is 64 hex characters, which is 32 bytes. Generate a key with
/// `python3 -c "import secrets; print(secrets.token_hex(32))"`. If the
/// section is omitted, the server uses an ephemeral OS-RNG key on each boot.
/// The tokens then die with the process. That is fine in development, and the
/// server logs a warning. To rotate a key, move the current secret to
/// `previous_secret`, then deploy the new one as `secret`. A token that was
/// made under either key still verifies until the old generation expires. The
/// TTL is 5 minutes.
#[derive(Deserialize, Debug, Default)]
pub struct CapabilityConfig {
    /// Current signing secret. It makes tokens.
    #[serde(default)]
    pub secret: Option<String>,
    /// Previous signing secret. It verifies tokens during a rotation only.
    #[serde(default)]
    pub previous_secret: Option<String>,
}

/// Object store settings, using AmazonS3 through object_store. Tests use
/// InMemory.
///
/// The settings apply to `object_store::aws::AmazonS3` for S3-compatible
/// providers, which are AWS, MinIO, and R2. Tests use
/// `object_store::memory::InMemory`.
#[derive(Deserialize, Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name.
    pub bucket: String,
    /// AWS region (e.g. `us-east-1`).
    pub region: String,
    /// Custom endpoint URL for S3-compatible providers (MinIO, R2). Omit for AWS.
    #[serde(default)]
    pub endpoint_url: Option<String>,
    /// Whether to use path-style addressing. MinIO requires that style.
    #[serde(default)]
    pub force_path_style: bool,
    /// Access key ID. If the field is absent, the client falls back to an
    /// environment variable or an instance profile.
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
    /// Every file-parsing test in this module uses this function instead of
    /// [`Config::try_from`]. The reason is that `try_from` reads
    /// `RUST_API_CLIENT_SECRET`, `RUST_API_S3_ACCESS_KEY_ID`,
    /// `RUST_API_CAPABILITY_SECRET`, `RUST_API_CAPABILITY_SECRET_PREV`,
    /// `RUST_API_S3_SECRET_ACCESS_KEY`, and `RUST_API_ALLOWED_ORIGINS` out of
    /// the process environment.
    ///
    /// That is a real hazard, not a theoretical one. `cargo test` inherits
    /// the developer's shell, and the run instructions in the README export
    /// `RUST_API_CLIENT_SECRET`. A fixture that asserts on the value in the
    /// file then fails for anyone who followed them. With the variable set,
    /// the empty `client_secret` case in `validate_rejects_bad_values` is
    /// validated against the environment value. Validation then PASSES, and
    /// the `unwrap_err()` in `validation_error` panics. The same applies to
    /// the `[capability] secret = "deadbeef"` case under
    /// `RUST_API_CAPABILITY_SECRET`. It also applies to the
    /// `access_key_id == "ak"` value in `parses_full_config_with_overrides`
    /// under `RUST_API_S3_ACCESS_KEY_ID`.
    ///
    /// The other option is worse. A test that changes the environment calls
    /// `set_var`, which is process-wide. The call races with every other test
    /// thread under the default parallelism of cargo. The call is also
    /// `unsafe` in Rust 2024. So this module has a pure entry point instead.
    /// That is the same split that `apply_env_overrides` already claimed to
    /// have, "so precedence is unit-testable without mutating the process
    /// environment". The file-parsing tests never had that treatment.
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
        // Use the loader instead of `parse_toml`, because the test asserts
        // on the message and an operator hits the loader.
        let path = tmp_toml("not = toml [[[ ");
        let err = Config::try_from(path.as_path()).unwrap_err().to_string();
        assert!(err.contains("Failed to parse config file"));
        let _ = std::fs::remove_file(&path);

        // The same document through the pure entry point, which the file
        // tests below use. The message is identical, so both functions
        // share the parse.
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
        // The prefix defaults to "oxkv" when the field is omitted.
        assert_eq!(cfg.database.prefix, "oxkv");
        // The observability defaults apply when the section is omitted.
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
    /// must come from the `tid` claim of each token. Without an allowlist,
    /// that check does nothing. Any tenant that agreed to an app registration
    /// for more than one tenant makes a token. That token verifies with the
    /// shared JWKS. That token carries our client ID as `aud`. The server
    /// must refuse to start instead.

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

        // With an allowlist, the same config starts. The key belongs to the
        // [authorization] table, so it goes next to client_secret rather
        // than at the end of the file.
        let allowed = templated.replace(
            "client_secret = \"csecret\"",
            "client_secret = \"csecret\"\n            allowed_tenants = [\"tenant-a\"]",
        );
        let cfg = parse(&allowed).expect("an allowlisted tenant should validate");
        assert_eq!(cfg.authorization.allowed_tenants, vec!["tenant-a"]);
    }

    /// An entry that is present but blank resolves an issuer to the text around
    /// the placeholder, with nothing substituted. Reject such an entry
    /// instead of accepting a tenant ID that has no value.
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

    /// The allowlist has meaning only for a templated issuer. A single-tenant
    /// issuer must still start without an allowlist.
    #[test]
    fn a_single_tenant_issuer_needs_no_allowlist() {
        parse(&minimal_toml()).expect("single-tenant issuer needs no allowlist");
    }

    fn validation_error(toml: &str) -> String {
        let err = parse(toml).unwrap_err();
        // Debug renders the whole chain of anyhow contexts. Display renders
        // only the outer context.
        format!("{err:?}")
    }

    #[test]
    fn validate_rejects_bad_values() {
        // The sample ratio is out of range. Telemetry used to clamp the
        // value silently.
        let err = validation_error(&minimal_toml().replace(
            "region = \"us-east-1\"",
            "region = \"us-east-1\"\n[observability]\nsample_ratio = 1.5",
        ));
        assert!(err.contains("sample_ratio"), "unexpected: {err}");

        // The prefix leaves its bucket scope.
        let err = validation_error(
            &minimal_toml().replace("prefix = \"oxkv\"", "prefix = \"../escape\""),
        );
        assert!(err.contains("database.prefix"), "unexpected: {err}");

        // The bucket or the region is empty.
        let err =
            validation_error(&minimal_toml().replace("bucket = \"my-bucket\"", "bucket = \"\""));
        assert!(err.contains("s3.bucket"), "unexpected: {err}");
        let err =
            validation_error(&minimal_toml().replace("region = \"us-east-1\"", "region = \"\""));
        assert!(err.contains("s3.region"), "unexpected: {err}");

        // The addresses are not URLs.
        let err =
            validation_error(&minimal_toml().replace("https://example.test", "not a url !!!"));
        assert!(err.contains("public_address"), "unexpected: {err}");
        let err = validation_error(&minimal_toml().replace("https://idp.test", "ftp://idp.test"));
        assert!(
            err.contains("authorization.issuer_url"),
            "unexpected: {err}"
        );

        // The credentials are empty.
        let err = validation_error(
            &minimal_toml().replace("client_secret = \"csecret\"", "client_secret = \"\""),
        );
        assert!(err.contains("client_secret"), "unexpected: {err}");

        // The capability secret is truncated or not hex. Such a secret gives
        // weak HMAC material.
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
        // A secret with the correct form passes validation.
        let ok = minimal_toml().replace(
            "region = \"us-east-1\"",
            &format!(
                "region = \"us-east-1\"\n[capability]\nsecret = \"{}\"",
                "ab".repeat(32)
            ),
        );
        assert!(parse(&ok).is_ok());
    }

    /// A TTL that is too large for the comparison must be refused at startup,
    /// not discovered later.
    ///
    /// `[database].writer_lease_ttl_secs` is a `u64` that no check reads. The
    /// lease compared `age < ttl_secs as i64`. A TTL at or above 2^63 casts
    /// to a negative `i64`. The test `age < negative` is then false for
    /// *every* live holder. Every second writer is told the lease is stale,
    /// and it takes the prefix from a running server. The only trace is a
    /// `warn!` that nobody reads. The single-writer guard is silently off,
    /// which is the one failure that this crate exists to prevent.
    #[test]
    fn a_lease_ttl_above_the_signed_range_is_refused() {
        // One value past the signed range. This is the exact value
        // that casts negative.
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

        // The highest value that is accepted still starts. The bound
        // sits at the limit of the comparison, not at an arbitrary
        // round number below it.
        let at_limit = minimal_toml().replace(
            "prefix = \"oxkv\"",
            "prefix = \"oxkv\"\nwriter_lease_ttl_secs = 9223372036854775807",
        );
        let cfg = parse(&at_limit).expect("i64::MAX is a valid TTL");
        assert_eq!(cfg.database.writer_lease_ttl_secs, i64::MAX as u64);
    }

    #[test]
    fn http_allowed_origins_default_empty_and_validate() {
        // An omitted [http] section means the same origin only.
        let cfg = parse(&minimal_toml()).expect("should parse");
        assert!(cfg.http.allowed_origins.is_empty());

        // Origins that the config lists are parsed.
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

        // Origins that are not http(s) fail at startup, not later in the
        // browser.
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

    /// The same TOML gives the same config on two runs.
    ///
    /// This is easy for a pure parser. That is why the test is worth keeping.
    /// This is the property that stopped being true when file parsing gained
    /// an environment overlay. `Config::try_from` reads six `RUST_API_*`
    /// variables. Under `RUST_API_CLIENT_SECRET=...`, two parses of the same
    /// document can therefore disagree. They did disagree for every test
    /// that asserted on a value in the file. No claim of the form "the config
    /// file says X" survives an overlay whose input the test does not
    /// control.
    ///
    /// `Config` does not implement `PartialEq`, so the test compares the
    /// fields that the overlay touches directly.
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
        // The values come from the file. That is the part that the
        // overlay used to change under the assertions.
        assert_eq!(first.s3.access_key_id.as_deref(), Some("ak"));
        assert_eq!(first.authorization.client_secret, "csecret");
    }

    /// A plain parse is not an overlay in disguise. The environment cannot
    /// reach it.
    ///
    /// The test proves this without touching the process environment, which
    /// is the whole point. A call to `set_var` is process-wide, and it would
    /// race with every other test thread. The test drives the overlay through
    /// the same injected lookup that `apply_env_overrides` uses, and it
    /// populates every variable. The function `parse_toml` is unaffected by
    /// construction, because it never calls the overlay. The test asserts on
    /// the RESULT, not on the absence of a call. The test applies the overlay
    /// to a config that was parsed the same way. Every field that the overlay
    /// claims then comes back different.
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

        // A plain parse of the SAME document has none of those changes.
        let plain = parse(&toml).expect("parses");
        assert_eq!(plain.authorization.client_secret, "csecret");
        assert_eq!(plain.s3.access_key_id.as_deref(), Some("ak"));
        assert_eq!(plain.s3.secret_access_key.as_deref(), Some("sk"));
        assert!(plain.capability.secret.is_none());
        assert!(plain.capability.previous_secret.is_none());
        assert_eq!(plain.http.allowed_origins, vec!["https://file.example.com"]);
    }

    /// The overlay is what production reads, so the loader needs covering. The
    /// loader reads the file, parses it, applies the overlay, and validates
    /// again.
    ///
    /// This test uses `try_from_with`, not `TryFrom`, so that the
    /// environment is injected. The reason is not only the assertions. The
    /// loader validates again after the overlay. A developer who sets
    /// `RUST_API_CAPABILITY_SECRET` to anything other than 64 hex characters
    /// therefore fails inside `validate()` before a single assertion runs.
    /// Asserting on fields with no `RUST_API_*` override is not enough,
    /// because validation reads the overlaid secret in any case.
    #[test]
    fn the_loader_reads_a_file_and_applies_the_overlay() {
        let path = tmp_toml(&minimal_toml());
        // No variables are set, so the values in the file apply.
        let plain = Config::try_from_with(path.as_path(), |_| None)
            .expect("the loader accepts a valid file");
        assert_eq!(plain.public_address, "https://example.test");
        assert_eq!(plain.listen_port, 8080);
        assert_eq!(plain.s3.bucket, "my-bucket");

        // The overlay wins, and validation reads the overlaid value.
        let secret = "ab".repeat(32);
        let overlaid = Config::try_from_with(path.as_path(), |name| match name {
            ENV_CLIENT_SECRET => Some("from-env".to_string()),
            ENV_CAPABILITY_SECRET => Some(secret.clone()),
            _ => None,
        })
        .expect("an overlay carrying a valid secret still validates");
        assert_eq!(overlaid.authorization.client_secret, "from-env");
        assert_eq!(overlaid.capability.secret.as_deref(), Some(secret.as_str()));

        // The loader rejects an overlay that the validator rejects. That
        // is the purpose of validating again after the overlay.
        let rejected = Config::try_from_with(path.as_path(), |name| {
            (name == ENV_CAPABILITY_SECRET).then(|| "short".to_string())
        })
        .expect_err("a bad overlaid secret must not survive validation");
        assert!(
            format!("{rejected:?}").contains("capability secret"),
            "the error names the offending field, got: {rejected:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// `TryFrom` is the production loader. It must still consult the real
    /// environment. This test checks the loader through the public path,
    /// instead of a copy of the code inside `try_from_with`.
    #[test]
    fn try_from_rejects_a_missing_file() {
        let missing = std::path::Path::new("/nonexistent/rust-api-config-test.toml");
        let err = Config::try_from(missing).expect_err("a missing file is an error");
        assert!(format!("{err:?}").contains("is not a file"), "got: {err:?}");
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

    /// The lease TTL decides how long a crashed writer blocks its
    /// replacement. The default must therefore be a real value, not zero. A
    /// value of zero silently disables single-writer enforcement.
    #[test]
    fn writer_lease_ttl_defaults_on_and_can_be_disabled() {
        let cfg = parse(&minimal_toml()).expect("should parse");
        assert_eq!(cfg.database.writer_lease_ttl_secs, 60);
        assert_eq!(
            cfg.database.writer_lease_ttl_secs,
            default_writer_lease_ttl_secs()
        );

        // The key must go in the [database] table. It must not go after
        // `region`, because `region` sits in [s3]. Serde ignores an
        // unknown key there, so the test would silently assert the
        // default.
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
