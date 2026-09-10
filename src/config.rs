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

impl TryFrom<&Path> for Config {
    type Error = anyhow::Error;

    /// Reads and parses a TOML config file from `value`.
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        if !value.is_file() {
            return Err(anyhow::anyhow!(
                "Given path '{:?}' is not a file",
                value.to_str()
            ));
        }

        let content = fs::read_to_string(value).context("Failed to read config file")?;
        let mut config: Self = toml::from_str(&content).context("Failed to parse config file")?;
        apply_env_overrides(&mut config);
        config.validate().context("Invalid config values")?;

        Ok(config)
    }
}

/// Overlays secret values from the environment onto a parsed config.
///
/// Split from file parsing so precedence is unit-testable without
/// mutating the process environment (see `prefer_env` tests).
fn apply_env_overrides(config: &mut Config) {
    config.authorization.client_secret = prefer_env(
        std::env::var(ENV_CLIENT_SECRET).ok(),
        std::mem::take(&mut config.authorization.client_secret),
    );
    config.s3.access_key_id = prefer_env_opt(
        std::env::var(ENV_S3_ACCESS_KEY_ID).ok(),
        config.s3.access_key_id.take(),
    );
    config.s3.secret_access_key = prefer_env_opt(
        std::env::var(ENV_S3_SECRET_ACCESS_KEY).ok(),
        config.s3.secret_access_key.take(),
    );
    config.capability.secret = prefer_env_opt(
        std::env::var(ENV_CAPABILITY_SECRET).ok(),
        config.capability.secret.take(),
    );
    config.capability.previous_secret = prefer_env_opt(
        std::env::var(ENV_CAPABILITY_SECRET_PREV).ok(),
        config.capability.previous_secret.take(),
    );
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
            let parsed: url::Url = url.parse().map_err(|e| {
                anyhow::anyhow!("{name} is not a valid URL ({url:?}): {e}")
            })?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                anyhow::bail!("{name} must use http(s), got {:?}", parsed.scheme());
            }
        }
        if self.authorization.client_id.trim().is_empty() {
            anyhow::bail!("authorization.client_id must not be empty");
        }
        if self.authorization.client_secret.trim().is_empty() {
            anyhow::bail!("authorization.client_secret must not be empty (or set RUST_API_CLIENT_SECRET)");
        }
        if self.database.prefix.trim().is_empty() {
            anyhow::bail!("database.prefix must not be empty");
        }
        if self.database.prefix.split('/').any(|seg| seg == ".." || seg == ".") {
            anyhow::bail!(
                "database.prefix must not contain '.' or '..' segments (got {:?})",
                self.database.prefix
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
}

/// Telemetry/observability settings.
#[derive(Debug, Deserialize, Clone)]
pub struct ObservabilityConfig {
    /// Service name attached to every exported telemetry resource.
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// OTLP/gRPC collector endpoint (e.g. `http://localhost:4317`).
    /// Span export is disabled when absent.
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
}

fn default_db_prefix() -> String {
    "oxkv".to_string()
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
        let path = tmp_toml("not = toml [[[ ");
        let err = Config::try_from(path.as_path()).unwrap_err().to_string();
        assert!(err.contains("Failed to parse config file"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn try_from_parses_minimal_config() {
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
        let path = tmp_toml(toml);
        let cfg = Config::try_from(path.as_path()).expect("should parse");
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
        let _ = std::fs::remove_file(&path);
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
        let path = tmp_toml(toml);
        let cfg = Config::try_from(path.as_path()).unwrap();
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
        let _ = std::fs::remove_file(&path);
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
        let path = tmp_toml(toml);
        let cfg = Config::try_from(path.as_path()).unwrap();
        assert_eq!(cfg.database.prefix, "custom/prefix");
        let _ = std::fs::remove_file(&path);
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

    fn validation_error(toml: &str) -> String {
        let path = tmp_toml(toml);
        let err = Config::try_from(path.as_path()).unwrap_err();
        let _ = std::fs::remove_file(&path);
        // Debug renders the anyhow context chain, Display only the outer.
        format!("{err:?}")
    }

    #[test]
    fn validate_rejects_bad_values() {
        // sample_ratio out of range (telemetry used to clamp silently).
        let err = validation_error(
            &minimal_toml().replace("region = \"us-east-1\"", "region = \"us-east-1\"\n[observability]\nsample_ratio = 1.5"),
        );
        assert!(err.contains("sample_ratio"), "unexpected: {err}");

        // Prefix escaping its bucket scope.
        let err = validation_error(&minimal_toml().replace("prefix = \"oxkv\"", "prefix = \"../escape\""));
        assert!(err.contains("database.prefix"), "unexpected: {err}");

        // Empty bucket / region.
        let err = validation_error(&minimal_toml().replace("bucket = \"my-bucket\"", "bucket = \"\""));
        assert!(err.contains("s3.bucket"), "unexpected: {err}");
        let err = validation_error(&minimal_toml().replace("region = \"us-east-1\"", "region = \"\""));
        assert!(err.contains("s3.region"), "unexpected: {err}");

        // Non-URL addresses.
        let err = validation_error(
            &minimal_toml().replace("https://example.test", "not a url !!!"),
        );
        assert!(err.contains("public_address"), "unexpected: {err}");
        let err = validation_error(&minimal_toml().replace("https://idp.test", "ftp://idp.test"));
        assert!(err.contains("authorization.issuer_url"), "unexpected: {err}");

        // Empty credentials.
        let err = validation_error(&minimal_toml().replace("client_secret = \"csecret\"", "client_secret = \"\""));
        assert!(err.contains("client_secret"), "unexpected: {err}");

        // Truncated/non-hex capability secrets (weak HMAC material).
        let err = validation_error(
            &minimal_toml().replace("region = \"us-east-1\"", "region = \"us-east-1\"\n[capability]\nsecret = \"deadbeef\""),
        );
        assert!(err.contains("64 hex chars"), "unexpected: {err}");
        let err = validation_error(
            &minimal_toml().replace("region = \"us-east-1\"", &format!("region = \"us-east-1\"\n[capability]\nsecret = \"{}\"\nprevious_secret = \"zz\"", "ab".repeat(32))),
        );
        assert!(err.contains("64 hex chars"), "unexpected: {err}");
        // A well-formed secret passes validation.
        let ok = minimal_toml().replace("region = \"us-east-1\"", &format!("region = \"us-east-1\"\n[capability]\nsecret = \"{}\"", "ab".repeat(32)));
        let path = tmp_toml(&ok);
        assert!(Config::try_from(path.as_path()).is_ok());
        let _ = std::fs::remove_file(&path);
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
        assert_eq!(prefer_env_opt(Some("".into()), Some("f".into())), Some("f".into()));
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
}
