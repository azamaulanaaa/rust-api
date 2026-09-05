//! TOML configuration model for the server binary.

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
    /// Telemetry settings; defaults apply when the section is omitted.
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

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
        let config: Self = toml::from_str(&content).context("Failed to parse config file")?;

        Ok(config)
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
    /// File path of the embedded oxkv (Redb) database backing policies.
    pub path: String,
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
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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
            path = "/tmp/db.redb"
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
            path = "/tmp/db2.redb"
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
        assert_eq!(cfg.observability.service_name, "my-service");
        assert_eq!(cfg.observability.sample_ratio, 0.5);
        assert_eq!(
            cfg.observability.otlp_endpoint.as_deref(),
            Some("http://localhost:4317")
        );
        let _ = std::fs::remove_file(&path);
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
