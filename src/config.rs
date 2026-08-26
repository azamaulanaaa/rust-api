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
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: default_service_name(),
            otlp_endpoint: None,
        }
    }
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
