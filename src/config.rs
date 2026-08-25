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
    /// Postgres connection string for the policy store.
    pub database_url: String,
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
