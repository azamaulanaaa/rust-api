use std::{fs, path::Path};

use anyhow::Context;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub public_address: String,
    pub listen_port: u16,
    pub authorization: ConfigAuthorization,
}

impl TryFrom<&Path> for Config {
    type Error = anyhow::Error;

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

#[derive(Deserialize, Debug)]
pub struct ConfigAuthorization {
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
}
