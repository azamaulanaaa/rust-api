//! Telemetry bootstrap: installs the global [`tracing`] subscriber.
//!
//! Console output is always enabled; `RUST_LOG` overrides the filter when
//! set, otherwise the level derives from the CLI's verbose flag.

use anyhow::Context;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Handle for telemetry resources that must live for the process duration.
///
/// Currently stateless; future observability features (e.g. an OTLP tracer
/// provider) will hold their shutdown handles here.
#[derive(Debug)]
pub struct Telemetry;

/// Installs the global tracing subscriber.
///
/// Log filtering uses `RUST_LOG` syntax; when the environment variable is
/// unset, `verbose` selects between `debug` and `info` levels. The returned
/// [`Telemetry`] handle must be kept alive until shutdown.
pub fn init(verbose: bool) -> anyhow::Result<Telemetry> {
    let default_filter = if verbose { "debug" } else { "info" };
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_filter));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to install tracing subscriber: {e}"))
        .context("telemetry initialization")?;

    Ok(Telemetry)
}
