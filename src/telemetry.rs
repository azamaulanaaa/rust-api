//! Telemetry bootstrap: installs the global [`tracing`] subscriber and,
//! when configured, exports spans to an OpenTelemetry collector via OTLP.
//!
//! Console output is always enabled; `RUST_LOG` overrides the filter when
//! set, otherwise the level derives from the CLI's verbose flag. When an
//! OTLP endpoint is configured, spans are batch-exported over gRPC and the
//! W3C Trace Context propagator is registered globally so distributed
//! traces can be continued across service boundaries.

use anyhow::Context;
use opentelemetry::{
    global,
    trace::TracerProvider as _, // trait method: provider.tracer(name)
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    propagation::TraceContextPropagator,
    trace::SdkTracerProvider,
};
use tracing_subscriber::{
    EnvFilter,
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// Handle for telemetry resources that must live for the process duration.
///
/// Dropping it shuts down any installed tracer provider, flushing pending
/// spans (best effort). Keep it alive until shutdown.
#[derive(Debug)]
pub struct Telemetry {
    tracer_provider: Option<SdkTracerProvider>,
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("failed to shut down tracer provider: {e:?}");
            }
        }
    }
}

/// Installs the global tracing subscriber and optional span export.
///
/// Log filtering uses `RUST_LOG` syntax; when the environment variable is
/// unset, `verbose` selects between `debug` and `info` levels. When
/// `otlp_endpoint` is `Some`, spans are exported via OTLP/gRPC and the W3C
/// Trace Context propagator is registered globally.
pub fn init(
    verbose: bool,
    service_name: &str,
    otlp_endpoint: Option<&str>,
) -> anyhow::Result<Telemetry> {
    let default_filter = if verbose { "debug" } else { "info" };
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_filter));

    // Register before any request can be served so inbound traceparent
    // headers link remote parents to our server spans (see request tracing).
    global::set_text_map_propagator(TraceContextPropagator::new());

    let fmt_layer = tracing_subscriber::fmt::layer();

    match otlp_endpoint {
        Some(endpoint) => {
            let exporter = SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()
                .map_err(|e| anyhow::anyhow!("OTLP span exporter build failed: {e}"))
                .context("telemetry initialization")?;

            let provider = SdkTracerProvider::builder()
                // Value: From<String> only — no borrowed-string conversion.
                .with_resource(
                    Resource::builder()
                        .with_service_name(service_name.to_string())
                        .build(),
                )
                .with_batch_exporter(exporter)
                .build();

            let tracer = provider.tracer("rust-api");

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to install tracing subscriber: {e}"))
                .context("telemetry initialization")?;

            Ok(Telemetry {
                tracer_provider: Some(provider),
            })
        }
        None => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .try_init()
                .map_err(|e| anyhow::anyhow!("failed to install tracing subscriber: {e}"))
                .context("telemetry initialization")?;

            Ok(Telemetry {
                tracer_provider: None,
            })
        }
    }
}
