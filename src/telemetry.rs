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
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    metrics::SdkMeterProvider,
    propagation::TraceContextPropagator,
    trace::{Sampler, SdkTracerProvider},
};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Handle for telemetry resources that must live for the process duration.
///
/// Dropping it shuts down the installed tracer and meter providers,
/// flushing pending spans and metric points (best effort). Keep it alive
/// until shutdown.
#[derive(Debug)]
pub struct Telemetry {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        // Safety net for early-error paths; the normal shutdown path is the
        // explicit [`Telemetry::shutdown`], which reports failures.
        self.shutdown_inner();
    }
}

impl Telemetry {
    /// Flushes and releases telemetry resources, returning an error if any
    /// pending spans or metric points could not be delivered. Call once at
    /// process exit; dropping without this still flushes best-effort.
    pub fn shutdown(mut self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            errors.push(format!("tracer provider: {e:?}"));
        }
        if let Some(provider) = self.meter_provider.take() {
            // Final periodic-reader collection: flushes pending metric
            // points to the collector.
            if let Err(e) = provider.shutdown() {
                errors.push(format!("meter provider: {e:?}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "telemetry shutdown failed: {}",
                errors.join("; ")
            ))
        }
    }

    fn shutdown_inner(&mut self) {
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("failed to shut down tracer provider: {e:?}");
        }
        if let Some(provider) = self.meter_provider.take() {
            // Final periodic-reader collection: flushes pending metric
            // points to the collector.
            if let Err(e) = provider.shutdown() {
                eprintln!("failed to shut down meter provider: {e:?}");
            }
        }
    }
}

/// Installs the global tracing subscriber and optional span export.
///
/// Log filtering uses `RUST_LOG` syntax; when the environment variable is
/// unset, `verbose` selects between `debug` and `info` levels. When
/// `otlp_endpoint` is `Some`, spans are exported via OTLP/gRPC and the W3C
/// Trace Context propagator is registered globally; request metrics are
/// exported through a second OTLP/gRPC pipeline on the same endpoint.
pub fn init(
    verbose: bool,
    service_name: &str,
    otlp_endpoint: Option<&str>,
    sample_ratio: f64,
) -> anyhow::Result<Telemetry> {
    let default_filter = if verbose { "debug" } else { "info" };
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

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

            let resource = Resource::builder()
                .with_service_name(service_name.to_string())
                .build();

            let provider = SdkTracerProvider::builder()
                .with_resource(resource.clone())
                .with_batch_exporter(exporter)
                // Root spans sample by trace-ID ratio; child spans follow
                // their parent's decision.
                .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                    sample_ratio.clamp(0.0, 1.0),
                ))))
                .build();

            // Metrics share the OTLP endpoint; the periodic reader collects
            // every 60s by default and on shutdown.
            let metric_exporter = MetricExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()
                .map_err(|e| anyhow::anyhow!("OTLP metric exporter build failed: {e}"))
                .context("telemetry initialization")?;
            let reader =
                opentelemetry_sdk::metrics::PeriodicReader::builder(metric_exporter).build();
            let meter_provider = SdkMeterProvider::builder()
                .with_resource(resource)
                .with_reader(reader)
                .build();
            global::set_meter_provider(meter_provider.clone());

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
                meter_provider: Some(meter_provider),
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
                meter_provider: None,
            })
        }
    }
}
