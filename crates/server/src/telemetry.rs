//! Telemetry bootstrap. The module installs the global [`tracing`]
//! subscriber. When the config sets an endpoint, it also exports spans to an
//! OpenTelemetry collector through OTLP.
//!
//! Console output is always on. The variable `RUST_LOG` sets the filter when
//! it is present. Otherwise the level comes from the verbose flag of the
//! command line. When the config sets an OTLP endpoint, the server exports
//! spans in batches over OTLP. It also registers the W3C Trace Context
//! propagator for the whole process, so that a trace continues across the
//! boundary between services.
//!
//! The transport follows the compiled cargo feature, not the endpoint string.
//! The default `otlp-http` feature exports over HTTP and protobuf. The
//! `otlp-grpc` feature exports over gRPC. The two features need different
//! shapes for the endpoint. The shapes are `http://collector:4318/v1/traces`
//! and `http://collector:4317`. So a change of feature also needs a change
//! to `observability.otlp_endpoint`.

use opentelemetry::global;
#[cfg(any(feature = "otlp-grpc", feature = "otlp-http"))]
use opentelemetry::trace::TracerProvider as _; // trait method: provider.tracer(name)
#[cfg(any(feature = "otlp-grpc", feature = "otlp-http"))]
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    metrics::SdkMeterProvider,
    propagation::TraceContextPropagator,
    trace::{Sampler, SdkTracerProvider},
};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Verbosity of the console log filter.
#[derive(Clone, Copy, Debug)]
pub enum LogVerbosity {
    /// Use `info` unless `RUST_LOG` sets another filter.
    Normal,
    /// Use `debug` unless `RUST_LOG` sets another filter.
    Verbose,
}

/// An error from telemetry setup or shutdown.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The global tracing subscriber could not be installed.
    #[error("failed to install the tracing subscriber: {0}")]
    Subscriber(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// An OTLP exporter could not be built.
    #[error("failed to build the OTLP exporter: {0}")]
    Exporter(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A provider could not flush its pending data.
    #[error("telemetry shutdown failed: {0}")]
    Shutdown(String),
}

impl TelemetryError {
    fn subscriber(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Subscriber(Box::new(error))
    }

    fn exporter(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Exporter(Box::new(error))
    }
}

/// Handle for the telemetry resources. The resources must stay alive for the
/// whole run of the process.
///
/// Dropping the handle stops the tracer and meter providers. The providers
/// send the spans and the metric points that are still pending, on a best
/// effort basis. Keep the handle until the server shuts down.
#[derive(Debug)]
pub struct Telemetry {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        // A safety net for the paths that end in an error. The normal
        // shutdown path is the explicit [`Telemetry::shutdown`], which
        // reports a failure.
        self.shutdown_inner();
    }
}

impl Telemetry {
    /// Sends the telemetry resources and releases them. The function returns an
    /// error if any span or metric point could not be delivered. Call the
    /// function once at the end of the process. Dropping the handle without
    /// this call still sends the data on a best effort basis.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Shutdown`] when a provider cannot flush its
    /// pending data.
    pub fn shutdown(mut self) -> Result<(), TelemetryError> {
        let mut errors = Vec::new();
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            errors.push(format!("tracer provider: {e:?}"));
        }
        if let Some(provider) = self.meter_provider.take() {
            // The last collection of the periodic reader. It sends
            // the metric points that are still pending to the collector.
            if let Err(e) = provider.shutdown() {
                errors.push(format!("meter provider: {e:?}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(TelemetryError::Shutdown(errors.join("; ")))
        }
    }

    fn shutdown_inner(&mut self) {
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            tracing::error!(error = ?e, "failed to shut down tracer provider");
        }
        if let Some(provider) = self.meter_provider.take() {
            // The last collection of the periodic reader. It sends
            // the metric points that are still pending to the collector.
            if let Err(e) = provider.shutdown() {
                tracing::error!(error = ?e, "failed to shut down meter provider");
            }
        }
    }
}

/// Installs the global tracing subscriber and, when the config sets an
/// endpoint, the export of spans.
///
/// The filter of the logs uses the syntax of `RUST_LOG`. When the variable
/// is not set, `verbosity` selects `debug` or `info`. When `otlp_endpoint` is
/// `Some`, the server exports spans over OTLP. It also registers the W3C
/// Trace Context propagator for the whole process. The request metrics go
/// through a second OTLP pipeline. That pipeline uses the same endpoint and
/// the same transport, which is HTTP and protobuf by default, or gRPC with
/// `otlp-grpc`.
///
/// # Errors
///
/// Returns [`TelemetryError::Subscriber`] when a subscriber is already
/// installed. Returns [`TelemetryError::Exporter`] when an OTLP exporter
/// cannot be built.
pub fn init(
    verbosity: LogVerbosity,
    service_name: &str,
    otlp_endpoint: Option<&str>,
    sample_ratio: f64,
) -> Result<Telemetry, TelemetryError> {
    let default_filter = filter_for(verbosity);
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    // Register before the server can serve any request. Then the
    // inbound `traceparent` headers link a remote parent to the spans of
    // this server. See the docs for the tracing of a request.
    global::set_text_map_propagator(TraceContextPropagator::new());

    let fmt_layer = tracing_subscriber::fmt::layer();

    match otlp_endpoint {
        Some(endpoint) => {
            #[cfg(not(any(feature = "otlp-grpc", feature = "otlp-http")))]
            {
                // Install the subscriber first. A warning before this point
                // has no subscriber and is lost.
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(fmt_layer)
                    .try_init()
                    .map_err(TelemetryError::subscriber)?;
                tracing::warn!(
                    "OTLP endpoint {endpoint} configured but no otlp-* feature enabled; tracing without export"
                );
                return Ok(Telemetry {
                    tracer_provider: None,
                    meter_provider: None,
                });
            }
            #[cfg(any(feature = "otlp-grpc", feature = "otlp-http"))]
            {
                #[cfg(feature = "otlp-grpc")]
                let exporter = SpanExporter::builder()
                    .with_tonic()
                    .with_endpoint(endpoint)
                    .build()
                    .map_err(TelemetryError::exporter)?;
                #[cfg(all(feature = "otlp-http", not(feature = "otlp-grpc")))]
                let exporter = SpanExporter::builder()
                    .with_http()
                    .with_endpoint(endpoint)
                    .build()
                    .map_err(TelemetryError::exporter)?;

                let resource = Resource::builder()
                    .with_service_name(service_name.to_string())
                    .build();

                let provider = SdkTracerProvider::builder()
                    .with_resource(resource.clone())
                    .with_batch_exporter(exporter)
                    .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                        sample_ratio.clamp(0.0, 1.0),
                    ))))
                    .build();

                #[cfg(feature = "otlp-grpc")]
                let metric_exporter = MetricExporter::builder()
                    .with_tonic()
                    .with_endpoint(endpoint)
                    .build()
                    .map_err(TelemetryError::exporter)?;
                #[cfg(all(feature = "otlp-http", not(feature = "otlp-grpc")))]
                let metric_exporter = MetricExporter::builder()
                    .with_http()
                    .with_endpoint(endpoint)
                    .build()
                    .map_err(TelemetryError::exporter)?;
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
                    .map_err(TelemetryError::subscriber)?;

                Ok(Telemetry {
                    tracer_provider: Some(provider),
                    meter_provider: Some(meter_provider),
                })
            }
        }
        None => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .try_init()
                .map_err(TelemetryError::subscriber)?;

            Ok(Telemetry {
                tracer_provider: None,
                meter_provider: None,
            })
        }
    }
}

/// Returns the console filter for one verbosity.
fn filter_for(verbosity: LogVerbosity) -> &'static str {
    match verbosity {
        LogVerbosity::Normal => "info",
        LogVerbosity::Verbose => "debug",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbosity_selects_the_filter() {
        assert_eq!(filter_for(LogVerbosity::Normal), "info");
        assert_eq!(filter_for(LogVerbosity::Verbose), "debug");
    }

    #[test]
    fn setup_errors_keep_their_source() {
        let error = TelemetryError::subscriber(std::io::Error::other("install failed"));
        assert!(std::error::Error::source(&error).is_some());
        assert!(error.to_string().starts_with("failed to install"));
    }
}
