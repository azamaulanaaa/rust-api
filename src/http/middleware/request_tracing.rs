//! Middleware that creates an OpenTelemetry-compatible server span for each
//! request.
//!
//! Each request gets a span named `<METHOD> <route-pattern>`. The span
//! holds the HTTP method, the path, the response status, and the latency.
//! The middleware reads the inbound `traceparent` headers through the
//! globally registered W3C Trace Context propagator. A request from an
//! upstream instrumented service therefore continues the same distributed
//! trace.

use std::{
    future::{Ready, ready},
    rc::Rc,
    sync::LazyLock,
    time::Instant,
};

use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, forward_ready},
    http::header::HeaderMap,
};
use futures_util::future::LocalBoxFuture;
use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram},
};
use tracing::{Instrument, field::Empty};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// The server-side HTTP metrics that the global meter provider exports.
/// The provider uses OTLP when an endpoint is set. The instrument names
/// follow the OTel HTTP semantic conventions.
struct HttpMetrics {
    requests: Counter<u64>,
    duration: Histogram<f64>,
}

static HTTP_METRICS: LazyLock<HttpMetrics> = LazyLock::new(|| {
    let meter = global::meter("rust-api");
    HttpMetrics {
        requests: meter.u64_counter("http.server.request.count").build(),
        duration: meter
            .f64_histogram("http.server.request.duration")
            .with_unit("s")
            .build(),
    }
});

/// The adapter that gives the Actix headers to the OpenTelemetry
/// propagator API.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// The middleware factory that installs a tracing span for each request.
///
/// Register it as the outermost middleware. The activity of the
/// downstream handler and middleware then nests inside the request span.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestTracingMiddleware;

impl<S, B> actix_web::dev::Transform<S, ServiceRequest> for RequestTracingMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = RequestTracingMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestTracingMiddlewareService {
            service: std::rc::Rc::new(service),
        }))
    }
}

/// The middleware service for one worker, which
/// [`RequestTracingMiddleware`] creates.
pub struct RequestTracingMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestTracingMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().to_string();
        // The route template, for example /policy/{user_id}, keeps the
        // number of values low in the trace backends. The code falls back to
        // the raw path when the request has no route.
        let route = req
            .match_pattern()
            .unwrap_or_else(|| req.path().to_string());
        let start = Instant::now();

        let span = tracing::info_span!(
            "http.request",
            "otel.name" = format!("{method} {route}"),
            "http.request.method" = %method,
            "url.path" = %req.path(),
            "http.response.status_code" = Empty,
            "latency.ms" = Empty,
            "request.id" = Empty,
            "request_id" = Empty,
            "http.request.id" = Empty,
        );

        // Continue an upstream distributed trace when a traceparent exists.
        let parent_cx =
            global::get_text_map_propagator(|p| p.extract(&HeaderExtractor(req.headers())));
        if let Err(e) = span.set_parent(parent_cx) {
            tracing::debug!("ignoring invalid inbound trace context: {e}");
        }

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.instrument(span.clone()).await?;

            let status = res.status();
            span.record("http.response.status_code", status.as_u16());
            let elapsed_ms = start.elapsed().as_millis() as u64;
            span.record("latency.ms", elapsed_ms);
            if status.is_server_error() {
                // Show a 5xx response as an error-status span in the trace
                // backends.
                span.record("otel.status_code", "ERROR");
            }

            let attrs = [
                KeyValue::new("http.request.method", method.clone()),
                KeyValue::new("url.route", route.clone()),
                KeyValue::new("http.response.status_code", i64::from(status.as_u16())),
            ];
            HTTP_METRICS.requests.add(1, &attrs);
            HTTP_METRICS
                .duration
                .record(elapsed_ms as f64 / 1000.0, &attrs);

            Ok(res)
        })
    }
}

/// Re-exported request id types for callers that expect them here.
pub use crate::http::middleware::request_id::{
    RequestID, RequestIDMiddleware, RequestId, RequestIdMiddleware,
};
