//! Per-request tracing middleware producing OpenTelemetry-compatible
//! server spans.
//!
//! Each request gets a span named `<METHOD> <route-pattern>` carrying the
//! HTTP method, path, response status, and latency. Inbound `traceparent`
//! headers are extracted through the globally registered W3C Trace Context
//! propagator, so requests from upstream instrumented services continue the
//! same distributed trace.

use std::{
    future::{Ready, ready},
    rc::Rc,
    time::Instant,
};

use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, forward_ready},
    http::header::HeaderMap,
};
use futures_util::future::LocalBoxFuture;
use opentelemetry::global;
use tracing::{Instrument, field::Empty};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Adapter exposing Actix headers to the OpenTelemetry propagator API.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Middleware factory installing per-request tracing spans.
///
/// Register outermost so downstream handler and middleware activity nests
/// inside the request span.
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

/// The instantiated per-worker middleware produced by
/// [`RequestTracingMiddleware`].
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
        // Route template (e.g. /policy/{user_id}) keeps cardinality low in
        // trace backends; fall back to the raw path when unrouted.
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
            span.record("latency.ms", start.elapsed().as_millis() as u64);
            if status.is_server_error() {
                // Surface 5xx as error-status spans in trace backends.
                span.record("otel.status_code", "ERROR");
            }

            Ok(res)
        })
    }
}
