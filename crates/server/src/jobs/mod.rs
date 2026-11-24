//! Job submission and status routes.
//!
//! This module owns the `/jobs` prefix. The poll route and the server-sent
//! event route live in the `poll` and `sse` submodules. The foundation
//! registers the prefix one time, so a feature branch changes only its
//! handler module.
//!
//! Polling is the guaranteed fallback. The SSE route is an optimization.
//! Both routes answer 501 until their feature branch lands.

use actix_web::{
    HttpResponse,
    http::StatusCode,
    web::{self, ServiceConfig},
};

use crate::http::{ApiModule, error::ApiError};

/// The poll route for one job status.
pub mod poll;

/// The server-sent event route for one job status.
pub mod sse;

/// The module that owns the `/jobs` route prefix.
#[derive(Default)]
pub struct JobsApiModule;

impl JobsApiModule {
    /// Creates the module. The module holds no state yet.
    pub fn new() -> Self {
        Self
    }
}

impl ApiModule for JobsApiModule {
    fn prefix(&self) -> &str {
        "/jobs"
    }

    fn configure(&self, cfg: &mut ServiceConfig) {
        cfg.service(
            web::scope("/jobs")
                .service(poll::get_job)
                .service(sse::job_events),
        );
    }
}

/// Builds the not-implemented answer for one route.
///
/// The answer uses the shared error envelope and a message that names the
/// missing behavior. A caller therefore learns that the route exists and
/// that the server has no implementation yet.
pub(crate) fn not_implemented(route: &str) -> HttpResponse {
    ApiError::envelope(
        StatusCode::NOT_IMPLEMENTED,
        &format!("{route} is not implemented"),
        Some("not_implemented"),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test as actix_test;
    use actix_web::{App, http::StatusCode};
    use serde_json::Value;

    /// The module claims only the `/jobs` prefix.
    #[test]
    fn the_module_claims_the_jobs_prefix() {
        assert_eq!(JobsApiModule::new().prefix(), "/jobs");
    }

    /// Both stub routes answer 501 with the shared error envelope.
    #[actix_web::test]
    async fn both_stub_routes_answer_not_implemented() {
        let module = JobsApiModule::new();
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let cases = [
            ("/jobs/one", "job status polling is not implemented"),
            (
                "/jobs/one/events",
                "job status streaming is not implemented",
            ),
        ];
        for (uri, message) in cases {
            let request = actix_test::TestRequest::get().uri(uri).to_request();
            let response = actix_test::call_service(&app, request).await;
            assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED, "{uri}");
            let body: Value = actix_test::read_body_json(response).await;
            assert_eq!(body["error"], message, "{uri}");
            assert_eq!(body["code"], "not_implemented", "{uri}");
        }
    }
}
