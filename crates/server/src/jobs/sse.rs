//! The server-sent event route for one job status.
//!
//! The SSE feature fills this route. The stub answers 501.

use actix_web::{HttpResponse, get, web};

use super::not_implemented;

/// Streams the status of one job as server-sent events.
///
/// The route answers 501 until the SSE feature lands. The finished route
/// sends an initial `status` event, a heartbeat, and one terminal event.
#[utoipa::path(
    get,
    path = "/jobs/{id}/events",
    tag = "jobs",
    params(("id" = String, Path, description = "job identifier")),
    responses(
        (status = 501, description = "not implemented", body = crate::http::error::ErrorBody)
    )
)]
#[get("/{id}/events")]
pub async fn job_events(_id: web::Path<String>) -> HttpResponse {
    not_implemented("job status streaming")
}
