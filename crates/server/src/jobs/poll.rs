//! The poll route for one job status.
//!
//! The poll feature fills this route. The stub answers 501.

use actix_web::{HttpResponse, get, web};

use super::not_implemented;

/// Returns the status of one job.
///
/// The route answers 501 until the poll feature lands. The finished route
/// returns `200` with a [`JobStatusView`](rust_api_model::wire::JobStatusView)
/// and `404` for an absent or invisible job.
#[utoipa::path(
    get,
    path = "/jobs/{id}",
    tag = "jobs",
    params(("id" = String, Path, description = "job identifier")),
    responses(
        (status = 501, description = "not implemented", body = crate::http::error::ErrorBody)
    )
)]
#[get("/{id}")]
pub async fn get_job(_id: web::Path<String>) -> HttpResponse {
    not_implemented("job status polling")
}
