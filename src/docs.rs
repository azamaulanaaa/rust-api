//! OpenAPI specification composed from `utoipa::path` handlers.

use utoipa::OpenApi;

/// Top-level OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    info(title = "rust-api", version = "0.1.0", description = "S3 proxy FS + Casbin RBAC + OIDC"),
    paths(
        crate::endpoint::route::health::health,
        crate::fs::route::init_upload,
        crate::fs::route::upload_part,
        crate::fs::route::complete_upload,
        crate::fs::route::cancel_upload,
        crate::fs::route::get_progress,
        crate::fs::route::get_metadata,
        crate::fs::route::get_file,
        crate::fs::route::delete_file,
        crate::policy::route::get_rules,
        crate::policy::route::add_rule,
        crate::policy::route::remove_rule,
    ),
    components(schemas(
        crate::fs::model::InitRequest,
        crate::fs::model::CompleteRequest,
        crate::fs::model::FileMetadata,
        crate::fs::model::InitResponse,
        crate::fs::model::ProgressResponse,
        crate::endpoint::error::ErrorBody,
        crate::policy::route::PolicyRequest,
        crate::policy::route::GroupRequest,
        crate::policy::route::ActionResponse,
        crate::policy::route::RuleListResponse,
        crate::policy::Action,
    )),
    tags((name = "health"), (name = "fs"), (name = "policy"))
)]
pub struct ApiDoc;
