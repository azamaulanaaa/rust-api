//! OpenAPI specification composed from `utoipa::path` handlers.

use utoipa::OpenApi;

/// Top-level OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    info(title = "rust-api", version = "0.1.0", description = "S3 proxy FS + Casbin RBAC + OIDC"),
    paths(
        crate::http::health::health,
        crate::http::health::ready,
        crate::oidc::route::login,
        crate::oidc::route::callback,
        crate::oidc::route::me,
        crate::oidc::route::logout,
        crate::policy::setup::claim_admin,
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
        crate::policy::route::get_user_groups,
        crate::policy::route::get_group_users,
        crate::policy::route::assign_group,
        crate::policy::route::remove_user_from_group,
        crate::policy::route::list_groups,
        crate::policy::route::list_users,
        crate::policy::route::delete_group,
        crate::sync::route::status_handler,
        crate::sync::route::sync_handler,
        crate::sync::route::object_handler,
    ),
    components(schemas(
        crate::fs::model::InitRequest,
        crate::fs::model::CompleteRequest,
        crate::fs::model::FileMetadata,
        crate::fs::model::InitResponse,
        crate::fs::model::ProgressResponse,
        crate::http::error::ErrorBody,
        crate::oidc::route::AuthResponse,
        crate::oidc::route::MeResponse,
        crate::policy::route::PolicyRequest,
        crate::policy::route::GroupRequest,
        crate::policy::route::ActionResponse,
        crate::policy::route::ListResponse,
        crate::policy::route::RuleListResponse,
        crate::policy::route::GroupsResponse,
        crate::policy::route::UsersResponse,
        crate::policy::setup::SetupResponse,
        crate::policy::GroupSummary,
        crate::policy::UserAssignment,
        crate::policy::Action,
        crate::sync::route::SyncStatusResponse,
        crate::sync::route::SyncAdvanceResponse,
    )),
    tags((name = "health"), (name = "auth"), (name = "setup"), (name = "fs"), (name = "policy"), (name = "sync"))
)]
pub struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Guards the PWA contract: every served route the SPA codegen depends
    /// on must appear in the spec, so drift breaks this test instead of the
    /// frontend at runtime.
    #[test]
    fn spec_covers_all_served_routes() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");
        let paths = spec.get("paths").and_then(Value::as_object).expect("paths");
        for route in [
            "/health",
            "/ready",
            "/auth/login",
            "/auth/callback",
            "/auth/me",
            "/auth/logout",
            "/setup/admin",
            "/fs/uploads",
            "/fs/uploads/{id}/parts/{idx}",
            "/fs/uploads/{id}/complete",
            "/fs/uploads/{id}",
            "/policy/rules",
            "/policy/groups",
            "/policy/groups/{user_id}",
            "/policy/groups/{group_name}/users",
            "/policy/groups/{group_name}/users/{user_id}",
            "/policy/groups/{group_name}",
            "/policy/users",
            "/sync/status",
            "/sync/sync",
            "/sync/db/{object}",
        ] {
            assert!(paths.contains_key(route), "spec missing {route}");
        }
    }
}
