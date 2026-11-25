//! OpenAPI specification, composed from the `utoipa::path` handlers.

use utoipa::OpenApi;

/// Top-level OpenAPI document.
#[derive(Debug, OpenApi)]
#[openapi(
    info(title = "rust-api", version = "0.1.0", description = "S3 proxy FS + Casbin RBAC + OIDC"),
    paths(
        crate::http::health::health,
        crate::http::health::ready,
        crate::oidc::route::login,
        crate::oidc::route::callback,
        crate::oidc::route::me,
        crate::oidc::route::logout,
        crate::oidc::route::refresh,
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
        crate::eav::route::publish_schema,
        crate::eav::route::list_schemas,
        crate::eav::route::get_schema,
        crate::eav::route::get_schema_version,
        crate::eav::route::get_effective_schema,
        crate::eav::route::list_schema_children,
        crate::eav::route::diff_schema,
        crate::eav::route::revalidate_schema,
        crate::eav::route::migrate_schema,
        crate::eav::route::create_entity,
        crate::eav::route::list_entities,
        crate::eav::route::query_entities,
        crate::eav::route::list_entity_referrers,
        crate::eav::route::get_entity,
        crate::eav::route::patch_entity,
        crate::eav::route::delete_entity,
        crate::eav::route::list_schema_entities,
        crate::eav::route::upsert_rule,
        crate::eav::route::list_rules,
        crate::eav::route::list_dead_letters,
        crate::eav::route::retry_dead_letter,
        crate::eav::route::retry_entry_dead_letter,
        crate::eav::route::get_rule,
        crate::eav::route::delete_rule,
        crate::eav::route::set_rule_enabled,
        crate::eav::sync::status,
        crate::eav::sync::events,
        crate::eav::sync::snapshot,
        crate::eav::sync::build_replica,
        crate::eav::sync::replica,
        crate::eav::sync::reset_replica,
        crate::eav::sync::replica_status,
        crate::jobs::poll::get_job,
        crate::jobs::poll::create_job,
        crate::jobs::sse::job_events,
    ),
    components(schemas(
        crate::eav::schema::SchemaDraft,
        crate::eav::schema::SchemaDef,
        crate::eav::schema::EffectiveSchema,
        crate::eav::schema::AttributeDef,
        crate::eav::schema::AttributeType,
        crate::eav::schema::SchemaRef,
        crate::eav::schema::AttributeTransition,
        crate::eav::schema::SchemaDiff,
        crate::eav::entity::EntityDraft,
        crate::eav::entity::EntityPatch,
        crate::eav::entity::Entity,
        crate::eav::entity::AttributeValue,
        crate::eav::entity::RevalidationIssue,
        crate::eav::entity::InvalidEntity,
        crate::eav::entity::RevalidationReport,
        crate::eav::entity::MigrationReport,
        crate::eav::route::EntityPatchRequest,
        crate::eav::route::RuleEnabledRequest,
        crate::eav::route::RevalidateRequest,
        crate::eav::route::MigrateRequest,
        crate::eav::route::SchemaPage,
        crate::eav::route::EntityPage,
        crate::eav::route::RulePage,
        crate::eav::route::DeadLetterPage,
        crate::eav::route::ReferrerPage,
        crate::eav::route::EntityQueryRequest,
        crate::eav::route::EntityQueryPage,
        crate::eav::sync::SyncStatusResponse,
        crate::eav::sync::SyncEvent,
        crate::eav::sync::SyncEventsResponse,
        crate::eav::sync::SyncEventsQuery,
        crate::eav::sync::SnapshotPage,
        crate::eav::sync::ReplicaBuildResponse,
        crate::eav::sync::ReplicaChunkQuery,
        crate::eav::sync::ReplicaChunkResponse,
        crate::eav::sync::ReplicaReadResponse,
        crate::eav::sync::ReplicaStatusResponse,
        crate::rules::rule::RuleDraft,
        crate::rules::rule::Rule,
        crate::rules::rule::RuleCapabilities,
        crate::rules::rule::RuleTrigger,
        crate::rules::rule::Condition,
        crate::rules::rule::CompareOp,
        crate::rules::rule::ActionRef,
        crate::rules::store::RuleDeadLetter,
        crate::records::EntityEventKind,
        crate::records::EntityEvent,
        crate::records::AttributeChange,
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
        rust_api_model::domain::CommandKind,
        rust_api_model::wire::CommandEnvelope,
        rust_api_model::wire::JobStatusView,
    )),
    tags((name = "health"), (name = "auth"), (name = "setup"), (name = "fs"), (name = "policy"), (name = "sync"), (name = "eav"), (name = "jobs"))
)]
pub struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// The error schema names the new optional fields. `error` stays the
    /// only required field, so an old client can read every body.
    #[test]
    fn error_schema_documents_the_optional_fields() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");
        let schema = &spec["components"]["schemas"]["ErrorBody"];
        let properties = schema["properties"].as_object().expect("error properties");
        assert!(properties.contains_key("error"));
        assert!(properties.contains_key("code"));
        assert!(properties.contains_key("details"));

        let required = schema["required"].as_array().expect("required fields");
        assert!(required.iter().any(|value| value == "error"));
        assert!(!required.iter().any(|value| value == "code"));
        assert!(!required.iter().any(|value| value == "details"));
    }

    /// Each list route returns one of the page envelopes.
    #[test]
    fn page_envelopes_are_in_the_spec() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");
        let schemas = spec["components"]["schemas"]
            .as_object()
            .expect("component schemas");
        for name in ["SchemaPage", "EntityPage", "RulePage"] {
            assert!(schemas.contains_key(name), "spec missing {name}");
        }
    }

    /// The schema evolution types appear in the components.
    #[test]
    fn schema_evolution_types_are_in_the_spec() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");
        let schemas = spec["components"]["schemas"]
            .as_object()
            .expect("component schemas");
        for name in [
            "SchemaDiff",
            "AttributeTransition",
            "RevalidationReport",
            "InvalidEntity",
            "RevalidationIssue",
            "RevalidateRequest",
            "MigrationReport",
            "MigrateRequest",
        ] {
            assert!(schemas.contains_key(name), "spec missing {name}");
        }
    }

    /// The entity sync types appear in the components.
    #[test]
    fn entity_sync_types_are_in_the_spec() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");
        let schemas = spec["components"]["schemas"]
            .as_object()
            .expect("component schemas");
        for name in [
            "EavSyncStatusResponse",
            "SyncEvent",
            "SyncEventsResponse",
            "SyncEventsQuery",
            "SnapshotPage",
            "ReplicaBuildResponse",
            "ReplicaChunkQuery",
            "ReplicaChunkResponse",
            "ReplicaStatusResponse",
        ] {
            assert!(schemas.contains_key(name), "spec missing {name}");
        }
    }

    /// The replica read route documents both response shapes.
    ///
    /// Without `chunk`, the route returns a JSON array of entities.
    /// With `chunk=N`, it returns one `ReplicaChunkResponse`.
    #[test]
    fn replica_read_documents_the_chunk_response() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");
        let schemas = spec["components"]["schemas"]
            .as_object()
            .expect("component schemas");
        assert!(schemas.contains_key("ReplicaChunkResponse"));
        let one_of = schemas["ReplicaReadResponse"]["oneOf"]
            .as_array()
            .expect("ReplicaReadResponse oneOf");
        assert_eq!(one_of.len(), 2);
        let shapes = serde_json::to_string(one_of).expect("oneOf serializes");
        assert!(shapes.contains("ReplicaChunkResponse"), "{shapes}");
        assert!(shapes.contains("Entity"), "{shapes}");

        let schema = &spec["paths"]["/eav/sync/replica"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"];
        assert_eq!(
            schema["$ref"], "#/components/schemas/ReplicaReadResponse",
            "replica read schema is {schema}"
        );
    }

    /// The job submission route documents its request body and accepted view.
    #[test]
    fn the_job_submission_route_documents_the_body_and_view() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");

        let post = &spec["paths"]["/jobs"]["post"];
        assert_eq!(
            post["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/CommandEnvelope",
            "the request body must name the command envelope"
        );
        assert_eq!(
            post["responses"]["202"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/JobStatusView",
            "the accepted response must name the job view"
        );

        let schemas = spec["components"]["schemas"]
            .as_object()
            .expect("component schemas");
        for name in ["CommandEnvelope", "CommandKind", "JobStatusView"] {
            assert!(schemas.contains_key(name), "spec missing {name}");
        }
    }

    /// The command kind schema carries the parser length limits and pattern.
    #[test]
    fn the_command_kind_schema_carries_the_parser_limits() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");

        let schema = &spec["components"]["schemas"]["CommandKind"];
        assert_eq!(schema["type"], serde_json::json!("string"));
        assert_eq!(schema["minLength"], serde_json::json!(1));
        assert_eq!(schema["maxLength"], serde_json::json!(64));
        assert_eq!(schema["pattern"], serde_json::json!("^[a-z0-9._-]{1,64}$"));
    }

    /// Guards the PWA contract. Every served route that the SPA code generator
    /// uses must appear in the specification. Drift therefore breaks this
    /// test instead of the front end at run time.
    ///
    /// The test also checks the method of each route and the status codes that
    /// a client must handle.
    ///
    /// Maintain these lists by hand:
    ///
    /// 1. Update a list when you change a route in a module's `configure`.
    /// 2. Do not wait for a new `utoipa::path` handler before you update
    ///    the list.
    #[test]
    fn spec_covers_all_served_routes() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");
        let paths = spec.get("paths").and_then(Value::as_object).expect("paths");

        let routes = [
            ("/health", "get"),
            ("/ready", "get"),
            ("/auth/login", "get"),
            ("/auth/callback", "get"),
            ("/auth/me", "get"),
            ("/auth/logout", "post"),
            ("/auth/refresh", "post"),
            ("/setup/admin", "post"),
            ("/fs/uploads", "post"),
            ("/fs/uploads/{id}/parts/{idx}", "put"),
            ("/fs/uploads/{id}/complete", "post"),
            ("/fs/uploads/{id}", "get"),
            ("/fs/uploads/{id}", "delete"),
            ("/fs/files/{id}/meta", "get"),
            ("/fs/files/{id}", "get"),
            ("/fs/files/{id}", "delete"),
            ("/policy/rules", "get"),
            ("/policy/rules", "post"),
            ("/policy/rules", "delete"),
            ("/policy/groups", "get"),
            ("/policy/groups", "post"),
            ("/policy/groups/{user_id}", "get"),
            ("/policy/groups/{group_name}/users", "get"),
            ("/policy/groups/{group_name}/users/{user_id}", "delete"),
            ("/policy/groups/{group_name}", "delete"),
            ("/policy/users", "get"),
            ("/sync/status", "get"),
            ("/sync/sync", "post"),
            ("/sync/db/{object}", "get"),
            ("/eav/schemas", "post"),
            ("/eav/schemas", "get"),
            ("/eav/schemas/{id}", "get"),
            ("/eav/schemas/{id}/versions/{version}", "get"),
            ("/eav/schemas/{id}/effective/{version}", "get"),
            ("/eav/schemas/{id}/children", "get"),
            ("/eav/schemas/{id}/diff", "get"),
            ("/eav/schemas/{id}/revalidate", "post"),
            ("/eav/schemas/{id}/migrate", "post"),
            ("/eav/schemas/{id}/entities", "get"),
            ("/eav/entities", "post"),
            ("/eav/entities", "get"),
            ("/eav/entities/query", "post"),
            ("/eav/entities/{id}/referrers", "get"),
            ("/eav/entities/{id}", "get"),
            ("/eav/entities/{id}", "patch"),
            ("/eav/entities/{id}", "delete"),
            ("/eav/rules", "post"),
            ("/eav/rules", "get"),
            ("/eav/rules/{id}", "get"),
            ("/eav/rules/{id}", "delete"),
            ("/eav/rules/{id}/enabled", "post"),
            ("/eav/rules/dead-letters", "get"),
            (
                "/eav/rules/dead-letters/{seq}/{event_id}/{rule_id}/retry",
                "post",
            ),
            ("/eav/rules/dead-letters/{seq}/{event_id}/retry", "post"),
            ("/eav/sync/status", "get"),
            ("/eav/sync/events", "get"),
            ("/eav/sync/snapshot", "get"),
            ("/eav/sync/replica", "post"),
            ("/eav/sync/replica", "get"),
            ("/eav/sync/replica", "delete"),
            ("/eav/sync/replica/status", "get"),
            ("/jobs", "post"),
            ("/jobs/{id}", "get"),
            ("/jobs/{id}/events", "get"),
        ];
        for (path, method) in routes {
            let item = paths
                .get(path)
                .unwrap_or_else(|| panic!("spec missing {path}"));
            assert!(
                item.get(method).is_some(),
                "spec missing {method} {path}: {item}"
            );
        }

        let statuses: &[(&str, &str, &[u16])] = &[
            ("/eav/schemas/{id}/children", "get", &[200, 404]),
            ("/eav/schemas/{id}/diff", "get", &[200, 400, 404]),
            ("/eav/schemas/{id}/migrate", "post", &[200, 409]),
            ("/eav/entities", "post", &[201, 404, 409]),
            ("/eav/rules", "get", &[200, 400]),
            ("/eav/sync/snapshot", "get", &[200, 400, 409]),
            ("/eav/sync/replica", "get", &[200, 400, 404]),
        ];
        for (path, method, expected) in statuses {
            let responses = paths[*path][*method]["responses"]
                .as_object()
                .unwrap_or_else(|| panic!("spec missing responses for {method} {path}"));
            for status in *expected {
                assert!(
                    responses.contains_key(&status.to_string()),
                    "spec missing status {status} for {method} {path}: {responses:?}"
                );
            }
        }
    }
}
