//! Actix routes for the EAV schemas, entities, and rules.
//!
//! Every handler authorizes itself.
//! Schema routes check `eav_schemas`.
//! Rule routes check `eav_rules`.
//! Entity routes check `eav_entities`, or a row grant on `entity:{id}`.
//! The query route checks only row grants.
//! A row grant on `entity:{id}` also allows one entity operation.
//!
//! The module adds no actions and no business rules.
//! It exposes only the stores that the runtime already owns.

// The route macros generate route-builder structs without doc comments.
#![allow(missing_docs)]

use std::fmt;

use actix_web::{HttpResponse, delete, get, patch, post, web};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::eav::MAX_PAGE_OFFSET;
use crate::eav::entity::{AttributeValue, Entity, EntityPatch, WriteContext};
use crate::eav::entity_error::EntityError;
use crate::eav::error::SchemaError;
use crate::eav::runtime::EavRuntime;
use crate::eav::schema::{SchemaDef, SchemaDraft};
use crate::http::{
    ApiModule,
    error::ApiError,
    middleware::jwt::{Claims, JwtClaimsMiddleware, Validated},
};
use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, Authorizer, PolicyError};
use crate::rules::error::RuleError;
use crate::rules::rule::{Rule, RuleDraft};

/// The route prefix of this module.
const EAV_PREFIX: &str = "/eav";

/// The Casbin object for schema management.
const SCHEMAS: &str = "eav_schemas";
/// The Casbin object for entity management.
pub(crate) const ENTITIES: &str = "eav_entities";
/// The Casbin object for rule management.
const RULES: &str = "eav_rules";
/// The row type for one entity.
pub(crate) const ENTITY_ROW: &str = "entity";
/// The default page size of a list route.
const DEFAULT_PAGE_LIMIT: usize = 50;
/// The maximum page size of a list route.
const MAX_PAGE_LIMIT: usize = 200;
/// The default count of entities that a revalidation checks.
const DEFAULT_REVALIDATE_LIMIT: usize = 100;
/// The maximum count of entities that a revalidation checks.
const MAX_REVALIDATE_LIMIT: usize = 500;
/// The default count of entities that a migration checks.
const DEFAULT_MIGRATE_LIMIT: usize = 100;
/// The maximum count of entities that a migration checks.
const MAX_MIGRATE_LIMIT: usize = 500;

/// The API module that exposes the `/eav` routes.
///
/// The module requires JWT validation.
/// It then enforces a Casbin check on each route.
pub struct EavApiModule {
    runtime: EavRuntime,
    policy: Authorizer,
    jwt: JwtClaimsMiddleware<Claims>,
}

impl EavApiModule {
    /// Creates the module from a runtime, an authorizer, and JWT middleware.
    ///
    /// Share the authorizer with the policy engine.
    /// The module then sees the same policy state as every other module.
    pub fn new(runtime: EavRuntime, policy: Authorizer, jwt: JwtClaimsMiddleware<Claims>) -> Self {
        Self {
            runtime,
            policy,
            jwt,
        }
    }
}

impl ApiModule for EavApiModule {
    fn prefix(&self) -> &str {
        EAV_PREFIX
    }

    fn configure(&self, cfg: &mut web::ServiceConfig) {
        let runtime = web::Data::new(self.runtime.clone());
        let policy = web::Data::new(self.policy.clone());
        let jwt = self.jwt.clone();
        let scope = web::scope(EAV_PREFIX)
            .app_data(runtime)
            .app_data(policy)
            .wrap(jwt)
            .service(publish_schema)
            .service(list_schemas)
            .service(get_schema)
            .service(get_schema_version)
            .service(get_effective_schema)
            .service(list_schema_children)
            .service(diff_schema)
            .service(revalidate_schema)
            .service(migrate_schema)
            .service(create_entity)
            .service(list_entities)
            .service(query_entities)
            .service(get_entity)
            .service(patch_entity)
            .service(delete_entity)
            .service(list_schema_entities)
            .service(upsert_rule)
            .service(list_rules)
            .service(get_rule)
            .service(delete_rule)
            .service(set_rule_enabled)
            .service(crate::eav::sync::status)
            .service(crate::eav::sync::events)
            .service(crate::eav::sync::snapshot)
            .service(crate::eav::sync::build_replica)
            .service(crate::eav::sync::replica)
            .service(crate::eav::sync::reset_replica)
            .service(crate::eav::sync::replica_status);
        cfg.service(scope);
    }
}

/// The query of the entity delete route.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ExpectedVersionQuery {
    /// The version that the caller expects.
    pub expected_version: u64,
    /// True to delete the entity even when other entities reference it.
    #[serde(default)]
    pub force: bool,
}

/// The paging query of a list route.
///
/// The default limit is 50.
/// The maximum limit is 200.
/// A present `after` field selects cursor mode.
/// The offset cap is 1000.
/// Use `after` to page deeper than the cap.
/// `GET /eav/rules` supports offset paging only, so it rejects a cursor.
#[derive(Debug, Clone, Deserialize, utoipa::IntoParams)]
pub struct PageQuery {
    /// The page size. The default is 50. The maximum is 200.
    #[serde(default)]
    pub limit: Option<usize>,
    /// The number of items to skip. The default is 0.
    ///
    /// The maximum is 1000. Use `after` for a deeper page.
    /// This field applies only to offset mode.
    #[serde(default)]
    pub offset: Option<usize>,
    /// The id to resume after. The default is `None`.
    ///
    /// A present value selects cursor mode.
    /// An empty value starts at the first item.
    /// A non-empty value starts after that id.
    /// Omit the field to use offset paging.
    /// Do not combine it with a non-zero `offset`.
    /// `GET /eav/rules` rejects this field.
    #[serde(default)]
    pub after: Option<String>,
}

/// The paging mode of a list route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PageMode {
    /// Skip `offset` items and use `next_offset`.
    Offset(usize),
    /// Resume after an id and use `next`.
    ///
    /// `None` starts at the first item.
    Cursor(Option<String>),
}

impl PageQuery {
    /// Resolves the page size and the paging mode.
    ///
    /// An offset above the cap is invalid.
    /// Use `after` for a deeper page.
    /// A cursor with a non-zero offset is invalid.
    /// An empty cursor starts at the first item.
    pub(crate) fn resolve(self) -> Result<(usize, PageMode), EavApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        if limit == 0 || limit > MAX_PAGE_LIMIT {
            return Err(EavApiError::Invalid(Box::new(InvalidPageLimit)));
        }
        let offset = self.offset.unwrap_or(0);
        if offset > MAX_PAGE_OFFSET {
            return Err(EavApiError::Invalid(Box::new(InvalidPageOffset)));
        }
        let mode = match self.after {
            Some(after) => {
                if offset != 0 {
                    return Err(EavApiError::Invalid(Box::new(InvalidPageCursor)));
                }
                if after.is_empty() {
                    PageMode::Cursor(None)
                } else {
                    PageMode::Cursor(Some(after))
                }
            }
            None => PageMode::Offset(offset),
        };
        Ok((limit, mode))
    }
}

/// The query of the schema diff route.
#[derive(Debug, Clone, Copy, Deserialize, utoipa::IntoParams)]
pub struct SchemaDiffQuery {
    /// The source version.
    pub from: u64,
    /// The target version.
    pub to: u64,
}

/// The body of the schema revalidation route.
///
/// The default limit is 100.
/// The maximum limit is 500.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct RevalidateRequest {
    /// The target schema version.
    pub target_version: u64,
    /// The maximum number of entities to check. The default is 100. The maximum is 500.
    #[serde(default)]
    pub limit: Option<usize>,
    /// The entity id to resume after. Omit it for the first page.
    #[serde(default)]
    pub after: Option<String>,
}

impl RevalidateRequest {
    /// Resolves the limit and checks its range.
    fn resolve(self) -> Result<(u64, usize, Option<String>), EavApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_REVALIDATE_LIMIT);
        if limit == 0 || limit > MAX_REVALIDATE_LIMIT {
            return Err(EavApiError::Invalid(Box::new(InvalidRevalidateLimit)));
        }
        Ok((self.target_version, limit, self.after))
    }
}

/// The body of the schema migration route.
///
/// The default limit is 100.
/// The maximum limit is 500.
/// The default for `dry_run` is true.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct MigrateRequest {
    /// The target schema version.
    pub target_version: u64,
    /// The maximum number of entities to check. The default is 100. The maximum is 500.
    #[serde(default)]
    pub limit: Option<usize>,
    /// True to report the changes without a write. The default is true.
    ///
    /// A true value requires `read` on `eav_schemas` and `eav_entities`.
    /// A false value requires `write` on both objects.
    #[serde(default = "default_dry_run")]
    pub dry_run: bool,
    /// The entity id to resume after. Omit it for the first page.
    #[serde(default)]
    pub after: Option<String>,
}

/// The default value of the migration dry-run flag.
fn default_dry_run() -> bool {
    true
}

impl MigrateRequest {
    /// Resolves the limit and checks its range.
    fn resolve(self) -> Result<(u64, usize, Option<String>, bool), EavApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_MIGRATE_LIMIT);
        if limit == 0 || limit > MAX_MIGRATE_LIMIT {
            return Err(EavApiError::Invalid(Box::new(InvalidMigrateLimit)));
        }
        Ok((self.target_version, limit, self.after, self.dry_run))
    }
}

/// A page of schemas.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SchemaPage {
    /// The schemas on this page.
    pub items: Vec<SchemaDef>,
    /// `Some` means the page was full and a following page may exist.
    /// Fetch it and stop when the page is empty.
    pub next_offset: Option<usize>,
    /// The id to resume after for the next page.
    ///
    /// The value is `Some` only in cursor mode.
    /// The value is `None` when the scan is exhausted.
    pub next: Option<String>,
}

/// A page of entities.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct EntityPage {
    /// The entities on this page.
    pub items: Vec<Entity>,
    /// `Some` means the page was full and a following page may exist.
    /// Fetch it and stop when the page is empty.
    pub next_offset: Option<usize>,
    /// The id to resume after for the next page.
    ///
    /// The value is `Some` only in cursor mode.
    /// The value is `None` when the scan is exhausted.
    pub next: Option<String>,
}

/// A page of rules.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct RulePage {
    /// The rules on this page.
    pub items: Vec<Rule>,
    /// `Some` means the page was full and a following page may exist.
    /// Fetch it and stop when the page is empty.
    pub next_offset: Option<usize>,
}

/// The body of the entity query route.
///
/// The default limit is 50.
/// The maximum limit is 200.
/// An empty `after` string starts at the first page.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct EntityQueryRequest {
    /// The indexed attribute name.
    pub attribute: String,
    /// The exact attribute value.
    pub value: AttributeValue,
    /// The page size. The default is 50. The maximum is 200.
    #[serde(default)]
    pub limit: Option<usize>,
    /// The entity id to resume after. An empty string starts at the first page.
    #[serde(default)]
    pub after: Option<String>,
}

impl EntityQueryRequest {
    /// Resolves the page window and checks the limit.
    fn resolve(&self) -> Result<(usize, Option<String>), EavApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        if limit == 0 || limit > MAX_PAGE_LIMIT {
            return Err(EavApiError::Invalid(Box::new(InvalidPageLimit)));
        }
        let after = self.after.clone().filter(|cursor| !cursor.is_empty());
        Ok((limit, after))
    }
}

/// A page of entities that match an indexed attribute value.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct EntityQueryPage {
    /// The entities on this page.
    pub items: Vec<Entity>,
    /// The entity id to pass as `after` for the next page.
    /// `None` means that the scan is exhausted.
    pub next: Option<String>,
}

/// The source of a page limit outside the allowed range.
#[derive(Debug)]
struct InvalidPageLimit;

impl fmt::Display for InvalidPageLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("limit must be between 1 and 200")
    }
}

impl std::error::Error for InvalidPageLimit {}

/// The source of a page offset above the maximum.
#[derive(Debug)]
struct InvalidPageOffset;

impl fmt::Display for InvalidPageOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "offset must be at most {MAX_PAGE_OFFSET}. Use after to page deeper."
        )
    }
}

impl std::error::Error for InvalidPageOffset {}

/// The source of a cursor that comes with a non-zero offset.
#[derive(Debug)]
struct InvalidPageCursor;

impl fmt::Display for InvalidPageCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("after and offset cannot be combined")
    }
}

impl std::error::Error for InvalidPageCursor {}

/// The source of a cursor on the rule list.
#[derive(Debug)]
struct InvalidRuleCursor;

impl fmt::Display for InvalidRuleCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rule paging does not support a cursor")
    }
}

impl std::error::Error for InvalidRuleCursor {}

/// The source of a revalidation limit outside the allowed range.
#[derive(Debug)]
struct InvalidRevalidateLimit;

impl fmt::Display for InvalidRevalidateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("limit must be between 1 and 500")
    }
}

impl std::error::Error for InvalidRevalidateLimit {}

/// The source of a migration limit outside the allowed range.
#[derive(Debug)]
struct InvalidMigrateLimit;

impl fmt::Display for InvalidMigrateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("limit must be between 1 and 500")
    }
}

impl std::error::Error for InvalidMigrateLimit {}

/// Returns the next offset when the page is full.
///
/// The call returns `None` when the page is not full.
pub(crate) fn page_next_offset(offset: usize, len: usize, limit: usize) -> Option<usize> {
    (len == limit).then_some(offset.saturating_add(len))
}

/// The body of the entity patch route.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct EntityPatchRequest {
    /// The version that the caller expects.
    pub expected_version: u64,
    /// The attribute changes.
    pub patch: EntityPatch,
}

/// The body of the rule enabled route.
#[derive(Debug, Clone, Copy, Deserialize, utoipa::ToSchema)]
pub struct RuleEnabledRequest {
    /// True to enable the rule.
    pub enabled: bool,
}

/// The kind of a failure in the EAV API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The resource does not exist.
    NotFound,
    /// The request is not valid.
    Invalid,
    /// The request conflicts with the stored state.
    Conflict,
    /// The caller has no permission.
    Forbidden,
    /// The store or the server failed.
    Internal,
}

/// A failure of the EAV API.
///
/// The `Display` text is stable and sanitized.
/// The source holds the internal cause for the server log.
/// The response body is the shared [`ApiError`] envelope.
#[derive(Debug, Error)]
pub enum EavApiError {
    /// The resource does not exist. HTTP 404.
    #[error("not found")]
    NotFound(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The request is not valid. HTTP 400.
    #[error("invalid request")]
    Invalid(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// An attribute is not indexed. HTTP 400.
    #[error("attribute is not indexed")]
    NotIndexed,
    /// The request conflicts with the stored state. HTTP 409.
    #[error("conflict")]
    Conflict(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The caller has no permission. HTTP 403.
    #[error("forbidden")]
    Forbidden(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The store or the server failed. HTTP 500.
    #[error("internal server error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl EavApiError {
    /// Builds an error of one kind with its source.
    fn wrap(kind: Kind, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        let source = Box::new(source);
        match kind {
            Kind::NotFound => Self::NotFound(source),
            Kind::Invalid => Self::Invalid(source),
            Kind::Conflict => Self::Conflict(source),
            Kind::Forbidden => Self::Forbidden(source),
            Kind::Internal => Self::Internal(source),
        }
    }

    /// Builds a not-found error with no request text.
    fn not_found() -> Self {
        Self::NotFound(Box::new(MissingResource))
    }

    /// Returns the HTTP status of this error.
    fn status(&self) -> actix_web::http::StatusCode {
        use actix_web::http::StatusCode;
        match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Invalid(_) | Self::NotIndexed => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Returns the stable code of this error.
    fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "not_found",
            Self::Invalid(_) | Self::NotIndexed => "invalid_request",
            Self::Conflict(_) => "conflict",
            Self::Forbidden(_) => "forbidden",
            Self::Internal(_) => "internal_error",
        }
    }
}

impl actix_web::ResponseError for EavApiError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        self.status()
    }

    fn error_response(&self) -> HttpResponse {
        if let Some(cause) = std::error::Error::source(self) {
            tracing::warn!("EAV API {} {}: {cause}", self.status(), self);
        }
        ApiError::envelope(self.status(), &self.to_string(), Some(self.code()), None)
    }
}

impl From<SchemaError> for EavApiError {
    fn from(error: SchemaError) -> Self {
        let kind = match &error {
            SchemaError::NotFound(_) => Kind::NotFound,
            SchemaError::Invalid(_) | SchemaError::Cycle | SchemaError::TypeConflict(_) => {
                Kind::Invalid
            }
            SchemaError::Store(_) | SchemaError::Internal(_) => Kind::Internal,
        };
        Self::wrap(kind, error)
    }
}

impl From<EntityError> for EavApiError {
    fn from(error: EntityError) -> Self {
        let kind = match &error {
            EntityError::NotFound(_) | EntityError::UnknownSchema(_) => Kind::NotFound,
            EntityError::NotIndexed(_) => return Self::NotIndexed,
            EntityError::Invalid(_)
            | EntityError::UnknownAttribute(_)
            | EntityError::SchemaConflict(_)
            | EntityError::MissingRequired(_)
            | EntityError::TypeMismatch(_)
            | EntityError::DanglingRef(_, _) => Kind::Invalid,
            EntityError::UniqueViolation(_)
            | EntityError::VersionConflict
            | EntityError::AlreadyExists(_)
            | EntityError::Referenced { .. }
            | EntityError::StaleHead { .. } => Kind::Conflict,
            EntityError::Store(_) | EntityError::Internal(_) | EntityError::Feed(_) => {
                Kind::Internal
            }
        };
        Self::wrap(kind, error)
    }
}

impl From<RuleError> for EavApiError {
    fn from(error: RuleError) -> Self {
        let kind = match &error {
            RuleError::NotFound(_) => Kind::NotFound,
            RuleError::Invalid(_) | RuleError::ConditionDepth | RuleError::UnknownAction(_) => {
                Kind::Invalid
            }
            RuleError::Store(_)
            | RuleError::Serialization(_)
            | RuleError::Action(_)
            | RuleError::Wal(_)
            | RuleError::DuplicateAction(_) => Kind::Internal,
        };
        Self::wrap(kind, error)
    }
}

impl From<PolicyError> for EavApiError {
    fn from(error: PolicyError) -> Self {
        let kind = match &error {
            PolicyError::AccessDenied => Kind::Forbidden,
            _ => Kind::Internal,
        };
        Self::wrap(kind, error)
    }
}

/// The source of a not-found error that has no domain error.
#[derive(Debug)]
struct MissingResource;

impl fmt::Display for MissingResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("resource does not exist")
    }
}

impl std::error::Error for MissingResource {}

/// Checks one management object.
async fn require_management(
    policy: &Authorizer,
    sub: &str,
    object: &str,
    act: Action,
) -> Result<(), EavApiError> {
    policy.require(sub, object, act).await.map_err(Into::into)
}

/// Checks the row grant or the collection grant for one entity.
async fn require_entity(
    policy: &Authorizer,
    sub: &str,
    id: &str,
    act: Action,
) -> Result<(), EavApiError> {
    if policy
        .authorize_row(sub, ENTITY_ROW, id, act)
        .await
        .map_err(EavApiError::from)?
    {
        return Ok(());
    }
    require_management(policy, sub, ENTITIES, act).await
}

/// Returns true when the caller can read one entity.
pub(crate) async fn can_read_entity(
    policy: &Authorizer,
    sub: &str,
    id: &str,
) -> Result<bool, EavApiError> {
    if policy
        .authorize_row(sub, ENTITY_ROW, id, Action::Read)
        .await
        .map_err(EavApiError::from)?
    {
        return Ok(true);
    }
    policy
        .authorize(sub, ENTITIES, Action::Read)
        .await
        .map_err(Into::into)
}

#[utoipa::path(post, path = "/eav/schemas", tag = "eav", request_body = SchemaDraft, responses((status=201, body=crate::eav::schema::SchemaDef), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[post("/schemas")]
async fn publish_schema(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    body: web::Json<SchemaDraft>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, SCHEMAS, Action::Write).await?;
    let def = runtime.schemas().publish(body.into_inner()).await?;
    Ok(HttpResponse::Created().json(def))
}

#[utoipa::path(get, path = "/eav/schemas", tag = "eav", params(PageQuery), responses((status=200, body=SchemaPage), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/schemas")]
async fn list_schemas(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    query: web::Query<PageQuery>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, SCHEMAS, Action::Read).await?;
    let (limit, mode) = query.into_inner().resolve()?;
    match mode {
        PageMode::Cursor(after) => {
            let (items, next) = runtime
                .schemas()
                .list_after(limit, after.as_deref())
                .await?;
            Ok(HttpResponse::Ok().json(SchemaPage {
                items,
                next_offset: None,
                next,
            }))
        }
        PageMode::Offset(offset) => {
            let items = runtime.schemas().list_page(limit, offset).await?;
            let next_offset = page_next_offset(offset, items.len(), limit);
            Ok(HttpResponse::Ok().json(SchemaPage {
                items,
                next_offset,
                next: None,
            }))
        }
    }
}

#[utoipa::path(get, path = "/eav/schemas/{id}", tag = "eav", params(("id" = String, Path)), responses((status=200, body=crate::eav::schema::SchemaDef), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/schemas/{id}")]
async fn get_schema(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, SCHEMAS, Action::Read).await?;
    let id = path.into_inner();
    let def = runtime
        .schemas()
        .latest(&id)
        .await?
        .ok_or_else(EavApiError::not_found)?;
    Ok(HttpResponse::Ok().json(def))
}

#[utoipa::path(get, path = "/eav/schemas/{id}/versions/{version}", tag = "eav", params(("id" = String, Path), ("version" = u64, Path)), responses((status=200, body=crate::eav::schema::SchemaDef), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/schemas/{id}/versions/{version}")]
async fn get_schema_version(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<(String, u64)>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, SCHEMAS, Action::Read).await?;
    let (id, version) = path.into_inner();
    let def = runtime
        .schemas()
        .get(&id, version)
        .await?
        .ok_or_else(EavApiError::not_found)?;
    Ok(HttpResponse::Ok().json(def))
}

#[utoipa::path(get, path = "/eav/schemas/{id}/effective/{version}", tag = "eav", params(("id" = String, Path), ("version" = u64, Path)), responses((status=200, body=crate::eav::schema::EffectiveSchema), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/schemas/{id}/effective/{version}")]
async fn get_effective_schema(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<(String, u64)>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, SCHEMAS, Action::Read).await?;
    let (id, version) = path.into_inner();
    let schema = runtime
        .schemas()
        .effective(&id, version)
        .await?
        .ok_or_else(EavApiError::not_found)?;
    Ok(HttpResponse::Ok().json(schema))
}

#[utoipa::path(get, path = "/eav/schemas/{id}/children", tag = "eav", params(("id" = String, Path)), responses((status=200, body=Vec<String>), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/schemas/{id}/children")]
async fn list_schema_children(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, SCHEMAS, Action::Read).await?;
    let id = path.into_inner();
    let children = runtime.schemas().children(&id).await?;
    Ok(HttpResponse::Ok().json(children))
}

#[utoipa::path(get, path = "/eav/schemas/{id}/diff", tag = "eav", params(("id" = String, Path), SchemaDiffQuery), responses((status=200, body=crate::eav::schema::SchemaDiff), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/schemas/{id}/diff")]
async fn diff_schema(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    query: web::Query<SchemaDiffQuery>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, SCHEMAS, Action::Read).await?;
    require_management(&policy, &claims.sub, ENTITIES, Action::Read).await?;
    let id = path.into_inner();
    let query = query.into_inner();
    let diff = runtime
        .schemas()
        .diff(&id, query.from, query.to)
        .await?
        .ok_or_else(EavApiError::not_found)?;
    Ok(HttpResponse::Ok().json(diff))
}

#[utoipa::path(post, path = "/eav/schemas/{id}/revalidate", tag = "eav", params(("id" = String, Path)), request_body = RevalidateRequest, responses((status=200, body=crate::eav::entity::RevalidationReport), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[post("/schemas/{id}/revalidate")]
async fn revalidate_schema(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    body: web::Json<RevalidateRequest>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, SCHEMAS, Action::Read).await?;
    require_management(&policy, &claims.sub, ENTITIES, Action::Read).await?;
    let id = path.into_inner();
    let (target_version, limit, after) = body.into_inner().resolve()?;
    let report = runtime
        .entities()
        .revalidation_report(&id, target_version, limit, after.as_deref())
        .await?;
    Ok(HttpResponse::Ok().json(report))
}

/// Repins stored entities to a target schema version.
///
/// A dry run requires `read` on `eav_schemas` and `eav_entities`.
/// A real run requires `write` on both objects.
/// A real run writes the entities, so it also needs the write grant.
/// The default `dry_run` value is true.
#[utoipa::path(post, path = "/eav/schemas/{id}/migrate", tag = "eav", params(("id" = String, Path)), request_body = MigrateRequest, responses((status=200, body=crate::eav::entity::MigrationReport), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[post("/schemas/{id}/migrate")]
async fn migrate_schema(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    body: web::Json<MigrateRequest>,
) -> Result<HttpResponse, EavApiError> {
    let id = path.into_inner();
    let (target_version, limit, after, dry_run) = body.into_inner().resolve()?;
    let action = if dry_run { Action::Read } else { Action::Write };
    require_management(&policy, &claims.sub, SCHEMAS, action).await?;
    require_management(&policy, &claims.sub, ENTITIES, action).await?;
    let report = runtime
        .entities()
        .migrate_schema(
            &id,
            target_version,
            limit,
            after.as_deref(),
            dry_run,
            &WriteContext::new(claims.sub.clone()),
        )
        .await?;
    Ok(HttpResponse::Ok().json(report))
}

#[utoipa::path(post, path = "/eav/entities", tag = "eav", request_body = crate::eav::entity::EntityDraft, responses((status=201, body=crate::eav::entity::Entity), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=409, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[post("/entities")]
async fn create_entity(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    body: web::Json<crate::eav::entity::EntityDraft>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, ENTITIES, Action::Write).await?;
    let change = runtime
        .entities()
        .create(body.into_inner(), &WriteContext::new(claims.sub.clone()))
        .await?;
    let entity = change
        .after
        .ok_or_else(|| EavApiError::Internal(Box::new(MissingState)))?;
    Ok(HttpResponse::Created().json(entity))
}

/// Lists one page of every entity.
///
/// The caller needs `read` on `eav_entities`.
/// The handler then checks the row grant or the collection grant for each
/// entity.
/// It loads a raw page, filters the rows, and returns the visible items.
/// `next_offset` comes from the number of raw rows that the page consumed.
/// The next page can then contain fewer items than the limit.
/// A cursor query uses the entity marker family and returns `next`.
#[utoipa::path(get, path = "/eav/entities", tag = "eav", params(PageQuery), responses((status=200, body=EntityPage), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/entities")]
async fn list_entities(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    query: web::Query<PageQuery>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, ENTITIES, Action::Read).await?;
    let (limit, mode) = query.into_inner().resolve()?;
    match mode {
        PageMode::Cursor(after) => {
            let (raw, next) = runtime
                .entities()
                .list_after(limit, after.as_deref())
                .await?;
            let mut items = Vec::with_capacity(raw.len());
            for entity in raw {
                if can_read_entity(&policy, &claims.sub, &entity.id).await? {
                    items.push(entity);
                }
            }
            Ok(HttpResponse::Ok().json(EntityPage {
                items,
                next_offset: None,
                next,
            }))
        }
        PageMode::Offset(offset) => {
            let raw = runtime.entities().list_page(limit, offset).await?;
            let raw_len = raw.len();
            let mut items = Vec::with_capacity(raw_len);
            for entity in raw {
                if can_read_entity(&policy, &claims.sub, &entity.id).await? {
                    items.push(entity);
                }
            }
            let next_offset = page_next_offset(offset, raw_len, limit);
            Ok(HttpResponse::Ok().json(EntityPage {
                items,
                next_offset,
                next: None,
            }))
        }
    }
}

/// Queries one page of entities by an indexed attribute value.
///
/// The route needs no collection `read` on `eav_entities`.
/// A collection `read` on `eav_entities` exposes every entity.
/// A row grant exposes only that entity.
/// The handler filters each result with `can_read_entity`.
/// A caller with no grant receives an empty page, not `403`.
/// The response holds the next cursor when the page is full.
/// An attribute that no applied schema indexes returns `400`.
#[utoipa::path(post, path = "/eav/entities/query", tag = "eav", request_body = EntityQueryRequest, responses((status=200, body=EntityQueryPage), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[post("/entities/query")]
async fn query_entities(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    body: web::Json<EntityQueryRequest>,
) -> Result<HttpResponse, EavApiError> {
    let request = body.into_inner();
    let (limit, after) = request.resolve()?;
    let (entities, next) = runtime
        .entities()
        .list_by_attribute_after(&request.attribute, &request.value, limit, after.as_deref())
        .await?;
    let mut items = Vec::with_capacity(entities.len());
    for entity in entities {
        if can_read_entity(&policy, &claims.sub, &entity.id).await? {
            items.push(entity);
        }
    }
    Ok(HttpResponse::Ok().json(EntityQueryPage { items, next }))
}

#[utoipa::path(get, path = "/eav/entities/{id}", tag = "eav", params(("id" = String, Path)), responses((status=200, body=crate::eav::entity::Entity), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/entities/{id}")]
async fn get_entity(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, EavApiError> {
    let id = path.into_inner();
    require_entity(&policy, &claims.sub, &id, Action::Read).await?;
    let entity = runtime
        .entities()
        .get(&id)
        .await?
        .ok_or_else(EavApiError::not_found)?;
    Ok(HttpResponse::Ok().json(entity))
}

#[utoipa::path(patch, path = "/eav/entities/{id}", tag = "eav", params(("id" = String, Path)), request_body = EntityPatchRequest, responses((status=200, body=crate::eav::entity::Entity), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=409, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[patch("/entities/{id}")]
async fn patch_entity(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    body: web::Json<EntityPatchRequest>,
) -> Result<HttpResponse, EavApiError> {
    let id = path.into_inner();
    require_entity(&policy, &claims.sub, &id, Action::Write).await?;
    let body = body.into_inner();
    let change = runtime
        .entities()
        .update(
            &id,
            body.expected_version,
            body.patch,
            &WriteContext::new(claims.sub.clone()),
        )
        .await?;
    let entity = change
        .after
        .ok_or_else(|| EavApiError::Internal(Box::new(MissingState)))?;
    Ok(HttpResponse::Ok().json(entity))
}

#[utoipa::path(delete, path = "/eav/entities/{id}", tag = "eav", params(("id" = String, Path), ("expected_version" = u64, Query), ("force" = Option<bool>, Query, description = "Delete the entity even when other entities reference it")), responses((status=204, description="entity deleted"), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=409, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[delete("/entities/{id}")]
async fn delete_entity(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    query: web::Query<ExpectedVersionQuery>,
) -> Result<HttpResponse, EavApiError> {
    let id = path.into_inner();
    require_entity(&policy, &claims.sub, &id, Action::Delete).await?;
    runtime
        .entities()
        .delete(
            &id,
            query.expected_version,
            query.force,
            &WriteContext::new(claims.sub.clone()),
        )
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// Lists one page of the entities that pin a schema.
///
/// The caller needs `read` on `eav_entities`.
/// An unknown schema id returns `404` before the list call.
/// A known schema keeps the offset or cursor page behavior.
#[utoipa::path(get, path = "/eav/schemas/{id}/entities", tag = "eav", params(("id" = String, Path), PageQuery), responses((status=200, body=EntityPage), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/schemas/{id}/entities")]
async fn list_schema_entities(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    query: web::Query<PageQuery>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, ENTITIES, Action::Read).await?;
    let id = path.into_inner();
    if !runtime.schemas().exists(&id).await? {
        return Err(EavApiError::not_found());
    }
    let (limit, mode) = query.into_inner().resolve()?;
    match mode {
        PageMode::Cursor(after) => {
            let (raw, next) = runtime
                .entities()
                .list_by_schema_after(&id, limit, after.as_deref())
                .await?;
            let mut items = Vec::with_capacity(raw.len());
            for entity in raw {
                if can_read_entity(&policy, &claims.sub, &entity.id).await? {
                    items.push(entity);
                }
            }
            Ok(HttpResponse::Ok().json(EntityPage {
                items,
                next_offset: None,
                next,
            }))
        }
        PageMode::Offset(offset) => {
            let raw = runtime
                .entities()
                .list_by_schema_page(&id, limit, offset)
                .await?;
            let raw_len = raw.len();
            let mut items = Vec::with_capacity(raw_len);
            for entity in raw {
                if can_read_entity(&policy, &claims.sub, &entity.id).await? {
                    items.push(entity);
                }
            }
            let next_offset = page_next_offset(offset, raw_len, limit);
            Ok(HttpResponse::Ok().json(EntityPage {
                items,
                next_offset,
                next: None,
            }))
        }
    }
}

#[utoipa::path(post, path = "/eav/rules", tag = "eav", request_body = RuleDraft, responses((status=201, body=crate::rules::rule::Rule), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[post("/rules")]
async fn upsert_rule(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    body: web::Json<RuleDraft>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, RULES, Action::Write).await?;
    let draft = body.into_inner();
    runtime
        .engine()
        .validate_action(&draft.action.kind, &draft.action.params)?;
    let rule = runtime.rules().upsert(draft).await?;
    Ok(HttpResponse::Created().json(rule))
}

/// Lists one page of rules.
///
/// The route supports offset paging only.
/// A cursor in `after` returns `400`.
/// The caller needs `read` on `eav_rules`.
#[utoipa::path(get, path = "/eav/rules", tag = "eav", params(PageQuery), responses((status=200, body=RulePage), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/rules")]
async fn list_rules(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    query: web::Query<PageQuery>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, RULES, Action::Read).await?;
    let (limit, mode) = query.into_inner().resolve()?;
    let offset = match mode {
        PageMode::Offset(offset) => offset,
        PageMode::Cursor(_) => return Err(EavApiError::Invalid(Box::new(InvalidRuleCursor))),
    };
    let items = runtime.rules().list_page(limit, offset).await?;
    let next_offset = page_next_offset(offset, items.len(), limit);
    Ok(HttpResponse::Ok().json(RulePage { items, next_offset }))
}

#[utoipa::path(get, path = "/eav/rules/{id}", tag = "eav", params(("id" = String, Path)), responses((status=200, body=crate::rules::rule::Rule), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/rules/{id}")]
async fn get_rule(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, RULES, Action::Read).await?;
    let id = path.into_inner();
    let rule = runtime
        .rules()
        .get(&id)
        .await?
        .ok_or_else(EavApiError::not_found)?;
    Ok(HttpResponse::Ok().json(rule))
}

#[utoipa::path(delete, path = "/eav/rules/{id}", tag = "eav", params(("id" = String, Path)), responses((status=204, description="rule deleted"), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[delete("/rules/{id}")]
async fn delete_rule(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, RULES, Action::Delete).await?;
    let id = path.into_inner();
    if !runtime.rules().delete(&id).await? {
        return Err(EavApiError::not_found());
    }
    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(post, path = "/eav/rules/{id}/enabled", tag = "eav", params(("id" = String, Path)), request_body = RuleEnabledRequest, responses((status=200, body=crate::rules::rule::Rule), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[post("/rules/{id}/enabled")]
async fn set_rule_enabled(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    path: web::Path<String>,
    body: web::Json<RuleEnabledRequest>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, RULES, Action::Write).await?;
    let id = path.into_inner();
    let rule = runtime.rules().set_enabled(&id, body.enabled).await?;
    Ok(HttpResponse::Ok().json(rule))
}

/// The source of an impossible missing state.
#[derive(Debug)]
struct MissingState;

impl fmt::Display for MissingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("entity change has no state")
    }
}

impl std::error::Error for MissingState {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{App, http, test as actix_test};
    use jsonwebtoken::EncodingKey;
    use serde_json::{Value, json};
    use utoipa::OpenApi as _;

    use super::*;
    use crate::db::{build_s3_store, build_test_store, test_prefix};
    use crate::docs::ApiDoc;
    use crate::eav::entity::{AttributeValue, EntityDraft};
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft};
    use crate::fs::s3::{S3Backend, S3ClientConfig};
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::policy::PolicyEngine;
    use crate::rules::action::{ActionContext, RuleAction};
    use crate::rules::webhook::WebhookAction;
    use crate::sync::wal::Wal;

    const KID: &str = "eav-route-test-kid";
    const AUD: &str = "test-aud";

    /// The routes that the module mounts.
    const ROUTES: &[&str] = &[
        "/eav/schemas",
        "/eav/schemas/{id}",
        "/eav/schemas/{id}/versions/{version}",
        "/eav/schemas/{id}/effective/{version}",
        "/eav/schemas/{id}/children",
        "/eav/schemas/{id}/diff",
        "/eav/schemas/{id}/revalidate",
        "/eav/schemas/{id}/migrate",
        "/eav/schemas/{id}/entities",
        "/eav/entities",
        "/eav/entities/query",
        "/eav/entities/{id}",
        "/eav/rules",
        "/eav/rules/{id}",
        "/eav/rules/{id}/enabled",
        "/eav/sync/status",
        "/eav/sync/events",
        "/eav/sync/snapshot",
        "/eav/sync/replica",
        "/eav/sync/replica/status",
    ];

    /// The list routes that read [`PageQuery`].
    const PAGED_ROUTES: &[&str] = &[
        "/eav/entities",
        "/eav/schemas",
        "/eav/schemas/task/entities",
        "/eav/sync/snapshot",
        "/eav/rules",
    ];

    /// The list routes that accept an `after` cursor.
    const CURSOR_ROUTES: &[&str] = &[
        "/eav/entities",
        "/eav/schemas",
        "/eav/schemas/task/entities",
        "/eav/sync/snapshot",
    ];

    /// A no-op action for the route tests.
    struct NoopAction;

    #[async_trait::async_trait]
    impl RuleAction for NoopAction {
        fn kind(&self) -> &str {
            "record"
        }

        async fn execute(&self, _ctx: ActionContext) -> Result<(), anyhow::Error> {
            Ok(())
        }
    }

    struct Fixture {
        server: wiremock::MockServer,
        encoding_key: EncodingKey,
        runtime: EavRuntime,
        engine: PolicyEngine,
    }

    impl Fixture {
        fn issuer(&self) -> String {
            self.server.uri()
        }

        fn token(&self, sub: &str) -> anyhow::Result<String> {
            sign_rs256(
                &json!({
                    "sub": sub,
                    "iss": self.issuer(),
                    "aud": AUD,
                    "exp": 2000000000u64,
                }),
                KID,
                &self.encoding_key,
            )
        }

        async fn module(&self) -> anyhow::Result<EavApiModule> {
            let middleware = JwtClaimsMiddleware::<Claims>::new_with_jks(
                &format!("{}/jwks", self.server.uri()),
                AUD,
                &self.issuer(),
            )
            .await?;
            Ok(EavApiModule::new(
                self.runtime.clone(),
                self.engine.authorizer(),
                middleware,
            ))
        }
    }

    async fn fixture() -> anyhow::Result<Fixture> {
        let (key, encoding_key) = rsa_key(KID)?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;
        let s3 = S3ClientConfig {
            bucket: "eav-route-test".to_string(),
            region: "us-east-1".to_string(),
            endpoint_url: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
            backend: S3Backend::Memory,
        };
        let prefix = test_prefix("eav-route");
        let wal = Wal::new(build_s3_store(&s3, &format!("{prefix}/wal")).await?);
        let runtime = EavRuntime::build(
            &s3,
            &prefix,
            wal,
            vec![
                Arc::new(NoopAction),
                Arc::new(
                    WebhookAction::new(vec![server.address().to_string()])
                        .allow_private_hosts(true),
                ),
            ],
            true,
            8,
        )
        .await?;
        let engine =
            PolicyEngine::init_s3(build_test_store(&test_prefix("eav-route-policy")).await).await?;
        Ok(Fixture {
            server,
            encoding_key,
            runtime,
            engine,
        })
    }

    fn auth(req: actix_test::TestRequest, token: &str) -> actix_test::TestRequest {
        req.insert_header(("Cookie", format!("auth_token={token}")))
    }

    fn schema_body() -> Value {
        json!({
            "id": "invoice",
            "extends": [],
            "attributes": {
                "total": {
                    "name": "total",
                    "ty": "integer"
                }
            }
        })
    }

    fn entity_body() -> Value {
        json!({
            "id": "e1",
            "schemas": ["invoice"],
            "attributes": {
                "total": {"type": "integer", "value": 10}
            }
        })
    }

    fn rule_body_with_action(kind: &str) -> Value {
        json!({
            "id": "alpha",
            "name": "alpha",
            "enabled": true,
            "priority": 0,
            "trigger": {
                "events": ["Created"],
                "schemas": ["invoice"]
            },
            "condition": "Always",
            "action": {"kind": kind, "params": {}}
        })
    }

    fn rule_body() -> Value {
        rule_body_with_action("record")
    }

    fn rule_body_with_params(kind: &str, params: Value) -> Value {
        let mut body = rule_body_with_action(kind);
        body["action"]["params"] = params;
        body
    }

    async fn publish_task_schema(fx: &Fixture) -> anyhow::Result<()> {
        fx.runtime
            .schemas()
            .publish(SchemaDraft {
                id: "task".to_string(),
                extends: Vec::new(),
                attributes: Default::default(),
            })
            .await?;
        Ok(())
    }

    async fn create_task(fx: &Fixture, id: &str) -> anyhow::Result<()> {
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: id.to_string(),
                    schemas: vec!["task".to_string()],
                    attributes: Default::default(),
                },
                &WriteContext::new("alice"),
            )
            .await?;
        Ok(())
    }

    async fn publish_indexed_tag_schema(fx: &Fixture) -> anyhow::Result<()> {
        publish_schema_version(fx, "task", vec![indexed_attr("tag", AttributeType::String)]).await
    }

    async fn create_tagged_task(fx: &Fixture, id: &str, tag: &str) -> anyhow::Result<()> {
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: id.to_string(),
                    schemas: vec!["task".to_string()],
                    attributes: [("tag".to_string(), AttributeValue::String(tag.to_string()))]
                        .into_iter()
                        .collect(),
                },
                &WriteContext::new("alice"),
            )
            .await?;
        Ok(())
    }

    fn attr(name: &str, ty: AttributeType) -> AttributeDef {
        AttributeDef {
            name: name.to_string(),
            ty,
            required: false,
            indexed: false,
            unique: false,
            default: None,
        }
    }

    fn indexed_attr(name: &str, ty: AttributeType) -> AttributeDef {
        AttributeDef {
            indexed: true,
            ..attr(name, ty)
        }
    }

    fn required_attr(name: &str, ty: AttributeType) -> AttributeDef {
        AttributeDef {
            required: true,
            ..attr(name, ty)
        }
    }

    async fn publish_schema_version(
        fx: &Fixture,
        id: &str,
        attrs: Vec<AttributeDef>,
    ) -> anyhow::Result<()> {
        fx.runtime
            .schemas()
            .publish(SchemaDraft {
                id: id.to_string(),
                extends: Vec::new(),
                attributes: attrs.into_iter().map(|a| (a.name.clone(), a)).collect(),
            })
            .await?;
        Ok(())
    }

    #[test]
    fn error_status_and_code_mapping() {
        for (error, status, code) in [
            (
                EavApiError::from(SchemaError::NotFound("x".into())),
                404,
                "not_found",
            ),
            (
                EavApiError::from(SchemaError::Invalid("x".into())),
                400,
                "invalid_request",
            ),
            (
                EavApiError::from(SchemaError::TypeConflict("x".into())),
                400,
                "invalid_request",
            ),
            (
                EavApiError::from(EntityError::UnknownSchema("x".into())),
                404,
                "not_found",
            ),
            (
                EavApiError::from(EntityError::TypeMismatch("x".into())),
                400,
                "invalid_request",
            ),
            (
                EavApiError::from(EntityError::NotIndexed("x".into())),
                400,
                "invalid_request",
            ),
            (
                EavApiError::from(EntityError::VersionConflict),
                409,
                "conflict",
            ),
            (
                EavApiError::from(EntityError::UniqueViolation("x".into())),
                409,
                "conflict",
            ),
            (
                EavApiError::from(EntityError::AlreadyExists("x".into())),
                409,
                "conflict",
            ),
            (
                EavApiError::from(EntityError::Referenced {
                    id: "x".into(),
                    count: 1,
                }),
                409,
                "conflict",
            ),
            (
                EavApiError::from(RuleError::NotFound("x".into())),
                404,
                "not_found",
            ),
            (
                EavApiError::from(RuleError::ConditionDepth),
                400,
                "invalid_request",
            ),
            (
                EavApiError::from(PolicyError::AccessDenied),
                403,
                "forbidden",
            ),
            (
                EavApiError::from(EntityError::Feed("x".into())),
                500,
                "internal_error",
            ),
            (
                EavApiError::from(RuleError::Wal("x".into())),
                500,
                "internal_error",
            ),
        ] {
            assert_eq!(error.status().as_u16(), status, "{error:?}");
            assert_eq!(error.code(), code, "{error:?}");
        }
    }

    #[test]
    fn error_body_never_contains_the_cause() {
        use actix_web::ResponseError as _;
        use actix_web::body::MessageBody as _;

        let error = EavApiError::from(SchemaError::Invalid("secret key text".into()));
        let body = error.error_response();
        let bytes = body.into_body().try_into_bytes().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("secret key text"), "{text}");
        assert!(text.contains("invalid request"), "{text}");
    }

    #[test]
    fn paging_errors_have_stable_messages() {
        assert_eq!(
            InvalidPageOffset.to_string(),
            "offset must be at most 1000. Use after to page deeper."
        );
        assert_eq!(
            InvalidRuleCursor.to_string(),
            "rule paging does not support a cursor"
        );
    }

    #[test]
    fn page_query_accepts_the_maximum_offset() {
        let query = PageQuery {
            limit: None,
            offset: Some(MAX_PAGE_OFFSET),
            after: None,
        };

        let (limit, mode) = query.resolve().unwrap();

        assert_eq!(limit, DEFAULT_PAGE_LIMIT);
        assert_eq!(mode, PageMode::Offset(MAX_PAGE_OFFSET));
    }

    #[test]
    fn page_query_rejects_an_offset_above_the_maximum() {
        let query = PageQuery {
            limit: None,
            offset: Some(MAX_PAGE_OFFSET + 1),
            after: None,
        };

        let error = query.resolve().unwrap_err();

        assert!(matches!(error, EavApiError::Invalid(_)));
        let cause = std::error::Error::source(&error)
            .expect("the error has a source")
            .to_string();
        assert_eq!(cause, InvalidPageOffset.to_string());
    }

    #[actix_web::test]
    async fn module_prefix_and_openapi_cover_every_route() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = fx.module().await?;
        assert_eq!(module.prefix(), "/eav");

        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");
        let paths = spec["paths"].as_object().expect("paths object");
        for route in ROUTES {
            assert!(paths.contains_key(*route), "spec missing {route}");
        }
        assert!(
            paths["/eav/entities"]["get"].is_object(),
            "spec missing GET /eav/entities"
        );
        assert!(
            spec["tags"]
                .as_array()
                .expect("tags")
                .iter()
                .any(|tag| tag["name"] == "eav"),
            "the spec has no eav tag"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn unauthenticated_request_is_401() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = actix_test::call_service(
            &app,
            actix_test::TestRequest::get()
                .uri("/eav/schemas")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[actix_web::test]
    async fn subject_without_rules_is_403() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/schemas"),
                &fx.token("bob")?,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);
        Ok(())
    }

    #[actix_web::test]
    async fn superadmin_crud_over_http() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas")
                    .set_json(schema_body()),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);
        let schema: Value = actix_test::read_body_json(res).await;
        assert_eq!(schema["version"], 1);

        let res = actix_test::call_service(
            &app,
            auth(actix_test::TestRequest::get().uri("/eav/schemas"), &token).to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let schemas: Value = actix_test::read_body_json(res).await;
        assert_eq!(schemas["items"].as_array().map(Vec::len), Some(1));
        assert!(schemas["next_offset"].is_null());

        for uri in [
            "/eav/schemas/invoice",
            "/eav/schemas/invoice/versions/1",
            "/eav/schemas/invoice/effective/1",
            "/eav/schemas/invoice/children",
        ] {
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
        }

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/entities")
                    .set_json(entity_body()),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);
        let entity: Value = actix_test::read_body_json(res).await;
        assert_eq!(entity["version"], 1);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/entities/e1"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::patch()
                    .uri("/eav/entities/e1")
                    .set_json(json!({
                        "expected_version": 1,
                        "patch": {
                            "attributes": {
                                "total": {"type": "integer", "value": 20}
                            }
                        }
                    })),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let entity: Value = actix_test::read_body_json(res).await;
        assert_eq!(entity["version"], 2);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/schemas/invoice/entities"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let entities: Value = actix_test::read_body_json(res).await;
        assert_eq!(entities["items"].as_array().map(Vec::len), Some(1));
        assert!(entities["next_offset"].is_null());

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::delete().uri("/eav/entities/e1?expected_version=2"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/rules")
                    .set_json(rule_body()),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);
        let rule: Value = actix_test::read_body_json(res).await;
        assert_eq!(rule["version"], 1);

        let res = actix_test::call_service(
            &app,
            auth(actix_test::TestRequest::get().uri("/eav/rules"), &token).to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let rules: Value = actix_test::read_body_json(res).await;
        assert_eq!(rules["items"].as_array().map(Vec::len), Some(1));
        assert!(rules["next_offset"].is_null());

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/rules/alpha"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/rules/alpha/enabled")
                    .set_json(json!({"enabled": false})),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let rule: Value = actix_test::read_body_json(res).await;
        assert_eq!(rule["enabled"], false);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::delete().uri("/eav/rules/alpha"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        Ok(())
    }

    #[actix_web::test]
    async fn global_entity_list_returns_page_envelopes() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_task(&fx, id).await?;
        }
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/entities?limit=2&offset=0"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let page: Value = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = page["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec!["e1", "e2"]);
        assert_eq!(page["next_offset"], 2);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/entities?limit=2&offset=2"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let page: Value = actix_test::read_body_json(res).await;
        assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
        assert!(page["next_offset"].is_null());

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/entities?offset=99"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let page: Value = actix_test::read_body_json(res).await;
        assert_eq!(page["items"].as_array().map(Vec::len), Some(0));
        assert!(page["next_offset"].is_null());
        Ok(())
    }

    #[actix_web::test]
    async fn the_entity_list_pages_with_an_after_cursor() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_task(&fx, id).await?;
        }
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let mut ids = Vec::new();
        let mut after = Some(String::new());
        let mut first = true;
        loop {
            let uri = match &after {
                Some(cursor) => format!("/eav/entities?limit=2&after={cursor}"),
                None => "/eav/entities?limit=2".to_string(),
            };
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(&uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let page: Value = actix_test::read_body_json(res).await;
            assert!(page["next_offset"].is_null(), "{uri}");
            let page_ids: Vec<&str> = page["items"]
                .as_array()
                .expect("items")
                .iter()
                .map(|item| item["id"].as_str().expect("id"))
                .collect();
            if first {
                assert_eq!(page_ids, vec!["e1", "e2"], "{uri}");
                assert_eq!(page["next"], "e2", "{uri}");
                first = false;
            }
            ids.extend(page_ids.iter().map(|id| id.to_string()));
            match page["next"].as_str() {
                Some(cursor) => after = Some(cursor.to_string()),
                None => break,
            }
        }

        assert_eq!(ids, vec!["e1", "e2", "e3"]);
        Ok(())
    }

    #[actix_web::test]
    async fn entity_query_returns_matching_entities() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_indexed_tag_schema(&fx).await?;
        create_tagged_task(&fx, "e1", "alpha").await?;
        create_tagged_task(&fx, "e2", "alpha").await?;
        create_tagged_task(&fx, "e3", "beta").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/entities/query")
                    .set_json(json!({
                        "attribute": "tag",
                        "value": {"type": "string", "value": "alpha"}
                    })),
                &fx.token("alice")?,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let page: Value = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = page["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec!["e1", "e2"]);
        assert!(page["next"].is_null());
        Ok(())
    }

    #[actix_web::test]
    async fn entity_query_pages_with_the_after_cursor() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_indexed_tag_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_tagged_task(&fx, id, "alpha").await?;
        }
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/entities/query")
                    .set_json(json!({
                        "attribute": "tag",
                        "value": {"type": "string", "value": "alpha"},
                        "limit": 2,
                        "after": ""
                    })),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let page: Value = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = page["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec!["e1", "e2"]);
        assert_eq!(page["next"], "e2");

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/entities/query")
                    .set_json(json!({
                        "attribute": "tag",
                        "value": {"type": "string", "value": "alpha"},
                        "limit": 2,
                        "after": "e2"
                    })),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let page: Value = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = page["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec!["e3"]);
        assert!(page["next"].is_null());
        Ok(())
    }

    #[actix_web::test]
    async fn the_schema_list_pages_with_an_after_cursor() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        for id in ["alpha", "beta", "gamma"] {
            fx.runtime
                .schemas()
                .publish(SchemaDraft {
                    id: id.to_string(),
                    extends: Vec::new(),
                    attributes: Default::default(),
                })
                .await?;
        }
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let mut ids = Vec::new();
        let mut after = Some(String::new());
        let mut first = true;
        loop {
            let uri = match &after {
                Some(cursor) => format!("/eav/schemas?limit=1&after={cursor}"),
                None => "/eav/schemas?limit=1".to_string(),
            };
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(&uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let page: Value = actix_test::read_body_json(res).await;
            assert!(page["next_offset"].is_null(), "{uri}");
            let page_ids: Vec<&str> = page["items"]
                .as_array()
                .expect("items")
                .iter()
                .map(|item| item["id"].as_str().expect("id"))
                .collect();
            if first {
                assert_eq!(page_ids, vec!["alpha"], "{uri}");
                assert_eq!(page["next"], "alpha", "{uri}");
                first = false;
            }
            ids.extend(page_ids.iter().map(|id| id.to_string()));
            match page["next"].as_str() {
                Some(cursor) => after = Some(cursor.to_string()),
                None => break,
            }
        }

        assert_eq!(ids, vec!["alpha", "beta", "gamma"]);
        Ok(())
    }

    #[actix_web::test]
    async fn entity_query_rejects_an_attribute_that_is_not_indexed() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "task", vec![attr("tag", AttributeType::String)]).await?;
        create_tagged_task(&fx, "e1", "secret").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/entities/query")
                    .set_json(json!({
                        "attribute": "tag",
                        "value": {"type": "string", "value": "secret"}
                    })),
                &fx.token("alice")?,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("invalid_request"));
        assert_eq!(body.error, "attribute is not indexed");
        assert!(!body.error.contains("secret"), "{}", body.error);
        Ok(())
    }

    #[actix_web::test]
    async fn an_after_cursor_with_a_non_zero_offset_is_400() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for uri in [
            "/eav/entities?after=e1&offset=1",
            "/eav/schemas?after=alpha&offset=1",
            "/eav/sync/snapshot?after=e1&offset=1",
        ] {
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::BAD_REQUEST, "{uri}");
            let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
            assert_eq!(body.code.as_deref(), Some("invalid_request"), "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn entity_query_applies_a_row_grant() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_indexed_tag_schema(&fx).await?;
        create_tagged_task(&fx, "e1", "alpha").await?;
        create_tagged_task(&fx, "e2", "alpha").await?;
        fx.engine
            .assign_group("carol".into(), "row-readers".into())
            .await?;
        fx.engine
            .add_rule("row-readers".into(), "entity:e1".into(), Action::Read)
            .await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/entities/query")
                    .set_json(json!({
                        "attribute": "tag",
                        "value": {"type": "string", "value": "alpha"}
                    })),
                &fx.token("carol")?,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let page: Value = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = page["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec!["e1"]);
        Ok(())
    }

    #[actix_web::test]
    async fn an_invalid_page_limit_is_400() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for uri in ["/eav/schemas?limit=0", "/eav/schemas?limit=201"] {
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::BAD_REQUEST, "{uri}");
            let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
            assert_eq!(body.code.as_deref(), Some("invalid_request"), "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn an_offset_at_the_maximum_returns_an_empty_page() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_task_schema(&fx).await?;
        create_task(&fx, "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for route in PAGED_ROUTES {
            let uri = format!("{route}?offset={MAX_PAGE_OFFSET}");
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(&uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let page: Value = actix_test::read_body_json(res).await;
            assert_eq!(page["items"].as_array().map(Vec::len), Some(0), "{uri}");
            assert!(page["next_offset"].is_null(), "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn an_offset_above_the_maximum_is_400_on_every_list_route() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_task_schema(&fx).await?;
        create_task(&fx, "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for route in PAGED_ROUTES {
            let uri = format!("{route}?offset={}", MAX_PAGE_OFFSET + 1);
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(&uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::BAD_REQUEST, "{uri}");
            let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
            assert_eq!(body.code.as_deref(), Some("invalid_request"), "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn a_usize_max_offset_is_400_on_every_list_route() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_task_schema(&fx).await?;
        create_task(&fx, "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for route in PAGED_ROUTES {
            let uri = format!("{route}?offset={}", usize::MAX);
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(&uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::BAD_REQUEST, "{uri}");
            let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
            assert_eq!(body.code.as_deref(), Some("invalid_request"), "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn after_still_pages_the_four_cursor_routes() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_task_schema(&fx).await?;
        fx.runtime
            .schemas()
            .publish(SchemaDraft {
                id: "other".to_string(),
                extends: Vec::new(),
                attributes: Default::default(),
            })
            .await?;
        create_task(&fx, "e1").await?;
        create_task(&fx, "e2").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for route in CURSOR_ROUTES {
            let uri = format!("{route}?limit=1&after=");
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(&uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let page: Value = actix_test::read_body_json(res).await;
            assert!(page["next_offset"].is_null(), "{uri}");
            assert_eq!(page["items"].as_array().map(Vec::len), Some(1), "{uri}");
            let cursor = page["next"]
                .as_str()
                .unwrap_or_else(|| panic!("{uri} has no next cursor"))
                .to_string();

            let uri = format!("{route}?limit=1&after={cursor}");
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(&uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let page: Value = actix_test::read_body_json(res).await;
            assert!(page["next_offset"].is_null(), "{uri}");
            assert!(page["items"].is_array(), "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn a_rule_cursor_is_400_and_returns_no_page() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/rules")
                    .set_json(rule_body()),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);

        for uri in ["/eav/rules?after=", "/eav/rules?after=alpha"] {
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::BAD_REQUEST, "{uri}");
            let body: Value = actix_test::read_body_json(res).await;
            assert_eq!(body["code"], "invalid_request", "{uri}");
            assert!(body["items"].is_null(), "{uri} returned a page");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn a_legacy_offset_below_the_cap_pages_every_list_route() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_task_schema(&fx).await?;
        fx.runtime
            .schemas()
            .publish(SchemaDraft {
                id: "extra".to_string(),
                extends: Vec::new(),
                attributes: Default::default(),
            })
            .await?;
        create_task(&fx, "e1").await?;
        create_task(&fx, "e2").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for id in ["alpha", "beta"] {
            let mut rule = rule_body();
            rule["id"] = json!(id);
            rule["name"] = json!(id);
            let res = actix_test::call_service(
                &app,
                auth(
                    actix_test::TestRequest::post()
                        .uri("/eav/rules")
                        .set_json(rule),
                    &token,
                )
                .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::CREATED, "{id}");
        }

        for (uri, expected) in [
            ("/eav/entities?limit=1&offset=1", "e2"),
            ("/eav/schemas?limit=1&offset=1", "task"),
            ("/eav/schemas/task/entities?limit=1&offset=1", "e2"),
            ("/eav/sync/snapshot?limit=1&offset=1", "e2"),
            ("/eav/rules?limit=1&offset=1", "beta"),
        ] {
            let res = actix_test::call_service(
                &app,
                auth(actix_test::TestRequest::get().uri(uri), &token).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let page: Value = actix_test::read_body_json(res).await;
            assert_eq!(page["items"][0]["id"], expected, "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn can_read_entity_allows_a_row_grant_or_a_collection_grant() -> anyhow::Result<()> {
        let fx = fixture().await?;
        fx.engine
            .assign_group("carol".into(), "row-readers".into())
            .await?;
        fx.engine
            .add_rule("row-readers".into(), "entity:e1".into(), Action::Read)
            .await?;
        fx.engine
            .assign_group("dave".into(), "collection-readers".into())
            .await?;
        fx.engine
            .add_rule(
                "collection-readers".into(),
                "eav_entities".into(),
                Action::Read,
            )
            .await?;

        let auth = fx.engine.authorizer();
        assert!(can_read_entity(&auth, "carol", "e1").await?);
        assert!(!can_read_entity(&auth, "carol", "e2").await?);
        assert!(can_read_entity(&auth, "dave", "e1").await?);
        assert!(can_read_entity(&auth, "dave", "e2").await?);
        Ok(())
    }

    #[actix_web::test]
    async fn unknown_rule_action_is_400_and_record_succeeds() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/rules")
                    .set_json(rule_body_with_action("ghost")),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("invalid_request"));
        assert!(!body.error.contains("ghost"), "{}", body.error);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/rules")
                    .set_json(rule_body()),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);
        Ok(())
    }

    #[actix_web::test]
    async fn webhook_rule_checks_the_allowlist() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/rules")
                    .set_json(rule_body_with_params(
                        "webhook",
                        json!({"url": "https://example.com/hook"}),
                    )),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("invalid_request"));
        assert!(!body.error.contains("example.com"), "{}", body.error);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/rules")
                    .set_json(rule_body_with_params(
                        "webhook",
                        json!({"url": format!("{}/hook", fx.server.uri())}),
                    )),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);
        Ok(())
    }

    #[actix_web::test]
    async fn a_row_grant_reads_one_entity() -> anyhow::Result<()> {
        let fx = fixture().await?;
        fx.runtime
            .schemas()
            .publish(crate::eav::schema::SchemaDraft {
                id: "invoice".to_string(),
                extends: Vec::new(),
                attributes: [(
                    "total".to_string(),
                    AttributeDef {
                        name: "total".to_string(),
                        ty: AttributeType::Integer,
                        required: false,
                        indexed: false,
                        unique: false,
                        default: None,
                    },
                )]
                .into_iter()
                .collect(),
            })
            .await?;
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: "e1".to_string(),
                    schemas: vec!["invoice".to_string()],
                    attributes: [("total".to_string(), AttributeValue::Integer(10))]
                        .into_iter()
                        .collect(),
                },
                &WriteContext::new("alice"),
            )
            .await?;

        fx.engine
            .assign_group("carol".into(), "row-readers".into())
            .await?;
        fx.engine
            .add_rule("row-readers".into(), "entity:e1".into(), Action::Read)
            .await?;

        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/entities/e1"),
                &fx.token("carol")?,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/entities/e1"),
                &fx.token("bob")?,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);
        Ok(())
    }

    #[actix_web::test]
    async fn missing_and_conflicting_requests_are_mapped() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/schemas/ghost"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas")
                    .set_json(schema_body()),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/entities")
                    .set_json(entity_body()),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/entities")
                    .set_json(entity_body()),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CONFLICT);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::patch()
                    .uri("/eav/entities/e1")
                    .set_json(json!({
                        "expected_version": 99,
                        "patch": {
                            "attributes": {
                                "total": {"type": "integer", "value": 20}
                            }
                        }
                    })),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CONFLICT);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::delete().uri("/eav/rules/ghost"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        Ok(())
    }

    #[actix_web::test]
    async fn delete_entity_reports_a_reference_and_accepts_force() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "customer", vec![attr("name", AttributeType::String)]).await?;
        publish_schema_version(
            &fx,
            "order",
            vec![attr("customer", AttributeType::EntityRef)],
        )
        .await?;
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: "c1".to_string(),
                    schemas: vec!["customer".to_string()],
                    attributes: [("name".to_string(), AttributeValue::String("c1".to_string()))]
                        .into_iter()
                        .collect(),
                },
                &WriteContext::new("alice"),
            )
            .await?;
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: "o1".to_string(),
                    schemas: vec!["order".to_string()],
                    attributes: [(
                        "customer".to_string(),
                        AttributeValue::EntityRef("c1".to_string()),
                    )]
                    .into_iter()
                    .collect(),
                },
                &WriteContext::new("alice"),
            )
            .await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::delete().uri("/eav/entities/c1?expected_version=1"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CONFLICT);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["code"], "conflict");

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::delete()
                    .uri("/eav/entities/c1?expected_version=1&force=true"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        assert!(fx.runtime.entities().get("c1").await?.is_none());
        let order = fx.runtime.entities().get("o1").await?.expect("order stays");
        assert_eq!(
            order.attributes.get("customer"),
            Some(&AttributeValue::EntityRef("c1".to_string()))
        );
        Ok(())
    }

    #[actix_web::test]
    async fn schema_diff_returns_the_diff_and_compatibility_flag() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(
            &fx,
            "invoice",
            vec![
                attr("total", AttributeType::Integer),
                attr("memo", AttributeType::String),
            ],
        )
        .await?;
        publish_schema_version(
            &fx,
            "invoice",
            vec![
                attr("total", AttributeType::Integer),
                required_attr("owner", AttributeType::String),
            ],
        )
        .await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/schemas/invoice/diff?from=1&to=2"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let diff: Value = actix_test::read_body_json(res).await;
        assert_eq!(diff["compatible"], false);
        assert!(diff["added"].get("owner").is_some());
        assert!(diff["removed"].get("memo").is_some());
        let breaking: Vec<&str> = diff["breaking"]
            .as_array()
            .expect("breaking list")
            .iter()
            .map(|code| code.as_str().expect("code"))
            .collect();
        assert!(breaking.contains(&"attribute-removed:memo"));
        assert!(breaking.contains(&"required-added:owner"));

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/schemas/invoice/diff?from=1&to=1"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let diff: Value = actix_test::read_body_json(res).await;
        assert_eq!(diff["compatible"], true);
        Ok(())
    }

    #[actix_web::test]
    async fn schema_diff_with_a_missing_version_is_404() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/schemas/invoice/diff?from=1&to=9"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        Ok(())
    }

    #[actix_web::test]
    async fn revalidation_returns_the_report() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: "e1".to_string(),
                    schemas: vec!["invoice".to_string()],
                    attributes: [("total".to_string(), AttributeValue::Integer(10))]
                        .into_iter()
                        .collect(),
                },
                &WriteContext::new("alice"),
            )
            .await?;
        publish_schema_version(
            &fx,
            "invoice",
            vec![
                attr("total", AttributeType::Integer),
                required_attr("owner", AttributeType::String),
            ],
        )
        .await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/revalidate")
                    .set_json(json!({"target_version": 2})),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let report: Value = actix_test::read_body_json(res).await;
        assert_eq!(report["scanned"], 1);
        assert_eq!(report["compatible"], 0);
        assert_eq!(report["invalid"].as_array().map(Vec::len), Some(1));
        assert_eq!(report["invalid"][0]["entity_id"], "e1");
        assert_eq!(report["invalid"][0]["issue"]["kind"], "missing_required");
        assert_eq!(report["invalid"][0]["issue"]["detail"], "owner");
        Ok(())
    }

    #[actix_web::test]
    async fn revalidation_rejects_an_invalid_limit() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for limit in [0, 501] {
            let res = actix_test::call_service(
                &app,
                auth(
                    actix_test::TestRequest::post()
                        .uri("/eav/schemas/invoice/revalidate")
                        .set_json(json!({"target_version": 1, "limit": limit})),
                    &token,
                )
                .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::BAD_REQUEST, "limit {limit}");
            let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
            assert_eq!(
                body.code.as_deref(),
                Some("invalid_request"),
                "limit {limit}"
            );
        }
        Ok(())
    }

    #[actix_web::test]
    async fn schema_evolution_routes_require_read_permission() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("bob")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/schemas/invoice/diff?from=1&to=1"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/revalidate")
                    .set_json(json!({"target_version": 1})),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);
        Ok(())
    }

    #[actix_web::test]
    async fn schema_migration_returns_the_report_and_defaults_to_a_dry_run() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: "e1".to_string(),
                    schemas: vec!["invoice".to_string()],
                    attributes: [("total".to_string(), AttributeValue::Integer(10))]
                        .into_iter()
                        .collect(),
                },
                &WriteContext::new("alice"),
            )
            .await?;
        publish_schema_version(
            &fx,
            "invoice",
            vec![
                attr("total", AttributeType::Integer),
                attr("memo", AttributeType::String),
            ],
        )
        .await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/migrate")
                    .set_json(json!({"target_version": 2})),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let report: Value = actix_test::read_body_json(res).await;
        assert_eq!(report["scanned"], 1);
        assert_eq!(report["migrated"], 1);
        assert_eq!(report["unchanged"], 0);
        assert_eq!(report["dry_run"], true);
        let entity = fx
            .runtime
            .entities()
            .get("e1")
            .await?
            .expect("entity exists");
        assert_eq!(entity.version, 1);
        assert_eq!(entity.schemas[0].version, 1);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/migrate")
                    .set_json(json!({
                        "target_version": 2,
                        "limit": 100,
                        "dry_run": false
                    })),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let report: Value = actix_test::read_body_json(res).await;
        assert_eq!(report["migrated"], 1);
        assert_eq!(report["dry_run"], false);
        let entity = fx
            .runtime
            .entities()
            .get("e1")
            .await?
            .expect("entity exists");
        assert_eq!(entity.version, 2);
        assert_eq!(entity.schemas[0].version, 2);
        Ok(())
    }

    #[actix_web::test]
    async fn schema_migration_resumes_after_the_cursor() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        for id in ["e1", "e2", "e3"] {
            fx.runtime
                .entities()
                .create(
                    EntityDraft {
                        id: id.to_string(),
                        schemas: vec!["invoice".to_string()],
                        attributes: [("total".to_string(), AttributeValue::Integer(10))]
                            .into_iter()
                            .collect(),
                    },
                    &WriteContext::new("alice"),
                )
                .await?;
        }
        publish_schema_version(
            &fx,
            "invoice",
            vec![
                attr("total", AttributeType::Integer),
                attr("memo", AttributeType::String),
            ],
        )
        .await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/migrate")
                    .set_json(json!({"target_version": 2, "limit": 2, "dry_run": false})),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let report: Value = actix_test::read_body_json(res).await;
        assert_eq!(report["scanned"], 2);
        assert_eq!(report["migrated"], 2);
        assert_eq!(report["next"], "e2");

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/migrate")
                    .set_json(json!({
                        "target_version": 2,
                        "limit": 2,
                        "dry_run": false,
                        "after": "e2"
                    })),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let report: Value = actix_test::read_body_json(res).await;
        assert_eq!(report["scanned"], 1);
        assert_eq!(report["migrated"], 1);
        assert_eq!(report["next"], Value::Null);

        let entity = fx
            .runtime
            .entities()
            .get("e3")
            .await?
            .expect("entity exists");
        assert_eq!(entity.version, 2);
        assert_eq!(entity.schemas[0].version, 2);
        Ok(())
    }

    #[actix_web::test]
    async fn schema_migration_with_a_missing_version_is_404() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/migrate")
                    .set_json(json!({"target_version": 9})),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        Ok(())
    }

    #[actix_web::test]
    async fn schema_migration_rejects_an_invalid_limit() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for limit in [0, 501] {
            let res = actix_test::call_service(
                &app,
                auth(
                    actix_test::TestRequest::post()
                        .uri("/eav/schemas/invoice/migrate")
                        .set_json(json!({"target_version": 1, "limit": limit})),
                    &token,
                )
                .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::BAD_REQUEST, "limit {limit}");
            let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
            assert_eq!(
                body.code.as_deref(),
                Some("invalid_request"),
                "limit {limit}"
            );
        }
        Ok(())
    }

    #[actix_web::test]
    async fn schema_migration_requires_write_on_schemas_and_entities() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: "e1".to_string(),
                    schemas: vec!["invoice".to_string()],
                    attributes: [("total".to_string(), AttributeValue::Integer(10))]
                        .into_iter()
                        .collect(),
                },
                &WriteContext::new("alice"),
            )
            .await?;
        publish_schema_version(
            &fx,
            "invoice",
            vec![
                attr("total", AttributeType::Integer),
                attr("memo", AttributeType::String),
            ],
        )
        .await?;

        fx.engine
            .assign_group("carol".into(), "schema-writers".into())
            .await?;
        fx.engine
            .add_rule("schema-writers".into(), "eav_schemas".into(), Action::Write)
            .await?;
        fx.engine
            .assign_group("dave".into(), "entity-writers".into())
            .await?;
        fx.engine
            .add_rule(
                "entity-writers".into(),
                "eav_entities".into(),
                Action::Write,
            )
            .await?;
        fx.engine
            .assign_group("erin".into(), "migration-writers".into())
            .await?;
        fx.engine
            .add_rule(
                "migration-writers".into(),
                "eav_schemas".into(),
                Action::Write,
            )
            .await?;
        fx.engine
            .add_rule(
                "migration-writers".into(),
                "eav_entities".into(),
                Action::Write,
            )
            .await?;

        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        for sub in ["carol", "dave"] {
            let res = actix_test::call_service(
                &app,
                auth(
                    actix_test::TestRequest::post()
                        .uri("/eav/schemas/invoice/migrate")
                        .set_json(json!({"target_version": 2, "dry_run": false})),
                    &fx.token(sub)?,
                )
                .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::FORBIDDEN, "{sub}");
        }

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/migrate")
                    .set_json(json!({"target_version": 2, "dry_run": false})),
                &fx.token("erin")?,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        Ok(())
    }

    #[actix_web::test]
    async fn schema_migration_dry_run_requires_read_only() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_schema_version(&fx, "invoice", vec![attr("total", AttributeType::Integer)]).await?;
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: "e1".to_string(),
                    schemas: vec!["invoice".to_string()],
                    attributes: [("total".to_string(), AttributeValue::Integer(10))]
                        .into_iter()
                        .collect(),
                },
                &WriteContext::new("alice"),
            )
            .await?;
        publish_schema_version(
            &fx,
            "invoice",
            vec![
                attr("total", AttributeType::Integer),
                attr("memo", AttributeType::String),
            ],
        )
        .await?;

        fx.engine
            .assign_group("frank".into(), "migration-readers".into())
            .await?;
        fx.engine
            .add_rule(
                "migration-readers".into(),
                "eav_schemas".into(),
                Action::Read,
            )
            .await?;
        fx.engine
            .add_rule(
                "migration-readers".into(),
                "eav_entities".into(),
                Action::Read,
            )
            .await?;

        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("frank")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/migrate")
                    .set_json(json!({"target_version": 2})),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let report: Value = actix_test::read_body_json(res).await;
        assert_eq!(report["dry_run"], true);
        assert_eq!(report["migrated"], 1);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post()
                    .uri("/eav/schemas/invoice/migrate")
                    .set_json(json!({"target_version": 2, "dry_run": false})),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);

        let entity = fx
            .runtime
            .entities()
            .get("e1")
            .await?
            .expect("entity exists");
        assert_eq!(entity.version, 1);
        assert_eq!(entity.schemas[0].version, 1);
        Ok(())
    }

    #[actix_web::test]
    async fn schema_entity_list_is_404_for_an_unknown_schema() -> anyhow::Result<()> {
        let fx = fixture().await?;
        assert!(fx.engine.claim_superadmin("alice").await?);
        publish_task_schema(&fx).await?;
        create_task(&fx, "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/schemas/absent/entities"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("not_found"));

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get().uri("/eav/schemas/task/entities?limit=2&offset=0"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let page: Value = actix_test::read_body_json(res).await;
        let items = page["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "e1");
        assert_eq!(page["next_offset"], Value::Null);
        Ok(())
    }
}
