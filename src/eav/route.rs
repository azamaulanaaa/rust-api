//! Actix routes for the EAV schemas, entities, and rules.
//!
//! Every handler authorizes itself.
//! Schema routes check `eav_schemas`.
//! Rule routes check `eav_rules`.
//! Entity routes check `eav_entities`.
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

use crate::eav::entity::{Entity, EntityPatch, WriteContext};
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
const ENTITIES: &str = "eav_entities";
/// The Casbin object for rule management.
const RULES: &str = "eav_rules";
/// The row type for one entity.
const ENTITY_ROW: &str = "entity";
/// The default page size of a list route.
const DEFAULT_PAGE_LIMIT: usize = 50;
/// The maximum page size of a list route.
const MAX_PAGE_LIMIT: usize = 200;

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
            .service(create_entity)
            .service(list_entities)
            .service(get_entity)
            .service(patch_entity)
            .service(delete_entity)
            .service(list_schema_entities)
            .service(upsert_rule)
            .service(list_rules)
            .service(get_rule)
            .service(delete_rule)
            .service(set_rule_enabled);
        cfg.service(scope);
    }
}

/// The query of the entity delete route.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ExpectedVersionQuery {
    /// The version that the caller expects.
    pub expected_version: u64,
}

/// The paging query of a list route.
///
/// The default limit is 50.
/// The maximum limit is 200.
#[derive(Debug, Clone, Copy, Deserialize, utoipa::IntoParams)]
pub struct PageQuery {
    /// The page size. The default is 50. The maximum is 200.
    #[serde(default)]
    pub limit: Option<usize>,
    /// The number of items to skip. The default is 0.
    #[serde(default)]
    pub offset: Option<usize>,
}

impl PageQuery {
    /// Resolves the page window and checks the limit.
    fn resolve(self) -> Result<(usize, usize), EavApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        if limit == 0 || limit > MAX_PAGE_LIMIT {
            return Err(EavApiError::Invalid(Box::new(InvalidPageLimit)));
        }
        Ok((limit, self.offset.unwrap_or(0)))
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
}

/// A page of entities.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct EntityPage {
    /// The entities on this page.
    pub items: Vec<Entity>,
    /// `Some` means the page was full and a following page may exist.
    /// Fetch it and stop when the page is empty.
    pub next_offset: Option<usize>,
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

/// The source of a page limit outside the allowed range.
#[derive(Debug)]
struct InvalidPageLimit;

impl fmt::Display for InvalidPageLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("limit must be between 1 and 200")
    }
}

impl std::error::Error for InvalidPageLimit {}

/// Returns the next offset when the page is full.
///
/// The call returns `None` when the page is not full.
fn page_next_offset(offset: usize, len: usize, limit: usize) -> Option<usize> {
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
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Returns the stable code of this error.
    fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "not_found",
            Self::Invalid(_) => "invalid_request",
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
            EntityError::Invalid(_)
            | EntityError::UnknownAttribute(_)
            | EntityError::SchemaConflict(_)
            | EntityError::MissingRequired(_)
            | EntityError::TypeMismatch(_)
            | EntityError::NotIndexed(_) => Kind::Invalid,
            EntityError::UniqueViolation(_)
            | EntityError::VersionConflict
            | EntityError::AlreadyExists(_) => Kind::Conflict,
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
async fn can_read_entity(policy: &Authorizer, sub: &str, id: &str) -> Result<bool, EavApiError> {
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
    let (limit, offset) = query.into_inner().resolve()?;
    let items = runtime.schemas().list_page(limit, offset).await?;
    let next_offset = page_next_offset(offset, items.len(), limit);
    Ok(HttpResponse::Ok().json(SchemaPage { items, next_offset }))
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
#[utoipa::path(get, path = "/eav/entities", tag = "eav", params(PageQuery), responses((status=200, body=EntityPage), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/entities")]
async fn list_entities(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    query: web::Query<PageQuery>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, ENTITIES, Action::Read).await?;
    let (limit, offset) = query.into_inner().resolve()?;
    let raw = runtime.entities().list_page(limit, offset).await?;
    let raw_len = raw.len();
    let mut items = Vec::with_capacity(raw_len);
    for entity in raw {
        if can_read_entity(&policy, &claims.sub, &entity.id).await? {
            items.push(entity);
        }
    }
    let next_offset = page_next_offset(offset, raw_len, limit);
    Ok(HttpResponse::Ok().json(EntityPage { items, next_offset }))
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

#[utoipa::path(delete, path = "/eav/entities/{id}", tag = "eav", params(("id" = String, Path), ("expected_version" = u64, Query)), responses((status=204, description="entity deleted"), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=404, body=crate::http::error::ErrorBody), (status=409, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
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
            &WriteContext::new(claims.sub.clone()),
        )
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(get, path = "/eav/schemas/{id}/entities", tag = "eav", params(("id" = String, Path), PageQuery), responses((status=200, body=EntityPage), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
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
    let (limit, offset) = query.into_inner().resolve()?;
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
    Ok(HttpResponse::Ok().json(EntityPage { items, next_offset }))
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
    if !runtime.engine().has_action(&draft.action.kind) {
        return Err(EavApiError::from(RuleError::UnknownAction(
            draft.action.kind,
        )));
    }
    let rule = runtime.rules().upsert(draft).await?;
    Ok(HttpResponse::Created().json(rule))
}

#[utoipa::path(get, path = "/eav/rules", tag = "eav", params(PageQuery), responses((status=200, body=RulePage), (status=400, body=crate::http::error::ErrorBody), (status=401, body=crate::http::error::ErrorBody), (status=403, body=crate::http::error::ErrorBody), (status=500, body=crate::http::error::ErrorBody)))]
#[get("/rules")]
async fn list_rules(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    query: web::Query<PageQuery>,
) -> Result<HttpResponse, EavApiError> {
    require_management(&policy, &claims.sub, RULES, Action::Read).await?;
    let (limit, offset) = query.into_inner().resolve()?;
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
    use crate::eav::schema::{AttributeDef, AttributeType};
    use crate::fs::s3::{S3Backend, S3ClientConfig};
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::policy::PolicyEngine;
    use crate::rules::action::{ActionContext, RuleAction};
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
        "/eav/schemas/{id}/entities",
        "/eav/entities",
        "/eav/entities/{id}",
        "/eav/rules",
        "/eav/rules/{id}",
        "/eav/rules/{id}/enabled",
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
        let runtime = EavRuntime::build(&s3, &prefix, wal, vec![Arc::new(NoopAction)]).await?;
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
}
