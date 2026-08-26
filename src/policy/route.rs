use std::sync::Arc;

use actix_web::{HttpResponse, Responder, delete, get, post, web};
use serde::{Deserialize, Serialize};

use super::{Action, PolicyEngine, PolicyError};
use crate::endpoint::{
    ApiModule,
    error::ApiError,
    middleware::jwt::{Claims, JwtClaimsMiddleware, Validated},
};

/// API module exposing `/policy` management routes (rules and group
/// membership), protected by JWT validation and self-authorizing checks.
pub struct PolicyApiModule {
    policy_engine: Arc<PolicyEngine>,
    jwt_middleware: JwtClaimsMiddleware<Claims>,
}

impl PolicyApiModule {
    /// Wraps a [`PolicyEngine`] with the given JWT middleware; every route
    /// in this module requires validated claims before enforcing policies.
    pub fn new(policy_engine: PolicyEngine, jwt_middleware: JwtClaimsMiddleware<Claims>) -> Self {
        Self {
            policy_engine: Arc::new(policy_engine),
            jwt_middleware,
        }
    }
}

impl ApiModule for PolicyApiModule {
    fn configure(&self, cfg: &mut web::ServiceConfig) {
        let policy_engine = web::Data::from(self.policy_engine.clone());
        let jwt_middleware = self.jwt_middleware.clone();

        let scope = web::scope("/policy")
            .app_data(policy_engine)
            .wrap(jwt_middleware)
            .service(get_rules)
            .service(add_rule)
            .service(remove_rule)
            .service(assign_group)
            .service(get_user_groups)
            .service(get_group_users)
            .service(remove_user_from_group);

        cfg.service(scope);
    }
}

/// The policy-managed objects routes operate on; used as the Casbin
/// object (`obj`) value when authorizing management operations.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// Group-membership assignments (`g` rules).
    UserGroups,
    /// Permission rules (`p` rules).
    Rules,
}

impl Resource {
    /// The canonical wire/Casbin string for this resource.
    pub fn as_str(&self) -> &'static str {
        match self {
            Resource::UserGroups => "user_groups",
            Resource::Rules => "rules",
        }
    }
}

/// Body for creating/removing a permission rule.
#[derive(Deserialize)]
pub struct PolicyRequest {
    /// Subject (user or group) the rule applies to.
    pub sub: String,
    /// Object being acted upon.
    pub obj: String,
    /// Operation granted by the rule.
    pub act: Action,
}

/// Body for assigning/unassigning group membership.
#[derive(Deserialize)]
pub struct GroupRequest {
    /// Subject to add to/remove from the group.
    pub user_id: String,
    /// Target group name.
    pub group: String,
}

/// Generic success indicator returned by mutating endpoints.
#[derive(Serialize)]
pub struct ActionResponse {
    /// Whether the mutation was applied.
    pub success: bool,
}

/// A flat list of string identifiers.
#[derive(Serialize)]
pub struct ListResponse {
    /// The listed items (users or groups).
    pub items: Vec<String>,
}

/// All stored permission rules as raw Casbin triples.
#[derive(Serialize)]
pub struct RuleListResponse {
    /// Each rule as `[sub, obj, act]`.
    pub rules: Vec<Vec<String>>,
}

/// Maps domain policy failures onto the uniform API error envelope:
/// `AccessDenied` becomes 403 Forbidden; store/engine failures become 500
/// with their cause attached for server-side logging.
impl From<PolicyError> for ApiError {
    fn from(value: PolicyError) -> Self {
        match value {
            PolicyError::AccessDenied => ApiError::Forbidden,
            PolicyError::Store(e) => ApiError::Internal(Box::new(e)),
            PolicyError::Casbin(e) => ApiError::Internal(Box::new(e)),
        }
    }
}

#[get("/rules")]
async fn get_rules(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(&auth_claims.sub, Resource::Rules.as_str(), Action::Read)
        .await?;

    let rules = policy_engine.get_all_rules().await;
    Ok(HttpResponse::Ok().json(RuleListResponse { rules }))
}

#[post("/rules")]
async fn add_rule(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    req: web::Json<PolicyRequest>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(&auth_claims.sub, Resource::Rules.as_str(), Action::Write)
        .await?;

    let success = policy_engine
        .add_rule(req.sub.clone(), req.obj.clone(), req.act)
        .await?;
    Ok(HttpResponse::Ok().json(ActionResponse { success }))
}

#[delete("/rules")]
async fn remove_rule(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    req: web::Json<PolicyRequest>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(&auth_claims.sub, Resource::Rules.as_str(), Action::Write)
        .await?;

    let success = policy_engine
        .remove_rule(req.sub.clone(), req.obj.clone(), req.act)
        .await?;
    Ok(HttpResponse::Ok().json(ActionResponse { success }))
}

#[get("/groups/{user_id}")]
async fn get_user_groups(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(
            &auth_claims.sub,
            Resource::UserGroups.as_str(),
            Action::Read,
        )
        .await?;

    let user_id = path.into_inner();
    let groups = policy_engine.get_groups_of_user(&user_id).await;

    Ok(HttpResponse::Ok().json(ListResponse { items: groups }))
}

#[get("/groups/{group_name}/users")]
async fn get_group_users(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(
            &auth_claims.sub,
            Resource::UserGroups.as_str(),
            Action::Read,
        )
        .await?;

    let group_name = path.into_inner();
    let users = policy_engine.get_users_in_group(&group_name).await;

    Ok(HttpResponse::Ok().json(ListResponse { items: users }))
}

#[post("/groups")]
async fn assign_group(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    req: web::Json<GroupRequest>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(
            &auth_claims.sub,
            Resource::UserGroups.as_str(),
            Action::Write,
        )
        .await?;

    let success = policy_engine
        .assign_group(req.user_id.clone(), req.group.clone())
        .await?;
    Ok(HttpResponse::Ok().json(ActionResponse { success }))
}

#[delete("/groups/{group_name}/users/{user_id}")]
async fn remove_user_from_group(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    path: web::Path<(String, String)>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(
            &auth_claims.sub,
            Resource::UserGroups.as_str(),
            Action::Write,
        )
        .await?;

    let (group_name, user_id) = path.into_inner();
    let success = policy_engine.remove_from_group(user_id, group_name).await?;

    Ok(HttpResponse::Ok().json(ActionResponse { success }))
}
