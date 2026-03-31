use std::sync::Arc;

use actix_web::{HttpResponse, Responder, ResponseError, delete, get, post, web};
use serde::{Deserialize, Serialize};

use super::{Action, PolicyEngine, PolicyError};
use crate::endpoint::{
    ApiModule,
    middleware::jwt::{Claims, JwtClaimsMiddleware},
};

pub struct PolicyApiModule {
    policy_engine: Arc<PolicyEngine>,
    jwt_middleware: JwtClaimsMiddleware<Claims>,
}

impl PolicyApiModule {
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

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    UserGroups,
    Rules,
}

impl Resource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Resource::UserGroups => "user_groups",
            Resource::Rules => "rules",
        }
    }
}

#[derive(Deserialize)]
pub struct PolicyRequest {
    pub sub: String,
    pub obj: String,
    pub act: Action,
}

#[derive(Deserialize)]
pub struct GroupRequest {
    pub user_id: String,
    pub group: String,
}

#[derive(Serialize)]
pub struct ActionResponse {
    pub success: bool,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub items: Vec<String>,
}

#[derive(Serialize)]
pub struct RuleListResponse {
    pub rules: Vec<Vec<String>>,
}

// Implement ResponseError so we can return PolicyError directly from handlers
impl ResponseError for PolicyError {
    fn error_response(&self) -> HttpResponse {
        match self {
            PolicyError::AccessDenied => HttpResponse::Forbidden().json("Access Denied"),
            PolicyError::Database(_) => HttpResponse::InternalServerError().json("Database error"),
            PolicyError::Casbin(_) => {
                HttpResponse::InternalServerError().json("Policy engine error")
            }
        }
    }
}

#[get("/rules")]
async fn get_rules(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: web::ReqData<Claims>,
) -> Result<impl Responder, PolicyError> {
    policy_engine
        .require(&auth_claims.sub, Resource::Rules.as_str(), Action::Read)
        .await?;

    let rules = policy_engine.get_all_rules().await;
    Ok(HttpResponse::Ok().json(RuleListResponse { rules }))
}

#[post("/rules")]
async fn add_rule(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: web::ReqData<Claims>,
    req: web::Json<PolicyRequest>,
) -> Result<impl Responder, PolicyError> {
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
    auth_claims: web::ReqData<Claims>,
    req: web::Json<PolicyRequest>,
) -> Result<impl Responder, PolicyError> {
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
    auth_claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<impl Responder, PolicyError> {
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
    auth_claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<impl Responder, PolicyError> {
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
    auth_claims: web::ReqData<Claims>,
    req: web::Json<GroupRequest>,
) -> Result<impl Responder, PolicyError> {
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
    auth_claims: web::ReqData<Claims>,
    path: web::Path<(String, String)>,
) -> Result<impl Responder, PolicyError> {
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
