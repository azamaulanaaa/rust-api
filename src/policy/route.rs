use std::sync::Arc;

use actix_web::{HttpResponse, Responder, delete, get, post, web};
use serde::{Deserialize, Serialize};

use super::{Action, GroupSummary, PolicyEngine, PolicyError, UserAssignment};
use crate::http::{
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
            .service(remove_user_from_group)
            .service(list_groups)
            .service(list_users)
            .service(delete_group);

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
#[derive(Deserialize, utoipa::ToSchema)]
pub struct PolicyRequest {
    /// Subject (user or group) the rule applies to.
    pub sub: String,
    /// Object being acted upon.
    pub obj: String,
    /// Operation granted by the rule.
    pub act: Action,
}

/// Body for assigning/unassigning group membership.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct GroupRequest {
    /// Subject to add to/remove from the group.
    pub user_id: String,
    /// Target group name.
    pub group: String,
}

/// Generic success indicator returned by mutating endpoints.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ActionResponse {
    /// Whether the mutation was applied.
    pub success: bool,
}

/// A flat list of string identifiers.
#[derive(Serialize, utoipa::ToSchema)]
pub struct ListResponse {
    /// The listed items (users or groups).
    pub items: Vec<String>,
}

/// Permission rules with pagination metadata.
#[derive(Serialize, utoipa::ToSchema)]
pub struct RuleListResponse {
    /// One page of rules, each as `[sub, obj, act]`.
    pub rules: Vec<Vec<String>>,
    /// Total number of stored rules (independent of paging).
    pub total: usize,
    /// The page size applied to this response.
    pub limit: usize,
    /// The offset this page starts at.
    pub offset: usize,
}

/// Query parameters for `GET /policy/rules`.
#[derive(Debug, Deserialize)]
pub struct RulesQuery {
    /// Page size; defaults to 100 and is capped at 1000.
    pub limit: Option<usize>,
    /// Number of rules to skip; defaults to 0.
    pub offset: Option<usize>,
}

/// Applies `offset`/`limit` to a full rule list. Kept pure for unit testing;
/// `limit` is capped at [`MAX_PAGE_SIZE`](const@MAX_PAGE_SIZE).
fn paginate(rules: &[Vec<String>], limit: Option<usize>, offset: usize) -> Vec<Vec<String>> {
    let start = offset.min(rules.len());
    let end = start
        .saturating_add(limit.unwrap_or(MAX_PAGE_SIZE).min(MAX_PAGE_SIZE))
        .min(rules.len());
    rules[start..end].to_vec()
}

/// Maximum number of rules returned in one page.
/// Page size used when the client does not specify one.
pub(crate) const DEFAULT_PAGE_SIZE: usize = 100;

/// Maximum number of rules returned in one page.
pub(crate) const MAX_PAGE_SIZE: usize = 1000;

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

#[utoipa::path(get, path = "/policy/rules", tag = "policy", params(("limit" = Option<usize>, Query), ("offset" = Option<usize>, Query)), responses((status=200, body=RuleListResponse), (status=401, body=crate::http::error::ErrorBody)))]
#[get("/rules")]
async fn get_rules(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    query: web::Query<RulesQuery>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(&auth_claims.sub, Resource::Rules.as_str(), Action::Read)
        .await?;

    let all_rules = policy_engine.get_all_rules().await;
    let total = all_rules.len();
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    let offset = query.offset.unwrap_or(0);
    let rules = paginate(&all_rules, Some(limit), offset);
    Ok(HttpResponse::Ok().json(RuleListResponse {
        rules,
        total,
        limit: limit.min(MAX_PAGE_SIZE),
        offset,
    }))
}

#[utoipa::path(post, path = "/policy/rules", tag = "policy", request_body = PolicyRequest, responses((status=200, body=ActionResponse), (status=401, body=crate::http::error::ErrorBody)))]
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

#[utoipa::path(delete, path = "/policy/rules", tag = "policy", request_body = PolicyRequest, responses((status=200, body=ActionResponse), (status=401, body=crate::http::error::ErrorBody)))]
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

/// Paginated group listing.
#[derive(Serialize)]
pub struct GroupsResponse {
    /// Page of groups with member counts.
    pub groups: Vec<GroupSummary>,
    /// Total number of known groups.
    pub total: usize,
    /// Effective page size after capping.
    pub limit: usize,
    /// Offset this page starts at.
    pub offset: usize,
}

/// Paginated user-assignment listing.
#[derive(Serialize)]
pub struct UsersResponse {
    /// Page of subjects with their groups.
    pub users: Vec<UserAssignment>,
    /// Total number of subjects holding memberships.
    pub total: usize,
    /// Effective page size after capping.
    pub limit: usize,
    /// Offset this page starts at.
    pub offset: usize,
}

/// Lists every known group with member counts.
#[get("/groups")]
async fn list_groups(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    query: web::Query<RulesQuery>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(
            &auth_claims.sub,
            Resource::UserGroups.as_str(),
            Action::Read,
        )
        .await?;

    let all = policy_engine.list_groups().await;
    let total = all.len();
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE);
    let offset = query.offset.unwrap_or(0);
    let groups = all.into_iter().skip(offset).take(limit).collect();

    Ok(HttpResponse::Ok().json(GroupsResponse {
        groups,
        total,
        limit,
        offset,
    }))
}

/// Lists every subject holding group memberships.
#[get("/users")]
async fn list_users(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    query: web::Query<RulesQuery>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(
            &auth_claims.sub,
            Resource::UserGroups.as_str(),
            Action::Read,
        )
        .await?;

    let all = policy_engine.list_user_assignments().await;
    let total = all.len();
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE);
    let offset = query.offset.unwrap_or(0);
    let users = all.into_iter().skip(offset).take(limit).collect();

    Ok(HttpResponse::Ok().json(UsersResponse {
        users,
        total,
        limit,
        offset,
    }))
}

/// Deletes a group together with every membership link to it.
#[delete("/groups/{group_name}")]
async fn delete_group(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    path: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(
            &auth_claims.sub,
            Resource::UserGroups.as_str(),
            Action::Write,
        )
        .await?;

    let group_name = path.into_inner();
    let success = policy_engine.delete_group(&group_name).await?;

    Ok(HttpResponse::Ok().json(ActionResponse { success }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, http};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::http::middleware::jwt::{Claims, JwtClaimsMiddleware};
    use crate::policy::PolicyEngine;

    const KID: &str = "policy-route-test-kid";
    const AUD: &str = "test-aud";

    struct Fixture {
        server: wiremock::MockServer,
        enc: EncodingKey,
        engine: PolicyEngine,
        _store_path: std::path::PathBuf,
    }
    impl Fixture {
        fn issuer(&self) -> String {
            self.server.uri()
        }
        fn token(&self, sub: &str) -> anyhow::Result<String> {
            sign_rs256(
                &json!({"sub": sub, "iss": self.issuer(), "aud": AUD, "exp": 2000000000u64}),
                KID,
                &self.enc,
            )
        }
    }
    async fn fixture(grant_alice: bool) -> anyhow::Result<Fixture> {
        let (key, enc) = rsa_key(KID)?;
        let jwks = json!({"keys": [key]});
        let server = spawn_jwks(jwks).await;
        let store_path = std::env::temp_dir().join(format!(
            "policy-route-{}-{}.redb",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
        ));
        let _ = std::fs::remove_file(&store_path);
        let engine = PolicyEngine::init(&store_path).await?;
        if grant_alice {
            engine
                .add_rule("alice".into(), "rules".into(), Action::Read)
                .await?;
            engine
                .add_rule("alice".into(), "rules".into(), Action::Write)
                .await?;
            engine
                .add_rule("alice".into(), "user_groups".into(), Action::Read)
                .await?;
            engine
                .add_rule("alice".into(), "user_groups".into(), Action::Write)
                .await?;
        }
        Ok(Fixture {
            server,
            enc,
            engine,
            _store_path: store_path,
        })
    }

    fn rule(sub: &str) -> Vec<String> {
        vec![sub.to_string(), "obj".to_string(), "read".to_string()]
    }

    #[test]
    fn paginate_slices_and_caps_limit() {
        let rules: Vec<Vec<String>> = (0..10).map(|i| rule(&format!("u{i}"))).collect();

        // Default limit applies when unset.
        // Default limit (100) exceeds this list, so the whole set returns.
        assert_eq!(paginate(&rules, None, 0), rules);

        // Offset slices from the right position.
        let page = paginate(&rules, Some(3), 4);
        assert_eq!(page, rules[4..7].to_vec());

        // Limit above MAX_PAGE_SIZE gets capped.
        let big: Vec<Vec<String>> = (0..(MAX_PAGE_SIZE + 50)).map(|_| rule("x")).collect();
        assert_eq!(
            paginate(&big, Some(MAX_PAGE_SIZE * 2), 0).len(),
            MAX_PAGE_SIZE
        );

        // Offset past the end yields an empty page, not a panic.
        assert!(paginate(&rules, Some(3), 99).is_empty());
    }

    #[actix_web::test]
    async fn unauthenticated_rules_is_401() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = PolicyApiModule::new(fx.engine.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/rules")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[actix_web::test]
    async fn forbidden_without_rule() -> anyhow::Result<()> {
        let fx = fixture(false).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = PolicyApiModule::new(fx.engine.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/rules")
                .insert_header(("Cookie", format!("auth_token={}", fx.token("bob")?)))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN);
        Ok(())
    }

    #[actix_web::test]
    async fn rules_crud_via_http() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = PolicyApiModule::new(fx.engine.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        // add rule
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/policy/rules")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"sub":"bob","obj":"doc","act":"Read"}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(res).await;
        assert_eq!(body["success"], true);
        // duplicate add returns false
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/policy/rules")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"sub":"bob","obj":"doc","act":"Read"}))
                .to_request(),
        )
        .await;
        let body: serde_json::Value = actix_web::test::read_body_json(res).await;
        assert_eq!(body["success"], false);
        // get rules with pagination
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/rules?limit=1&offset=0")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(res).await;
        assert!(body["total"].as_u64().unwrap_or(0) >= 1);
        assert_eq!(body["rules"].as_array().map(|a| a.len()).unwrap_or(0), 1);
        // remove rule
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::delete()
                .uri("/policy/rules")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"sub":"bob","obj":"doc","act":"Read"}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(res).await;
        assert_eq!(body["success"], true);
        Ok(())
    }

    #[actix_web::test]
    async fn groups_crud_via_http() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = PolicyApiModule::new(fx.engine.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        // assign group
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::post()
                .uri("/policy/groups")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .set_json(json!({"user_id":"carol","group":"editors"}))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        // get user groups
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/groups/carol")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(res).await;
        assert!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "editors")
        );
        // get group users
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/groups/editors/users")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(res).await;
        assert!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "carol")
        );
        // list groups
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/groups?limit=1")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        // list users
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/users?limit=1")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        // remove from group
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::delete()
                .uri("/policy/groups/editors/users/carol")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(res).await;
        assert_eq!(body["success"], true);
        // delete group (non-existent -> false but 200)
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::delete()
                .uri("/policy/groups/editors")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        Ok(())
    }

    #[actix_web::test]
    async fn delete_group_authorized() -> anyhow::Result<()> {
        let fx = fixture(true).await?;
        // create a group with member via engine directly to test delete_group handler pagination branches
        fx.engine.assign_group("dave".into(), "temp".into()).await?;
        let mw = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUD,
            &fx.issuer(),
        )
        .await?;
        let module = PolicyApiModule::new(fx.engine.clone(), mw);
        let app =
            actix_web::test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::delete()
                .uri("/policy/groups/temp")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(res).await;
        assert_eq!(body["success"], true);
        // offset/limit cap branches for groups/users
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/groups?limit=9999&offset=999")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/users?limit=9999&offset=999")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        Ok(())
    }
}
