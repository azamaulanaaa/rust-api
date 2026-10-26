//! Actix routes for `/policy` rule and group management.
//!
//! Every handler authorizes itself. It first requires the caller to hold
//! Casbin permission on the [`Resource`](crate::policy::route::Resource) it
//! touches. Rule endpoints use `rules`. Membership and listing endpoints
//! use `user_groups`. A valid token alone is therefore not enough.

use std::sync::Arc;

use actix_web::{HttpResponse, Responder, delete, get, post, web};
use serde::{Deserialize, Serialize};

use super::{Action, GroupSummary, PolicyEngine, PolicyError, UserAssignment};
use crate::http::{
    ApiModule,
    error::ApiError,
    middleware::jwt::{Claims, JwtClaimsMiddleware, Validated},
};

/// API module exposing the `/policy` management routes for rules and group
/// membership. The module uses JWT validation and a self-authorizing check.
pub struct PolicyApiModule {
    policy_engine: Arc<PolicyEngine>,
    jwt_middleware: JwtClaimsMiddleware<Claims>,
}

impl PolicyApiModule {
    /// Wraps a [`PolicyEngine`] with the given JWT middleware. Every route
    /// in this module requires validated claims before it enforces policies.
    pub fn new(policy_engine: PolicyEngine, jwt_middleware: JwtClaimsMiddleware<Claims>) -> Self {
        Self {
            policy_engine: Arc::new(policy_engine),
            jwt_middleware,
        }
    }
}

impl ApiModule for PolicyApiModule {
    fn prefix(&self) -> &str {
        "/policy"
    }

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

/// The objects that the policy manages and that the routes operate on. The
/// value is the Casbin object (`obj`) when the module authorizes a
/// management operation.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// Group-membership assignments (`g` rules).
    UserGroups,
    /// Permission rules (`p` rules).
    Rules,
}

impl Resource {
    /// The canonical wire string and Casbin string for this resource.
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
    /// Subject to add to the group, or to remove from it.
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
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct ListResponse {
    /// The listed items (users or groups).
    pub items: Vec<String>,
}

/// Permission rules with pagination metadata.
#[derive(Serialize, utoipa::ToSchema)]
pub struct RuleListResponse {
    /// One page of items, each as `[sub, obj, act]`.
    pub items: Vec<Vec<String>>,
    /// Total number of stored rules (independent of paging).
    pub total: usize,
    /// The page size applied to this response.
    pub limit: usize,
    /// The offset this page starts at.
    pub offset: usize,
}

/// Query parameters shared by every `/policy` listing endpoint.
///
/// `limit` and `offset` are optional. [`Page`] resolves them, and it is the
/// single place where the bounds `DEFAULT_PAGE_SIZE` and `MAX_PAGE_SIZE`
/// live.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, utoipa::IntoParams)]
pub struct ListQuery {
    /// Page size. The default is 100, and the cap is 1000.
    #[serde(rename = "limit")]
    pub limit: Option<usize>,
    /// Number of items to skip. The default is 0.
    #[serde(rename = "offset")]
    pub offset: Option<usize>,
}

/// Backwards-compatible alias for the previous name of [`ListQuery`].
pub type RulesQuery = ListQuery;

/// Page size used when the client does not specify one.
pub(crate) const DEFAULT_PAGE_SIZE: usize = 100;

/// Upper bound on the page size a client may ask for.
pub(crate) const MAX_PAGE_SIZE: usize = 1000;

/// A resolved pagination window.
///
/// Every listing endpoint resolves its `limit` and `offset` through this
/// type. The endpoints therefore cannot drift apart. The cap, the default,
/// and the value that the response echoes back all come from the same
/// computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Page {
    /// Effective page size, after the [`MAX_PAGE_SIZE`] cap.
    limit: usize,
    /// Offset this page starts at.
    offset: usize,
}

impl Page {
    /// Resolves the client's requested window against the shared bounds.
    fn from_query(query: &ListQuery) -> Self {
        Self {
            limit: query.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE),
            offset: query.offset.unwrap_or(0),
        }
    }

    /// Slices `items` down to this window. An offset past the end returns an
    /// empty page instead of panicking. The function consumes the
    /// collection, so callers do not need `Clone` on their response types.
    fn apply<T>(&self, items: impl IntoIterator<Item = T>) -> Vec<T> {
        items
            .into_iter()
            .skip(self.offset)
            .take(self.limit)
            .collect()
    }
}

/// Maps the failures of the policy domain onto the uniform API error
/// envelope. `AccessDenied` becomes 403 Forbidden. A store failure or an
/// engine failure becomes 500, with the cause attached for logging on the
/// server.
impl From<PolicyError> for ApiError {
    fn from(value: PolicyError) -> Self {
        match value {
            PolicyError::AccessDenied => ApiError::Forbidden,
            // The code hands the fencing case over whole, and not unwrapped,
            // so that its `Display` reaches the log line that `ApiError`
            // writes for a 500. The verb `error!` is wrong here. A
            // `tracing::error!` inside a `From` would add a side effect to
            // a conversion. The distinguishable text is the mechanism, and
            // its wording matches `FsError::Fenced`. One query finds both.
            other => ApiError::Internal(Box::new(other)),
        }
    }
}

#[utoipa::path(get, path = "/policy/rules", tag = "policy", params(ListQuery), responses((status=200, body=RuleListResponse), (status=401, body=crate::http::error::ErrorBody)))]
#[get("/rules")]
async fn get_rules(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    query: web::Query<ListQuery>,
) -> Result<impl Responder, ApiError> {
    policy_engine
        .require(&auth_claims.sub, Resource::Rules.as_str(), Action::Read)
        .await?;

    let all_rules = policy_engine.get_all_rules().await;
    let total = all_rules.len();
    let page = Page::from_query(&query);
    Ok(HttpResponse::Ok().json(RuleListResponse {
        items: page.apply(all_rules),
        total,
        limit: page.limit,
        offset: page.offset,
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
    tracing::info!(
        subject = %auth_claims.sub,
        action = "rule.add",
        target = %format!("{} {} {}", req.sub, req.obj, req.act),
        "audit mutation"
    );
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
    tracing::info!(
        subject = %auth_claims.sub,
        action = "rule.remove",
        target = %format!("{} {} {}", req.sub, req.obj, req.act),
        "audit mutation"
    );
    Ok(HttpResponse::Ok().json(ActionResponse { success }))
}

#[utoipa::path(get, path = "/policy/groups/{user_id}", tag = "policy", params(("user_id" = String, Path)), responses((status = 200, body = ListResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 403, body = crate::http::error::ErrorBody)))]
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

#[utoipa::path(get, path = "/policy/groups/{group_name}/users", tag = "policy", params(("group_name" = String, Path)), responses((status = 200, body = ListResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 403, body = crate::http::error::ErrorBody)))]
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

#[utoipa::path(post, path = "/policy/groups", tag = "policy", request_body = GroupRequest, responses((status = 200, body = ActionResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 403, body = crate::http::error::ErrorBody)))]
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
    tracing::info!(
        subject = %auth_claims.sub,
        action = "group.assign",
        target = %format!("{} -> {}", req.user_id, req.group),
        "audit mutation"
    );
    Ok(HttpResponse::Ok().json(ActionResponse { success }))
}

#[utoipa::path(delete, path = "/policy/groups/{group_name}/users/{user_id}", tag = "policy", params(("group_name" = String, Path), ("user_id" = String, Path)), responses((status = 200, body = ActionResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 403, body = crate::http::error::ErrorBody)))]
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
    tracing::info!(
        subject = %auth_claims.sub,
        action = "group.remove",
        target = %format!("{} -> {}", user_id, group_name),
        "audit mutation"
    );
    let success = policy_engine.remove_from_group(user_id, group_name).await?;

    Ok(HttpResponse::Ok().json(ActionResponse { success }))
}

/// Paginated group listing.
#[derive(Serialize, utoipa::ToSchema)]
pub struct GroupsResponse {
    /// Page of groups with member counts.
    pub items: Vec<GroupSummary>,
    /// Total number of known groups.
    pub total: usize,
    /// Effective page size after capping.
    pub limit: usize,
    /// Offset this page starts at.
    pub offset: usize,
}

/// Paginated user-assignment listing.
#[derive(Serialize, utoipa::ToSchema)]
pub struct UsersResponse {
    /// Page of subjects with their groups.
    pub items: Vec<UserAssignment>,
    /// Total number of subjects holding memberships.
    pub total: usize,
    /// Effective page size after capping.
    pub limit: usize,
    /// Offset this page starts at.
    pub offset: usize,
}

/// Lists every known group with member counts.
#[utoipa::path(get, path = "/policy/groups", tag = "policy", params(ListQuery), responses((status = 200, body = GroupsResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 403, body = crate::http::error::ErrorBody)))]
#[get("/groups")]
async fn list_groups(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    query: web::Query<ListQuery>,
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
    let page = Page::from_query(&query);
    Ok(HttpResponse::Ok().json(GroupsResponse {
        items: page.apply(all),
        total,
        limit: page.limit,
        offset: page.offset,
    }))
}

/// Lists every subject holding group memberships.
#[utoipa::path(get, path = "/policy/users", tag = "policy", params(ListQuery), responses((status = 200, body = UsersResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 403, body = crate::http::error::ErrorBody)))]
#[get("/users")]
async fn list_users(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
    query: web::Query<ListQuery>,
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
    let page = Page::from_query(&query);
    Ok(HttpResponse::Ok().json(UsersResponse {
        items: page.apply(all),
        total,
        limit: page.limit,
        offset: page.offset,
    }))
}

/// Deletes a group together with every membership link to it.
#[utoipa::path(delete, path = "/policy/groups/{group_name}", tag = "policy", params(("group_name" = String, Path)), responses((status = 200, body = ActionResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 403, body = crate::http::error::ErrorBody)))]
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
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::http::middleware::jwt::{Claims, JwtClaimsMiddleware};
    use crate::policy::PolicyEngine;

    const KID: &str = "policy-route-test-kid";
    const AUD: &str = "test-aud";

    /// A fencing loss is a 500 that says so in the log and says nothing in the
    /// body.
    ///
    /// Both halves matter. The client must not learn the reason from the
    /// store, because `ApiError::Internal` only ever renders its fixed
    /// `Display`. The operator must be able to tell this apart from any
    /// other 500. Lifting the variant out of casbin exists for that reason.
    /// The text that `ApiError` logs for a cause is the only thing that
    /// reaches a log line, so the wording is the mechanism.
    #[test]
    fn a_fencing_loss_is_a_500_with_a_sanitized_body() {
        use crate::http::error::ApiError;
        use actix_web::ResponseError as _;
        use actix_web::body::MessageBody as _;
        use std::error::Error as _;

        let api: ApiError = PolicyError::Fenced("epoch 7 superseded".into()).into();
        assert_eq!(
            api.status_code(),
            actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
        );

        // Nothing about the store reaches the wire.
        assert_eq!(api.to_string(), "internal server error");
        let body = api.error_response();
        assert!(
            !String::from_utf8_lossy(&body.into_body().try_into_bytes().unwrap())
                .contains("epoch 7"),
            "the fencing reason must not be serialized to the client"
        );

        // The log line is searchable, and it matches the `fs` wording. One
        // query therefore finds a fencing loss on either store.
        let logged = api
            .source()
            .expect("the cause is retained for logging")
            .to_string();
        assert!(
            logged.contains("store epoch lost to another writer"),
            "{logged}"
        );
        assert!(logged.contains("epoch 7 superseded"), "{logged}");
    }

    struct Fixture {
        server: wiremock::MockServer,
        enc: EncodingKey,
        engine: PolicyEngine,
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
        let prefix = crate::db::test_prefix("policy-route");
        let s3 = crate::db::build_test_store(&prefix).await;
        let engine = PolicyEngine::init_s3(s3).await?;
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
        })
    }

    fn rule(sub: &str) -> Vec<String> {
        vec![sub.to_string(), "obj".to_string(), "read".to_string()]
    }

    #[test]
    fn page_slices_caps_and_defaults() {
        let rules: Vec<Vec<String>> = (0..10).map(|i| rule(&format!("u{i}"))).collect();

        // The default limit of 100 is larger than this list, so the function
        // returns the whole set.
        assert_eq!(
            Page::from_query(&ListQuery {
                limit: None,
                offset: None
            })
            .apply(rules.clone()),
            rules
        );

        // The offset slices the list at the right position.
        let page = Page::from_query(&ListQuery {
            limit: Some(3),
            offset: Some(4),
        });
        assert_eq!(page.apply(rules.clone()), rules[4..7].to_vec());

        // A limit above MAX_PAGE_SIZE is capped. The response
        // echoes back the capped value.
        let big: Vec<Vec<String>> = (0..(MAX_PAGE_SIZE + 50)).map(|_| rule("x")).collect();
        let capped = Page::from_query(&ListQuery {
            limit: Some(MAX_PAGE_SIZE * 2),
            offset: Some(0),
        });
        assert_eq!(capped.limit, MAX_PAGE_SIZE);
        assert_eq!(capped.apply(big.clone()).len(), MAX_PAGE_SIZE);

        // An offset past the end returns an empty page, not a panic.
        let past_end = Page::from_query(&ListQuery {
            limit: Some(3),
            offset: Some(99),
        });
        assert!(past_end.apply(rules.clone()).is_empty());
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
    async fn rule_crud_over_http() -> anyhow::Result<()> {
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
        // The function adds a rule.
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
        // A duplicate add returns false.
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
        // The function reads the rules with pagination.
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
        assert_eq!(body["items"].as_array().map(|a| a.len()).unwrap_or(0), 1);
        // The function removes the rule.
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
    async fn group_crud_over_http() -> anyhow::Result<()> {
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
        // The function assigns a group.
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
        // The function reads the groups of a user.
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
        // The function reads the users of a group.
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
        // The function lists the groups.
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/groups?limit=1")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        // The function lists the users.
        let res = actix_web::test::call_service(
            &app,
            actix_web::test::TestRequest::get()
                .uri("/policy/users?limit=1")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        // The function removes a user from a group.
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
        // The function deletes a group. A group that does not exist
        // returns false, but the status is still 200.
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
        // The engine creates a group with one member directly. The test
        // then covers the branches of pagination in the delete_group
        // handler.
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
        // The functions check the offset and limit caps for groups and
        // users.
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
