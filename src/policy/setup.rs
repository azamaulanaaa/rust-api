//! One-time bootstrap endpoint. It assigns an authenticated account the
//! built-in [`SUPERADMIN_ROLE`] while no other superadmin exists.
//!
//! A fresh deployment starts with an empty policy store. Nobody can pass
//! the self-authorization checks on the `/policy` routes. This module
//! closes that gap. The first authenticated user that calls
//! `POST /setup/admin` with the configured bootstrap secret claims the
//! superadmin role. Every later call is a hard conflict (409). This holds
//! even after a restart. The claim check and the write share one lock. That
//! lock covers the persisted state of the enforcer.
//!
//! The route is absent when `[authorization].setup_token` is unset. An
//! unconfigured deployment must not hand superadmin to the first caller.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, Responder, post, web};
use serde::Serialize;

use super::{PolicyEngine, SUPERADMIN_ROLE};
use crate::http::{
    ApiModule,
    error::ApiError,
    middleware::jwt::{Claims, JwtClaimsMiddleware, Validated},
};

/// The request header that carries the bootstrap secret.
const SETUP_TOKEN_HEADER: &str = "X-Setup-Token";

/// The configured bootstrap secret, as request data.
struct SetupToken(String);

/// The request presented a token that does not match the configured value.
#[derive(Debug, thiserror::Error)]
#[error("setup token mismatch")]
struct SetupTokenMismatch;

/// Compares two byte strings in constant time.
///
/// The function checks the length first. A length difference leaks only the
/// length. The byte comparison visits every position, so the time does not
/// depend on the first mismatch.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// API module exposing the one-time `/setup/admin` bootstrap route. The
/// module uses JWT validation only, because authorization is impossible.
/// The store starts with no roles at all.
pub struct SetupApiModule {
    policy_engine: Arc<PolicyEngine>,
    jwt_middleware: JwtClaimsMiddleware<Claims>,
    setup_token: Option<String>,
}

impl SetupApiModule {
    /// Wraps a [`PolicyEngine`] with the given JWT middleware and bootstrap
    /// secret. Pass a clone of the engine that other modules share, because
    /// all clones see one policy state. Pass `None` to disable the route.
    pub fn new(
        policy_engine: PolicyEngine,
        jwt_middleware: JwtClaimsMiddleware<Claims>,
        setup_token: Option<String>,
    ) -> Self {
        Self {
            policy_engine: Arc::new(policy_engine),
            jwt_middleware,
            setup_token,
        }
    }
}

impl ApiModule for SetupApiModule {
    fn prefix(&self) -> &str {
        "/setup"
    }

    fn configure(&self, cfg: &mut web::ServiceConfig) {
        // No token means no bootstrap path. The route is then absent, and
        // the request gets a 404.
        let Some(token) = &self.setup_token else {
            return;
        };
        let policy_engine = web::Data::from(self.policy_engine.clone());
        let jwt_middleware = self.jwt_middleware.clone();

        let scope = web::scope("/setup")
            .app_data(policy_engine)
            .app_data(web::Data::new(SetupToken(token.clone())))
            .wrap(jwt_middleware)
            .service(claim_admin);

        cfg.service(scope);
    }
}

/// Body of a successful bootstrap response.
#[derive(Serialize, utoipa::ToSchema)]
pub struct SetupResponse {
    /// Subject that was granted the role.
    pub sub: String,
    /// The role that was granted.
    pub role: String,
}

/// Grants the caller the superadmin role if nobody holds it yet.
#[utoipa::path(post, path = "/setup/admin", tag = "setup", params(("X-Setup-Token" = String, Header, description = "Bootstrap secret from [authorization].setup_token")), responses((status = 201, body = SetupResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 409, body = crate::http::error::ErrorBody)))]
#[post("/admin")]
async fn claim_admin(
    setup_token: web::Data<SetupToken>,
    req: HttpRequest,
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
) -> Result<impl Responder, ApiError> {
    let supplied = req
        .headers()
        .get(SETUP_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !constant_time_eq(supplied.as_bytes(), setup_token.0.as_bytes()) {
        return Err(ApiError::InvalidCredentials(Box::new(SetupTokenMismatch)));
    }

    let claimed = policy_engine.claim_superadmin(&auth_claims.sub).await?;
    if !claimed {
        return Err(ApiError::Conflict);
    }
    tracing::info!(
        "bootstrap: assigned {SUPERADMIN_ROLE} role to {}",
        auth_claims.sub
    );
    Ok(HttpResponse::Created().json(SetupResponse {
        sub: auth_claims.sub.clone(),
        role: SUPERADMIN_ROLE.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use actix_web::{App, http, test};
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use super::*;
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};

    const KID: &str = "setup-test-key";
    const AUDIENCE: &str = "test-aud";
    const SETUP_TOKEN: &str = "setup-token-that-is-at-least-32-bytes";

    struct Fixture {
        server: wiremock::MockServer,
        encoding_key: EncodingKey,
        store_prefix: String,
        shared_store: std::sync::Arc<dyn object_store::ObjectStore>,
        engine: PolicyEngine,
    }

    async fn fixture() -> anyhow::Result<Fixture> {
        let (key, encoding_key) = rsa_key(KID)?;
        let jwks = json!({ "keys": [key] });
        let server = spawn_jwks(jwks).await;

        let store_prefix = crate::db::test_prefix("setup");
        let shared_store = std::sync::Arc::new(object_store::memory::InMemory::new())
            as std::sync::Arc<dyn object_store::ObjectStore>;
        let s3 = crate::db::build_test_store_new_session(shared_store.clone(), &store_prefix).await;
        let engine = PolicyEngine::init_s3(s3).await?;
        Ok(Fixture {
            server,
            encoding_key,
            store_prefix,
            shared_store,
            engine,
        })
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
                    "aud": AUDIENCE,
                    "exp": 2000000000u64,
                }),
                KID,
                &self.encoding_key,
            )
        }
    }

    /// Builds the API module against the JWKS server and the shared engine
    /// state of the fixture. Each test wires the module into an inline app,
    /// so that actix infers the service types as concrete types.
    async fn setup_module(
        fx: &Fixture,
        setup_token: Option<&str>,
    ) -> anyhow::Result<SetupApiModule> {
        let middleware = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUDIENCE,
            &fx.issuer(),
        )
        .await?;
        Ok(SetupApiModule::new(
            PolicyEngine {
                enforcer: fx.engine.enforcer.clone(),
                feed: None,
                outbox: fx.engine.outbox.clone(),
                drain_lock: fx.engine.drain_lock.clone(),
                latch: fx.engine.latch,
            },
            middleware,
            setup_token.map(str::to_string),
        ))
    }

    #[actix_web::test]
    async fn first_claim_succeeds_then_conflicts() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = setup_module(&fx, Some(SETUP_TOKEN)).await?;
        let app =
            test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                .await;

        // The first authenticated caller wins.
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
                .insert_header((SETUP_TOKEN_HEADER, SETUP_TOKEN))
                .insert_header(("Cookie", format!("auth_token={}", fx.token("alice")?)))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 201);
        let body: serde_json::Value = test::read_body_json(res).await;
        assert_eq!(body["sub"], "alice");
        assert_eq!(body["role"], SUPERADMIN_ROLE);

        // A different subject that arrives afterwards is locked out.
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
                .insert_header((SETUP_TOKEN_HEADER, SETUP_TOKEN))
                .insert_header(("Cookie", format!("auth_token={}", fx.token("mallory")?)))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 409);

        Ok(())
    }

    /// An unset bootstrap secret must not leave an open route.
    ///
    /// The route is absent, so a deployment that forgot the secret cannot
    /// hand superadmin to the first authenticated caller.
    #[actix_web::test]
    async fn the_route_is_absent_when_no_setup_token_is_configured() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = setup_module(&fx, None).await?;
        let app =
            test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                .await;

        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
                .insert_header((SETUP_TOKEN_HEADER, SETUP_TOKEN))
                .insert_header(("Cookie", format!("auth_token={}", fx.token("alice")?)))
                .to_request(),
        )
        .await;

        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        Ok(())
    }

    /// A wrong bootstrap secret is an invalid credential.
    #[actix_web::test]
    async fn a_wrong_setup_token_is_unauthorized() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = setup_module(&fx, Some(SETUP_TOKEN)).await?;
        let app =
            test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                .await;
        let alice = fx.token("alice")?;

        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
                .insert_header((SETUP_TOKEN_HEADER, "wrong-token-that-is-at-least-32-bytes"))
                .insert_header(("Cookie", format!("auth_token={alice}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);

        // The rejected call granted nothing, so the right token still works.
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
                .insert_header((SETUP_TOKEN_HEADER, SETUP_TOKEN))
                .insert_header(("Cookie", format!("auth_token={alice}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CREATED);

        Ok(())
    }

    #[actix_web::test]
    async fn unauthenticated_call_is_unauthorized() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = setup_module(&fx, Some(SETUP_TOKEN)).await?;
        let app =
            test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                .await;

        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
                .insert_header((SETUP_TOKEN_HEADER, SETUP_TOKEN))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);

        // Nothing was granted by the rejected call.
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
                .insert_header((SETUP_TOKEN_HEADER, SETUP_TOKEN))
                .insert_header(("Cookie", format!("auth_token={}", fx.token("alice")?)))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 201);

        Ok(())
    }

    #[actix_web::test]
    async fn completed_setup_survives_restart() -> anyhow::Result<()> {
        let fx = fixture().await?;

        {
            let module = setup_module(&fx, Some(SETUP_TOKEN)).await?;
            let app =
                test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                    .await;
            let res = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/setup/admin")
                    .insert_header((SETUP_TOKEN_HEADER, SETUP_TOKEN))
                    .insert_header(("Cookie", format!("auth_token={}", fx.token("alice")?)))
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), 201);
        }

        // Capture the data of the fixture first. Dropping the engine
        // partially moves `fx`, so the method borrows must happen before
        // the drop.
        let bob_token = fx.token("bob")?;
        let issuer = fx.issuer();
        let jwks_url = format!("{}/jwks", issuer);

        // The first engine is released. The same persisted state then reopens
        // as a fresh engine.
        let prefix = fx.store_prefix.clone();
        let shared = fx.shared_store.clone();
        drop(fx.engine);
        let s3_reopened = crate::db::build_test_store_new_session(shared.clone(), &prefix).await;
        let reopened = PolicyEngine::init_s3(s3_reopened).await?;
        let engine_clone = PolicyEngine {
            enforcer: reopened.enforcer.clone(),
            feed: None,
            outbox: reopened.outbox.clone(),
            drain_lock: reopened.drain_lock.clone(),
            latch: reopened.latch,
        };
        let middleware =
            JwtClaimsMiddleware::<Claims>::new_with_jks(&jwks_url, AUDIENCE, &issuer).await?;
        let module = SetupApiModule::new(engine_clone, middleware, Some(SETUP_TOKEN.to_string()));
        let app =
            test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                .await;

        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
                .insert_header((SETUP_TOKEN_HEADER, SETUP_TOKEN))
                .insert_header(("Cookie", format!("auth_token={bob_token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 409);

        Ok(())
    }

    #[tokio::test]
    async fn constant_time_eq_matches_only_equal_values() {
        assert!(constant_time_eq(b"same-value", b"same-value"));
        assert!(!constant_time_eq(b"same-value", b"different-value"));
        assert!(!constant_time_eq(b"short", b"a-longer-value"));
        assert!(constant_time_eq(b"", b""));
    }
}
