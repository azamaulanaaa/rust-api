//! One-time bootstrap endpoint. It assigns an authenticated account the
//! built-in [`SUPERADMIN_ROLE`] while no other superadmin exists.
//!
//! A fresh deployment starts with an empty policy store. Nobody can pass
//! the self-authorization checks on the `/policy` routes. This module
//! closes that gap. The first authenticated user that calls
//! `POST /setup/admin` claims the superadmin role. Every later call is a
//! hard conflict (409). This holds even after a restart. The claim check
//! and the write share one lock. That lock covers the persisted state of
//! the enforcer.

use std::sync::Arc;

use actix_web::{HttpResponse, Responder, post, web};
use serde::Serialize;

use super::{PolicyEngine, SUPERADMIN_ROLE};
use crate::http::{
    ApiModule,
    error::ApiError,
    middleware::jwt::{Claims, JwtClaimsMiddleware, Validated},
};

/// API module exposing the one-time `/setup/admin` bootstrap route. The
/// module uses JWT validation only, because authorization is impossible.
/// The store starts with no roles at all.
pub struct SetupApiModule {
    policy_engine: Arc<PolicyEngine>,
    jwt_middleware: JwtClaimsMiddleware<Claims>,
}

impl SetupApiModule {
    /// Wraps a [`PolicyEngine`] with the given JWT middleware. Pass a clone
    /// of the engine that other modules share, because all clones see one
    /// policy state.
    pub fn new(policy_engine: PolicyEngine, jwt_middleware: JwtClaimsMiddleware<Claims>) -> Self {
        Self {
            policy_engine: Arc::new(policy_engine),
            jwt_middleware,
        }
    }
}

impl ApiModule for SetupApiModule {
    fn prefix(&self) -> &str {
        "/setup"
    }

    fn configure(&self, cfg: &mut web::ServiceConfig) {
        let policy_engine = web::Data::from(self.policy_engine.clone());
        let jwt_middleware = self.jwt_middleware.clone();

        let scope = web::scope("/setup")
            .app_data(policy_engine)
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
#[utoipa::path(post, path = "/setup/admin", tag = "setup", responses((status = 201, body = SetupResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 409, body = crate::http::error::ErrorBody)))]
#[post("/admin")]
async fn claim_admin(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
) -> Result<impl Responder, ApiError> {
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
    async fn setup_module(fx: &Fixture) -> anyhow::Result<SetupApiModule> {
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
                latch: fx.engine.latch,
            },
            middleware,
        ))
    }

    #[actix_web::test]
    async fn first_claim_succeeds_then_conflicts() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = setup_module(&fx).await?;
        let app =
            test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                .await;

        // The first authenticated caller wins.
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
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
                .insert_header(("Cookie", format!("auth_token={}", fx.token("mallory")?)))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 409);

        Ok(())
    }

    #[actix_web::test]
    async fn unauthenticated_call_is_unauthorized() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = setup_module(&fx).await?;
        let app =
            test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                .await;

        let res = test::call_service(
            &app,
            test::TestRequest::post().uri("/setup/admin").to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED);

        // Nothing was granted by the rejected call.
        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
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
            let module = setup_module(&fx).await?;
            let app =
                test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                    .await;
            let res = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/setup/admin")
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
            latch: reopened.latch,
        };
        let middleware =
            JwtClaimsMiddleware::<Claims>::new_with_jks(&jwks_url, AUDIENCE, &issuer).await?;
        let module = SetupApiModule::new(engine_clone, middleware);
        let app =
            test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                .await;

        let res = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/setup/admin")
                .insert_header(("Cookie", format!("auth_token={bob_token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 409);

        Ok(())
    }
}
