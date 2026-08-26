//! One-time bootstrap endpoint: assigns an authenticated account the
//! built-in [`SUPERADMIN_ROLE`] while no other superadmin exists.
//!
//! Fresh deployments boot with an empty policy store, so nobody can pass
//! the self-authorization checks on `/policy` routes. This module closes
//! that chicken-and-egg gap: the first authenticated user to call
//! `POST /setup/admin` claims the superadmin role; every later call is a
//! hard conflict (409), including after restarts, because the claim check
//! and write share one lock over the persisted enforcer state.

use std::sync::Arc;

use actix_web::{HttpResponse, Responder, post, web};
use serde::Serialize;

use super::{PolicyEngine, SUPERADMIN_ROLE};
use crate::endpoint::{
    ApiModule,
    error::ApiError,
    middleware::jwt::{Claims, JwtClaimsMiddleware, Validated},
};

/// API module exposing the one-time `/setup/admin` bootstrap route,
/// protected by JWT validation only (authorization would be impossible:
/// the store starts with no roles at all).
pub struct SetupApiModule {
    policy_engine: Arc<PolicyEngine>,
    jwt_middleware: JwtClaimsMiddleware<Claims>,
}

impl SetupApiModule {
    /// Wraps a [`PolicyEngine`] with the given JWT middleware. Pass a
    /// clone of the engine shared with other modules; clones see one
    /// policy state.
    pub fn new(policy_engine: PolicyEngine, jwt_middleware: JwtClaimsMiddleware<Claims>) -> Self {
        Self {
            policy_engine: Arc::new(policy_engine),
            jwt_middleware,
        }
    }
}

impl ApiModule for SetupApiModule {
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
#[derive(Serialize)]
struct SetupResponse<'a> {
    /// Subject that was granted the role.
    sub: &'a str,
    /// The role that was granted.
    role: &'static str,
}

/// Grants the caller the superadmin role if nobody holds it yet.
#[post("/admin")]
async fn claim_admin(
    policy_engine: web::Data<PolicyEngine>,
    auth_claims: Validated<Claims>,
) -> Result<impl Responder, ApiError> {
    let claimed = policy_engine.claim_superadmin(&auth_claims.sub).await?;
    if !claimed {
        return Err(ApiError::Conflict("setup already completed".to_string()));
    }
    tracing::info!(
        "bootstrap: assigned {SUPERADMIN_ROLE} role to {}",
        auth_claims.sub
    );
    Ok(HttpResponse::Created().json(SetupResponse {
        sub: &auth_claims.sub,
        role: SUPERADMIN_ROLE,
    }))
}

#[cfg(test)]
mod tests {
    use actix_web::{App, http, test};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use super::*;
    use crate::endpoint::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};

    const KID: &str = "setup-test-key";
    const AUDIENCE: &str = "test-aud";

    struct Fixture {
        server: wiremock::MockServer,
        encoding_key: EncodingKey,
        store_path: std::path::PathBuf,
        engine: PolicyEngine,
    }

    async fn fixture() -> anyhow::Result<Fixture> {
        let (key, encoding_key) = rsa_key(KID)?;
        let jwks = json!({ "keys": [key] });
        let server = spawn_jwks(jwks).await;

        let store_path = std::env::temp_dir().join(format!(
            "rust-api-setup-test-{}-{}.redb",
            std::process::id(),
            uuid_like()
        ));
        let _ = std::fs::remove_file(&store_path);

        let engine = PolicyEngine::init(&store_path).await?;
        Ok(Fixture {
            server,
            encoding_key,
            store_path,
            engine,
        })
    }

    /// Suffix unique enough for parallel test processes on one machine.
    fn uuid_like() -> String {
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
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

    /// Builds the API module against the fixture's JWKS server and shared
    /// engine state; each test wires it into an inline app so actix service
    /// types stay concretely inferred.
    async fn setup_module(fx: &Fixture) -> SetupApiModule {
        let middleware = JwtClaimsMiddleware::<Claims>::new_with_jks(
            &format!("{}/jwks", fx.server.uri()),
            AUDIENCE,
            &fx.issuer(),
        )
        .await
        .expect("test jwks middleware must initialize");
        SetupApiModule::new(
            PolicyEngine {
                enforcer: fx.engine.enforcer.clone(),
            },
            middleware,
        )
    }

    #[actix_web::test]
    async fn first_claim_succeeds_then_conflicts() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = setup_module(&fx).await;
        let app =
            test::init_service(App::new().configure(|cfg| ApiModule::configure(&module, cfg)))
                .await;

        // First authenticated caller wins.
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

        // A different subject arriving afterwards is locked out.
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
        let module = setup_module(&fx).await;
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
            let module = setup_module(&fx).await;
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

        // Capture fixture data up front: dropping the engine partially
        // moves `fx`, so method borrows must happen before it.
        let bob_token = fx.token("bob")?;
        let issuer = fx.issuer();
        let jwks_url = format!("{}/jwks", issuer);

        // Release the first engine's store lock, then reopen the same
        // persisted state as a fresh engine.
        drop(fx.engine);
        let reopened = PolicyEngine::init(&fx.store_path).await?;
        let engine_clone = PolicyEngine {
            enforcer: reopened.enforcer.clone(),
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

        let _ = std::fs::remove_file(&fx.store_path);
        Ok(())
    }
}
