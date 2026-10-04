//! Actix routes for the OIDC login, callback, session, and logout flows.
//!
//! [`OidcApiModule`](crate::oidc::route::OidcApiModule) owns the provider
//! client and the whole `/auth` scope. The scope holds `/auth/login`,
//! `/auth/callback`, `/auth/logout`, and the `/auth/me` session probe. The
//! module also seeds the JWT validation middleware that every other module
//! reuses.
//!
//! This file has one module, not a public-flow module plus a session module,
//! because actix matches scopes by prefix. If two modules register
//! `web::scope("/auth")`, the module registered first swallows every
//! `/auth/*` path and the routes of the other module are unreachable. One
//! module owns one prefix.

use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, Responder,
    cookie::{Cookie, SameSite, time::Duration},
    get, post, web,
};
use openidconnect::{Nonce, PkceCodeVerifier};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{OidcClient, OidcError};
use crate::http::middleware::jwt::{Audience, Validated};
use crate::http::{ApiModule, middleware};

/// API module exposing the `/auth` routes and owning the JWT validation
/// middleware configured from the discovered provider.
pub struct OidcApiModule<C>
where
    C: DeserializeOwned,
{
    oidc_client: Arc<OidcClient>,
    jwt_middleware: middleware::jwt::JwtClaimsMiddleware<C>,
    /// Middleware for `/auth/me` only.
    ///
    /// `C` is the claims type of the host app. The route `me` has to answer
    /// with the concrete [`Claims`](middleware::jwt::Claims) shape that the
    /// SPA codegen depends on, so it needs its own middleware. The single
    /// `/auth/me` resource keeps this middleware. That is what lets the rest
    /// of the scope stay generic. The scope itself never has to name
    /// `Claims`.
    session_middleware: middleware::jwt::JwtClaimsMiddleware<middleware::jwt::Claims>,
}

impl<C> OidcApiModule<C>
where
    C: DeserializeOwned,
{
    /// Builds the module. It loads the provider's JWKS once to seed the JWT
    /// validation middleware. The audience is the client ID. The issuer is
    /// the provider.
    pub async fn init(oidc_client: OidcClient) -> anyhow::Result<Self> {
        let jwt_middleware = middleware::jwt::JwtClaimsMiddleware::new_with_jks(
            oidc_client.jwks_uri().as_str(),
            oidc_client.client_id().as_str(),
            oidc_client.issuer(),
        )
        .await?
        .with_allowed_tenants(oidc_client.allowed_tenants().to_vec());

        // This uses the same provider and the same keys, but a different
        // claims type. Loading the JWKS twice costs one extra request at
        // startup. It keeps `/auth/me` able to answer for a host app that
        // gives its own claims type any value other than `Claims`.
        let session_middleware = middleware::jwt::JwtClaimsMiddleware::new_with_jks(
            oidc_client.jwks_uri().as_str(),
            oidc_client.client_id().as_str(),
            oidc_client.issuer(),
        )
        .await?
        .with_allowed_tenants(oidc_client.allowed_tenants().to_vec());

        Ok(Self {
            oidc_client: Arc::new(oidc_client),
            jwt_middleware,
            session_middleware,
        })
    }

    /// Returns a clone of this module's JWT validation middleware so other
    /// modules can protect their routes with the same provider keys.
    pub fn middleware(&self) -> middleware::jwt::JwtClaimsMiddleware<C>
    where
        C: Clone,
    {
        self.jwt_middleware.clone()
    }
}

impl<C> ApiModule for OidcApiModule<C>
where
    C: DeserializeOwned + Clone + Send + Sync + 'static,
{
    fn prefix(&self) -> &str {
        "/auth"
    }

    fn configure(&self, cfg: &mut web::ServiceConfig) {
        let oidc_client = web::Data::from(self.oidc_client.clone());

        // The JWT wrap is safe for the public routes. A request without any
        // token passes through unmodified. The route `/auth/me` gets its own
        // `Claims`-typed middleware on the resource instead. The scope
        // therefore does not have to name a concrete claims type.
        //
        // The whole scope lives here on purpose. A second module that
        // registers `web::scope("/auth")` matches every `/auth/*` path. Actix
        // tries services in registration order, so the routes of the later
        // module stay unreachable instead of merging.
        cfg.service(
            web::scope("/auth")
                .app_data(oidc_client)
                .wrap(self.jwt_middleware.clone())
                .service(login)
                .service(callback)
                .service(logout)
                .service(
                    web::resource("/me")
                        .wrap(self.session_middleware.clone())
                        .route(web::get().to(me)),
                ),
        );
    }
}

/// Authenticated session probe returned by `GET /auth/me`.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct MeResponse {
    /// Stable user identifier (`sub` claim).
    pub sub: String,
    /// Issuer that minted the token (`iss` claim).
    pub iss: String,
    /// Audience(s) the token was issued for.
    pub aud: Vec<String>,
    /// Expiration time (unix seconds).
    pub exp: u64,
}

/// Returns the caller's session (`401` without valid credentials).
///
/// This route is the entry point for the SPA. The TanStack guards and the
/// worker poll it instead of decoding the JWT themselves. A change in the
/// claim shape then breaks the codegen instead of silently authorizing the
/// wrong data.
///
/// The route uses an explicit `web::resource` and not a `#[get]` attribute.
/// The route needs its own `Claims`-typed middleware, and only a resource
/// can carry one.
#[utoipa::path(get, path = "/auth/me", tag = "auth", responses((status = 200, body = MeResponse), (status = 401, body = crate::http::error::ErrorBody)))]
pub async fn me(claims: Validated<middleware::jwt::Claims>) -> impl Responder {
    let aud = match &claims.aud {
        Audience::Single(s) => vec![s.clone()],
        Audience::Multi(v) => v.clone(),
    };
    HttpResponse::Ok().json(MeResponse {
        sub: claims.sub.clone(),
        iss: claims.iss.clone(),
        aud,
        exp: claims.exp,
    })
}

/// Clears the `auth_token` session cookie (always `204`, even anonymous).
///
/// The route uses `POST` and not `GET`. Prefetchers and links that can cause
/// a CSRF therefore cannot log the user out. The cleared cookie copies the
/// `Secure` and `SameSite` flags of the login cookie, so browsers drop it.
#[utoipa::path(post, path = "/auth/logout", tag = "auth", responses((status = 204, description = "logged out")))]
#[post("/logout")]
pub async fn logout(oidc_client: web::Data<OidcClient>) -> impl Responder {
    HttpResponse::NoContent()
        .cookie(clear_cookie(
            "auth_token".to_string(),
            oidc_client.secure_cookies(),
        ))
        .finish()
}

/// Starts the OIDC authorization-code flow (redirects to the provider).
#[utoipa::path(get, path = "/auth/login", tag = "auth", responses((status = 302, description = "redirect to provider")))]
#[get("/login")]
pub async fn login(oidc_client: web::Data<OidcClient>) -> impl Responder {
    let auth_data = oidc_client.get_auth_url();
    let cookie_duration = Duration::minutes(5);
    let secure = oidc_client.secure_cookies();

    let base_cookie = |name: &'static str, value: String| {
        Cookie::build(name, value)
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(cookie_duration)
            .path("/")
            .finish()
    };

    HttpResponse::Found()
        .append_header(("Location", auth_data.url))
        .cookie(base_cookie(
            "oidc_csrf",
            auth_data.csrf_token.secret().to_string(),
        ))
        .cookie(base_cookie(
            "oidc_nonce",
            auth_data.nonce.secret().to_string(),
        ))
        .cookie(base_cookie(
            "oidc_pkce",
            auth_data.pkce_verifier.secret().to_string(),
        ))
        .finish()
}

/// Query parameters the OIDC provider appends when redirecting back to
/// `/auth/callback`.
#[derive(Deserialize)]
pub struct AuthCallbackQuery {
    /// Authorization code issued by the provider.
    pub code: String,
    /// OAuth2 `state` value. It must match the CSRF cookie.
    pub state: String,
}

/// JSON body returned by `/auth/callback` describing the login outcome.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuthResponse {
    /// Whether authentication completed successfully.
    pub success: bool,
    /// The validated ID token on success (also set as a cookie).
    pub token: Option<String>,
    /// Human-readable failure reason on error.
    pub error: Option<String>,
}

/// OIDC authorization-code callback (validates state/nonce/PKCE, sets the session cookie).
#[utoipa::path(get, path = "/auth/callback", tag = "auth", params(("code" = String, Query), ("state" = String, Query)), responses((status = 200, body = AuthResponse), (status = 400, body = AuthResponse), (status = 401, body = AuthResponse)))]
#[get("/callback")]
pub async fn callback(
    oidc_client: web::Data<OidcClient>,
    query: web::Query<AuthCallbackQuery>,
    req: HttpRequest,
) -> impl Responder {
    let cookies = (
        req.cookie("oidc_csrf"),
        req.cookie("oidc_nonce"),
        req.cookie("oidc_pkce"),
    );

    let (Some(csrf), Some(nonce), Some(pkce)) = cookies else {
        return HttpResponse::BadRequest().json(AuthResponse {
            success: false,
            token: None,
            error: Some("Session expired or security cookies missing".to_string()),
        });
    };

    if query.state != csrf.value() {
        return HttpResponse::Unauthorized().json(AuthResponse {
            success: false,
            token: None,
            error: Some("Invalid state parameter".to_string()),
        });
    }

    let nonce_val = Nonce::new(nonce.value().to_string());
    let pkce_val = PkceCodeVerifier::new(pkce.value().to_string());

    match oidc_client
        .exchange_code(query.code.clone(), nonce_val, pkce_val)
        .await
    {
        Ok(token_string) => {
            let secure = oidc_client.secure_cookies();
            let auth_cookie = Cookie::build("auth_token", token_string.clone())
                .path("/")
                .http_only(true)
                .secure(secure)
                .same_site(SameSite::Lax)
                .max_age(Duration::days(7))
                .finish();

            HttpResponse::Ok()
                .cookie(clear_cookie("oidc_csrf".to_string(), secure))
                .cookie(clear_cookie("oidc_nonce".to_string(), secure))
                .cookie(clear_cookie("oidc_pkce".to_string(), secure))
                .cookie(auth_cookie)
                .json(AuthResponse {
                    success: true,
                    token: Some(token_string),
                    error: None,
                })
        }
        Err(e) => {
            // The server logs receive the full detail. Clients only ever see a stable,
            // non-sensitive message.
            let (status, message) = match &e {
                OidcError::ExchangeFailure(_)
                | OidcError::MissingIdToken
                | OidcError::InvalidToken(_) => {
                    tracing::warn!("OIDC code exchange rejected: {e}");
                    (
                        actix_web::http::StatusCode::UNAUTHORIZED,
                        "authentication failed",
                    )
                }
                other => {
                    tracing::error!("OIDC callback failed unexpectedly: {other:?}");
                    (
                        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "internal server error",
                    )
                }
            };
            HttpResponse::build(status).json(AuthResponse {
                success: false,
                token: None,
                error: Some(message.to_string()),
            })
        }
    }
}

fn clear_cookie(name: String, secure: bool) -> Cookie<'static> {
    Cookie::build(name, "")
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(Duration::ZERO)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::oidc::OidcConfig;
    use actix_web::{dev::ServiceResponse, http::header::LOCATION, test};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
    use serde_json::json;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CLIENT_ID: &str = "test-client";

    /// A mock OIDC provider, the API module wired to it, and the RSA
    /// signing key that matches the served JWKS.
    struct Fixture {
        server: MockServer,
        module: OidcApiModule<serde_json::Value>,
        encoding_key: EncodingKey,
    }

    impl Fixture {
        async fn new() -> anyhow::Result<Self> {
            let server = MockServer::start().await;

            let mut rng = rand::thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
            let public_key = RsaPublicKey::from(&private_key);

            Mock::given(method("GET"))
                .and(path("/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "keys": [{
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "test-key-id",
                        "alg": "RS256",
                        "n": URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                        "e": URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
                    }]
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "issuer": server.uri(),
                    "authorization_endpoint": format!("{}/auth", server.uri()),
                    "token_endpoint": format!("{}/token", server.uri()),
                    "jwks_uri": format!("{}/jwks", server.uri()),
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                })))
                .mount(&server)
                .await;

            let oidc_client = OidcClient::new(OidcConfig {
                client_id: CLIENT_ID.to_string(),
                client_secret: "test-secret".to_string(),
                issuer_url: server.uri(),
                redirect_url: "http://localhost/callback".to_string(),
                allowed_tenants: Vec::new(),
            })
            .await?;

            Ok(Self {
                module: OidcApiModule::init(oidc_client).await?,
                server,
                encoding_key: EncodingKey::from_rsa_der(private_key.to_pkcs1_der()?.as_bytes()),
            })
        }
    }

    /// Builds a test app that exposes the routes of the module. This code
    /// stays inline per test, so that actix always infers the service type
    /// as a concrete type.
    macro_rules! test_app {
        ($fixture:expr) => {
            test::init_service(actix_web::App::new().configure(|cfg| {
                ApiModule::configure(&$fixture.module, cfg);
            }))
            .await
        };
    }

    /// Extracts the CSRF, nonce, and PKCE cookie values, plus the
    /// authorization code and state parameters, from a completed
    /// `GET /auth/login` response.
    fn login_parts(res: &ServiceResponse) -> anyhow::Result<(String, String, String, String)> {
        assert_eq!(res.status(), 302);

        let location = Url::parse(
            res.response()
                .headers()
                .get(LOCATION)
                .expect("redirect Location header")
                .to_str()
                .unwrap(),
        )?;
        let query: std::collections::HashMap<String, String> =
            location.query_pairs().into_owned().collect();

        let cookie_value = |name: &str| {
            res.response()
                .cookies()
                .find(|c| c.name() == name)
                .map(|c| c.value().to_string())
                .expect("login must set security cookies")
        };

        Ok((
            cookie_value("oidc_csrf"),
            cookie_value("oidc_nonce"),
            cookie_value("oidc_pkce"),
            query["state"].clone(),
        ))
    }

    /// Builds the Cookie header value carrying the three security cookies.
    fn cookie_header(csrf: &str, nonce: &str, pkce: &str) -> String {
        format!("oidc_csrf={csrf}; oidc_nonce={nonce}; oidc_pkce={pkce}")
    }

    #[tokio::test]
    async fn login_redirects_to_provider_with_security_cookies() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        let res = test::call_service(
            &svc,
            test::TestRequest::get().uri("/auth/login").to_request(),
        )
        .await;
        assert_eq!(res.status(), 302);

        let location = Url::parse(
            res.response()
                .headers()
                .get(LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(location.host_str().unwrap(), "127.0.0.1"); // The mock provider.
        let query: std::collections::HashMap<String, String> =
            location.query_pairs().into_owned().collect();
        assert_eq!(query["client_id"], CLIENT_ID);
        assert_eq!(query["response_type"], "code");
        assert!(
            query.get("code_challenge").is_some_and(|c| !c.is_empty()),
            "PKCE challenge must be present"
        );

        for name in ["oidc_csrf", "oidc_nonce", "oidc_pkce"] {
            let cookie = res
                .response()
                .cookies()
                .find(|c| c.name() == name)
                .unwrap_or_else(|| panic!("missing {name} cookie"));
            assert_eq!(cookie.http_only(), Some(true), "{name} must be HttpOnly");
            // The callback in the fixture is plain http, so the cookie
            // omits the Secure flag. The cookie crate reports the missing
            // flag as None. The test `secure_scheme_https_only` in
            // `oidc::tests` pins the https behavior instead. The HttpOnly and
            // SameSite flags still hold.
            assert_eq!(cookie.secure(), None, "{name} omits Secure on http");
            assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        }
    }

    #[tokio::test]
    async fn callback_without_cookies_is_400() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        let req = test::TestRequest::get()
            .uri("/auth/callback?code=x&state=y")
            .to_request();
        let res = test::call_service(&svc, req).await;

        assert_eq!(res.status(), 400);
        let body: AuthResponse = serde_json::from_slice(&test::read_body(res).await).unwrap();
        assert!(!body.success);
        assert!(
            body.error
                .as_deref()
                .is_some_and(|e| e.contains("cookies missing"))
        );
    }

    #[tokio::test]
    async fn callback_with_tampered_state_is_401() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);
        let login_res = test::call_service(
            &svc,
            test::TestRequest::get().uri("/auth/login").to_request(),
        )
        .await;
        let (csrf, nonce, pkce, _state) = login_parts(&login_res).unwrap();

        let req = test::TestRequest::get()
            .uri("/auth/callback?code=abc&state=tampered")
            .insert_header(("Cookie", cookie_header(&csrf, &nonce, &pkce)))
            .to_request();
        let res = test::call_service(&svc, req).await;

        assert_eq!(res.status(), 401);
        let body: AuthResponse = serde_json::from_slice(&test::read_body(res).await).unwrap();
        assert_eq!(body.error.as_deref(), Some("Invalid state parameter"));
    }

    #[tokio::test]
    async fn callback_with_valid_code_returns_token_and_clears_cookies() -> anyhow::Result<()> {
        let fx = Fixture::new().await?;
        let svc = test_app!(fx);
        let login_res = test::call_service(
            &svc,
            test::TestRequest::get().uri("/auth/login").to_request(),
        )
        .await;
        let (csrf, nonce, pkce, state) = login_parts(&login_res)?;
        let code = "test-code";

        // This mints an ID token whose nonce matches the cookie from the
        // login, so the mocked token response passes the full validation of
        // the provider.
        let header = {
            let mut h = Header::new(jsonwebtoken::Algorithm::RS256);
            h.kid = Some("test-key-id".to_string());
            h
        };
        let claims = json!({
            "iss": fx.server.uri(),
            "sub": "user-123",
            "aud": CLIENT_ID,
            "exp": 2_000_000_000i64,
            "iat": 1_000_000_000i64,
            "nonce": nonce,
        });
        let id_token = encode(&header, &claims, &fx.encoding_key)?;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mock-access",
                "token_type": "Bearer",
                "id_token": id_token,
            })))
            .mount(&fx.server)
            .await;

        let req = test::TestRequest::get()
            .uri(&format!("/auth/callback?code={code}&state={state}"))
            .insert_header(("Cookie", cookie_header(&csrf, &nonce, &pkce)))
            .to_request();
        let res = test::call_service(&svc, req).await;

        assert_eq!(res.status(), 200);
        // The code reads the cookies before read_body consumes the response.
        let auth_cookie = res
            .response()
            .cookies()
            .find(|c| c.name() == "auth_token")
            .expect("auth_token cookie must be set")
            .value()
            .to_string();
        for name in ["oidc_csrf", "oidc_nonce", "oidc_pkce"] {
            let cookie = res
                .response()
                .cookies()
                .find(|c| c.name() == name)
                .unwrap_or_else(|| panic!("{name} must be cleared"));
            assert_eq!(
                cookie.max_age(),
                Some(Duration::ZERO),
                "{name} must be cleared"
            );
        }

        let body: AuthResponse = serde_json::from_slice(&test::read_body(res).await)?;
        assert!(body.success);
        assert!(body.error.is_none());

        assert_eq!(auth_cookie, body.token.as_deref().unwrap_or_default());
        Ok(())
    }

    /// Signs a session JWT the module's JWKS middleware accepts.
    fn session_token(fx: &Fixture, sub: &str, issuer: &str) -> anyhow::Result<String> {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("test-key-id".to_string());
        encode(
            &header,
            &json!({
                "iss": issuer,
                "sub": sub,
                "aud": CLIENT_ID,
                "exp": 2_000_000_000i64,
                "iat": 1_000_000_000i64,
            }),
            &fx.encoding_key,
        )
        .map_err(anyhow::Error::from)
    }

    /// The session probe has to survive being served from the same scope
    /// as the public flow.
    ///
    /// This test used to register `OidcSessionModule` next to
    /// `OidcApiModule`. Both claimed `web::scope("/auth")`. Actix tries
    /// services in registration order, and a scope matches its whole prefix.
    /// The first scope therefore swallowed every `/auth/*` path, and
    /// `/auth/me` was a `404` in the shipped server. The old test passed
    /// because it mounted the session module alone. The composition is what
    /// matters, so this test composes the modules.
    #[tokio::test]
    async fn me_returns_session_for_valid_cookie() -> anyhow::Result<()> {
        let fx = Fixture::new().await?;
        let svc = test_app!(fx);

        let token = session_token(&fx, "alice", &fx.server.uri())?;
        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/auth/me")
                .insert_header(("Cookie", format!("auth_token={token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 200);
        let body: MeResponse = serde_json::from_slice(&test::read_body(res).await)?;
        assert_eq!(body.sub, "alice");
        assert_eq!(body.iss, fx.server.uri());
        assert_eq!(body.aud, vec![CLIENT_ID.to_string()]);

        // An anonymous probe is a 401, never a 500.
        let res =
            test::call_service(&svc, test::TestRequest::get().uri("/auth/me").to_request()).await;
        assert_eq!(res.status(), 401);
        Ok(())
    }

    #[tokio::test]
    async fn logout_clears_session_cookie() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        let res = test::call_service(
            &svc,
            test::TestRequest::post().uri("/auth/logout").to_request(),
        )
        .await;
        assert_eq!(res.status(), 204);
        let cookie = res
            .response()
            .cookies()
            .find(|c| c.name() == "auth_token")
            .expect("logout must clear auth_token");
        assert_eq!(cookie.max_age(), Some(Duration::ZERO));
    }

    #[tokio::test]
    async fn callback_with_failing_exchange_is_401_without_leaking_details() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);
        let login_res = test::call_service(
            &svc,
            test::TestRequest::get().uri("/auth/login").to_request(),
        )
        .await;
        let (csrf, nonce, pkce, state) = login_parts(&login_res).unwrap();
        let code = "test-code";

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&fx.server)
            .await;

        let req = test::TestRequest::get()
            .uri(&format!("/auth/callback?code={code}&state={state}"))
            .insert_header(("Cookie", cookie_header(&csrf, &nonce, &pkce)))
            .to_request();
        let res = test::call_service(&svc, req).await;

        assert_eq!(res.status(), 401);
        let body: AuthResponse = serde_json::from_slice(&test::read_body(res).await).unwrap();
        assert!(!body.success);
        // The details of a provider failure never reach the client.
        assert_eq!(body.error.as_deref(), Some("authentication failed"));
    }
}
