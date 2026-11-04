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
    HttpRequest, HttpResponse, HttpResponseBuilder, Responder,
    cookie::{Cookie, SameSite, time::Duration},
    get,
    http::StatusCode,
    post, web,
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
                .service(refresh)
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

/// Clears the `auth_token` and `refresh_token` session cookies.
///
/// The route always returns `204`, even for an anonymous request or a failed
/// provider revocation. It uses `POST` and not `GET`. Prefetchers and links
/// that can cause a CSRF therefore cannot log the user out. The cleared
/// cookies copy the `Secure` and `SameSite` flags of the login cookie, so
/// browsers drop them.
///
/// When the provider advertises a revocation endpoint, the route starts a
/// best-effort RFC 7009 revocation of the refresh token. It does not wait for
/// the result. A failure is logged and does not change the response.
#[utoipa::path(post, path = "/auth/logout", tag = "auth", responses((status = 204, description = "logged out. Clears auth_token and refresh_token. Starts a best-effort RFC 7009 revocation.")))]
#[post("/logout")]
pub async fn logout(oidc_client: web::Data<OidcClient>, req: HttpRequest) -> impl Responder {
    let refresh_token = req
        .cookie("refresh_token")
        .map(|cookie| cookie.value().to_string());
    let secure = oidc_client.secure_cookies();

    if let Some(token) = refresh_token
        && oidc_client.has_revocation_endpoint()
    {
        let oidc_client = oidc_client.clone();
        tokio::spawn(async move {
            if let Err(e) = oidc_client.revoke_token(&token).await {
                tracing::warn!("OIDC token revocation failed: {e}");
            }
        });
    }

    HttpResponse::NoContent()
        .cookie(clear_cookie("auth_token".to_string(), secure))
        .cookie(clear_cookie("refresh_token".to_string(), secure))
        .finish()
}

/// Query parameters for `GET /auth/login`.
#[derive(Deserialize)]
pub struct LoginQuery {
    /// Optional relative path to open after the callback. The value must
    /// start with one `/`. Absolute URLs are rejected.
    pub return_to: Option<String>,
}

/// Checks that a return path is relative and stays on this site.
///
/// The path must start with exactly one `/`. The check rejects absolute
/// URLs, protocol-relative values, values with a scheme or a host, values
/// with a backslash, and control characters. A query and a fragment are
/// allowed.
fn is_valid_return_to(value: &str) -> bool {
    if !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.contains("%5c")
        || value.contains("%5C")
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let Ok(base) = url::Url::parse("http://localhost/") else {
        return false;
    };
    match base.join(value) {
        Ok(parsed) => parsed.scheme() == "http" && parsed.host_str() == Some("localhost"),
        Err(_) => false,
    }
}

/// Adds the `error` query parameter to a relative return path.
///
/// An existing `error` parameter stays unchanged. The function keeps an
/// existing query and fragment.
fn redirect_target(return_to: &str, error: Option<&str>) -> String {
    let Some(code) = error else {
        return return_to.to_string();
    };
    let (before_fragment, fragment) = match return_to.split_once('#') {
        Some((before_fragment, fragment)) => (before_fragment, Some(fragment)),
        None => (return_to, None),
    };
    let (_, query) = match before_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (before_fragment, None),
    };
    let has_error = query
        .map(|query| {
            query
                .split('&')
                .any(|pair| pair.split('=').next() == Some("error"))
        })
        .unwrap_or(false);

    let mut target = before_fragment.to_string();
    if !has_error {
        if before_fragment.ends_with('?') || before_fragment.ends_with('&') {
            target.push_str("error=");
        } else if query.is_some() {
            target.push_str("&error=");
        } else {
            target.push_str("?error=");
        }
        target.push_str(code);
    }
    if let Some(fragment) = fragment {
        target.push('#');
        target.push_str(fragment);
    }
    target
}

/// Clears the temporary OIDC flow cookies.
fn clear_auth_flow_cookies(response: &mut HttpResponseBuilder, secure: bool) {
    response
        .cookie(clear_cookie("oidc_csrf".to_string(), secure))
        .cookie(clear_cookie("oidc_nonce".to_string(), secure))
        .cookie(clear_cookie("oidc_pkce".to_string(), secure))
        .cookie(clear_cookie("oidc_return_to".to_string(), secure));
}

/// Builds a callback failure response.
///
/// A valid return cookie selects a `302` response with the stable error code.
/// Without the cookie the response keeps the JSON `AuthResponse` and the
/// given status.
fn callback_failure(
    status: StatusCode,
    message: &str,
    code: &str,
    return_to: Option<&str>,
    secure: bool,
) -> HttpResponse {
    if let Some(return_to) = return_to {
        let mut response = HttpResponse::Found();
        clear_auth_flow_cookies(&mut response, secure);
        response
            .append_header(("Location", redirect_target(return_to, Some(code))))
            .finish()
    } else {
        let mut response = HttpResponse::build(status);
        clear_auth_flow_cookies(&mut response, secure);
        response.json(AuthResponse {
            success: false,
            token: None,
            error: Some(message.to_string()),
        })
    }
}

/// Starts the OIDC authorization-code flow (redirects to the provider).
///
/// The optional `return_to` query parameter stores a relative path in the
/// short-lived `oidc_return_to` cookie. The callback uses that path to send
/// the browser back to the SPA. An invalid value returns `400` and does not
/// start the provider redirect.
#[utoipa::path(get, path = "/auth/login", tag = "auth", params(("return_to" = Option<String>, Query, description = "Relative path to open after the callback")), responses((status = 302, description = "redirect to provider"), (status = 400, body = AuthResponse)))]
#[get("/login")]
pub async fn login(
    oidc_client: web::Data<OidcClient>,
    query: web::Query<LoginQuery>,
) -> impl Responder {
    if let Some(return_to) = &query.return_to
        && !is_valid_return_to(return_to)
    {
        return HttpResponse::BadRequest().json(AuthResponse {
            success: false,
            token: None,
            error: Some("invalid return_to".to_string()),
        });
    }

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

    let mut response = HttpResponse::Found();
    response.append_header(("Location", auth_data.url));
    response
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
        ));
    if let Some(return_to) = &query.return_to {
        response.cookie(base_cookie("oidc_return_to", return_to.clone()));
    }
    response.finish()
}

/// Query parameters the OIDC provider appends when redirecting back to
/// `/auth/callback`.
///
/// The provider can send `error` without `code` and `state`. The handler
/// then reports a stable failure instead of a query extraction error.
#[derive(Deserialize)]
pub struct AuthCallbackQuery {
    /// Authorization code issued by the provider.
    pub code: Option<String>,
    /// OAuth2 `state` value. It must match the CSRF cookie.
    pub state: Option<String>,
    /// Provider error, for example `access_denied`.
    pub error: Option<String>,
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

/// OIDC authorization-code callback.
///
/// The handler validates the state, nonce, and PKCE values and sets the
/// session cookies. It clears the temporary OIDC cookies on every outcome.
///
/// A valid `oidc_return_to` cookie selects a `302` redirect to the SPA. A
/// failure adds a stable `error` query parameter. Without the cookie the
/// handler keeps the JSON `AuthResponse` and its status codes.
#[utoipa::path(get, path = "/auth/callback", tag = "auth", params(("code" = Option<String>, Query), ("state" = Option<String>, Query), ("error" = Option<String>, Query, description = "Provider error, for example access_denied")), responses((status = 200, body = AuthResponse), (status = 302, description = "redirect to return_to with an optional stable error code"), (status = 400, body = AuthResponse), (status = 401, body = AuthResponse), (status = 403, body = AuthResponse), (status = 500, body = AuthResponse)))]
#[get("/callback")]
pub async fn callback(
    oidc_client: web::Data<OidcClient>,
    query: web::Query<AuthCallbackQuery>,
    req: HttpRequest,
) -> impl Responder {
    let secure = oidc_client.secure_cookies();
    let return_to = req
        .cookie("oidc_return_to")
        .map(|cookie| cookie.value().to_string())
        .filter(|value| is_valid_return_to(value));

    if let Some(provider_error) = query.error.as_deref() {
        return if provider_error == "access_denied" {
            tracing::warn!("OIDC provider denied access");
            callback_failure(
                StatusCode::FORBIDDEN,
                "access denied",
                "access_denied",
                return_to.as_deref(),
                secure,
            )
        } else {
            tracing::warn!("OIDC provider returned error: {provider_error}");
            callback_failure(
                StatusCode::UNAUTHORIZED,
                "authentication failed",
                "authentication_failed",
                return_to.as_deref(),
                secure,
            )
        };
    }

    let cookies = (
        req.cookie("oidc_csrf"),
        req.cookie("oidc_nonce"),
        req.cookie("oidc_pkce"),
    );

    let (Some(csrf), Some(nonce), Some(pkce)) = cookies else {
        return callback_failure(
            StatusCode::BAD_REQUEST,
            "Session expired or security cookies missing",
            "security_cookies_missing",
            return_to.as_deref(),
            secure,
        );
    };

    let (Some(code), Some(state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return callback_failure(
            StatusCode::UNAUTHORIZED,
            "authentication failed",
            "authentication_failed",
            return_to.as_deref(),
            secure,
        );
    };

    if state != csrf.value() {
        return callback_failure(
            StatusCode::UNAUTHORIZED,
            "Invalid state parameter",
            "invalid_state",
            return_to.as_deref(),
            secure,
        );
    }

    let nonce_val = Nonce::new(nonce.value().to_string());
    let pkce_val = PkceCodeVerifier::new(pkce.value().to_string());

    match oidc_client
        .exchange_code(code.to_string(), nonce_val, pkce_val)
        .await
    {
        Ok((token_string, refresh_token)) => {
            let auth_cookie = Cookie::build("auth_token", token_string.clone())
                .path("/")
                .http_only(true)
                .secure(secure)
                .same_site(SameSite::Lax)
                .max_age(Duration::days(7))
                .finish();
            let refresh_cookie = refresh_token.map(|rt| {
                Cookie::build("refresh_token", rt)
                    .path("/")
                    .http_only(true)
                    .secure(secure)
                    .same_site(SameSite::Lax)
                    .max_age(Duration::days(30))
                    .finish()
            });

            if let Some(return_to) = return_to {
                let mut response = HttpResponse::Found();
                clear_auth_flow_cookies(&mut response, secure);
                response.cookie(auth_cookie);
                if let Some(refresh_cookie) = refresh_cookie {
                    response.cookie(refresh_cookie);
                }
                response.append_header(("Location", return_to)).finish()
            } else {
                let mut response = HttpResponse::Ok();
                clear_auth_flow_cookies(&mut response, secure);
                response.cookie(auth_cookie);
                if let Some(refresh_cookie) = refresh_cookie {
                    response.cookie(refresh_cookie);
                }
                response.json(AuthResponse {
                    success: true,
                    token: Some(token_string),
                    error: None,
                })
            }
        }
        Err(e) => {
            // The server logs receive the full detail. Clients only ever see a stable,
            // non-sensitive message.
            let (status, message, code) = match &e {
                OidcError::ExchangeFailure(_)
                | OidcError::MissingIdToken
                | OidcError::InvalidToken(_) => {
                    tracing::warn!("OIDC code exchange rejected: {e}");
                    (
                        StatusCode::UNAUTHORIZED,
                        "authentication failed",
                        "authentication_failed",
                    )
                }
                other => {
                    tracing::error!("OIDC callback failed unexpectedly: {other:?}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal server error",
                        "internal_error",
                    )
                }
            };
            callback_failure(status, message, code, return_to.as_deref(), secure)
        }
    }
}

/// Renews a session from a refresh token stored in the `refresh_token`
/// cookie. Returns a new ID token and extends the session cookies.
#[utoipa::path(post, path = "/auth/refresh", tag = "auth", responses((status = 200, body = AuthResponse), (status = 401, body = AuthResponse)))]
#[post("/refresh")]
pub async fn refresh(oidc_client: web::Data<OidcClient>, req: HttpRequest) -> impl Responder {
    let Some(cookie) = req.cookie("refresh_token") else {
        return HttpResponse::Unauthorized().json(AuthResponse {
            success: false,
            token: None,
            error: Some("missing refresh token".to_string()),
        });
    };
    match oidc_client.refresh_token(cookie.value()).await {
        Ok((token_string, new_refresh)) => {
            let secure = oidc_client.secure_cookies();
            let auth_cookie = Cookie::build("auth_token", token_string.clone())
                .path("/")
                .http_only(true)
                .secure(secure)
                .same_site(SameSite::Lax)
                .max_age(Duration::days(7))
                .finish();
            let mut response = HttpResponse::Ok();
            response.cookie(auth_cookie);
            if let Some(rt) = new_refresh {
                let refresh_cookie = Cookie::build("refresh_token", rt)
                    .path("/")
                    .http_only(true)
                    .secure(secure)
                    .same_site(SameSite::Lax)
                    .max_age(Duration::days(30))
                    .finish();
                response.cookie(refresh_cookie);
            }
            response.json(AuthResponse {
                success: true,
                token: Some(token_string),
                error: None,
            })
        }
        Err(e) => {
            tracing::warn!("OIDC refresh failed: {e}");
            HttpResponse::Unauthorized().json(AuthResponse {
                success: false,
                token: None,
                error: Some("authentication failed".to_string()),
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
    use wiremock::matchers::{body_string_contains, method, path};
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
                    "revocation_endpoint": format!("{}/revoke", server.uri()),
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

    /// Builds the Cookie header value carrying the security cookies and a
    /// return path.
    fn return_cookie_header(csrf: &str, nonce: &str, pkce: &str, return_to: &str) -> String {
        format!(
            "{}; oidc_return_to={return_to}",
            cookie_header(csrf, nonce, pkce)
        )
    }

    /// Asserts that a response clears a cookie.
    fn assert_cookie_cleared(res: &ServiceResponse, name: &str) {
        let cookie = res
            .response()
            .cookies()
            .find(|cookie| cookie.name() == name)
            .unwrap_or_else(|| panic!("{name} must be cleared"));
        assert_eq!(
            cookie.max_age(),
            Some(Duration::ZERO),
            "{name} must be cleared"
        );
    }

    /// Returns the Location header of a response.
    fn location(res: &ServiceResponse) -> String {
        res.response()
            .headers()
            .get(LOCATION)
            .expect("redirect Location header")
            .to_str()
            .unwrap()
            .to_string()
    }

    /// Signs an ID token whose nonce matches the login cookie.
    fn id_token_for(fx: &Fixture, nonce: &str) -> anyhow::Result<String> {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("test-key-id".to_string());
        encode(
            &header,
            &json!({
                "iss": fx.server.uri(),
                "sub": "user-123",
                "aud": CLIENT_ID,
                "exp": 2_000_000_000i64,
                "iat": 1_000_000_000i64,
                "nonce": nonce,
            }),
            &fx.encoding_key,
        )
        .map_err(anyhow::Error::from)
    }

    /// Mounts a token endpoint that accepts the exchange.
    async fn mount_successful_exchange(fx: &Fixture, nonce: &str) -> anyhow::Result<()> {
        let id_token = id_token_for(fx, nonce)?;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "mock-access",
                "token_type": "Bearer",
                "id_token": id_token,
            })))
            .mount(&fx.server)
            .await;
        Ok(())
    }

    /// Waits for the mock provider to receive a request on `path`.
    async fn wait_for_provider_request(server: &MockServer, path: &str) {
        for _ in 0..100 {
            if let Some(requests) = server.received_requests().await
                && requests.iter().any(|request| request.url.path() == path)
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let paths = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|request| request.url.path().to_string())
            .collect::<Vec<_>>();
        panic!("mock provider did not receive {path}; received {paths:?}");
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
    async fn login_with_return_to_sets_return_cookie() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/auth/login?return_to=%2Fapp%3Ftab%3D1%23section")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 302);

        let cookie = res
            .response()
            .cookies()
            .find(|cookie| cookie.name() == "oidc_return_to")
            .expect("login must set oidc_return_to");
        assert_eq!(cookie.value(), "/app?tab=1#section");
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), None, "the fixture callback uses http");
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.max_age(), Some(Duration::minutes(5)));
    }

    #[tokio::test]
    async fn login_without_return_to_sets_no_return_cookie() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        let res = test::call_service(
            &svc,
            test::TestRequest::get().uri("/auth/login").to_request(),
        )
        .await;
        assert_eq!(res.status(), 302);
        assert!(
            res.response()
                .cookies()
                .all(|cookie| cookie.name() != "oidc_return_to")
        );
    }

    #[tokio::test]
    async fn login_rejects_absolute_return_to() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/auth/login?return_to=https%3A%2F%2Fevil.example%2Fapp")
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 400);
        assert!(res.response().headers().get(LOCATION).is_none());
        let body: AuthResponse = serde_json::from_slice(&test::read_body(res).await).unwrap();
        assert_eq!(body.error.as_deref(), Some("invalid return_to"));
    }

    #[tokio::test]
    async fn login_rejects_protocol_relative_return_to() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        for value in ["%2F%2Fevil.example%2Fapp", "%2F%2F%2Fevil.example"] {
            let res = test::call_service(
                &svc,
                test::TestRequest::get()
                    .uri(&format!("/auth/login?return_to={value}"))
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), 400, "value {value} must fail");
            assert!(res.response().headers().get(LOCATION).is_none());
        }
    }

    #[tokio::test]
    async fn login_rejects_return_to_with_scheme_or_host() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        for value in [
            "https%3A%2F%2Fevil.example%2Fapp",
            "javascript%3Aalert%281%29",
            "%2F%5Cevil.example%2Fapp",
        ] {
            let res = test::call_service(
                &svc,
                test::TestRequest::get()
                    .uri(&format!("/auth/login?return_to={value}"))
                    .to_request(),
            )
            .await;
            assert_eq!(res.status(), 400, "value {value} must fail");
            assert!(res.response().headers().get(LOCATION).is_none());
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
    async fn callback_success_with_return_cookie_redirects_to_app() -> anyhow::Result<()> {
        let fx = Fixture::new().await?;
        let svc = test_app!(fx);
        let login_res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/auth/login?return_to=%2Fapp%2Fdashboard")
                .to_request(),
        )
        .await;
        let (csrf, nonce, pkce, state) = login_parts(&login_res)?;
        mount_successful_exchange(&fx, &nonce).await?;

        let req = test::TestRequest::get()
            .uri(&format!("/auth/callback?code=test-code&state={state}"))
            .insert_header((
                "Cookie",
                return_cookie_header(&csrf, &nonce, &pkce, "/app/dashboard"),
            ))
            .to_request();
        let res = test::call_service(&svc, req).await;

        assert_eq!(res.status(), 302);
        assert_eq!(location(&res), "/app/dashboard");
        assert!(
            res.response()
                .cookies()
                .any(|cookie| cookie.name() == "auth_token")
        );
        for name in ["oidc_csrf", "oidc_nonce", "oidc_pkce", "oidc_return_to"] {
            assert_cookie_cleared(&res, name);
        }
        Ok(())
    }

    #[tokio::test]
    async fn callback_failure_with_return_cookie_redirects_with_stable_code() -> anyhow::Result<()>
    {
        let fx = Fixture::new().await?;
        let svc = test_app!(fx);
        let login_res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/auth/login?return_to=%2Fapp%3Ftab%3D1%23section")
                .to_request(),
        )
        .await;
        let (csrf, nonce, pkce, _state) = login_parts(&login_res)?;

        let req = test::TestRequest::get()
            .uri("/auth/callback?code=test-code&state=tampered")
            .insert_header((
                "Cookie",
                return_cookie_header(&csrf, &nonce, &pkce, "/app?tab=1#section"),
            ))
            .to_request();
        let res = test::call_service(&svc, req).await;

        assert_eq!(res.status(), 302);
        let target = Url::parse("http://localhost/")?.join(&location(&res))?;
        let query: std::collections::HashMap<String, String> =
            target.query_pairs().into_owned().collect();
        assert_eq!(query["error"], "invalid_state");
        assert_eq!(query["tab"], "1");
        assert_eq!(target.fragment(), Some("section"));
        for name in ["oidc_csrf", "oidc_nonce", "oidc_pkce", "oidc_return_to"] {
            assert_cookie_cleared(&res, name);
        }
        Ok(())
    }

    #[tokio::test]
    async fn callback_with_provider_access_denied_returns_403() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/auth/callback?error=access_denied")
                .to_request(),
        )
        .await;

        assert_eq!(res.status(), 403);
        let body: AuthResponse = serde_json::from_slice(&test::read_body(res).await).unwrap();
        assert!(!body.success);
        assert_eq!(body.error.as_deref(), Some("access denied"));
    }

    #[tokio::test]
    async fn callback_with_provider_access_denied_redirects_with_code() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        let req = test::TestRequest::get()
            .uri("/auth/callback?error=access_denied")
            .insert_header(("Cookie", "oidc_return_to=/app?tab=1"))
            .to_request();
        let res = test::call_service(&svc, req).await;

        assert_eq!(res.status(), 302);
        let target = Url::parse("http://localhost/")
            .unwrap()
            .join(&location(&res))
            .unwrap();
        let query: std::collections::HashMap<String, String> =
            target.query_pairs().into_owned().collect();
        assert_eq!(query["error"], "access_denied");
        assert_eq!(query["tab"], "1");
        assert_cookie_cleared(&res, "oidc_return_to");
    }

    #[tokio::test]
    async fn callback_success_without_return_cookie_returns_json() -> anyhow::Result<()> {
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
        assert!(res.response().headers().get(LOCATION).is_none());
        // The code reads the cookies before read_body consumes the response.
        let auth_cookie = res
            .response()
            .cookies()
            .find(|c| c.name() == "auth_token")
            .expect("auth_token cookie must be set")
            .value()
            .to_string();
        for name in ["oidc_csrf", "oidc_nonce", "oidc_pkce", "oidc_return_to"] {
            assert_cookie_cleared(&res, name);
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
    async fn logout_clears_auth_and_refresh_cookies() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        let res = test::call_service(
            &svc,
            test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header(("Cookie", "refresh_token=r"))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 204);
        assert_cookie_cleared(&res, "auth_token");
        assert_cookie_cleared(&res, "refresh_token");
    }

    #[tokio::test]
    async fn refresh_after_logout_returns_401() -> anyhow::Result<()> {
        let fx = Fixture::new().await?;
        let svc = test_app!(fx);
        let auth_token = session_token(&fx, "alice", &fx.server.uri())?;
        let mut jar = vec![
            ("auth_token".to_string(), auth_token),
            ("refresh_token".to_string(), "r".to_string()),
        ];

        let res = test::call_service(
            &svc,
            test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header((
                    "Cookie",
                    jar.iter()
                        .map(|(name, value)| format!("{name}={value}"))
                        .collect::<Vec<_>>()
                        .join("; "),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 204);
        for cookie in res.response().cookies() {
            if cookie.max_age() == Some(Duration::ZERO) {
                jar.retain(|(name, _)| name != cookie.name());
            }
        }

        let res = test::call_service(
            &svc,
            test::TestRequest::post()
                .uri("/auth/refresh")
                .insert_header((
                    "Cookie",
                    jar.iter()
                        .map(|(name, value)| format!("{name}={value}"))
                        .collect::<Vec<_>>()
                        .join("; "),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 401);
        Ok(())
    }

    #[tokio::test]
    async fn logout_returns_204_without_waiting_for_revocation() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);

        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(2)))
            .mount(&fx.server)
            .await;

        let started = std::time::Instant::now();
        let res = test::call_service(
            &svc,
            test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header(("Cookie", "refresh_token=r"))
                .to_request(),
        )
        .await;

        assert_eq!(res.status(), 204);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "logout must not wait for the revocation request"
        );
    }

    #[tokio::test]
    async fn logout_revokes_refresh_token_when_provider_advertises_endpoint() {
        let fx = Fixture::new().await.unwrap();
        let svc = test_app!(fx);
        assert!(fx.module.oidc_client.has_revocation_endpoint());

        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(body_string_contains("token=refresh-token"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&fx.server)
            .await;

        let res = test::call_service(
            &svc,
            test::TestRequest::post()
                .uri("/auth/logout")
                .insert_header(("Cookie", "refresh_token=refresh-token"))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 204);

        wait_for_provider_request(&fx.server, "/revoke").await;
    }

    #[tokio::test]
    async fn callback_failure_without_return_cookie_returns_json() {
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
        assert!(res.response().headers().get(LOCATION).is_none());
        let body: AuthResponse = serde_json::from_slice(&test::read_body(res).await).unwrap();
        assert!(!body.success);
        // The details of a provider failure never reach the client.
        assert_eq!(body.error.as_deref(), Some("authentication failed"));
    }
}
