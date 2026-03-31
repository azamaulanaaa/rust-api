use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, Responder,
    cookie::{Cookie, SameSite, time::Duration},
    get, web,
};
use openidconnect::{Nonce, PkceCodeVerifier};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::OidcClient;
use crate::endpoint::{ApiModule, middleware};

pub struct OidcApiModule<C>
where
    C: DeserializeOwned,
{
    oidc_client: Arc<OidcClient>,
    jwt_middleware: middleware::jwt::JwtClaimsMiddleware<C>,
}

impl<C> OidcApiModule<C>
where
    C: DeserializeOwned,
{
    pub async fn init(oidc_client: OidcClient) -> anyhow::Result<Self> {
        let jwt_middleware = middleware::jwt::JwtClaimsMiddleware::new_with_jks(
            oidc_client.jwks_uri().as_str(),
            oidc_client.issuer().as_str(),
            oidc_client.client_id().as_str(),
        )
        .await?;

        Ok(Self {
            oidc_client: Arc::new(oidc_client),
            jwt_middleware,
        })
    }

    pub fn middleware(&self) -> middleware::jwt::JwtClaimsMiddleware<C>
    where
        C: Clone,
    {
        return self.jwt_middleware.clone();
    }
}

impl<C> ApiModule for OidcApiModule<C>
where
    C: DeserializeOwned + Send + Sync + 'static,
{
    fn configure(&self, cfg: &mut web::ServiceConfig) {
        let oidc_client = web::Data::from(self.oidc_client.clone());

        let scope = web::scope("/auth")
            .app_data(oidc_client)
            .service(login)
            .service(callback);

        cfg.service(scope);
    }
}

#[get("/login")]
pub async fn login(oidc_client: web::Data<OidcClient>) -> impl Responder {
    let auth_data = oidc_client.get_auth_url();
    let cookie_duration = Duration::minutes(5);

    let base_cookie = |name: &'static str, value: String| {
        Cookie::build(name, value)
            .http_only(true)
            .secure(true)
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

#[derive(Deserialize)]
pub struct AuthCallbackQuery {
    code: String,
    state: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub token: Option<String>,
    pub error: Option<String>,
}

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
            let auth_cookie = Cookie::build("auth_token", token_string.clone())
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Lax)
                .max_age(Duration::days(7))
                .finish();

            HttpResponse::Ok()
                .cookie(clear_cookie("oidc_csrf".to_string()))
                .cookie(clear_cookie("oidc_nonce".to_string()))
                .cookie(clear_cookie("oidc_pkce".to_string()))
                .cookie(auth_cookie)
                .json(AuthResponse {
                    success: true,
                    token: Some(token_string),
                    error: None,
                })
        }
        Err(e) => HttpResponse::InternalServerError().json(AuthResponse {
            success: false,
            token: None,
            error: Some(e.to_string()),
        }),
    }
}

fn clear_cookie(name: String) -> Cookie<'static> {
    Cookie::build(name, "")
        .path("/")
        .max_age(Duration::ZERO)
        .finish()
}
