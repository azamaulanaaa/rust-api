//! OpenID Connect client and login/callback routes implementing the
//! authorization-code flow with PKCE, CSRF state, and nonce validation.
//!
//! [`OidcClient`](crate::oidc::OidcClient) wraps the discovered provider
//! metadata. It builds authorization URLs with fresh PKCE/CSRF/nonce values.
//! It exchanges authorization codes for signature-verified ID tokens.
//! Multi-tenant providers that publish a `{tenantid}` issuer
//! placeholder are supported by resolving the expected issuer per token
//! instead of pinning it statically.

use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, JsonWebKeySet, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse,
};

use thiserror::Error;

use crate::http::middleware::jwt::{IssuerTemplate, extract_unverified_claim};

/// HTTP routes for the OIDC login and callback endpoints.
pub mod route;

/// Provider and client settings required to bootstrap [`OidcClient`].
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// OAuth2 client identifier registered at the provider.
    pub client_id: String,
    /// OAuth2 client secret registered at the provider.
    pub client_secret: String,
    /// Base URL of the provider's OIDC discovery document.
    pub issuer_url: String,
    /// Absolute URL the provider redirects back to after login.
    pub redirect_url: String,
    /// Tenant identifiers this deployment accepts, for a provider that
    /// publishes a `{tenantid}` issuer template.
    ///
    /// Empty for a single-tenant issuer, where the issuer is pinned
    /// statically. Must be non-empty when the discovered issuer is
    /// templated. [`OidcClient::new`] rejects that combination.
    pub allowed_tenants: Vec<String>,
}

/// Errors raised by [`OidcClient`] during discovery and token exchange.
///
/// Display text is lowercase sentence style, matching
/// [`FsError`](crate::fs::error::FsError) and
/// [`ApiError`](crate::http::error::ApiError). These strings reach server
/// logs and startup error output, so they read as one voice.
#[derive(Error, Debug)]
pub enum OidcError {
    /// Client configuration could not be applied.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// A provider or redirect URL failed to parse.
    #[error("invalid URL format: {0}")]
    UrlParse(#[from] url::ParseError),

    /// The outbound HTTP request to the provider failed.
    #[error("http client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    /// The provider's discovery document was missing or malformed.
    #[error("failed to discover OIDC provider: {0}")]
    Discovery(String),

    /// The authorization-code exchange was rejected by the provider.
    #[error("failed to exchange authorization code: {0}")]
    ExchangeFailure(String),

    /// The provider's token response contained no ID token.
    #[error("provider did not return an ID token")]
    MissingIdToken,

    /// The ID token failed signature, nonce, or claims validation.
    #[error("id token validation failed: {0}")]
    InvalidToken(String),
}

/// OpenID Connect client wrapping the discovered provider metadata:
/// builds authorization URLs with PKCE/CSRF/nonce and exchanges
/// authorization codes for validated ID tokens.
pub struct OidcClient {
    client: CoreClient<
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
    http_client: reqwest::Client,
    provider_metadata: CoreProviderMetadata,
    /// Original discovered issuer. It may contain a `{tenantid}` placeholder
    /// for multi-tenant providers (Azure AD).
    issuer: String,
    /// Parsed template when [`OidcClient::issuer`] holds a `{tenantid}`
    /// placeholder.
    issuer_template: Option<IssuerTemplate>,
    allowed_tenants: Vec<String>,
    /// Absolute login-callback URL. Its scheme decides the `Secure` flag on
    /// auth cookies. Plain-http deployments must still receive the cookies.
    redirect_url: String,
}

/// Everything a caller needs to start the authorization-code flow. It holds
/// the provider URL to redirect the user agent to. It also holds the
/// CSRF/nonce/PKCE values that must round-trip through temporary cookies.
pub struct AuthUrlResponse {
    /// The provider's authorization endpoint URL including query params.
    pub url: String,
    /// CSRF value. The OAuth2 `state` parameter also carries it.
    pub csrf_token: CsrfToken,
    /// Nonce bound into the returned ID token.
    pub nonce: Nonce,
    /// PKCE verifier kept server-side to complete the exchange.
    pub pkce_verifier: PkceCodeVerifier,
}

impl OidcClient {
    /// Performs provider discovery and builds the client. Fails if the
    /// issuer URL is malformed or the discovery document is unreachable.
    pub async fn new(config: OidcConfig) -> Result<Self, OidcError> {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        // The client fetches the discovery document by hand. Multi-tenant
        // providers publish an issuer that contains a literal {tenantid}
        // placeholder. That placeholder can never equal the requested URL,
        // and openidconnect rejects such metadata. The client substitutes a
        // sentinel tenant before it parses the document. The client then
        // enforces the issuer per token against the parsed template (see
        // `exchange_code` and `JwtClaimsMiddleware`).
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer_url.trim_end_matches('/')
        );
        let body = http_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(OidcError::HttpClient)?
            .error_for_status()
            .map_err(|e| OidcError::Discovery(e.to_string()))?
            .text()
            .await
            .map_err(OidcError::HttpClient)?;

        let raw_issuer = serde_json::from_str::<serde_json::Value>(&body)
            .map_err(|e| OidcError::Discovery(e.to_string()))?
            .get("issuer")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| OidcError::Discovery("metadata missing issuer".to_string()))?
            .to_string();
        let issuer_template = IssuerTemplate::parse(&raw_issuer, config.allowed_tenants.clone());
        if let Some(template) = &issuer_template
            && template.allowed_tenants().is_empty()
        {
            return Err(OidcError::Configuration(format!(
                "issuer {raw_issuer:?} is a multi-tenant template but no allowed tenants are \
                 configured; set [authorization].allowed_tenants"
            )));
        }

        let body = if issuer_template.is_some() {
            body.replace("{tenantid}", &format!("{:032x}", 0))
        } else {
            body
        };

        let provider_metadata: CoreProviderMetadata =
            serde_json::from_str(&body).map_err(|e| OidcError::Discovery(e.to_string()))?;

        // from_provider_metadata reads the keys of the ID-token verifier
        // from the JWKS that the metadata embeds. discover_async normally
        // fetches that document. This call repeats the step for metadata
        // that the client parsed by hand.
        let jwks = JsonWebKeySet::fetch_async(provider_metadata.jwks_uri(), &http_client)
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        let provider_metadata = provider_metadata.set_jwks(jwks);

        let client = CoreClient::from_provider_metadata(
            provider_metadata.clone(),
            ClientId::new(config.client_id),
            Some(ClientSecret::new(config.client_secret)),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone())?);

        Ok(Self {
            client,
            http_client,
            provider_metadata,
            issuer: raw_issuer,
            issuer_template,
            redirect_url: config.redirect_url,
            allowed_tenants: config.allowed_tenants,
        })
    }

    /// Generates a fresh authorization URL with a new PKCE challenge,
    /// CSRF token, and nonce. The returned secrets must be stored in
    /// temporary cookies and passed back to [`OidcClient::exchange_code`].
    pub fn get_auth_url(&self) -> AuthUrlResponse {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (url, csrf_token, nonce) = self
            .client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("offline_access".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        AuthUrlResponse {
            url: url.to_string(),
            csrf_token,
            nonce,
            pkce_verifier,
        }
    }

    /// Exchanges an authorization code for an ID token, verifying its
    /// signature against the provider's keys and binding it to `nonce`.
    /// Returns the raw serialized ID token and, when the provider issued
    /// one, a refresh token on success.
    pub async fn exchange_code(
        &self,
        code: String,
        nonce: Nonce,
        pkce_verifier: PkceCodeVerifier,
    ) -> Result<(String, Option<String>), OidcError> {
        let request = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|e| OidcError::Configuration(format!("{:?}", e)))?;

        let token_response = request
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http_client)
            .await
            .map_err(|e| OidcError::ExchangeFailure(e.to_string()))?;

        let refresh_token = token_response
            .refresh_token()
            .map(|token| token.secret().to_string());
        let id_token = token_response.id_token().ok_or(OidcError::MissingIdToken)?;

        if let Some(template) = &self.issuer_template {
            // A multi-tenant provider publishes an issuer that carries a
            // {tenantid} placeholder. No real token can match that
            // placeholder, so the client disables the static issuer check.
            // The client then enforces the template against the tenant
            // identifier of the token itself. Signature, nonce, audience,
            // and expiry validation do not change.
            let verifier = self.client.id_token_verifier().require_issuer_match(false);
            let _verified_claims = id_token
                .claims(&verifier, &nonce)
                .map_err(|e| OidcError::InvalidToken(e.to_string()))?;

            // The signature verification above authenticates this payload.
            // An authenticated caller is not an *authorized* tenant. Any
            // tenant that consented to a multi-tenant app registration can
            // mint a token that verifies against the shared JWKS. The
            // allowlist is the tenant gate, and it fails closed.
            let raw = id_token.to_string();
            let Some(tenant_id) = extract_unverified_claim(&raw, "tid").filter(|t| !t.is_empty())
            else {
                return Err(OidcError::InvalidToken(
                    "token missing tenant identifier".to_string(),
                ));
            };
            let expected = template
                .resolve_checked(&tenant_id)
                .map_err(OidcError::InvalidToken)?;
            let actual_iss = extract_unverified_claim(&raw, "iss");
            if actual_iss.as_deref() != Some(expected.as_str()) {
                return Err(OidcError::InvalidToken(format!(
                    "token issuer does not match tenant `{tenant_id}`"
                )));
            }
        } else {
            id_token
                .claims(&self.client.id_token_verifier(), &nonce)
                .map_err(|e| OidcError::InvalidToken(e.to_string()))?;
        }

        Ok((id_token.to_string(), refresh_token))
    }

    /// Renews an ID token using a provider refresh token. Returns the new
    /// ID token and, when the provider rotated it, a new refresh token.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<(String, Option<String>), OidcError> {
        let refresh_token_value = RefreshToken::new(refresh_token.to_string());
        let request = self
            .client
            .exchange_refresh_token(&refresh_token_value)
            .map_err(|e| OidcError::Configuration(format!("{:?}", e)))?;

        let token_response = request
            .request_async(&self.http_client)
            .await
            .map_err(|e| OidcError::ExchangeFailure(e.to_string()))?;

        let new_refresh = token_response
            .refresh_token()
            .map(|token| token.secret().to_string());
        let id_token = token_response.id_token().ok_or(OidcError::MissingIdToken)?;

        let nonce_verifier = |_: Option<&Nonce>| Ok(());
        if let Some(template) = &self.issuer_template {
            // The refresh response carries a new ID token but no fresh
            // nonce. Keep signature, audience, and expiry validation, then
            // re-apply the tenant gate that `exchange_code` uses. Trusting
            // the signed token alone would let any tenant that consented to
            // the app registration mint a session for this deployment.
            let verifier = self.client.id_token_verifier().require_issuer_match(false);
            let _verified_claims = id_token
                .claims(&verifier, nonce_verifier)
                .map_err(|e| OidcError::InvalidToken(e.to_string()))?;

            let raw = id_token.to_string();
            let Some(tenant_id) = extract_unverified_claim(&raw, "tid").filter(|t| !t.is_empty())
            else {
                return Err(OidcError::InvalidToken(
                    "token missing tenant identifier".to_string(),
                ));
            };
            let expected = template
                .resolve_checked(&tenant_id)
                .map_err(OidcError::InvalidToken)?;
            let actual_iss = extract_unverified_claim(&raw, "iss");
            if actual_iss.as_deref() != Some(expected.as_str()) {
                return Err(OidcError::InvalidToken(format!(
                    "token issuer does not match tenant `{tenant_id}`"
                )));
            }
        } else {
            id_token
                .claims(&self.client.id_token_verifier(), nonce_verifier)
                .map_err(|e| OidcError::InvalidToken(e.to_string()))?;
        }

        Ok((id_token.to_string(), new_refresh))
    }

    /// Whether auth cookies must carry the `Secure` flag.
    ///
    /// True for `https://` callbacks. Plain-http deployments (local dev)
    /// opt out, so that browsers accept the cookies at all. Unparseable
    /// URLs fail closed to `true`.
    pub fn secure_cookies(&self) -> bool {
        secure_scheme(&self.redirect_url)
    }

    /// The provider's discovered issuer URL. It may contain a `{tenantid}`
    /// placeholder for multi-tenant providers.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The absolute login-callback URL this client redirects to.
    pub fn redirect_url(&self) -> &str {
        &self.redirect_url
    }

    /// The OAuth2 client ID used for token requests.
    pub fn client_id(&self) -> &ClientId {
        self.client.client_id()
    }

    /// The provider's JWKS endpoint hosting its public signing keys.
    pub fn jwks_uri(&self) -> &url::Url {
        self.provider_metadata.jwks_uri().url()
    }

    /// The tenant identifiers this deployment accepts for a templated
    /// issuer. Empty for a single-tenant issuer.
    pub fn allowed_tenants(&self) -> &[String] {
        &self.allowed_tenants
    }
}

/// Reports whether `callback_url` uses `https`.
///
/// It drives the `Secure` flag on auth cookies. Unparseable input fails
/// closed to `true`. A misconfigured URL can then only make the cookies
/// stricter, and never leak them over plaintext.
fn secure_scheme(callback_url: &str) -> bool {
    url::Url::parse(callback_url)
        .map(|u| u.scheme() == "https")
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn secure_scheme_https_only() {
        assert!(secure_scheme("https://app.example.com/auth/callback"));
        assert!(!secure_scheme("http://localhost:8080/auth/callback"));
        // Fail closed: garbage can only make cookies stricter.
        assert!(secure_scheme("not a url"));
        assert!(secure_scheme(""));
    }

    /// Every variant renders lowercase sentence style, matching the display
    /// style of `FsError` and `ApiError`, so the log output reads as one
    /// voice. The enum doc makes this a contract rather than a
    /// coincidence.
    #[test]
    fn error_display_is_lowercase_sentence_style() {
        for rendered in [
            OidcError::MissingIdToken.to_string(),
            OidcError::Discovery("no issuer".into()).to_string(),
            OidcError::ExchangeFailure("400 from /token".into()).to_string(),
            OidcError::InvalidToken("aud mismatch".into()).to_string(),
        ] {
            let first = rendered.chars().next().expect("non-empty display");
            assert!(
                first.is_lowercase(),
                "expected lowercase start, got {rendered:?}"
            );
        }
    }

    #[tokio::test]
    async fn auth_url_and_code_exchange_return_signed_id_token() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let client_id = "test-client";

        let (private_key, public_key) = {
            let mut rng = rand::thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
            let public_key = RsaPublicKey::from(&private_key);

            (private_key, public_key)
        };

        {
            let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
            let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

            let jwks_body = json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "test-key-id",
                    "alg": "RS256",
                    "n": n,
                    "e": e
                }]
            });

            Mock::given(method("GET"))
                .and(path("/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body))
                .mount(&server)
                .await;
        }

        {
            let discovery_body = json!({
                "issuer": server.uri(),
                "authorization_endpoint": format!("{}/auth", server.uri()),
                "token_endpoint": format!("{}/token", server.uri()),
                "jwks_uri": format!("{}/jwks", server.uri()),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            });

            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(discovery_body))
                .mount(&server)
                .await;
        }

        let oidc_client = {
            let config = OidcConfig {
                client_id: client_id.to_string(),
                client_secret: "test-secret".to_string(),
                issuer_url: server.uri(),
                redirect_url: "http://localhost/callback".to_string(),
                allowed_tenants: Vec::new(),
            };

            OidcClient::new(config).await?
        };
        let auth_data = oidc_client.get_auth_url();

        let signed_id_token = {
            let signed_id_token = {
                let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
                header.kid = Some("test-key-id".to_string());

                let claims = json!({
                    "iss": server.uri(),
                    "sub": "user-123",
                    "aud": client_id,
                    "exp": 2000000000,
                    "iat": 1000000000,
                    "nonce":auth_data.nonce.secret(),
                });

                let private_key_der = private_key.to_pkcs1_der()?;
                let encoding_key = EncodingKey::from_rsa_der(private_key_der.as_bytes());
                encode(&header, &claims, &encoding_key)?
            };

            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "mock-access",
                    "token_type": "Bearer",
                    "id_token": signed_id_token,
                })))
                .mount(&server)
                .await;

            signed_id_token
        };

        let (output_token, _refresh) = oidc_client
            .exchange_code(
                "mock-code".to_string(),
                auth_data.nonce,
                auth_data.pkce_verifier,
            )
            .await?;

        assert_eq!(output_token, signed_id_token);

        Ok(())
    }
}
