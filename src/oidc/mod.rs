//! OpenID Connect client and login/callback routes implementing the
//! authorization-code flow with PKCE, CSRF state, and nonce validation.
//!
//! [`OidcClient`](crate::oidc::OidcClient) wraps the discovered provider
//! metadata. It builds authorization URLs with fresh PKCE/CSRF/nonce values.
//! It exchanges authorization codes for signature-verified ID tokens.
//! Multi-tenant providers that publish a `{tenantid}` issuer
//! placeholder are supported by resolving the expected issuer per token
//! instead of pinning it statically.

use std::time::Duration;

use openidconnect::core::{CoreClient, CoreIdToken, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret,
    CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, JsonWebKeySet, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken,
    RevocationUrl, Scope, SignatureVerificationError, TokenResponse,
};
use tokio::sync::RwLock;

use thiserror::Error;

use crate::http::middleware::jwt::{IssuerTemplate, extract_unverified_claim};

/// HTTP routes for the OIDC login and callback endpoints.
pub mod route;

/// The connect timeout for every call to the identity provider.
pub const PROVIDER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The request timeout for every call to the identity provider.
///
/// This bound applies to discovery, the token exchange, token refresh, the
/// JWKS fetch, and token revocation.
pub const PROVIDER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The concrete OpenID Connect client type that this module uses.
type CoreOidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

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

    /// The provider rejected or did not complete token revocation.
    #[error("token revocation failed: {0}")]
    Revocation(String),
}

/// OpenID Connect client wrapping the discovered provider metadata:
/// builds authorization URLs with PKCE/CSRF/nonce and exchanges
/// authorization codes for validated ID tokens.
pub struct OidcClient {
    /// The provider client. The lock lets a callback replace the client
    /// after the provider rotates its signing keys.
    client: RwLock<CoreOidcClient>,
    /// RFC 7009 client. It is present only when discovery advertises a
    /// revocation endpoint.
    revocation_client: Option<
        CoreClient<
            EndpointSet,
            EndpointNotSet,
            EndpointNotSet,
            EndpointSet,
            EndpointMaybeSet,
            EndpointMaybeSet,
        >,
    >,
    client_id: ClientId,
    /// Client secret for the RFC 7009 revocation request.
    client_secret: String,
    http_client: reqwest::Client,
    /// URL of the discovery document. A key refresh reads it again.
    discovery_url: String,
    jwks_uri: url::Url,
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
    request_timeout: Duration,
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
        Self::new_with_timeouts(config, PROVIDER_CONNECT_TIMEOUT, PROVIDER_REQUEST_TIMEOUT).await
    }

    /// Builds the client with explicit timeouts.
    ///
    /// A test uses this entry point to bound a delayed provider response.
    async fn new_with_timeouts(
        config: OidcConfig,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, OidcError> {
        let http_client = reqwest::ClientBuilder::new()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer_url.trim_end_matches('/')
        );
        let (raw_issuer, issuer_template, revocation_endpoint, provider_metadata) =
            fetch_provider_metadata(&http_client, &discovery_url, &config.allowed_tenants).await?;
        let jwks_uri = provider_metadata.jwks_uri().url().clone();

        let client_id = ClientId::new(config.client_id);
        let client_secret = ClientSecret::new(config.client_secret.clone());

        let revocation_client = match revocation_endpoint {
            Some(endpoint) => {
                let revocation_url = RevocationUrl::new(endpoint).map_err(|e| {
                    OidcError::Configuration(format!("invalid revocation endpoint: {e}"))
                })?;
                let client = CoreClient::from_provider_metadata(
                    provider_metadata.clone(),
                    client_id.clone(),
                    Some(client_secret.clone()),
                )
                .set_revocation_url(revocation_url);
                Some(client)
            }
            None => None,
        };

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            client_id.clone(),
            Some(client_secret),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone())?);

        Ok(Self {
            client: RwLock::new(client),
            revocation_client,
            client_id,
            client_secret: config.client_secret,
            http_client,
            discovery_url,
            jwks_uri,
            issuer: raw_issuer,
            issuer_template,
            redirect_url: config.redirect_url,
            allowed_tenants: config.allowed_tenants,
            request_timeout,
        })
    }

    /// Fetches the provider metadata and its JWKS again.
    ///
    /// A callback calls this function when an ID token names a signing key
    /// that the current JWKS does not hold. That state follows a key
    /// rotation at the provider.
    async fn refresh_id_token_keys(&self) -> Result<(), OidcError> {
        let (_, _, _, provider_metadata) = fetch_provider_metadata(
            &self.http_client,
            &self.discovery_url,
            &self.allowed_tenants,
        )
        .await?;
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            self.client_id.clone(),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(self.redirect_url.clone())?);
        *self.client.write().await = client;
        Ok(())
    }

    /// Generates a fresh authorization URL with a new PKCE challenge,
    /// CSRF token, and nonce. The returned secrets must be stored in
    /// temporary cookies and passed back to [`OidcClient::exchange_code`].
    pub async fn get_auth_url(&self) -> AuthUrlResponse {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let client = self.client.read().await;
        let (url, csrf_token, nonce) = client
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
        let token_response = {
            let client = self.client.read().await;
            let request = client
                .exchange_code(AuthorizationCode::new(code))
                .map_err(|e| OidcError::Configuration(format!("{:?}", e)))?;
            request
                .set_pkce_verifier(pkce_verifier)
                .request_async(&self.http_client)
                .await
                .map_err(|e| OidcError::ExchangeFailure(e.to_string()))?
        };

        let refresh_token = token_response
            .refresh_token()
            .map(|token| token.secret().to_string());
        let id_token = token_response.id_token().ok_or(OidcError::MissingIdToken)?;

        self.verify_id_token_with_refresh(id_token, Some(&nonce))
            .await?;

        Ok((id_token.to_string(), refresh_token))
    }

    /// Renews an ID token using a provider refresh token. Returns the new
    /// ID token and, when the provider rotated it, a new refresh token.
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<(String, Option<String>), OidcError> {
        let token_response = {
            let client = self.client.read().await;
            let refresh_token_value = RefreshToken::new(refresh_token.to_string());
            let request = client
                .exchange_refresh_token(&refresh_token_value)
                .map_err(|e| OidcError::Configuration(format!("{:?}", e)))?;
            request
                .request_async(&self.http_client)
                .await
                .map_err(|e| OidcError::ExchangeFailure(e.to_string()))?
        };

        let new_refresh = token_response
            .refresh_token()
            .map(|token| token.secret().to_string());
        let id_token = token_response.id_token().ok_or(OidcError::MissingIdToken)?;

        // The refresh response carries a new ID token but no fresh nonce.
        // Keep signature, audience, and expiry validation, then re-apply the
        // tenant gate that `exchange_code` uses. Trusting the signed token
        // alone would let any tenant that consented to the app registration
        // mint a session for this deployment.
        self.verify_id_token_with_refresh(id_token, None).await?;

        Ok((id_token.to_string(), new_refresh))
    }

    /// Verifies an ID token, and retries once with fresh keys.
    ///
    /// The provider can rotate its signing keys after startup. An ID token
    /// then names a `kid` that the cached JWKS does not hold. The function
    /// fetches the metadata and JWKS again, rebuilds the client, and runs the
    /// verification one more time.
    async fn verify_id_token_with_refresh(
        &self,
        id_token: &CoreIdToken,
        nonce: Option<&Nonce>,
    ) -> Result<(), OidcError> {
        let first = {
            let client = self.client.read().await;
            self.verify_id_token(&client, id_token, nonce)
        };

        match first {
            Err(OidcError::InvalidToken(message)) if mentions_unknown_key(&message) => {
                tracing::info!("refreshing the OIDC JWKS after an unknown signing key");
                self.refresh_id_token_keys().await?;
                let client = self.client.read().await;
                self.verify_id_token(&client, id_token, nonce)
            }
            other => other,
        }
    }

    /// Verifies the signature, nonce, issuer, and claims of an ID token.
    fn verify_id_token(
        &self,
        client: &CoreOidcClient,
        id_token: &CoreIdToken,
        nonce: Option<&Nonce>,
    ) -> Result<(), OidcError> {
        // A multi-tenant provider publishes an issuer that carries a
        // {tenantid} placeholder. No real token can match that placeholder,
        // so the client disables the static issuer check. The client then
        // enforces the template against the tenant identifier of the token
        // itself. Signature, nonce, audience, and expiry validation do not
        // change.
        let verifier = if self.issuer_template.is_some() {
            client.id_token_verifier().require_issuer_match(false)
        } else {
            client.id_token_verifier()
        };

        let claims = match nonce {
            Some(nonce) => id_token.claims(&verifier, nonce),
            None => id_token.claims(&verifier, |_: Option<&Nonce>| Ok(())),
        };
        claims.map_err(map_claims_error)?;

        if let Some(template) = &self.issuer_template {
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
        }

        Ok(())
    }

    /// Whether auth cookies must carry the `Secure` flag.
    ///
    /// True for `https://` callbacks. Plain-http deployments (local dev)
    /// opt out, so that browsers accept the cookies at all. Unparseable
    /// URLs fail closed to `true`.
    pub fn secure_cookies(&self) -> bool {
        secure_scheme(&self.redirect_url)
    }

    /// Whether provider discovery advertises an RFC 7009 revocation endpoint.
    pub fn has_revocation_endpoint(&self) -> bool {
        self.revocation_client.is_some()
    }

    /// Revokes a refresh token with the provider's RFC 7009 endpoint.
    ///
    /// The call is a no-op when discovery has no revocation endpoint. The
    /// request uses the same HTTP client as the token calls. That client
    /// bounds the request with its timeout.
    pub async fn revoke_token(&self, token: &str) -> Result<(), OidcError> {
        let Some(client) = &self.revocation_client else {
            return Ok(());
        };
        // The oauth2 client rejects a revocation URL that does not use https.
        // A local provider can advertise an http endpoint, so this method
        // sends the RFC 7009 form itself. It uses the configured client URL
        // and the same client credentials.
        let response = self
            .http_client
            .post(client.revocation_url().url().clone())
            .basic_auth(client.client_id().as_str(), Some(&self.client_secret))
            .form(&[("token", token), ("token_type_hint", "refresh_token")])
            .send()
            .await
            .map_err(|e| OidcError::Revocation(e.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(OidcError::Revocation(format!(
                "provider returned {}",
                response.status()
            )))
        }
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
        &self.client_id
    }

    /// The provider's JWKS endpoint hosting its public signing keys.
    pub fn jwks_uri(&self) -> &url::Url {
        &self.jwks_uri
    }

    /// The request timeout for every call to the provider.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// The tenant identifiers this deployment accepts for a templated
    /// issuer. Empty for a single-tenant issuer.
    pub fn allowed_tenants(&self) -> &[String] {
        &self.allowed_tenants
    }
}

/// Fetches the provider discovery document and its JWKS.
///
/// The client fetches the discovery document by hand. Multi-tenant
/// providers publish an issuer that contains a literal `{tenantid}`
/// placeholder. That placeholder can never equal the requested URL, and
/// openidconnect rejects such metadata. The function substitutes a sentinel
/// tenant before it parses the document. The client then enforces the issuer
/// per token against the parsed template.
async fn fetch_provider_metadata(
    http_client: &reqwest::Client,
    discovery_url: &str,
    allowed_tenants: &[String],
) -> Result<
    (
        String,
        Option<IssuerTemplate>,
        Option<String>,
        CoreProviderMetadata,
    ),
    OidcError,
> {
    let body = http_client
        .get(discovery_url)
        .send()
        .await
        .map_err(OidcError::HttpClient)?
        .error_for_status()
        .map_err(|e| OidcError::Discovery(e.to_string()))?
        .text()
        .await
        .map_err(OidcError::HttpClient)?;

    let discovery = serde_json::from_str::<serde_json::Value>(&body)
        .map_err(|e| OidcError::Discovery(e.to_string()))?;
    let revocation_endpoint = discovery
        .get("revocation_endpoint")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let raw_issuer = discovery
        .get("issuer")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| OidcError::Discovery("metadata missing issuer".to_string()))?
        .to_string();
    let issuer_template = IssuerTemplate::parse(&raw_issuer, allowed_tenants.to_vec());
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

    // from_provider_metadata reads the keys of the ID-token verifier from
    // the JWKS that the metadata embeds. This call supplies that document
    // for metadata that the client parsed by hand.
    let jwks = JsonWebKeySet::fetch_async(provider_metadata.jwks_uri(), http_client)
        .await
        .map_err(|e| OidcError::Discovery(e.to_string()))?;

    Ok((
        raw_issuer,
        issuer_template,
        revocation_endpoint,
        provider_metadata.set_jwks(jwks),
    ))
}

/// Maps a claims verification error to an [`OidcError`].
///
/// The display text of `SignatureVerification` hides its source. The source
/// is the only place that says whether the token named an unknown signing
/// key. The mapping keeps that fact, so the caller can refresh the JWKS.
fn map_claims_error(error: ClaimsVerificationError) -> OidcError {
    if let ClaimsVerificationError::SignatureVerification(
        SignatureVerificationError::NoMatchingKey | SignatureVerificationError::AmbiguousKeyId(_),
    ) = &error
    {
        return OidcError::InvalidToken(format!("unknown signing key: {error}"));
    }
    OidcError::InvalidToken(error.to_string())
}

/// Reports whether an ID-token error says that no key matched the token.
///
/// The provider names the signing key in the token header. A key that left
/// the JWKS after a rotation yields this error. Any other validation error
/// must not start a key refresh.
fn mentions_unknown_key(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "unknown signing key",
        "no matching key",
        "matching key not found",
        "no key found",
        "unknown key",
        "unknown kid",
        "kid not found",
    ]
    .iter()
    .any(|needle| message.contains(needle))
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
            OidcError::Revocation("400 from /revoke".into()).to_string(),
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
        let auth_data = oidc_client.get_auth_url().await;

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

    /// A delayed provider response must not hold the callback open.
    ///
    /// The client applies one request timeout to discovery, JWKS, and token
    /// calls. The test uses a short timeout and a two-second delay.
    #[tokio::test]
    async fn a_slow_provider_request_hits_the_request_timeout() -> anyhow::Result<()> {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
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
                "id_token_signing_alg_values_supported": ["RS256"]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(2))
                    .set_body_json(json!({
                        "access_token": "late-access",
                        "token_type": "Bearer",
                    })),
            )
            .mount(&server)
            .await;

        let client = OidcClient::new_with_timeouts(
            OidcConfig {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                issuer_url: server.uri(),
                redirect_url: "http://localhost/callback".to_string(),
                allowed_tenants: Vec::new(),
            },
            Duration::from_millis(100),
            Duration::from_millis(200),
        )
        .await?;

        let auth_data = client.get_auth_url().await;
        let started = std::time::Instant::now();
        let result = client
            .exchange_code(
                "slow-code".to_string(),
                auth_data.nonce,
                auth_data.pkce_verifier,
            )
            .await;

        assert!(result.is_err(), "the slow response must time out");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the request timeout must bound the call, took {:?}",
            started.elapsed()
        );
        Ok(())
    }

    #[test]
    fn an_unknown_key_error_is_recognized() {
        assert!(mentions_unknown_key(
            "signature verification failed: no matching key found"
        ));
        assert!(mentions_unknown_key("unknown kid in token header"));
        assert!(!mentions_unknown_key("expired token"));
        assert!(!mentions_unknown_key("audience mismatch"));
    }
}
