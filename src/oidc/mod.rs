use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use thiserror::Error;

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
}

/// Errors raised by [`OidcClient`] during discovery and token exchange.
#[derive(Error, Debug)]
pub enum OidcError {
    /// Client configuration could not be applied.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// A provider or redirect URL failed to parse.
    #[error("Invalid URL format: {0}")]
    UrlParse(#[from] url::ParseError),

    /// The outbound HTTP request to the provider failed.
    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    /// The provider's discovery document was missing or malformed.
    #[error("Failed to discover OIDC provider: {0}")]
    Discovery(String),

    /// The authorization-code exchange was rejected by the provider.
    #[error("Failed to exchange authorization code: {0}")]
    ExchangeFailure(String),

    /// The provider's token response contained no ID token.
    #[error("Provider did not return an ID token")]
    MissingIdToken,

    /// The ID token failed signature, nonce, or claims validation.
    #[error("ID token validation failed: {0}")]
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
}

/// Everything a caller needs to start the authorization-code flow: the
/// provider URL to redirect the user agent to, plus the CSRF/nonce/PKCE
/// values that must round-trip through temporary cookies.
pub struct AuthUrlResponse {
    /// The provider's authorization endpoint URL including query params.
    pub url: String,
    /// CSRF value; also carried as the OAuth2 `state` parameter.
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

        let provider_metadata =
            CoreProviderMetadata::discover_async(IssuerUrl::new(config.issuer_url)?, &http_client)
                .await
                .map_err(|e| OidcError::Discovery(e.to_string()))?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata.clone(),
            ClientId::new(config.client_id),
            Some(ClientSecret::new(config.client_secret)),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_url)?);

        Ok(Self {
            client,
            http_client,
            provider_metadata,
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
    /// Returns the raw serialized ID token on success.
    pub async fn exchange_code(
        &self,
        code: String,
        nonce: Nonce,
        pkce_verifier: PkceCodeVerifier,
    ) -> Result<String, OidcError> {
        let request = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|e| OidcError::Configuration(format!("{:?}", e)))?;

        let token_response = request
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http_client)
            .await
            .map_err(|e| OidcError::ExchangeFailure(e.to_string()))?;

        let id_token = token_response.id_token().ok_or(OidcError::MissingIdToken)?;

        let _claims = id_token
            .claims(&self.client.id_token_verifier(), &nonce)
            .map_err(|e| OidcError::InvalidToken(e.to_string()))?;

        Ok(id_token.to_string())
    }

    /// The provider's discovered issuer URL.
    pub fn issuer(&self) -> &IssuerUrl {
        self.provider_metadata.issuer()
    }

    /// The OAuth2 client ID used for token requests.
    pub fn client_id(&self) -> &ClientId {
        self.client.client_id()
    }

    /// The provider's JWKS endpoint hosting its public signing keys.
    pub fn jwks_uri(&self) -> &url::Url {
        self.provider_metadata.jwks_uri().url()
    }
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

    #[tokio::test]
    async fn oidc_end_to_end() -> anyhow::Result<()> {
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

        let output_token = oidc_client
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
