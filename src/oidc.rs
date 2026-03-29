use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    pub redirect_url: String,
}

#[derive(Error, Debug)]
pub enum OidcError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Invalid URL format: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("Failed to discover OIDC provider: {0}")]
    Discovery(String),

    #[error("Failed to exchange authorization code: {0}")]
    ExchangeFailure(String),

    #[error("Provider did not return an ID token")]
    MissingIdToken,

    #[error("ID token validation failed: {0}")]
    InvalidToken(String),
}

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

pub struct AuthUrlResponse {
    pub url: String,
    pub csrf_token: CsrfToken,
    pub nonce: Nonce,
    pub pkce_verifier: PkceCodeVerifier,
}

impl OidcClient {
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

    pub fn issuer(&self) -> &IssuerUrl {
        self.provider_metadata.issuer()
    }

    pub fn jwks_uri(&self) -> &url::Url {
        self.provider_metadata.jwks_uri().url()
    }
}
