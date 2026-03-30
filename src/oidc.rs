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

    pub fn client_id(&self) -> &ClientId {
        self.client.client_id()
    }

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
