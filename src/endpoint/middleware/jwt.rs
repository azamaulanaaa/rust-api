//! Actix middleware validating JWTs against a JWKS-backed key store.
//!
//! Validated claims (generic over `C`) are inserted into request extensions
//! — consume them with [`Validated`] — and requests without any token pass
//! through unmodified so routes decide their own auth requirements.

use std::{
    future::{Ready, ready},
    marker::PhantomData,
    rc::Rc,
};

use actix_web::{
    Error, FromRequest, HttpMessage, HttpRequest,
    dev::{Payload, Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
};
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::decode;
pub use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde::{Deserialize, de::DeserializeOwned};

use super::bearer_token::BearerToken;
use super::jwks::JwksKeys;
use crate::endpoint::error::ApiError;

// Preserve the public API surface for consumers of this module.
pub use super::jwks::SigningKey;

/// Audience (`aud`) claim values: providers emit either a single string or
/// an array of strings, both of which deserialize into this enum.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience value.
    Single(String),
    /// Multiple audience values.
    Multi(Vec<String>),
}

/// Standard ID-token claims extracted from a validated JWT and inserted
/// into request extensions.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    /// Issuer: the identity provider that issued the token.
    pub iss: String,
    /// Subject: the stable user identifier.
    pub sub: String,
    /// Audience(s) the token was issued for.
    pub aud: Audience,
    /// Expiration time (unix seconds); validated on every request.
    pub exp: u64,
    /// Not-before time (unix seconds), when present.
    pub nbf: Option<u64>,
    /// Issued-at time (unix seconds), when present.
    pub iat: Option<u64>,
    /// Nonce echoed back by the provider during the OIDC flow.
    pub nonce: Option<String>,
    /// Unique token identifier; usable as a revocation key.
    pub jti: Option<String>,
}

/// Actix middleware validating JWTs against a [`JwksKeys`] store before the
/// request reaches the wrapped service. Validated claims (generic over `C`)
/// are inserted into request extensions — consume them with [`Validated`] —
/// and requests without any token pass through unmodified so routes decide
/// their own auth requirements.
#[derive(Clone)]
pub struct JwtClaimsMiddleware<C>
where
    C: DeserializeOwned,
{
    keys: JwksKeys,
    validation: Validation,
    _claims: PhantomData<C>,
}

impl<C> JwtClaimsMiddleware<C>
where
    C: DeserializeOwned,
{
    /// Assembles the middleware from an existing key store and base
    /// validation config (audience/issuer/leeway).
    pub fn new(keys: JwksKeys, validation: Validation) -> Self {
        Self {
            keys,
            validation,
            _claims: PhantomData,
        }
    }

    /// Fetches the JWKS document from `jwks_url` and builds the middleware,
    /// pinning `audience` and `issuer` validation. See [`JwksKeys`] for the
    /// refresh behavior.
    pub async fn new_with_jks(
        jwks_url: &str,
        audience: &str,
        issuer: &str,
    ) -> anyhow::Result<Self> {
        let keys = JwksKeys::new(jwks_url).await?;

        // Base validation carries the audience/issuer checks; the expected
        // algorithm is re-pinned per request from the selected signing key.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[issuer]);

        Ok(Self::new(keys, validation))
    }
}

impl<S, B, C> Transform<S, ServiceRequest> for JwtClaimsMiddleware<C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    C: DeserializeOwned + Clone + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtClaimsMiddlewareService<S, C>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtClaimsMiddlewareService {
            service: Rc::new(service),
            keys: self.keys.clone(),
            validation: self.validation.clone(),
            _claims: PhantomData,
        }))
    }
}

/// Extractor for claims validated by [`JwtClaimsMiddleware`].
///
/// Unlike `web::ReqData`, which fails extraction with a 500 when the
/// middleware did not run or no token was presented, this resolves to a
/// **401 Unauthorized** — anonymous hits on protected routes must not look
/// like server faults.
#[derive(Debug)]
pub struct Validated<C>(pub C);

impl<C> std::ops::Deref for Validated<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C> FromRequest for Validated<C>
where
    C: DeserializeOwned + Clone + 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(
            req.extensions()
                .get::<C>()
                .cloned()
                .map(Self)
                .ok_or_else(|| ApiError::MissingCredentials.into()),
        )
    }
}

/// The per-worker instantiated middleware produced by
/// [`JwtClaimsMiddleware::new_transform`]. Not constructed directly.
pub struct JwtClaimsMiddlewareService<S, C> {
    service: Rc<S>,
    keys: JwksKeys,
    validation: Validation,
    _claims: PhantomData<C>,
}

impl<S, B, C> Service<ServiceRequest> for JwtClaimsMiddlewareService<S, C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    C: DeserializeOwned + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let keys = self.keys.clone();
        let validation = self.validation.clone();

        // Bearer header wins over the auth cookie: a stale/expired browser
        // session cookie must not shadow an explicitly presented header.
        let token = [
            req.extensions().get::<BearerToken>().cloned().map(|v| v.0),
            req.cookie("auth_token").map(|c| c.value().to_string()),
        ]
        .into_iter()
        .flatten()
        .next();

        Box::pin(async move {
            if let Some(token) = token {
                let header = match jsonwebtoken::decode_header(&token) {
                    Ok(h) => h,
                    Err(e) => {
                        return Err(ApiError::InvalidCredentials(Box::new(e)).into());
                    }
                };

                let Some(signing_key) = keys.get(header.kid.as_deref()).await else {
                    let cause = format!("no signing key matches kid {:?}", header.kid);
                    return Err(ApiError::InvalidCredentials(cause.into()).into());
                };

                // Pin validation to the selected key's own algorithm so a
                // token cannot downgrade to an unexpected algorithm.
                let mut validation = validation.clone();
                validation.algorithms = vec![signing_key.algorithm];

                match decode::<C>(&token, &signing_key.decoding_key, &validation) {
                    Ok(token_data) => req.extensions_mut().insert(token_data.claims),
                    Err(e) => return Err(ApiError::InvalidCredentials(Box::new(e)).into()),
                };
            }

            svc.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::middleware::jwks::test_support::*;
    use serde_json::json;

    #[tokio::test]
    async fn loads_keys_and_decodes_token() -> anyhow::Result<()> {
        let (key_a, enc_a) = rsa_key("kid-a")?;
        let server = spawn_jwks(json!({ "keys": [key_a] })).await;

        let keys = JwksKeys::new(format!("{}/jwks", server.uri())).await?;

        let token = sign_rs256(
            &json!({ "sub": "u1", "exp": 2000000000u64 }),
            "kid-a",
            &enc_a,
        )?;
        let signing_key = keys.get(Some("kid-a")).await.expect("kid-a should resolve");
        assert_eq!(signing_key.algorithm, Algorithm::RS256);

        let validation = Validation::new(Algorithm::RS256);
        let decoded = decode::<TestClaims>(&token, &signing_key.decoding_key, &validation)?;
        assert_eq!(decoded.claims.sub, "u1");

        Ok(())
    }

    fn sample_claims() -> Claims {
        Claims {
            iss: "https://idp.test".to_string(),
            sub: "u1".to_string(),
            aud: Audience::Single("client".to_string()),
            exp: 2000000000,
            nbf: None,
            iat: Some(1000000000),
            nonce: None,
            jti: None,
        }
    }

    #[actix_web::test]
    async fn validated_extractor_resolves_inserted_claims() {
        use actix_web::test::TestRequest;

        let (req, mut payload) = TestRequest::default().to_http_parts();
        req.extensions_mut().insert(sample_claims());

        let extracted = Validated::<Claims>::from_request(&req, &mut payload)
            .await
            .expect("claims present");
        assert_eq!(extracted.sub, "u1"); // Deref to the inner claims
    }

    #[actix_web::test]
    async fn validated_extractor_is_unauthorized_when_missing() {
        use actix_web::test::TestRequest;

        let (req, mut payload) = TestRequest::default().to_http_parts();

        let result = Validated::<Claims>::from_request(&req, &mut payload).await;
        assert_eq!(result.unwrap_err().as_response_error().status_code(), 401);
    }
}
