use std::{
    collections::HashMap,
    future::{Ready, ready},
    marker::PhantomData,
    rc::Rc,
    sync::Arc,
};

use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    error::ErrorUnauthorized,
};
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::decode;
pub use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde::{Deserialize, de::DeserializeOwned};

use super::bearer_token::BearerToken;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multi(Vec<String>),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    pub iss: String,           // Issuer
    pub sub: String,           // Subject (User ID)
    pub aud: Audience,         // Handle both String and [String]
    pub exp: u64,              // Expiration (u64 for 2038+ safety)
    pub nbf: Option<u64>,      // Not Before
    pub iat: Option<u64>,      // Issued At
    pub nonce: Option<String>, // Required for OIDC flow verification
    pub jti: Option<String>,   // JWT ID (Good for revocation)
}

#[derive(Clone)]
pub struct JwtClaimsMiddleware<C>
where
    C: DeserializeOwned,
{
    keys: Arc<HashMap<String, DecodingKey>>,
    validation: Validation,
    _claims: PhantomData<C>,
}

impl<C> JwtClaimsMiddleware<C>
where
    C: DeserializeOwned,
{
    pub fn new(keys: HashMap<String, DecodingKey>, validation: Validation) -> Self {
        Self {
            keys: Arc::new(keys),
            validation,
            _claims: PhantomData,
        }
    }

    pub async fn new_with_jks(
        jwks_url: &str,
        audience: &str,
        issuer: &str,
    ) -> anyhow::Result<Self> {
        let jwks: JwkSet = reqwest::get(jwks_url).await?.json().await?;
        let keys = jwks
            .keys
            .iter()
            .map(|jwk| {
                let kid = jwk
                    .common
                    .key_id
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("JWK missing key_id"))?;

                let decoding_key = DecodingKey::from_jwk(jwk)?;

                Ok((kid, decoding_key))
            })
            .collect::<anyhow::Result<HashMap<_, _>>>()?;

        if keys.is_empty() {
            anyhow::bail!("No valid keys found in JWKS at {}", jwks_url);
        }

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

pub struct JwtClaimsMiddlewareService<S, C> {
    service: Rc<S>,
    keys: Arc<HashMap<String, DecodingKey>>,
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

        let token = [
            req.cookie("auth_token").map(|c| c.value().to_string()),
            req.extensions().get::<BearerToken>().cloned().map(|v| v.0),
        ]
        .into_iter()
        .flatten()
        .next();

        if let Some(token) = token {
            let header = match jsonwebtoken::decode_header(&token) {
                Ok(h) => h,
                Err(e) => return Box::pin(async move { Err(ErrorUnauthorized(e)) }),
            };

            let decoding_key = header
                .kid
                .and_then(|id| keys.get(&id))
                .or_else(|| keys.values().next());

            if let Some(key) = decoding_key {
                match decode::<C>(&token, key, &validation) {
                    Ok(token_data) => {
                        req.extensions_mut().insert(token_data.claims);
                    }
                    Err(e) => {
                        return Box::pin(async move {
                            Err(ErrorUnauthorized(format!("Invalid Token: {}", e)))
                        });
                    }
                }
            } else {
                return Box::pin(async move {
                    Err(ErrorUnauthorized("No matching key found for token"))
                });
            }
        }

        return Box::pin(async move { svc.call(req).await });
    }
}
