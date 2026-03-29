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
pub use jsonwebtoken::{DecodingKey, Validation};
use serde::de::DeserializeOwned;

use super::bearer_token::BearerToken;

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

        let token_wrapper = req.extensions().get::<BearerToken>().cloned();

        if let Some(bearer_token) = token_wrapper {
            let header = match jsonwebtoken::decode_header(&bearer_token.0) {
                Ok(h) => h,
                Err(e) => return Box::pin(async move { Err(ErrorUnauthorized(e)) }),
            };

            let decoding_key = header
                .kid
                .and_then(|id| keys.get(&id))
                .or_else(|| keys.values().next());

            if let Some(key) = decoding_key {
                match decode::<C>(&bearer_token.0, key, &validation) {
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
