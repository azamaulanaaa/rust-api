use std::{
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
    key: Arc<DecodingKey>,
    validation: Validation,
    _claims: PhantomData<C>,
}

impl<C> JwtClaimsMiddleware<C>
where
    C: DeserializeOwned,
{
    pub fn new(key: DecodingKey, validation: Validation) -> Self {
        Self {
            key: Arc::new(key),
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
            key: self.key.clone(),
            validation: self.validation.clone(),
            _claims: PhantomData,
        }))
    }
}

pub struct JwtClaimsMiddlewareService<S, C> {
    service: Rc<S>,
    key: Arc<DecodingKey>,
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
        let key = self.key.clone();
        let validation = self.validation.clone();

        let token_wrapper = req.extensions().get::<BearerToken>().cloned();

        if let Some(bearer_token) = token_wrapper {
            match decode::<C>(&bearer_token.0, &key, &validation) {
                Ok(token_data) => {
                    req.extensions_mut().insert(token_data.claims);
                }
                Err(e) => {
                    return Box::pin(async move {
                        Err(ErrorUnauthorized(format!("Invalid Token: {}", e)))
                    });
                }
            }
        }
        return Box::pin(async move { svc.call(req).await });
    }
}
