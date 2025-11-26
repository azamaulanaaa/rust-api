use std::{
    future::{Ready, ready},
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
use serde::Deserialize;

use super::bearer_token::BearerToken;

pub struct JwtClaimsMiddleware {
    key: Arc<DecodingKey>,
    validation: Validation,
}

impl JwtClaimsMiddleware {
    pub fn new(key: DecodingKey, validation: Validation) -> Self {
        Self {
            key: Arc::new(key),
            validation,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtClaimsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtClaimsMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtClaimsMiddlewareService {
            service: Rc::new(service),
            key: self.key.clone(),
            validation: self.validation.clone(),
        }))
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub struct JwtClaimsMiddlewareService<S> {
    service: Rc<S>,
    key: Arc<DecodingKey>,
    validation: Validation,
}

impl<S, B> Service<ServiceRequest> for JwtClaimsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
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
            match decode::<Claims>(&bearer_token.0, &key, &validation) {
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
