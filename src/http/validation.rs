//! Reusable request-body validation for Actix handlers.
//!
//! A handler takes [`ValidatedJson<T>`] instead of `web::Json<T>`. The
//! extractor deserializes the body as `T` and then calls
//! [`Validate::validate`] on it. A body that fails either step answers with
//! the uniform [`ApiError`] envelope (HTTP 400).

use std::future::Future;
use std::pin::Pin;

use actix_web::{FromRequest, HttpRequest, dev::Payload, web};
use serde::de::DeserializeOwned;

use crate::http::error::ApiError;

/// A value that knows how to check its own invariants.
///
/// Implement this trait for a request body type. Return
/// [`ValidationError`] when the value is not acceptable.
/// [`ValidatedJson`] calls the method after deserialization.
pub trait Validate {
    /// Checks the invariants of `self`.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `self` is not acceptable.
    fn validate(&self) -> Result<(), ValidationError>;
}

/// The error returned by [`Validate::validate`].
///
/// The message is for server-side logs. [`ValidatedJson`] never puts it on
/// the wire; the client receives the fixed `bad request` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError(pub String);

impl ValidationError {
    /// Builds a [`ValidationError`] from any message-like value.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The message carried by this error.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ValidationError {}

impl From<String> for ValidationError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl From<&str> for ValidationError {
    fn from(message: &str) -> Self {
        Self(message.to_string())
    }
}

/// An Actix extractor that deserializes a JSON body and validates it.
///
/// The extractor wraps [`web::Json<T>`]. It runs [`Validate::validate`]
/// after deserialization. A malformed body or a failed validation answers
/// with [`ApiError::BadRequest`] (HTTP 400), rendered as the uniform
/// envelope.
#[derive(Debug)]
pub struct ValidatedJson<T>(pub T);

impl<T> ValidatedJson<T> {
    /// Consumes the extractor and returns the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for ValidatedJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for ValidatedJson<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> FromRequest for ValidatedJson<T>
where
    T: DeserializeOwned + Validate + 'static,
{
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let json_future = web::Json::<T>::from_request(req, payload);
        Box::pin(async move {
            let json = json_future.await.map_err(|err| {
                tracing::debug!("malformed JSON body: {err}");
                actix_web::Error::from(ApiError::BadRequest)
            })?;
            json.0.validate().map_err(|err| {
                tracing::debug!("validation failed: {err}");
                actix_web::Error::from(ApiError::BadRequest)
            })?;
            Ok(ValidatedJson(json.into_inner()))
        })
    }
}

/// Convenience alias for [`ValidatedJson`].
pub type Validated<T> = ValidatedJson<T>;
