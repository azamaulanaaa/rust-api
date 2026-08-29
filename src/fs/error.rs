//! Error type for the FS module, mapped to the uniform `{"error":...}` envelope.

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use thiserror::Error;

/// Errors raised by the FS engine and routes.
#[derive(Debug, Error)]
pub enum FsError {
    /// Validation failure - 400.
    #[error("{0}")]
    BadRequest(String),
    /// Caller lacks permission - 403.
    #[error("forbidden")]
    Forbidden,
    /// Resource not found - 404.
    #[error("{0}")]
    NotFound(String),
    /// Conflict (e.g. duplicate).
    #[error("{0}")]
    Conflict(String),
    /// S3 or store failure - 500.
    #[error("internal server error: {0}")]
    Internal(String),
    /// Oxkv store error
    #[error("store error: {0}")]
    Store(String),
}

impl From<oxkv::StoreError> for FsError {
    fn from(e: oxkv::StoreError) -> Self {
        Self::Store(e.to_string())
    }
}

impl ResponseError for FsError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Internal(_) | Self::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        if matches!(self, Self::Internal(_) | Self::Store(_)) {
            tracing::warn!("fs error {}: {}", self.status_code(), self);
        }
        let body = serde_json::json!({ "error": self.to_string() });
        HttpResponse::build(self.status_code()).json(body)
    }
}
