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
    /// S3 or store failure - 500. The inner detail is logged server-side
    /// only and never rendered to clients (see `error_response`).
    #[error("internal server error")]
    Internal(String),
    /// Oxkv store error - 500. Same sanitization contract as `Internal`.
    #[error("internal server error")]
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
        // Internal/store causes carry sensitive detail (S3 errors, store
        // paths): log them here so call sites can't forget, never
        // serialize them — the body only carries the stable Display text.
        match self {
            Self::Internal(detail) | Self::Store(detail) => {
                tracing::warn!("fs error {}: internal: {detail}", self.status_code());
            }
            Self::BadRequest(_) | Self::NotFound(_) | Self::Conflict(_) => {
                tracing::debug!("fs error {}: {}", self.status_code(), self);
            }
            Self::Forbidden => {}
        }
        let body = serde_json::json!({ "error": self.to_string() });
        HttpResponse::build(self.status_code()).json(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_detail_never_reaches_clients() {
        let err = FsError::Internal("secret bucket DSN".to_string());
        assert_eq!(err.to_string(), "internal server error");
        let store = FsError::Store("raw oxkv dump".to_string());
        assert_eq!(store.to_string(), "internal server error");
    }

    #[actix_web::test]
    async fn internal_body_is_sanitized() {
        let res = FsError::Internal("secret bucket DSN".to_string()).error_response();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = actix_web::body::to_bytes(res.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "internal server error");
        assert!(!String::from_utf8_lossy(&body).contains("secret"));
    }
}
