//! Shared API error type rendering a uniform JSON error envelope.
//!
//! Every API failure serializes as `{"error": "<message>"}` where the
//! message is a stable, non-sensitive description. Underlying causes are
//! attached via [`std::error::Error::source`] and logged server-side by the
//! response renderer — they are never sent to clients.

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use thiserror::Error;

/// Wire format for every API error: `{"error": "<message>"}`.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    /// Stable, non-sensitive description of the failure.
    pub error: String,
}

/// Application-wide API error.
///
/// The `Display` text (via `#[error]`) doubles as the client-facing body,
/// while any `#[source]` cause is reserved for server-side logging.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Request carried no credential at all. HTTP 401.
    #[error("authentication required")]
    MissingCredentials,

    /// Credential was present but failed verification; the source holds the
    /// rejection detail for logs only. HTTP 401.
    #[error("invalid credentials")]
    InvalidCredentials(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Authenticated subject lacks the required permission. HTTP 403.
    #[error("forbidden")]
    Forbidden,

    /// Unexpected failure; the source is logged server-side only. HTTP 500.
    #[error("internal server error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            Self::MissingCredentials | Self::InvalidCredentials(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        self.status()
    }

    fn error_response(&self) -> HttpResponse {
        // Causes carry sensitive internals (DB errors, provider responses):
        // log them here so call sites can't forget, never serialize them.
        if let Some(cause) = std::error::Error::source(self) {
            tracing::warn!("API {} {}: {cause}", self.status(), self);
        }

        HttpResponse::build(self.status()).json(ErrorBody {
            error: self.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_to_expected_codes() {
        assert_eq!(ApiError::MissingCredentials.status(), 401);
        assert_eq!(
            ApiError::InvalidCredentials("kid mismatch".into()).status(),
            401
        );
        assert_eq!(ApiError::Forbidden.status(), 403);
        assert_eq!(ApiError::Internal("db down".into()).status(), 500);
    }

    #[test]
    fn display_messages_are_stable_and_sanitized() {
        // Display must never embed the cause: it becomes the client body.
        let internal = ApiError::Internal("secret db DSN".into());
        assert_eq!(internal.to_string(), "internal server error");

        let invalid = ApiError::InvalidCredentials("raw jwks dump".into());
        assert_eq!(invalid.to_string(), "invalid credentials");
        // Source chain still exposes the cause for logging.
        assert_eq!(
            std::error::Error::source(&invalid)
                .expect("cause retained")
                .to_string(),
            "raw jwks dump"
        );
    }

    #[actix_web::test]
    async fn error_response_renders_uniform_envelope() {
        let err = ApiError::MissingCredentials;
        let res = err.error_response();
        assert_eq!(res.status(), 401);

        // Re-render through a full request cycle to exercise serialization.
        let body = actix_web::body::to_bytes(res.into_body()).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"authentication required"}"#);
    }
}
