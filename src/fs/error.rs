//! Error type for the FS module, mapped to the uniform `{"error":...}` envelope.
//!
//! # `Display` is not the client-facing message
//!
//! [`ApiError`](crate::http::error::ApiError)'s `#[error]` text *is* the
//! response body, and no variant of it carries a `String` so that cannot
//! leak. This type is the other way round: the 4xx variants hold
//! request-derived detail (a filename, a key, a size) and their `Display` is
//! that detail, which is for logs only. The wire gets a fixed string per
//! status instead.
//!
//! The two contracts are opposites for the same trait method, which is worth
//! stating at both types: reaching for `to_string()` when building a response
//! from an `FsError` sends user input to the client. Both render through
//! [`ApiError::envelope`](crate::http::error::ApiError), so the body is
//! `ErrorBody` either way.

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use thiserror::Error;

/// Errors raised by the FS engine and routes.
#[derive(Debug, Error)]
pub enum FsError {
    /// Validation failure - 400.
    #[error("{0}")]
    BadRequest(String),
    /// Request body exceeds the declared part size - 413.
    #[error("payload too large")]
    PayloadTooLarge,
    /// Caller lacks permission - 403.
    #[error("forbidden")]
    Forbidden,
    /// Resource not found - 404.
    #[error("{0}")]
    NotFound(String),
    /// S3 or store failure - 500. The inner detail is logged server-side
    /// only and never rendered to clients (see `error_response`).
    #[error("internal server error")]
    Internal(String),
    /// Oxkv store error - 500. Same sanitization contract as `Internal`.
    #[error("internal server error")]
    Store(String),
    /// A cost limit refused the request - 429.
    ///
    /// Raised when no concurrency slot was free for a replica download. A
    /// request *rate* limit would not catch the shape that matters here: a
    /// client allowed a hundred reads a minute can still have a hundred
    /// multi-hundred-megabyte segments in flight at once.
    #[error("too many requests")]
    TooManyRequests,

    /// The store's epoch was lost to another writer - 500.    ///
    /// Split out from [`Store`](Self::Store) because it is *actionable*:
    /// `oxkv` documents `StoreError::Fenced` as terminal ("the current
    /// process must stop writing and restart via `ownership.json` CAS"),
    /// and a caller that can recover from losing a fencing race — such as
    /// adopting a concurrent builder's coverage instead of failing — has to
    /// be able to recognise the condition.
    ///
    /// It used to detect that by searching the flattened detail for the
    /// substring `"fenced"`, which silently degraded to a 500 for every
    /// client if `oxkv` ever reworded the message. Same sanitization
    /// contract as `Store`: the reason is logged, never sent.
    #[error("internal server error")]
    Fenced(String),
}

impl From<oxkv::StoreError> for FsError {
    /// The single place an `oxkv` error is classified.
    ///
    /// Every conversion into `FsError` must go through here — including
    /// the `store_err` helpers in `fs::store` and `sync::snapshot` — or a
    /// fencing loss gets flattened into [`Store`](Self::Store) and becomes
    /// undetectable again.
    fn from(e: oxkv::StoreError) -> Self {
        match e {
            oxkv::StoreError::Fenced(reason) => Self::Fenced(reason),
            other => Self::Store(other.to_string()),
        }
    }
}

impl FsError {
    /// True when this is a lost epoch, i.e. another writer took the prefix.
    ///
    /// The detection point for recoverable fencing races. Distinct from a
    /// generic store failure: a fencing loss can be raced and retried,
    /// while a corrupt or missing store cannot.
    pub fn is_fencing_loss(&self) -> bool {
        matches!(self, Self::Fenced(_))
    }

    /// The store's own reason for a failure, for server-side logs.
    ///
    /// Never rendered to a client: every variant's `Display` is the fixed
    /// sanitized text, and only this reaches an operator.
    pub fn detail(&self) -> &str {
        match self {
            Self::BadRequest(d)
            | Self::NotFound(d)
            | Self::Internal(d)
            | Self::Store(d)
            | Self::Fenced(d) => d,
            Self::PayloadTooLarge | Self::Forbidden | Self::TooManyRequests => "",
        }
    }

    /// Stable client-facing message: never carries request input.
    ///
    /// The inner detail stays in `Display` for server-side logs; the
    /// wire body only gets this fixed string, so filenames, keys, and
    /// sizes from the request can never reflect back to clients.
    fn client_message(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad request",
            Self::Forbidden => "forbidden",
            Self::NotFound(_) => "not found",
            Self::PayloadTooLarge => "payload too large",
            Self::Internal(_) | Self::Store(_) | Self::Fenced(_) => "internal server error",
            Self::TooManyRequests => "too many requests",
        }
    }
}

impl ResponseError for FsError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Internal(_) | Self::Store(_) | Self::Fenced(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    fn error_response(&self) -> HttpResponse {
        // Internal/store causes carry sensitive detail (S3 errors, store
        // paths): log them here so call sites can't forget, never
        // serialize them — the body only carries the stable Display text.
        match self {
            // A lost epoch is not a transient blip: every subsequent write
            // on this handle will fail the same way. `error` so it stands
            // out in a log tail and is not lost among store warnings.
            Self::Fenced(detail) => {
                tracing::error!(
                    "fs error {}: store epoch lost to another writer ({detail}); \
                     this handle must stop writing and be rebuilt",
                    self.status_code()
                );
            }
            Self::Internal(detail) | Self::Store(detail) => {
                tracing::warn!("fs error {}: internal: {detail}", self.status_code());
            }
            Self::BadRequest(_) | Self::NotFound(_) | Self::PayloadTooLarge => {
                tracing::debug!("fs error {}: {}", self.status_code(), self);
            }
            Self::TooManyRequests => {
                tracing::debug!("fs error {}: download gate full", self.status_code());
            }
            Self::Forbidden => {}
        }
        // Rendered through `ApiError` so the served body is literally the
        // `ErrorBody` the OpenAPI document names, not a hand-built value
        // that happens to have the same shape. This type exists because the
        // FS engine's errors are richer than the API's, not because the
        // envelope needed a second implementation.
        crate::http::error::ApiError::envelope(self.status_code(), self.client_message())
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
        let fenced = FsError::Fenced("epoch 7 superseded by 8".to_string());
        assert_eq!(fenced.to_string(), "internal server error");
    }

    /// `From<oxkv::StoreError>` is the only place fencing is classified, so
    /// the split has to hold for every other oxkv error too.
    #[test]
    fn oxkv_fencing_is_classified_and_others_are_not() {
        assert!(FsError::from(oxkv::StoreError::Fenced("epoch 2".into())).is_fencing_loss());
        for other in [
            oxkv::StoreError::Storage("disk".into()),
            oxkv::StoreError::CasConflict("race".into()),
            oxkv::StoreError::NotModified,
        ] {
            let mapped = FsError::from(other);
            assert!(
                !mapped.is_fencing_loss(),
                "misdclassified: {mapped:?} ({mapped})"
            );
            assert!(matches!(mapped, FsError::Store(_)), "got {mapped:?}");
        }
    }

    /// `/fs` and `/sync` bodies are the documented `ErrorBody`, not a value
    /// that merely resembles it.
    ///
    /// The OpenAPI document names `ErrorBody` for this crate's errors, and
    /// `FsError` used to build its body with a bare `json!` macro -- so the
    /// served shape for every `/fs` and `/sync` failure was an anonymous
    /// value that matched the schema only by convention, in a second
    /// `ResponseError` impl that could drift from the first.
    ///
    /// What this checks is the contract half: every variant renders a body
    /// that deserializes as `ErrorBody` and carries the sanitized message.
    /// It deliberately does *not* claim to detect the duplication -- a
    /// hand-built `json!` with the same keys serializes to the same bytes,
    /// which is exactly why the duplication was invisible. That is
    /// `http::error::tests::the_envelope_has_one_construction_site`.
    ///
    /// The expected message is `client_message()` and not `Display`, which is
    /// the opposite of `ApiError`, where `#[error]` *is* the body. `FsError`
    /// keeps request-derived text in its variants and out of the wire, so the
    /// two types have opposite contracts for the same trait method and a
    /// refactor that confuses them leaks input.
    #[actix_web::test]
    async fn fs_and_api_errors_render_one_envelope() {
        use crate::http::error::{ApiError, ErrorBody};

        async fn body_of(res: HttpResponse) -> String {
            let raw = actix_web::body::to_bytes(res.into_body())
                .await
                .expect("body");
            String::from_utf8(raw.to_vec()).expect("utf-8 json")
        }

        for err in [
            FsError::BadRequest("got 7".into()),
            FsError::PayloadTooLarge,
            FsError::Forbidden,
            FsError::NotFound("no such file".into()),
            FsError::Internal("dsn".into()),
            FsError::Store("oxkv".into()),
            FsError::Fenced("epoch 2".into()),
        ] {
            let expected = err.client_message().to_string();
            let parsed: ErrorBody = serde_json::from_str(&body_of(err.error_response()).await)
                .expect("body is an ErrorBody");
            assert_eq!(
                parsed.error, expected,
                "{parsed:?} must carry the sanitized message, never the detail"
            );
        }

        // And the two types agree wherever their statuses overlap, despite
        // the opposite `Display` contracts.
        for (api, expected) in [
            (ApiError::Forbidden, "forbidden"),
            (ApiError::Internal("dsn".into()), "internal server error"),
            (ApiError::Conflict, "conflict"),
        ] {
            let parsed: ErrorBody =
                serde_json::from_str(&body_of(api.error_response()).await).expect("ErrorBody");
            assert_eq!(parsed.error, expected);
        }
    }

    /// The fencing reason is operator-facing and must not reach the wire.
    #[actix_web::test]
    async fn fencing_reason_is_logged_but_not_serialized() {
        let res = FsError::Fenced("epoch 7 superseded by writer on host-a".into()).error_response();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let raw = actix_web::body::to_bytes(res.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(json["error"], "internal server error");
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains("epoch"), "leaks epoch: {text}");
        assert!(!text.contains("host-a"), "leaks host: {text}");
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

    #[actix_web::test]
    async fn client_errors_never_echo_request_input() {
        // Each body carries attacker-controlled input in its detail;
        // the wire must only see the stable per-status message.
        for (err, status, message) in [
            (
                FsError::BadRequest("blob size mismatch: got <script>alert(1)</script>".into()),
                StatusCode::BAD_REQUEST,
                "bad request",
            ),
            (
                FsError::NotFound("file ../../etc/passwd not found".into()),
                StatusCode::NOT_FOUND,
                "not found",
            ),
        ] {
            let res = err.error_response();
            assert_eq!(res.status(), status);
            let raw = actix_web::body::to_bytes(res.into_body()).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(json["error"], message);
            let text = String::from_utf8_lossy(&raw);
            assert!(!text.contains("script"));
            assert!(!text.contains("passwd"));
            assert!(!text.contains("../"));
        }
    }
}
