//! Error type for the FS module. Every error maps to the uniform
//! `{"error":...}` envelope.
//!
//! # `Display` is not the client message
//!
//! The `#[error]` text of [`ApiError`](crate::http::error::ApiError) *is*
//! the response body.
//! No variant of that type carries a `String`, so that text cannot leak.
//! `FsError` works the other way round.
//! Its 4xx variants hold request detail such as a filename, a key, or a
//! size.
//! Their `Display` is that detail, and the detail is for logs only.
//! The wire receives a fixed string for each status instead.
//!
//! The two types use the same trait method in opposite ways.
//! This fact matters for both types.
//! If you call `to_string()` when you build a response from an `FsError`,
//! you send user input to the client.
//! Both types render through
//! [`ApiError::envelope`](crate::http::error::ApiError), so the body is
//! `ErrorBody` in both cases.

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use thiserror::Error;

/// Errors raised by the FS engine and routes.
#[derive(Debug, Error)]
pub enum FsError {
    /// Validation failure. The status is 400.
    #[error("{0}")]
    BadRequest(String),
    /// The request body is larger than the declared part size. The status
    /// is 413.
    #[error("payload too large")]
    PayloadTooLarge,
    /// The caller does not have permission. The status is 403.
    #[error("forbidden")]
    Forbidden,
    /// The resource does not exist. The status is 404.
    #[error("{0}")]
    NotFound(String),
    /// S3 or store failure. The status is 500. The engine logs the inner
    /// detail on the server side only. The engine never renders it to
    /// clients (see `error_response`).
    #[error("internal server error")]
    Internal(String),
    /// Oxkv store error. The status is 500. This variant uses the same
    /// sanitization contract as `Internal`.
    #[error("internal server error")]
    Store(String),
    /// A cost limit refused the request. The status is 429.
    ///
    /// The engine raises this error when no concurrency slot was free for
    /// a replica download.
    /// A request *rate* limit does not catch the case that matters here.
    /// A client can be allowed a hundred reads a minute and still have a
    /// hundred segments of several hundred megabytes in flight at once.
    #[error("too many requests")]
    TooManyRequests,

    /// The store lost its epoch to another writer. The status is 500.
    ///
    /// This variant is separate from [`Store`](Self::Store) because the
    /// condition is *actionable*.
    /// `oxkv` documents `StoreError::Fenced` as terminal.
    /// The quote in that documentation is "the current process must stop
    /// writing and restart via `ownership.json` CAS".
    /// A caller that can recover from a lost fencing race must be able to
    /// recognise the condition.
    /// Such a caller may adopt the coverage of a concurrent builder
    /// instead of failing.
    ///
    /// The code used to detect this condition by searching the flattened
    /// detail for the substring `"fenced"`.
    /// If `oxkv` ever reworded the message, every client would get a 500
    /// without any report.
    /// The sanitization contract is the same as for `Store`.
    /// The engine logs the reason and never sends it.
    #[error("internal server error")]
    Fenced(String),
}

impl From<oxkv::StoreError> for FsError {
    /// The only place that classifies an `oxkv` error.
    ///
    /// Every conversion into `FsError` must use this implementation.
    /// The `store_err` helpers in `fs::store` and `sync::snapshot` are
    /// part of this rule.
    /// Without this rule, a fencing loss becomes [`Store`](Self::Store)
    /// and stays undetectable.
    fn from(e: oxkv::StoreError) -> Self {
        match e {
            oxkv::StoreError::Fenced(reason) => Self::Fenced(reason),
            other => Self::Store(other.to_string()),
        }
    }
}

impl FsError {
    /// True when the store lost its epoch, which means that another writer
    /// took the prefix.
    ///
    /// Use this method to detect a recoverable fencing race.
    /// A fencing loss is not a normal store failure.
    /// A caller can retry a fencing loss, but a corrupt or missing store
    /// cannot be retried.
    pub fn is_fencing_loss(&self) -> bool {
        matches!(self, Self::Fenced(_))
    }

    /// The reason for the failure, for server-side logs.
    ///
    /// The engine never renders this reason to a client.
    /// Each variant has fixed sanitized text in `Display`.
    /// Only this reason reaches an operator.
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

    /// The fixed message for the client. This message never carries
    /// request input.
    ///
    /// The inner detail stays in `Display` for server-side logs.
    /// The wire body receives this fixed string only.
    /// A filename, a key, or a size from the request can never reach a
    /// client.
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
        // Internal and store causes carry sensitive detail, such as S3
        // errors and store paths.
        // The engine logs them here so that a call site does not forget.
        // The engine never serializes them.
        // The body carries only the stable Display text.
        match self {
            // A lost epoch is not a transient failure.
            // Every later write on this handle fails in the same way.
            // The engine logs at `error` level, so the event stands out in
            // a log tail and does not disappear among store warnings.
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
        // This code renders through `ApiError`, so the served body is the
        // `ErrorBody` that the OpenAPI document names.
        // The code does not build a value that only has the same shape.
        // This type exists because the errors of the FS engine carry more
        // detail than the errors of the API.
        // The type does not exist because the envelope needed a second
        // implementation.
        crate::http::error::ApiError::envelope(self.status_code(), self.client_message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_of_internal_variants_hides_the_detail() {
        let err = FsError::Internal("secret bucket DSN".to_string());
        assert_eq!(err.to_string(), "internal server error");
        let store = FsError::Store("raw oxkv dump".to_string());
        assert_eq!(store.to_string(), "internal server error");
        let fenced = FsError::Fenced("epoch 7 superseded by 8".to_string());
        assert_eq!(fenced.to_string(), "internal server error");
    }

    /// `From<oxkv::StoreError>` is the only place that classifies fencing.
    /// The split must also hold for every other oxkv error.
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

    /// `/fs` and `/sync` bodies are the documented `ErrorBody`, and not a
    /// value that only looks like it.
    ///
    /// The OpenAPI document names `ErrorBody` for the errors of this crate.
    /// `FsError` used to build its body with a bare `json!` macro.
    /// The served shape for every `/fs` and `/sync` failure was then an
    /// anonymous value.
    /// That value matched the schema only by convention, in a second
    /// `ResponseError` impl that could drift from the first.
    ///
    /// This test checks the contract half.
    /// Every variant must render a body that deserializes as `ErrorBody`
    /// and carries the sanitized message.
    /// The test does not detect the duplication.
    /// A hand-built `json!` with the same keys serializes to the same
    /// bytes, which is why the duplication was invisible.
    /// The test `http::error::tests::the_envelope_has_one_construction_site`
    /// checks that.
    ///
    /// The expected message is `client_message()` and not `Display`.
    /// `ApiError` does the opposite, because there `#[error]` *is* the body.
    /// `FsError` keeps request text in its variants and out of the wire.
    /// The two types use the same trait method in opposite ways, so a
    /// refactor that mixes them leaks input.
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

        // The two types agree on every status that both of them use.
        // Their `Display` contracts are opposite.
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
        // Each body carries attacker-controlled input in its detail.
        // The wire must receive only the fixed message for the status.
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
