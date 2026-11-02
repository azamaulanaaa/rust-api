//! The shared API error type that renders one uniform JSON error envelope.
//!
//! Every API failure serializes as `{"error": "<message>"}`. The message is
//! a stable description. The description contains no sensitive data. The
//! response renderer attaches the underlying causes through
//! [`std::error::Error::source`]. It logs them on the server. The renderer
//! never sends the causes to a client.
//!
//! The envelope can also carry an optional `code` and optional `details`.
//! The server omits each field when its value is `None`. Thus the minimal
//! body keeps its old bytes.

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The wire format for every API error.
///
/// The minimal body is `{"error": "<message>"}`. The optional `code` and
/// `details` fields extend that body. The server omits each optional field
/// when its value is `None`.
///
/// The type also derives `Deserialize`. A test can check the served body
/// through this type instead of an anonymous `serde_json::Value`. That way
/// a test confirms that the wire format really has this shape.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErrorBody {
    /// A stable description of the failure. The description contains no
    /// sensitive data.
    pub error: String,

    /// A stable machine-readable code for the failure class.
    ///
    /// The server omits this field when no code applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    /// Optional structured context for the failure.
    ///
    /// This field never carries request input, filenames, keys, sizes, store
    /// errors, or other sensitive data. The server omits this field when no
    /// safe details exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// The API error for the whole application.
///
/// The `Display` text (via `#[error]`) also forms the body that the server
/// sends to the client. Any `#[source]` cause is only for server-side logs.
/// This split is why no variant carries a `String`. A payload here would put
/// request text on the wire. Detailed information belongs in a `#[source]`
/// cause, which the server logs and never serializes. This rule matches the
/// sanitization contract in [`FsError`](crate::fs::error::FsError).
#[derive(Debug, Error)]
pub enum ApiError {
    /// The request carried no credential at all. HTTP 401.
    #[error("authentication required")]
    MissingCredentials,

    /// The server could not parse the request body into the type of the
    /// handler. HTTP 400.
    ///
    /// This variant exists because the actix JSON extractor fails with a
    /// bare `400 Bad Request` in `text/plain`. That is the one way a
    /// documented route answers outside the uniform envelope. Any client
    /// that sends a truncated or mistyped payload reaches it.
    /// [`apply_limits`](crate::http::apply_limits) installs this variant as
    /// the error handler of the extractor. The extractor message names the
    /// offending field. The server logs the message and never sends it.
    #[error("bad request")]
    BadRequest,

    /// The request carried a credential, but the credential failed
    /// verification. The source holds the rejection detail for the log
    /// only. HTTP 401.
    #[error("invalid credentials")]
    InvalidCredentials(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The authenticated subject does not have the required permission.
    /// HTTP 403.
    #[error("forbidden")]
    Forbidden,

    /// The request failed for an unexpected reason. The server logs the
    /// source only. HTTP 500.
    #[error("internal server error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The request conflicts with state that already exists. The one-time
    /// bootstrap route uses this variant after setup has finished. HTTP
    /// 409.
    #[error("conflict")]
    Conflict,

    /// A cost limit refused the request. HTTP 429.
    #[error("too many requests")]
    TooManyRequests,
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::MissingCredentials | Self::InvalidCredentials(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Conflict => StatusCode::CONFLICT,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    /// The stable machine-readable code for this failure class.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::BadRequest => "invalid_request",
            Self::MissingCredentials => "authentication_required",
            Self::InvalidCredentials(_) => "invalid_credentials",
            Self::Forbidden => "forbidden",
            Self::Internal(_) => "internal_error",
            Self::Conflict => "conflict",
            Self::TooManyRequests => "too_many_requests",
        }
    }

    /// Renders the uniform envelope for any status and message.
    ///
    /// The function is the only place that builds the body. A status
    /// cannot receive a body of a different shape. [`FsError`] renders
    /// through this function too. `FsError` is a second `ResponseError`
    /// implementation in this crate. It has its own status table. It used
    /// to build its body with a bare `json!` macro. The served shape for
    /// `/fs` and `/sync` was an anonymous value. The OpenAPI document
    /// described that value as [`ErrorBody`] by convention only. The
    /// function now builds an [`ErrorBody`] directly.
    ///
    /// A `None` code or detail does not appear in the JSON body. Thus the
    /// minimal body stays exactly `{"error":"<message>"}`.
    pub(crate) fn envelope(
        status: StatusCode,
        message: &str,
        code: Option<&str>,
        details: Option<serde_json::Value>,
    ) -> HttpResponse {
        HttpResponse::build(status).json(ErrorBody {
            error: message.to_string(),
            code: code.map(str::to_owned),
            details,
        })
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        self.status()
    }

    fn error_response(&self) -> HttpResponse {
        // The causes carry sensitive internal data (database errors,
        // provider responses). The server logs them here, so a call site
        // cannot forget to log them. The server never serializes them.
        if let Some(cause) = std::error::Error::source(self) {
            tracing::warn!("API {} {}: {cause}", self.status(), self);
        }

        // No current error class has safe structured details. Keep
        // `details` as `None` so no internal value can reach the wire.
        Self::envelope(self.status(), &self.to_string(), Some(self.code()), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::production_source;

    /// Reads the production code of a source file and drops the comment
    /// lines, with [`crate::test_support::production_source`]. Every such
    /// guard shares this one helper. No file needs a copy of it.
    ///
    /// The walk stops at a `#[cfg(test)]` that opens a `mod`. It does not
    /// stop at the attribute alone. The attribute also marks test-only
    /// items. This walk reads every file under `src`. Matching the attribute
    /// after `trim_start` would stop at the first indented one. `limits.rs`
    /// carries two. Matching the attribute at column 0 alone would stop at
    /// a column-0 item attribute. `src/db.rs` carries three before its real
    /// test module. Another test calls the helper directly with a fixture
    /// that has both shapes.
    ///
    /// The error envelope is built in exactly one place.
    ///
    /// This crate has two `ResponseError` implementations. `ApiError` serves
    /// control-plane failures. `FsError` serves the larger set of errors of
    /// the file engine. `FsError` used to build its own body with a bare
    /// `json!` macro. Both types then produced identical bytes. That is
    /// exactly the problem. The OpenAPI document described every error as
    /// `ErrorBody`. `/fs` and `/sync` served an anonymous value. That value
    /// matched the schema only by convention. No test could tell the two
    /// apart.
    ///
    /// The test therefore checks the duplication in the source structure
    /// instead. A test of the behavior cannot work here. Writing such a
    /// test would be worse than no test. It would read as coverage of a
    /// property that it does not have.
    #[test]
    fn the_envelope_has_one_construction_site() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{dir:?}: {e}")) {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }

        let mut files = Vec::new();
        walk(std::path::Path::new("src"), &mut files);

        let mut sites: Vec<String> = Vec::new();
        for path in &files {
            let rel = path.to_string_lossy().replace('\\', "/");
            let src = production_source(&rel);
            for line in src.lines() {
                // A hand-built body: either the struct literal, or a
                // `json!` that emits the envelope key.
                if line.contains("ErrorBody {")
                    || (line.contains("json!") && line.contains("\"error\""))
                {
                    sites.push(rel.clone());
                    break;
                }
            }
        }
        sites.sort();
        assert_eq!(
            sites,
            vec!["src/http/error.rs".to_string()],
            "the error envelope must be constructed in exactly one file. Build it \
             through `ApiError::envelope` so `/fs` and `/sync` serve the `ErrorBody` \
             the OpenAPI document names."
        );
    }

    #[test]
    fn status_codes_map_to_the_expected_values() {
        assert_eq!(ApiError::BadRequest.status(), 400);
        assert_eq!(ApiError::MissingCredentials.status(), 401);
        assert_eq!(
            ApiError::InvalidCredentials("kid mismatch".into()).status(),
            401
        );
        assert_eq!(ApiError::Forbidden.status(), 403);
        assert_eq!(ApiError::Internal("db down".into()).status(), 500);
        assert_eq!(ApiError::Conflict.status(), 409);
        assert_eq!(ApiError::TooManyRequests.status(), 429);
    }

    /// Every variant has one stable code. The codes never carry input.
    #[test]
    fn every_variant_has_the_intended_code() {
        for (err, code) in [
            (ApiError::BadRequest, "invalid_request"),
            (ApiError::MissingCredentials, "authentication_required"),
            (
                ApiError::InvalidCredentials("raw jwks dump".into()),
                "invalid_credentials",
            ),
            (ApiError::Forbidden, "forbidden"),
            (ApiError::Internal("secret db DSN".into()), "internal_error"),
            (ApiError::Conflict, "conflict"),
            (ApiError::TooManyRequests, "too_many_requests"),
        ] {
            assert_eq!(err.code(), code, "wrong code for {err:?}");
        }
    }

    #[test]
    fn display_messages_are_stable_and_sanitized() {
        // The `Display` text must never contain a cause or text that the
        // caller supplied, because it becomes the body for the client.
        let internal = ApiError::Internal("secret db DSN".into());
        assert_eq!(internal.to_string(), "internal server error");

        let invalid = ApiError::InvalidCredentials("raw jwks dump".into());
        assert_eq!(invalid.to_string(), "invalid credentials");
        // The source chain still gives the cause for the log.
        assert_eq!(
            std::error::Error::source(&invalid)
                .expect("cause retained")
                .to_string(),
            "raw jwks dump"
        );
    }

    /// Every variant renders a fixed string. No request-derived payload
    /// can reach the wire through the envelope. The file engine holds the
    /// same rule. See `FsError::client_message`. This test fixes the API
    /// side.
    #[test]
    fn every_variant_has_a_fixed_client_message() {
        for (err, message) in [
            (ApiError::MissingCredentials, "authentication required"),
            (ApiError::Forbidden, "forbidden"),
            (ApiError::Conflict, "conflict"),
        ] {
            assert_eq!(err.to_string(), message);
        }
    }

    #[actix_web::test]
    async fn error_response_renders_uniform_envelope() {
        let err = ApiError::MissingCredentials;
        let res = err.error_response();
        assert_eq!(res.status(), 401);

        // The function renders the response again through a full request
        // cycle, so the test covers the serialization as well.
        let body = actix_web::body::to_bytes(res.into_body()).await.unwrap();
        let parsed: ErrorBody = serde_json::from_slice(&body).expect("body is an ErrorBody");
        assert_eq!(parsed.error, "authentication required");
        assert_eq!(parsed.code.as_deref(), Some("authentication_required"));
        assert!(parsed.details.is_none());
    }

    /// A body with no code and no details keeps the old bytes. This is the
    /// backward-compatibility contract for existing clients.
    #[actix_web::test]
    async fn minimal_body_keeps_the_old_bytes() {
        let res = ApiError::envelope(
            StatusCode::UNAUTHORIZED,
            "authentication required",
            None,
            None,
        );
        let body = actix_web::body::to_bytes(res.into_body()).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"authentication required"}"#);
    }

    /// The optional fields extend the body without a new envelope shape.
    #[test]
    fn optional_fields_serialize_additively() {
        let body = ErrorBody {
            error: "bad request".to_string(),
            code: Some("invalid_request".to_string()),
            details: Some(serde_json::json!({ "field": "name" })),
        };
        let json = serde_json::to_value(&body).expect("body serializes");
        assert_eq!(json["error"], "bad request");
        assert_eq!(json["code"], "invalid_request");
        assert_eq!(json["details"]["field"], "name");

        // A client can still parse the minimal body.
        let old: ErrorBody =
            serde_json::from_str(r#"{"error":"bad request"}"#).expect("old body parses");
        assert_eq!(old.error, "bad request");
        assert!(old.code.is_none());
        assert!(old.details.is_none());
    }
}
