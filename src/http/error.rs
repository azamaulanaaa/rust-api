//! Shared API error type rendering a uniform JSON error envelope.
//!
//! Every API failure serializes as `{"error": "<message>"}` where the
//! message is a stable, non-sensitive description. Underlying causes are
//! attached via [`std::error::Error::source`] and logged server-side by the
//! response renderer — they are never sent to clients.

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire format for every API error: `{"error": "<message>"}`.
///
/// `Deserialize` as well as `Serialize` so tests can assert on the served
/// body through this type rather than through an anonymous
/// `serde_json::Value` -- the point being to check that what is on the wire
/// really is this shape.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErrorBody {
    /// Stable, non-sensitive description of the failure.
    pub error: String,
}

/// Application-wide API error.
///
/// The `Display` text (via `#[error]`) doubles as the client-facing body,
/// while any `#[source]` cause is reserved for server-side logging. That
/// split is why no variant carries a `String`: a payload here would be
/// request-derived text on the wire. Detail belongs in a `#[source]`
/// cause, which is logged and never serialized. This mirrors the
/// sanitization contract in [`FsError`](crate::fs::error::FsError).
#[derive(Debug, Error)]
pub enum ApiError {
    /// Request carried no credential at all. HTTP 401.
    #[error("authentication required")]
    MissingCredentials,

    /// The request body could not be parsed into the handler's type. HTTP
    /// 400.
    ///
    /// Exists because actix's own JSON-extractor failure is a bare
    /// `400 Bad Request` in `text/plain` -- the one way a documented route
    /// answers outside the uniform envelope, reached by any client that
    /// sends a truncated or mistyped payload. [`apply_limits`](crate::http::apply_limits)
    /// installs this as the extractor's error handler; the extractor's
    /// message names the offending field and is logged, never sent.
    #[error("bad request")]
    BadRequest,

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

    /// The request conflicts with already-established state; used by the
    /// one-time bootstrap route once setup has been completed. HTTP 409.
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

    /// Renders the uniform envelope for an arbitrary status and message.
    ///
    /// The single place the body is constructed, so a status cannot end up
    /// paired with a differently-shaped body. [`FsError`] renders through
    /// here too: it is a second `ResponseError` implementation in this crate
    /// with its own status table, and while it built its body with a bare
    /// `json!` macro the served shape for `/fs` and `/sync` was an anonymous
    /// value that the OpenAPI document described as
    /// [`ErrorBody`] only by convention. Now it is
    /// [`ErrorBody`] by construction.
    pub(crate) fn envelope(status: StatusCode, message: &str) -> HttpResponse {
        HttpResponse::build(status).json(ErrorBody {
            error: message.to_string(),
        })
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

        Self::envelope(self.status(), &self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a source file's production code: everything before the
    /// column-0 `#[cfg(test)]` module, with comment lines dropped.
    ///
    /// Matched at column 0, not after `trim_start`: an indented
    /// `#[cfg(test)]` gates a single test-only item and does not open the
    /// file's test module, and this walk reads every file under `src`. The
    /// `trim_start` variant stopped at the first such item -- `limits.rs`
    /// carries two, at `:171` and `:203`, so the whole `RateLimit`
    /// middleware was invisible to the scan below -- which is why a
    /// hand-rolled `json!({"error": ...})` anywhere past that line read as
    /// "one construction site" without being looked at.
    fn production_source(path: &str) -> String {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let mut out = String::new();
        for line in src.lines() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if line == "#[cfg(test)]" {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// A file shaped like `limits.rs`: production code, an *indented*
    /// `#[cfg(test)]` on a single test-only item, more production code, then
    /// the real test module at column 0.
    const FIXTURE: &str = r#"pub fn before() {}
    #[cfg(test)]
    pub(crate) fn test_only_item() {}
pub fn after() {}
#[cfg(test)]
mod tests {}
"#;

    /// The helper itself: it walks `src`, so a truncated scan is a silently
    /// weakened guard rather than a failing one. See the identical fixture
    /// test in `records::tests`, which is the twin of this helper.
    #[test]
    fn production_source_does_not_stop_at_an_indented_cfg_test() {
        let path = std::env::temp_dir().join(format!(
            "rust-api-error-prod-source-{}-{}.rs",
            std::process::id(),
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                rand::random::<[u8; 8]>(),
            )
        ));
        std::fs::write(&path, FIXTURE).expect("write the fixture");

        let src = production_source(path.to_str().expect("utf-8 path"));
        let _ = std::fs::remove_file(&path);

        assert!(
            src.contains("pub fn after()"),
            "an indented #[cfg(test)] gates one item, not the rest of the file: {src}"
        );
        assert!(
            !src.contains("mod tests"),
            "the column-0 module is the stop point: {src}"
        );
    }

    /// The error envelope is built in exactly one place.
    ///
    /// This crate has two `ResponseError` implementations -- `ApiError` for
    /// control-plane failures and `FsError` for the file engine's richer set
    /// -- and `FsError` used to assemble its own body with a bare `json!`
    /// macro. The two produced identical bytes, which is precisely the
    /// problem: the OpenAPI document described every error as `ErrorBody`,
    /// `/fs` and `/sync` served an anonymous value that only matched the
    /// schema by convention, and no test could tell the difference.
    ///
    /// So the duplication is checked structurally instead. A behavioural
    /// test cannot work here, and writing one anyway would be worse than
    /// none: it would read as coverage of a property it does not have.
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
                // A hand-rolled body: either the struct literal or a
                // `json!` that emits the envelope's key.
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
    fn statuses_map_to_expected_codes() {
        assert_eq!(ApiError::MissingCredentials.status(), 401);
        assert_eq!(
            ApiError::InvalidCredentials("kid mismatch".into()).status(),
            401
        );
        assert_eq!(ApiError::Forbidden.status(), 403);
        assert_eq!(ApiError::Internal("db down".into()).status(), 500);
        assert_eq!(ApiError::Conflict.status(), 409);
    }

    #[test]
    fn display_messages_are_stable_and_sanitized() {
        // Display must never embed a cause or caller-supplied text: it
        // becomes the client body.
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

    /// Every variant renders a fixed string, so no request-derived payload
    /// can reach the wire through the envelope. The FS engine holds the
    /// same line (see `FsError::client_message`); this pins the API side.
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

        // Re-render through a full request cycle to exercise serialization.
        let body = actix_web::body::to_bytes(res.into_body()).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"authentication required"}"#);
    }
}
