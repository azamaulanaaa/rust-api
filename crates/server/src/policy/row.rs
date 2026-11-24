//! Modular row-level authorization.
//!
//! Business tables authorize `{type}:{id}` objects through the shared
//! Casbin enforcer. `Fs` and other modules depend only on this trait.

use async_trait::async_trait;

use super::{Action, Authorizer, PolicyError};

/// Row-level authorizer for business entities.
///
/// The object is `{row_type}:{row_id}`. The policies stay in the form
/// `sub, obj, act`. They need no schema change.
#[async_trait]
pub trait RowAuthorizer: Send + Sync {
    /// Returns `true` when `sub` may perform `act` on the row.
    async fn authorize_row(
        &self,
        sub: &str,
        row_type: &str,
        row_id: &str,
        act: Action,
    ) -> Result<bool, PolicyError>;

    /// Like [`RowAuthorizer::authorize_row`], but returns
    /// [`PolicyError::AccessDenied`] on denial.
    async fn require_row(
        &self,
        sub: &str,
        row_type: &str,
        row_id: &str,
        act: Action,
    ) -> Result<(), PolicyError>;
}

/// Canonical object for a row.
///
/// The function escapes `:` and `\` in both parts. Two different row pairs
/// therefore never give the same object string.
pub fn row_object(row_type: &str, row_id: &str) -> String {
    format!("{}:{}", escape_row_part(row_type), escape_row_part(row_id))
}

/// Escapes one part of a row object.
///
/// The backslash escapes first, so that the later colon escape does not
/// double-escape the backslash that it inserts.
fn escape_row_part(value: &str) -> String {
    value.replace('\\', "\\\\").replace(':', "\\:")
}

/// Splits a canonical row object into `(row_type, row_id)`.
///
/// The function inverts [`row_object`]. It splits at the first unescaped
/// colon and then unescapes both parts. The function returns `None` when the
/// object is not a row object, when a part is empty, or when an escape is
/// malformed.
///
/// A control-plane object (`rules`, `user_groups`, …) has no colon and
/// returns `None`.
pub fn parse_row_object(obj: &str) -> Option<(String, String)> {
    let (row_type, row_id) = split_unescaped(obj)?;
    if row_type.is_empty() || row_id.is_empty() {
        return None;
    }
    Some((unescape_row_part(row_type)?, unescape_row_part(row_id)?))
}

/// Splits at the first colon that a backslash does not escape.
fn split_unescaped(value: &str) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (at, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            ':' => return Some((&value[..at], &value[at + 1..])),
            _ => {}
        }
    }
    None
}

/// Inverts [`escape_row_part`] for one part of a row object.
fn unescape_row_part(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some(':') => out.push(':'),
            Some('\\') => out.push('\\'),
            _ => return None,
        }
    }
    Some(out)
}

/// Row-level checks for business entities.
///
/// The code implements this trait only for [`Authorizer`], the read-only
/// handle. The code also implemented the trait for
/// [`PolicyEngine`](super::PolicyEngine), with an identical body. That impl
/// existed only because `fs` received the whole engine, and `fs` only
/// reads. The duplication created a second place to edit. Any edit to the
/// row object or to the denial mapping had to touch both places. The impl
/// that could also write gave a consumer that held the engine no reason to
/// use the handle that matched its use.
#[async_trait]
impl RowAuthorizer for Authorizer {
    async fn authorize_row(
        &self,
        sub: &str,
        row_type: &str,
        row_id: &str,
        act: Action,
    ) -> Result<bool, PolicyError> {
        self.authorize(sub, row_object(row_type, row_id), act).await
    }

    async fn require_row(
        &self,
        sub: &str,
        row_type: &str,
        row_id: &str,
        act: Action,
    ) -> Result<(), PolicyError> {
        self.require(sub, row_object(row_type, row_id), act).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, PolicyEngine};

    #[tokio::test]
    async fn row_object_joins_type_and_id() {
        assert_eq!(row_object("invoice", "123"), "invoice:123");
    }

    #[test]
    fn row_object_escapes_colons_in_type_and_id() {
        assert_eq!(row_object("invoice", "12:3"), "invoice:12\\:3");
        assert_eq!(row_object("invoice:12", "3"), "invoice\\:12:3");
        assert_ne!(row_object("invoice", "12:3"), row_object("invoice:12", "3"));
        assert_eq!(row_object("a\\b", "c"), "a\\\\b:c");
    }

    /// The parser is the exact inverse of the encoder.
    #[test]
    fn parse_row_object_inverts_row_object() {
        for (row_type, row_id) in [
            ("invoice", "123"),
            ("invoice", "12:3"),
            ("invoice:12", "3"),
            ("a\\b", "c"),
            ("a:b", "c\\d:e"),
        ] {
            let obj = row_object(row_type, row_id);
            assert_eq!(
                parse_row_object(&obj),
                Some((row_type.to_string(), row_id.to_string())),
                "the object {obj:?} must decode to its original parts"
            );
        }
    }

    /// A colon in the id must not truncate it.
    #[test]
    fn parse_row_object_keeps_colons_in_the_row_id() {
        assert_eq!(
            parse_row_object("invoice:12\\:3"),
            Some(("invoice".to_string(), "12:3".to_string()))
        );
    }

    /// An object that is not a canonical row object has no row pair.
    #[test]
    fn parse_row_object_rejects_control_plane_and_malformed_objects() {
        assert_eq!(parse_row_object("rules"), None);
        assert_eq!(parse_row_object("user_groups"), None);
        assert_eq!(parse_row_object(":123"), None);
        assert_eq!(parse_row_object("invoice:"), None);
        assert_eq!(parse_row_object("invoice:12\\"), None);
        assert_eq!(parse_row_object("invoice:12\\q3"), None);
    }

    #[tokio::test]
    async fn authorize_row_via_policy() {
        let s3 = crate::db::build_test_store(&crate::db::test_prefix("row")).await;
        let engine = PolicyEngine::init_s3(s3).await.unwrap();
        engine
            .assign_group("alice".into(), "editors".into())
            .await
            .unwrap();
        engine
            .add_rule("editors".into(), "invoice:123".into(), Action::Write)
            .await
            .unwrap();

        // The code checks the rows through the read handle. That handle
        // is the only impl of this trait. The code seeds the policy
        // through the engine above, because writing rules is exactly what
        // the engine is for.
        let auth = engine.authorizer();
        assert!(
            auth.authorize_row("alice", "invoice", "123", Action::Write)
                .await
                .unwrap()
        );
        assert!(
            !auth
                .authorize_row("alice", "invoice", "123", Action::Read)
                .await
                .unwrap()
        );
        assert!(
            auth.require_row("alice", "invoice", "999", Action::Write)
                .await
                .is_err()
        );
    }
}
