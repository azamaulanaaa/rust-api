//! Modular row-level authorization.
//!
//! Business tables authorize as `{type}:{id}` objects via the shared
//! Casbin enforcer. `Fs` and other modules depend only on this trait.

use async_trait::async_trait;

use super::{Action, Authorizer, PolicyError, PolicyEngine};

/// Row-level authorizer for business entities.
///
/// Object is derived as `{row_type}:{row_id}` so policies remain
/// `sub, obj, act` without schema changes.
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

    /// Like [`RowAuthorizer::authorize_row`] but errors with
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
pub fn row_object(row_type: &str, row_id: &str) -> String {
    format!("{row_type}:{row_id}")
}

#[async_trait]
impl RowAuthorizer for PolicyEngine {
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

    fn tmp_path() -> std::path::PathBuf {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        std::env::temp_dir().join(format!(
            "row-test-{}-{}.redb",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
        ))
    }

    #[tokio::test]
    async fn row_object_formatting() {
        assert_eq!(row_object("invoice", "123"), "invoice:123");
    }

    #[tokio::test]
    async fn authorize_row_via_policy() {
        let path = tmp_path();
        let _ = std::fs::remove_file(&path);
        let engine = PolicyEngine::init(&path).await.unwrap();
        engine
            .assign_group("alice".into(), "editors".into())
            .await
            .unwrap();
        engine
            .add_rule("editors".into(), "invoice:123".into(), Action::Write)
            .await
            .unwrap();

        assert!(
            engine
                .authorize_row("alice", "invoice", "123", Action::Write)
                .await
                .unwrap()
        );
        assert!(
            !engine
                .authorize_row("alice", "invoice", "123", Action::Read)
                .await
                .unwrap()
        );
        assert!(
            engine
                .require_row("alice", "invoice", "999", Action::Write)
                .await
                .is_err()
        );

        let auth = engine.authorizer();
        assert!(auth.authorize_row("alice", "invoice", "123", Action::Write).await.unwrap());

        let _ = std::fs::remove_file(&path);
    }
}
