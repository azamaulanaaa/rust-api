//! Modular row-level authorization.
//!
//! Business tables authorize `{type}:{id}` objects through the shared
//! Casbin enforcer. `Fs` and other modules depend only on this trait.

use async_trait::async_trait;

use super::{Action, Authorizer, PolicyError};

/// Row-level authorizer for business entities.
///
/// The object is `{row_type}:{row_id}`, so the policies stay in the form
/// `sub, obj, act` and need no schema change.
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

    /// Like [`RowAuthorizer::authorize_row`], but the function returns an
    /// error [`PolicyError::AccessDenied`] on denial.
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

/// Row-level checks for business entities.
///
/// The code implements this trait only for [`Authorizer`], the read-only
/// handle. It also implemented the trait for
/// [`PolicyEngine`](super::PolicyEngine), with an identical body. That impl
/// existed only because `fs` received the whole engine, and `fs` only
/// ever reads. The duplication was a second place where a change to the row
/// object or to the mapping of a denial had to be applied. The impl that
/// could also write gave a consumer that held the engine no reason to use
/// the handle that matched its use.
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
