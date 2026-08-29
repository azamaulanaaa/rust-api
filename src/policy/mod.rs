use std::{collections::HashMap, fmt, str::FromStr};
use std::{path::Path, sync::Arc};

use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi, RbacApi};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

/// HTTP routes for managing policy rules and group membership.
pub mod route;
pub mod setup;

/// Casbin storage adapter persisting policies to an embedded oxkv store.
pub mod adapter;

/// JSON export/import of policy data for backups and migrations.
pub mod admin;

/// The operation a policy rule grants on an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum Action {
    /// Permission to view the object.
    Read,
    /// Permission to modify the object.
    Write,
    /// Permission to remove the object.
    Delete,
    /// Permission to invoke/run the object.
    Execute,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let act = match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Delete => "delete",
            Action::Execute => "execute",
        };
        write!(f, "{}", act)
    }
}

impl FromStr for Action {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "read" => Ok(Action::Read),
            "write" => Ok(Action::Write),
            "delete" => Ok(Action::Delete),
            "execute" => Ok(Action::Execute),
            _ => Err(format!("Unknown action: {}", s)),
        }
    }
}

/// Errors raised by [`PolicyEngine`] and [`Authorizer`].
#[derive(Debug, Error)]
pub enum PolicyError {
    /// An operation on the embedded policy store failed.
    #[error("Policy store error: {0}")]
    Store(#[from] oxkv::StoreError),

    /// The Casbin engine rejected an operation or failed enforcement.
    #[error("Casbin authorization engine error: {0}")]
    Casbin(#[from] casbin::Error),

    /// The subject does not hold the required permission.
    #[error("Access Denied")]
    AccessDenied,
}

/// Central authorization engine: a Casbin RBAC enforcer persisted to an
/// embedded oxkv (Redb) database file, plus management helpers for rules
/// and group membership.
///
/// Cloning is cheap: the enforcer lives behind an `Arc`, so clones share
/// one policy state (used to hand the same store to several API modules).
#[derive(Clone)]
pub struct PolicyEngine {
    /// The underlying Casbin enforcer shared across workers.
    pub enforcer: Arc<RwLock<Enforcer>>,
}

/// The built-in role granted by the one-time bootstrap endpoint; holders
/// may manage every policy rule and group assignment.
pub const SUPERADMIN_ROLE: &str = "superadmin";

/// One group and how many subjects belong to it.
#[derive(Debug, Serialize)]
pub struct GroupSummary {
    /// Group (role) name.
    pub name: String,
    /// Number of subjects linked to the group.
    pub members: usize,
}

/// One subject's group memberships.
#[derive(Debug, Serialize)]
pub struct UserAssignment {
    /// Subject identifier.
    pub sub: String,
    /// Groups the subject belongs to, sorted.
    pub groups: Vec<String>,
}

/// The Casbin RBAC model used by [`PolicyEngine`]: group-based
/// permissions where a subject authorizes through its group memberships.
pub(crate) const RBAC_MODEL: &str = r#"
    [request_definition]
    r = sub, obj, act
    [policy_definition]
    p = sub, obj, act
    [role_definition]
    g = _, _
    [policy_effect]
    e = some(where (p.eft == allow))
    [matchers]
    m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"#;

impl PolicyEngine {
    /// Opens the embedded oxkv database at `store_path`, loads the RBAC
    /// model and stored policies via the [`adapter::OxkvAdapter`], and
    /// returns the engine. Parent directories of the file are created as
    /// needed.
    pub async fn init(store_path: &Path) -> Result<Self, PolicyError> {
        if let Some(parent) = store_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| oxkv::StoreError::Other(e.to_string()))?;
        }

        let enforcer = {
            let store = oxkv::HookStore::new(
                oxkv::RedbStore::new_file(store_path).map_err(PolicyError::Store)?,
            )
            .with_validator(adapter::PolicyRuleValidator);
            let adapter = adapter::OxkvAdapter::new(store);

            let model = DefaultModel::from_str(RBAC_MODEL).await?;

            let mut enforcer = Enforcer::new(model, adapter).await?;
            enforcer.enable_auto_save(true);

            enforcer
        };

        Ok(Self {
            enforcer: Arc::new(RwLock::new(enforcer)),
        })
    }
}

impl PolicyEngine {
    /// Returns all granular permissions (p-rules)
    pub async fn get_all_rules(&self) -> Vec<Vec<String>> {
        let ef = self.enforcer.read().await;
        ef.get_policy()
    }

    /// Adds a granular permission (e.g., user_1, table_a.col_1, read)
    pub async fn add_rule(
        &self,
        sub: String,
        obj: String,
        act: Action,
    ) -> Result<bool, PolicyError> {
        let mut ef = self.enforcer.write().await;
        let success = ef.add_policy(vec![sub, obj, act.to_string()]).await?;
        Ok(success)
    }

    /// Removes a granular permission
    pub async fn remove_rule(
        &self,
        sub: String,
        obj: String,
        act: Action,
    ) -> Result<bool, PolicyError> {
        let mut ef = self.enforcer.write().await;
        let success = ef.remove_policy(vec![sub, obj, act.to_string()]).await?;
        Ok(success)
    }

    /// Assigns a user to a group (e.g., user_id, superuser)
    pub async fn assign_group(&self, user_id: String, group: String) -> Result<bool, PolicyError> {
        let mut ef = self.enforcer.write().await;
        let success = ef.add_grouping_policy(vec![user_id, group]).await?;
        Ok(success)
    }

    /// Atomically grants `user_id` the [`SUPERADMIN_ROLE`] provided no
    /// user holds that role yet. Returns `false` when the bootstrap was
    /// already completed (the check and the write share one lock, so two
    /// concurrent first-time claims cannot both succeed).
    pub async fn claim_superadmin(&self, user_id: &str) -> Result<bool, PolicyError> {
        let mut ef = self.enforcer.write().await;
        if !ef.get_users_for_role(SUPERADMIN_ROLE, None).is_empty() {
            return Ok(false);
        }
        ef.add_grouping_policy(vec![user_id.to_string(), SUPERADMIN_ROLE.to_string()])
            .await?;
        Ok(true)
    }

    /// Removes a user from a group
    pub async fn remove_from_group(
        &self,
        user_id: String,
        group: String,
    ) -> Result<bool, PolicyError> {
        let mut ef = self.enforcer.write().await;
        let success = ef.remove_grouping_policy(vec![user_id, group]).await?;
        Ok(success)
    }

    /// Lists every group known to the store with its member count,
    /// sorted by name. Groups vanish from this view once they hold no
    /// members (Casbin only materializes roles referenced by a link).
    pub async fn list_groups(&self) -> Vec<GroupSummary> {
        let ef = self.enforcer.read().await;
        let mut groups: Vec<GroupSummary> = ef
            .get_all_roles()
            .into_iter()
            .map(|name| GroupSummary {
                members: ef.get_users_for_role(&name, None).len(),
                name,
            })
            .collect();
        groups.sort_by(|a, b| a.name.cmp(&b.name));
        groups
    }

    /// Lists every subject holding at least one group membership with
    /// its groups, sorted by subject then group.
    pub async fn list_user_assignments(&self) -> Vec<UserAssignment> {
        let ef = self.enforcer.read().await;
        let mut by_user: HashMap<String, Vec<String>> = HashMap::new();
        for link in ef.get_grouping_policy() {
            by_user
                .entry(link[0].clone())
                .or_default()
                .push(link[1].clone());
        }
        let mut users: Vec<UserAssignment> = by_user
            .into_iter()
            .map(|(sub, mut groups)| {
                groups.sort();
                UserAssignment { groups, sub }
            })
            .collect();
        users.sort_by(|a, b| a.sub.cmp(&b.sub));
        users
    }

    /// Removes every membership link pointing at `group`, effectively
    /// deleting it. Returns `false` when the group holds no members.
    pub async fn delete_group(&self, group: &str) -> Result<bool, PolicyError> {
        let mut ef = self.enforcer.write().await;
        Ok(ef
            .remove_filtered_grouping_policy(1, vec![group.to_string()])
            .await?)
    }

    /// Primary Authorization method.
    ///
    /// The object accepts anything string-like (`&str`, `String`, or your
    /// own typed enum implementing `AsRef<str>`), so business modules can
    /// pass IDE-completable variants without `.into()` ceremony.
    #[tracing::instrument(skip(self, obj), fields(sub = %sub, obj = %obj.as_ref(), act = %act), err)]
    pub async fn authorize<S: AsRef<str>>(
        &self,
        sub: &str,
        obj: S,
        act: Action,
    ) -> Result<bool, PolicyError> {
        let ef = self.enforcer.read().await;

        // Casbin check
        let allowed = ef.enforce((sub, obj.as_ref(), &act.to_string()))?;

        Ok(allowed)
    }

    /// Like [`PolicyEngine::authorize`], but returns
    /// [`PolicyError::AccessDenied`] instead of a boolean when the subject
    /// lacks the permission.
    #[tracing::instrument(skip(self, obj), fields(sub = %sub, obj = %obj.as_ref(), act = %act), err)]
    pub async fn require<S: AsRef<str>>(
        &self,
        sub: &str,
        obj: S,
        act: Action,
    ) -> Result<(), PolicyError> {
        let allowed = self.authorize(sub, obj, act).await?;

        if allowed {
            Ok(())
        } else {
            Err(PolicyError::AccessDenied)
        }
    }

    /// Returns a list of all users that belong to a specific group
    pub async fn get_users_in_group(&self, group: &str) -> Vec<String> {
        let ef = self.enforcer.read().await;
        // RbacApi provides `get_users_for_role` to fetch all subjects 'sub' for a given 'group'
        ef.get_users_for_role(group, None)
    }

    /// Returns a list of all groups assigned to a specific user
    pub async fn get_groups_of_user(&self, user_id: &str) -> Vec<String> {
        let ef = self.enforcer.read().await;
        // RbacApi provides `get_roles_for_user` to fetch all 'groups' for a given 'sub'
        ef.get_roles_for_user(user_id, None)
    }

    /// Returns a safe, read-only client that can be passed to other services
    pub fn authorizer(&self) -> Authorizer {
        Authorizer {
            enforcer: self.enforcer.clone(),
        }
    }
}

/// A capability-limited handle to the policy engine exposing only read and
/// enforcement operations; safe to share with modules that must never mutate
/// policies.
#[derive(Clone)]
pub struct Authorizer {
    // Private! Consumers cannot access the RwLock or call write().
    enforcer: Arc<RwLock<Enforcer>>,
}

impl Authorizer {
    /// Primary Authorization method. Accepts any string-like object; see
    /// [`PolicyEngine::authorize`].
    #[tracing::instrument(skip(self, obj), fields(sub = %sub, obj = %obj.as_ref(), act = %act), err)]
    pub async fn authorize<S: AsRef<str>>(
        &self,
        sub: &str,
        obj: S,
        act: Action,
    ) -> Result<bool, PolicyError> {
        let ef = self.enforcer.read().await;
        Ok(ef.enforce((sub, obj.as_ref(), &act.to_string()))?)
    }

    /// Like [`Authorizer::authorize`], but returns
    /// [`PolicyError::AccessDenied`] instead of a boolean when the subject
    /// lacks the permission.
    #[tracing::instrument(skip(self, obj), fields(sub = %sub, obj = %obj.as_ref(), act = %act), err)]
    pub async fn require<S: AsRef<str>>(
        &self,
        sub: &str,
        obj: S,
        act: Action,
    ) -> Result<(), PolicyError> {
        let allowed = self.authorize(sub, obj, act).await?;

        if allowed {
            Ok(())
        } else {
            Err(PolicyError::AccessDenied)
        }
    }

    /// Read-only method: Get users in a group
    pub async fn get_users_in_group(&self, group: &str) -> Vec<String> {
        let ef = self.enforcer.read().await;
        ef.get_users_for_role(group, None)
    }

    /// Read-only method: Get groups of a user
    pub async fn get_groups_of_user(&self, user_id: &str) -> Vec<String> {
        let ef = self.enforcer.read().await;
        ef.get_roles_for_user(user_id, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn engine() -> (PolicyEngine, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "rust-api-policy-mod-test-{}-{}.redb",
            std::process::id(),
            uuid_like()
        ));
        let _ = std::fs::remove_file(&path);
        let engine = PolicyEngine::init(&path).await.unwrap();
        (engine, path)
    }

    fn uuid_like() -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
    }

    #[tokio::test]
    async fn groups_list_assignments_and_delete_round_trip() {
        let (engine, path) = engine().await;

        engine
            .assign_group("alice".into(), "admins".into())
            .await
            .unwrap();
        engine
            .assign_group("bob".into(), "viewers".into())
            .await
            .unwrap();
        engine
            .assign_group("carol".into(), "admins".into())
            .await
            .unwrap();

        // Groups are listed sorted with member counts.
        let groups = engine.list_groups().await;
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["admins", "viewers"]);
        assert_eq!(groups[0].members, 2);
        assert_eq!(groups[1].members, 1);

        // User assignments aggregate every link per subject.
        let users = engine.list_user_assignments().await;
        assert_eq!(users.len(), 3);
        assert_eq!(users[0].sub, "alice");
        assert_eq!(users[0].groups, vec!["admins".to_string()]);
        assert_eq!(users[2].sub, "carol");

        // Deleting a group removes every link to it at once.
        assert!(engine.delete_group("admins").await.unwrap());
        let groups = engine.list_groups().await;
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["viewers"]);
        assert!(engine.get_groups_of_user("alice").await.is_empty());
        assert!(engine.get_groups_of_user("carol").await.is_empty());

        // Deleting an unknown group reports no-op rather than failing.
        assert!(!engine.delete_group("admins").await.unwrap());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn require_accepts_strings_and_typed_objects() {
        let (engine, path) = engine().await;

        engine
            .assign_group("alice".into(), "editors".into())
            .await
            .unwrap();
        engine
            .add_rule("editors".into(), "invoices".into(), Action::Write)
            .await
            .unwrap();

        // Plain string object.
        engine
            .require("alice", "invoices", Action::Write)
            .await
            .unwrap();

        // Business modules may define their own IDE-completable object
        // enums; anything AsRef<str> drops straight into require().
        #[derive(Clone, Copy)]
        enum BizObject {
            Invoices,
        }
        impl AsRef<str> for BizObject {
            fn as_ref(&self) -> &str {
                match self {
                    Self::Invoices => "invoices",
                }
            }
        }
        engine
            .require("alice", BizObject::Invoices, Action::Write)
            .await
            .unwrap();
        assert!(
            engine
                .require("alice", BizObject::Invoices, Action::Read)
                .await
                .is_err()
        );

        let _ = std::fs::remove_file(&path);
    }
}
