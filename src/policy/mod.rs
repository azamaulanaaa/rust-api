use std::{fmt, str::FromStr};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Primary Authorization method.
    pub async fn authorize(&self, sub: &str, obj: &str, act: Action) -> Result<bool, PolicyError> {
        let ef = self.enforcer.read().await;

        // Casbin check
        let allowed = ef.enforce((sub, obj, &act.to_string()))?;

        Ok(allowed)
    }

    /// Like [`PolicyEngine::authorize`], but returns
    /// [`PolicyError::AccessDenied`] instead of a boolean when the subject
    /// lacks the permission.
    pub async fn require(&self, sub: &str, obj: &str, act: Action) -> Result<(), PolicyError> {
        let ef = self.enforcer.read().await;
        let allowed = ef.enforce((sub, obj, &act.to_string()))?;

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
    /// Primary Authorization method.
    pub async fn authorize(&self, sub: &str, obj: &str, act: Action) -> Result<bool, PolicyError> {
        let ef = self.enforcer.read().await;
        Ok(ef.enforce((sub, obj, &act.to_string()))?)
    }

    /// Like [`Authorizer::authorize`], but returns
    /// [`PolicyError::AccessDenied`] instead of a boolean when the subject
    /// lacks the permission.
    pub async fn require(&self, sub: &str, obj: &str, act: Action) -> Result<(), PolicyError> {
        let ef = self.enforcer.read().await;
        let allowed = ef.enforce((sub, obj, &act.to_string()))?;

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
