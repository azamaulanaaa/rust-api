use std::sync::Arc;
use std::{fmt, str::FromStr};

use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi, RbacApi};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx_adapter::SqlxAdapter;
use thiserror::Error;
use tokio::sync::RwLock;

pub mod route;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Delete,
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

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Casbin authorization engine error: {0}")]
    Casbin(#[from] casbin::Error),

    #[error("Access Denied")]
    AccessDenied,
}

pub struct PolicyEngine {
    pub enforcer: Arc<RwLock<Enforcer>>,
}

impl PolicyEngine {
    pub async fn init(database_url: &str) -> Result<Self, PolicyError> {
        let pool = PgPool::connect(database_url).await?;

        let enforcer = {
            let adapter = SqlxAdapter::new_with_pool(pool.clone()).await?;

            let model = DefaultModel::from_str(
                r#"
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
                "#,
            )
            .await?;

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
