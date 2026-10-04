//! Casbin RBAC policy engine backed by prefix-scoped OxKV stores, with
//! management routes for permission rules and group membership.
//!
//! [`PolicyEngine`](crate::policy::PolicyEngine) owns the enforcer and is
//! cheap to clone (the enforcer sits behind an `Arc`), so the same policy
//! state is shared across every API module.
//! [`Authorizer`](crate::policy::Authorizer) is the read-only handle for
//! callers that must never mutate policies, and
//! [`row::RowAuthorizer`](crate::policy::row::RowAuthorizer) adds
//! row-level (`{type}:{id}`) checks on top.

use std::{collections::HashMap, fmt, str::FromStr, sync::Arc};

use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi, RbacApi};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::fencing::Latch;
use crate::records::{ChangeSink, WalOp};

/// Casbin storage adapter persisting policies to an embedded oxkv store.
pub mod adapter;

/// JSON export/import of policy data for backups and migrations.
pub mod admin;

/// HTTP routes for managing policy rules and group membership.
pub mod route;

/// Modular row-level authorization.
pub mod row;

/// One-time bootstrap route claiming the built-in superadmin role.
pub mod setup;

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
///
/// Display text is lowercase sentence style, matching
/// [`FsError`](crate::fs::error::FsError) and
/// [`ApiError`](crate::http::error::ApiError). These strings are internal:
/// the `From<PolicyError> for ApiError` impl maps every variant onto a
/// sanitized `ApiError` before anything reaches a client.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// An operation on the policy store failed.
    #[error("policy store error: {0}")]
    Store(#[from] oxkv::StoreError),

    /// The Casbin engine rejected an operation or failed enforcement.
    #[error("casbin authorization engine error: {0}")]
    Casbin(casbin::Error),

    /// The subject does not hold the required permission.
    #[error("access denied")]
    AccessDenied,

    /// Announcing a committed mutation to the change feed failed.
    #[error("change feed error: {0}")]
    ChangeFeed(String),

    /// The policy store's epoch was lost to another writer.
    ///
    /// Wording mirrors [`FsError::Fenced`](crate::fs::error::FsError) on
    /// purpose: both are the same condition on the same prefix, so one log
    /// query finds either. The detail is the store's reason and stays
    /// server-side.
    #[error(
        "store epoch lost to another writer ({0}); \
         this handle must stop writing and be rebuilt"
    )]
    Fenced(String),
}

/// The master policy prefix, named in the fencing-loss log line.
const POLICY_PREFIX: &str = "{db}/policy";

impl PolicyError {
    /// True when this is a lost epoch, i.e. another writer took the prefix.
    ///
    /// The detection point for a policy write that failed because this
    /// process is no longer the writer, as opposed to a rejected or
    /// unreachable store.
    pub fn is_fencing_loss(&self) -> bool {
        matches!(self, Self::Fenced(_))
    }
}

impl From<casbin::Error> for PolicyError {
    /// Lifts a lost epoch out of casbin's adapter wrapper.
    ///
    /// [`OxkvAdapter`](crate::policy::adapter::OxkvAdapter) satisfies
    /// casbin's `Adapter` trait, whose signatures are written in
    /// `casbin::Error`, so an `oxkv::StoreError` crosses that boundary
    /// boxed inside `AdapterError`. This is the one place that boxing can
    /// still be undone, and skipping it leaves a stale writer's policy
    /// write indistinguishable from any other 500 -- the same undetectable
    /// condition [`FsError::Fenced`](crate::fs::error::FsError) exists to
    /// rule out, reached by a different route.
    ///
    /// Matching on the downcast rather than the message text means a
    /// reworded `oxkv` error cannot silently degrade the classification.
    ///
    /// The latch is the process-wide one. Callers that own a
    /// [`PolicyEngine`] use [`PolicyEngine::classify`] instead, so a test
    /// can point the engine at a private [`Latch`](crate::fencing::Latch)
    /// and observe the trip; see that method for why the assertion needs
    /// one.
    fn from(e: casbin::Error) -> Self {
        classify_with(crate::fencing::process_latch(), e)
    }
}

/// Classifies a casbin failure, recording a lost epoch on `latch`.
///
/// Split out of the [`From`] impl because that impl has nowhere to hang a
/// per-instance latch: it is a conversion between two error types and is
/// called from every `?` in the module, including ones with no engine in
/// scope. `PRIMARY_LOSS` is a one-way flag with no reset, so an assertion
/// against it is satisfied by whichever test in the binary tripped it
/// first -- `fencing::tests::the_process_wide_signal_is_readable` does so
/// unconditionally, and cargo runs the threads in parallel. That makes
/// "did THIS write latch?" unanswerable against the global.
fn classify_with(latch: &crate::fencing::Latch, e: casbin::Error) -> PolicyError {
    if let casbin::Error::AdapterError(adapter) = &e
        && let Some(oxkv::StoreError::Fenced(reason)) = adapter.0.downcast_ref::<oxkv::StoreError>()
    {
        // Casbin backs only the master policy store, so a lost epoch here
        // is always a primary loss and never a recoverable race.
        latch.trip(POLICY_PREFIX, reason);
        return PolicyError::Fenced(reason.clone());
    }
    PolicyError::Casbin(e)
}

/// Central authorization engine: a Casbin RBAC enforcer persisted to a
/// prefix-scoped `OxKvStore`, plus management helpers for rules
/// and group membership.
///
/// Cloning is cheap: the enforcer lives behind an `Arc`, so clones share
/// one policy state (used to hand the same store to several API modules).
#[derive(Clone)]
pub struct PolicyEngine {
    /// The underlying Casbin enforcer shared across workers.
    ///
    /// Private on purpose. `Enforcer` is casbin's own type and its methods
    /// (`add_policy`, `remove_grouping_policy`, …) bypass this engine's
    /// `add_rule`/`assign_group` wrappers, which is where the feed append
    /// lives. Exposing it publicly made it possible to mutate policy
    /// without announcing the change, so replicas would silently drift
    /// from the master with nothing to replay.
    ///
    /// Use the methods on this type to mutate, [`authorizer`](Self::authorizer)
    /// for a read-only handle, and [`is_unlocked`](Self::is_unlocked) for a
    /// non-blocking liveness probe.
    enforcer: Arc<RwLock<Enforcer>>,
    /// Change feed for replica sync; `None` disables logging (tests).
    /// Production must wire it: without appends the feed head never
    /// advances and replicas freeze at their last snapshot.
    ///
    /// Typed as [`ChangeSink`] rather than a concrete WAL so this module
    /// has no compile-time path to `sync` — see [`crate::records`].
    feed: Option<Arc<dyn ChangeSink>>,
    /// Where a lost epoch on the master policy prefix is recorded.
    ///
    /// The process-wide latch in production (see
    /// [`process_latch`](crate::fencing::process_latch)); an engine in a
    /// test can be given its own [`Latch`](crate::fencing::Latch) via
    /// [`with_latch`](Self::with_latch).
    ///
    /// Held rather than reached through the free
    /// [`note_primary_loss`](crate::fencing::note_primary_loss) so the latch
    /// travels with the engine that owns the prefix. That makes it
    /// substitutable: `PRIMARY_LOSS` is one-way with no reset, so a test
    /// asserting against it is satisfied by whichever test tripped it
    /// first, and a fenced write here would prove nothing.
    latch: &'static Latch,
}

/// The built-in role granted by the one-time bootstrap endpoint; holders
/// may manage every policy rule and group assignment.
pub const SUPERADMIN_ROLE: &str = "superadmin";

/// One group and how many subjects belong to it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GroupSummary {
    /// Group (role) name.
    pub name: String,
    /// Number of subjects linked to the group.
    pub members: usize,
}

/// One subject's group memberships.
#[derive(Debug, Serialize, utoipa::ToSchema)]
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
    /// Creates the engine from an [`oxkv::OxKvStore`] (OxKV S3 backend).
    pub async fn init_s3(s3_store: oxkv::OxKvStore) -> Result<Self, PolicyError> {
        Self::init_with_store(s3_store).await
    }

    /// Generic initializer over any [`oxkv::Store`] (e.g. `OxKvStore` in
    /// production, `InMemory`-backed `OxKvStore` or `BTreeStore` in tests).
    ///
    /// Writes are validated through `adapter::PolicyRuleValidator` by the
    /// adapter itself, before any transaction opens.
    pub async fn init_with_store<S>(store: S) -> Result<Self, PolicyError>
    where
        S: oxkv::Store + Send + Sync + 'static,
    {
        let adapter = adapter::OxkvAdapter::new(store);
        let model = DefaultModel::from_str(RBAC_MODEL).await?;
        let mut enforcer = Enforcer::new(model, adapter).await?;
        enforcer.enable_auto_save(true);
        Ok(Self {
            enforcer: Arc::new(RwLock::new(enforcer)),
            feed: None,
            latch: crate::fencing::process_latch(),
        })
    }

    /// Records fencing losses on `latch` instead of the process-wide one.
    ///
    /// Mirrors `FsStore::primary_with_latch`, and for the same reason: the
    /// process latch is one-way and global, so an assertion against it
    /// passes whether or not the code under test latched at all. Every
    /// other test in this binary — `fencing::tests` alone — trips it.
    #[cfg(test)]
    pub(crate) fn with_latch(mut self, latch: &'static Latch) -> Self {
        self.latch = latch;
        self
    }

    /// Classifies a casbin failure against THIS engine's latch.
    ///
    /// Every casbin call in this module goes through here rather than
    /// `?`-ing straight into [`PolicyError::from`], because the `From` impl
    /// has no engine in scope and so can only reach the process-wide latch.
    /// Production behaviour is identical: the engine's latch *is*
    /// [`process_latch`](crate::fencing::process_latch).
    fn classify(&self, e: casbin::Error) -> PolicyError {
        classify_with(self.latch, e)
    }

    /// Attaches a [`ChangeSink`] for replica sync; ops are announced after
    /// each mutation (fail-closed: a logging failure fails the whole
    /// operation so the feed never silently misses a committed write).
    ///
    /// Takes a trait object so this module never names `sync`. The
    /// concrete implementation is [`sync::wal::Wal`](crate::sync::wal::Wal).
    pub fn with_change_sink(mut self, feed: Arc<dyn ChangeSink>) -> Self {
        self.feed = Some(feed);
        self
    }

    /// Announces `op` when a feed is wired; no-op otherwise.
    async fn announce(&self, op: WalOp) -> Result<(), PolicyError> {
        if let Some(feed) = &self.feed {
            feed.append(op)
                .await
                .map_err(|e| PolicyError::ChangeFeed(e.to_string()))?;
        }
        Ok(())
    }

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
        let act_str = act.to_string();
        let mut ef = self.enforcer.write().await;
        let success = ef
            .add_policy(vec![sub.clone(), obj.clone(), act_str.clone()])
            .await
            .map_err(|e| self.classify(e))?;
        drop(ef);
        if success {
            self.announce(WalOp::PolicyRuleAdd {
                sub,
                obj,
                act: act_str,
            })
            .await?;
        }
        Ok(success)
    }

    /// Removes a granular permission
    pub async fn remove_rule(
        &self,
        sub: String,
        obj: String,
        act: Action,
    ) -> Result<bool, PolicyError> {
        let act_str = act.to_string();
        let mut ef = self.enforcer.write().await;
        let success = ef
            .remove_policy(vec![sub.clone(), obj.clone(), act_str.clone()])
            .await
            .map_err(|e| self.classify(e))?;
        drop(ef);
        if success {
            self.announce(WalOp::PolicyRuleRemove {
                sub,
                obj,
                act: act_str,
            })
            .await?;
        }
        Ok(success)
    }

    /// Assigns a user to a group (e.g., user_id, superuser)
    pub async fn assign_group(&self, user_id: String, group: String) -> Result<bool, PolicyError> {
        let mut ef = self.enforcer.write().await;
        let success = ef
            .add_grouping_policy(vec![user_id.clone(), group.clone()])
            .await
            .map_err(|e| self.classify(e))?;
        drop(ef);
        if success {
            self.announce(WalOp::GroupAdd {
                user: user_id,
                group,
            })
            .await?;
        }
        Ok(success)
    }

    /// Atomically grants `user_id` the [`SUPERADMIN_ROLE`] provided no
    /// user holds that role yet, plus the permission rules the role needs
    /// to actually manage policies (`read`/`write` on `rules` and
    /// `user_groups`). Without the latter a fresh bootstrap would return
    /// `201` yet still get `403` on every `/policy/*` call.
    ///
    /// Returns `false` when the bootstrap was already completed (the check
    /// and the write share one lock, so two concurrent first-time claims
    /// cannot both succeed). When returning `false` any missing superadmin
    /// permission rules are still repaired, so deployments bootstrapped
    /// before the rules were seeded heal on the next claim attempt.
    pub async fn claim_superadmin(&self, user_id: &str) -> Result<bool, PolicyError> {
        let mut ef = self.enforcer.write().await;
        if !ef.get_users_for_role(SUPERADMIN_ROLE, None).is_empty() {
            let repaired = Self::ensure_superadmin_rules(self.latch, &mut ef).await?;
            drop(ef);
            for (obj, act) in repaired {
                self.announce(WalOp::PolicyRuleAdd {
                    sub: SUPERADMIN_ROLE.to_string(),
                    obj,
                    act: act.to_string(),
                })
                .await?;
            }
            return Ok(false);
        }
        ef.add_grouping_policy(vec![user_id.to_string(), SUPERADMIN_ROLE.to_string()])
            .await
            .map_err(|e| self.classify(e))?;
        let seeded = Self::ensure_superadmin_rules(self.latch, &mut ef).await?;
        drop(ef);
        self.announce(WalOp::GroupAdd {
            user: user_id.to_string(),
            group: SUPERADMIN_ROLE.to_string(),
        })
        .await?;
        for (obj, act) in seeded {
            self.announce(WalOp::PolicyRuleAdd {
                sub: SUPERADMIN_ROLE.to_string(),
                obj,
                act: act.to_string(),
            })
            .await?;
        }
        Ok(true)
    }

    /// Idempotently grants [`SUPERADMIN_ROLE`] full management rights over
    /// policy rules and group membership. Returns the newly added
    /// `(obj, act)` pairs. Caller must hold the enforcer write lock so
    /// the bootstrap check and the seed share one critical section.
    ///
    /// Takes the latch rather than reaching for the process-wide one,
    /// because it is an associated function with no `&self` to read a
    /// per-engine latch from.
    async fn ensure_superadmin_rules(
        latch: &Latch,
        ef: &mut Enforcer,
    ) -> Result<Vec<(String, Action)>, PolicyError> {
        let mut added = Vec::new();
        for (obj, act) in [
            ("rules", Action::Read),
            ("rules", Action::Write),
            ("user_groups", Action::Read),
            ("user_groups", Action::Write),
        ] {
            if ef
                .add_policy(vec![
                    SUPERADMIN_ROLE.to_string(),
                    obj.to_string(),
                    act.to_string(),
                ])
                .await
                .map_err(|e| classify_with(latch, e))?
            {
                added.push((obj.to_string(), act));
            }
        }
        Ok(added)
    }

    /// Removes a user from a group
    pub async fn remove_from_group(
        &self,
        user_id: String,
        group: String,
    ) -> Result<bool, PolicyError> {
        let mut ef = self.enforcer.write().await;
        let success = ef
            .remove_grouping_policy(vec![user_id.clone(), group.clone()])
            .await
            .map_err(|e| self.classify(e))?;
        drop(ef);
        if success {
            self.announce(WalOp::GroupRemove {
                user: user_id,
                group,
            })
            .await?;
        }
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
        let removed = ef
            .remove_filtered_grouping_policy(1, vec![group.to_string()])
            .await
            .map_err(|e| self.classify(e))?;
        drop(ef);
        if removed {
            self.announce(WalOp::GroupDelete {
                group: group.to_string(),
            })
            .await?;
        }
        Ok(removed)
    }

    /// Primary Authorization method.
    ///
    /// The object accepts anything string-like (`&str`, `String`, or your
    /// own typed enum implementing `AsRef<str>`), so business modules can
    /// pass IDE-completable variants without `.into()` ceremony.
    ///
    /// The body lives on [`Authorizer`]; this forwards to it.
    ///
    /// No `tracing::instrument` here: the delegated call opens the span, so
    /// instrumenting both would emit two spans with identical fields per
    /// check instead of the one this path used to produce.
    pub async fn authorize<S: AsRef<str>>(
        &self,
        sub: &str,
        obj: S,
        act: Action,
    ) -> Result<bool, PolicyError> {
        self.authorizer().authorize(sub, obj, act).await
    }

    /// Like [`PolicyEngine::authorize`], but returns
    /// [`PolicyError::AccessDenied`] instead of a boolean when the subject
    /// lacks the permission.
    pub async fn require<S: AsRef<str>>(
        &self,
        sub: &str,
        obj: S,
        act: Action,
    ) -> Result<(), PolicyError> {
        self.authorizer().require(sub, obj, act).await
    }

    /// Returns `(obj, act)` pairs granted to `sub` by `p` rules.
    ///
    /// Used by incremental replica replay to find rows a group membership
    /// change can affect, without scanning the whole policy.
    pub async fn rules_for_subject(&self, sub: &str) -> Vec<(String, String)> {
        self.authorizer().rules_for_subject(sub).await
    }

    /// Returns a list of all users that belong to a specific group
    pub async fn get_users_in_group(&self, group: &str) -> Vec<String> {
        self.authorizer().get_users_in_group(group).await
    }

    /// Returns a list of all groups assigned to a specific user
    pub async fn get_groups_of_user(&self, user_id: &str) -> Vec<String> {
        self.authorizer().get_groups_of_user(user_id).await
    }

    /// Returns a safe, read-only client that can be passed to other services
    pub fn authorizer(&self) -> Authorizer {
        Authorizer {
            enforcer: self.enforcer.clone(),
        }
    }

    /// Non-blocking liveness probe: `true` when the enforcer's write lock
    /// is free.
    ///
    /// The only sanctioned way to inspect the enforcer from outside. Backs
    /// the `/ready` check, which must stay cheap: a `try_read` on a
    /// `try_lock`-free `RwLock` never blocks and never does I/O. A `false`
    /// here means a writer is holding the lock — normally a policy write
    /// in flight, pathologically a wedged one.
    pub fn is_unlocked(&self) -> bool {
        self.authorizer().is_unlocked()
    }
}

/// A capability-limited handle to the policy engine exposing only read and
/// enforcement operations; safe to share with modules that must never mutate
/// policies.
///
/// This type owns the read method bodies. [`PolicyEngine`] holds the same
/// `Arc` and used to carry a byte-identical copy of each one, which meant
/// every casbin behaviour change had to be made twice and neither copy was
/// distinguishable by a test — including the `rules_for_subject` body, which
/// reads casbin's policy tuple by index and so silently depends on its field
/// order. The engine's versions delegate here.
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

    /// Returns the `(obj, act)` pairs granted to `sub` by `p` rules.
    ///
    /// Read-only mirror of [`PolicyEngine::rules_for_subject`], so a
    /// caller holding only an `Authorizer` can still answer "what does this
    /// group grant?" without a write-capable engine.
    pub async fn rules_for_subject(&self, sub: &str) -> Vec<(String, String)> {
        let ef = self.enforcer.read().await;
        ef.get_filtered_policy(0, vec![sub.to_string()])
            .into_iter()
            .filter_map(|r| {
                let obj = r.get(1)?.clone();
                let act = r.get(2)?.clone();
                Some((obj, act))
            })
            .collect()
    }

    /// Non-blocking liveness probe, mirroring
    /// [`PolicyEngine::is_unlocked`] over the same shared enforcer.
    pub fn is_unlocked(&self) -> bool {
        self.enforcer.try_read().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::wal::Wal;
    use crate::test_support::production_source;

    async fn engine() -> PolicyEngine {
        let s3 = crate::db::build_test_store(&crate::db::test_prefix("policy")).await;
        PolicyEngine::init_s3(s3).await.unwrap()
    }

    /// Every variant renders lowercase sentence style, so policy and OIDC
    /// failures read the same in logs as the FS ones. The enum doc makes
    /// this a contract rather than a coincidence.
    /// Only a lost epoch is lifted out of casbin's wrapper.
    ///
    /// The tempting version of this test matches the message text, which
    /// would pass for the wrong reason: an unrelated store failure that
    /// happened to mention fencing would be reclassified, and a reworded
    /// `oxkv` error would silently stop being recognised. Downcasting is
    /// what makes the classification depend on the error's type.
    #[test]
    fn only_a_lost_epoch_is_lifted_out_of_the_adapter_wrapper() {
        use casbin::error::AdapterError;

        // The shape `OxkvAdapter` actually produces.
        let adapter = |e: oxkv::StoreError| {
            PolicyError::from(casbin::Error::AdapterError(AdapterError(Box::new(e))))
        };

        let fenced = adapter(oxkv::StoreError::Fenced("epoch 7 superseded".into()));
        assert!(fenced.is_fencing_loss(), "{fenced:?}");
        assert!(fenced.to_string().contains("epoch 7 superseded"));

        for other in [
            oxkv::StoreError::Storage("bucket gone".into()),
            oxkv::StoreError::CasConflict("two writers".into()),
            oxkv::StoreError::Other("fenced-ish wording that must not count".into()),
        ] {
            let classified = adapter(other.clone());
            assert!(
                !classified.is_fencing_loss(),
                "{other:?} was misread as a fencing loss"
            );
            assert!(matches!(classified, PolicyError::Casbin(_)));
        }

        // A casbin failure that never touched the store is untouched too.
        let engine_failure = PolicyError::from(casbin::Error::PolicyError(
            casbin::error::PolicyError::UnmatchPolicyDefinition(0, 0),
        ));
        assert!(!engine_failure.is_fencing_loss());
        assert!(matches!(engine_failure, PolicyError::Casbin(_)));
    }

    #[test]
    fn error_display_is_lowercase_sentence_style() {
        for rendered in [
            PolicyError::AccessDenied.to_string(),
            PolicyError::ChangeFeed("seq 7 missing".into()).to_string(),
            PolicyError::Fenced("epoch 7 superseded".into()).to_string(),
        ] {
            let first = rendered.chars().next().expect("non-empty display");
            assert!(
                first.is_lowercase(),
                "expected lowercase start, got {rendered:?}"
            );
        }
    }

    #[tokio::test]
    async fn groups_list_assignments_and_delete_round_trip() {
        let engine = engine().await;

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
    }

    #[tokio::test]
    async fn require_accepts_strings_and_typed_objects() {
        let engine = engine().await;

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
    }

    #[tokio::test]
    async fn is_unlocked_tracks_the_write_lock() {
        let engine = engine().await;
        assert!(engine.is_unlocked(), "idle engine must probe ready");

        // Hold the write lock the way a policy mutation does: a wedged
        // writer is exactly what `/ready` is meant to catch.
        let guard = engine.enforcer.write().await;
        assert!(
            !engine.is_unlocked(),
            "a held write lock must read as not-ready"
        );
        drop(guard);
        assert!(engine.is_unlocked(), "probe must recover");
    }

    #[tokio::test]
    async fn authorizer_shares_the_engines_policy_state() {
        let engine = engine().await;
        engine
            .assign_group("alice".into(), "editors".into())
            .await
            .unwrap();
        engine
            .add_rule("editors".into(), "doc".into(), Action::Write)
            .await
            .unwrap();

        // The handle has to observe writes made through the engine, or it
        // is useless for the cross-module sharing it exists to support.
        let auth = engine.authorizer();
        assert_eq!(auth.get_groups_of_user("alice").await, vec!["editors"]);
        assert!(
            auth.authorize("alice", "doc", Action::Write).await.unwrap(),
            "authorizer must see the engine's rules"
        );
        // And it is the read side of the same enforcer, not a copy.
        assert!(auth.is_unlocked());
    }

    /// The read methods have exactly one body, on `Authorizer`.
    ///
    /// `PolicyEngine` and `Authorizer` hold the same `Arc<RwLock<Enforcer>>`
    /// and used to carry byte-identical copies of six read methods. Nothing
    /// about the types required that: a casbin behaviour change had to be
    /// applied twice, and the `rules_for_subject` copy read casbin's policy
    /// tuple by index, so it depended on casbin's field ORDER in two places
    /// at once with no test able to tell the copies apart.
    ///
    /// The duplication is checked structurally, like `http::error`'s
    /// `the_envelope_has_one_construction_site`: a behavioural test cannot
    /// distinguish two identical bodies, and writing one anyway would read
    /// as coverage of a property it does not have.
    #[test]
    fn the_read_methods_have_one_body_and_the_engine_delegates() {
        const DELEGATED: [&str; 6] = [
            "authorize",
            "require",
            "get_users_in_group",
            "get_groups_of_user",
            "rules_for_subject",
            "is_unlocked",
        ];

        let src = production_source("src/policy/mod.rs");
        let (engine, authorizer) = src
            .split_once("\nimpl Authorizer {")
            .expect("both impls are in this file");
        let engine = engine
            .split_once("\nimpl PolicyEngine {")
            .map(|(_, tail)| tail)
            .expect("the engine impl comes first");

        for name in DELEGATED {
            let body = method_body(engine, name);
            assert!(
                body.contains(&format!("self.authorizer().{name}(")),
                "PolicyEngine::{name} must delegate to Authorizer::{name}; it holds \
                 this line instead:\n{body}\nA second copy of a read method is a place a \
                 casbin behaviour change must be applied twice."
            );
            // The delegation is the whole body: anything that reaches the
            // enforcer directly is a second implementation forming.
            assert!(
                !body.contains("self.enforcer"),
                "PolicyEngine::{name} touches the enforcer directly, so it is no \
                 longer a delegation:\n{body}"
            );

            // And the body still exists on the side that owns it, so this
            // cannot be satisfied by deleting both.
            assert!(
                !method_body(authorizer, name).is_empty(),
                "Authorizer::{name} lost its body; there is now no implementation"
            );
        }
    }

    /// The index-addressed casbin policy read exists once in the crate.
    ///
    /// `rules_for_subject` maps a `p` rule row to `(obj, act)` by index, so
    /// it is correct only while casbin's tuple is `(sub, obj, act)`. That is
    /// an assumption about a dependency's internals, and the copy that this
    /// commit deleted had to be corrected alongside the surviving one; a
    /// reordering would have left one of the two silently wrong rather than
    /// failing. One site means one edit and one place to blame.
    #[test]
    fn the_index_addressed_policy_read_has_one_site() {
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

        let mut sites: Vec<(String, usize)> = Vec::new();
        for path in &files {
            let rel = path.to_string_lossy().replace('\\', "/");
            let hits = production_source(&rel)
                .matches("get_filtered_policy(0,")
                .count();
            if hits > 0 {
                sites.push((rel, hits));
            }
        }
        sites.sort();
        assert_eq!(
            sites,
            vec![("src/policy/mod.rs".to_string(), 1)],
            "`get_filtered_policy(0, ..)` reads casbin's policy tuple by \
             position, so it is coupled to the `p = sub, obj, act` field \
             order. It must have exactly one site, counted per occurrence: a \
             second copy inside one file is precisely the case this guards, \
             and counting files would let it through."
        );
    }

    /// Reads a source file's production code: everything before the
    /// column-0 `#[cfg(test)]` module, with comment lines dropped.
    ///
    /// The attribute is matched at column 0 rather than after `trim_start`,
    /// unlike the copies in `http::error` and `records` used to. Those
    /// stopped at the first *indented* `#[cfg(test)]`, which several files
    /// carry on an inner item; scanning `src` with that variant truncated
    /// the walk partway through the files the assertions are about. All
    /// three now match at column 0 and each is tested directly against a
    /// fixture carrying an indented attribute mid-file.
    /// The body of `fn <name>` inside an `impl` block: everything from the
    /// signature to the method's closing brace at one indent level.
    fn method_body(impl_src: &str, name: &str) -> String {
        let needle = format!("fn {name}");
        let start = impl_src
            .find(&needle)
            .unwrap_or_else(|| panic!("no `{name}` in this impl block"))
            + needle.len();
        let rest = &impl_src[start..];
        let end = rest
            .find("\n    }")
            .unwrap_or_else(|| panic!("`{name}` has no closing brace"));
        rest[..end].to_string()
    }

    #[tokio::test]
    async fn superadmin_claim_seeds_management_rules() {
        let engine = engine().await;

        assert!(engine.claim_superadmin("alice").await.unwrap());
        // The bootstrapped subject can actually manage policies now.
        for obj in ["rules", "user_groups"] {
            for act in [Action::Read, Action::Write] {
                assert!(
                    engine.authorize("alice", obj, act).await.unwrap(),
                    "superadmin should hold {act} on {obj}"
                );
            }
        }
        assert!(!engine.claim_superadmin("mallory").await.unwrap());
    }

    #[tokio::test]
    async fn superadmin_claim_heals_prefixed_deployments() {
        use casbin::MgmtApi;

        let engine = engine().await;
        // Simulate a store bootstrapped before the seed existed: g-link
        // only, no permission rules.
        {
            let mut ef = engine.enforcer.write().await;
            ef.add_grouping_policy(vec!["alice".to_string(), SUPERADMIN_ROLE.to_string()])
                .await
                .unwrap();
        }
        assert!(
            !engine
                .authorize("alice", "rules", Action::Read)
                .await
                .unwrap()
        );
        // Next claim attempt still conflicts but repairs the missing rules.
        assert!(!engine.claim_superadmin("bob").await.unwrap());
        assert!(
            engine
                .authorize("alice", "rules", Action::Read)
                .await
                .unwrap()
        );
        assert!(
            engine
                .authorize("alice", "user_groups", Action::Write)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn mutations_are_announced_to_the_feed() {
        use crate::records::WalOp;

        let prefix = crate::db::test_prefix("policy-wal");
        let wal = Wal::new(crate::db::build_test_store(&prefix).await);
        let engine = engine().await.with_change_sink(Arc::new(wal.clone()));

        assert!(
            engine
                .add_rule("alice".into(), "doc".into(), Action::Read)
                .await
                .unwrap()
        );
        // Duplicate: no mutation, no log entry.
        assert!(
            !engine
                .add_rule("alice".into(), "doc".into(), Action::Read)
                .await
                .unwrap()
        );
        assert!(
            engine
                .assign_group("alice".into(), "admins".into())
                .await
                .unwrap()
        );
        assert!(
            engine
                .remove_rule("alice".into(), "doc".into(), Action::Read)
                .await
                .unwrap()
        );
        assert!(
            engine
                .remove_from_group("alice".into(), "admins".into())
                .await
                .unwrap()
        );

        let entries = wal.range(1, wal.head().await.unwrap()).await.unwrap();
        let ops: Vec<&WalOp> = entries.iter().map(|e| &e.op).collect();
        assert_eq!(ops.len(), 4);
        assert!(matches!(&ops[0], WalOp::PolicyRuleAdd { sub, obj, act }
            if sub == "alice" && obj == "doc" && act == "read"));
        assert!(matches!(&ops[1], WalOp::GroupAdd { user, group }
            if user == "alice" && group == "admins"));
        assert!(matches!(&ops[2], WalOp::PolicyRuleRemove { sub, obj, act }
            if sub == "alice" && obj == "doc" && act == "read"));
        assert!(matches!(&ops[3], WalOp::GroupRemove { user, group }
            if user == "alice" && group == "admins"));
    }
}
