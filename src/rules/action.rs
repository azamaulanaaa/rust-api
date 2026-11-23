//! Rule actions and the action context.
//!
//! A [`RuleAction`] is the only extension point of the rule engine.
//! The engine finds an action by its kind and calls it for one rule and one
//! event.
//! The context holds owned values, so the trait needs no lifetime parameter.
//! This module has no concrete action.

use async_trait::async_trait;

use crate::eav::entity::{Entity, WriteContext};
use crate::records::EntityEvent;
use crate::rules::rule::Rule;

/// An error from a rule action.
#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    /// The action parameters are not valid.
    #[error("rule action parameters are not valid")]
    Invalid,
    /// The action could not run or could not validate its parameters.
    #[error("rule action failed: {kind}")]
    Failed {
        /// Kind of the action that failed.
        kind: String,
    },
}

impl ActionError {
    /// Creates an error for invalid parameters.
    #[must_use]
    pub fn invalid() -> Self {
        Self::Invalid
    }

    /// Creates an error that names the failed action kind.
    #[must_use]
    pub fn failed(kind: &str) -> Self {
        Self::Failed {
            kind: kind.to_string(),
        }
    }
}

/// The owned input of one rule action.
///
/// The engine builds one context for each rule that it runs.
/// The entity is `None` when the entity is deleted.
#[derive(Debug, Clone)]
pub struct ActionContext {
    /// The rule that matched.
    pub rule: Rule,
    /// The event that matched.
    pub event: EntityEvent,
    /// The current entity. `None` means that the entity is deleted.
    pub entity: Option<Entity>,
    /// The action parameters from the rule.
    pub params: serde_json::Value,
}

impl ActionContext {
    /// Returns a write context for an entity that this action writes.
    ///
    /// The context uses `actor` as the subject.
    /// It carries the event id as the causation id.
    /// It sets the causation depth to one more than the depth of the event.
    ///
    /// An action that writes an entity must use this context.
    /// That is how the depth guard sees the chain.
    pub fn child_write_context(&self, actor: impl Into<String>) -> WriteContext {
        WriteContext::new(actor).with_causation(
            self.event.event_id.clone(),
            self.event.causation_depth.saturating_add(1),
        )
    }
}

/// One action that the rule engine can run.
///
/// An implementation must be idempotent.
/// A crash can repeat one event.
/// The engine can also retry one failed action.
#[async_trait]
pub trait RuleAction: Send + Sync {
    /// Returns the action kind. The value must not be empty.
    fn kind(&self) -> &str;

    /// Checks the action parameters before the rule is stored.
    ///
    /// The API calls this check before it stores a rule.
    /// The default accepts every parameter.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError`] when a parameter is not valid.
    fn validate(&self, _params: &serde_json::Value) -> Result<(), ActionError> {
        Ok(())
    }

    /// Runs this action for one context.
    ///
    /// A failure stops the engine for this event.
    /// The engine writes no execution marker in that case.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError`] when the action cannot run.
    async fn execute(&self, ctx: ActionContext) -> Result<(), ActionError>;
}
