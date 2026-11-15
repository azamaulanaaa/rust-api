//! Errors for the rule store and the rule engine.
//!
//! Each variant carries a short and sanitized message.
//! The message never contains a raw store dump or a raw key.
//! Internal detail stays in the tuple field for server-side logs.

use thiserror::Error;

use crate::rules::script::ScriptError;

/// An error from the rule store.
#[derive(Debug, Error)]
pub enum RuleError {
    /// A store read or write failed.
    #[error("rule store operation failed")]
    Store(#[source] oxkv::StoreError),
    /// The input is not valid.
    #[error("{0}")]
    Invalid(String),
    /// The rule does not exist.
    #[error("rule not found: {0}")]
    NotFound(String),
    /// Data could not be encoded or decoded.
    #[error("rule serialization failed")]
    Serialization(String),
    /// The condition tree is deeper than 16 levels.
    #[error("rule condition depth exceeds 16")]
    ConditionDepth,
    /// The trigger names an event that no code path emits.
    #[error("rule trigger event is not accepted: {0}")]
    UnsupportedTrigger(String),
    /// The rule names an action that the engine does not know.
    #[error("unknown action: {0}")]
    UnknownAction(String),
    /// An action failed.
    ///
    /// The message holds the action kind only.
    /// It never holds the raw action error.
    #[error("rule action failed: {0}")]
    Action(String),
    /// A change-feed read or write failed.
    #[error("rule feed failed: {0}")]
    Wal(String),
    /// Two registered actions have the same kind.
    #[error("duplicate action kind: {0}")]
    DuplicateAction(String),
    /// A condition script failed at run time.
    ///
    /// The inner message is stable and sanitized.
    /// It never holds the script source.
    #[error("rule script failed: {0}")]
    Script(#[from] ScriptError),
}
