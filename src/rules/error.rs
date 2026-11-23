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
    /// The stored rule changed before the write could commit.
    #[error("rule version conflict")]
    VersionConflict,
    /// Data could not be encoded or decoded.
    #[error("rule serialization failed: {message}")]
    Serialization {
        /// Sanitized detail for server logs.
        message: String,
        /// Cause from the codec.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A typed cause that the engine flattens for its callers.
    #[error("{message}")]
    Cause {
        /// Sanitized detail for server logs.
        message: String,
        /// Cause from the lower layer.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
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
    #[error("rule feed failed: {message}")]
    Wal {
        /// Sanitized detail for server logs.
        message: String,
        /// Cause from the feed, when one is available.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
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

impl RuleError {
    /// Wraps a codec error without losing its source.
    pub(crate) fn serialization(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Serialization {
            message: error.to_string(),
            source: Box::new(error),
        }
    }

    /// Wraps a typed cause behind a sanitized message.
    pub(crate) fn cause(
        message: impl Into<String>,
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Cause {
            message: message.into(),
            source: Box::new(error),
        }
    }

    /// Builds a feed error from a message with no typed source.
    pub(crate) fn wal(message: impl Into<String>) -> Self {
        Self::Wal {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a feed error that keeps the underlying cause.
    pub(crate) fn wal_source(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Wal {
            message: error.to_string(),
            source: Some(Box::new(error)),
        }
    }
}
