//! Errors for the rule store.
//!
//! Each variant carries a short and sanitized message.
//! The message never contains a raw store dump or a raw key.
//! Internal detail stays in the tuple field for server-side logs.

use thiserror::Error;

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
}
