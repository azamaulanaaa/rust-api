//! Errors for the EAV schema registry.
//!
//! Each variant carries a short sanitized message.
//! The message never contains a raw store dump or a raw key.
//! Internal detail stays in the tuple field for server-side logs.

use thiserror::Error;

/// An error from the EAV schema registry.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// A store read or write failed.
    #[error("schema store operation failed")]
    Store(#[source] oxkv::StoreError),
    /// The input is not valid.
    #[error("{0}")]
    Invalid(String),
    /// A schema or parent schema does not exist.
    #[error("{0}")]
    NotFound(String),
    /// Schema inheritance contains a cycle.
    #[error("schema inheritance cycle")]
    Cycle,
    /// One attribute has two different types.
    #[error("attribute type conflict: {0}")]
    TypeConflict(String),
    /// Data could not be encoded or decoded.
    #[error("schema serialization failed")]
    Internal(String),
}
