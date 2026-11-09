//! Errors for the EAV entity store.
//!
//! Each variant carries a short and sanitized message.
//! The message never contains a raw store dump or a raw key.
//! Internal detail stays in the tuple field for server-side logs.

use thiserror::Error;

/// An error from the EAV entity store.
#[derive(Debug, Error)]
pub enum EntityError {
    /// A store read or write failed.
    #[error("entity store operation failed")]
    Store(#[source] oxkv::StoreError),
    /// The input is not valid.
    #[error("{0}")]
    Invalid(String),
    /// A schema id does not exist.
    #[error("unknown schema: {0}")]
    UnknownSchema(String),
    /// An attribute is not defined by the applied schemas.
    #[error("unknown attribute: {0}")]
    UnknownAttribute(String),
    /// The applied schemas conflict.
    #[error("entity schema conflict: {0}")]
    SchemaConflict(String),
    /// A required attribute is missing.
    #[error("missing required attribute: {0}")]
    MissingRequired(String),
    /// An attribute value has the wrong type.
    #[error("attribute type mismatch: {0}")]
    TypeMismatch(String),
    /// A unique attribute value already exists.
    #[error("unique attribute value already exists: {0}")]
    UniqueViolation(String),
    /// The attribute is not indexed by any applied schema.
    #[error("attribute is not indexed: {0}")]
    NotIndexed(String),
    /// The entity version does not match.
    #[error("entity version conflict")]
    VersionConflict,
    /// The entity already exists.
    #[error("entity already exists: {0}")]
    AlreadyExists(String),
    /// The entity does not exist.
    #[error("entity not found: {0}")]
    NotFound(String),
    /// Data could not be encoded or decoded.
    #[error("entity serialization failed")]
    Internal(String),
    /// The change feed did not accept a committed event.
    ///
    /// The entity data and the outbox row stay committed.
    /// A later flush can deliver the event.
    #[error("entity feed delivery failed")]
    Feed(String),
}
