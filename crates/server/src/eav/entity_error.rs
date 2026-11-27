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
    /// A replica build is older than the stored replica.
    ///
    /// The stored head and data stay unchanged.
    #[error("stale replica head: stored {stored}, incoming {incoming}")]
    StaleHead {
        /// The head of the stored replica.
        stored: u64,
        /// The head of the rejected build.
        incoming: u64,
    },
    /// The OxKV wrapper publish did not complete.
    ///
    /// The JSON replica can already hold the new generation.
    /// The old wrapper and its objects stay readable.
    /// A later build reconciles the wrapper to the JSON replica.
    #[error("oxkv replica publish conflict")]
    PublishConflict,
    /// An `EntityRef` attribute names an entity that does not exist.
    ///
    /// The first field is the attribute name.
    /// The second field is the target entity id.
    #[error("attribute {0} references an entity that does not exist: {1}")]
    DanglingRef(String, String),
    /// Other entities still reference the entity.
    ///
    /// The fields are the entity id and the number of distinct referring
    /// entities.
    /// The message does not list the referring ids.
    #[error(
        "entity {id} has {count} references from other entities. Delete with force to override"
    )]
    Referenced {
        /// The entity id.
        id: String,
        /// The number of distinct referring entities.
        count: usize,
    },
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
