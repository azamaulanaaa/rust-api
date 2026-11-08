//! Generic Entity-Attribute-Value foundations.
//!
//! This module holds a schema registry and an entity store.
//! It has no HTTP routes and no business rules.
//! [`schema::SchemaRegistry`] stores immutable schema versions on OxKV.
//! A schema can extend other schemas.
//! [`schema::SchemaRegistry::effective`] flattens the inheritance chain into
//! one attribute map.
//! [`entity::EntityStore`] stores validated entities with typed attributes,
//! plus schema, attribute, and unique indexes.
//!
//! An entity pins one or more schema versions.
//! An update changes attributes only.
//! A later operation changes the pinned schemas.
//! The entity store returns an [`entity::EntityChange`].
//! With a change sink, it writes entity events through an outbox.
//! The event row commits with the entity data.
//! Delivery is at least once.
//! A consumer must be idempotent.

/// Entity storage, validation, and indexes.
pub mod entity;

/// Error type for the entity store.
pub mod entity_error;

/// Error type for the schema registry.
pub mod error;

/// Versioned schema storage and inheritance.
pub mod schema;

pub use entity::{
    AttributeValue, Entity, EntityChange, EntityDraft, EntityPatch, EntityStore, WriteContext,
};
pub use entity_error::EntityError;
