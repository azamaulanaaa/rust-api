//! Generic Entity-Attribute-Value foundations.
//!
//! This module holds a schema registry, an entity store, and the `/eav` API.
//! The API exposes management routes for schemas, entities, and rules.
//! It adds no concrete actions and no business rules.
//! [`schema::SchemaRegistry`](crate::eav::schema::SchemaRegistry) stores immutable schema versions on OxKV.
//! A schema can extend other schemas.
//! [`schema::SchemaRegistry::effective`](crate::eav::schema::SchemaRegistry::effective) flattens the inheritance chain into
//! one attribute map.
//! [`entity::EntityStore`](crate::eav::entity::EntityStore) stores validated entities with typed attributes,
//! plus schema, attribute, and unique indexes.
//!
//! An entity pins one or more schema versions.
//! An update changes attributes only.
//! A later operation changes the pinned schemas.
//! The entity store returns an [`entity::EntityChange`](crate::eav::entity::EntityChange).
//! With a change sink, it writes entity events through an outbox.
//! The event row commits with the entity data.
//! Delivery is at least once.
//! A consumer must be idempotent.
//!
//! [`runtime::EavRuntime`](crate::eav::runtime::EavRuntime) builds the stores from one S3 config and prefix.
//! It then starts the outbox relay and the rule runner.
//! The runtime is always on.
//! A host that does not want EAV removes its wiring in the binary and rebuilds.

/// The maximum value of the `offset` paging field.
///
/// A larger offset is invalid.
/// Use cursor paging with `after` to read a deeper page.
pub(crate) const MAX_PAGE_OFFSET: usize = 1_000;

/// Entity storage, validation, and indexes.
pub mod entity;

/// Error type for the entity store.
pub mod entity_error;

/// Error type for the schema registry.
pub mod error;

/// Metrics helpers for the EAV runtime.
pub mod metrics;

/// Per-user, generation-scoped OxKV replicas for the WASM client.
pub mod oxkv_replica;

/// Portable export, import, index rebuild, and restore checks.
pub mod portable;

/// Stored per-user entity replicas.
pub mod replica;

/// Actix routes for schemas, entities, and rules.
pub mod route;

/// The background runtime for the EAV stores.
pub mod runtime;

/// Versioned schema storage and inheritance.
pub mod schema;

/// Per-user entity change feed for clients.
pub mod sync;

pub use entity::{
    AttributeValue, Entity, EntityChange, EntityDraft, EntityPatch, EntityStore, WriteContext,
};
pub use entity_error::EntityError;
pub use metrics::EavMetrics;
pub use runtime::{EavRuntime, EavRuntimeConfig, EavRuntimeError, RefCheck, Scripts};
