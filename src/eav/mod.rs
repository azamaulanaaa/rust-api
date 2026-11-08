//! Generic Entity-Attribute-Value foundations.
//!
//! This module holds the schema registry only.
//! It has no entity storage, no HTTP routes, and no business rules.
//! [`schema::SchemaRegistry`] stores immutable schema versions on OxKV.
//! A schema can extend other schemas.
//! [`schema::SchemaRegistry::effective`] flattens the inheritance chain into
//! one attribute map.

/// Error type for the schema registry.
pub mod error;

/// Versioned schema storage and inheritance.
pub mod schema;
