//! Local entity-attribute-value (EAV) reads over one replica.
//!
//! The `storage` module adapts the replica object map to the read-only oxkv
//! `Storage` trait. The `view` module decodes the `entity:` rows into the
//! shared search entity type. Later work adds the query.
//!
//! The client reads only the replica that the server built. It makes no
//! authorization decision.

/// The read-only oxkv storage adapter.
pub mod storage;

/// The decoded entity view.
pub mod view;

pub use storage::ReplicaStorage;
pub use view::{EntityView, QueryPage, ViewError};
