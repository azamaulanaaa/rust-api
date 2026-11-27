//! Local entity-attribute-value (EAV) reads over one replica.
//!
//! The `storage` module adapts the replica object map to the read-only oxkv
//! `Storage` trait. The `view` module decodes the `entity:` rows into the
//! shared search entity type. The `query` module caches one view for each
//! replica object map and runs the shared core query.
//!
//! The client reads only the replica that the server built. It makes no
//! authorization decision.

/// The local entity query and its view cache.
pub mod query;

/// The read-only oxkv storage adapter.
pub mod storage;

/// The decoded entity view.
pub mod view;

#[cfg(test)]
pub(crate) mod test_support;

pub use query::{QueryError, ReplicaQuery};
pub use storage::ReplicaStorage;
pub use view::{EntityView, QueryPage, ViewError};
