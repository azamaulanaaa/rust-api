//! Local entity-attribute-value (EAV) reads over one replica.
//!
//! The `storage` module adapts the replica object map to the read-only oxkv
//! `Storage` trait. Later work adds the entity view and the query.
//!
//! The client reads only the replica that the server built. It makes no
//! authorization decision.

/// The read-only oxkv storage adapter.
pub mod storage;

pub use storage::ReplicaStorage;
