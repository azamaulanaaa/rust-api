//! Per-user filtered replicas with on-demand WAL replay.
//!
//! The master [`FsStore`](crate::fs::store::FsStore) remains the sole write
//! path; per-user snapshot versions are filtered read replicas on
//! versioned `OxKvStore` prefixes, served over `/sync/db/` for oxkv readers.

pub mod route;
pub mod snapshot;
pub mod wal;
