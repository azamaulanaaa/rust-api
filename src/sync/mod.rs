//! Per-user filtered replicas on stable prefixes with WAL replay.
//!
//! The master [`FsStore`](crate::fs::store::FsStore) remains the sole write
//! path; each user owns one replica prefix holding their filtered file set,
//! served over `/sync/db/` for oxkv readers.

pub mod route;
pub mod snapshot;
pub mod wal;
