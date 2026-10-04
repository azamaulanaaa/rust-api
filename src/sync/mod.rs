//! Per-user filtered replicas on stable prefixes, updated by WAL replay.
//!
//! The master [`FsStore`](crate::fs::store::FsStore) stays the only write
//! path. Each user owns one replica prefix. That prefix holds the file set
//! the user can read. The route `/sync/db/` serves the prefix to oxkv
//! readers.

pub mod route;
pub mod snapshot;
pub mod wal;
