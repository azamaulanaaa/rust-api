//! Per-user filtered clones with on-demand WAL replay.
//!
//! The master [`FsStore`](crate::fs::store::FsStore) lives on a prefix-scoped
//! `S3Store`; per-user clones are the filtered file list serialized as JSON
//! objects on `S3`.

pub mod route;
pub mod snapshot;
pub mod wal;
