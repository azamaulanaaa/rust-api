//! Per-user filtered clones with on-demand WAL replay.
//!
//! Master stays `Redb` file; per-user clones are `Redb` files cached as `S3` objects.
//! When `oxkv` ships `S3` backend, only `Store` open changes.

pub mod snapshot;
pub mod wal;
