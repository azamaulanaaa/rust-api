//! The WASM client for the rust-api server.
//!
//! This crate builds as a `cdylib` for the browser and as an `rlib` for the
//! native test target. The skeleton holds no browser code yet. Later work
//! adds fetch, the replica cache, local reads, and job status.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use rust_api_model::wire::{ReplicaManifest, SyncCursor};

/// The client-side job status modules.
///
/// The poll and SSE transports live in the `poll` and `sse` submodules.
pub mod jobs;

/// Returns `true` when a replica has applied the full change feed.
pub fn replica_is_current(cursor: SyncCursor, manifest: &ReplicaManifest) -> bool {
    rust_api_core::replica_is_current(cursor, manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_api_model::wire::ReplicaManifest;

    /// The client uses the shared core rule for a current replica.
    #[test]
    fn the_client_uses_the_shared_replica_rule() {
        let manifest = ReplicaManifest {
            generation: 3,
            head: 5,
            objects: Vec::new(),
        };
        assert!(!replica_is_current(SyncCursor { seq: 4 }, &manifest));
        assert!(replica_is_current(SyncCursor { seq: 5 }, &manifest));
    }
}
