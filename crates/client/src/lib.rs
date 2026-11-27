//! The WASM client for the rust-api server.
//!
//! This crate builds as a `cdylib` for the browser and as an `rlib` for the
//! native test target. The `auth` module holds the session check and the
//! transport seam. The `replica` module downloads, verifies, and stores a
//! per-user replica. The `eav` module reads the local entity view and runs
//! the shared core query. The `jobs` module submits a command and polls its
//! status. The client never applies a pending command to the replica view.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use rust_api_model::wire::{ReplicaManifest, SyncCursor};

/// The auth transport seam and the session check.
pub mod auth;

/// Local entity-attribute-value queries over a replica.
pub mod eav;

/// The client-side job status modules.
///
/// The poll and SSE transports live in the `poll` and `sse` submodules.
pub mod jobs;

/// The replica loader and its in-memory cache.
pub mod replica;

#[cfg(target_arch = "wasm32")]
mod wasm;

/// The JavaScript-facing client type.
///
/// This type builds only for `wasm32`, because it carries the
/// `wasm-bindgen` binding for JavaScript. Native builds of this crate do not
/// include it.
#[cfg(target_arch = "wasm32")]
pub use wasm::Client;

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
