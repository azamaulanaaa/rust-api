//! Shared pure behavior for the rust-api server and the WASM client.
//!
//! The crate is synchronous. It has no I/O, no network, no runtime, and no
//! server dependency. A caller loads the data and passes a view or an
//! iterator. The same code then runs on the server and in the browser.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use rust_api_model::wire::{ReplicaManifest, SyncCursor};

/// Pure entity-attribute-value (EAV) validation rules and in-memory search.
pub mod eav;

/// Returns `true` when a replica has applied the full change feed.
///
/// The cursor is current when its sequence is at or above the manifest
/// head. A higher cursor is not an error here. The server detects that
/// condition when it reads the replica.
pub fn replica_is_current(cursor: SyncCursor, manifest: &ReplicaManifest) -> bool {
    cursor.seq >= manifest.head
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_api_model::wire::ReplicaManifest;

    /// Builds one empty replica manifest at the named head.
    fn manifest(head: u64) -> ReplicaManifest {
        ReplicaManifest {
            generation: 1,
            head,
            objects: Vec::new(),
        }
    }

    /// The cursor is current only at or above the head.
    #[test]
    fn a_replica_is_current_at_or_above_the_head() {
        let manifest = manifest(10);
        assert!(!replica_is_current(SyncCursor { seq: 9 }, &manifest));
        assert!(replica_is_current(SyncCursor { seq: 10 }, &manifest));
        assert!(replica_is_current(SyncCursor { seq: 11 }, &manifest));
    }
}
