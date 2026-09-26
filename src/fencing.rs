//! Process-wide latch for a lost *primary* write session.
//!
//! # What this is for
//!
//! `oxkv` acquires a prefix by CAS-bumping `ownership.json`: last writer
//! wins, and the loser discovers it only at write time, as
//! `StoreError::Fenced`. `oxkv` documents that condition as terminal -- "the
//! current process must stop writing and restart via `ownership.json` CAS".
//!
//! This process was already handling the *cooperative* half of that: the
//! single-writer lease on `[database].prefix` (see [`crate::lease`]) gates
//! `/ready` when it cannot be renewed, so a replaced writer stops
//! advertising itself. What was missing is the uncooperative half. A second
//! writer that never took the lease -- an older build, a `writer_lease_ttl_secs
//! = 0` deployment, an operator running the `policy import` subcommand
//! against a live prefix -- can still fence this process, and then the lease
//! check keeps reporting healthy while every master write fails.
//!
//! So a fencing loss is latched here as a second, independent signal for the
//! same condition, and `/ready` reports on both.
//!
//! # Why the process is not terminated
//!
//! The obvious alternative is to exit. That makes the outage worse rather
//! than better: a fenced primary is already read-only, so it can no longer
//! diverge, and killing it immediately means zero healthy writers if the
//! successor is not serving yet. Marking the instance unready lets the load
//! balancer drain it while the replacement takes over, and leaves the
//! decision to restart with the operator, who has the log line saying the
//! handle is terminal.
//!
//! # Replica fencing is not this
//!
//! Losing a replica *build* race is routine: two workers building the same
//! user's prefix, resolved by adopting the winner's coverage. Only the
//! primary prefixes -- `{db}/fs`, `{db}/policy`, `{db}/wal` -- are terminal,
//! so the trip points are chosen to exclude replica writes.

use std::sync::atomic::{AtomicBool, Ordering};

/// One latch. The process-wide instance is the module's `static`; tests use
/// their own so they cannot observe each other's trips.
#[derive(Debug)]
pub struct Latch {
    tripped: AtomicBool,
}

impl Default for Latch {
    fn default() -> Self {
        Self::new()
    }
}

impl Latch {
    /// A latch that has not tripped.
    pub const fn new() -> Self {
        Self {
            tripped: AtomicBool::new(false),
        }
    }

    /// Records a loss, logging the first one at `error` and the rest at
    /// `debug`.
    ///
    /// Idempotent on the state, noisy only once. Every subsequent write on a
    /// fenced handle fails the same way, so a per-request `error!` would
    /// bury the first occurrence -- the one that matters -- under the
    /// symptom.
    pub fn trip(&self, source: &str, reason: &str) {
        if self.tripped.swap(true, Ordering::SeqCst) {
            tracing::debug!("fencing loss repeated on {source}: {reason}");
            return;
        }
        tracing::error!(
            "store epoch lost to another writer on {source} ({reason}); \
             this process can no longer write that prefix and is now \
             unready. Writes to it will keep failing until it is restarted."
        );
    }

    /// True once any primary write has been fenced.
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }
}

/// The process-wide primary-fencing latch.
static PRIMARY_LOSS: Latch = Latch::new();

/// Records a lost epoch on a primary prefix. See the module docs for which
/// prefixes qualify and why the process is not terminated.
pub fn note_primary_loss(source: &str, reason: &str) {
    PRIMARY_LOSS.trip(source, reason);
}

/// True once a primary write has been fenced, i.e. this instance should stop
/// advertising readiness.
pub fn primary_loss() -> bool {
    PRIMARY_LOSS.is_tripped()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first report is the one an operator needs; the rest are the same
    /// condition repeating.
    #[test]
    fn trip_is_idempotent_and_observable() {
        let latch = Latch::new();
        assert!(!latch.is_tripped());

        latch.trip("{db}/fs", "epoch 2 superseded");
        assert!(latch.is_tripped());

        // A second, different prefix still trips the same latch, and does
        // not reset it.
        latch.trip("{db}/policy", "epoch 2 superseded");
        assert!(latch.is_tripped());
    }

    /// Two latches are independent, which is what keeps a test that trips one
    /// from making the process-wide signal flap.
    #[test]
    fn latches_do_not_share_state() {
        let a = Latch::new();
        let b = Latch::new();
        a.trip("{db}/fs", "epoch 2");
        assert!(a.is_tripped());
        assert!(!b.is_tripped());
    }

    /// The signal is reachable from outside this module, which is what lets
    /// `main.rs` gate `/ready` on it.
    ///
    /// One-directional on purpose: the latch is process-wide, so other tests
    /// in this binary trip it too and asserting "not tripped" would be
    /// order-dependent. The assertion that matters in the other direction --
    /// that a *replica* write must not trip it -- needs no global state and
    /// lives in `fs::store::tests::only_a_fenced_master_write_latches`.
    #[test]
    fn the_process_wide_signal_is_readable() {
        note_primary_loss("{db}/test", "epoch 2");
        assert!(primary_loss());
    }
}
