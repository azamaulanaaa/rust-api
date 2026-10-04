//! Process-wide latch for a lost *primary* write session.
//!
//! # What this is for
//!
//! `oxkv` takes a prefix by doing a CAS bump on `ownership.json`. The last
//! writer wins. The loser finds out only at write time, as
//! `StoreError::Fenced`. The `oxkv` docs call that condition final. They say
//! "the current process must stop writing and restart via `ownership.json`
//! CAS".
//!
//! This process already handled the *cooperative* half of that. The
//! single-writer lease on `[database].prefix` (see [`crate::lease`]) makes
//! `/ready` report unready when it cannot renew the lease. So a writer that
//! was replaced stops advertising itself. The uncooperative half was
//! missing. A second writer can still fence this process without ever taking
//! the lease. An older build can do it. A deployment with
//! `writer_lease_ttl_secs = 0` can do it. An operator who runs the
//! `policy import` subcommand against a prefix that is live can do it. After
//! that, the lease check keeps reporting healthy while every write to the
//! master fails.
//!
//! So this module records a fencing loss on a latch. That latch is a second
//! signal, independent of the lease, for the same condition. `/ready` checks
//! both signals.
//!
//! # Why the process is not terminated
//!
//! The obvious alternative is to exit. That makes the failure worse. A
//! fenced primary is already read-only, so it can no longer diverge. Killing
//! it at once means zero healthy writers, if the successor is not serving
//! yet. Marking the instance unready lets the load balancer drain it while
//! the replacement takes over. The decision to restart stays with the
//! operator. The operator has the log line that says the handle is final.
//!
//! # Replica fencing is not this
//!
//! Losing a race to build a *replica* is routine. Two workers build the
//! prefix of the same user, and the result resolves by adopting the
//! coverage of the winner. Only the primary prefixes are final. Those are
//! `{db}/fs`, `{db}/policy`, and `{db}/wal`. So the points that call the
//! latch leave out replica writes.

use std::sync::atomic::{AtomicBool, Ordering};

/// One latch. The instance for the whole process is the `static` of the
/// module. Each test uses its own latch, so the tests cannot see each other's
/// losses.
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
    /// A latch that has not recorded a loss.
    pub const fn new() -> Self {
        Self {
            tripped: AtomicBool::new(false),
        }
    }

    /// Records a loss. The function logs the first loss at `error`. It logs
    /// every later loss at `debug`.
    ///
    /// The function does not change the state again after the first loss. It
    /// is noisy only once. Every later write on a fenced handle fails in the
    /// same way. So an `error!` for each request would bury the first loss,
    /// which is the one that matters, under the symptom.
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

    /// True after the server fences a primary write.
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }
}

/// The process-wide primary-fencing latch.
static PRIMARY_LOSS: Latch = Latch::new();

/// The latch on which the fencing losses of a primary prefix are recorded.
///
/// The owner of the master store holds this latch, instead of calling
/// [`note_primary_loss`] directly. So the latch moves with the ownership that
/// decides whether a loss is final. That also makes the latch replaceable. A
/// test can point a store at its own [`Latch`] and see the loss. The latch
/// for the whole process cannot support that. It only works in one direction,
/// and every other test in the binary would set it first.
pub fn process_latch() -> &'static Latch {
    &PRIMARY_LOSS
}

/// Records a lost epoch on a primary prefix. The module docs list the
/// prefixes that qualify. They also explain why the process is not
/// terminated.
pub fn note_primary_loss(source: &str, reason: &str) {
    PRIMARY_LOSS.trip(source, reason);
}

/// True after the server fences a primary write. So this instance must stop
/// advertising that it is ready.
pub fn primary_loss() -> bool {
    PRIMARY_LOSS.is_tripped()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first report is the one that an operator needs. The later reports
    /// are the same condition again.
    #[test]
    fn trip_is_idempotent_and_observable() {
        let latch = Latch::new();
        assert!(!latch.is_tripped());

        latch.trip("{db}/fs", "epoch 2 superseded");
        assert!(latch.is_tripped());

        // A second prefix that is different also sets the same latch. It
        // does not clear it.
        latch.trip("{db}/policy", "epoch 2 superseded");
        assert!(latch.is_tripped());
    }

    /// Two latches do not share state. That is what keeps a test that sets
    /// one latch from making the signal of the whole process change.
    #[test]
    fn latches_do_not_share_state() {
        let a = Latch::new();
        let b = Latch::new();
        a.trip("{db}/fs", "epoch 2");
        assert!(a.is_tripped());
        assert!(!b.is_tripped());
    }

    /// Code outside this module can read the signal. That is what lets
    /// `main.rs` use it in the check for `/ready`.
    ///
    /// The signal only works in one direction, on purpose. The latch belongs
    /// to the whole process, so other tests in this binary also set it. An
    /// assertion that it is not set would depend on the order of the tests.
    /// The assertion that matters in the other direction is that a write to
    /// a *replica* must not set it. That assertion needs no global state. It
    /// is in `fs::store::tests::only_a_fenced_master_write_latches`.
    #[test]
    fn the_process_wide_signal_is_readable() {
        note_primary_loss("{db}/test", "epoch 2");
        assert!(primary_loss());
    }
}
