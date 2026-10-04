//! Single-writer enforcement for a `[database].prefix` scope.
//!
//! # Why this is not an `oxkv` concern
//!
//! `oxkv` owns a prefix through `ownership.json`, and acquiring it is a
//! CAS-bump of a monotonic epoch: whoever builds a handle last wins and
//! fences the previous one at write time ([`StoreError::Fenced`](oxkv::StoreError::Fenced),
//! which `oxkv` documents as "the current process must stop writing and
//! restart"). That is a correct *takeover* protocol and a useless
//! *detection* protocol: nothing in it can distinguish "my predecessor is
//! still serving traffic" from "my predecessor crashed", so a second
//! replica pointed at the same prefix starts cleanly, serves writes that
//! silently diverge, and only fails later and elsewhere.
//!
//! Telling those two cases apart needs a liveness signal, which needs a
//! lease. This module is that signal: one small object in the same bucket,
//! written with a conditional create, renewed on a timer, and released on a
//! clean shutdown.
//!
//! # What it guarantees
//!
//! - Two processes racing to start on the same prefix: the loser refuses to
//!   start and names the winner. No split brain.
//! - A crashed predecessor: the lease goes stale after `ttl_secs` and the
//!   next start takes over automatically. No manual cleanup.
//! - Two predecessors crashing together and two replicas starting together:
//!   the stale record is replaced under a compare-and-set, so exactly one
//!   of them wins and the other is told who.
//! - A predecessor that stalls (GC pause, node partition) past the TTL: the
//!   successor takes over, and the predecessor notices on its next renewal
//!   and reports itself unready. Divergence is bounded to the stall window
//!   rather than being silent forever.
//!
//! It cannot prevent a network partition from splitting the prefix; nothing
//! lease-based can. What it buys is that the losing side *finds out*, and
//! stops taking traffic, instead of discovering it through corrupted data.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use object_store::{ObjectStore, PutMode, PutPayload, UpdateVersion, path::Path as ObjectPath};
use serde::{Deserialize, Serialize};

/// Object key holding the lease record, relative to the bucket root.
///
/// Deliberately *not* under any `oxkv` prefix: it has to be readable through
/// a raw [`ObjectStore`] before any store is built (building one takes an
/// epoch, which is the thing being guarded), and it must never collide with
/// a transactional key. The leading underscore keeps it out of the
/// `{prefix}/policy`, `/fs`, `/wal`, `/u/...` namespace.
const LEASE_KEY: &str = "_rust-api-writer-lease.json";

/// Default lease TTL: long enough to ride out a GC pause or a slow S3
/// request, short enough that a crashed node is replaced promptly.
pub const DEFAULT_LEASE_TTL_SECS: u64 = 60;

/// The lease record as stored in the bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseRecord {
    /// Identity of the holder, `{hostname}:{uuid}`.
    instance: String,
    /// Unix seconds when this process first claimed the lease.
    claimed_at: i64,
    /// Unix seconds of the most recent renewal.
    renewed_at: i64,
    /// TTL the holder is operating under.
    ttl_secs: u64,
    /// Holder's pid, for an operator reading the object by hand.
    pid: u32,
}

/// Why a lease could not be claimed.
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    /// Another process holds a live lease on this prefix.
    #[error(
        "another writer already holds {prefix:?}: instance {instance:?} (pid {pid}) \
         last renewed {age}s ago, ttl {ttl}s. Refusing to start: two writers on one \
         `[database].prefix` silently diverge. Stop the other process, or wait {wait}s \
         for its lease to go stale (or raise `[database].writer_lease_ttl_secs`)."
    )]
    Held {
        /// The contested prefix.
        prefix: String,
        /// Identity recorded by the holder.
        instance: String,
        /// Holder's pid.
        pid: u32,
        /// Seconds since the holder last renewed.
        age: i64,
        /// TTL the holder is operating under.
        ttl: u64,
        /// Seconds until the lease goes stale.
        wait: i64,
    },

    /// The lease record exists but could not be parsed.
    #[error("writer lease at {prefix:?} is corrupt ({detail}); refusing to guess who owns it")]
    Corrupt {
        /// The contested prefix.
        prefix: String,
        /// Decode failure.
        detail: String,
    },

    /// The object store rejected a lease operation.
    #[error("writer lease I/O failed for {prefix:?}: {source}")]
    Io {
        /// The contested prefix.
        prefix: String,
        /// Underlying store error.
        source: object_store::Error,
    },
}

/// A held single-writer lease.
///
/// Dropping the guard does *not* release the lease: an orderly release is an
/// explicit [`release`](Self::release) so that shutdown ordering is visible at
/// the call site. A dropped lease simply goes stale after its TTL, which is
/// the crash path working as intended.
#[derive(Debug)]
pub struct WriterLease {
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    record: LeaseRecord,
    /// Set when a renewal finds another instance holding the lease. Drives
    /// `/ready`, so the orchestrator drains and replaces this process.
    lost: Arc<AtomicBool>,
}

impl WriterLease {
    /// Claims the lease for `db_prefix`, or explains who holds it.
    ///
    /// Must be called *before* any
    /// [`build_s3_store`](crate::db::build_s3_store) for the same scope:
    /// building a store takes an epoch, so checking afterwards would mean
    /// having already displaced the incumbent.
    pub async fn acquire(
        store: Arc<dyn ObjectStore>,
        db_prefix: &str,
        ttl_secs: u64,
    ) -> Result<Self, LeaseError> {
        let prefix = db_prefix.trim_matches('/').to_string();
        let path = lease_path(&prefix);
        let now = chrono::Utc::now().timestamp();
        let record = LeaseRecord {
            instance: instance_id(),
            claimed_at: now,
            renewed_at: now,
            ttl_secs,
            pid: std::process::id(),
        };

        // Fast path: nobody has ever written the record.
        if write_record(&*store, &path, &record, WriteMode::Create)
            .await
            .is_ok()
        {
            tracing::info!(
                prefix = %prefix,
                instance = %record.instance,
                "claimed single-writer lease"
            );
            return Ok(Self::new(store, path, record));
        }

        // Someone holds it. Stale means crashed; fresh means alive.
        let held = fetch(&*store, &path, &prefix)
            .await?
            .ok_or_else(|| LeaseError::Io {
                prefix: prefix.clone(),
                source: object_store::Error::NotFound {
                    path: path.to_string(),
                    source: "lease vanished between create and read".into(),
                },
            })?;
        let age = now - held.record.renewed_at;
        if age < held.record.ttl_secs as i64 {
            return Err(LeaseError::held(&prefix, &held.record, age));
        }

        tracing::warn!(
            prefix = %prefix,
            previous_instance = %held.record.instance,
            previous_pid = held.record.pid,
            stale_for_secs = age,
            ttl_secs = held.record.ttl_secs,
            "taking over an expired single-writer lease (previous holder stopped renewing)"
        );
        // Conditional on the exact record we judged stale. A racing
        // take-over that got there first changes the object, so this write
        // fails its precondition and the loser reports the winner instead
        // of confirming a record it clobbered.
        if let Err(source) =
            write_record(&*store, &path, &record, WriteMode::Unchanged(held.version)).await
        {
            return Err(match source {
                object_store::Error::Precondition { .. } => {
                    let winner =
                        fetch(&*store, &path, &prefix)
                            .await?
                            .ok_or_else(|| LeaseError::Io {
                                prefix: prefix.clone(),
                                source: object_store::Error::NotFound {
                                    path: path.to_string(),
                                    source: "lease vanished during take-over".into(),
                                },
                            })?;
                    LeaseError::held(&prefix, &winner.record, 0)
                }
                other => LeaseError::Io {
                    prefix: prefix.clone(),
                    source: other,
                },
            });
        }
        tracing::info!(prefix = %prefix, instance = %record.instance, "claimed expired lease");
        Ok(Self::new(store, path, record))
    }

    fn new(store: Arc<dyn ObjectStore>, path: ObjectPath, record: LeaseRecord) -> Self {
        Self {
            store,
            path,
            record,
            lost: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Identity recorded in the lease, for logs and operator tooling.
    pub fn instance(&self) -> &str {
        &self.record.instance
    }

    /// Flag flipped once another instance is observed holding the lease.
    ///
    /// Share the `Arc` with the `/ready` check: losing the lease means this
    /// process must stop taking traffic, because a successor now owns the
    /// prefix.
    pub fn lost_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.lost)
    }

    /// Renews the lease. Returns `false` once another instance holds it.
    ///
    /// Read-before-write, and deliberately so: a renewal that wrote first
    /// would overwrite a successor's record and then read back its *own*
    /// write, concluding it still held the lease. That is the exact
    /// split brain this module exists to prevent -- the displaced process
    /// would keep re-claiming the record it had already lost.
    ///
    /// A renewal that cannot confirm ownership (S3 blip, unparseable
    /// record) also returns `false`: treating transient I/O as "still
    /// fine" would let a partitioned node keep serving after its lease
    /// expired elsewhere.
    ///
    /// A successor may still slip in between the read and the write, but
    /// only one that already considered us stale (past the TTL). The
    /// residual window is one round trip inside a TTL violation, not a
    /// standing condition.
    ///
    /// The write here stays unconditional, unlike the take-over in
    /// [`WriterLease::acquire`]: this process has already established it is
    /// the holder, and making the renewal itself a compare-and-set would
    /// only convert a benign overwrite into a spurious "lease lost" the
    /// first time a successor took over.
    pub async fn renew(&mut self) -> bool {
        if self.lost.load(Ordering::Relaxed) {
            return false;
        }
        match fetch(&*self.store, &self.path, "").await {
            Ok(Some(current)) if current.record.instance != self.record.instance => {
                tracing::error!(
                    instance = %self.record.instance,
                    new_holder = %current.record.instance,
                    "single-writer lease was taken over by another instance; \
                     this process must stop serving writes"
                );
                self.lost.store(true, Ordering::Relaxed);
                return false;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    instance = %self.record.instance,
                    error = %e,
                    "could not confirm single-writer lease; reporting unready"
                );
                self.lost.store(true, Ordering::Relaxed);
                return false;
            }
        }
        self.record.renewed_at = chrono::Utc::now().timestamp();
        if write_record(&*self.store, &self.path, &self.record, WriteMode::Overwrite)
            .await
            .is_err()
        {
            tracing::warn!(
                instance = %self.record.instance,
                "failed to renew single-writer lease; reporting unready"
            );
            self.lost.store(true, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Releases the lease if we still hold it, so a replacement can start
    /// immediately instead of waiting out the TTL.
    ///
    /// Best effort: a failure here only costs the next start `ttl_secs`, so
    /// it is logged rather than propagated.
    pub async fn release(&mut self) {
        match fetch(&*self.store, &self.path, "").await {
            Ok(Some(current)) if current.record.instance != self.record.instance => {
                tracing::info!(
                    instance = %self.record.instance,
                    "lease already held by another instance; leaving it alone"
                );
            }
            Ok(_) => {
                if let Err(e) = self.store.delete(&self.path).await {
                    tracing::warn!(
                        instance = %self.record.instance,
                        error = %e,
                        "failed to release single-writer lease; it will expire in {}s",
                        self.record.ttl_secs
                    );
                } else {
                    tracing::info!(instance = %self.record.instance, "released single-writer lease");
                }
            }
            Err(e) => {
                tracing::warn!(
                    instance = %self.record.instance,
                    error = %e,
                    "could not read the lease to release it; it will expire in {}s",
                    self.record.ttl_secs
                );
            }
        }
    }
}

/// Keeps a renewal task alive and releases the lease when dropped.
///
/// Dropping this guard ends the renewal loop and lets the release run, but
/// *nothing waits for it*. A `Drop` impl cannot await, and the task it
/// wakes only becomes runnable -- it is not run. At process exit the Tokio
/// runtime drops spawned tasks without polling them, so a shutdown that
/// relies on the drop never deletes the record and the replacement waits
/// out the whole TTL.
///
/// [`release`](Self::release) is the orderly path and the one the server
/// takes. Drop remains a best-effort backstop for the early-error exits
/// that cannot await.
///
/// `#[must_use]`: dropping it early silently disables renewal, and the
/// release it would have triggered is the part that does not run.
#[must_use = "dropping the guard stops renewal and releases the lease on a best-effort basis"]
#[derive(Debug)]
pub struct LeaseGuard {
    /// Ends the renewal task's shutdown future. `None` once [`release`](Self::release)
    /// has taken it, so a released guard does not signal twice.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// The renewal task, which owns the lease and releases it on the way
    /// out. `None` once [`release`](Self::release) has taken it.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LeaseGuard {
    /// Stops renewal and waits for the lease to be released.
    ///
    /// This is what makes a rolling restart hand the prefix over without a
    /// TTL wait, and the reason the shutdown path in `main.rs` awaits it
    /// rather than dropping the guard.
    ///
    /// Bounded by [`RELEASE_TIMEOUT`]: a release is best effort (it only
    /// costs the next start one TTL), so an unreachable object store must
    /// not hold the process open forever. On timeout this returns and the
    /// lease expires on its own, which is the crash path working as
    /// intended. The renewal task is left running rather than aborted --
    /// its release is a single `get` plus a `delete`, so aborting mid-call
    /// buys nothing and the runtime will drop it on exit anyway.
    ///
    /// Consumes the guard, so the `Drop` backstop does not fire behind it
    /// and release twice.
    pub async fn release(mut self) {
        self.release_within(RELEASE_TIMEOUT).await
    }

    /// [`release`](Self::release), bounded by `timeout` instead.
    pub async fn release_within(&mut self, timeout: std::time::Duration) {
        // Both fields are `Option` so this is idempotent: a guard released
        // twice signals once, and the second call finds nothing to await.
        self.shutdown.take();
        let Some(task) = self.task.take() else {
            return;
        };
        let timed_out = tokio::time::timeout(timeout, task).await;
        match timed_out {
            Ok(Ok(())) => {}
            Ok(Err(e)) if e.is_cancelled() => {
                tracing::warn!("single-writer lease renewal task was cancelled before releasing");
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "single-writer lease renewal task panicked");
            }
            Err(_) => {
                tracing::warn!(
                    timeout_secs = timeout.as_secs(),
                    "timed out releasing the single-writer lease; it will expire instead"
                );
            }
        }
    }
}

impl Drop for LeaseGuard {
    /// Stops renewal and lets the release run, without waiting for it.
    ///
    /// Only the best-effort half: the task is detached rather than awaited,
    /// so at process exit the runtime drops it unpolled and the record
    /// survives until the TTL expires. Callers that can await should call
    /// [`release`](Self::release) instead -- see the type docs for why
    /// dropping is not equivalent.
    fn drop(&mut self) {
        self.shutdown.take();
    }
}

/// How long [`LeaseGuard::release`] waits for the record to be deleted
/// before giving up and letting the TTL expire it.
///
/// A release is a single `get` plus a `delete` on the lease key, so a
/// correct store answers in well under a second. The bound is generous
/// because its only job is to stop a wedged store from holding the process
/// open indefinitely, and the cost of firing is bounded and known: the
/// replacement waits one TTL.
pub const RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawns a renewal task, returning the `/ready` flag and the guard that
/// keeps it running.
///
/// The task releases the lease when the guard drops, and when
/// [`LeaseGuard::release`] tells it to. It keeps ticking after a lost
/// lease rather than exiting: a later successful renewal cannot un-fence
/// us, and the flag must stay set so the process is never re-admitted to
/// traffic, so there is nothing useful left to do.
pub fn spawn_renewer(
    mut lease: WriterLease,
    interval: std::time::Duration,
) -> (Arc<AtomicBool>, LeaseGuard) {
    let lost = lease.lost_flag();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // the first tick completes immediately
        // Pinned outside the loop: `select!` would otherwise move the
        // shutdown future on the first iteration.
        tokio::pin!(rx);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if !lease.renew().await {
                        tracing::error!("single-writer lease lost; /ready reports 503");
                    }
                }
                // Fires when the guard drops (sender closed) or on an
                // explicit send.
                _ = &mut rx => break,
            }
        }
        lease.release().await;
    });
    (
        lost,
        LeaseGuard {
            shutdown: Some(tx),
            task: Some(task),
        },
    )
}

fn instance_id() -> String {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string());
    format!("{host}:{}", uuid::Uuid::now_v7())
}

/// Object path of the lease record for a (already trimmed) prefix.
fn lease_path(prefix: &str) -> ObjectPath {
    if prefix.is_empty() {
        ObjectPath::from(LEASE_KEY)
    } else {
        ObjectPath::from(format!("{prefix}/{LEASE_KEY}"))
    }
}

impl LeaseError {
    /// Builds the "someone else holds it" error for a lease we read.
    fn held(prefix: &str, record: &LeaseRecord, age: i64) -> Self {
        let ttl = record.ttl_secs as i64;
        Self::Held {
            prefix: prefix.to_string(),
            instance: record.instance.clone(),
            pid: record.pid,
            age,
            ttl: record.ttl_secs,
            wait: (ttl - age).max(0),
        }
    }
}

/// A lease record read off the store, with the version that read observed.
///
/// The version is what makes a take-over a compare-and-set: it is the token
/// `PutMode::Update` checks, so the write can only land if nobody changed
/// the record between this read and that write.
#[derive(Debug)]
struct Fetched {
    record: LeaseRecord,
    version: UpdateVersion,
}

/// Reads the lease record, mapping a decode failure to [`LeaseError::Corrupt`]
/// rather than a generic I/O error: an unparseable record must not look
/// like a transient blip, because the safe response to it is to refuse.
async fn fetch(
    store: &dyn ObjectStore,
    path: &ObjectPath,
    prefix: &str,
) -> Result<Option<Fetched>, LeaseError> {
    let out = match store
        .get_opts(path, object_store::GetOptions::default())
        .await
    {
        Ok(out) => out,
        Err(object_store::Error::NotFound { .. }) => return Ok(None),
        Err(source) => {
            return Err(LeaseError::Io {
                prefix: prefix.to_string(),
                source,
            });
        }
    };
    let version = UpdateVersion {
        e_tag: out.meta.e_tag.clone(),
        version: out.meta.version.clone(),
    };
    let bytes = out.bytes().await.map_err(|source| LeaseError::Io {
        prefix: prefix.to_string(),
        source,
    })?;
    let record = serde_json::from_slice(&bytes).map_err(|e| LeaseError::Corrupt {
        prefix: prefix.to_string(),
        detail: e.to_string(),
    })?;
    Ok(Some(Fetched { record, version }))
}

/// How a record write may land.
enum WriteMode {
    /// Only if the object does not exist.
    Create,
    /// Replace whatever is there.
    Overwrite,
    /// Replace only the exact version observed.
    Unchanged(UpdateVersion),
}

async fn write_record(
    store: &dyn ObjectStore,
    path: &ObjectPath,
    record: &LeaseRecord,
    mode: WriteMode,
) -> Result<(), object_store::Error> {
    let bytes = serde_json::to_vec(record).map_err(|e| object_store::Error::Generic {
        store: "writer-lease",
        source: Box::new(e),
    })?;
    let mode = match mode {
        WriteMode::Create => PutMode::Create,
        WriteMode::Overwrite => PutMode::Overwrite,
        WriteMode::Unchanged(version) => PutMode::Update(version),
    };
    store
        .put_opts(
            path,
            PutPayload::from(bytes),
            object_store::PutOptions {
                mode,
                ..Default::default()
            },
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::BoxFuture;
    use futures_util::stream::BoxStream;

    fn mem() -> Arc<dyn ObjectStore> {
        Arc::new(object_store::memory::InMemory::new())
    }

    const TTL: u64 = 60;

    /// A fresh lease blocks a second writer, and the error names the holder.
    /// This is the case the whole module exists for: without it, a second
    /// replica starts cleanly and the two diverge silently.
    #[tokio::test]
    async fn second_writer_is_refused_while_the_lease_is_live() {
        let store = mem();
        let prefix = "lease-test-live";
        let first = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("first writer claims");

        let err = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect_err("second writer must be refused");
        let LeaseError::Held {
            instance,
            pid,
            wait,
            ..
        } = &err
        else {
            panic!("expected Held, got {err:?}");
        };
        assert_eq!(instance, first.instance());
        assert_eq!(*pid, std::process::id());
        assert!(*wait > 0, "error should say how long to wait: {err}");
        // The message has to be actionable for an operator reading logs.
        let text = err.to_string();
        assert!(text.contains(prefix), "unhelpful message: {text}");
        assert!(text.contains(first.instance()), "unhelpful message: {text}");
    }

    /// A holder that stops renewing (crash) must not block recovery: past
    /// the TTL the next start takes over, and says who it displaced.
    #[tokio::test]
    async fn expired_lease_is_taken_over() {
        let store = mem();
        let prefix = "lease-test-stale";
        let first = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("first writer claims");

        // Backdate the record instead of sleeping: this is what a crashed
        // holder looks like on disk.
        let path = lease_path(prefix);
        let mut stale: LeaseRecord =
            serde_json::from_slice(&store.get(&path).await.unwrap().bytes().await.unwrap())
                .unwrap();
        stale.renewed_at -= TTL as i64 * 10;
        write_record(&*store, &path, &stale, WriteMode::Overwrite)
            .await
            .unwrap();

        let second = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("stale lease is takeable");
        assert_ne!(second.instance(), first.instance());

        // And the record on disk is now the new holder's.
        let current: LeaseRecord =
            serde_json::from_slice(&store.get(&path).await.unwrap().bytes().await.unwrap())
                .unwrap();
        assert_eq!(current.instance, second.instance());
    }

    /// Two processes may not both take over the *same* stale lease.
    ///
    /// A crashed holder plus two replicas starting together is the ordinary
    /// case, not an exotic one: it is what a node failure and a rolling
    /// restart both look like. The take-over used to be write-then-verify:
    /// both replicas read the stale record, both overwrote it
    /// unconditionally, and each confirm-read landed after its *own* write,
    /// so both returned `Ok`. The check caught only the interleaving that
    /// does not produce two winners, while the comment over it claimed to
    /// catch the racing process.
    ///
    /// The damage was bounded -- the second `build_s3_store` epoch-fences
    /// the first, whose next `renew()` notices within one tick and latches
    /// `lost` -- but for up to `ttl/3` both are in rotation and one 500s on
    /// every write.
    ///
    /// `RaceStore` performs a competing writer's overwrite in the window
    /// between our read and our write, which is exactly the interleaving a
    /// real second process produces. With the take-over as a compare-and-set
    /// on the observed version, the write fails its precondition and the
    /// loser is told who won; with the unconditional overwrite it lands and
    /// both processes believe they hold the prefix.
    #[tokio::test]
    async fn a_takeover_that_loses_the_race_reports_the_winner_instead_of_claiming_it() {
        let store = mem();
        let prefix = "lease-test-takeover-race";
        let stale = seed_stale_lease(&store, prefix, "crashed-holder").await;

        // `acquire` reads the record, decides it is stale, then writes.
        // This puts a competitor's record in that window, on the same
        // backend so the racer's own conditional write sees the change.
        let path = lease_path(prefix);
        let racing = RaceStore {
            inner: Arc::clone(&store),
            before_put: RaceHook::new({
                let store = Arc::clone(&store);
                let path = path.clone();
                move || {
                    let store = Arc::clone(&store);
                    let path = path.clone();
                    Box::pin(async move {
                        store
                            .put_opts(
                                &path,
                                PutPayload::from(
                                    serde_json::to_vec(&winner_record()).expect("encode"),
                                ),
                                object_store::PutOptions::default(),
                            )
                            .await
                            .expect("competitor write");
                    })
                }
            }),
        };
        let racing: Arc<dyn ObjectStore> = Arc::new(racing);

        let err = WriterLease::acquire(racing, prefix, TTL)
            .await
            .expect_err("a lost take-over race must not produce a second writer");
        let LeaseError::Held { instance, .. } = &err else {
            panic!("expected Held, got {err:?}");
        };
        assert_eq!(
            instance,
            &winner_record().instance,
            "the loser must name the winner: {err}",
        );

        // And the record on disk is still the winner's: the loser did not
        // clobber it on the way out.
        let current: LeaseRecord =
            serde_json::from_slice(&store.get(&path).await.unwrap().bytes().await.unwrap())
                .unwrap();
        assert_eq!(current.instance, winner_record().instance);
        assert_ne!(
            current.instance, stale.instance,
            "the crashed holder must be displaced"
        );
    }

    /// Identity the racing winner in the test above claims to be.
    fn winner_record() -> LeaseRecord {
        let now = chrono::Utc::now().timestamp();
        LeaseRecord {
            instance: "racer-1".to_string(),
            claimed_at: now,
            renewed_at: now,
            ttl_secs: TTL,
            pid: std::process::id(),
        }
    }

    /// A record that looks like a crashed holder's: present but past its
    /// TTL, which is the precondition for a take-over.
    async fn seed_stale_lease(
        store: &Arc<dyn ObjectStore>,
        prefix: &str,
        instance: &str,
    ) -> LeaseRecord {
        let now = chrono::Utc::now().timestamp();
        let record = LeaseRecord {
            instance: instance.to_string(),
            claimed_at: now - TTL as i64 * 10,
            renewed_at: now - TTL as i64 * 10,
            ttl_secs: TTL,
            pid: std::process::id(),
        };
        write_record(&**store, &lease_path(prefix), &record, WriteMode::Overwrite)
            .await
            .expect("seed a stale record");
        record
    }

    /// An [`ObjectStore`] that runs a competing write in the window between
    /// the caller's read and its write.
    ///
    /// The interleaving is the whole point and cannot be produced by
    /// timing: `acquire` reads the record, decides it is stale, then writes.
    /// A real second process lands its write in that gap. This injects one
    /// there, deterministically, so the assertion is about the
    /// compare-and-set rather than about a race that may or may not happen
    /// to resolve this way on this run.
    #[derive(Debug)]
    struct RaceStore {
        inner: Arc<dyn ObjectStore>,
        before_put: RaceHook,
    }

    /// A boxed competing write. Newtype so it can carry a [`Debug`] impl, which
    /// the store it feeds requires and a boxed future does not have.
    #[derive(Clone)]
    struct RaceHook(Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>);

    impl std::fmt::Debug for RaceHook {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("RaceHook")
        }
    }

    impl RaceHook {
        /// Wraps the competing-write closure.
        fn new<F>(hook: F) -> Self
        where
            F: Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static,
        {
            Self(Arc::new(hook))
        }

        /// Runs the hook.
        async fn run(&self) {
            (self.0)().await
        }
    }

    impl std::fmt::Display for RaceStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("RaceStore")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for RaceStore {
        async fn put_opts(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            opts: object_store::PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            // Only the conditional write is the contended one; the initial
            // `PutMode::Create` fast path has nothing to race against.
            if matches!(opts.mode, PutMode::Update(_)) {
                self.before_put.run().await;
            }
            self.inner.put_opts(location, payload, opts).await
        }

        async fn put_multipart_opts(
            &self,
            _location: &ObjectPath,
            _opts: object_store::PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            unimplemented!("the lease never uses multipart")
        }

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: object_store::GetOptions,
        ) -> object_store::Result<object_store::GetResult> {
            self.inner.get_opts(location, options).await
        }

        async fn delete(&self, location: &ObjectPath) -> object_store::Result<()> {
            self.inner.delete(location).await
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> object_store::Result<object_store::ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy(&self, from: &ObjectPath, to: &ObjectPath) -> object_store::Result<()> {
            self.inner.copy(from, to).await
        }

        async fn copy_if_not_exists(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
        ) -> object_store::Result<()> {
            self.inner.copy_if_not_exists(from, to).await
        }

        fn list(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
            self.inner.list(prefix)
        }
    }

    /// The displaced writer must find out on its next renewal and latch
    /// itself unready -- this is the half that makes the lease a lease
    /// rather than a startup assertion.
    #[tokio::test]
    async fn renewal_detects_takeover_and_latches_unready() {
        let store = mem();
        let prefix = "lease-test-renew";
        let mut first = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("first writer claims");
        let lost = first.lost_flag();
        assert!(!lost.load(Ordering::Relaxed));

        // A successor backdates the record past its TTL and takes over.
        let path = lease_path(prefix);
        let mut stale: LeaseRecord =
            serde_json::from_slice(&store.get(&path).await.unwrap().bytes().await.unwrap())
                .unwrap();
        stale.renewed_at -= TTL as i64 * 10;
        write_record(&*store, &path, &stale, WriteMode::Overwrite)
            .await
            .unwrap();
        let _second = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("stale lease is takeable");

        assert!(!first.renew().await, "renewal must notice the takeover");
        assert!(lost.load(Ordering::Relaxed), "lost flag must latch");
        // Latched: a later renewal must not "recover" and re-admit traffic.
        assert!(!first.renew().await);
    }

    /// Renewal keeps a live lease alive, so a long-running process is never
    /// displaced by a peer that sees a stale record.
    #[tokio::test]
    async fn renewal_keeps_a_healthy_lease() {
        let store = mem();
        let prefix = "lease-test-healthy";
        let mut lease = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("claims");
        let lost = lease.lost_flag();
        assert!(lease.renew().await);
        assert!(!lost.load(Ordering::Relaxed));
    }

    /// A displaced process must not overwrite the record on its way out.
    /// This is the failure the read-before-write ordering in `renew`
    /// prevents: writing first would make the loser clobber the winner's
    /// lease on every tick, and read back its own write to conclude it
    /// still held it.
    #[tokio::test]
    async fn displaced_writer_does_not_clobber_its_successor() {
        let store = mem();
        let prefix = "lease-test-noclobber";
        let mut first = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("claims");

        let path = lease_path(prefix);
        let mut stale: LeaseRecord =
            serde_json::from_slice(&store.get(&path).await.unwrap().bytes().await.unwrap())
                .unwrap();
        stale.renewed_at -= TTL as i64 * 10;
        write_record(&*store, &path, &stale, WriteMode::Overwrite)
            .await
            .unwrap();
        let second = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("stale lease is takeable");

        assert!(!first.renew().await, "renewal must notice the takeover");
        let on_disk: LeaseRecord =
            serde_json::from_slice(&store.get(&path).await.unwrap().bytes().await.unwrap())
                .unwrap();
        assert_eq!(
            on_disk.instance,
            second.instance(),
            "the displaced writer overwrote its successor's lease"
        );
    }

    /// An orderly release hands the prefix over without a TTL wait, which is
    /// what makes a rolling restart fast.
    #[tokio::test]
    async fn release_allows_immediate_reacquisition() {
        let store = mem();
        let prefix = "lease-test-release";
        let mut lease = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("claims");
        lease.release().await;

        let next = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("released lease must be immediately claimable");
        assert_ne!(next.instance(), lease.instance());
    }

    /// Shutting the guard down must actually delete the lease record, before
    /// the caller returns.
    ///
    /// This is the property the whole orderly-release path rests on, and it
    /// was not true. `serve` held the guard in a plain `_lease_guard`
    /// binding and relied on its `Drop` to run `lease.release()`. Dropping
    /// the `oneshot::Sender` only *made* the detached task runnable; `serve`
    /// then returned to `#[tokio::main] main`, which returned and dropped
    /// the runtime, and Tokio drops spawned tasks without polling them. A
    /// `Drop` impl cannot compensate because it cannot await.
    ///
    /// So `DELETE _rust-api-writer-lease.json` never executed on *any*
    /// graceful shutdown. A replacement pod read the still-present record
    /// with `age < ttl_secs`, got `LeaseError::Held`, propagated it out of
    /// `serve`, and CrashLoopBackOffs until the TTL expired -- defeating
    /// the rolling-restart handover the lease exists to provide.
    ///
    /// Awaiting the guard's `release` is what makes it happen, so the test
    /// awaits it and asserts the record is gone on return. Confirmed to
    /// fail if the guard is dropped instead: the record survives, and the
    /// reacquisition below returns `Held`.
    #[tokio::test]
    async fn awaiting_the_guard_release_deletes_the_record_before_returning() {
        let store = mem();
        let prefix = "lease-test-guard-release";
        let lease = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("claims");
        let instance = lease.instance().to_string();
        let (_lost, guard) = spawn_renewer(lease, std::time::Duration::from_secs(3600));
        let path = lease_path(prefix);
        assert!(
            store.get(&path).await.is_ok(),
            "precondition: the lease record exists while held",
        );

        // The orderly shutdown path.
        guard.release().await;

        assert!(
            store.get(&path).await.is_err(),
            "awaiting the release returned without deleting the lease record; \
             a replacement waits out the whole TTL",
        );
        // And the practical consequence: the prefix is immediately
        // claimable, with no TTL wait.
        let next = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("an orderly shutdown must hand the prefix over immediately");
        assert_ne!(next.instance(), instance);
    }

    /// The renewal task must stop when the guard shuts down.
    ///
    /// A renewal that kept ticking after shutdown would overwrite the
    /// successor's record and read back its own write, concluding it still
    /// held the lease -- the split brain `renew`'s read-before-write
    /// ordering exists to prevent, reachable from the other direction.
    #[tokio::test]
    async fn releasing_the_guard_stops_renewal() {
        let store = mem();
        let prefix = "lease-test-stop-renew";
        let lease = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("claims");
        let (_lost, mut guard) = spawn_renewer(lease, std::time::Duration::from_millis(10));
        let path = lease_path(prefix);

        // `release_within` awaits the task, so a stop is observable once it
        // returns: nothing else can write the record afterwards.
        guard
            .release_within(std::time::Duration::from_secs(5))
            .await;

        // A successor takes the prefix.
        let next = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("released lease is claimable");

        // Several renewal intervals with room to spare. If the task were
        // still ticking it would have clobbered the successor's record.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let on_disk: LeaseRecord =
            serde_json::from_slice(&store.get(&path).await.unwrap().bytes().await.unwrap())
                .unwrap();
        assert_eq!(
            on_disk.instance,
            next.instance(),
            "a stopped renewal task overwrote its successor's lease",
        );
    }

    /// Releasing twice must not release twice.
    ///
    /// `release` consumes the guard, but `release_within` takes `&mut self`
    /// so the shutdown ordering can be exercised directly. A second call
    /// finds the task already taken and does nothing, rather than awaiting
    /// a `JoinHandle` it no longer owns.
    #[tokio::test]
    async fn releasing_a_guard_twice_is_a_no_op() {
        let store = mem();
        let prefix = "lease-test-double-release";
        let lease = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("claims");
        let (_lost, mut guard) = spawn_renewer(lease, std::time::Duration::from_secs(3600));
        let path = lease_path(prefix);

        guard
            .release_within(std::time::Duration::from_secs(5))
            .await;
        assert!(store.get(&path).await.is_err());

        // Must not hang or panic; there is nothing left to await.
        guard
            .release_within(std::time::Duration::from_secs(5))
            .await;
    }

    /// An unreachable store must not hold shutdown open forever.
    ///
    /// The release is best effort: failing to delete the record costs the
    /// next start one TTL, while blocking shutdown costs a rolling restart
    /// entirely and, on an orchestrator with a termination grace period,
    /// a SIGKILL. So the wait is bounded, and the bound is what the test
    /// exercises -- `StuckStore` never answers `get`, which is what an
    /// unreachable S3 looks like from here.
    #[tokio::test]
    async fn a_stalled_release_gives_up_rather_than_blocking_shutdown() {
        let prefix = "lease-test-stalled-release";
        let now = chrono::Utc::now().timestamp();
        let record = LeaseRecord {
            instance: "holder-1".to_string(),
            claimed_at: now,
            renewed_at: now,
            ttl_secs: TTL,
            pid: std::process::id(),
        };
        // Built directly rather than acquired: `acquire` needs a store that
        // answers, and the whole point is a store that does not.
        let lease = WriterLease::new(Arc::new(StuckStore), lease_path(prefix), record);
        let (_lost, mut guard) = spawn_renewer(lease, std::time::Duration::from_secs(3600));

        // The release reads the record before deleting it, so a store that
        // hangs on `get` stalls the whole release.
        let started = std::time::Instant::now();
        guard
            .release_within(std::time::Duration::from_millis(100))
            .await;

        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the release was not bounded; shutdown would hang on the store",
        );
        // Bounded, not skipped: the wait really ran, just not forever.
        // Without the `timeout` this future never resolves at all, which is
        // the property the assertion below cannot express and this one can.
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(50),
            "the release gave up before even trying; the bound is a no-op",
        );
    }

    /// A store that never answers, so a shutdown's release cannot complete.
    #[derive(Debug)]
    struct StuckStore;

    impl std::fmt::Display for StuckStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("StuckStore")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for StuckStore {
        async fn put_opts(
            &self,
            _location: &ObjectPath,
            _payload: PutPayload,
            _opts: object_store::PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            unreachable!("the release never writes")
        }

        async fn put_multipart_opts(
            &self,
            _location: &ObjectPath,
            _opts: object_store::PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            unreachable!("the release never uses multipart")
        }

        async fn get_opts(
            &self,
            _location: &ObjectPath,
            _options: object_store::GetOptions,
        ) -> object_store::Result<object_store::GetResult> {
            std::future::pending().await
        }

        async fn delete(&self, _location: &ObjectPath) -> object_store::Result<()> {
            std::future::pending().await
        }

        fn list(
            &self,
            _prefix: Option<&ObjectPath>,
        ) -> BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
            unreachable!("the release never lists")
        }

        async fn list_with_delimiter(
            &self,
            _prefix: Option<&ObjectPath>,
        ) -> object_store::Result<object_store::ListResult> {
            unreachable!("the release never lists")
        }

        async fn copy(&self, _from: &ObjectPath, _to: &ObjectPath) -> object_store::Result<()> {
            unreachable!("the release never copies")
        }

        async fn copy_if_not_exists(
            &self,
            _from: &ObjectPath,
            _to: &ObjectPath,
        ) -> object_store::Result<()> {
            unreachable!("the release never copies")
        }
    }

    /// A release must not delete a lease someone else now owns, or a
    /// displaced process would un-fence its own successor on the way out.
    #[tokio::test]
    async fn release_leaves_a_successors_lease_alone() {
        let store = mem();
        let prefix = "lease-test-nosteal";
        let mut first = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("claims");

        let path = lease_path(prefix);
        let mut stale: LeaseRecord =
            serde_json::from_slice(&store.get(&path).await.unwrap().bytes().await.unwrap())
                .unwrap();
        stale.renewed_at -= TTL as i64 * 10;
        write_record(&*store, &path, &stale, WriteMode::Overwrite)
            .await
            .unwrap();
        let _second = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("stale lease is takeable");

        first.release().await;
        assert!(
            store.get(&path).await.is_ok(),
            "release deleted the successor's lease"
        );
    }

    /// An unparseable record must be refused, never guessed at: silently
    /// overwriting it is exactly the split brain this module prevents.
    #[tokio::test]
    async fn corrupt_lease_is_refused_not_overwritten() {
        let store = mem();
        let prefix = "lease-test-corrupt";
        store
            .put(&lease_path(prefix), PutPayload::from(b"not json".to_vec()))
            .await
            .unwrap();

        let err = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect_err("corrupt lease must not be claimable");
        assert!(
            matches!(err, LeaseError::Corrupt { .. }),
            "expected Corrupt, got {err:?}"
        );
    }

    /// The record must sit outside every oxkv prefix, or it would collide
    /// with transactional keys and be swept by prefix scans.
    #[tokio::test]
    async fn lease_lives_outside_the_oxkv_prefixes() {
        for prefix in ["oxkv", "custom/prefix", ""] {
            let path = lease_path(prefix);
            let text = path.as_ref();
            assert!(text.ends_with(LEASE_KEY), "unexpected path {text}");
            for domain in ["/policy", "/fs", "/wal", "/u/"] {
                assert!(
                    !text.contains(domain),
                    "lease path {text} collides with the {domain} prefix"
                );
            }
        }
        assert_eq!(lease_path("").as_ref(), LEASE_KEY);
        assert_eq!(lease_path("oxkv").as_ref(), format!("oxkv/{LEASE_KEY}"));
    }
}
