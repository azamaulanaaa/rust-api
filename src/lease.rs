//! Single-writer enforcement for a `[database].prefix` scope.
//!
//! # Why this is not an `oxkv` concern
//!
//! `oxkv` owns a prefix through `ownership.json`. Acquiring it is a CAS bump
//! of a monotonic epoch. The last process to build a handle wins. That
//! process fences the earlier one at write time
//! ([`StoreError::Fenced`](oxkv::StoreError::Fenced)). The `oxkv` docs call
//! that condition "the current process must stop writing and restart". That
//! is a correct *takeover* protocol and a useless *detection* protocol.
//!
//! Nothing in the protocol tells the two cases apart:
//!
//! - The earlier process still serves traffic.
//! - The earlier process crashed.
//!
//! A second replica that uses the same prefix therefore starts cleanly. It
//! then serves writes that diverge in a way that no tool reports. The failure
//! appears later and elsewhere.
//!
//! Telling the two cases apart needs a liveness signal. A liveness signal
//! needs a lease. This module is that signal. The lease is one small object
//! in the same bucket. The holder creates it with a conditional create. A
//! timer renews it. A clean shutdown releases it.
//!
//! # What it guarantees
//!
//! - Two processes that start at the same time on one prefix: the loser
//!   refuses to start and names the winner. There is no split brain.
//! - A predecessor that crashed: the lease goes stale after `ttl_secs`, and
//!   the next start takes it over. There is no manual cleanup.
//! - Two predecessors that crash together, and two replicas that start
//!   together: the stale record is replaced under a compare-and-set. So
//!   exactly one of them wins, and the other is told who won.
//! - A predecessor that stops for longer than the TTL, for example during a
//!   GC pause or a node partition: the successor takes over. The predecessor
//!   finds out on its next renewal, and reports itself unready. Divergence
//!   stays inside the length of the stop, instead of being silent forever.
//!
//! The lease cannot stop a network partition from splitting the prefix.
//! Nothing that uses a lease can. What the lease does give is that the losing
//! side *finds out* and stops taking traffic, instead of finding out through
//! data that is corrupt.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use object_store::{ObjectStore, PutMode, PutPayload, UpdateVersion, path::Path as ObjectPath};
use serde::{Deserialize, Serialize};

/// Object key that holds the lease record, relative to the root of the
/// bucket.
///
/// The key is deliberately not under any `oxkv` prefix. The lease must be
/// readable through a raw [`ObjectStore`] before any store is built. Building
/// a store takes an epoch, and that epoch is the thing the lease guards. The
/// key must also never collide with a transactional key. The leading
/// underscore keeps it out of the `{prefix}/policy`, `/fs`, `/wal`, and
/// `/u/...` namespace.
const LEASE_KEY: &str = "_rust-api-writer-lease.json";

/// Default lease TTL. The value is long enough to survive a GC pause or a
/// slow S3 request. It is short enough that a node that crashed is replaced
/// soon.
pub const DEFAULT_LEASE_TTL_SECS: u64 = 60;

/// The lease record, as stored in the bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseRecord {
    /// Identity of the holder, in the form `{hostname}:{uuid}`.
    instance: String,
    /// Unix seconds at which this process first claimed the lease.
    claimed_at: i64,
    /// Unix seconds of the most recent renewal.
    renewed_at: i64,
    /// TTL that the holder operates under.
    ttl_secs: u64,
    /// Process ID of the holder. The field is here for an operator who
    /// reads the object by hand.
    pid: u32,
}

impl LeaseRecord {
    /// True while this record is still a live lease at `now`.
    ///
    /// The subtraction is unsigned on purpose. The comparison used to be
    /// `age < ttl_secs as i64`. A TTL at or above 2^63 casts to a
    /// *negative* `i64`. The test `age < negative` is then false for every
    /// live holder. Every second writer was told the lease was stale, and it
    /// took over. The only trace was a `warn!` that nobody reads.
    /// `[database].writer_lease_ttl_secs` is a `u64` that no check reads, so
    /// that value was one keystroke away.
    ///
    /// `checked_sub` yields `None` when the clock of the holder is behind
    /// ours. The function reads that case as live. A negative age from clock
    /// skew is the safe direction in which to be wrong here.
    fn is_live_at(&self, now: i64) -> bool {
        match now.checked_sub(self.renewed_at) {
            Some(age) => u64::try_from(age).is_ok_and(|age| age < self.ttl_secs),
            None => true,
        }
    }
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
        /// Identity that the holder recorded.
        instance: String,
        /// Process ID of the holder.
        pid: u32,
        /// Seconds since the holder last renewed.
        age: i64,
        /// TTL that the holder operates under.
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
/// Dropping the guard does *not* release the lease. An orderly release is an
/// explicit [`release`](Self::release), so that the order of the steps at
/// shutdown stays visible at the call site. A dropped lease goes stale after
/// its TTL. That is the crash path working as intended.
#[derive(Debug)]
pub struct WriterLease {
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    record: LeaseRecord,
    /// Set when a renewal finds that another instance holds the lease. The
    /// flag drives `/ready`, so the orchestrator drains this process and
    /// replaces it.
    lost: Arc<AtomicBool>,
}

impl WriterLease {
    /// Claims the lease for `db_prefix`, or explains who holds it.
    ///
    /// The function must be called *before* any
    /// [`build_s3_store`](crate::db::build_s3_store) for the same scope.
    /// Building a store takes an epoch, so a check after that would report
    /// that the function had already displaced the current holder.
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

        // Fast path. No process has ever written the record.
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

        // Another process holds the lease. A stale lease means a crash. A
        // fresh lease means the holder is alive.
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
        if held.record.is_live_at(now) {
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
        // The write is conditional on the exact record that we judged to be
        // stale. A racing take-over that arrived first changes the object. So
        // this write fails its precondition, and the loser reports the winner
        // instead of confirming a record that it replaced.
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

    /// Identity that the lease records, for logs and operator tools.
    pub fn instance(&self) -> &str {
        &self.record.instance
    }

    /// Flag that is set once another instance holds the lease.
    ///
    /// Share the `Arc` with the `/ready` check. Losing the lease means that
    /// this process must stop taking traffic, because a successor now owns
    /// the prefix.
    pub fn lost_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.lost)
    }

    /// Renews the lease. The function returns `false` once another instance
    /// holds the lease.
    ///
    /// The function reads before it writes, and that order is deliberate. A
    /// renewal that wrote first would replace the record of a successor. It
    /// would then read back its *own* write, and conclude that it still held
    /// the lease. That is the exact split brain that this module exists to
    /// prevent. The displaced process would keep taking the record back that
    /// it had already lost.
    ///
    /// A renewal that cannot confirm ownership also returns `false`. The
    /// causes are an S3 error and an unreadable record. Treating a
    /// temporary I/O error as "still fine" would let a node on a partition
    /// keep serving after its lease expired somewhere else.
    ///
    /// A successor can still get the record between the read and the write.
    /// That successor must have judged us to be stale, which means the TTL
    /// had passed. The remaining window is one round trip inside a TTL
    /// violation. It is not a condition that lasts.
    ///
    /// The write in this function stays unconditional, unlike the take-over
    /// in [`WriterLease::acquire`]. This process has already established that
    /// it is the holder. A compare-and-set on the renewal would only turn a
    /// harmless replace into a false "lease lost" the first time a successor
    /// took over.
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

    /// Releases the lease if this process still holds it. A replacement can
    /// then start at once, instead of waiting out the TTL.
    ///
    /// The function makes a best effort. A failure here costs the next start
    /// only `ttl_secs`, so the function logs the failure instead of passing
    /// it on.
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

/// Keeps a renewal task alive and releases the lease when the guard drops.
///
/// Dropping this guard ends the renewal loop and lets the release run.
/// *Nothing waits for the release.* A `Drop` implementation cannot await. The
/// task that it wakes only becomes runnable, and the runtime does not run
/// it. At process exit, the Tokio runtime drops tasks that it spawned
/// without polling them. So a shutdown that relies on the drop never deletes
/// the record, and the replacement waits out the whole TTL.
///
/// [`release`](Self::release) is the orderly path, and it is the path that
/// the server takes. Drop remains a backstop that tries but cannot promise.
/// It covers the early error exits that cannot await.
///
/// `#[must_use]`: dropping the guard early stops the renewal without a
/// guarantee. The release that it would have started is the part that does
/// not run.
#[must_use = "dropping the guard stops renewal and releases the lease on a best-effort basis"]
#[derive(Debug)]
pub struct LeaseGuard {
    /// Ends the shutdown future of the renewal task. The field is `None`
    /// once [`release`](Self::release) has taken it, so a released guard
    /// does not signal twice.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// The renewal task. It owns the lease and releases it on the way out.
    /// The field is `None` once [`release`](Self::release) has taken it.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LeaseGuard {
    /// Stops the renewal and waits for the lease to be released.
    ///
    /// This is what makes a rolling restart hand the prefix over without a
    /// wait for the TTL. It is also why the shutdown path in `main.rs`
    /// awaits the function instead of dropping the guard.
    ///
    /// [`RELEASE_TIMEOUT`] sets the bound. A release is a best effort, and it
    /// costs the next start only one TTL. So an object store that does not
    /// answer must not hold the process open forever. On a timeout, the
    /// function returns and the lease expires on its own. That is the crash
    /// path working as intended. The renewal task keeps running instead of
    /// being aborted. Its release is one `get` and one `delete`, so aborting
    /// it during the call gains nothing. The runtime drops the task at exit
    /// in any case.
    ///
    /// The function takes the guard, so the `Drop` backstop does not fire
    /// behind it and release the lease a second time.
    pub async fn release(mut self) {
        self.release_within(RELEASE_TIMEOUT).await
    }

    /// [`release`](Self::release), with `timeout` as the bound instead.
    pub async fn release_within(&mut self, timeout: std::time::Duration) {
        // Both fields are `Option`, so the function is idempotent. A guard
        // that is released twice signals once. The second call finds nothing
        // to await.
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
    /// Stops the renewal and lets the release run, without waiting for it.
    ///
    /// This function only does the best-effort half. The task is detached
    /// instead of awaited. At process exit, the runtime drops the task
    /// without polling it, and the record survives until the TTL expires.
    /// A caller that can await should call [`release`](Self::release)
    /// instead. The type docs explain why dropping is not the same.
    fn drop(&mut self) {
        self.shutdown.take();
    }
}

/// How long [`LeaseGuard::release`] waits for the record to be deleted
/// before it gives up and lets the TTL expire the lease.
///
/// A release is one `get` and one `delete` on the lease key, so a store that
/// works answers in much less than a second. The bound is generous because
/// its only purpose is to stop a stuck store from holding the process open.
/// The cost of reaching the bound is known and bounded: the replacement waits
/// one TTL.
pub const RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Starts a renewal task. The function returns the `/ready` flag and the
/// guard that keeps the task running.
///
/// The task releases the lease when the guard drops. It also releases the
/// lease when [`LeaseGuard::release`] tells it to. The task keeps running
/// after a lost lease instead of exiting. A later renewal that succeeds
/// cannot un-fence us. The flag must stay set, so that the process never
/// takes traffic again. Nothing useful is left for the task to do.
pub fn spawn_renewer(
    mut lease: WriterLease,
    interval: std::time::Duration,
) -> (Arc<AtomicBool>, LeaseGuard) {
    let lost = lease.lost_flag();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // the first tick completes at once
        // Pinned outside the loop. A `select!` would otherwise move the
        // shutdown future during the first pass.
        tokio::pin!(rx);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if !lease.renew().await {
                        tracing::error!("single-writer lease lost; /ready reports 503");
                    }
                }
                // The channel fires when the guard drops, because the
                // sender closed. It also fires on an explicit send.
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

/// Object path of the lease record for a prefix that is already trimmed.
fn lease_path(prefix: &str) -> ObjectPath {
    if prefix.is_empty() {
        ObjectPath::from(LEASE_KEY)
    } else {
        ObjectPath::from(format!("{prefix}/{LEASE_KEY}"))
    }
}

impl LeaseError {
    /// Builds the "another process holds it" error for a lease that was read.
    fn held(prefix: &str, record: &LeaseRecord, age: i64) -> Self {
        // The subtraction is unsigned, not `ttl as i64 - age`. A TTL at or
        // above 2^63 casts negative, so the old form gave a negative `wait`
        // for a lease that was nowhere near stale. The cast clamped it to 0.
        let wait = u64::try_from(age)
            .ok()
            .and_then(|age| record.ttl_secs.checked_sub(age))
            .unwrap_or(0);
        Self::Held {
            prefix: prefix.to_string(),
            instance: record.instance.clone(),
            pid: record.pid,
            age,
            ttl: record.ttl_secs,
            wait: i64::try_from(wait).unwrap_or(i64::MAX),
        }
    }
}

/// A lease record that was read from the store, with the version that the
/// read observed.
///
/// The version is what makes a take-over a compare-and-set. The version is
/// the token that `PutMode::Update` checks. So the write can only land if
/// nobody changed the record between this read and that write.
#[derive(Debug)]
struct Fetched {
    record: LeaseRecord,
    version: UpdateVersion,
}

/// Reads the lease record. The function maps a decode failure to
/// [`LeaseError::Corrupt`] instead of a general I/O error. A record that
/// cannot be parsed must not look like a temporary error, because the safe
/// response to that record is to refuse.
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

/// How a write of a record may land.
enum WriteMode {
    /// Only if the object does not exist.
    Create,
    /// Replaces whatever is there.
    Overwrite,
    /// Replaces only the exact version that was observed.
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
    /// This is the case that the whole module exists for. Without this case,
    /// a second replica starts cleanly and the two diverge with no report.
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
        // The message must be useful to an operator who reads the logs.
        let text = err.to_string();
        assert!(text.contains(prefix), "unhelpful message: {text}");
        assert!(text.contains(first.instance()), "unhelpful message: {text}");
    }

    /// A TTL that is too large for the comparison must not make a live lease
    /// look stale.
    ///
    /// The check was `age < ttl_secs as i64`. A TTL at or above 2^63 casts
    /// to a negative `i64`, so the comparison is false for every live
    /// holder. The second writer is told the lease expired, and it takes the
    /// prefix from a running server. The only trace is a `warn!`.
    /// `[database].writer_lease_ttl_secs` is a `u64`, so that value was
    /// reachable.
    ///
    /// The test claims with a huge TTL instead of going back in time. The
    /// record is milliseconds old. Under the old comparison, it read as
    /// stale, and the take-over would have succeeded. The lease must refuse.
    #[tokio::test]
    async fn a_lease_with_a_huge_ttl_is_still_live() {
        let store = mem();
        let prefix = "lease-test-huge-ttl";
        const HUGE: u64 = i64::MAX as u64 + 1;
        let first = WriterLease::acquire(Arc::clone(&store), prefix, HUGE)
            .await
            .expect("first writer claims");

        let err = WriterLease::acquire(Arc::clone(&store), prefix, HUGE)
            .await
            .expect_err("an unexpired lease must not be takeable at any TTL");
        let LeaseError::Held { instance, wait, .. } = &err else {
            panic!("expected Held, got {err:?}");
        };
        assert_eq!(instance, first.instance());
        // The `wait` value in the operator message came from the same
        // cast, and it came out as 0 for a lease with centuries left. So the
        // test asserts it here. A number that says "no wait needed" on a
        // live lease is as misleading as the comparison itself.
        assert!(
            *wait > 0,
            "the error must still say how long to wait: {err}",
        );
    }

    /// A holder that stops renewing, such as after a crash, must not block
    /// recovery. After the TTL passes, the next start takes over, and it
    /// says which holder it displaced.
    #[tokio::test]
    async fn expired_lease_is_taken_over() {
        let store = mem();
        let prefix = "lease-test-stale";
        let first = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("first writer claims");

        // Go back in time in the record instead of sleeping. This is what a
        // holder that crashed looks like on disk.
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

        // The record on disk now holds the identity of the new holder.
        let current: LeaseRecord =
            serde_json::from_slice(&store.get(&path).await.unwrap().bytes().await.unwrap())
                .unwrap();
        assert_eq!(current.instance, second.instance());
    }

    /// Two processes must not both acquire the *same* stale lease.
    ///
    /// A holder that crashed together with two replicas that start at the
    /// same time is the ordinary case. A node failure looks that way. A
    /// rolling restart looks that way. The take-over used to write and then
    /// check. Both replicas read the stale record. Both replaced it without
    /// a condition. The check of each replica then came after its *own*
    /// write, so both returned `Ok`. The check caught only the order of
    /// operations that cannot give two winners. The comment above the check
    /// claimed that it caught the racing process.
    ///
    /// The damage was bounded. The second `build_s3_store` fences the first
    /// through the epoch. The next `renew()` of the first finds out within
    /// one tick, and it sets `lost`. For up to `ttl/3`, though, both are in
    /// rotation and one returns 500 for every write.
    ///
    /// `RaceStore` performs the replace of a competing writer in the gap
    /// between the read and the write. That gap is the exact one that a real
    /// second process creates. With the take-over as a compare-and-set on
    /// the observed version, the write fails its precondition, and the loser
    /// is told who won. With the unconditional replace, the write lands, and
    /// both processes believe that they hold the prefix.
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

    /// Identity that the racing winner in the test above claims to have.
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

    /// A record that looks like the record of a holder that crashed. The record
    /// is present but past its TTL. That is the condition that a take-over
    /// requires.
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

    /// An [`ObjectStore`] that runs a competing write in the gap between the
    /// read of the caller and its write.
    ///
    /// That order of operations is the whole point, and timing cannot create
    /// it. `acquire` reads the record, decides that it is stale, then writes.
    /// A real second process lands its write in that gap. This store injects
    /// one write there, in a fixed way. So the assertion tests the
    /// compare-and-set. It does not test a race that may or may not end this
    /// way in one run.
    #[derive(Debug)]
    struct RaceStore {
        inner: Arc<dyn ObjectStore>,
        before_put: RaceHook,
    }

    /// A competing write in a box. The function is a new type so that it can
    /// carry a [`Debug`] implementation. The store that it feeds needs that
    /// implementation. A boxed future does not have one.
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
            // Only the conditional write has a competitor. The initial
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
            return Err(object_store::Error::NotSupported {
                source: "the lease never uses multipart".to_string().into(),
            });
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

    /// The displaced writer must discover the loss on its next renewal, and it must set
    /// itself unready. That is the half that makes this a lease instead of
    /// an assertion at startup.
    #[tokio::test]
    async fn renewal_detects_takeover_and_latches_unready() {
        let store = mem();
        let prefix = "lease-test-renew";
        let mut first = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("first writer claims");
        let lost = first.lost_flag();
        assert!(!lost.load(Ordering::Relaxed));

        // A successor goes back in time in the record, past its TTL, and
        // then takes over.
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
        // The flag stays set. A later renewal must not "recover" and let
        // traffic in again.
        assert!(!first.renew().await);
    }

    /// Renewal keeps a live lease alive. So a process that runs for a long
    /// time is never displaced by a peer that saw a stale record.
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

    /// A displaced process must not replace the record on its way out.
    /// This is the failure that the read before write in `renew` prevents. If
    /// the write came first, the loser would replace the lease of the winner
    /// on every tick. It would then read back its own write, and conclude
    /// that it still held the lease.
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

    /// An orderly release hands the prefix over without a wait for the TTL. That
    /// is what makes a rolling restart fast.
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

    /// A shutdown of the guard must delete the lease record before the caller
    /// returns.
    ///
    /// The whole orderly release path rests on this property, and the
    /// property was not true. `serve` held the guard in a plain
    /// `_lease_guard` binding. The function relied on its `Drop` to run
    /// `lease.release()`. Dropping the `oneshot::Sender` only *made* the
    /// detached task runnable. `serve` then returned to `#[tokio::main]
    /// main`, which returned and dropped the runtime. Tokio drops tasks that
    /// it spawned without polling them. A `Drop` implementation cannot
    /// compensate, because it cannot await.
    ///
    /// So `DELETE _rust-api-writer-lease.json` never ran on *any* graceful
    /// shutdown. A replacement pod read the record that was still there,
    /// found `age < ttl_secs`, and got `LeaseError::Held`. It passed the
    /// error out of `serve`, and it entered CrashLoopBackOff until the TTL
    /// expired. That defeated the handover on a rolling restart, which is
    /// the one thing that the lease exists to provide.
    ///
    /// Awaiting the `release` of the guard is what makes the delete happen.
    /// So the test awaits it, and it checks that the record is gone when the
    /// function returns. The test was confirmed to fail when the guard drops
    /// instead. The record survives in that case, and the claim below returns
    /// `Held`.
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
        // The practical result. The prefix can be claimed at once, with
        // no wait for the TTL.
        let next = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("an orderly shutdown must hand the prefix over immediately");
        assert_ne!(next.instance(), instance);
    }

    /// The renewal task must stop when the guard stops it.
    ///
    /// A renewal that kept running after the shutdown would replace the
    /// record of the successor. It would then read back its own write, and
    /// conclude that it still held the lease. That is the split brain that
    /// the read before write in `renew` prevents. The same split brain is
    /// also reachable from this direction.
    #[tokio::test]
    async fn releasing_the_guard_stops_renewal() {
        let store = mem();
        let prefix = "lease-test-stop-renew";
        let lease = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("claims");
        let (_lost, mut guard) = spawn_renewer(lease, std::time::Duration::from_millis(10));
        let path = lease_path(prefix);

        // `release_within` awaits the task, so a stop is visible once it
        // returns. Nothing else can write the record after that.
        guard
            .release_within(std::time::Duration::from_secs(5))
            .await;

        // A successor takes the prefix.
        let next = WriterLease::acquire(Arc::clone(&store), prefix, TTL)
            .await
            .expect("released lease is claimable");

        // Many renewal intervals pass, with time to spare. If the task
        // still ran, it would have replaced the record of the successor.
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

    /// A release must not run twice when the guard is released twice.
    ///
    /// `release` takes the guard. `release_within` takes `&mut self`, so a
    /// test can set the order of the shutdown steps directly. The second
    /// call finds that the task has already been taken, and it does nothing.
    /// It does not await a `JoinHandle` that it no longer owns.
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

        // The call must not hang or panic. There is nothing left to await.
        guard
            .release_within(std::time::Duration::from_secs(5))
            .await;
    }

    /// An object store that does not answer must not hold the shutdown open
    /// forever.
    ///
    /// The release is a best effort. A failure to delete the record costs
    /// the next start one TTL. Holding the shutdown costs a rolling restart
    /// in full. On an orchestrator with a termination grace period, it costs
    /// a SIGKILL. So the function sets a bound, and the test exercises that
    /// bound. `StuckStore` never answers `get`. That is what an
    /// unreachable S3 looks like from here.
    #[tokio::test]
    async fn a_stalled_release_abandons_rather_than_blocking_shutdown() {
        let prefix = "lease-test-stalled-release";
        let now = chrono::Utc::now().timestamp();
        let record = LeaseRecord {
            instance: "holder-1".to_string(),
            claimed_at: now,
            renewed_at: now,
            ttl_secs: TTL,
            pid: std::process::id(),
        };
        // Build the lease directly instead of claiming it. `acquire` needs a
        // store that answers, and the whole point of the test is a store
        // that does not answer.
        let lease = WriterLease::new(Arc::new(StuckStore), lease_path(prefix), record);
        let (_lost, mut guard) = spawn_renewer(lease, std::time::Duration::from_secs(3600));

        // The release reads the record before it deletes it, so a store
        // that stops on `get` stops the whole release.
        let started = std::time::Instant::now();
        guard
            .release_within(std::time::Duration::from_millis(100))
            .await;

        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the release was not bounded; shutdown would hang on the store",
        );
        // The wait is bounded, not skipped. The wait really ran, but it
        // did not run forever. Without the `timeout`, the future never
        // completes at all. The assertion below cannot express that
        // property. This assertion can.
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(50),
            "the release gave up before even trying; the bound is a no-op",
        );
    }

    /// A store that never answers, so that the release of a shutdown cannot
    /// complete.
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

    /// A release must not delete a lease that another process now owns. A
    /// displaced process must not un-fence its own successor on the way out.
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

    /// A record that cannot be parsed must be refused, never guessed at. A
    /// silent replace of that record is the exact split brain that this
    /// module prevents.
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

    /// The record must sit outside every oxkv prefix. Otherwise it would
    /// collide with transactional keys, and a scan of the prefix would
    /// delete it.
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
    /// The lease wrapper does not support multipart uploads. It must report
    /// that as an error instead of panicking.
    #[tokio::test]
    async fn race_store_put_multipart_opts_returns_not_supported() {
        let store = mem();
        let racing = RaceStore {
            inner: Arc::clone(&store),
            before_put: RaceHook::new(|| Box::pin(async {})),
        };
        let racing: Arc<dyn ObjectStore> = Arc::new(racing);
        let path = ObjectPath::from("lease-test-multipart");
        let err = racing
            .put_multipart_opts(&path, object_store::PutMultipartOptions::default())
            .await
            .expect_err("multipart uploads are not supported by the lease wrapper");
        assert!(matches!(err, object_store::Error::NotSupported { .. }));
    }
}
