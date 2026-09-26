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

use object_store::{ObjectStore, PutMode, PutPayload, path::Path as ObjectPath};
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
        if write_record(&*store, &path, &record, true).await.is_ok() {
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
        let age = now - held.renewed_at;
        if age < held.ttl_secs as i64 {
            return Err(LeaseError::held(&prefix, &held, age));
        }

        tracing::warn!(
            prefix = %prefix,
            previous_instance = %held.instance,
            previous_pid = held.pid,
            stale_for_secs = age,
            ttl_secs = held.ttl_secs,
            "taking over an expired single-writer lease (previous holder stopped renewing)"
        );
        write_record(&*store, &path, &record, false)
            .await
            .map_err(|source| LeaseError::Io {
                prefix: prefix.clone(),
                source,
            })?;
        // The overwrite is not atomic against a concurrent take-over, so
        // confirm the record is actually ours. If a racing process won
        // instead, back out rather than run two writers.
        match fetch(&*store, &path, &prefix).await? {
            Some(current) if current.instance == record.instance => {}
            Some(current) => return Err(LeaseError::held(&prefix, &current, 0)),
            None => {
                return Err(LeaseError::Io {
                    prefix,
                    source: object_store::Error::NotFound {
                        path: path.to_string(),
                        source: "lease vanished after take-over".into(),
                    },
                });
            }
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
    /// only one that already considered us stale (past the TTL), and its
    /// own confirm-read then sees whichever write landed last. The
    /// residual window is one round trip inside a TTL violation, not a
    /// standing condition.
    pub async fn renew(&mut self) -> bool {
        if self.lost.load(Ordering::Relaxed) {
            return false;
        }
        match fetch(&*self.store, &self.path, "").await {
            Ok(Some(current)) if current.instance != self.record.instance => {
                tracing::error!(
                    instance = %self.record.instance,
                    new_holder = %current.instance,
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
        if write_record(&*self.store, &self.path, &self.record, false)
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
            Ok(Some(current)) if current.instance != self.record.instance => {
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
/// Dropping this guard ends the renewal loop and releases the lease, so a
/// replacement process can claim the prefix immediately instead of waiting
/// out the TTL. The happy path for a rolling restart.
///
/// `#[must_use]`: dropping it early silently disables both renewal and
/// release, which is the opposite of what a caller usually wants.
#[must_use = "dropping the guard stops renewal and releases the lease"]
#[derive(Debug)]
pub struct LeaseGuard {
    /// Dropping the sender completes the renewal task's shutdown future.
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// Spawns a renewal task, returning the `/ready` flag and the guard that
/// keeps it running.
///
/// The task releases the lease when the guard is dropped. It keeps ticking
/// after a lost lease rather than exiting: a later successful renewal
/// cannot un-fence us, and the flag must stay set so the process is never
/// re-admitted to traffic, so there is nothing useful left to do.
pub fn spawn_renewer(
    mut lease: WriterLease,
    interval: std::time::Duration,
) -> (Arc<AtomicBool>, LeaseGuard) {
    let lost = lease.lost_flag();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
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
    (lost, LeaseGuard { _shutdown: tx })
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

/// Reads the lease record, mapping a decode failure to [`LeaseError::Corrupt`]
/// rather than a generic I/O error: an unparseable record must not look
/// like a transient blip, because the safe response to it is to refuse.
async fn fetch(
    store: &dyn ObjectStore,
    path: &ObjectPath,
    prefix: &str,
) -> Result<Option<LeaseRecord>, LeaseError> {
    let bytes = match store.get(path).await {
        Ok(out) => out.bytes().await.map_err(|source| LeaseError::Io {
            prefix: prefix.to_string(),
            source,
        })?,
        Err(object_store::Error::NotFound { .. }) => return Ok(None),
        Err(source) => {
            return Err(LeaseError::Io {
                prefix: prefix.to_string(),
                source,
            });
        }
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| LeaseError::Corrupt {
            prefix: prefix.to_string(),
            detail: e.to_string(),
        })
}

async fn write_record(
    store: &dyn ObjectStore,
    path: &ObjectPath,
    record: &LeaseRecord,
    create_only: bool,
) -> Result<(), object_store::Error> {
    let bytes = serde_json::to_vec(record).map_err(|e| object_store::Error::Generic {
        store: "writer-lease",
        source: Box::new(e),
    })?;
    let mode = if create_only {
        PutMode::Create
    } else {
        PutMode::Overwrite
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
        write_record(&*store, &path, &stale, false).await.unwrap();

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
        write_record(&*store, &path, &stale, false).await.unwrap();
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
        write_record(&*store, &path, &stale, false).await.unwrap();
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
        write_record(&*store, &path, &stale, false).await.unwrap();
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
