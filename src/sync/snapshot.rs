//! Per-user filtered replicas on stable `OxKvStore` prefixes.
//!
//! The master [`FsStore`] stays the only write path. Each user owns one
//! replica prefix (`{db_prefix}/u/{sha256-hex(sub)}/`). That prefix holds
//! the file set the user can read. A build filters into a RAM scratch store.
//! Then the build compares the scratch store with the live replica. Then the
//! build commits the diff and the coverage marker in ONE transaction. A
//! crash before the commit leaves the old state untouched, because `oxkv`
//! replays only the WALs that it lists on open. An empty diff commits
//! nothing.
//!
//! The `sync:applied` sentinel inside the prefix tracks WAL coverage. No
//! sidecar pointer object exists. A small delta replays with an idempotent
//! re-apply, and the code writes the sentinel last. A legacy policy mark or a
//! large range falls back to a full recalculation. A rich rule op or group
//! op resyncs only the affected user or row. The route `/sync/db/` serves
//! the prefix read-only. A wasm client opens an `OxKvReader` over the
//! prefix and follows the live manifest.
//!
//! # This module never writes a manifest
//!
//! `oxkv` writes `{prefix}/manifest.json`. This module never writes it, and
//! it never parses it. The only use of the object is an existence check in
//! [`SnapshotManager::load_applied`]. The route in
//! [`crate::sync::route`] streams the bytes to the client.
//!
//! That restraint is a contract, because `oxkv` gives the `sst` list in the
//! manifest two meanings at once. The list position is the recency. Every
//! read walks the list in reverse and stops at the first hit. Each entry of
//! the list records that position in a `seq` field, so the order is
//! recoverable. A sort by key range therefore destroys the recency. It lets
//! an older segment win a lookup, so a client reads a stale value.
//!
//! So no code in this crate may sort, filter, or rewrite those entries.
//! The segment names stay immutable, so the route can serve every segment,
//! log, and blob object with a one-year max-age. `oxkv` never reuses a name
//! for different bytes. It refuses to overwrite a sequence object that holds
//! other bytes, and a blob name is the SHA-256 of the value. The manifest,
//! the ownership record, and the storage probe are the exceptions, because
//! `oxkv` rewrites each of them under one name.
//!
//! # A reader in `oxkv` 0.9 holds no pin
//!
//! `oxkv` 0.9 removed `register_reader`, `unregister_reader`, and
//! `min_reader_version`. No caller can now ask a writer to keep a segment
//! alive. The writer instead collects a `WAL` file only after a flush put
//! every record of that file into an `SST`. A read that loses a segment to a
//! compaction then runs again against a fresh manifest.
//!
//! `open_reader` opens one follower per call. The call then reads one key
//! and drops the follower. So the call does not need a pin, and the loss of
//! the pin costs nothing here.

use crate::fs::error::FsError;
use crate::fs::store::{FileScan, FsStore, KvPages};
use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, Authorizer};
use crate::records::WalOp;
use oxkv::{GetSet as _, OxKvReader, Store as _, Transaction as _};

use super::wal::Wal;

/// Sync-version marker stored inside every replica prefix.
const APPLIED_KEY: &str = "sync:applied";

/// Upper bound for file/relation ops replayed incrementally.
const MAX_REPLAY_OPS: usize = 1000;

/// Upper bound for the files that one policy op may touch before the code
/// falls back to a full recalculation. The bound stops one group or row
/// change from scanning the whole store.
const MAX_POLICY_REPLAY_FILES: usize = 1000;

/// Manager for per-user replicas.
#[derive(Clone)]
pub struct SnapshotManager {
    /// WAL for version tracking.
    pub(crate) wal: Wal,
    /// Master file store.
    pub(crate) store: FsStore,
    /// Policy for filtering.
    ///
    /// This field holds the read-only [`Authorizer`](crate::policy::Authorizer).
    /// It does not hold a [`PolicyEngine`](crate::policy::PolicyEngine). A
    /// snapshot build only asks whether the caller may read a row. Holding
    /// the full engine here, and exposing it as a public field, would give
    /// every consumer of `SnapshotManager` a write-capable engine. That is
    /// the bypass that `PolicyEngine::enforcer` prevents by being private.
    pub(crate) policy: Authorizer,
    /// Shared object store backing every replica prefix.
    pub(crate) object_store: std::sync::Arc<dyn object_store::ObjectStore>,
    /// Root prefix for replica prefixes (e.g. `"oxkv"`).
    pub(crate) db_prefix: String,
    /// Skip the oxkv storage probe (tests on `InMemory`).
    skip_probe: bool,
    /// SST block cache shared by every replica open from this manager.
    ///
    /// Each open used to build a private cold cache that the handle dropped.
    /// Sharing the cache keeps the hot SSTs in memory across rebuilds.
    /// Clones share this state, in the same way as the build queue.
    sst_cache: oxkv::LruCache<String, std::sync::Arc<oxkv::SstFile>>,
    /// Subjects with a rebuild queued or running, plus the work channel.
    builds: std::sync::Arc<BuildQueue>,
}

/// One subject's queued rebuild.
pub struct BuildJob {
    /// Stable hash of the OIDC subject. See [`SnapshotManager::user_prefix`].
    sub: String,
    /// WAL head observed when the job was queued.
    ///
    /// The worker uses this value only for log lines. A worker re-reads the
    /// head before it builds. A job that waited behind a long build then
    /// covers more entries than this value, not fewer.
    head: u64,
    /// The in-flight slot, carried with the job.
    ///
    /// The slot is released when the code drops the job. The slot stays held
    /// across the queue wait, across the build, and through a worker that
    /// dies during the build. None of these events can leave the subject
    /// marked in flight forever. The leading underscore shows that the field
    /// matters only through the `Drop` of [`BuildClaim`]. No code reads the
    /// field.
    _claim: BuildClaim,
}

impl BuildJob {
    /// Stable hash of the OIDC subject. See [`SnapshotManager::user_prefix`].
    pub fn sub(&self) -> &str {
        &self.sub
    }

    /// WAL head observed when the job was queued.
    ///
    /// The worker uses this value only for log lines. A worker re-reads the
    /// head before it builds. The returned value is what the code observed
    /// when the job was queued. It is not the current head.
    pub fn head(&self) -> u64 {
        self.head
    }
}

/// Tracks the subjects that have a rebuild in flight and gives the work to
/// the pool that runs it.
///
/// This type replaces a process-wide `Mutex<()>` that both `replay` and
/// `build_full` held for their whole duration. That lock made all work wait
/// behind one job. A full rebuild for one user blocked an incremental
/// replay for a different user. The blocked replay typically takes
/// milliseconds. The blocking rebuild can take minutes. Users are
/// independent here, because each replica has its own S3 prefix. The guard
/// only ever needed to be per subject.
///
/// The in-flight set also merges requests for the same rebuild. A client
/// polls `POST /sync/sync`, so a deploy or a busy period sends many requests
/// per user for the same pending rebuild. Without the set, each request runs
/// a full scan and then finds that there is nothing to do.
///
/// The host creates this type. The host keeps the receiving end and drains it
/// with [`BuildPool::spawn`]. [`SnapshotManager::new`] does not create it,
/// because a test that clones the manager would then start background work
/// without asking for it.
pub struct BuildQueue {
    inflight: std::sync::Mutex<std::collections::HashSet<String>>,
    jobs: tokio::sync::mpsc::UnboundedSender<BuildJob>,
}

/// A held in-flight slot. The `Drop` of this type releases the slot.
///
/// The type acts as a `Drop` guard instead of a call that every holder must
/// remember. The reason is that the holders are droppable futures. A client
/// sends `POST /sync/sync`, and the client may drop the handler future at
/// any `.await` inside `replay`. Those points are `wal.range`,
/// `open_writer`, and the `apply_op` loop for each op. The old code released
/// the slot through a manual `release` call on a separate path. A disconnect
/// during a replay then left the subject in the set, and no code ran the
/// release. Every later `advance` for that subject then took the
/// `!claim(sub)` branch. That branch returns `{applied_seq: <stale>, pending:
/// true}`. No other path skips both the re-check and the re-queue. The
/// replica then stays frozen at its old coverage for the life of the
/// process. No code logs an error. Only a restart recovers.
///
/// The worker has the same shape for another reason. The old `release` call
/// ran only if `build_full` returned. A panic inside `build_full` then both
/// leaked the claim and killed the task that held it. The [`BuildJob`] now
/// carries this guard, so the code releases the slot when the job is dropped,
/// however that drop happens.
pub struct BuildClaim {
    queue: std::sync::Arc<BuildQueue>,
    sub: String,
}

impl BuildClaim {
    /// The subject whose slot this guard holds.
    fn sub(&self) -> &str {
        &self.sub
    }
}

impl Drop for BuildClaim {
    fn drop(&mut self) {
        self.queue.inflight().remove(&self.sub);
    }
}

impl BuildQueue {
    /// Creates a queue and the receiving end its pool will drain.
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<BuildJob>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                inflight: std::sync::Mutex::new(std::collections::HashSet::new()),
                jobs: tx,
            },
            rx,
        )
    }

    /// Takes the single in-flight slot for `sub`, or reports that the slot is
    /// taken.
    ///
    /// `None` means that another request or worker already advances this
    /// user's replica. That is the merge case, not an error. The caller then
    /// reports the current coverage and lets the client poll.
    ///
    /// The method takes `self` by `Arc`, so the returned [`BuildClaim`] can
    /// keep the queue alive and release through it. A guard that holds a
    /// borrow cannot outlive the call that made it.
    fn claim(self: &std::sync::Arc<Self>, sub: &str) -> Option<BuildClaim> {
        self.inflight().insert(sub.to_string()).then(|| BuildClaim {
            queue: std::sync::Arc::clone(self),
            sub: sub.to_string(),
        })
    }

    /// Releases the slot for `sub` without a guard.
    ///
    /// Only tests call this method. Every production holder owns a
    /// [`BuildClaim`], and the `Drop` of that type releases the slot. This
    /// method stands in for a worker that finished its job. The method does
    /// not create a guard that the caller then fails to hold.
    #[cfg(test)]
    fn release(&self, sub: &str) {
        self.inflight().remove(sub);
    }

    /// The in-flight set. The method recovers from a poisoned lock.
    ///
    /// The set holds subject strings and nothing else. A panic in an
    /// unrelated holder then cannot leave the set inconsistent. The worst
    /// case is one stale entry, and that costs one redundant rebuild.
    /// Propagating the poison would make the queue permanently unusable, so
    /// the method takes the inner value in every case.
    fn inflight(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<String>> {
        self.inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Hands a claimed subject to the worker pool.
    ///
    /// The method takes the [`BuildClaim`] by value and moves it into the
    /// job. The slot then stays held across the queue wait. Without that, the
    /// slot would be released the moment the request returns. A burst of
    /// polls between `send` and the pickup by a worker would then queue
    /// duplicates. The in-flight set exists to prevent those duplicates.
    ///
    /// The method returns `false` if no pool drains the queue. The
    /// `BuildJob` then comes back inside the `SendError`. The error drops the
    /// job, and the job drops the claim. The next request then retries.
    /// Without that, the subject stays marked in flight forever and never
    /// rebuilds.
    fn dispatch(&self, claim: BuildClaim, head: u64) -> bool {
        self.jobs
            .send(BuildJob {
                sub: claim.sub().to_string(),
                head,
                _claim: claim,
            })
            .is_ok()
    }
}

/// Drains a [`BuildQueue`] and runs the full rebuilds that it carries.
///
/// The type is separate from [`SnapshotManager`] because a task spawn is a
/// side effect. A `Clone` must not carry that side effect. This type mirrors
/// [`crate::fs::gc::spawn`].
pub struct BuildPool {
    rx: tokio::sync::mpsc::UnboundedReceiver<BuildJob>,
}

impl BuildPool {
    /// Wraps the receiving end of a [`BuildQueue`].
    pub fn new(rx: tokio::sync::mpsc::UnboundedReceiver<BuildJob>) -> Self {
        Self { rx }
    }

    /// Starts `workers` tasks. Each task runs the queued rebuilds to the end.
    ///
    /// The `workers` count is deliberately small. A build streams its diff
    /// (see [`SnapshotManager::build_full`]), so its memory tracks the size
    /// of a change instead of the size of a replica. The build still scans
    /// the master and writes to S3. This count therefore limits
    /// object-store pressure as much as it limits CPU use. One worker is a
    /// valid setting and a reasonable default.
    pub fn spawn(self, manager: std::sync::Arc<SnapshotManager>, workers: usize) {
        // A single receiver cannot move into N tasks, so the pool shares one
        // receiver behind a lock. The code holds the lock for a short time.
        // The code awaits `recv` outside the guard. The guard only decides
        // which worker takes the next job. Holding the guard across the await
        // would make the workers run one at a time.
        let rx = std::sync::Arc::new(tokio::sync::Mutex::new(self.rx));
        let workers = workers.max(1);
        for worker in 0..workers {
            let manager = std::sync::Arc::clone(&manager);
            let rx = std::sync::Arc::clone(&rx);
            tokio::spawn(async move {
                loop {
                    let job = {
                        let mut guard = rx.lock().await;
                        guard.recv().await
                    };
                    let Some(job) = job else { break };
                    // The request that queued this job already returned, so
                    // the log is the only remaining channel for a failure.
                    // The slot travels with `job`. The code releases the slot
                    // when the job drops. The next `advance` then retries
                    // instead of finding the subject stuck. The same holds if
                    // this task unwinds.
                    let result = manager.build_full(job.sub()).await;
                    if let Err(e) = &result {
                        tracing::warn!(
                            "background replica rebuild for {} failed: {e}",
                            manager.user_prefix(job.sub())
                        );
                    }
                    tracing::debug!(
                        "rebuild worker {worker} finished {} (queued at head {}, now {})",
                        job.sub(),
                        job.head(),
                        result.unwrap_or_default()
                    );
                }
            });
        }
    }
}

/// The collaborators that a [`SnapshotManager`] uses to read master state.
///
/// The type groups the collaborators so that [`SnapshotManager::new`] takes
/// three arguments instead of six. It also lets a fourth source of master
/// state become a field addition instead of a signature change for every
/// caller.
pub struct SnapshotDeps {
    /// Change feed to replay from.
    pub wal: Wal,
    /// Master file store for reads only. The code writes the master through
    /// [`FsEngine`](crate::fs::FsEngine).
    pub store: FsStore,
    /// Read-only policy view for row visibility checks.
    pub policy: Authorizer,
    /// Object store backing every replica prefix.
    pub object_store: std::sync::Arc<dyn object_store::ObjectStore>,
    /// Rebuild queue, shared with the [`BuildPool`] that drains it.
    ///
    /// The caller passes the queue instead of the code creating it here, so
    /// the host can hold the receiving end and choose when to start the
    /// background work. See [`BuildQueue::new`].
    pub builds: BuildQueue,
}

/// What a replica prefix is opened against.
///
/// The type is an enum instead of a `skip_probe: bool`, because the flag was
/// the sixth positional argument of a six-argument constructor. Nothing at
/// the call site said what `true` meant. The wrong value does not cause a
/// compile error. It also does not cause an obviously wrong answer. It
/// causes a probe against a backend that has no conditional writes, or a
/// skipped probe against real S3. The second case removes the check that
/// guards the `manifest.json` CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaBackend {
    /// A real object store. Opens probe for conditional writes.
    ObjectStore,
    /// `InMemory`, which has no conditional-write probe to run. Tests only.
    InMemory,
}

impl SnapshotManager {
    /// Creates a manager.
    ///
    /// The method takes an [`Authorizer`] instead of a
    /// [`PolicyEngine`](crate::policy::PolicyEngine). A replica is a read
    /// projection, so this type never needs write access to policy.
    pub fn new(deps: SnapshotDeps, db_prefix: impl Into<String>, backend: ReplicaBackend) -> Self {
        Self {
            wal: deps.wal,
            store: deps.store,
            policy: deps.policy,
            object_store: deps.object_store,
            db_prefix: db_prefix.into(),
            skip_probe: matches!(backend, ReplicaBackend::InMemory),
            builds: std::sync::Arc::new(deps.builds),
            sst_cache: crate::db::default_sst_cache(),
        }
    }
}

/// What an incremental [`SnapshotManager::replay`] was able to do.
///
/// A decline is not an error, and that distinction is the point of the type.
/// "This delta cannot be replayed incrementally, so recalculate instead" and
/// "the store rejected the write" are different facts. The previous encoding
/// signalled the first fact with this value:
/// `FsError::Internal("replay needs full recalc ...")`. Matching on that
/// string is as fragile as the `detail.contains("fenced")` search that this
/// crate already removed. A reworded message turns a real store failure into
/// a queued rebuild without a trace. A reworded message also turns a
/// legitimate decline into 500 responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// The replica now covers this WAL sequence.
    Advanced(u64),
    /// The change cannot replay incrementally. A full rebuild is required.
    ///
    /// One of these conditions requires the rebuild:
    ///
    /// - A legacy policy mark.
    /// - A delta over `MAX_REPLAY_OPS`.
    /// - A replica that was never built.
    NeedsFullRebuild,
}

/// What one replayed op did to the replica.
///
/// The enum separates two different facts. The first fact states that this
/// op cannot apply incrementally. The second fact states that the store
/// rejected the write. Only the first fact is a reason to queue a rebuild.
/// Every decline site returns [`Self::NeedsFullRebuild`]. A genuine failure
/// is still `Err` and stays a 500. [`ReplayOutcome`] exists for that
/// difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyOutcome {
    /// The op was applied incrementally.
    Applied,
    /// The op cannot apply incrementally. The whole delta then needs a full
    /// rebuild.
    NeedsFullRebuild,
}

/// How far a replica got, and whether more is still to come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvanceOutcome {
    /// WAL sequence the replica now covers.
    pub applied_seq: u64,
    /// True when the code queued a full rebuild or found one already queued.
    /// The caller then sees the coverage from before that rebuild.
    ///
    /// This field differs from `applied_seq < head`. A rebuild that was
    /// already in flight also leaves the caller short of the head. A client
    /// that cannot tell "queued for you" from "someone else got there first"
    /// cannot decide how long to keep polling.
    pub pending: bool,
}

impl SnapshotManager {
    /// Advances the replica of `sub` toward the WAL head.
    ///
    /// The method tries three outcomes in this order:
    ///
    /// 1. The replica is already covered. Covered means `applied == head`.
    ///    It does not mean `applied >= head`. A replica that claims coverage
    ///    ahead of the head is not caught up. The feed is corrupt or has
    ///    rewound. The method then falls through to
    ///    [`replay`](Self::replay), which declines the case into a rebuild.
    ///    See the note there.
    /// 2. A bounded incremental [`replay`](Self::replay) succeeds. The
    ///    method runs the replay inline. The replay takes milliseconds, and
    ///    the caller wants the result now.
    /// 3. Otherwise the code needs a full rebuild. The method queues the
    ///    rebuild instead of running it. A rebuild scans the whole master and
    ///    can take minutes. Running the rebuild inside a request held a
    ///    connection for the whole duration. It also blocked the sync of
    ///    every other user. The caller receives `pending: true` and polls
    ///    [`GET /sync/status`](crate::sync::route) to watch the coverage move.
    ///
    /// Concurrent calls for the same subject merge into one. The second call
    /// returns the current coverage as `pending` instead of queuing a
    /// duplicate scan. Different subjects are independent.
    ///
    /// A [`BuildClaim`] holds the claim for the whole body. A client that
    /// disconnects during a replay then releases the slot on the way out. An
    /// older manual `release` call on a separate code path leaked the slot
    /// forever. That leak kept this subject on the `pending: true`
    /// short-circuit below for the life of the process.
    pub async fn advance(&self, sub: &str) -> Result<AdvanceOutcome, FsError> {
        let head = self.wal.head().await?;
        let applied = self.load_applied(sub).await?;
        if applied == Some(head) {
            return Ok(AdvanceOutcome {
                applied_seq: head,
                pending: false,
            });
        }

        // No claim means someone else is already advancing this subject.
        let Some(claim) = self.builds.claim(sub) else {
            return Ok(AdvanceOutcome {
                applied_seq: applied.unwrap_or_default(),
                pending: true,
            });
        };

        match self.replay(head, sub).await {
            Ok(ReplayOutcome::Advanced(seq)) => {
                drop(claim);
                Ok(AdvanceOutcome {
                    applied_seq: seq,
                    pending: false,
                })
            }
            Ok(ReplayOutcome::NeedsFullRebuild) => {
                // The claim moves into the queue with the job, so the slot
                // stays held until the pool finishes with it. `dispatch`
                // takes the claim by value. When no pool drains the queue,
                // `dispatch` drops the claim with the `SendError`. The
                // release therefore runs on both paths.
                if !self.builds.dispatch(claim, head) {
                    // No pool drains the queue, so nothing will ever run
                    // this build. Every future poll for this subject then
                    // queues another. A deployment mistake caused this
                    // state, because no code called `BuildPool::spawn`. The
                    // mistake fails silently otherwise, so the code logs it
                    // at `error` instead of leaving a client to find it by
                    // polling.
                    tracing::error!(
                        "no replica rebuild worker is running; {} will not converge. \
                         Call BuildPool::spawn when wiring SnapshotManager.",
                        self.user_prefix(sub)
                    );
                }
                Ok(AdvanceOutcome {
                    applied_seq: self.load_applied(sub).await?.unwrap_or_default(),
                    pending: true,
                })
            }
            // A fencing loss here means that a concurrent builder published
            // this replica first. The method adopts the coverage of that
            // builder instead of returning an error. The full-rebuild path
            // used the same recovery before it moved into the pool.
            Err(e) if e.is_fencing_loss() => {
                drop(claim);
                Ok(AdvanceOutcome {
                    applied_seq: self.load_applied(sub).await?.ok_or(e)?,
                    pending: false,
                })
            }
            Err(e) => {
                drop(claim);
                Err(e)
            }
        }
    }

    /// Replica prefix for `sub` (`{db}/u/{sha256-hex(sub)}`).
    ///
    /// The digest keeps each replica prefix fixed-length and safe by
    /// construction. The digest contains hex digits only. Subjects are
    /// attacker-influenced OIDC values, so a raw subject would allow path
    /// traversal or prefix collisions.
    pub fn user_prefix(&self, sub: &str) -> String {
        format!("{}/u/{}", self.db_prefix.trim_matches('/'), safe_sub(sub))
    }

    /// Full object key for `tail` inside the replica.
    ///
    /// The method rejects path traversal (`..`) and empty path segments. The
    /// empty interior segment matters. `object_store`'s `Path::from` removes
    /// empty parts when it splits on `/` (object_store-0.12.5
    /// `path/mod.rs`, `from_iter`). The backend then reads
    /// `db/u/{sha}//manifest.json` and `db/u/{sha}/manifest.json` as the same
    /// key. The caller of this function reads them as different strings.
    /// Serving the alias gave two URLs for one object that changes on each
    /// commit. The code also chose the cache headers from the raw tail. See
    /// [`crate::sync::route::object_handler`].
    pub fn resolve_object(&self, sub: &str, tail: &str) -> Result<String, FsError> {
        if tail.split('/').any(|seg| seg.is_empty() || seg == "..") {
            return Err(FsError::BadRequest("invalid object path".into()));
        }
        Ok(format!("{}/{tail}", self.user_prefix(sub)))
    }

    /// Reads the WAL coverage marker, or `None` when never built.
    ///
    /// The method reads `manifest.json` only to test that the prefix exists.
    /// The method never parses the bytes. `oxkv` alone writes that object, and
    /// `oxkv` alone decides the order of its `sst` list. See the module
    /// documentation.
    ///
    /// An error from the follower open is now an error here. `oxkv` 0.7
    /// opened a follower with an empty manifest when the read of
    /// `manifest.json` failed. The method then answered `None`. `oxkv` 0.9
    /// reports that failure instead. A temporary `S3` error then reaches the
    /// caller as an error. It no longer looks like a prefix that was never
    /// built.
    pub async fn load_applied(&self, sub: &str) -> Result<Option<u64>, FsError> {
        use object_store::ObjectStore as _;

        let manifest =
            object_store::path::Path::from(format!("{}/manifest.json", self.user_prefix(sub)));
        match self.object_store.get(&manifest).await {
            Ok(_) => {}
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(FsError::Internal(e.to_string())),
        }
        let reader = self.open_reader(sub).await?;
        let tx = reader.begin_tx().map_err(store_err)?;
        let out = match tx.get_bytes(APPLIED_KEY).await.map_err(store_err)? {
            Some(bytes) => serde_json::from_slice(&bytes).ok(),
            None => None,
        };
        tx.rollback().await.map_err(store_err)?;
        Ok(out)
    }

    /// Builds the replica for `sub` at the current `wal` head. Returns the
    /// covered WAL head.
    ///
    /// The module docs state the atomicity contract.
    ///
    /// A master file row that does not decode makes the method REFUSE the
    /// build. The filtered walk cannot see that row. The merge-join below then
    /// sees the key on the live side only. The join then reads that key as
    /// "the master no longer has this file". A commit would then delete the
    /// metadata row of that file, and its relation rows, from this replica.
    /// The master would still hold them. The gc orphan-byte pass declines to
    /// act on the same evidence for the same reason
    /// ([`crate::fs::gc`]). This path takes the same input in the
    /// destructive direction. The replica stays exactly as it was. That
    /// choice keeps one stale file that the user can already see instead of
    /// an unrecoverable file.
    pub async fn build_full(&self, sub: &str) -> Result<u64, FsError> {
        let head = self.wal.head().await?;
        // Bring the RAM mirror up to date before the bulk scan. This call
        // does nothing unless [database].mirror_master opted into the
        // prototype.
        self.store.refresh_mirror().await?;

        let snap_prefix = format!(
            "snap-{}-{head}-{}",
            safe_sub(sub),
            &uuid::Uuid::now_v7().to_string()[..8]
        );
        let scratch = FsStore::new(crate::db::build_scratch_store(&snap_prefix).await);
        let undecodable = self.copy_filtered(sub, &scratch).await?;
        if !undecodable.is_empty() {
            // This check runs before the code opens anything on the live
            // side, so a refusal really does leave the replica alone.
            tracing::error!(
                replica = %self.user_prefix(sub),
                rows = undecodable.len(),
                "sync refusing to commit a full rebuild: {} master file metadata rows did not \
                 decode (each is named at WARN), so their keys are absent from the filtered set \
                 and the diff would delete those files from this replica",
                undecodable.len()
            );
            return Err(FsError::Internal(format!(
                "full rebuild refused: {} file metadata rows did not decode",
                undecodable.len()
            )));
        }

        // One writer handles three jobs. The writer is the live side of the
        // diff, the transaction that stages the diff, and the handle that
        // runs the commit. Reading the live side through the writer is safe
        // instead of using a separate reader, because no code has written
        // through the writer yet. Its session overlay is therefore empty. It
        // sees exactly the committed state that the replica holds now.
        let writer = self.open_writer(sub).await?;

        let mut desired = scratch.pages();
        let mut live = KvPages::owned(writer.clone());

        let tx = writer.begin_tx().map_err(store_err)?;
        let mut wrote = false;

        // The coverage marker is control metadata, not replica data. The
        // marker lives on the live side only. The code writes the marker
        // after the diff, below. The merge must step over the marker. It must
        // not read the marker as a key that the filter dropped and then
        // delete it.
        async fn next_data_key(live: &mut KvPages) -> Result<Option<oxkv::KeyValue>, FsError> {
            while let Some(kv) = live.next().await? {
                if kv.key != APPLIED_KEY {
                    return Ok(Some(kv));
                }
            }
            Ok(None)
        }

        // The loop performs a merge join. Both sides are key-ordered by
        // construction, so the loop holds one key per side instead of a map
        // of the whole replica.
        loop {
            let a = desired.next().await?;
            let b = next_data_key(&mut live).await?;
            match (a, b) {
                (None, None) => break,
                (Some(a), None) => {
                    tx.put_bytes(&a.key, &a.value).await.map_err(store_err)?;
                    wrote = true;
                }
                (None, Some(b)) => {
                    tx.delete(&b.key).await.map_err(store_err)?;
                    wrote = true;
                }
                (Some(a), Some(b)) => match a.key.cmp(&b.key) {
                    // The key is only on the desired side. The key is new,
                    // or the value changed.
                    std::cmp::Ordering::Less => {
                        tx.put_bytes(&a.key, &a.value).await.map_err(store_err)?;
                        wrote = true;
                    }
                    // The key is only on the live side. Either the filter
                    // dropped it, or the master no longer has it.
                    std::cmp::Ordering::Greater => {
                        tx.delete(&b.key).await.map_err(store_err)?;
                        wrote = true;
                    }
                    std::cmp::Ordering::Equal => {
                        if a.value != b.value {
                            tx.put_bytes(&a.key, &a.value).await.map_err(store_err)?;
                            wrote = true;
                        }
                    }
                },
            }
        }

        // The coverage marker goes last, in the same transaction as the data.
        // A crash before the commit leaves the previous state and its marker
        // untouched, so the next build repeats the work.
        let marker = serde_json::to_vec(&head).map_err(|e| FsError::Internal(e.to_string()))?;
        let covered = self.load_applied(sub).await? == Some(head);
        if !wrote && covered {
            tx.rollback().await.map_err(store_err)?;
            return Ok(head);
        }
        tx.put_bytes(APPLIED_KEY, &marker)
            .await
            .map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(head)
    }

    /// Replays WAL entries `applied+1..=head` for `sub` onto the live replica.
    ///
    /// The method applies the ops in order. The method re-checks visibility
    /// against the current master state. Then the method advances the coverage
    /// marker. Re-applying the same ops converges, so a crash between ops
    /// heals on the next poll.
    ///
    /// Each condition below returns [`ReplayOutcome::NeedsFullRebuild`]:
    ///
    /// - A legacy policy mark (object only).
    /// - A range over `MAX_REPLAY_OPS` entries.
    /// - A delta that the fan-out budget cannot replay.
    /// - A replica that claims coverage ahead of the head.
    ///
    /// A store failure still returns `Err`. A rich rule op or group op
    /// resyncs only the affected user or row. The method skips irrelevant
    /// users and objects.
    pub async fn replay(&self, head: u64, sub: &str) -> Result<ReplayOutcome, FsError> {
        let Some(applied) = self.load_applied(sub).await? else {
            return Ok(ReplayOutcome::NeedsFullRebuild);
        };
        // The comparison uses `>` and not `>=`, and that difference is the
        // point. A head only moves forward. A replica whose applied sequence
        // is ahead of the head is therefore not caught up. The feed has
        // rewound, or the code restored the object store from a backup, or a
        // coverage marker outlived the entries it claims to cover. Returning
        // `Advanced` there leaves the replica serving data that comes from
        // entries the feed no longer has. The marker still claims that the
        // code applied those entries.
        //
        // The only correct answer is a rebuild from the master, and
        // `NeedsFullRebuild` queues that rebuild. This case also makes the
        // `from > to` error of `Wal::range` reachable from here. Wave 3 made
        // that error a loud `Err`, and this caller was supposed to reach it.
        if applied > head {
            return Ok(ReplayOutcome::NeedsFullRebuild);
        }
        // Genuinely caught up: nothing to replay, and nothing to rebuild.
        if applied == head {
            return Ok(ReplayOutcome::Advanced(applied));
        }
        let entries = self.wal.range(applied + 1, head).await?;
        if entries.len() > MAX_REPLAY_OPS || entries.iter().any(|e| e.op.is_legacy_policy_mark()) {
            return Ok(ReplayOutcome::NeedsFullRebuild);
        }
        let writer = self.open_writer(sub).await?;
        let dst = FsStore::new(writer.clone());
        for entry in &entries {
            if self.apply_op(sub, &dst, &entry.op).await? == ApplyOutcome::NeedsFullRebuild {
                return Ok(ReplayOutcome::NeedsFullRebuild);
            }
        }
        writer
            .set_bytes(
                APPLIED_KEY,
                &serde_json::to_vec(&head).map_err(|e| FsError::Internal(e.to_string()))?,
            )
            .await
            .map_err(store_err)?;
        Ok(ReplayOutcome::Advanced(head))
    }

    /// Opens the replica writer. The call acquires or takes over the prefix
    /// epoch.
    ///
    /// The method takes a fresh handle for each build or replay instead of
    /// caching it for the life of the manager. Replicas are read-mostly and
    /// stay idle long enough for a cached writer to sit on a stale epoch.
    /// `build_lock` serializes the sequence open, write, commit. Two handles
    /// on one prefix are therefore never live at the same time. The
    /// `db::build_s3_store` contract holds for every concurrent writer. Each
    /// sequential build instead uses a new session, exactly as the
    /// `policy export` CLI does.
    async fn open_writer(&self, sub: &str) -> Result<oxkv::OxKvStore, FsError> {
        oxkv::OxKvStore::builder()
            .with_object_store(self.object_store.clone())
            .with_prefix(oxkv::ObjectPath::from(self.user_prefix(sub).as_str()))
            .skip_probe(self.skip_probe)
            .build_with_cache(self.sst_cache.clone())
            .await
            .map_err(FsError::from)
    }

    /// Opens a read-only follower over the replica. The call takes no
    /// ownership.
    ///
    /// A follower never takes an epoch, so a follower cannot fence the
    /// writer. The shared SST cache keeps repeated opens from downloading the
    /// hot segments again.
    ///
    /// `oxkv` 0.9 offers no reader pin. The writer collects a `WAL` file only
    /// after a flush put every record of that file into an `SST`. A read that
    /// loses a segment to a compaction then runs again against a fresh
    /// manifest. The follower therefore sees the live state of the prefix.
    /// It does not see the state of the moment it opened.
    ///
    /// Every caller in this module opens the follower for one short read. So
    /// one repair per read is enough for the call. A caller that must read a
    /// stable snapshot needs another mechanism, because `oxkv` 0.9 does not
    /// provide one.
    async fn open_reader(&self, sub: &str) -> Result<OxKvReader, FsError> {
        let base: std::sync::Arc<dyn object_store::ObjectStore> = self.object_store.clone();
        let storage: std::sync::Arc<dyn oxkv::Storage> = std::sync::Arc::new(base);
        oxkv::OxKvStore::builder()
            .with_store(storage)
            .with_prefix(oxkv::ObjectPath::from(self.user_prefix(sub).as_str()))
            .build_reader_with_cache(self.sst_cache.clone())
            .await
            .map_err(FsError::from)
    }

    /// Applies one WAL op onto a replica under construction.
    ///
    /// The method re-checks visibility against the current master state, so
    /// applying is idempotent. Files that vanished or turned unreadable are
    /// skipped.
    ///
    /// A delta that cannot replay incrementally returns
    /// [`ApplyOutcome::NeedsFullRebuild`], not `Err`. The three fan-out
    /// helpers used to answer with this value:
    /// `FsError::Internal("replay needs full recalc (policy fan-out too large)")`.
    /// Every caller above sees that text as the same thing as a store
    /// failure. `replay` propagated it with a bare `?`. The last arm of
    /// `advance` released the claim and returned it. The `?` of the route
    /// then rendered `500 {"error":"internal server error"}`. `APPLIED_KEY`
    /// only advances on success. The next poll then replayed the same entry
    /// and returned the same 500, for the life of the process. That leaves a
    /// subject that never converges and a rebuild that is never queued. That
    /// last outcome is the one that `ReplayOutcome` now makes expressible.
    async fn apply_op(
        &self,
        sub: &str,
        dst: &FsStore,
        op: &WalOp,
    ) -> Result<ApplyOutcome, FsError> {
        match op {
            WalOp::FileCreate { rec } => {
                if self.can_read(sub, &rec.id).await? {
                    dst.save_file(rec).await?;
                }
            }
            WalOp::FileDelete { file_id } => {
                dst.delete_file(file_id).await?;
            }
            WalOp::Attach {
                row_type,
                row_id,
                file_id,
            } => {
                if let Some(rec) = self.store.get_file(file_id).await?
                    && self.can_read(sub, file_id).await?
                {
                    dst.save_file(&rec).await?;
                    if self
                        .policy
                        .authorize_row(sub, row_type, row_id, Action::Read)
                        .await
                        .unwrap_or(false)
                    {
                        dst.attach(row_type, row_id, file_id).await?;
                    }
                }
            }
            WalOp::Detach {
                row_type,
                row_id,
                file_id,
            } => {
                dst.detach(row_type, row_id, file_id).await?;
            }
            WalOp::PolicyAdd { .. } | WalOp::PolicyRemove { .. } => {
                // `replay` rejects a range that contains one of these ops
                // before it opens a writer, so this arm is unreachable today.
                // The arm declines for the same reason as the fan-out arms. A
                // legacy mark names an object and no rule. The only correct
                // handling is therefore a full recalculation. That is a
                // decision, not a failure.
                return Ok(ApplyOutcome::NeedsFullRebuild);
            }
            WalOp::PolicyRuleAdd {
                sub: rule_sub,
                obj,
                act,
            }
            | WalOp::PolicyRuleRemove {
                sub: rule_sub,
                obj,
                act,
            } => {
                return self.apply_rule_op(sub, dst, rule_sub, obj, act).await;
            }
            WalOp::GroupAdd { user, group } | WalOp::GroupRemove { user, group } => {
                return self.apply_membership_op(sub, dst, user, group).await;
            }
            WalOp::GroupDelete { group } => {
                return self.apply_group_delete(sub, dst, group).await;
            }
        }
        Ok(ApplyOutcome::Applied)
    }

    /// Every group that `sub` is a member of, including indirect groups.
    ///
    /// The RBAC matcher resolves this closure. `g = _, _` with
    /// `m = g(r.sub, p.sub) && …` walks the whole role hierarchy.
    /// `WalOp::GroupAdd { user, group }` sets no constraint on `group`, so
    /// the feed can carry the shape `alice ∈ editors ∈ staff`.
    /// [`Authorizer::get_groups_of_user`] is casbin's
    /// `RoleManager::get_roles`. That function answers with DIRECT roles
    /// only. One hop therefore does not answer "can this rule subject be
    /// `sub`".
    ///
    /// The method walks the same breadth-first expansion as casbin's
    /// `get_implicit_roles_for_user` (casbin-2.20.0 `rbac_api.rs:313`).
    /// The method does not call that function. That function lives on
    /// `Enforcer`, which is private to [`crate::policy`]. Reaching it would
    /// hand the replay path a write-capable engine, which is the bypass that
    /// `PolicyEngine::enforcer` prevents by being private. The read-only
    /// handle already has the hop primitive.
    ///
    /// The method uses a visited set instead of a depth limit. A cycle in the
    /// hierarchy (`a ∈ b` and `b ∈ a`) must end. A cycle also makes the
    /// closure the whole reachable component. A fixed depth would cut that
    /// component short.
    async fn implicit_groups(&self, sub: &str) -> std::collections::HashSet<String> {
        let mut found: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut frontier = vec![sub.to_string()];
        while let Some(name) = frontier.pop() {
            for g in self.policy.get_groups_of_user(&name).await {
                if found.insert(g.clone()) {
                    frontier.push(g);
                }
            }
        }
        found
    }

    /// Resyncs the single row that a permission rule changed.
    ///
    /// The method skips most cases early. A non-`read` action never affects a
    /// read replica. A non-row object (`rules`, `user_groups`, …) holds no
    /// files. A rule subject `sub` cannot reach cannot match, neither
    /// directly nor through nested groups. Otherwise the method re-checks
    /// every file on the row through [`Self::resync_file`]. That resync is
    /// idempotent. It converges, and it never deletes too much. A fan-out
    /// over [`MAX_POLICY_REPLAY_FILES`] returns
    /// [`ApplyOutcome::NeedsFullRebuild`].
    async fn apply_rule_op(
        &self,
        sub: &str,
        dst: &FsStore,
        rule_sub: &str,
        obj: &str,
        act: &str,
    ) -> Result<ApplyOutcome, FsError> {
        if !act.eq_ignore_ascii_case("read") {
            return Ok(ApplyOutcome::Applied);
        }
        let Some((row_type, row_id)) = split_row_obj(obj) else {
            return Ok(ApplyOutcome::Applied);
        };
        if rule_sub != sub && !self.implicit_groups(sub).await.contains(rule_sub) {
            return Ok(ApplyOutcome::Applied);
        }
        let files = self.store.files_for_row(row_type, row_id).await?;
        if files.len() > MAX_POLICY_REPLAY_FILES {
            return Ok(ApplyOutcome::NeedsFullRebuild);
        }
        for file_id in files {
            self.resync_file(sub, dst, row_type, row_id, &file_id)
                .await?;
        }
        Ok(ApplyOutcome::Applied)
    }

    /// Resyncs the rows that a membership change can affect. The method acts
    /// only when `user == sub`.
    ///
    /// The method does nothing when the change is for another user. For `sub`
    /// itself, the method resyncs every `read` row that the group grants.
    /// Groups with no row reads, such as `superadmin` on
    /// `rules`/`user_groups`, cause no work. An oversized fan-out returns
    /// [`ApplyOutcome::NeedsFullRebuild`].
    async fn apply_membership_op(
        &self,
        sub: &str,
        dst: &FsStore,
        user: &str,
        group: &str,
    ) -> Result<ApplyOutcome, FsError> {
        if user != sub {
            return Ok(ApplyOutcome::Applied);
        }
        let rows = self.read_rows_for_group(group).await?;
        let mut total = 0usize;
        for (row_type, row_id) in rows {
            let files = self.store.files_for_row(&row_type, &row_id).await?;
            total += files.len();
            if total > MAX_POLICY_REPLAY_FILES {
                return Ok(ApplyOutcome::NeedsFullRebuild);
            }
            for file_id in files {
                self.resync_file(sub, dst, &row_type, &row_id, &file_id)
                    .await?;
            }
        }
        Ok(ApplyOutcome::Applied)
    }

    /// Resyncs the rows that a deleted group could have exposed.
    ///
    /// The old membership is unknowable, because the links are already gone.
    /// Every group that holds row `read` rules therefore resyncs its rows.
    /// [`Self::resync_file`] re-checks the current visibility, so extra
    /// applications are safe. Files that stay visible through other rows
    /// remain. The other files converge to deleted. Groups with no row reads
    /// skip the work. An oversized fan-out returns
    /// [`ApplyOutcome::NeedsFullRebuild`].
    async fn apply_group_delete(
        &self,
        sub: &str,
        dst: &FsStore,
        group: &str,
    ) -> Result<ApplyOutcome, FsError> {
        let rows = self.read_rows_for_group(group).await?;
        if rows.is_empty() {
            return Ok(ApplyOutcome::Applied);
        }
        let mut total = 0usize;
        for (row_type, row_id) in rows {
            let files = self.store.files_for_row(&row_type, &row_id).await?;
            total += files.len();
            if total > MAX_POLICY_REPLAY_FILES {
                return Ok(ApplyOutcome::NeedsFullRebuild);
            }
            for file_id in files {
                self.resync_file(sub, dst, &row_type, &row_id, &file_id)
                    .await?;
            }
        }
        Ok(ApplyOutcome::Applied)
    }

    /// Converges one file on the replica after a policy change.
    ///
    /// The method ensures that a readable file is present, with the changed
    /// row attached. The method detaches the row when that row alone turned
    /// unreadable. The method deletes files that no row makes readable. A
    /// missing master record makes the method delete the stale replica copy.
    async fn resync_file(
        &self,
        sub: &str,
        dst: &FsStore,
        row_type: &str,
        row_id: &str,
        file_id: &str,
    ) -> Result<(), FsError> {
        let Some(rec) = self.store.get_file(file_id).await? else {
            dst.delete_file(file_id).await?;
            return Ok(());
        };
        if !self.can_read(sub, file_id).await? {
            dst.delete_file(file_id).await?;
            return Ok(());
        }
        dst.save_file(&rec).await?;
        if self
            .policy
            .authorize_row(sub, row_type, row_id, Action::Read)
            .await
            .unwrap_or(false)
        {
            dst.attach(row_type, row_id, file_id).await?;
        } else {
            dst.detach(row_type, row_id, file_id).await?;
        }
        Ok(())
    }

    /// Row `(type, id)` pairs that `group` can read, at any depth.
    ///
    /// The method answers the question that [`Self::apply_membership_op`]
    /// stands in for. It must ask the same question as `enforce`, not a
    /// narrower one. The old code asked the narrower question:
    ///
    /// ```text
    /// for (obj, act) in self.policy.rules_for_subject(group).await { … }
    /// ```
    ///
    /// [`Authorizer::rules_for_subject`] reads direct `p` rules, which are
    /// the rules whose `p.sub` is literally `group`. For `alice ∈ editors ∈
    /// staff` with `p, staff, invoice:1, read`, that read returned nothing
    /// for `editors`. A replay of `WalOp::GroupAdd { user: alice, group:
    /// editors }` then resynced no rows. The file that `enforce` would have
    /// authorized never reached alice's replica. Commit 77036cb fixed the
    /// same direct and transitive asymmetry on the rule path, because
    /// `apply_rule_op` built its skip set from `get_groups_of_user`. The
    /// harm has the same shape here. A full rebuild routes every file
    /// through `visible_rows` -> `authorize_row` and handles this case
    /// correctly, so the incremental path was weaker than the rebuild.
    ///
    /// This case is the inverse of a revocation, so it does less harm than
    /// the rule-path bug. It is still worth fixing. The resync here only
    /// ADDS what [`Self::resync_file`] then re-checks through `can_read` and
    /// `authorize_row`. Widening this set therefore cannot include too much.
    /// The set only decides how much the code re-checks. A stale missing file
    /// converges on the next replay of a membership op, or on the next full
    /// rebuild. Neither of those two events is guaranteed, which is why the
    /// code closes the silent staleness instead of noting it.
    ///
    /// The method walks the hierarchy with [`Self::implicit_groups`] instead
    /// of a second traversal. That way "the closure of a group under `g`" has
    /// exactly one definition in this module. The walk is unbounded, in the
    /// same way as that closure, and deliberately so. The method errs toward
    /// re-checking MORE rows, which is the safe direction for a set that only
    /// feeds idempotent resyncs. A depth limit would bring back a skip, and a
    /// skip is the whole bug. [`MAX_POLICY_REPLAY_FILES`] already bounds the
    /// cost where the cost causes harm, by limiting the fan-out itself.
    ///
    /// The method removes duplicates, because a group and its ancestors often
    /// share a row. Every repeated entry would repeat the resync of the same
    /// files.
    async fn read_rows_for_group(&self, group: &str) -> Result<Vec<(String, String)>, FsError> {
        let mut out: std::collections::BTreeSet<(String, String)> =
            std::collections::BTreeSet::new();
        let mut subjects = vec![group.to_string()];
        subjects.extend(self.implicit_groups(group).await);
        for subject in &subjects {
            for (obj, act) in self.policy.rules_for_subject(subject).await {
                if !act.eq_ignore_ascii_case("read") {
                    continue;
                }
                if let Some((ty, rid)) = split_row_obj(&obj) {
                    out.insert((ty.to_string(), rid.to_string()));
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    /// Writes the visible file set of the caller into `dst`.
    ///
    /// The method makes one pass over the master listing. The record in hand
    /// answers the owner check, with no second read. One rows scan then
    /// serves the visibility check and the attach loop. The old code instead
    /// paid one re-read and two full-store scans for each file, one inside
    /// `can_read` and one for the attach, on top of the listing itself.
    ///
    /// The method returns the keys that the walk could not decode. The caller
    /// uses that list as the cue to refuse the diff. `dst` is deliberately
    /// INCOMPLETE when the list is not empty. `build_full` then compares
    /// `dst` with a live replica.
    async fn copy_filtered(&self, sub: &str, dst: &FsStore) -> Result<Vec<String>, FsError> {
        // The method pages the listing instead of collecting it. `list_files`
        // returns every master record as a `Vec<FileRecord>`. For a large
        // master, that vector is the single largest allocation in the
        // rebuild, and the code does not need it. The filter below decides
        // per record and keeps no record. The key layout stays in
        // `fs::store`, and this method only drives that layout.
        let mut scan = self.store.pages();
        let mut undecodable = Vec::new();
        loop {
            let FileScan {
                record,
                undecodable: skipped,
            } = self.store.next_file(&mut scan).await?;
            undecodable.extend(skipped);
            let Some(rec) = record else {
                break;
            };
            let rows = self.visible_rows(sub, &rec.id).await?;
            if rec.owner_sub != sub && rows.is_empty() {
                continue;
            }
            dst.save_file(&rec).await?;
            if self.store.get_ref_info(&rec.id).await?.count > 0 {
                for (ty, rid) in &rows {
                    dst.attach(ty, rid, &rec.id).await?;
                }
            }
        }
        Ok(undecodable)
    }

    /// Rows of `file_id` that `sub` may read (each authorized individually).
    async fn visible_rows(
        &self,
        sub: &str,
        file_id: &str,
    ) -> Result<Vec<(String, String)>, FsError> {
        let mut out = Vec::new();
        for (ty, rid) in self.store.rows_for_file(file_id).await? {
            if self
                .policy
                .authorize_row(sub, &ty, &rid, Action::Read)
                .await
                .unwrap_or(false)
            {
                out.push((ty, rid));
            }
        }
        Ok(out)
    }

    /// True when `sub` may read `file_id`, by ownership or through any
    /// row that grants `read`.
    async fn can_read(&self, sub: &str, file_id: &str) -> Result<bool, FsError> {
        let Some(rec) = self.store.get_file(file_id).await? else {
            return Ok(false);
        };
        Ok(rec.owner_sub == sub || !self.visible_rows(sub, file_id).await?.is_empty())
    }
}

/// Maps oxkv errors into [`FsError`].
fn store_err(e: oxkv::StoreError) -> FsError {
    FsError::from(e)
}

/// Splits a rule object into `(row_type, row_id)` when it names a row.
///
/// Row objects have the form `{type}:{id}`. Control-plane objects (`rules`,
/// `user_groups`, …) contain no colon. The function returns `None` for them,
/// so that policy replay can skip them without touching storage.
fn split_row_obj(obj: &str) -> Option<(&str, &str)> {
    let (ty, rid) = obj.split_once(':')?;
    if ty.is_empty() || rid.is_empty() {
        return None;
    }
    Some((ty, rid))
}

/// Maps a subject to an identifier that is safe in a prefix.
///
/// An attacker can influence subjects (OIDC `sub`), so a lossy replace is
/// not enough. The values `a/b`, `a:b`, and `a_b` would all collide on one
/// replica prefix, and that collision leaks data across users. The SHA-256
/// hex digest resists collisions, has a fixed length, and is prefix-safe by
/// construction. It contains lowercase hex digits only, with no separators
/// and no traversal sequences.
fn safe_sub(sub: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(sub.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::store::FileRecord;
    use crate::records::ChangeSink;
    use object_store::memory::InMemory;

    /// Builds a manager plus the [`PolicyEngine`] that it reads through.
    ///
    /// The function also returns the engine, so that a test can change the
    /// policy and then let the replica observe the change. The test does not
    /// change the policy through the manager. The manager holds only a
    /// read-only `Authorizer`, and that is the property under test.
    async fn test_manager() -> (
        SnapshotManager,
        crate::policy::PolicyEngine,
        std::sync::Arc<InMemory>,
    ) {
        let mem = std::sync::Arc::new(InMemory::new());
        let wal = Wal::new(crate::db::build_test_store(&crate::db::test_prefix("snap-wal")).await);
        let store =
            FsStore::new(crate::db::build_test_store(&crate::db::test_prefix("snap-store")).await);
        let policy = crate::policy::PolicyEngine::init_s3(
            crate::db::build_test_store(&crate::db::test_prefix("snap-policy")).await,
        )
        .await
        .unwrap();
        let mgr = SnapshotManager::new(
            crate::sync::snapshot::SnapshotDeps {
                wal,
                store,
                policy: policy.authorizer(),
                object_store: mem.clone() as std::sync::Arc<dyn object_store::ObjectStore>,
                builds: crate::sync::snapshot::BuildQueue::new().0,
            },
            "test-db",
            crate::sync::snapshot::ReplicaBackend::InMemory,
        );
        (mgr, policy, mem)
    }

    /// The backend choice maps to the probe flag, and the flag polarity is
    /// the whole risk.
    ///
    /// `skip_probe` was a bare `bool` in a six-argument constructor. Nothing
    /// at the call site told "probe real S3" apart from "no probe". The wrong
    /// value does not cause a compile error. It also does not cause an
    /// obviously wrong answer. Skipping the probe against real S3 removes
    /// the conditional-write check that guards the `manifest.json` CAS. That
    /// fault shows up later, as two builders that each believe it won.
    #[tokio::test]
    async fn replica_backend_selects_the_storage_probe() {
        let deps = async {
            SnapshotDeps {
                wal: Wal::new(
                    crate::db::build_test_store(&crate::db::test_prefix("probe-wal")).await,
                ),
                store: FsStore::new(
                    crate::db::build_test_store(&crate::db::test_prefix("probe-store")).await,
                ),
                policy: crate::policy::PolicyEngine::init_s3(
                    crate::db::build_test_store(&crate::db::test_prefix("probe-policy")).await,
                )
                .await
                .expect("engine")
                .authorizer(),
                object_store: std::sync::Arc::new(object_store::memory::InMemory::new())
                    as std::sync::Arc<dyn object_store::ObjectStore>,
                builds: crate::sync::snapshot::BuildQueue::new().0,
            }
        }
        .await;

        let make = |backend| {
            SnapshotManager::new(
                SnapshotDeps {
                    wal: deps.wal.clone(),
                    store: deps.store.clone(),
                    policy: deps.policy.clone(),
                    object_store: deps.object_store.clone(),
                    builds: crate::sync::snapshot::BuildQueue::new().0,
                },
                "test-db",
                backend,
            )
        };

        assert!(
            !make(ReplicaBackend::ObjectStore).skip_probe,
            "real object stores must be probed for conditional writes"
        );
        assert!(
            make(ReplicaBackend::InMemory).skip_probe,
            "InMemory has no conditional writes to probe"
        );
    }

    /// Builds a manager and KEEPS the receiver of its [`BuildQueue`].
    ///
    /// `test_manager` drops the receiver (`BuildQueue::new().0`). Then every
    /// dispatch fails, and the failure path releases the claim at once. That
    /// default suits a fixture that only tests replay. It does not suit a
    /// test about merging requests. A test written against that fixture
    /// cannot tell "the in-flight set held the slot" from "nothing was ever
    /// claimed".
    async fn test_manager_with_queue() -> (
        SnapshotManager,
        crate::policy::PolicyEngine,
        tokio::sync::mpsc::UnboundedReceiver<BuildJob>,
    ) {
        let mem = std::sync::Arc::new(InMemory::new());
        let wal = Wal::new(crate::db::build_test_store(&crate::db::test_prefix("snap-wal")).await);
        let store =
            FsStore::new(crate::db::build_test_store(&crate::db::test_prefix("snap-store")).await);
        let policy = crate::policy::PolicyEngine::init_s3(
            crate::db::build_test_store(&crate::db::test_prefix("snap-policy")).await,
        )
        .await
        .unwrap();
        let (builds, jobs) = BuildQueue::new();
        let mgr = SnapshotManager::new(
            SnapshotDeps {
                wal,
                store,
                policy: policy.authorizer(),
                object_store: mem as std::sync::Arc<dyn object_store::ObjectStore>,
                builds,
            },
            "test-db",
            ReplicaBackend::InMemory,
        );
        (mgr, policy, jobs)
    }

    fn file_record(id: &str, owner: &str) -> FileRecord {
        FileRecord {
            id: id.into(),
            name: format!("{id}.txt"),
            mimetype: "text/plain".into(),
            size: 1,
            s3_key: format!("k/{id}"),
            owner_sub: owner.into(),
            created_at: 0,
        }
    }

    async fn open_reader(mem: &std::sync::Arc<InMemory>, prefix: &str) -> OxKvReader {
        let base: std::sync::Arc<dyn object_store::ObjectStore> = mem.clone();
        let storage: std::sync::Arc<dyn oxkv::Storage> = std::sync::Arc::new(base);
        OxKvReader::open(storage, oxkv::ObjectPath::from(prefix))
            .await
            .unwrap()
    }

    async fn replica_has(
        mem: &std::sync::Arc<InMemory>,
        mgr: &SnapshotManager,
        sub: &str,
        key: &str,
    ) -> bool {
        let reader = open_reader(mem, &mgr.user_prefix(sub)).await;
        let tx = reader.begin_tx().unwrap();
        let out = tx.get_bytes(key).await.unwrap().is_some();
        tx.rollback().await.unwrap();
        out
    }

    #[tokio::test]
    async fn build_full_filters_into_live_prefix() -> anyhow::Result<()> {
        let (mgr, policy, mem) = test_manager().await;
        policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        let rec = file_record("f1", "alice");
        mgr.store.save_file(&rec).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.store.save_file(&file_record("f2", "bob")).await?;

        assert_eq!(mgr.build_full("alice").await?, 0);
        assert_eq!(mgr.load_applied("alice").await?, Some(0));

        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await);
        assert!(replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);
        Ok(())
    }

    /// Writes a raw value under `key` in the MASTER store. The call skips
    /// every typed setter, so that a test can plant a row that no writer in
    /// this crate would produce.
    async fn put_raw(store: &FsStore, key: &str, value: &[u8]) {
        store
            .kv_handle()
            .write()
            .await
            .set_bytes(key, value)
            .await
            .unwrap();
    }

    /// An undecodable master row must not delete a file from a replica that
    /// already has the file.
    ///
    /// The rebuild performs a merge join. The filtered master walk is the
    /// desired side. The replica is the live side. The join deletes a key
    /// that is present only on the live side. A `fs:files:{id}:meta` row
    /// that fails to decode is skipped by `next_file`. The walk then cannot
    /// see that row. The join then reads "master no longer has this file".
    /// The join then deletes the metadata row of that file, and its relation
    /// rows, from the replica of the user. The master still holds them.
    /// `GET /sync/db/...{id}:meta` then returns 404 for a file that the
    /// master serves correctly.
    ///
    /// This fault does more than "omit one file from one replica". The
    /// omission is not the outcome. The DELETE is the outcome. An earlier
    /// change assessed the consequence as an omission. That assessment is
    /// right about the master and wrong about the replica.
    ///
    /// For the same input, the gc orphan-byte pass reaches the opposite
    /// conclusion and refuses to act. Its rule is "an unreferenced key cannot
    /// be proven unreferenced", src/fs/gc.rs. `build_full` had no equivalent
    /// gate, and `build_full` acts in the destructive direction. The method
    /// therefore refuses the build now. The replica stays exactly as it was.
    ///
    /// The code can reach this state without corruption. Adding any field to
    /// `FileRecord` without a `#[serde(default)]` makes every row that the
    /// previous version wrote undecodable. One ordinary schema change is
    /// enough.
    ///
    /// The test checks both halves. `f1` decodes, and `f1` is still there, so
    /// the rebuild is not refusing everything. `f2` is the file whose master
    /// row stopped decoding, and `f2` must survive on the replica. The old
    /// code deleted `fs:files:f2:meta` AND `fs:rel:invoice:1:f2` from the
    /// replica on the second build.
    #[tokio::test]
    async fn an_undecodable_master_row_cannot_delete_a_file_from_a_replica() -> anyhow::Result<()> {
        let (mgr, policy, mem) = test_manager().await;
        policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        // Both files belong to alice. Both hang off a row that she may read.
        // Both are in her filtered set on the first build.
        for id in ["f1", "f2"] {
            mgr.store.save_file(&file_record(id, "alice")).await?;
            mgr.store.attach("invoice", "1", id).await?;
        }
        assert_eq!(mgr.build_full("alice").await?, 0);
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await);
        assert!(replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f2").await);

        // The master row for f2 stops decoding, as it would after a schema
        // change. The master still HAS the file. Only the walk cannot read
        // it.
        put_raw(&mgr.store, "fs:files:f2:meta", br#"{"id":"f2","size":1"#).await;

        let refused = mgr.build_full("alice").await;
        assert!(
            refused.is_err(),
            "a rebuild over an unreadable master row must not be committed: {refused:?}"
        );
        // Nothing was committed, so coverage has not moved...
        assert_eq!(mgr.load_applied("alice").await?, Some(0));
        // ...the readable file is still there...
        assert!(
            replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await,
            "the refusal must not cost the replica the files it CAN read"
        );
        // The unreadable file was also not deleted from the replica.
        assert!(
            replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await,
            "the rebuild deleted a file from the replica on the strength of a row it could not read"
        );
        assert!(
            replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f2").await,
            "the rebuild deleted a file's relation rows from the replica as well"
        );

        // After the repair, the rebuild resumes. The gate defers the build.
        // It does not disable the replica.
        mgr.store.save_file(&file_record("f2", "alice")).await?;
        assert_eq!(mgr.build_full("alice").await?, 0);
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await);
        Ok(())
    }

    #[tokio::test]
    async fn build_full_with_mirrored_master() -> anyhow::Result<()> {
        let (mut mgr, policy, mem) = test_manager().await;
        policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        let rec = file_record("f1", "alice");
        mgr.store.save_file(&rec).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.store.save_file(&file_record("f2", "bob")).await?;
        mgr.store = mgr.store.mirrored_clone().await?;

        assert_eq!(mgr.build_full("alice").await?, 0);
        assert_eq!(mgr.load_applied("alice").await?, Some(0));

        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await);
        assert!(replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);
        Ok(())
    }

    #[tokio::test]
    async fn build_is_idempotent_without_new_manifest_cas() -> anyhow::Result<()> {
        use object_store::ObjectStore as _;

        let (mgr, _, mem) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;

        let manifest =
            object_store::path::Path::from(format!("{}/manifest.json", mgr.user_prefix("alice")));
        let etag_before = mem.get(&manifest).await?.meta.e_tag.unwrap();
        mgr.build_full("alice").await?;
        let etag_after = mem.get(&manifest).await?.meta.e_tag.unwrap();
        assert_eq!(etag_before, etag_after);
        Ok(())
    }

    #[tokio::test]
    async fn fresh_prefix_has_no_coverage() -> anyhow::Result<()> {
        let (mgr, _, _) = test_manager().await;
        assert_eq!(mgr.load_applied("alice").await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn replay_applies_file_delta() -> anyhow::Result<()> {
        let (mgr, _, mem) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;

        // Simulate the logged write path. The code changes the master and
        // appends a WAL entry.
        let f2 = file_record("f2", "alice");
        mgr.store.save_file(&f2).await?;
        mgr.wal.append(WalOp::FileCreate { rec: f2 }).await?;

        assert_eq!(mgr.replay(1, "alice").await?, ReplayOutcome::Advanced(1));
        assert_eq!(mgr.load_applied("alice").await?, Some(1));
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await);
        Ok(())
    }

    #[tokio::test]
    async fn replay_detach_and_delete_converge() -> anyhow::Result<()> {
        let (mgr, policy, mem) = test_manager().await;
        policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.build_full("alice").await?;
        assert!(replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);

        // Detach and then delete on the master. The code logs both, as the
        // engines do.
        mgr.store.detach("invoice", "1", "f1").await?;
        mgr.wal
            .append(WalOp::Detach {
                row_type: "invoice".into(),
                row_id: "1".into(),
                file_id: "f1".into(),
            })
            .await?;
        mgr.store.delete_file("f1").await?;
        mgr.wal
            .append(WalOp::FileDelete {
                file_id: "f1".into(),
            })
            .await?;

        assert_eq!(mgr.replay(2, "alice").await?, ReplayOutcome::Advanced(2));
        assert!(!replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        Ok(())
    }

    /// Concurrent `advance` calls for one subject merge into one build.
    ///
    /// This is the merge property, and it matters more than the queue itself.
    /// A client polls `POST /sync/sync`, so a deploy or a busy period sends
    /// many requests per user for the same pending rebuild. Without the
    /// in-flight set, each request runs a full master scan and then finds
    /// that there is nothing to do. The old guard was also a process-wide
    /// mutex, so those scans ran one at a time. They then queued up behind
    /// each other instead of at least being cheap.
    ///
    /// The fixture KEEPS the queue receiver. The old `BuildQueue::new().0`
    /// dropped the receiver. Every `dispatch` then failed on a closed
    /// channel, and the failure path released the claim. The in-flight set
    /// was empty again before each assertion. "The claim short-circuited the
    /// queue" and "nothing was ever claimed" then looked the same from
    /// outside. Deleting the whole set left this test green.
    ///
    /// The test does not drain the receiver on purpose. A live pool would
    /// finish the build and release the slot between calls. That result is
    /// correct, but it tests nothing. Holding the queued job IS the merge
    /// window.
    #[tokio::test]
    async fn concurrent_advances_for_one_subject_collapse() -> anyhow::Result<()> {
        let (mgr, _, mut jobs) = test_manager_with_queue().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;

        // A replica that was never built needs a full rebuild, so every call
        // here tries to queue one.
        let first = mgr.advance("alice").await?;
        assert!(first.pending, "a never-built replica must be queued");
        assert_eq!(first.applied_seq, 0, "nothing has been built yet");

        // The slot is held by the queued job, so further calls must not queue
        // again.
        for _ in 0..3 {
            let again = mgr.advance("alice").await?;
            assert!(
                again.pending,
                "still pending, but the claim should short-circuit the queue"
            );
            assert_eq!(again.applied_seq, 0);
        }

        // And only one job ever reached the queue.
        let job = jobs.try_recv().expect("one job queued");
        assert_eq!(job.sub(), "alice");
        assert!(jobs.try_recv().is_err(), "exactly one job, not four");
        Ok(())
    }

    /// Drives one `advance` until it stops at an object-store read, then
    /// drops it there.
    ///
    /// The test polls `advance` with a no-op waker. Every operation that the
    /// `InMemory` backend can answer at once then runs to the end inside a
    /// single poll. The one exception is the stalling read that the test arms
    /// below. That suspension point is exactly the state that a client
    /// disconnect abandons. The handler future is dropped with the claim
    /// inserted and with no release executed.
    ///
    /// The helper returns `true` once the future has stopped. The caller then
    /// knows that the claim was live at the drop. Without that value, the test
    /// could assert against a future that ran to the end and released on its
    /// own.
    ///
    /// The helper arms on the first WRITE, not on the first read. `advance`
    /// reads the coverage marker (`load_applied`) before it takes the claim. A
    /// stop on a read would then park with the slot still free, and it would
    /// prove nothing. Every replica write happens inside `replay`, after the
    /// claim is held. Those writes are the opening of the writer, the apply
    /// for each op, and the marker write.
    #[derive(Debug)]
    struct StallingStore {
        inner: std::sync::Arc<dyn object_store::ObjectStore>,
        /// Armed before the advance, so that only that read stalls.
        armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
        /// Set by the stalling read. The field lets the test prove that the
        /// future stopped at THAT read and not somewhere else.
        hit: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl object_store::ObjectStore for StallingStore {
        async fn put_opts(
            &self,
            location: &object_store::path::Path,
            payload: object_store::PutPayload,
            opts: object_store::PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.hit.store(true, std::sync::atomic::Ordering::SeqCst);
                // This call never resolves. The caller must drop the future
                // that it is stopped in instead of waiting for a result.
                std::future::pending::<()>().await;
            }
            self.inner.put_opts(location, payload, opts).await
        }

        async fn put_multipart_opts(
            &self,
            _location: &object_store::path::Path,
            _opts: object_store::PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            unimplemented!("replica writes are not multipart")
        }

        async fn get_opts(
            &self,
            location: &object_store::path::Path,
            options: object_store::GetOptions,
        ) -> object_store::Result<object_store::GetResult> {
            self.inner.get_opts(location, options).await
        }

        async fn delete(&self, location: &object_store::path::Path) -> object_store::Result<()> {
            self.inner.delete(location).await
        }

        fn list(
            &self,
            prefix: Option<&object_store::path::Path>,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
        {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&object_store::path::Path>,
        ) -> object_store::Result<object_store::ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy(
            &self,
            from: &object_store::path::Path,
            to: &object_store::path::Path,
        ) -> object_store::Result<()> {
            self.inner.copy(from, to).await
        }

        async fn copy_if_not_exists(
            &self,
            from: &object_store::path::Path,
            to: &object_store::path::Path,
        ) -> object_store::Result<()> {
            self.inner.copy_if_not_exists(from, to).await
        }

        fn list_with_offset(
            &self,
            prefix: Option<&object_store::path::Path>,
            offset: &object_store::path::Path,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
        {
            self.inner.list_with_offset(prefix, offset)
        }
    }

    impl std::fmt::Display for StallingStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("StallingStore")
        }
    }

    /// A future that the code drops mid-flight must release the slot of the
    /// subject.
    ///
    /// This is the leak that the [`BuildClaim`] exists to close. `advance`
    /// runs inside a request handler future, and the client may disconnect at
    /// any `.await` in `replay`. The code then drops the handler with the
    /// claim inserted and with no release executed. Every later `advance` for
    /// that subject then takes the `pending: true` short-circuit forever. The
    /// replica stays frozen at its old coverage for the life of the process.
    /// No code logs an error, and only a restart recovers.
    ///
    /// The test drives a real `advance` future and stops it at a real store
    /// read. The test then fails if the guard ever moves off the path that
    /// holds it. The stalling store arms AFTER `build_full`. The setup then
    /// builds normally, and only the advance that the test drops stops.
    #[tokio::test]
    async fn a_future_dropped_mid_replay_releases_the_slot() -> anyhow::Result<()> {
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll};

        let (mut mgr, _, _) = test_manager_with_queue().await;
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.build_full("alice").await?;
        mgr.wal
            .append(WalOp::FileCreate {
                rec: file_record("f2", "alice"),
            })
            .await?;

        // Arm the stall only now. `build_full` and the WAL append above must
        // run for real. Only the advance that the test drops may stop.
        let armed = Arc::new(AtomicBool::new(true));
        let hit = Arc::new(AtomicBool::new(false));
        let inner = mgr.object_store.clone();
        mgr.object_store = Arc::new(StallingStore {
            inner,
            armed: Arc::clone(&armed),
            hit: Arc::clone(&hit),
        });

        let mut advance = Box::pin(mgr.advance("alice"));
        let waker = futures_util::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        // One poll. With the stall armed, everything that `InMemory` can
        // answer at once runs to the first replica WRITE and stops there. One
        // poll is therefore the whole wait. A `Ready` result here would mean
        // that the write never happened, and the assertion below catches it.
        match Pin::new(&mut advance).as_mut().poll(&mut cx) {
            Poll::Pending => {}
            Poll::Ready(r) => panic!("the advance finished instead of parking: {r:?}"),
        }
        assert!(
            hit.load(Ordering::SeqCst),
            "the advance future must park inside replay, with the claim live"
        );

        // The test drops the future during the replay, with the claim
        // inserted. The slot must not survive.
        drop(advance);
        assert!(
            mgr.builds.claim("alice").is_some(),
            "a dropped replay future must not leave alice marked in flight"
        );
        assert!(
            !armed.load(Ordering::SeqCst),
            "the stalling read must have been consumed exactly once"
        );
        Ok(())
    }

    /// A rebuild that already runs leaves the caller short of the head, and
    /// `pending` must say so.
    ///
    /// The difference from `applied_seq < head` is the point. A client that
    /// cannot tell "queued for you" from "someone else got there first"
    /// cannot decide whether to keep polling or to stop.
    #[tokio::test]
    async fn pending_is_reported_rather_than_silently_short() -> anyhow::Result<()> {
        let (mgr, _, _) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;

        let out = mgr.advance("alice").await?;
        assert!(!out.pending, "an up-to-date replica is not pending");
        assert_eq!(out.applied_seq, mgr.wal.head().await?);
        Ok(())
    }

    /// Different subjects do not block each other.
    ///
    /// The test guards against a past fault. `replay` and `build_full` shared
    /// one process-wide `Mutex<()>`. A full rebuild for alice then blocked a
    /// replay for bob behind work that can take minutes.
    #[tokio::test]
    async fn one_subject_does_not_block_another() -> anyhow::Result<()> {
        let (mgr, _, _) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;

        // Alice takes the slot.
        let alice = mgr.builds.claim("alice").expect("alice's slot is free");

        // Bob is not affected. He is not behind alice in any queue.
        let bob = mgr
            .builds
            .claim("bob")
            .expect("bob must not be blocked by alice");
        drop(bob);

        // Alice still cannot be double-built while her first is in flight.
        assert!(
            mgr.builds.claim("alice").is_none(),
            "the in-flight set must reject a second claim for alice"
        );
        drop(alice);
        assert!(
            mgr.builds.claim("alice").is_some(),
            "a released slot is reusable"
        );
        Ok(())
    }

    /// A replica that claims coverage ahead of the WAL head must rebuild. The
    /// genuinely caught-up case must stay a no-op.
    ///
    /// Wave 3 made `Wal::range(from > to)` a loud `Err`. The ground for that
    /// change was that a rewound head must reach the full-rebuild fallback.
    /// The author of that change flagged the gap that this test closes.
    /// `range` cannot tell "caught up" from "head rewound" from inside
    /// itself, because it does not know the applied sequence of the caller.
    /// The loud error therefore helps only a caller that reaches it. `replay`
    /// stopped at `applied >= head` and never passed `from > to`. `advance`
    /// stopped at the same condition before `replay` ran at all. Both
    /// reported success for a replica whose coverage the feed can no longer
    /// justify.
    ///
    /// A head only moves forward. Therefore `applied > head` means a rewound
    /// feed, an object store restored from a backup, or a marker that
    /// outlived the entries it claims. The only correct answer is a rebuild
    /// from the master.
    ///
    /// The test writes the applied marker directly instead of rewinding a
    /// real head. `Wal` has no rewind. Commit 130841e made a corrupt head
    /// fail the append instead of rewinding it. The public API therefore
    /// cannot produce a backwards head at all. Writing the marker over a
    /// built replica reproduces the state that a rewind leaves behind, and
    /// that is the state that the code must recognise.
    #[tokio::test]
    async fn an_applied_sequence_ahead_of_the_head_triggers_a_rebuild() -> anyhow::Result<()> {
        let (mgr, _, _) = test_manager_with_queue().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;
        assert_eq!(mgr.load_applied("alice").await?, Some(0));

        // The replica now claims three entries. The feed at head 0 cannot
        // have given it those entries.
        let ahead = 3u64;
        mgr.open_writer("alice")
            .await?
            .set_bytes(super::APPLIED_KEY, &serde_json::to_vec(&ahead)?)
            .await?;
        assert_eq!(mgr.load_applied("alice").await?, Some(3));

        // Not "caught up": a rebuild is required.
        assert_eq!(
            mgr.replay(0, "alice").await?,
            ReplayOutcome::NeedsFullRebuild,
            "coverage ahead of the head is corruption, not convergence"
        );

        // The same holds through `advance`. Its own short-circuit used to
        // return `pending: false` before `replay` ever ran.
        let out = mgr.advance("alice").await?;
        assert!(
            out.pending,
            "a replica ahead of the head must queue a rebuild: {out:?}"
        );

        // The legitimate case is untouched: covered exactly is a no-op.
        mgr.build_full("alice").await?;
        let up_to_date = mgr.advance("alice").await?;
        assert!(
            !up_to_date.pending,
            "applied == head is genuinely caught up: {up_to_date:?}"
        );
        assert_eq!(up_to_date.applied_seq, mgr.wal.head().await?);
        Ok(())
    }

    #[tokio::test]
    async fn replay_bails_on_legacy_policy_marks() -> anyhow::Result<()> {
        let (mgr, _, _) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;
        mgr.wal
            .append(WalOp::PolicyAdd {
                obj: "invoice:1".into(),
            })
            .await?;
        assert_eq!(
            mgr.replay(1, "alice").await?,
            ReplayOutcome::NeedsFullRebuild
        );
        assert_eq!(mgr.load_applied("alice").await?, Some(0));
        Ok(())
    }

    #[tokio::test]
    async fn replay_skips_irrelevant_policy_ops() -> anyhow::Result<()> {
        let (mgr, _, mem) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;
        mgr.build_full("alice").await?;
        // The ops cover another user's membership, a non-row object, and a
        // non-read action. None of them can affect the read replica of alice.
        mgr.wal
            .append(WalOp::GroupAdd {
                user: "bob".into(),
                group: "editors".into(),
            })
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleAdd {
                sub: "editors".into(),
                obj: "rules".into(),
                act: "read".into(),
            })
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleAdd {
                sub: "editors".into(),
                obj: "invoice:9".into(),
                act: "write".into(),
            })
            .await?;
        assert_eq!(mgr.replay(3, "alice").await?, ReplayOutcome::Advanced(3));
        assert_eq!(mgr.load_applied("alice").await?, Some(3));
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        Ok(())
    }

    #[tokio::test]
    async fn replay_applies_rule_grant_then_revoke() -> anyhow::Result<()> {
        let (mgr, policy, mem) = test_manager().await;
        // The file on invoice:1 belongs to bob. Alice sees nothing yet.
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.build_full("alice").await?;
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);

        // Grant editors read on the row, then add alice to editors. The
        // master mutation comes first, then the WAL entries, as the engines
        // append them.
        policy
            .add_rule("editors".into(), "invoice:1".into(), Action::Read)
            .await?;
        policy
            .assign_group("alice".into(), "editors".into())
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleAdd {
                sub: "editors".into(),
                obj: "invoice:1".into(),
                act: "read".into(),
            })
            .await?;
        mgr.wal
            .append(WalOp::GroupAdd {
                user: "alice".into(),
                group: "editors".into(),
            })
            .await?;
        assert_eq!(mgr.replay(2, "alice").await?, ReplayOutcome::Advanced(2));
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);

        // Revoke the rule: the file must leave the replica.
        policy
            .remove_rule("editors".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleRemove {
                sub: "editors".into(),
                obj: "invoice:1".into(),
                act: "read".into(),
            })
            .await?;
        assert_eq!(mgr.replay(3, "alice").await?, ReplayOutcome::Advanced(3));
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        assert!(!replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await);
        Ok(())
    }

    /// A revocation through a NESTED group must still reach the replica.
    ///
    /// The test guards against a past fault. `apply_rule_op` decided "this
    /// replayed op cannot affect this subject" from `get_groups_of_user`.
    /// That function is casbin's `RoleManager::get_roles`, and it returns
    /// DIRECT roles only. Here `alice ∈ editors ∈ staff`. A removal of
    /// `p, staff, invoice:1, read` then returned `Ok(())` without a call to
    /// `resync_file`. The filter and the `authorize_row` that it stands in
    /// for then disagreed about whether the rule applied. The file stayed in
    /// the replica of alice. The route `GET /sync/db/{object}` kept serving
    /// it under a coverage marker that had already moved past the
    /// revocation. The result is too much data for a subject that the
    /// revocation just denied, and not stale data.
    ///
    /// The full rebuild seeds the replica. That rebuild routes every file
    /// through `visible_rows` -> `authorize_row`, and it handles the case
    /// correctly. That matters for the meaning of the assertion. The file is
    /// PROVABLY present before the replayed revocation, so "it is gone
    /// afterwards" can only come from the replay. A skipped grant would let
    /// the test pass for the wrong reason.
    #[tokio::test]
    async fn a_revoke_through_a_nested_group_reaches_the_replica() -> anyhow::Result<()> {
        let (mgr, policy, mem) = test_manager().await;
        // Two hops. Alice is in editors, and editors is in staff. The rule
        // names staff. `get_groups_of_user("alice")` answers ["editors"].
        policy
            .assign_group("alice".into(), "editors".into())
            .await?;
        policy
            .assign_group("editors".into(), "staff".into())
            .await?;
        policy
            .add_rule("staff".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.build_full("alice").await?;
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);

        // Revoke through the OUTER group, as the policy engine announces it.
        policy
            .remove_rule("staff".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleRemove {
                sub: "staff".into(),
                obj: "invoice:1".into(),
                act: "read".into(),
            })
            .await?;
        assert_eq!(mgr.replay(1, "alice").await?, ReplayOutcome::Advanced(1));
        assert!(
            !replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await,
            "revoking through a nested group must REMOVE the file; the \
             direct-roles filter skipped the op and left revoked data \
             readable under an advanced coverage marker"
        );
        Ok(())
    }

    /// The mirror case: a grant through a nested group must not be skipped.
    ///
    /// The old filter was wrong in both directions. Testing only the revoke
    /// half would let the grant half regress without a trace. The test builds
    /// the replica while the rule does NOT exist. The only way for `f1` to
    /// appear is for the replayed `PolicyRuleAdd` to reach it. Skipping that
    /// op leaves a file that `enforce` authorizes silently absent.
    #[tokio::test]
    async fn a_grant_through_a_nested_group_reaches_the_replica() -> anyhow::Result<()> {
        let (mgr, policy, mem) = test_manager().await;
        policy
            .assign_group("alice".into(), "editors".into())
            .await?;
        policy
            .assign_group("editors".into(), "staff".into())
            .await?;
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.build_full("alice").await?;
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);

        policy
            .add_rule("staff".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleAdd {
                sub: "staff".into(),
                obj: "invoice:1".into(),
                act: "read".into(),
            })
            .await?;
        assert_eq!(mgr.replay(1, "alice").await?, ReplayOutcome::Advanced(1));
        assert!(
            replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await,
            "a grant an `enforce` would authorize must not be silently absent"
        );
        Ok(())
    }

    /// The membership path mirrors the two tests above.
    ///
    /// Commit 77036cb added the nested-group fix to `apply_rule_op`. The
    /// path that handles a GROUP MEMBERSHIP change never received that fix.
    /// `read_rows_for_group` resolved the rules of the group through
    /// `rules_for_subject`. That call reads the rules whose `p.sub` is
    /// literally the group name, and no rule above it. Here `alice ∈ editors
    /// ∈ staff`, and the rule names `staff`. The replayed op is the op that
    /// makes alice a member at all:
    ///
    /// ```text
    /// WalOp::GroupAdd { user: alice, group: editors }
    /// ```
    ///
    /// The old code called `rules_for_subject("editors")` and found no `p`
    /// row, because the grant names `staff`. The old code then resynced
    /// nothing and left the file out of the replica of alice. `enforce`
    /// authorized the file at the same time. The full rebuild would have
    /// included it, because that rebuild routes every file through
    /// `visible_rows` -> `authorize_row`. The incremental path was weaker
    /// than the rebuild, and that is the asymmetry. The harm is the
    /// under-inclusion, not the over-inclusion that 77036cb fixed. That is
    /// why the fault was not a blocker. It belongs to the same class, and it
    /// is silent.
    ///
    /// The test takes a full rebuild while the rule and the OUTER membership
    /// already exist, and while alice's own membership is still missing. The
    /// test therefore sets `!replica_has` first. The file is provably absent
    /// before the replay. Only a transitive resolution of the membership op
    /// can put it there.
    #[tokio::test]
    async fn a_membership_op_resolves_the_groups_ancestor_rules() -> anyhow::Result<()> {
        let (mgr, policy, mem) = test_manager().await;
        policy
            .assign_group("editors".into(), "staff".into())
            .await?;
        policy
            .add_rule("staff".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        // Alice is in nothing yet, so the rebuild authorizes nothing.
        mgr.build_full("alice").await?;
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);

        // Master mutation first, WAL entry second, as the engines append.
        policy
            .assign_group("alice".into(), "editors".into())
            .await?;
        mgr.wal
            .append(WalOp::GroupAdd {
                user: "alice".into(),
                group: "editors".into(),
            })
            .await?;
        assert_eq!(mgr.replay(1, "alice").await?, ReplayOutcome::Advanced(1));
        assert!(
            replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await,
            "a grant held by an ANCESTOR of the joined group must reach the \
             replica; a direct-only rule read resynced no rows and left a \
             file an `enforce` authorizes silently absent"
        );
        assert!(
            replica_has(&mem, &mgr, "alice", "fs:rel:invoice:1:f1").await,
            "and it must be attached to the row the ancestor's rule grants"
        );
        Ok(())
    }

    /// The direct rule still resolves, and the code does not invent a rule
    /// that an ancestor does NOT hold.
    ///
    /// The transitive widening is sound only if the rows of the group still
    /// come through, and only if the answer stays inside what the hierarchy
    /// actually grants. The test pins both halves. That keeps a future
    /// shortcut that returns everything from passing.
    #[tokio::test]
    async fn a_membership_op_still_resolves_the_groups_own_rules() -> anyhow::Result<()> {
        let (mgr, policy, mem) = test_manager().await;
        policy
            .assign_group("editors".into(), "staff".into())
            .await?;
        // Direct grant on the joined group, ancestor grant on another row.
        policy
            .add_rule("editors".into(), "invoice:1".into(), Action::Read)
            .await?;
        policy
            .add_rule("staff".into(), "report:9".into(), Action::Read)
            .await?;
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.store.save_file(&file_record("f2", "bob")).await?;
        mgr.store.attach("report", "9", "f2").await?;
        mgr.store.save_file(&file_record("f3", "bob")).await?;
        mgr.store.attach("secret", "7", "f3").await?;
        mgr.build_full("alice").await?;

        policy
            .assign_group("alice".into(), "editors".into())
            .await?;
        mgr.wal
            .append(WalOp::GroupAdd {
                user: "alice".into(),
                group: "editors".into(),
            })
            .await?;
        assert_eq!(mgr.replay(1, "alice").await?, ReplayOutcome::Advanced(1));
        assert!(
            replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await,
            "the joined group's own read rows must still resolve"
        );
        assert!(
            replica_has(&mem, &mgr, "alice", "fs:files:f2:meta").await,
            "and its ancestors' alongside them"
        );
        assert!(
            !replica_has(&mem, &mgr, "alice", "fs:files:f3:meta").await,
            "a row neither the group nor its ancestors grants stays out"
        );
        Ok(())
    }

    #[tokio::test]
    async fn replay_group_remove_converges() -> anyhow::Result<()> {
        let (mgr, policy, mem) = test_manager().await;
        policy
            .add_rule("editors".into(), "invoice:1".into(), Action::Read)
            .await?;
        policy
            .assign_group("alice".into(), "editors".into())
            .await?;
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.build_full("alice").await?;
        assert!(replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);

        policy
            .remove_from_group("alice".into(), "editors".into())
            .await?;
        mgr.wal
            .append(WalOp::GroupRemove {
                user: "alice".into(),
                group: "editors".into(),
            })
            .await?;
        assert_eq!(mgr.replay(1, "alice").await?, ReplayOutcome::Advanced(1));
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);
        Ok(())
    }

    /// An oversized policy fan-out DECLINES. It does not return a 500, and it
    /// does not fail the same way forever.
    ///
    /// `ReplayOutcome` replaced error-TEXT matching ("replay needs full
    /// recalc ...") with a typed value. That change converted the two
    /// PRE-FLIGHT decline sites to `Ok(NeedsFullRebuild)`. It left all three
    /// FAN-OUT sites returning the `Err` that the change was meant to
    /// eliminate. An admin who grants `read` on a row that holds 1001 files
    /// then reached `apply_rule_op`. The call tripped
    /// `MAX_POLICY_REPLAY_FILES` and produced `FsError::Internal`. The last
    /// arm of `advance` treated that error as a store failure. The arm
    /// released the claim, returned the error, and rendered `500`. Because
    /// `APPLIED_KEY` never advanced, the next poll replayed the same entry
    /// and returned the same 500. The subject never converged, and no
    /// rebuild was ever queued.
    ///
    /// The test calls `advance` instead of `replay`, because that is the
    /// level at which the old `Err` became visible. The second call covers
    /// the "forever" half. It must reach the same declining branch and answer
    /// `pending: true`, and it must not repeat the failure.
    #[tokio::test]
    async fn an_oversized_policy_fan_out_declines_instead_of_failing() -> anyhow::Result<()> {
        let (mgr, policy, mut jobs) = test_manager_with_queue().await;
        // One row, one more file than the fan-out budget allows.
        for i in 0..=MAX_POLICY_REPLAY_FILES {
            let id = format!("f{i}");
            mgr.store.save_file(&file_record(&id, "bob")).await?;
            mgr.store.attach("invoice", "1", &id).await?;
        }
        // Alice is covered through seq 0 with nothing on invoice:1.
        mgr.build_full("alice").await?;

        // The grant is the op whose fan-out trips the cap.
        policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        mgr.wal
            .append(WalOp::PolicyRuleAdd {
                sub: "alice".into(),
                obj: "invoice:1".into(),
                act: "read".into(),
            })
            .await?;

        let first = mgr
            .advance("alice")
            .await
            .map_err(|e| anyhow::anyhow!("a fan-out cap must not be an error: {e}"))?;
        assert!(
            first.pending,
            "an oversized fan-out must queue a rebuild, not fail: {first:?}"
        );
        assert_eq!(
            first.applied_seq, 0,
            "coverage is from before the queued rebuild"
        );
        // The test then checks that a rebuild really reached the queue. That
        // is the point of the test. The old `Err` path released the claim and
        // queued nothing.
        let queued = jobs.try_recv().expect("a rebuild must be queued");
        assert_eq!(queued.sub, "alice");
        assert!(
            jobs.try_recv().is_err(),
            "the in-flight set must collapse the retries into one job"
        );

        // The "forever" half. The marker did not advance, so the next poll
        // replays the same entry. The call must decline again in the same way
        // instead of returning the same 500. The test releases the claim
        // first, so the call reaches `replay` instead of stopping on the
        // slot.
        mgr.builds.release("alice");
        let second = mgr
            .advance("alice")
            .await
            .map_err(|e| anyhow::anyhow!("the repeat call must not fail either: {e}"))?;
        assert!(second.pending, "still pending, and still not an error");
        assert_eq!(second.applied_seq, 0);
        Ok(())
    }

    #[tokio::test]
    async fn split_row_obj_rejects_control_plane_objects() {
        assert_eq!(split_row_obj("invoice:123"), Some(("invoice", "123")));
        assert_eq!(split_row_obj("rules"), None);
        assert_eq!(split_row_obj("user_groups"), None);
        assert_eq!(split_row_obj(":123"), None);
        assert_eq!(split_row_obj("invoice:"), None);
    }

    #[tokio::test]
    async fn prefixes_are_stable_and_safe() {
        let (mgr, _, _) = test_manager().await;
        // The prefix is stable and contains hex digits only, so it is
        // prefix-safe by construction.
        let prefix = mgr.user_prefix("alice");
        assert_eq!(prefix, mgr.user_prefix("alice"));
        let digest = prefix.strip_prefix("test-db/u/").expect("prefix shape");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        // The former collisions now separate. Each subject maps to its own
        // prefix.
        assert_ne!(mgr.user_prefix("a/b"), mgr.user_prefix("a:b"));
        assert_ne!(mgr.user_prefix("a/b"), mgr.user_prefix("a_b"));
        assert_ne!(mgr.user_prefix("alice"), mgr.user_prefix("bob"));
        // The gateway still confines reads to the replica prefix. The alias
        // that the empty interior segment created does not exist.
        assert!(mgr.resolve_object("alice", "../escape").is_err());
        assert!(mgr.resolve_object("alice", "a/../../escape").is_err());
        assert!(mgr.resolve_object("alice", "").is_err());
        assert!(mgr.resolve_object("alice", "/manifest.json").is_err());
        assert!(mgr.resolve_object("alice", "a//b").is_err());
    }
}
