//! Per-user filtered replicas on stable `OxKvStore` prefixes.
//!
//! The master [`FsStore`] remains the sole write path. Each user owns one
//! replica prefix (`{db_prefix}/u/{sha256-hex(sub)}/`) holding their
//! filtered file set. Builds filter into a RAM scratch store, diff against
//! the live replica, and commit the diff plus the coverage marker in ONE
//! transaction: crash before commit leaves the old state untouched (oxkv
//! replays only listed WALs on open), and an empty diff commits nothing at
//! all.
//!
//! The `sync:applied` sentinel inside the prefix tracks WAL coverage, so no
//! sidecar pointer object exists. Small deltas replay with idempotent
//! re-apply (sentinel written last); legacy policy marks and large ranges
//! fall back to full recalc, while rich rule/group ops resync only the
//! affected user/row. Served read-only via `/sync/db/`; wasm clients open
//! an `OxKvReader` over the prefix and follow the live manifest.

use crate::fs::error::FsError;
use crate::fs::store::{FsStore, KvPages};
use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, Authorizer};
use crate::records::WalOp;
use oxkv::{GetSet as _, OxKvReader, Store as _, Transaction as _};

use super::wal::Wal;

/// Sync-version marker stored inside every replica prefix.
const APPLIED_KEY: &str = "sync:applied";

/// Upper bound for file/relation ops replayed incrementally.
const MAX_REPLAY_OPS: usize = 1000;

/// Upper bound for files touched by one policy op before falling back to
/// a full recalc (keeps one group/row change from scanning the store).
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
    /// The read-only [`Authorizer`](crate::policy::Authorizer), not a
    /// [`PolicyEngine`](crate::policy::PolicyEngine): a snapshot build
    /// only ever *asks* whether the caller may read a row. Holding the full
    /// engine here — and exposing it as a public field — would hand every
    /// consumer of `SnapshotManager` a write-capable engine, which is the
    /// bypass `PolicyEngine::enforcer` being private exists to prevent.
    pub(crate) policy: Authorizer,
    /// Shared object store backing every replica prefix.
    pub(crate) object_store: std::sync::Arc<dyn object_store::ObjectStore>,
    /// Root prefix for replica prefixes (e.g. `"oxkv"`).
    pub(crate) db_prefix: String,
    /// Skip the oxkv storage probe (tests on `InMemory`).
    skip_probe: bool,
    /// SST block cache shared by every replica open from this manager.
    ///
    /// Writer/reader opens used to build a private cold cache per call
    /// (dropped with the handle); sharing keeps hot SSTs resident across
    /// rebuilds. Clones share the state, matching the build queue.
    sst_cache: oxkv::LruCache<String, std::sync::Arc<oxkv::SstFile>>,
    /// Subjects with a rebuild queued or running, plus the work channel.
    builds: std::sync::Arc<BuildQueue>,
}

/// One subject's queued rebuild.
#[derive(Debug, Clone)]
pub struct BuildJob {
    /// Stable hash of the OIDC subject; see [`SnapshotManager::user_prefix`].
    sub: String,
    /// WAL head observed when the job was queued.
    ///
    /// Advisory only, kept for log lines: a worker re-reads the head before
    /// building, so a job that waited behind a long build covers *more* than
    /// this rather than less.
    head: u64,
}

/// Tracks which subjects have a rebuild in flight, and hands work to the
/// pool that runs them.
///
/// This replaces a process-wide `Mutex<()>` that both `replay` and
/// `build_full` held for their whole duration. That lock was a convoy: a
/// full rebuild for one user blocked an incremental replay for a *different*
/// user -- typically milliseconds of work -- behind a job that can take
/// minutes. Users are independent here, each replica being its own S3 prefix,
/// so the guard only ever needed to be per subject.
///
/// The in-flight set doubles as the coalescing point. `POST /sync/sync` is
/// driven by client polling, so a deploy or a busy period produces many
/// requests per user for the same pending rebuild; without this each one
/// would run a full scan to discover there was nothing to do.
///
/// Created by the host, which keeps the receiving end and drains it with
/// [`BuildPool::spawn`]. It is not created inside [`SnapshotManager::new`]
/// because a `Clone`d manager in a test would otherwise silently start
/// background work.
pub struct BuildQueue {
    inflight: std::sync::Mutex<std::collections::HashSet<String>>,
    jobs: tokio::sync::mpsc::UnboundedSender<BuildJob>,
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

    /// Takes the single in-flight slot for `sub`, or reports it is taken.
    ///
    /// `false` means another request or worker is already advancing this
    /// user's replica, which is the coalescing case rather than an error: the
    /// caller reports current coverage and lets the client poll.
    fn claim(&self, sub: &str) -> bool {
        self.inflight().insert(sub.to_string())
    }

    /// Releases the slot. The caller must hold a claim from [`Self::claim`].
    fn release(&self, sub: &str) {
        self.inflight().remove(sub);
    }

    /// The in-flight set, recovering from a poisoned lock.
    ///
    /// The set holds subject strings and nothing else, so a panic in some
    /// unrelated holder cannot leave it inconsistent -- the worst case is a
    /// stale entry, which costs one redundant rebuild. Propagating the poison
    /// would turn that into a permanently broken queue, so the inner value is
    /// taken regardless.
    fn inflight(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<String>> {
        self.inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Hands a claimed subject to the worker pool.
    ///
    /// Returns `false` if no pool is draining the queue, in which case the
    /// claim is released so the next request retries rather than leaving the
    /// subject permanently marked in-flight and never rebuilt.
    fn dispatch(&self, sub: &str, head: u64) -> bool {
        if self
            .jobs
            .send(BuildJob {
                sub: sub.to_string(),
                head,
            })
            .is_ok()
        {
            return true;
        }
        self.release(sub);
        false
    }
}

/// Drains a [`BuildQueue`], running the full rebuilds it carries.
///
/// Separate from [`SnapshotManager`] because spawning tasks is a side effect
/// a `Clone` should not carry, mirroring [`crate::fs::gc::spawn`].
pub struct BuildPool {
    rx: tokio::sync::mpsc::UnboundedReceiver<BuildJob>,
}

impl BuildPool {
    /// Wraps the receiving end of a [`BuildQueue`].
    pub fn new(rx: tokio::sync::mpsc::UnboundedReceiver<BuildJob>) -> Self {
        Self { rx }
    }

    /// Starts `workers` tasks, each running queued rebuilds to completion.
    ///
    /// `workers` is deliberately small. A build streams its diff (see
    /// [`SnapshotManager::build_full`]) so its memory tracks the size of a
    /// *change* rather than of a replica, but it still scans the master and
    /// writes to S3 -- so this bounds object-store pressure as much as CPU.
    /// One worker is a valid configuration and a reasonable default.
    pub fn spawn(self, manager: std::sync::Arc<SnapshotManager>, workers: usize) {
        // A single receiver cannot be moved into N tasks, so the pool shares
        // one behind a short-held lock. `recv` is awaited outside the guard --
        // the guard only exists to pick which worker takes the next job, and
        // holding it across the await would serialize the workers into one.
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
                    // The request that queued this has already returned, so the
                    // log is the only remaining channel for a failure. The
                    // slot is released either way, so the next `advance`
                    // retries rather than finding the subject wedged.
                    let result = manager.build_full(&job.sub).await;
                    if let Err(e) = &result {
                        tracing::warn!(
                            "background replica rebuild for {} failed: {e}",
                            manager.user_prefix(&job.sub)
                        );
                    }
                    tracing::debug!(
                        "rebuild worker {worker} finished {} (queued at head {}, now {})",
                        job.sub,
                        job.head,
                        result.unwrap_or_default()
                    );
                    manager.builds.release(&job.sub);
                }
            });
        }
    }
}

/// The collaborators a [`SnapshotManager`] reads master state through.
///
/// Grouped so [`SnapshotManager::new`] is three arguments instead of six,
/// and so adding a fourth source of master state is a field addition rather
/// than a signature change for every caller.
pub struct SnapshotDeps {
    /// Change feed to replay from.
    pub wal: Wal,
    /// Master file store (reads only; the master is written through
    /// [`FsEngine`](crate::fs::FsEngine)).
    pub store: FsStore,
    /// Read-only policy view for row visibility checks.
    pub policy: Authorizer,
    /// Object store backing every replica prefix.
    pub object_store: std::sync::Arc<dyn object_store::ObjectStore>,
    /// Rebuild queue, shared with the [`BuildPool`] that drains it.
    ///
    /// Taken rather than created here so the host can hold the receiving end
    /// and decide when background work starts. See [`BuildQueue::new`].
    pub builds: BuildQueue,
}

/// What a replica prefix is opened against.
///
/// An enum rather than a `skip_probe: bool`, because the flag was the sixth
/// positional argument of a six-argument constructor and nothing at the call
/// site said what `true` meant. Passing the wrong one is not a compile error
/// and not a wrong answer either -- it is a probe run against a backend that
/// has no conditional writes, or a skipped probe against real S3, and the
/// second of those loses the check that guards the `manifest.json` CAS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaBackend {
    /// A real object store. Opens probe for conditional writes.
    ObjectStore,
    /// `InMemory`, which has no conditional-write probe to run. Tests only.
    InMemory,
}

impl SnapshotManager {
    /// Create a manager.
    ///
    /// Takes an [`Authorizer`] rather than a
    /// [`PolicyEngine`](crate::policy::PolicyEngine): replicas are a read
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
/// A decline is not an error, and that distinction is the whole point of the
/// type. "This delta cannot be replayed incrementally, recalculate instead"
/// and "the store rejected the write" are different facts, and the previous
/// encoding signalled the first with `FsError::Internal("replay needs full
/// recalc ...")`. Matching on that string is the same fragility as the
/// `detail.contains("fenced")` search this crate already removed: reword the
/// message and a real store failure silently becomes a queued rebuild, or a
/// legitimate decline starts returning 500s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// The replica now covers this WAL sequence.
    Advanced(u64),
    /// This change cannot be replayed incrementally. A full rebuild is
    /// required: a legacy policy mark, a delta over `MAX_REPLAY_OPS`, or a
    /// replica that was never built.
    NeedsFullRebuild,
}

/// How far a replica got, and whether more is still to come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvanceOutcome {
    /// WAL sequence the replica now covers.
    pub applied_seq: u64,
    /// True when a full rebuild was queued (or is already queued) and the
    /// caller is looking at coverage from before it.
    ///
    /// Distinct from `applied_seq < head`: a rebuild that was already in
    /// flight also leaves the caller short of the head, and a client that
    /// cannot tell "queued for you" from "someone else got there first" cannot
    /// decide how long to keep polling.
    pub pending: bool,
}

impl SnapshotManager {
    /// Advances `sub`'s replica toward the WAL head.
    ///
    /// Three outcomes, in the order they are tried:
    ///
    /// 1. Already covered. Nothing to do.
    /// 2. A bounded incremental [`replay`](Self::replay) succeeds. Run inline,
    ///    because it is milliseconds of work and the caller wants the result
    ///    now.
    /// 3. Otherwise a full rebuild is needed, and it is *queued* rather than
    ///    run. A rebuild scans the whole master and can take minutes; doing
    ///    that inside a request held a connection for its duration and blocked
    ///    every other user's sync behind it. The caller gets
    ///    `pending: true` and polls [`GET /sync/status`](crate::sync::route) to
    ///    watch coverage move.
    ///
    /// Concurrent calls for the same subject collapse to one: the second
    /// returns the current coverage as `pending` rather than queueing a
    /// duplicate scan. Different subjects are independent.
    pub async fn advance(&self, sub: &str) -> Result<AdvanceOutcome, FsError> {
        let head = self.wal.head().await?;
        let applied = self.load_applied(sub).await?;
        if let Some(covered) = applied
            && covered >= head
        {
            return Ok(AdvanceOutcome {
                applied_seq: covered,
                pending: false,
            });
        }

        // No claim means someone else is already advancing this subject.
        if !self.builds.claim(sub) {
            return Ok(AdvanceOutcome {
                applied_seq: applied.unwrap_or_default(),
                pending: true,
            });
        }

        match self.replay(head, sub).await {
            Ok(ReplayOutcome::Advanced(seq)) => {
                self.builds.release(sub);
                Ok(AdvanceOutcome {
                    applied_seq: seq,
                    pending: false,
                })
            }
            Ok(ReplayOutcome::NeedsFullRebuild) => {
                // The claim is handed to the pool, which releases it when the
                // build finishes.
                if !self.builds.dispatch(sub, head) {
                    // No pool is draining the queue, so nothing will ever run
                    // this build and every future poll for this subject queues
                    // another. That is a deployment mistake -- `BuildPool::spawn`
                    // was never called -- and it fails silently otherwise, so
                    // it is logged at `error` rather than left for a client to
                    // discover by polling.
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
            // A fencing loss here means a concurrent builder published this
            // replica first. Adopt their coverage rather than failing, the
            // same recovery the full-rebuild path used before it moved into
            // the pool.
            Err(e) if e.is_fencing_loss() => {
                self.builds.release(sub);
                Ok(AdvanceOutcome {
                    applied_seq: self.load_applied(sub).await?.ok_or(e)?,
                    pending: false,
                })
            }
            Err(e) => {
                self.builds.release(sub);
                Err(e)
            }
        }
    }

    /// Replica prefix for `sub` (`{db}/u/{sha256-hex(sub)}`).    ///
    /// The digest keeps replica prefixes fixed-length and safe by
    /// construction (hex only): subjects are attacker-influenced OIDC
    /// values, so embedding them raw would allow traversal or collisions.
    pub fn user_prefix(&self, sub: &str) -> String {
        format!("{}/u/{}", self.db_prefix.trim_matches('/'), safe_sub(sub))
    }

    /// Full object key for `tail` inside the replica.
    ///
    /// Rejects path traversal (`..`) so the gateway cannot escape the
    /// replica prefix.
    pub fn resolve_object(&self, sub: &str, tail: &str) -> Result<String, FsError> {
        if tail.is_empty() || tail.split('/').any(|seg| seg == "..") {
            return Err(FsError::BadRequest("invalid object path".into()));
        }
        Ok(format!("{}/{tail}", self.user_prefix(sub)))
    }

    /// Reads the WAL coverage marker, or `None` when never built.
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

    /// Builds the replica for `sub` at current `wal` head.
    ///
    /// See the module docs for the atomicity contract. Returns the covered
    /// WAL head.
    pub async fn build_full(&self, sub: &str) -> Result<u64, FsError> {
        let head = self.wal.head().await?;
        // Converge the RAM mirror before the bulk scan (no-op unless
        // [database].mirror_master opted into the prototype).
        self.store.refresh_mirror().await?;

        let snap_prefix = format!(
            "snap-{}-{head}-{}",
            safe_sub(sub),
            &uuid::Uuid::now_v7().to_string()[..8]
        );
        let scratch = FsStore::new(crate::db::build_scratch_store(&snap_prefix).await);
        self.copy_filtered(sub, &scratch).await?;

        // One writer, used for three jobs: the live side of the diff, the
        // transaction the diff is staged in, and the handle the commit runs on.
        // Reading the live side through the writer rather than a separate
        // reader is safe because nothing has been written through it yet, so
        // its session overlay is empty and it observes exactly the committed
        // state the replica currently holds.
        let writer = self.open_writer(sub).await?;

        let mut desired = scratch.pages();
        let mut live = KvPages::owned(writer.clone());

        let tx = writer.begin_tx().map_err(store_err)?;
        let mut wrote = false;

        // The coverage marker is control metadata, not replica data. It lives
        // on the live side only -- it is written after the diff, below -- so
        // the merge has to step over it rather than read it as a key the
        // filter dropped and delete it.
        async fn next_data_key(live: &mut KvPages) -> Result<Option<oxkv::KeyValue>, FsError> {
            while let Some(kv) = live.next().await? {
                if kv.key != APPLIED_KEY {
                    return Ok(Some(kv));
                }
            }
            Ok(None)
        }

        // Merge-join. Both sides are key-ordered by construction, so this
        // holds one key per side rather than a map of the whole replica.
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
                    // Only on the desired side: a new or changed key.
                    std::cmp::Ordering::Less => {
                        tx.put_bytes(&a.key, &a.value).await.map_err(store_err)?;
                        wrote = true;
                    }
                    // Only on the live side: the filter dropped it, or the
                    // master no longer has it.
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

        // Coverage marker last, in the same transaction as the data. A crash
        // before commit leaves the previous state and its marker untouched, so
        // the next build simply redoes the work.
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
    /// Ops apply in order with visibility re-checked against current master
    /// state, then the coverage marker advances: re-applying converges, so a
    /// crash between ops heals on the next poll. Legacy policy marks (object
    /// only) and ranges over `MAX_REPLAY_OPS` entries fall back to a full
    /// recalc via `Err`; rich rule/group ops resync only the affected
    /// user/row (irrelevant users/objects skip, oversized fan-out falls
    /// back via `Err`).
    pub async fn replay(&self, head: u64, sub: &str) -> Result<ReplayOutcome, FsError> {
        let Some(applied) = self.load_applied(sub).await? else {
            return Ok(ReplayOutcome::NeedsFullRebuild);
        };
        if applied >= head {
            return Ok(ReplayOutcome::Advanced(applied));
        }
        let entries = self.wal.range(applied + 1, head).await?;
        if entries.len() > MAX_REPLAY_OPS || entries.iter().any(|e| e.op.is_legacy_policy_mark()) {
            return Ok(ReplayOutcome::NeedsFullRebuild);
        }
        let writer = self.open_writer(sub).await?;
        let dst = FsStore::new(writer.clone());
        for entry in &entries {
            self.apply_op(sub, &dst, &entry.op).await?;
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

    /// Opens the replica writer (acquires/takes over the prefix epoch).
    ///
    /// A fresh handle is taken per build/replay rather than cached for the
    /// manager's lifetime: replicas are read-mostly and idle long enough
    /// for a cached writer to sit on a stale epoch, and `build_lock`
    /// serializes open→write→commit so two handles on one prefix are never
    /// live at the same time (the `db::build_s3_store` contract holds for
    /// every *concurrent* writer; it is a new session per *sequential*
    /// build, exactly like the `policy export` CLI).
    async fn open_writer(&self, sub: &str) -> Result<oxkv::OxKvStore, FsError> {
        oxkv::OxKvStore::builder()
            .with_object_store(self.object_store.clone())
            .with_prefix(oxkv::ObjectPath::from(self.user_prefix(sub).as_str()))
            .skip_probe(self.skip_probe)
            .build_with_cache(self.sst_cache.clone())
            .await
            .map_err(FsError::from)
    }

    /// Opens a read-only follower over the replica (no ownership taken).
    ///
    /// Followers never take an epoch, so they cannot fence the writer; the
    /// shared SST cache keeps repeated opens from re-downloading hot
    /// segments.
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
    /// Visibility is re-checked against current master state, so applying
    /// is idempotent: files that vanished or turned unreadable are skipped.
    async fn apply_op(&self, sub: &str, dst: &FsStore, op: &WalOp) -> Result<(), FsError> {
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
                return Err(FsError::Internal(
                    "legacy policy op reached apply (needs full recalc)".into(),
                ));
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
                self.apply_rule_op(sub, dst, rule_sub, obj, act).await?;
            }
            WalOp::GroupAdd { user, group } | WalOp::GroupRemove { user, group } => {
                self.apply_membership_op(sub, dst, user, group).await?;
            }
            WalOp::GroupDelete { group } => {
                self.apply_group_delete(sub, dst, group).await?;
            }
        }
        Ok(())
    }

    /// Resyncs the single row a permission rule changed.
    ///
    /// Skips fast: non-`read` actions never affect read replicas,
    /// non-row objects (`rules`, `user_groups`, …) hold no files, direct
    /// rules for other users cannot match, and group rules skip when `sub`
    /// holds no current membership. Otherwise every file on the row is
    /// re-checked via [`Self::resync_file`] (idempotent: converge, never
    /// over-delete). Fan-out over [`MAX_POLICY_REPLAY_FILES`] falls back
    /// via `Err`.
    async fn apply_rule_op(
        &self,
        sub: &str,
        dst: &FsStore,
        rule_sub: &str,
        obj: &str,
        act: &str,
    ) -> Result<(), FsError> {
        if !act.eq_ignore_ascii_case("read") {
            return Ok(());
        }
        let Some((row_type, row_id)) = split_row_obj(obj) else {
            return Ok(());
        };
        if rule_sub != sub
            && !self
                .policy
                .get_groups_of_user(sub)
                .await
                .iter()
                .any(|g| g == rule_sub)
        {
            return Ok(());
        }
        let files = self.store.files_for_row(row_type, row_id).await?;
        if files.len() > MAX_POLICY_REPLAY_FILES {
            return Err(FsError::Internal(
                "replay needs full recalc (policy fan-out too large)".into(),
            ));
        }
        for file_id in files {
            self.resync_file(sub, dst, row_type, row_id, &file_id)
                .await?;
        }
        Ok(())
    }

    /// Resyncs rows a membership change can affect (only when `user == sub`).
    ///
    /// Drops through when the change is for another user. For `sub` itself,
    /// every `read` row the group grants is resynced; groups with no row
    /// reads (e.g. `superadmin` on `rules`/`user_groups`) are a no-op.
    /// Oversized fan-out falls back via `Err`.
    async fn apply_membership_op(
        &self,
        sub: &str,
        dst: &FsStore,
        user: &str,
        group: &str,
    ) -> Result<(), FsError> {
        if user != sub {
            return Ok(());
        }
        let rows = self.read_rows_for_group(group).await?;
        let mut total = 0usize;
        for (row_type, row_id) in rows {
            let files = self.store.files_for_row(&row_type, &row_id).await?;
            total += files.len();
            if total > MAX_POLICY_REPLAY_FILES {
                return Err(FsError::Internal(
                    "replay needs full recalc (policy fan-out too large)".into(),
                ));
            }
            for file_id in files {
                self.resync_file(sub, dst, &row_type, &row_id, &file_id)
                    .await?;
            }
        }
        Ok(())
    }

    /// Resyncs rows a deleted group could have exposed.
    ///
    /// Past membership is unknowable (links are already gone), so any group
    /// holding row `read` rules resyncs its rows: [`Self::resync_file`]
    /// re-checks current visibility, making over-application safe (files
    /// still visible via other rows stay, others converge to deleted).
    /// Groups with no row reads skip; oversized fan-out falls back via `Err`.
    async fn apply_group_delete(
        &self,
        sub: &str,
        dst: &FsStore,
        group: &str,
    ) -> Result<(), FsError> {
        let rows = self.read_rows_for_group(group).await?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut total = 0usize;
        for (row_type, row_id) in rows {
            let files = self.store.files_for_row(&row_type, &row_id).await?;
            total += files.len();
            if total > MAX_POLICY_REPLAY_FILES {
                return Err(FsError::Internal(
                    "replay needs full recalc (policy fan-out too large)".into(),
                ));
            }
            for file_id in files {
                self.resync_file(sub, dst, &row_type, &row_id, &file_id)
                    .await?;
            }
        }
        Ok(())
    }

    /// Converges one file on the replica after a policy change.
    ///
    /// Readable files are ensured present with the changed row attached
    /// (or detached when that row alone turned unreadable); files readable
    /// via no row are deleted. Missing master records delete the stale
    /// replica copy.
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

    /// Row `(type, id)` pairs `group` currently grants `read` on.
    async fn read_rows_for_group(&self, group: &str) -> Result<Vec<(String, String)>, FsError> {
        let mut out = Vec::new();
        for (obj, act) in self.policy.rules_for_subject(group).await {
            if !act.eq_ignore_ascii_case("read") {
                continue;
            }
            if let Some((ty, rid)) = split_row_obj(&obj) {
                out.push((ty.to_string(), rid.to_string()));
            }
        }
        Ok(out)
    }

    /// Writes the caller's visible file set into `dst`.
    ///
    /// One pass over the master listing: the record in hand answers the
    /// owner check (no re-read), and one rows scan serves both the
    /// visibility check and the attach loop. Previously each file cost
    /// a re-read plus two full-store scans (one inside `can_read`, one
    /// for attach) on top of the listing itself.
    async fn copy_filtered(&self, sub: &str, dst: &FsStore) -> Result<(), FsError> {
        // Paged, not collected. `list_files` returns every record in the
        // master as a `Vec<FileRecord>`, which for a large master is the
        // single largest allocation in the rebuild and is entirely
        // unnecessary: the filter below decides per record and keeps none of
        // them. The key layout stays in `fs::store`; this only drives it.
        let mut scan = self.store.pages();
        while let Some(rec) = self.store.next_file(&mut scan).await? {
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
        Ok(())
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
/// Row objects are `{type}:{id}`; control-plane objects (`rules`,
/// `user_groups`, …) contain no colon and return `None` so policy replay
/// can skip them without touching storage.
fn split_row_obj(obj: &str) -> Option<(&str, &str)> {
    let (ty, rid) = obj.split_once(':')?;
    if ty.is_empty() || rid.is_empty() {
        return None;
    }
    Some((ty, rid))
}

/// Maps a subject to a prefix-safe identifier.
///
/// Subjects are attacker-influenced (OIDC `sub`), so a lossy replace is
/// not enough: `a/b`, `a:b`, and `a_b` would all collide on one replica
/// prefix and leak data across users. The SHA-256 hex digest is
/// collision-resistant, fixed-length, and prefix-safe by construction
/// (lowercase hex only, no separators or traversal sequences).
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

    /// Builds a manager plus the [`PolicyEngine`] it reads through.
    ///
    /// The engine comes back alongside so tests can mutate policy and then
    /// let the replica *observe* the change, rather than mutating through
    /// the manager — the manager deliberately only holds a read-only
    /// `Authorizer`, which is the property under test.
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

    /// The backend choice maps to the probe flag, and the polarity is the
    /// whole risk.
    ///
    /// `skip_probe` was a bare `bool` in a six-argument constructor, so
    /// nothing at the call site distinguished "probe real S3" from "no
    /// probe". Getting it backwards is not a compile error and not a wrong
    /// answer: skipping the probe against real S3 drops the conditional-write
    /// check that guards the `manifest.json` CAS, which only shows up later
    /// as two builders believing they both won.
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

        // Simulate the logged write path: master mutation + WAL entry.
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

        // Detach then delete on master, each logged like the engines do.
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

    /// Concurrent `advance` calls for one subject collapse into one build.
    ///
    /// This is the coalescing property, and it is worth more than the queue
    /// itself. `POST /sync/sync` is driven by client polling, so a deploy or a
    /// busy period produces many requests per user for the same pending
    /// rebuild. Without the in-flight set each one runs a full master scan to
    /// discover there was nothing to do -- and because the old guard was a
    /// process-wide mutex, those scans also ran one at a time, so they queued
    /// up behind each other rather than at least being cheap.
    #[tokio::test]
    async fn concurrent_advances_for_one_subject_collapse() -> anyhow::Result<()> {
        let (mgr, _, _) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;

        // A never-built replica needs a full rebuild, so every call here wants
        // to queue one.
        let first = mgr.advance("alice").await?;
        assert!(first.pending, "a never-built replica must be queued");
        assert_eq!(first.applied_seq, 0, "nothing has been built yet");

        // The slot is held, so further calls must not queue again.
        for _ in 0..3 {
            let again = mgr.advance("alice").await?;
            assert!(
                again.pending,
                "still pending, but the claim should short-circuit the queue"
            );
            assert_eq!(again.applied_seq, 0);
        }

        // And only one job ever reached the queue.
        let (queue, mut rx) = BuildQueue::new();
        assert!(queue.dispatch("alice", 1), "queue accepts work");
        let job = rx.try_recv().expect("one job queued");
        assert_eq!(job.sub, "alice");
        assert!(rx.try_recv().is_err(), "exactly one job, not four");
        Ok(())
    }

    /// A rebuild that is already running leaves the caller short of the head,
    /// and `pending` has to say so.
    ///
    /// The distinction from `applied_seq < head` is the point: a client that
    /// cannot tell "queued for you" from "someone else got there first"
    /// cannot decide whether to keep polling or give up.
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
    /// The regression this pins: `replay` and `build_full` used to share one
    /// process-wide `Mutex<()>`, so a full rebuild for alice blocked a replay
    /// for bob behind work that can take minutes.
    #[tokio::test]
    async fn one_subject_does_not_block_another() -> anyhow::Result<()> {
        let (mgr, _, _) = test_manager().await;
        mgr.store.save_file(&file_record("f1", "alice")).await?;

        // Alice's rebuild takes the slot.
        assert!(mgr.builds.claim("alice"));

        // Bob is unaffected: he is not behind alice in any queue.
        assert!(mgr.builds.claim("bob"), "bob must not be blocked by alice");
        mgr.builds.release("bob");

        // Alice still cannot be double-built while her first is in flight.
        assert!(!mgr.builds.claim("alice"));
        mgr.builds.release("alice");
        assert!(mgr.builds.claim("alice"), "released slot is reusable");
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
        // Other user's membership, non-row object, and non-read action:
        // none can affect alice's read replica.
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
        // Bob's file on invoice:1; alice sees nothing yet.
        mgr.store.save_file(&file_record("f1", "bob")).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.build_full("alice").await?;
        assert!(!replica_has(&mem, &mgr, "alice", "fs:files:f1:meta").await);

        // Grant editors read on the row, add alice to editors (master
        // mutation first, WAL entries like the engines append).
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

    #[test]
    fn split_row_obj_rejects_control_plane_objects() {
        assert_eq!(split_row_obj("invoice:123"), Some(("invoice", "123")));
        assert_eq!(split_row_obj("rules"), None);
        assert_eq!(split_row_obj("user_groups"), None);
        assert_eq!(split_row_obj(":123"), None);
        assert_eq!(split_row_obj("invoice:"), None);
    }

    #[tokio::test]
    async fn prefixes_are_stable_and_safe() {
        let (mgr, _, _) = test_manager().await;
        // Stable and hex-only (prefix-safe by construction).
        let prefix = mgr.user_prefix("alice");
        assert_eq!(prefix, mgr.user_prefix("alice"));
        let digest = prefix.strip_prefix("test-db/u/").expect("prefix shape");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        // Former collisions now isolate: each maps to its own prefix.
        assert_ne!(mgr.user_prefix("a/b"), mgr.user_prefix("a:b"));
        assert_ne!(mgr.user_prefix("a/b"), mgr.user_prefix("a_b"));
        assert_ne!(mgr.user_prefix("alice"), mgr.user_prefix("bob"));
        // Gateway still confines reads to the replica prefix.
        assert!(mgr.resolve_object("alice", "../escape").is_err());
        assert!(mgr.resolve_object("alice", "a/../../escape").is_err());
        assert!(mgr.resolve_object("alice", "").is_err());
    }
}
