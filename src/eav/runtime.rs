//! The EAV background runtime.
//!
//! [`EavRuntime`] builds the schema, entity, and rule stores.
//! It then starts four loops.
//! One loop relays the entity outbox to the change feed.
//! One loop runs the matching rules.
//! One loop deletes old rule execution markers.
//! One loop fires the due timers.
//!
//! A host application builds the runtime with [`EavRuntime::build`].
//! The call takes the actions that the rule engine dispatches.
//! The binary passes an empty action list.
//!
//! The runtime has no HTTP routes and no concrete actions.
//! It adds no business rules.
//!
//! Each loop runs under its own supervisor.
//! A supervisor restarts its loop after an error or a panic.
//! It first sets the failure flag of its own loop.
//! It then logs the error or panic and sleeps for a backoff delay.
//! The delay starts at one second and doubles up to 60 seconds.
//! The backoff wait stops when the cancel token fires.
//! Tests use a 10 millisecond base.
//! A loop clears its flag after a pass succeeds.
//! The readiness probe reads the flags.
//! Readiness stays false while any loop flag is set.
//! The flags are a signal for the operator, not a stop switch.
//! The loops keep running after a flag is set.
//! [`EavRuntime::run`] returns only when the cancel token fires.
//! It then waits for all four loops to stop.
//! A normal cancellation does not set a flag.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use futures_util::FutureExt;
use tokio::task::JoinHandle;

use crate::CancelToken;
use crate::db::build_s3_store;
use crate::eav::entity::{AttributeValue, EntityStore};
use crate::eav::metrics::EavMetrics;
use crate::eav::replica::ReplicaStore;
use crate::eav::schema::SchemaRegistry;
use crate::fs::s3::S3ClientConfig;
use crate::rules::action::RuleAction;
use crate::rules::engine::RuleEngine;
use crate::rules::store::RuleStore;
use crate::sync::wal::Wal;

/// The first backoff delay after a background loop fails.
#[cfg(not(test))]
const LOOP_BACKOFF_BASE: Duration = Duration::from_secs(1);

/// The first backoff delay after a background loop fails.
///
/// Tests use a short delay, so a retry does not make the test slow.
#[cfg(test)]
const LOOP_BACKOFF_BASE: Duration = Duration::from_millis(10);

/// The largest backoff delay after a background loop fails.
const LOOP_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// The longest single sleep in a backoff wait.
///
/// A shorter slice lets a cancelled runtime stop before the full delay ends.
const BACKOFF_SLICE: Duration = Duration::from_millis(25);

/// One supervised background loop.
///
/// The value names the loop in a log line. It also selects the loop failure
/// flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopSlot {
    /// The outbox relay.
    OutboxRelay,
    /// The rule runner.
    RuleRunner,
    /// The execution marker cleanup.
    MarkerCleanup,
    /// The due timer pass.
    TimerPass,
}

impl LoopSlot {
    /// Returns the index of the loop failure flag.
    fn index(self) -> usize {
        self as usize
    }

    /// Returns the loop name for a log line.
    fn name(self) -> &'static str {
        match self {
            Self::OutboxRelay => "outbox relay",
            Self::RuleRunner => "rule runner",
            Self::MarkerCleanup => "marker cleanup",
            Self::TimerPass => "timer pass",
        }
    }
}

/// The failure state of the background loops.
///
/// A supervisor sets the flag of its own loop when a pass fails.
/// The loop clears the flag after a later pass succeeds.
/// `failed` is `true` while any flag is set.
/// The state is a signal for the operator, not a stop switch.
/// A normal cancellation does not set a flag.
#[derive(Debug, Default)]
pub struct LoopFailures {
    /// One flag for each supervised loop.
    loops: [AtomicBool; 4],
    /// Set when [`EavRuntime::run`] itself returns an error.
    runtime: AtomicBool,
}

impl LoopFailures {
    /// Returns `true` while any loop is failed.
    ///
    /// The call is cheap and does not block.
    /// The readiness probe reads the flags with [`Ordering::Relaxed`].
    pub fn failed(&self) -> bool {
        self.runtime.load(Ordering::Relaxed)
            || self.loops.iter().any(|flag| flag.load(Ordering::Relaxed))
    }

    /// Sets the flag of `slot`.
    fn set(&self, slot: LoopSlot) {
        self.loops[slot.index()].store(true, Ordering::Relaxed);
    }

    /// Clears the flag of `slot`.
    fn clear(&self, slot: LoopSlot) {
        self.loops[slot.index()].store(false, Ordering::Relaxed);
    }

    /// Sets the runtime flag.
    fn set_runtime(&self) {
        self.runtime.store(true, Ordering::Relaxed);
    }
}

/// Test-only controls for the background supervisors.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct RuntimeTestHooks {
    /// The number of supervisors that run now.
    active_loops: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl RuntimeTestHooks {
    /// Counts one started supervisor.
    fn enter_loop(&self) {
        self.active_loops.fetch_add(1, Ordering::SeqCst);
    }

    /// Counts one stopped supervisor.
    fn exit_loop(&self) {
        self.active_loops.fetch_sub(1, Ordering::SeqCst);
    }

    /// Returns the number of supervisors that run now.
    pub(crate) fn active_loops(&self) -> usize {
        self.active_loops.load(Ordering::SeqCst)
    }
}

/// Settings for the EAV background runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EavRuntimeConfig {
    /// The pause between outbox flushes.
    pub outbox_interval: Duration,
    /// The pause between rule runner polls.
    pub rule_poll_interval: Duration,
    /// The pause between execution marker cleanups.
    pub gc_interval: Duration,
    /// The retention window for execution markers.
    pub execution_retention: Duration,
    /// The pause between due timer passes.
    pub timer_interval: Duration,
    /// The largest number of due entities to read for each key.
    pub timer_batch: usize,
}

impl Default for EavRuntimeConfig {
    /// Returns the default settings.
    ///
    /// The outbox relay runs every second.
    /// The rule runner polls every 200 milliseconds.
    /// The marker cleanup runs every hour.
    /// Execution markers stay for 30 days.
    /// The timer pass runs every second and reads 100 entities for each key.
    fn default() -> Self {
        Self {
            outbox_interval: Duration::from_secs(1),
            rule_poll_interval: Duration::from_millis(200),
            gc_interval: Duration::from_secs(3_600),
            execution_retention: Duration::from_secs(2_592_000),
            timer_interval: Duration::from_secs(1),
            timer_batch: 100,
        }
    }
}

/// Test-only controls for a replica build.
///
/// The `limit` value is zero when the test did not set a limit.
/// The `read` value is the number of entities that the last build examined.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct ReplicaTestHooks {
    /// The entity limit for a build. Zero means the default limit.
    limit: Arc<std::sync::atomic::AtomicUsize>,
    /// The number of entities that the last build examined.
    read: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl ReplicaTestHooks {
    /// Sets the entity limit for a replica build.
    ///
    /// A value of zero restores the default limit.
    pub(crate) fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    /// Returns the entity limit for a replica build.
    ///
    /// The result is `None` when the test did not set a limit.
    pub(crate) fn limit(&self) -> Option<usize> {
        match self.limit.load(Ordering::Relaxed) {
            0 => None,
            limit => Some(limit),
        }
    }

    /// Resets the entity read counter.
    pub(crate) fn reset_read(&self) {
        self.read.store(0, Ordering::Relaxed);
    }

    /// Adds one to the entity read counter.
    pub(crate) fn count_read(&self) {
        self.read.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the entity read counter.
    pub(crate) fn read(&self) -> usize {
        self.read.load(Ordering::Relaxed)
    }
}

/// The EAV stores and their background loops.
///
/// The runtime holds one shared WAL.
/// The entity store writes its events to the WAL.
/// The rule engine reads the same WAL.
#[derive(Clone)]
pub struct EavRuntime {
    /// The versioned schema registry.
    schemas: SchemaRegistry,
    /// The validated entity store.
    entities: EntityStore,
    /// The durable rule store.
    rules: RuleStore,
    /// The stored per-user entity replicas.
    replicas: ReplicaStore,
    /// The rule runner.
    engine: RuleEngine,
    /// The shared change feed.
    wal: Wal,
    /// The OpenTelemetry instruments for the runtime.
    metrics: EavMetrics,
    /// The failure flag of each background loop.
    ///
    /// The flags start clear.
    /// A normal cancellation does not set a flag.
    failed: Arc<LoopFailures>,
    /// Test-only controls for the background supervisors.
    #[cfg(test)]
    runtime_test: RuntimeTestHooks,
    /// Test-only controls for a replica build.
    #[cfg(test)]
    replica_test: ReplicaTestHooks,
}

impl EavRuntime {
    /// Builds the EAV stores under `db_prefix`.
    ///
    /// The call creates one store for each EAV domain.
    /// The schema store lives at `{db_prefix}/eav/schema`.
    /// The entity store lives at `{db_prefix}/eav/entity`.
    /// The rule store lives at `{db_prefix}/eav/rules`.
    /// The replica store lives at `{db_prefix}/eav/replica`.
    /// The entity store writes its events to `wal`.
    /// The rule engine uses the given actions.
    /// The entity store checks that each `EntityRef` target exists when
    /// `check_entity_refs` is true.
    /// The rule engine runs an action only when the event depth is at most
    /// `max_causation_depth`.
    /// The rule engine accepts a condition script only when `script_enabled`
    /// is true.
    pub async fn build(
        s3: &S3ClientConfig,
        db_prefix: &str,
        wal: Wal,
        actions: Vec<Arc<dyn RuleAction>>,
        check_entity_refs: bool,
        max_causation_depth: u32,
        script_enabled: bool,
    ) -> anyhow::Result<Self> {
        let schema_store = build_s3_store(s3, &domain_prefix(db_prefix, "schema"))
            .await
            .context("build the EAV schema store")?;
        let entity_store = build_s3_store(s3, &domain_prefix(db_prefix, "entity"))
            .await
            .context("build the EAV entity store")?;
        let rule_store = build_s3_store(s3, &rule_store_prefix(db_prefix))
            .await
            .context("build the EAV rule store")?;
        let replica_store = build_s3_store(s3, &domain_prefix(db_prefix, "replica"))
            .await
            .context("build the EAV replica store")?;

        let schemas = SchemaRegistry::new(schema_store);
        let entities = EntityStore::new(entity_store, schemas.clone())
            .with_change_sink(Arc::new(wal.clone()))
            .with_entity_ref_check(check_entity_refs);
        let rules = RuleStore::new(rule_store);
        let replicas = ReplicaStore::new(replica_store);
        let metrics = EavMetrics::global();
        let engine = RuleEngine::new(rules.clone(), entities.clone(), actions)
            .context("build the EAV rule engine")?
            .with_max_causation_depth(max_causation_depth)
            .with_script_enabled(script_enabled)
            .with_observer(Arc::new(metrics.clone()));

        Ok(Self {
            schemas,
            entities,
            rules,
            replicas,
            engine,
            wal,
            metrics,
            failed: Arc::new(LoopFailures::default()),
            #[cfg(test)]
            runtime_test: RuntimeTestHooks::default(),
            #[cfg(test)]
            replica_test: ReplicaTestHooks::default(),
        })
    }

    /// Returns the schema registry.
    pub fn schemas(&self) -> &SchemaRegistry {
        &self.schemas
    }

    /// Returns the entity store.
    pub fn entities(&self) -> &EntityStore {
        &self.entities
    }

    /// Returns the rule store.
    pub fn rules(&self) -> &RuleStore {
        &self.rules
    }

    /// Returns the stored per-user entity replicas.
    pub fn replicas(&self) -> &ReplicaStore {
        &self.replicas
    }

    /// Returns the test-only controls for a replica build.
    #[cfg(test)]
    pub(crate) fn replica_test(&self) -> &ReplicaTestHooks {
        &self.replica_test
    }

    /// Returns the rule engine.
    pub fn engine(&self) -> &RuleEngine {
        &self.engine
    }

    /// Returns the shared change feed.
    pub fn wal(&self) -> &Wal {
        &self.wal
    }

    /// Returns the runtime metrics.
    pub fn metrics(&self) -> &EavMetrics {
        &self.metrics
    }

    /// Returns `true` while any background loop is failed.
    ///
    /// The call is cheap and does not block.
    pub fn failed(&self) -> bool {
        self.failed.failed()
    }

    /// Returns the shared loop failure state.
    ///
    /// The state starts clear.
    /// A supervisor sets the flag of its loop when a pass returns an error or
    /// panics.
    /// The loop clears its flag after a later pass succeeds.
    /// Readiness stays false while any loop flag is set.
    /// The state is a signal for the operator, not a stop switch.
    /// The loops keep running after a flag is set.
    /// A normal cancellation does not set a flag.
    ///
    /// The call is cheap and does not block.
    /// The readiness probe reads the flags with [`Ordering::Relaxed`].
    pub fn loop_failures(&self) -> Arc<LoopFailures> {
        self.failed.clone()
    }

    /// Sets the failure flag of `slot`.
    fn mark_loop_failed(&self, slot: LoopSlot) {
        self.failed.set(slot);
    }

    /// Clears the failure flag of `slot`.
    fn mark_loop_ok(&self, slot: LoopSlot) {
        self.failed.clear(slot);
    }

    /// Returns the test-only controls for the background supervisors.
    #[cfg(test)]
    pub(crate) fn runtime_test(&self) -> &RuntimeTestHooks {
        &self.runtime_test
    }

    /// Emits a timer event for each due timestamp value and returns the count.
    ///
    /// The call reads every time index key.
    /// For each key it reads at most `limit` due entities.
    /// The call emits the timer event first.
    /// It then retires the time index row and writes the fired marker in one
    /// transaction.
    /// A retire that returns `false` means the value changed after the read,
    /// and the call does not count the timer as emitted.
    /// When a fired marker already exists for a due value, the call retires
    /// the row without an event.
    /// That drain removes rows that fired before retirement existed, so an
    /// upgraded store recovers.
    /// A failed retire returns the error.
    /// The next pass then emits the same event again.
    /// The event is already written, and a duplicate event is idempotent.
    /// The rule engine execution marker stops a duplicate action.
    pub async fn fire_due_timers(&self, now: i64, limit: usize) -> anyhow::Result<usize> {
        let mut emitted = 0;
        let mut due_count = 0;
        for key in self
            .entities
            .time_keys()
            .await
            .context("read the EAV time keys")?
        {
            let due = self
                .entities
                .list_due(&key, now, limit)
                .await
                .context("list the due EAV entities")?;
            due_count += due.len() as u64;
            for entity in due {
                let Some(AttributeValue::Timestamp(due_at)) = entity.attributes.get(&key) else {
                    continue;
                };
                let due_at = *due_at;
                if self
                    .entities
                    .is_timer_fired(&entity.id, &key, due_at)
                    .await
                    .context("read the EAV timer marker")?
                {
                    // The row fired before the timer retire existed.
                    // Remove it without a second event.
                    self.entities
                        .retire_timer(&entity.id, &key, due_at)
                        .await
                        .context("retire the EAV timer row")?;
                    continue;
                }
                self.entities
                    .emit_timer(&entity, &key, due_at, now)
                    .await
                    .context("emit an EAV timer event")?;
                let retired = self
                    .entities
                    .retire_timer(&entity.id, &key, due_at)
                    .await
                    .context("retire the EAV timer row")?;
                // A false result means the value changed after the read.
                // The event stays idempotent, and the next pass reads the new value.
                emitted += usize::from(retired);
            }
        }
        self.metrics.record_timer_due(due_count);
        Ok(emitted)
    }

    /// Runs the outbox relay, the rule runner, the marker cleanup, and the
    /// timer pass under supervision until `cancel` fires.
    ///
    /// The call runs all four loops at the same time.
    /// Each loop has its own supervisor.
    /// When a loop returns an error or panics, its supervisor does four
    /// things.
    /// It sets the failure flag of that loop.
    /// It logs the error or panic with the loop name at `error` level.
    /// It sleeps for the backoff delay.
    /// It then calls the loop again.
    /// The wait stops when cancellation fires.
    /// The delay starts at one second and doubles up to 60 seconds.
    /// Tests use a 10 millisecond base.
    /// An error in one loop does not stop the other loops or the remaining
    /// work of that loop.
    /// A loop clears its flag after a pass succeeds.
    /// The flags are a signal for the operator, not a stop switch.
    /// The call returns `Ok(())` only when `cancel` is cancelled.
    /// It waits for all four supervisors to stop before it returns.
    /// A normal cancellation does not set a flag.
    ///
    /// The outbox relay flushes the pending entity events.
    /// The rule runner tails the shared change feed.
    /// The marker cleanup deletes old execution markers.
    /// The timer pass emits the due timer events.
    pub async fn run<C: CancelToken>(
        &self,
        cancel: C,
        config: EavRuntimeConfig,
    ) -> anyhow::Result<()> {
        let relay = self.supervise(LoopSlot::OutboxRelay, cancel.clone(), {
            let runtime = self.clone();
            move |token| {
                let runtime = runtime.clone();
                async move { runtime.run_outbox(token, config.outbox_interval).await }
            }
        });
        let runner = self.supervise(LoopSlot::RuleRunner, cancel.clone(), {
            let runtime = self.clone();
            move |token| {
                let runtime = runtime.clone();
                async move {
                    runtime
                        .run_rule_runner(token, config.rule_poll_interval)
                        .await
                }
            }
        });
        let cleanup = self.supervise(LoopSlot::MarkerCleanup, cancel.clone(), {
            let runtime = self.clone();
            move |token| {
                let runtime = runtime.clone();
                async move {
                    runtime
                        .run_execution_gc(token, config.gc_interval, config.execution_retention)
                        .await
                }
            }
        });
        let timers = self.supervise(LoopSlot::TimerPass, cancel.clone(), {
            let runtime = self.clone();
            move |token| {
                let runtime = runtime.clone();
                async move {
                    runtime
                        .run_timers(token, config.timer_interval, config.timer_batch)
                        .await
                }
            }
        });
        // Drive every supervisor to completion. A `select!` would return on
        // the first cancelled loop and drop the other three mid-await.
        let (relay, runner, cleanup, timers) = tokio::join!(relay, runner, cleanup, timers);
        relay?;
        runner?;
        cleanup?;
        timers?;
        Ok(())
    }

    /// Runs one background loop under supervision until `cancel` fires.
    ///
    /// The call runs `work`.
    /// It catches a panic from `work`, so one failed pass does not stop the
    /// supervisor.
    /// When `work` returns an error or panics, the call does four things.
    /// It sets the failure flag of `slot`.
    /// It logs the error or panic with the loop name.
    /// It sleeps for the backoff delay.
    /// It runs `work` again.
    /// The delay starts at [`LOOP_BACKOFF_BASE`] and doubles up to
    /// [`LOOP_BACKOFF_MAX`].
    /// The backoff wait stops when the cancel token fires, and the call then
    /// returns `Ok(())`.
    /// When `work` returns `Ok(())` before cancellation, the call clears the
    /// flag and returns.
    /// The flags are a signal for the operator, not a stop switch.
    /// The call keeps running after it sets a flag.
    /// A normal cancellation returns `Ok(())` and does not set a flag.
    async fn supervise<C, F, Fut>(
        &self,
        slot: LoopSlot,
        cancel: C,
        mut work: F,
    ) -> anyhow::Result<()>
    where
        C: CancelToken,
        F: FnMut(C) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        let mut delay = LOOP_BACKOFF_BASE;
        #[cfg(test)]
        self.runtime_test.enter_loop();
        let outcome = loop {
            let pass = AssertUnwindSafe(work(cancel.clone())).catch_unwind().await;
            match pass {
                Ok(Ok(())) => {
                    if !cancel.is_cancelled() {
                        self.mark_loop_ok(slot);
                    }
                    break Ok(());
                }
                Ok(Err(error)) => {
                    if cancel.is_cancelled() {
                        break Ok(());
                    }
                    self.mark_loop_failed(slot);
                    tracing::error!(
                        loop_name = slot.name(),
                        ?error,
                        "EAV background loop failed"
                    );
                }
                Err(payload) => {
                    if cancel.is_cancelled() {
                        break Ok(());
                    }
                    self.mark_loop_failed(slot);
                    tracing::error!(
                        loop_name = slot.name(),
                        panic = %panic_message(payload.as_ref()),
                        "EAV background loop panicked"
                    );
                }
            }
            if sleep_unless_cancelled(&cancel, delay).await {
                break Ok(());
            }
            delay = delay.saturating_mul(2).min(LOOP_BACKOFF_MAX);
        };
        #[cfg(test)]
        self.runtime_test.exit_loop();
        outcome
    }

    /// Starts [`EavRuntime::run`] on a Tokio task.
    ///
    /// [`EavRuntime::run`] returns only when the cancel token fires, so a
    /// normal handle result is `Ok(())` after cancellation.
    /// Each loop supervisor sets the failure flag of its loop when a pass
    /// fails.
    /// The call also sets the runtime flag if [`EavRuntime::run`] itself
    /// returns an error.
    /// A caller can await the handle during shutdown.
    pub fn spawn<C: CancelToken + Send + 'static>(
        &self,
        cancel: C,
        config: EavRuntimeConfig,
    ) -> JoinHandle<anyhow::Result<()>> {
        let runtime = self.clone();
        tokio::spawn(async move {
            let result = runtime.run(cancel, config).await;
            if let Err(error) = &result {
                runtime.failed.set_runtime();
                tracing::error!(?error, "EAV runtime failed");
            }
            result
        })
    }

    /// Flushes the entity outbox until `cancel` fires.
    ///
    /// The call sleeps for `interval` between flushes.
    /// It checks cancellation after each sleep and before each flush.
    async fn run_outbox<C: CancelToken>(
        &self,
        cancel: C,
        interval: Duration,
    ) -> anyhow::Result<()> {
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            tokio::time::sleep(interval).await;
            if cancel.is_cancelled() {
                return Ok(());
            }
            let started = Instant::now();
            let flushed = self.entities.flush_outbox().await;
            let elapsed = started.elapsed();
            match flushed {
                Ok(count) => {
                    self.mark_loop_ok(LoopSlot::OutboxRelay);
                    self.metrics.record_outbox_flush(count as u64, elapsed);
                    if let Ok(pending) = self.entities.outbox_count().await {
                        self.metrics.record_outbox_pending(pending as u64);
                    }
                }
                Err(error) => {
                    self.metrics.record_outbox_failure();
                    return Err(error).context("flush the EAV entity outbox");
                }
            }
        }
    }

    /// Runs the rule engine until `cancel` fires.
    ///
    /// The engine call returns only on an error or on cancellation.
    /// The call treats one full poll interval without an error as a
    /// successful pass, and clears the failure flag of the rule runner.
    /// A zero interval becomes one second.
    /// A failed engine call returns the error to the supervisor.
    async fn run_rule_runner<C: CancelToken>(
        &self,
        cancel: C,
        poll_interval: Duration,
    ) -> anyhow::Result<()> {
        let interval = nonzero_duration(poll_interval);
        let mut run = std::pin::pin!(self.engine.run(&self.wal, cancel.clone(), interval));
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick completes at once. Skip it, so a pass needs one full
        // interval.
        ticker.tick().await;
        loop {
            tokio::select! {
                result = &mut run => {
                    return result
                        .map_err(|error| anyhow::anyhow!("EAV rule runner failed: {error}"));
                }
                _ = ticker.tick() => {
                    if !cancel.is_cancelled() {
                        self.mark_loop_ok(LoopSlot::RuleRunner);
                    }
                }
            }
        }
    }

    /// Deletes old execution markers until `cancel` fires.
    ///
    /// The call sleeps for `interval` between passes.
    /// It deletes the markers older than `retention`.
    /// A failed cleanup returns the error to the supervisor, which sets the
    /// failure flag of the marker cleanup and restarts the loop after a
    /// backoff delay.
    /// A zero interval becomes one second. A zero retention becomes one second.
    async fn run_execution_gc<C: CancelToken>(
        &self,
        cancel: C,
        interval: Duration,
        retention: Duration,
    ) -> anyhow::Result<()> {
        let interval = nonzero_duration(interval);
        let retention = nonzero_duration(retention);
        let retention = i64::try_from(retention.as_secs()).unwrap_or(i64::MAX);
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            tokio::time::sleep(interval).await;
            if cancel.is_cancelled() {
                return Ok(());
            }
            let older_than = chrono::Utc::now().timestamp().saturating_sub(retention);
            self.rules
                .gc_executions(older_than)
                .await
                .context("delete the old EAV execution markers")?;
            self.entities
                .gc_execution_markers(older_than)
                .await
                .context("delete the old EAV script markers")?;
            self.mark_loop_ok(LoopSlot::MarkerCleanup);
        }
    }

    /// Fires the due timers until `cancel` fires.
    ///
    /// The call sleeps for `interval` between passes.
    /// A failed pass returns the error to the supervisor, which sets the
    /// failure flag of the timer pass and restarts the loop after a backoff
    /// delay.
    /// A zero interval becomes one second.
    /// A zero batch becomes 1.
    async fn run_timers<C: CancelToken>(
        &self,
        cancel: C,
        interval: Duration,
        batch: usize,
    ) -> anyhow::Result<()> {
        let interval = nonzero_duration(interval);
        let batch = batch.max(1);
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            tokio::time::sleep(interval).await;
            if cancel.is_cancelled() {
                return Ok(());
            }
            let now = chrono::Utc::now().timestamp();
            let started = Instant::now();
            match self.fire_due_timers(now, batch).await {
                Ok(fired) => {
                    self.mark_loop_ok(LoopSlot::TimerPass);
                    self.metrics
                        .record_timer_fired(fired as u64, started.elapsed());
                }
                Err(error) => {
                    self.metrics.record_timer_failure();
                    return Err(error).context("fire the due EAV timers");
                }
            }
        }
    }
}

/// Returns the text of a panic payload.
///
/// A payload that is not a string returns a fixed text.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Waits for `delay` in short slices and stops when `cancel` fires.
///
/// The call checks `cancel` before each slice and after the last slice.
/// It returns `true` when the token is cancelled.
/// A zero delay does not sleep and checks the token one time.
async fn sleep_unless_cancelled<C: CancelToken>(cancel: &C, delay: Duration) -> bool {
    let mut remaining = delay;
    while !remaining.is_zero() {
        if cancel.is_cancelled() {
            return true;
        }
        let slice = remaining.min(BACKOFF_SLICE);
        tokio::time::sleep(slice).await;
        remaining = remaining.saturating_sub(slice);
    }
    cancel.is_cancelled()
}

/// Returns `duration`, or one second when it is zero.
fn nonzero_duration(duration: Duration) -> Duration {
    if duration.is_zero() {
        Duration::from_secs(1)
    } else {
        duration
    }
}

/// Returns the store prefix for one EAV domain.
///
/// An empty root omits the leading slash.
fn domain_prefix(db_prefix: &str, domain: &str) -> String {
    let root = db_prefix.trim_matches('/');
    if root.is_empty() {
        format!("eav/{domain}")
    } else {
        format!("{root}/eav/{domain}")
    }
}

/// Returns the rule-store prefix under one `[database].prefix`.
///
/// The server and the operator commands use this function.
/// The rule cursor and the dead-letter rows then live under one prefix.
pub fn rule_store_prefix(db_prefix: &str) -> String {
    domain_prefix(db_prefix, "rules")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::db::{build_s3_store, test_prefix};
    use crate::eav::entity::{AttributeValue, EntityDraft, WriteContext};
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft};
    use crate::fs::s3::S3Backend;
    use crate::records::{ChangeSink, EntityEventKind, WalOp};
    use crate::rules::action::ActionContext;
    use crate::rules::engine::ExecutionOutcome;
    use crate::rules::rule::{ActionRef, Condition, RuleDraft, RuleTrigger};

    /// A [`RuleAction`] test double that records each context.
    struct RecordingAction {
        kind: String,
        records: std::sync::Mutex<Vec<ActionContext>>,
    }

    impl RecordingAction {
        fn new(kind: &str) -> Self {
            Self {
                kind: kind.to_string(),
                records: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn records(&self) -> Vec<ActionContext> {
            self.records.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl RuleAction for RecordingAction {
        fn kind(&self) -> &str {
            &self.kind
        }

        async fn execute(&self, ctx: ActionContext) -> Result<(), anyhow::Error> {
            self.records.lock().unwrap().push(ctx);
            Ok(())
        }
    }

    fn memory_s3() -> S3ClientConfig {
        S3ClientConfig {
            bucket: "eav-runtime-test".to_string(),
            region: "us-east-1".to_string(),
            endpoint_url: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
            backend: S3Backend::Memory,
        }
    }

    fn schema() -> SchemaDraft {
        SchemaDraft {
            id: "invoice".to_string(),
            extends: Vec::new(),
            attributes: BTreeMap::from([(
                "total".to_string(),
                AttributeDef {
                    name: "total".to_string(),
                    ty: AttributeType::Integer,
                    required: false,
                    indexed: false,
                    unique: false,
                    default: None,
                },
            )]),
        }
    }

    fn rule() -> RuleDraft {
        RuleDraft {
            id: "alpha".to_string(),
            name: "alpha".to_string(),
            enabled: true,
            priority: 0,
            trigger: RuleTrigger {
                events: vec![EntityEventKind::Created],
                schemas: vec!["invoice".to_string()],
            },
            condition: Condition::Always,
            action: ActionRef {
                kind: "record".to_string(),
                params: serde_json::json!({}),
            },
            capabilities: crate::rules::rule::RuleCapabilities::default(),
        }
    }

    fn entity() -> EntityDraft {
        EntityDraft {
            id: "e1".to_string(),
            schemas: vec!["invoice".to_string()],
            attributes: BTreeMap::from([("total".to_string(), AttributeValue::Integer(10))]),
        }
    }

    fn timer_schema() -> SchemaDraft {
        SchemaDraft {
            id: "timer".to_string(),
            extends: Vec::new(),
            attributes: BTreeMap::from([(
                "due".to_string(),
                AttributeDef {
                    name: "due".to_string(),
                    ty: AttributeType::Timestamp,
                    required: false,
                    indexed: true,
                    unique: false,
                    default: None,
                },
            )]),
        }
    }

    fn timer_entity(id: &str, due: i64) -> EntityDraft {
        EntityDraft {
            id: id.to_string(),
            schemas: vec!["timer".to_string()],
            attributes: BTreeMap::from([("due".to_string(), AttributeValue::Timestamp(due))]),
        }
    }

    async fn build_runtime(actions: Vec<Arc<dyn RuleAction>>) -> EavRuntime {
        build_runtime_with_max_causation_depth(actions, 8).await
    }

    async fn build_runtime_with_max_causation_depth(
        actions: Vec<Arc<dyn RuleAction>>,
        max_causation_depth: u32,
    ) -> EavRuntime {
        let s3 = memory_s3();
        let prefix = test_prefix("eav-runtime");
        let wal = Wal::new(build_s3_store(&s3, &format!("{prefix}/wal")).await.unwrap());
        EavRuntime::build(&s3, &prefix, wal, actions, true, max_causation_depth, false)
            .await
            .unwrap()
    }

    async fn build_runtime_with_scripts(actions: Vec<Arc<dyn RuleAction>>) -> EavRuntime {
        let s3 = memory_s3();
        let prefix = test_prefix("eav-runtime-script");
        let wal = Wal::new(build_s3_store(&s3, &format!("{prefix}/wal")).await.unwrap());
        EavRuntime::build(&s3, &prefix, wal, actions, true, 8, true)
            .await
            .unwrap()
    }

    fn short_config() -> EavRuntimeConfig {
        EavRuntimeConfig {
            outbox_interval: Duration::from_millis(2),
            rule_poll_interval: Duration::from_millis(2),
            gc_interval: Duration::from_millis(2),
            execution_retention: Duration::from_secs(1),
            timer_interval: Duration::from_millis(2),
            timer_batch: 100,
        }
    }

    /// A [`ChangeSink`] that refuses every append.
    struct FailingFeed;

    #[async_trait::async_trait]
    impl ChangeSink for FailingFeed {
        async fn append(&self, _op: WalOp) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("the test feed is down"))
        }
    }

    /// A [`ChangeSink`] that accepts timer events and refuses other events.
    ///
    /// The outbox relay fails on the created entity event.
    /// The timer pass can still append its event to the shared feed.
    struct TimerOnlyFeed {
        wal: Wal,
    }

    #[async_trait::async_trait]
    impl ChangeSink for TimerOnlyFeed {
        async fn append(&self, op: WalOp) -> anyhow::Result<()> {
            match &op {
                WalOp::Entity { event } if event.kind == EntityEventKind::Timer => {
                    self.wal.append(op).await
                }
                _ => Err(anyhow::anyhow!("the test feed refuses a non-timer event")),
            }
        }
    }

    /// Builds a runtime whose outbox relay fails on its first flush.
    ///
    /// The entity store uses a feed that refuses every append.
    /// The create commits the outbox row and then reports the delivery
    /// error, so the row stays for the relay to find.
    async fn runtime_with_a_failing_outbox() -> EavRuntime {
        let mut runtime = build_runtime(Vec::new()).await;
        let s3 = memory_s3();
        let prefix = test_prefix("eav-runtime-failing");
        let store = build_s3_store(&s3, &format!("{prefix}/entity"))
            .await
            .unwrap();
        let schemas = SchemaRegistry::new(
            build_s3_store(&s3, &format!("{prefix}/schema"))
                .await
                .unwrap(),
        );
        let entities =
            EntityStore::new(store, schemas.clone()).with_change_sink(Arc::new(FailingFeed));
        schemas.publish(schema()).await.unwrap();
        runtime.entities = entities;
        runtime
    }

    /// Builds a runtime whose outbox relay fails and whose timer pass works.
    ///
    /// The entity store uses a feed that accepts timer events and refuses
    /// other events.
    /// The created entity leaves an outbox row, so the relay fails.
    /// The timer pass can still append its event to the runtime WAL.
    async fn runtime_with_a_timer_only_feed() -> EavRuntime {
        let mut runtime = build_runtime(Vec::new()).await;
        let s3 = memory_s3();
        let prefix = test_prefix("eav-runtime-timer-feed");
        let store = build_s3_store(&s3, &format!("{prefix}/entity"))
            .await
            .unwrap();
        let schemas = SchemaRegistry::new(
            build_s3_store(&s3, &format!("{prefix}/schema"))
                .await
                .unwrap(),
        );
        let feed = Arc::new(TimerOnlyFeed {
            wal: runtime.wal().clone(),
        });
        let entities = EntityStore::new(store, schemas.clone()).with_change_sink(feed);
        schemas.publish(schema()).await.unwrap();
        schemas.publish(timer_schema()).await.unwrap();
        runtime.entities = entities;
        runtime
    }

    /// A [`ChangeSink`] that refuses a fixed number of appends.
    ///
    /// A later append goes to the runtime WAL.
    struct FlakyFeed {
        failures_left: AtomicUsize,
        failures: Arc<AtomicUsize>,
        wal: Wal,
    }

    #[async_trait::async_trait]
    impl ChangeSink for FlakyFeed {
        async fn append(&self, op: WalOp) -> anyhow::Result<()> {
            if self.failures_left.load(Ordering::SeqCst) > 0 {
                self.failures_left.fetch_sub(1, Ordering::SeqCst);
                self.failures.fetch_add(1, Ordering::SeqCst);
                return Err(anyhow::anyhow!("the flaky test feed is down"));
            }
            self.wal.append(op).await
        }
    }

    /// Builds a runtime whose outbox relay fails `failures` times and then
    /// succeeds.
    ///
    /// The create commits the outbox row and then reports the delivery
    /// error, so the row stays for the relay to find.
    async fn runtime_with_a_flaky_outbox(failures: usize) -> (EavRuntime, Arc<AtomicUsize>) {
        let mut runtime = build_runtime(Vec::new()).await;
        let s3 = memory_s3();
        let prefix = test_prefix("eav-runtime-flaky");
        let store = build_s3_store(&s3, &format!("{prefix}/entity"))
            .await
            .unwrap();
        let schemas = SchemaRegistry::new(
            build_s3_store(&s3, &format!("{prefix}/schema"))
                .await
                .unwrap(),
        );
        let failed_appends = Arc::new(AtomicUsize::new(0));
        let feed = Arc::new(FlakyFeed {
            failures_left: AtomicUsize::new(failures),
            failures: failed_appends.clone(),
            wal: runtime.wal().clone(),
        });
        let entities = EntityStore::new(store, schemas.clone()).with_change_sink(feed);
        schemas.publish(schema()).await.unwrap();
        runtime.entities = entities;
        (runtime, failed_appends)
    }

    /// A [`ChangeSink`] that waits before it refuses an append.
    ///
    /// The flags show that an append started and that it completed.
    struct SlowFailFeed {
        started: Arc<AtomicBool>,
        finished: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl ChangeSink for SlowFailFeed {
        async fn append(&self, _op: WalOp) -> anyhow::Result<()> {
            self.started.store(true, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.finished.store(true, Ordering::SeqCst);
            Err(anyhow::anyhow!("the slow test feed is down"))
        }
    }

    /// Builds a runtime whose outbox relay waits in a failing flush.
    ///
    /// The create commits the outbox row and then reports the delivery
    /// error, so the row stays for the relay to find.
    async fn runtime_with_a_slow_failing_outbox() -> (EavRuntime, Arc<AtomicBool>, Arc<AtomicBool>)
    {
        let mut runtime = build_runtime(Vec::new()).await;
        let s3 = memory_s3();
        let prefix = test_prefix("eav-runtime-slow-failing");
        let store = build_s3_store(&s3, &format!("{prefix}/entity"))
            .await
            .unwrap();
        let schemas = SchemaRegistry::new(
            build_s3_store(&s3, &format!("{prefix}/schema"))
                .await
                .unwrap(),
        );
        let started = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let feed = Arc::new(SlowFailFeed {
            started: started.clone(),
            finished: finished.clone(),
        });
        let entities = EntityStore::new(store, schemas.clone()).with_change_sink(feed);
        schemas.publish(schema()).await.unwrap();
        runtime.entities = entities;
        (runtime, started, finished)
    }

    #[tokio::test]
    async fn a_new_runtime_starts_with_clear_loop_failures() {
        let runtime = build_runtime(Vec::new()).await;
        assert!(!runtime.failed());
    }

    #[tokio::test]
    async fn a_successful_loop_does_not_clear_another_loop_failure() {
        let runtime = build_runtime(Vec::new()).await;
        runtime.mark_loop_failed(LoopSlot::OutboxRelay);
        runtime.mark_loop_ok(LoopSlot::TimerPass);
        assert!(
            runtime.failed(),
            "a successful loop must not clear a failed loop"
        );

        runtime.mark_loop_ok(LoopSlot::OutboxRelay);
        assert!(
            !runtime.failed(),
            "the state must clear after every failed loop succeeds"
        );
    }

    #[tokio::test]
    async fn one_failed_loop_keeps_the_state_failed_after_another_loop_succeeds() {
        let runtime = build_runtime(Vec::new()).await;
        runtime.mark_loop_failed(LoopSlot::RuleRunner);
        runtime.mark_loop_failed(LoopSlot::MarkerCleanup);
        runtime.mark_loop_ok(LoopSlot::MarkerCleanup);
        assert!(
            runtime.failed(),
            "the rule runner must keep the state failed"
        );
    }

    #[tokio::test]
    async fn a_loop_failure_clears_after_a_later_pass_succeeds() {
        let runtime = build_runtime(Vec::new()).await;
        let cancel = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_work = calls.clone();
        let runtime_for_work = runtime.clone();
        let cancel_for_work = cancel.clone();

        let supervisor = tokio::spawn(async move {
            runtime_for_work
                .supervise(LoopSlot::OutboxRelay, cancel_for_work, move |_token| {
                    let calls = calls_for_work.clone();
                    async move {
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            return Err(anyhow::anyhow!("the test pass fails"));
                        }
                        Ok(())
                    }
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            while !runtime.failed() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("a failed pass must set the loop flag");

        let result = tokio::time::timeout(Duration::from_secs(2), supervisor)
            .await
            .expect("the supervisor must stop after the successful pass")
            .expect("the supervisor task must not panic");
        assert!(result.is_ok(), "the successful pass must return Ok");
        assert!(
            !runtime.failed(),
            "a later successful pass must clear the failure flag"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_panicking_loop_is_contained_and_recovers() {
        let runtime = build_runtime(Vec::new()).await;
        let cancel = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_work = calls.clone();
        let runtime_for_work = runtime.clone();
        let cancel_for_work = cancel.clone();

        let supervisor = tokio::spawn(async move {
            runtime_for_work
                .supervise(LoopSlot::TimerPass, cancel_for_work, move |_token| {
                    let calls = calls_for_work.clone();
                    async move {
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            panic!("the test pass panics once");
                        }
                        Ok(())
                    }
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            while !runtime.failed() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("a panic must set the loop flag");

        let result = tokio::time::timeout(Duration::from_secs(2), supervisor)
            .await
            .expect("the supervisor must stay alive after the panic")
            .expect("the supervisor task must not panic");
        assert!(result.is_ok(), "the later pass must return Ok");
        assert!(
            !runtime.failed(),
            "a later successful pass must clear the panic failure"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_recovered_outbox_loop_clears_its_failure_flag() {
        let (runtime, failed_appends) = runtime_with_a_flaky_outbox(2).await;
        let created = runtime
            .entities()
            .create(entity(), &WriteContext::new("tester"))
            .await;
        assert!(created.is_ok(), "the entity and the outbox row must commit");
        assert_eq!(
            failed_appends.load(Ordering::SeqCst),
            1,
            "the inline flush must use one failure"
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel.clone(), short_config());

        tokio::time::timeout(Duration::from_secs(2), async {
            while failed_appends.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the outbox relay must fail at least once");

        tokio::time::timeout(Duration::from_secs(2), async {
            while runtime.failed() || runtime.entities().outbox_count().await.unwrap() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("a successful flush must clear the failure flag");

        assert!(!runtime.failed());
        assert_eq!(runtime.entities().outbox_count().await.unwrap(), 0);

        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("a cancelled runtime must stop")
            .expect("the task does not panic")
            .expect("a normal cancellation must return Ok");
    }

    #[tokio::test]
    async fn a_healthy_rule_runner_clears_its_failure_flag() {
        let runtime = build_runtime(Vec::new()).await;
        runtime.mark_loop_failed(LoopSlot::RuleRunner);
        let cancel = Arc::new(AtomicBool::new(false));
        let runner = {
            let runtime = runtime.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                runtime
                    .run_rule_runner(cancel, Duration::from_millis(2))
                    .await
            })
        };

        tokio::time::timeout(Duration::from_secs(2), async {
            while runtime.failed() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("a healthy rule runner must clear its failure flag");

        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), runner)
            .await
            .expect("the rule runner must stop")
            .expect("the task does not panic")
            .expect("a normal cancellation must return Ok");
    }

    #[tokio::test]
    async fn spawn_sets_the_failure_flag_when_the_outbox_relay_fails() {
        let runtime = runtime_with_a_failing_outbox().await;
        assert!(!runtime.failed());

        let created = runtime
            .entities()
            .create(entity(), &WriteContext::new("tester"))
            .await;
        assert!(created.is_ok(), "the entity and the outbox row must commit");
        assert_eq!(
            runtime.entities().outbox_count().await.unwrap(),
            1,
            "a failed inline flush must leave the outbox row"
        );

        let cancel = Arc::new(AtomicBool::new(false));
        let mut handle = runtime.spawn(cancel.clone(), short_config());

        tokio::time::timeout(Duration::from_secs(2), async {
            while !runtime.failed() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the outbox failure must set the loop flag");

        // The flag is a signal, not a stop switch. The runtime keeps
        // running, so the handle stays pending.
        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut handle)
                .await
                .is_err(),
            "the runtime must keep running after the flag is set"
        );

        cancel.store(true, Ordering::SeqCst);
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("a cancelled runtime must stop")
            .expect("the task does not panic");
        assert!(result.is_ok(), "a normal cancellation must return Ok");
    }

    #[tokio::test]
    async fn a_failed_outbox_loop_does_not_stop_the_timer_loop() {
        let runtime = runtime_with_a_timer_only_feed().await;
        assert!(!runtime.failed());

        // The created invoice event makes the outbox relay fail.
        runtime
            .entities()
            .create(entity(), &WriteContext::new("tester"))
            .await
            .unwrap();
        // The due timer entity makes the timer pass emit one event.
        let now = chrono::Utc::now().timestamp();
        runtime
            .entities()
            .create(timer_entity("t1", now - 10), &WriteContext::new("tester"))
            .await
            .unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel.clone(), short_config());

        tokio::time::timeout(Duration::from_secs(2), async {
            while !runtime.failed() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the outbox failure must set the loop flag");

        tokio::time::timeout(Duration::from_secs(2), async {
            while runtime.wal().head().await.unwrap() == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the timer loop must still emit after the outbox failure");

        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("a cancelled runtime must stop")
            .expect("the task does not panic")
            .expect("a normal cancellation must return Ok");
    }

    #[tokio::test]
    async fn a_matching_rule_runs_through_the_runtime() {
        let recorder = Arc::new(RecordingAction::new("record"));
        let runtime = build_runtime(vec![recorder.clone()]).await;
        runtime.schemas().publish(schema()).await.unwrap();
        runtime.rules().upsert(rule()).await.unwrap();
        runtime
            .entities()
            .create(entity(), &WriteContext::new("tester"))
            .await
            .unwrap();
        assert_eq!(runtime.wal().head().await.unwrap(), 1);

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel.clone(), short_config());

        tokio::time::timeout(Duration::from_secs(2), async {
            while recorder.records().is_empty() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();

        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let records = recorder.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rule.id, "alpha");
        assert_eq!(records[0].event.entity_id, "e1");
    }

    #[tokio::test]
    async fn a_script_rule_runs_when_the_runtime_enables_scripts() {
        let recorder = Arc::new(RecordingAction::new("record"));
        let runtime = build_runtime_with_scripts(vec![recorder.clone()]).await;
        runtime.schemas().publish(schema()).await.unwrap();
        let mut scripted = rule();
        scripted.condition = Condition::Script {
            source: r#"event.kind == "created" && entity.attributes.total == 10"#.to_string(),
        };
        runtime.rules().upsert(scripted).await.unwrap();
        runtime
            .entities()
            .create(entity(), &WriteContext::new("tester"))
            .await
            .unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel.clone(), short_config());

        tokio::time::timeout(Duration::from_secs(2), async {
            while recorder.records().is_empty() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();

        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(recorder.records().len(), 1);
    }

    /// The configured value must reach the rule engine through the runtime
    /// build.
    ///
    /// A depth at the configured value runs the action.
    /// A depth above the configured value returns `CausationLimit`.
    #[tokio::test]
    async fn the_runtime_rules_with_the_configured_max_causation_depth() {
        let recorder = Arc::new(RecordingAction::new("record"));
        let runtime = build_runtime_with_max_causation_depth(vec![recorder.clone()], 2).await;
        runtime.schemas().publish(schema()).await.unwrap();
        runtime.rules().upsert(rule()).await.unwrap();
        runtime
            .entities()
            .create(entity(), &WriteContext::new("tester"))
            .await
            .unwrap();

        let head = runtime.wal().head().await.unwrap();
        let entry = runtime
            .wal()
            .range(head, head)
            .await
            .unwrap()
            .pop()
            .expect("the create event must be in the feed");
        let WalOp::Entity { event } = entry.op else {
            panic!("the create event must be an entity op");
        };

        let mut at_limit = event.clone();
        at_limit.event_id = "depth-at-limit".to_string();
        at_limit.causation_depth = 2;
        let executions = runtime.engine().process(&at_limit).await.unwrap();
        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);
        assert_eq!(recorder.records().len(), 1);

        let mut above = event;
        above.event_id = "depth-above-limit".to_string();
        above.causation_depth = 3;
        let executions = runtime.engine().process(&above).await.unwrap();
        assert_eq!(executions[0].outcome, ExecutionOutcome::CausationLimit);
        assert_eq!(
            recorder.records().len(),
            1,
            "a depth above the configured value must run no action"
        );
    }

    #[tokio::test]
    async fn fire_due_timers_emits_one_event_per_due_value_and_not_again() {
        let runtime = build_runtime(Vec::new()).await;
        runtime.schemas().publish(timer_schema()).await.unwrap();
        runtime
            .entities()
            .create(timer_entity("e1", 100), &WriteContext::new("tester"))
            .await
            .unwrap();

        assert_eq!(runtime.fire_due_timers(100, 100).await.unwrap(), 1);
        assert_eq!(runtime.fire_due_timers(100, 100).await.unwrap(), 0);
        assert_eq!(runtime.wal().head().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn a_new_timestamp_value_allows_a_new_timer_event() {
        let runtime = build_runtime(Vec::new()).await;
        runtime.schemas().publish(timer_schema()).await.unwrap();
        runtime
            .entities()
            .create(timer_entity("e1", 100), &WriteContext::new("tester"))
            .await
            .unwrap();
        assert_eq!(runtime.fire_due_timers(100, 100).await.unwrap(), 1);

        runtime
            .entities()
            .update(
                "e1",
                1,
                crate::eav::entity::EntityPatch {
                    attributes: BTreeMap::from([(
                        "due".to_string(),
                        Some(AttributeValue::Timestamp(50)),
                    )]),
                },
                &WriteContext::new("tester"),
            )
            .await
            .unwrap();

        assert_eq!(runtime.fire_due_timers(100, 100).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_zero_limit_emits_no_timer_event() {
        let runtime = build_runtime(Vec::new()).await;
        runtime.schemas().publish(timer_schema()).await.unwrap();
        runtime
            .entities()
            .create(timer_entity("e1", 100), &WriteContext::new("tester"))
            .await
            .unwrap();

        assert_eq!(runtime.fire_due_timers(100, 0).await.unwrap(), 0);
        assert_eq!(runtime.wal().head().await.unwrap(), 1);
    }

    /// Returns the entity ids of every timer event in the WAL.
    async fn timer_event_ids(runtime: &EavRuntime) -> Vec<String> {
        let head = runtime.wal().head().await.unwrap();
        if head == 0 {
            return Vec::new();
        }
        runtime
            .wal()
            .range(1, head)
            .await
            .unwrap()
            .into_iter()
            .filter_map(|entry| match entry.op {
                WalOp::Entity { event } if event.kind == EntityEventKind::Timer => {
                    Some(event.entity_id)
                }
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn a_retired_timer_row_lets_the_next_pass_reach_later_entities() {
        let runtime = build_runtime(Vec::new()).await;
        runtime.schemas().publish(timer_schema()).await.unwrap();
        for (id, due) in [("e1", 100), ("e2", 101), ("e3", 102)] {
            runtime
                .entities()
                .create(timer_entity(id, due), &WriteContext::new("tester"))
                .await
                .unwrap();
        }

        assert_eq!(runtime.fire_due_timers(102, 2).await.unwrap(), 2);
        let remaining = runtime.entities().list_due("due", 102, 100).await.unwrap();
        let ids: Vec<&str> = remaining.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(ids, vec!["e3"]);

        assert_eq!(runtime.fire_due_timers(102, 2).await.unwrap(), 1);
        assert!(
            runtime
                .entities()
                .list_due("due", 102, 100)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(runtime.fire_due_timers(102, 2).await.unwrap(), 0);

        let mut events = timer_event_ids(&runtime).await;
        events.sort();
        assert_eq!(events, vec!["e1", "e2", "e3"]);
        assert_eq!(runtime.wal().head().await.unwrap(), 6);
    }

    #[tokio::test]
    async fn a_small_limit_retires_due_rows_on_every_pass() {
        let runtime = build_runtime(Vec::new()).await;
        runtime.schemas().publish(timer_schema()).await.unwrap();
        for (index, id) in ["e1", "e2", "e3", "e4", "e5"].iter().enumerate() {
            runtime
                .entities()
                .create(
                    timer_entity(id, 100 + index as i64),
                    &WriteContext::new("tester"),
                )
                .await
                .unwrap();
        }

        assert_eq!(runtime.fire_due_timers(200, 2).await.unwrap(), 2);
        assert_eq!(
            runtime
                .entities()
                .list_due("due", 200, 100)
                .await
                .unwrap()
                .len(),
            3
        );
        assert_eq!(runtime.fire_due_timers(200, 2).await.unwrap(), 2);
        assert_eq!(
            runtime
                .entities()
                .list_due("due", 200, 100)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(runtime.fire_due_timers(200, 2).await.unwrap(), 1);
        assert!(
            runtime
                .entities()
                .list_due("due", 200, 100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_upgraded_store_drains_a_fired_row_without_a_second_event() {
        let runtime = build_runtime(Vec::new()).await;
        runtime.schemas().publish(timer_schema()).await.unwrap();
        runtime
            .entities()
            .create(timer_entity("e1", 100), &WriteContext::new("tester"))
            .await
            .unwrap();
        // Simulate a store that fired the value before timer retire existed.
        assert!(
            runtime
                .entities()
                .mark_timer_fired("e1", "due", 100)
                .await
                .unwrap()
        );
        assert_eq!(
            runtime
                .entities()
                .list_due("due", 100, 100)
                .await
                .unwrap()
                .len(),
            1
        );
        let before = runtime.wal().head().await.unwrap();

        assert_eq!(runtime.fire_due_timers(100, 100).await.unwrap(), 0);

        assert_eq!(runtime.wal().head().await.unwrap(), before);
        assert!(timer_event_ids(&runtime).await.is_empty());
        assert!(
            runtime
                .entities()
                .is_timer_fired("e1", "due", 100)
                .await
                .unwrap()
        );
        assert!(
            runtime
                .entities()
                .list_due("due", 100, 100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_timer_rule_runs_through_the_runtime() {
        let recorder = Arc::new(RecordingAction::new("record"));
        let runtime = build_runtime(vec![recorder.clone()]).await;
        runtime.schemas().publish(timer_schema()).await.unwrap();
        let mut timer_rule = rule();
        timer_rule.trigger.events = vec![EntityEventKind::Timer];
        timer_rule.trigger.schemas = vec!["timer".to_string()];
        runtime.rules().upsert(timer_rule).await.unwrap();
        let now = chrono::Utc::now().timestamp();
        runtime
            .entities()
            .create(timer_entity("e1", now - 10), &WriteContext::new("tester"))
            .await
            .unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel.clone(), short_config());

        tokio::time::timeout(Duration::from_secs(2), async {
            while recorder.records().is_empty() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();

        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let records = recorder.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rule.id, "alpha");
        assert_eq!(records[0].event.kind, EntityEventKind::Timer);
    }

    #[tokio::test]
    async fn run_stops_when_the_token_fires() {
        let runtime = build_runtime(Vec::new()).await;
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel.clone(), short_config());

        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel.store(true, Ordering::SeqCst);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn run_waits_for_all_four_loops_after_cancellation() {
        let runtime = build_runtime(Vec::new()).await;
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel.clone(), short_config());

        tokio::time::timeout(Duration::from_secs(2), async {
            while runtime.runtime_test().active_loops() < 4 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("all four supervisors must start");

        cancel.store(true, Ordering::SeqCst);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("the runtime must stop")
            .expect("the task does not panic")
            .expect("a normal cancellation must return Ok");

        assert_eq!(
            runtime.runtime_test().active_loops(),
            0,
            "the runtime must wait for all four loops to stop"
        );
    }

    #[tokio::test]
    async fn run_waits_for_an_in_flight_flush_after_cancellation() {
        let (runtime, started, finished) = runtime_with_a_slow_failing_outbox().await;
        let created = runtime
            .entities()
            .create(entity(), &WriteContext::new("tester"))
            .await;
        assert!(created.is_ok(), "the entity and the outbox row must commit");
        assert_eq!(
            runtime.entities().outbox_count().await.unwrap(),
            1,
            "a failed inline flush must leave the outbox row"
        );
        started.store(false, Ordering::SeqCst);

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel.clone(), short_config());

        tokio::time::timeout(Duration::from_secs(2), async {
            while !started.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the outbox relay must start its flush");

        cancel.store(true, Ordering::SeqCst);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("the runtime must stop")
            .expect("the task does not panic")
            .expect("a normal cancellation must return Ok");

        assert!(
            finished.load(Ordering::SeqCst),
            "the runtime must not drop an in-flight flush"
        );
        assert_eq!(
            runtime.runtime_test().active_loops(),
            0,
            "the runtime must wait for all four loops to stop"
        );
    }

    #[test]
    fn nonzero_duration_replaces_zero_and_keeps_other_values() {
        assert_eq!(nonzero_duration(Duration::ZERO), Duration::from_secs(1));
        assert_eq!(
            nonzero_duration(Duration::from_millis(5)),
            Duration::from_millis(5)
        );
    }

    #[tokio::test]
    async fn sleep_unless_cancelled_returns_true_soon_after_cancellation() {
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            token.cancel();
        });
        let started = Instant::now();

        let cancelled = tokio::time::timeout(
            Duration::from_millis(100),
            sleep_unless_cancelled(&cancel, Duration::from_millis(200)),
        )
        .await
        .expect("the wait must stop soon after cancellation");

        assert!(cancelled);
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "a cancelled wait must not sleep for the full delay"
        );
    }

    #[tokio::test]
    async fn sleep_unless_cancelled_returns_false_after_a_full_short_delay() {
        let cancel = CancellationToken::new();
        let started = Instant::now();

        let cancelled = sleep_unless_cancelled(&cancel, Duration::from_millis(20)).await;

        assert!(!cancelled);
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(!sleep_unless_cancelled(&cancel, Duration::ZERO).await);
    }

    #[tokio::test]
    async fn run_stops_when_the_token_fires_with_zero_gc_settings() {
        let runtime = build_runtime(Vec::new()).await;
        let config = EavRuntimeConfig {
            outbox_interval: Duration::from_millis(2),
            rule_poll_interval: Duration::from_millis(2),
            gc_interval: Duration::ZERO,
            execution_retention: Duration::ZERO,
            timer_interval: Duration::ZERO,
            timer_batch: 0,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel.clone(), config);

        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel.store(true, Ordering::SeqCst);

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
