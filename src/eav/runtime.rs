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
//! The runtime has one shared failure latch.
//! [`EavRuntime::spawn`] sets the latch when [`EavRuntime::run`] returns an
//! error.
//! The readiness probe reads the latch.
//! A normal cancellation stops the loops and leaves the latch clear.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
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
    /// Set when a background loop returns an error.
    ///
    /// The latch starts as `false`.
    /// A normal cancellation does not set it.
    failed: Arc<AtomicBool>,
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
    pub async fn build(
        s3: &S3ClientConfig,
        db_prefix: &str,
        wal: Wal,
        actions: Vec<Arc<dyn RuleAction>>,
    ) -> anyhow::Result<Self> {
        let schema_store = build_s3_store(s3, &domain_prefix(db_prefix, "schema"))
            .await
            .context("build the EAV schema store")?;
        let entity_store = build_s3_store(s3, &domain_prefix(db_prefix, "entity"))
            .await
            .context("build the EAV entity store")?;
        let rule_store = build_s3_store(s3, &domain_prefix(db_prefix, "rules"))
            .await
            .context("build the EAV rule store")?;
        let replica_store = build_s3_store(s3, &domain_prefix(db_prefix, "replica"))
            .await
            .context("build the EAV replica store")?;

        let schemas = SchemaRegistry::new(schema_store);
        let entities =
            EntityStore::new(entity_store, schemas.clone()).with_change_sink(Arc::new(wal.clone()));
        let rules = RuleStore::new(rule_store);
        let replicas = ReplicaStore::new(replica_store);
        let metrics = EavMetrics::global();
        let engine = RuleEngine::new(rules.clone(), entities.clone(), actions)
            .context("build the EAV rule engine")?
            .with_observer(Arc::new(metrics.clone()));

        Ok(Self {
            schemas,
            entities,
            rules,
            replicas,
            engine,
            wal,
            metrics,
            failed: Arc::new(AtomicBool::new(false)),
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

    /// Returns the shared failure latch.
    ///
    /// The latch starts as `false`.
    /// [`EavRuntime::spawn`] sets it to `true` when [`EavRuntime::run`]
    /// returns an error.
    /// A normal cancellation leaves it `false`.
    ///
    /// The call is cheap and does not block.
    /// The readiness probe reads the flag with [`Ordering::Relaxed`].
    pub fn failure_latch(&self) -> Arc<AtomicBool> {
        self.failed.clone()
    }

    /// Sets the failure latch.
    fn mark_failed(&self) {
        self.failed.store(true, Ordering::Relaxed);
    }

    /// Emits a timer event for each due timestamp value and returns the count.
    ///
    /// The call reads every time index key.
    /// For each key it reads at most `limit` due entities.
    /// A fired marker for the same entity, key, and value is skipped.
    /// The call writes the event and then the marker.
    /// A failed marker write returns the error.
    /// The next pass then emits the same event again.
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
                    continue;
                }
                self.entities
                    .emit_timer(&entity, &key, due_at, now)
                    .await
                    .context("emit an EAV timer event")?;
                self.entities
                    .mark_timer_fired(&entity.id, &key, due_at)
                    .await
                    .context("write the EAV timer marker")?;
                emitted += 1;
            }
        }
        self.metrics.record_timer_due(due_count);
        Ok(emitted)
    }

    /// Runs the outbox relay, the rule runner, the marker cleanup, and the
    /// timer pass until `cancel` fires.
    ///
    /// The call runs all four loops at the same time.
    /// The first failure of the outbox relay or the rule runner stops the
    /// runtime and returns the error.
    /// The marker cleanup and the timer pass are best effort.
    /// They log a warning and continue.
    /// The outbox relay flushes the pending entity events.
    /// The rule runner tails the shared change feed.
    /// The timer pass emits the due timer events.
    /// Each loop stops when `cancel` is cancelled.
    pub async fn run<C: CancelToken>(
        &self,
        cancel: C,
        config: EavRuntimeConfig,
    ) -> anyhow::Result<()> {
        let relay = self.run_outbox(cancel.clone(), config.outbox_interval);
        let runner = async {
            self.engine
                .run(&self.wal, cancel.clone(), config.rule_poll_interval)
                .await
                .map_err(|error| anyhow::anyhow!("EAV rule runner failed: {error}"))
        };
        let cleanup = self.run_execution_gc(
            cancel.clone(),
            config.gc_interval,
            config.execution_retention,
        );
        let timers = self.run_timers(cancel.clone(), config.timer_interval, config.timer_batch);
        tokio::select! {
            result = relay => result,
            result = runner => result,
            result = cleanup => result,
            result = timers => result,
        }
    }

    /// Starts [`EavRuntime::run`] on a Tokio task.
    ///
    /// The call logs a runtime error, sets the failure latch, and returns
    /// the error.
    /// The call does not set the latch on a normal cancellation.
    /// A caller can await the handle during shutdown.
    pub fn spawn<C: CancelToken + Send + 'static>(
        &self,
        cancel: C,
        config: EavRuntimeConfig,
    ) -> JoinHandle<anyhow::Result<()>> {
        let runtime = self.clone();
        tokio::spawn(async move {
            match runtime.run(cancel, config).await {
                Ok(()) => Ok(()),
                Err(error) => {
                    runtime.mark_failed();
                    tracing::error!(?error, "EAV runtime failed");
                    Err(error)
                }
            }
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

    /// Deletes old execution markers until `cancel` fires.
    ///
    /// The call sleeps for `interval` between passes.
    /// It deletes the markers older than `retention`.
    /// A failed cleanup logs a warning and continues.
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
            if let Err(error) = self.rules.gc_executions(older_than).await {
                tracing::warn!(?error, "EAV execution marker cleanup failed");
            }
        }
    }

    /// Fires the due timers until `cancel` fires.
    ///
    /// The call sleeps for `interval` between passes.
    /// A failed pass logs a warning and continues.
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
                Ok(fired) => self
                    .metrics
                    .record_timer_fired(fired as u64, started.elapsed()),
                Err(error) => {
                    self.metrics.record_timer_failure();
                    tracing::warn!(?error, "EAV due timer pass failed");
                }
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::db::{build_s3_store, test_prefix};
    use crate::eav::entity::{AttributeValue, EntityDraft, WriteContext};
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft};
    use crate::fs::s3::S3Backend;
    use crate::records::{ChangeSink, EntityEventKind, WalOp};
    use crate::rules::action::ActionContext;
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
        let s3 = memory_s3();
        let prefix = test_prefix("eav-runtime");
        let wal = Wal::new(build_s3_store(&s3, &format!("{prefix}/wal")).await.unwrap());
        EavRuntime::build(&s3, &prefix, wal, actions).await.unwrap()
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

    #[tokio::test]
    async fn a_new_runtime_starts_with_a_clear_failure_latch() {
        let runtime = build_runtime(Vec::new()).await;
        assert!(!runtime.failure_latch().load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn a_set_failure_latch_reads_true() {
        let runtime = build_runtime(Vec::new()).await;
        let latch = runtime.failure_latch();
        assert!(!latch.load(Ordering::Relaxed));
        runtime.mark_failed();
        assert!(latch.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn spawn_sets_the_failure_latch_when_the_outbox_relay_fails() {
        let runtime = runtime_with_a_failing_outbox().await;
        let latch = runtime.failure_latch();
        assert!(!latch.load(Ordering::Relaxed));

        let created = runtime
            .entities()
            .create(entity(), &WriteContext::new("tester"))
            .await;
        assert!(created.is_err(), "the test feed must refuse the create");

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = runtime.spawn(cancel, short_config());
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("the runtime stops after the outbox failure")
            .expect("the task does not panic");
        assert!(result.is_err(), "the outbox failure must reach the handle");
        assert!(
            latch.load(Ordering::Relaxed),
            "a dead runtime must set the failure latch"
        );
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

    #[test]
    fn nonzero_duration_replaces_zero_and_keeps_other_values() {
        assert_eq!(nonzero_duration(Duration::ZERO), Duration::from_secs(1));
        assert_eq!(
            nonzero_duration(Duration::from_millis(5)),
            Duration::from_millis(5)
        );
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
