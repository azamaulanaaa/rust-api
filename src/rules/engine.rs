//! The generic rule runner.
//!
//! [`RuleEngine::process`] runs the matching rules for one entity event.
//! [`RuleEngine::run`] tails the durable change feed and calls `process`.
//! Delivery is at least once.
//! [`RuleEngine::run`] reads at most `RULE_BATCH_SIZE` entries in one batch.
//! The batch size is 256 entries in a normal build.
//! Tests use a batch of two entries.
//! [`RuleEngine::run`] writes the cursor one time for each batch of 32
//! successful entries.
//! A crash can replay the last batch, so at most 32 entries repeat.
//! An execution marker stops a duplicate action.
//! An action must still be idempotent because a crash can repeat one event.
//! A failed run keeps the cursor before the failed entry.
//! The runtime supervisor restarts a failed run after a backoff delay.
//! The delay starts at one second and doubles up to 60 seconds.
//!
//! The process lock is per event.
//! Two calls for one event do not run one rule action twice.
//! Two calls for different events run at the same time.
//! The engine removes a lock entry when no caller holds or waits for it.
//!
//! An action can write an entity.
//! That write can create another event, and that event can match a rule
//! again.
//! A causation-depth guard stops such a chain.
//! The maximum depth is inclusive.
//! A depth above the maximum is a runaway chain.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::CancelToken;
use crate::eav::entity::{Entity, EntityStore};
use crate::eav::entity_error::EntityError;
use crate::records::{EntityEvent, WalOp};
use crate::rules::action::{ActionContext, RuleAction};
use crate::rules::error::RuleError;
use crate::rules::rule::{Rule, validate_identifier};
use crate::rules::store::RuleStore;
use crate::sync::wal::Wal;

/// The default maximum causation depth.
///
/// A chain deeper than this value is a runaway chain.
const DEFAULT_MAX_CAUSATION_DEPTH: u32 = 8;

/// The number of successful entries between cursor writes.
///
/// A crash can replay the last batch, so at most this number of entries
/// repeat.
const CURSOR_BATCH_SIZE: u64 = 32;

/// The largest number of change-feed entries to read in one rule batch.
#[cfg(not(test))]
const RULE_BATCH_SIZE: usize = 256;

/// The largest number of change-feed entries to read in one rule batch.
///
/// Tests use a small batch, so a few entries cross the batch boundary.
#[cfg(test)]
const RULE_BATCH_SIZE: usize = 2;

/// The result of one rule for one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// The action ran and the engine wrote the execution marker.
    Executed,
    /// The condition was false, so the engine ran no action.
    ConditionFalse,
    /// An execution marker already exists, so the engine ran no action.
    AlreadyExecuted,
    /// The event depth is above the maximum, so the engine ran no action.
    ///
    /// The engine wrote no execution marker.
    CausationLimit,
}

/// One rule result from [`RuleEngine::process`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleExecution {
    /// The id of the rule.
    pub rule_id: String,
    /// The result for this rule.
    pub outcome: ExecutionOutcome,
}

/// Observes the result of one rule execution.
///
/// The engine calls the observer for every rule result.
/// The observer must be thread safe.
pub trait RuleObserver: Send + Sync {
    /// Records the result of one rule.
    fn on_execution(&self, outcome: ExecutionOutcome);

    /// Records one action failure.
    fn on_action_failure(&self);
}

/// The generic rule runner.
///
/// The engine holds one action for each registered kind.
/// The engine holds one process lock for each event id.
/// Two calls for one rule and one event run the action one time.
/// Calls for different events do not serialize.
/// The engine removes a lock entry when no caller holds or waits for it.
#[derive(Clone)]
pub struct RuleEngine {
    /// The durable rule store.
    rules: RuleStore,
    /// The entity store that supplies the current entity.
    entities: EntityStore,
    /// The registered actions, keyed by kind.
    actions: HashMap<String, Arc<dyn RuleAction>>,
    /// The maximum causation depth that can run an action.
    ///
    /// The maximum is inclusive.
    /// A depth above the maximum is a runaway chain.
    max_causation_depth: u32,
    /// The optional observer for rule results.
    observer: Option<Arc<dyn RuleObserver>>,
    /// The process locks, keyed by event id.
    ///
    /// One lock stops two calls from running one rule and one event twice.
    process_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl RuleEngine {
    /// Creates an engine from one rule store, one entity store, and the
    /// registered actions.
    ///
    /// The call rejects an empty action kind.
    /// It also rejects two actions with the same kind.
    /// A rule that names an unknown kind fails at process time.
    pub fn new(
        rules: RuleStore,
        entities: EntityStore,
        actions: Vec<Arc<dyn RuleAction>>,
    ) -> Result<Self, RuleError> {
        let mut by_kind = HashMap::with_capacity(actions.len());
        for action in actions {
            let kind = action.kind().to_string();
            validate_identifier("action kind", &kind)?;
            if by_kind.contains_key(&kind) {
                return Err(RuleError::DuplicateAction(kind));
            }
            by_kind.insert(kind, action);
        }
        Ok(Self {
            rules,
            entities,
            actions: by_kind,
            max_causation_depth: DEFAULT_MAX_CAUSATION_DEPTH,
            observer: None,
            process_locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Returns true when the engine has a registered action of `kind`.
    ///
    /// A rule can name only a registered kind.
    pub fn has_action(&self, kind: &str) -> bool {
        self.actions.contains_key(kind)
    }

    /// Checks the parameters for one registered action kind.
    ///
    /// The API calls this check before it stores a rule.
    /// An unknown kind returns [`RuleError::UnknownAction`].
    /// A failed check returns [`RuleError::Invalid`] with a generic message.
    /// The message never repeats the parameter or the URL.
    pub fn validate_action(&self, kind: &str, params: &serde_json::Value) -> Result<(), RuleError> {
        let action = self
            .actions
            .get(kind)
            .ok_or_else(|| RuleError::UnknownAction(kind.to_string()))?;
        action
            .validate(params)
            .map_err(|_| RuleError::Invalid("rule action parameters are not valid".to_string()))
    }

    /// Sets the maximum causation depth.
    ///
    /// The maximum is inclusive.
    /// A depth above the maximum is a runaway chain.
    pub fn with_max_causation_depth(mut self, max: u32) -> Self {
        self.max_causation_depth = max;
        self
    }

    /// Sets the observer for rule results.
    pub fn with_observer(mut self, observer: Arc<dyn RuleObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Records one rule result when an observer exists.
    fn observe(&self, outcome: ExecutionOutcome) {
        if let Some(observer) = &self.observer {
            observer.on_execution(outcome);
        }
    }

    /// Records one action failure when an observer exists.
    fn observe_action_failure(&self) {
        if let Some(observer) = &self.observer {
            observer.on_action_failure();
        }
    }

    /// Returns the process lock for one event id.
    ///
    /// The call adds a new entry when the map has no entry for the id.
    async fn event_process_lock(&self, event_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.process_locks.lock().await;
        locks
            .entry(event_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Removes the process lock for one event id when no caller needs it.
    ///
    /// The map holds one strong reference to the lock.
    /// This call holds one more strong reference in `lock`.
    /// A count of two therefore shows that no other caller holds or waits.
    async fn release_process_lock(&self, event_id: &str, lock: &Arc<Mutex<()>>) {
        let mut locks = self.process_locks.lock().await;
        let removable = locks
            .get(event_id)
            .is_some_and(|entry| Arc::ptr_eq(entry, lock) && Arc::strong_count(entry) == 2);
        if removable {
            locks.remove(event_id);
        }
    }

    /// Returns the number of live process lock entries.
    #[cfg(test)]
    async fn live_process_locks(&self) -> usize {
        self.process_locks.lock().await.len()
    }

    /// Runs the matching rules for one entity event.
    ///
    /// The call loads the current entity first.
    /// A deleted entity gives `None`.
    /// It then lists the enabled matching rules in priority order.
    /// If the event depth is above the maximum, it returns one
    /// [`ExecutionOutcome::CausationLimit`] for each matching rule.
    /// It then runs no action and writes no marker.
    /// Otherwise, it locks the entry for the event id.
    /// The lock covers the marker read, the condition check, the action call,
    /// and the marker write.
    /// Two calls for the same event run each rule action one time.
    /// Calls for different events do not serialize.
    /// A successful action writes the marker for this rule and event.
    /// A failed action writes no marker, so a later retry can run it again.
    /// The call removes the lock entry when the last caller releases it.
    pub async fn process(&self, event: &EntityEvent) -> Result<Vec<RuleExecution>, RuleError> {
        let entity = self
            .entities
            .get(&event.entity_id)
            .await
            .map_err(map_entity_error)?;
        let rules = self.rules.matching(event).await?;
        if event.causation_depth > self.max_causation_depth {
            return Ok(rules
                .into_iter()
                .map(|rule| {
                    let outcome = ExecutionOutcome::CausationLimit;
                    self.observe(outcome);
                    RuleExecution {
                        rule_id: rule.id,
                        outcome,
                    }
                })
                .collect());
        }

        let lock = self.event_process_lock(&event.event_id).await;
        let guard = lock.lock().await;
        let result = self.run_rules(event, entity, rules).await;
        drop(guard);
        self.release_process_lock(&event.event_id, &lock).await;
        result
    }

    /// Runs the loaded rules for one event under the event lock.
    ///
    /// The caller holds the lock for `event.event_id`.
    /// A successful action writes the marker for this rule and event.
    /// A failed action writes no marker.
    async fn run_rules(
        &self,
        event: &EntityEvent,
        entity: Option<Entity>,
        rules: Vec<Rule>,
    ) -> Result<Vec<RuleExecution>, RuleError> {
        let mut executions = Vec::with_capacity(rules.len());

        for rule in rules {
            if self.rules.is_executed(&rule.id, &event.event_id).await? {
                let outcome = ExecutionOutcome::AlreadyExecuted;
                self.observe(outcome);
                executions.push(RuleExecution {
                    rule_id: rule.id,
                    outcome,
                });
                continue;
            }
            if !rule.condition.eval(entity.as_ref(), event) {
                let outcome = ExecutionOutcome::ConditionFalse;
                self.observe(outcome);
                executions.push(RuleExecution {
                    rule_id: rule.id,
                    outcome,
                });
                continue;
            }
            let Some(action) = self.actions.get(&rule.action.kind) else {
                self.observe_action_failure();
                return Err(RuleError::UnknownAction(rule.action.kind.clone()));
            };
            let kind = rule.action.kind.clone();
            let ctx = ActionContext {
                rule: rule.clone(),
                event: event.clone(),
                entity: entity.clone(),
                params: rule.action.params.clone(),
            };
            action.execute(ctx).await.map_err(|_| {
                self.observe_action_failure();
                RuleError::Action(kind)
            })?;
            self.rules.mark_executed(&rule.id, &event.event_id).await?;
            let outcome = ExecutionOutcome::Executed;
            self.observe(outcome);
            executions.push(RuleExecution {
                rule_id: rule.id,
                outcome,
            });
        }
        Ok(executions)
    }

    /// Tails the change feed and processes each entity event until
    /// cancellation.
    ///
    /// The call starts at the persisted cursor.
    /// It reads the head and asks for at most `RULE_BATCH_SIZE` entries after
    /// the cursor.
    /// The range ends at `min(head, cursor + RULE_BATCH_SIZE)`.
    /// The batch size is 256 entries in a normal build.
    /// Tests use a batch of two entries.
    /// It processes each entry in order and then reads the next batch.
    /// It writes the cursor one time after each batch of 32 successful
    /// entries.
    /// It also writes the cursor when the feed is caught up and when the
    /// loop exits.
    /// A non-entity entry does no rule work, but it still moves the cursor.
    /// A process failure writes the last successful sequence and returns the
    /// error.
    /// The cursor never moves past a failed entry.
    /// The failed entry and the entries after it replay on the next run.
    /// The runtime supervisor restarts a failed run after a backoff delay.
    /// The delay starts at one second and doubles up to 60 seconds.
    /// The retried batch starts at the entry that failed.
    /// When the cursor is ahead of the head, the call returns an error and
    /// does not rewind.
    /// When the feed is caught up, the call sleeps for `poll_interval` and
    /// checks cancellation again.
    ///
    /// Delivery is at least once.
    /// A crash can replay the last batch, so at most 32 entries repeat.
    /// An execution marker stops a duplicate action.
    /// An action must still be idempotent.
    pub async fn run<C: CancelToken>(
        &self,
        wal: &Wal,
        cancel: C,
        poll_interval: Duration,
    ) -> Result<(), RuleError> {
        let mut cursor = self.rules.cursor().await?;
        // The number of successful entries since the last cursor write.
        let mut pending: u64 = 0;
        loop {
            if cancel.is_cancelled() {
                if pending > 0 {
                    self.rules.set_cursor(cursor).await?;
                }
                return Ok(());
            }
            let head = wal.head().await.map_err(map_wal_error)?;
            if cursor > head {
                return Err(RuleError::Wal(format!(
                    "rule cursor {cursor} is ahead of feed head {head}"
                )));
            }
            if cursor < head {
                let end = head.min(cursor.saturating_add(RULE_BATCH_SIZE as u64));
                let entries = wal.range(cursor + 1, end).await.map_err(map_wal_error)?;
                for entry in entries {
                    if let WalOp::Entity { event } = &entry.op
                        && let Err(error) = self.process(event).await
                    {
                        // Do not move the cursor past the failed entry. Write
                        // the last successful sequence, so the next run starts
                        // at the failed entry.
                        if pending > 0 {
                            self.rules.set_cursor(cursor).await?;
                        }
                        return Err(error);
                    }
                    cursor = entry.seq;
                    pending += 1;
                    if pending >= CURSOR_BATCH_SIZE {
                        self.rules.set_cursor(cursor).await?;
                        pending = 0;
                    }
                }
                continue;
            }
            // The feed is caught up. Write the last successful sequence before
            // the call waits for new entries.
            if pending > 0 {
                self.rules.set_cursor(cursor).await?;
                pending = 0;
            }
            tokio::time::sleep(poll_interval).await;
        }
    }
}

/// Maps an entity store error into a rule error.
fn map_entity_error(error: EntityError) -> RuleError {
    match error {
        EntityError::Store(error) => RuleError::Store(error),
        other => RuleError::Invalid(other.to_string()),
    }
}

/// Maps a change-feed error into a rule error.
fn map_wal_error(error: crate::fs::error::FsError) -> RuleError {
    RuleError::Wal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::{AttributeValue, Entity, EntityDraft, WriteContext};
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft, SchemaRegistry};
    use crate::records::{ChangeSink, EntityEventKind};
    use crate::rules::rule::{ActionRef, CompareOp, Condition, RuleDraft, RuleTrigger};

    /// A [`RuleAction`] test double that records each context.
    ///
    /// The `failing` switch makes `execute` return an error.
    /// `fail_at_call` makes one numbered call return an error.
    /// The optional notify signals one test when the action ran.
    struct RecordingAction {
        kind: String,
        records: std::sync::Mutex<Vec<ActionContext>>,
        failing: AtomicBool,
        fail_at_call: AtomicUsize,
        notify: Option<Arc<Notify>>,
    }

    impl RecordingAction {
        fn new(kind: &str) -> Self {
            Self {
                kind: kind.to_string(),
                records: std::sync::Mutex::new(Vec::new()),
                failing: AtomicBool::new(false),
                fail_at_call: AtomicUsize::new(0),
                notify: None,
            }
        }

        fn with_notify(mut self, notify: Arc<Notify>) -> Self {
            self.notify = Some(notify);
            self
        }

        fn set_failing(&self, failing: bool) {
            self.failing.store(failing, Ordering::SeqCst);
        }

        /// Makes call number `call` return an error. A value of 0 disables it.
        fn fail_on_call(&self, call: usize) {
            self.fail_at_call.store(call, Ordering::SeqCst);
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
            let call = {
                let mut records = self.records.lock().unwrap();
                records.push(ctx);
                records.len()
            };
            if let Some(notify) = &self.notify {
                notify.notify_one();
            }
            let fail_at = self.fail_at_call.load(Ordering::SeqCst);
            if self.failing.load(Ordering::SeqCst) || (fail_at != 0 && call == fail_at) {
                return Err(anyhow::anyhow!("recording action failed"));
            }
            Ok(())
        }
    }

    /// A [`RuleAction`] test double that coordinates two events.
    ///
    /// The action for `waited_event_id` signals `waiting` and then waits on
    /// `gate`.
    /// The action for any other event signals `gate`.
    /// The pair finishes only when two event locks allow both actions to run.
    struct GatedAction {
        kind: String,
        waited_event_id: String,
        gate: Arc<Notify>,
        waiting: Arc<Notify>,
        calls: AtomicUsize,
    }

    impl GatedAction {
        fn new(kind: &str, waited_event_id: &str, gate: Arc<Notify>) -> Self {
            Self {
                kind: kind.to_string(),
                waited_event_id: waited_event_id.to_string(),
                gate,
                waiting: Arc::new(Notify::new()),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl RuleAction for GatedAction {
        fn kind(&self) -> &str {
            &self.kind
        }

        async fn execute(&self, ctx: ActionContext) -> Result<(), anyhow::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if ctx.event.event_id == self.waited_event_id {
                self.waiting.notify_one();
                self.gate.notified().await;
            } else {
                self.gate.notify_one();
            }
            Ok(())
        }
    }

    /// Waits for two task results and fails the test on a timeout.
    async fn join_two<T>(
        first: &mut tokio::task::JoinHandle<T>,
        second: &mut tokio::task::JoinHandle<T>,
        timeout_message: &str,
    ) -> (T, T) {
        match tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(&mut *first, &mut *second)
        })
        .await
        {
            Ok((first_result, second_result)) => (
                first_result.expect("the first task must not panic"),
                second_result.expect("the second task must not panic"),
            ),
            Err(_) => {
                first.abort();
                second.abort();
                panic!("{timeout_message}");
            }
        }
    }

    /// A [`RuleObserver`] test double that records each result.
    struct RecordingObserver {
        outcomes: std::sync::Mutex<Vec<ExecutionOutcome>>,
        failures: AtomicUsize,
    }

    impl RecordingObserver {
        fn new() -> Self {
            Self {
                outcomes: std::sync::Mutex::new(Vec::new()),
                failures: AtomicUsize::new(0),
            }
        }

        fn outcomes(&self) -> Vec<ExecutionOutcome> {
            self.outcomes.lock().unwrap().clone()
        }

        fn failures(&self) -> usize {
            self.failures.load(Ordering::SeqCst)
        }
    }

    impl RuleObserver for RecordingObserver {
        fn on_execution(&self, outcome: ExecutionOutcome) {
            self.outcomes.lock().unwrap().push(outcome);
        }

        fn on_action_failure(&self) {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A [`RuleAction`] test double that rejects every parameter value.
    struct RejectingAction;
    #[async_trait::async_trait]
    impl RuleAction for RejectingAction {
        fn kind(&self) -> &str {
            "reject"
        }

        fn validate(&self, _params: &serde_json::Value) -> Result<(), anyhow::Error> {
            Err(anyhow::anyhow!("the test action rejects the parameters"))
        }

        async fn execute(&self, _ctx: ActionContext) -> Result<(), anyhow::Error> {
            Ok(())
        }
    }

    /// The shared state of one test.
    struct TestStores {
        rules: RuleStore,
        entities: EntityStore,
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

    async fn stores() -> TestStores {
        let registry =
            SchemaRegistry::new(build_test_store(&test_prefix("rules-engine-schema")).await);
        registry.publish(schema()).await.unwrap();
        let raw = build_test_store(&test_prefix("rules-engine")).await;
        TestStores {
            rules: RuleStore::new(raw.clone()),
            entities: EntityStore::new(raw, registry),
        }
    }

    fn engine(stores: &TestStores, actions: Vec<Arc<dyn RuleAction>>) -> RuleEngine {
        RuleEngine::new(stores.rules.clone(), stores.entities.clone(), actions).unwrap()
    }

    async fn make_entity(entities: &EntityStore) -> Entity {
        entities
            .create(
                EntityDraft {
                    id: "e1".to_string(),
                    schemas: vec!["invoice".to_string()],
                    attributes: BTreeMap::from([(
                        "total".to_string(),
                        AttributeValue::Integer(10),
                    )]),
                },
                &WriteContext::new("tester"),
            )
            .await
            .unwrap()
            .after
            .unwrap()
    }

    fn draft(id: &str, kind: &str) -> RuleDraft {
        RuleDraft {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            priority: 0,
            trigger: RuleTrigger {
                events: vec![EntityEventKind::Created],
                schemas: vec!["invoice".to_string()],
            },
            condition: Condition::Always,
            action: ActionRef {
                kind: kind.to_string(),
                params: serde_json::json!({ "note": "hello" }),
            },
        }
    }

    fn event(kind: EntityEventKind) -> EntityEvent {
        EntityEvent {
            event_id: "evt-1".to_string(),
            entity_id: "e1".to_string(),
            entity_version: 1,
            kind,
            schemas: vec!["invoice".to_string()],
            changed: Vec::new(),
            actor: "tester".to_string(),
            causation_id: None,
            causation_depth: 0,
            correlation_id: "req-1".to_string(),
            snapshot: None,
            occurred_at: 1,
        }
    }

    /// Returns one created event with a unique event id for `seq`.
    fn event_at(seq: u64) -> EntityEvent {
        let mut item = event(EntityEventKind::Created);
        item.event_id = format!("evt-{seq}");
        item
    }

    async fn test_wal() -> Wal {
        Wal::new(build_test_store(&test_prefix("rules-engine-wal")).await)
    }

    async fn wait_for_cursor(rules: &RuleStore, target: u64) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if rules.cursor().await.unwrap() >= target {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_matching_rule_runs_its_action_once() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();

        let executions = engine
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].rule_id, "alpha");
        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);
        assert_eq!(recorder.records().len(), 1);
    }

    #[tokio::test]
    async fn a_recording_observer_sees_each_result() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let observer = Arc::new(RecordingObserver::new());
        let engine = engine(&stores, vec![recorder.clone()]).with_observer(observer.clone());
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let created = event(EntityEventKind::Created);

        engine.process(&created).await.unwrap();
        engine.process(&created).await.unwrap();
        assert_eq!(
            observer.outcomes(),
            vec![
                ExecutionOutcome::Executed,
                ExecutionOutcome::AlreadyExecuted
            ]
        );
        assert_eq!(observer.failures(), 0);

        recorder.set_failing(true);
        let mut failed = event(EntityEventKind::Created);
        failed.event_id = "evt-2".to_string();
        let result = engine.process(&failed).await;

        assert!(matches!(result, Err(RuleError::Action(_))));
        assert_eq!(observer.failures(), 1);
    }

    #[tokio::test]
    async fn a_recording_observer_sees_a_condition_false_and_a_causation_limit() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let observer = Arc::new(RecordingObserver::new());
        let subject = engine(&stores, vec![recorder.clone()]).with_observer(observer.clone());
        make_entity(&stores.entities).await;
        let mut rule = draft("alpha", "record");
        rule.condition = Condition::Compare {
            key: "total".to_string(),
            op: CompareOp::Gt,
            value: serde_json::json!(100),
        };
        stores.rules.upsert(rule).await.unwrap();

        subject
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();
        assert_eq!(observer.outcomes(), vec![ExecutionOutcome::ConditionFalse]);
        assert_eq!(observer.failures(), 0);

        let limited = engine(&stores, vec![recorder.clone()])
            .with_max_causation_depth(0)
            .with_observer(observer.clone());
        let mut deep = event(EntityEventKind::Created);
        deep.event_id = "evt-2".to_string();
        deep.causation_depth = 1;
        limited.process(&deep).await.unwrap();

        assert_eq!(
            observer.outcomes(),
            vec![
                ExecutionOutcome::ConditionFalse,
                ExecutionOutcome::CausationLimit
            ]
        );
        assert!(recorder.records().is_empty());
    }

    #[tokio::test]
    async fn a_repeated_event_returns_already_executed() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let created = event(EntityEventKind::Created);

        engine.process(&created).await.unwrap();
        let second = engine.process(&created).await.unwrap();

        assert_eq!(second[0].outcome, ExecutionOutcome::AlreadyExecuted);
        assert_eq!(recorder.records().len(), 1);
    }

    /// Two calls for one event run the action one time.
    ///
    /// The barrier makes both calls start before either can finish.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_calls_for_one_event_run_the_action_one_time() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let subject = event(EntityEventKind::Created);
        let barrier = Arc::new(tokio::sync::Barrier::new(2));

        let mut first = tokio::spawn({
            let engine = engine.clone();
            let subject = subject.clone();
            let barrier = barrier.clone();
            async move {
                barrier.wait().await;
                engine.process(&subject).await
            }
        });
        let mut second = tokio::spawn({
            let engine = engine.clone();
            let subject = subject.clone();
            let barrier = barrier.clone();
            async move {
                barrier.wait().await;
                engine.process(&subject).await
            }
        });

        let (first_result, second_result) = join_two(
            &mut first,
            &mut second,
            "two calls for one event did not finish: the event lock must not deadlock",
        )
        .await;
        let first_result = first_result.unwrap();
        let second_result = second_result.unwrap();

        let outcomes: Vec<ExecutionOutcome> = first_result
            .into_iter()
            .chain(second_result)
            .map(|item| item.outcome)
            .collect();
        assert_eq!(recorder.records().len(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ExecutionOutcome::Executed)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ExecutionOutcome::AlreadyExecuted)
                .count(),
            1
        );
        assert_eq!(engine.live_process_locks().await, 0);
    }

    /// Two calls for different events do not serialize.
    ///
    /// The action for `evt-a` waits for the action for `evt-b`.
    /// A global lock would block the pair until the timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_calls_for_different_events_do_not_serialize() {
        let stores = stores().await;
        let gate = Arc::new(Notify::new());
        let action = Arc::new(GatedAction::new("record", "evt-a", gate.clone()));
        let engine = engine(&stores, vec![action.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let mut first_event = event_at(1);
        first_event.event_id = "evt-a".to_string();
        let second_event = event_at(2);

        let mut first = tokio::spawn({
            let engine = engine.clone();
            async move { engine.process(&first_event).await }
        });
        tokio::time::timeout(Duration::from_secs(5), action.waiting.notified())
            .await
            .expect("the first action must start and wait before the second call");
        assert_eq!(action.calls(), 1);

        let mut second = tokio::spawn({
            let engine = engine.clone();
            async move { engine.process(&second_event).await }
        });

        let (first_result, second_result) = join_two(
            &mut first,
            &mut second,
            "two different events serialized: the first call blocked the second call",
        )
        .await;
        let first_result = first_result.unwrap();
        let second_result = second_result.unwrap();

        assert_eq!(first_result[0].outcome, ExecutionOutcome::Executed);
        assert_eq!(second_result[0].outcome, ExecutionOutcome::Executed);
        assert_eq!(action.calls(), 2);
        assert_eq!(engine.live_process_locks().await, 0);
    }

    /// The engine removes each event lock after the call.
    #[tokio::test]
    async fn the_process_lock_map_is_empty_after_process_returns() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();

        for seq in 1..=3 {
            engine.process(&event_at(seq)).await.unwrap();
        }

        assert_eq!(engine.live_process_locks().await, 0);
    }

    #[tokio::test]
    async fn a_false_condition_returns_condition_false() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        let mut rule = draft("alpha", "record");
        rule.condition = Condition::Compare {
            key: "total".to_string(),
            op: CompareOp::Gt,
            value: serde_json::json!(100),
        };
        stores.rules.upsert(rule).await.unwrap();

        let executions = engine
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        assert_eq!(executions[0].outcome, ExecutionOutcome::ConditionFalse);
        assert!(recorder.records().is_empty());
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    /// A depth equal to the maximum still runs the action.
    ///
    /// The maximum is inclusive.
    #[tokio::test]
    async fn a_depth_equal_to_the_maximum_runs_the_action() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]).with_max_causation_depth(2);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let mut ev = event(EntityEventKind::Created);
        ev.causation_depth = 2;

        let executions = engine.process(&ev).await.unwrap();

        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);
        assert_eq!(recorder.records().len(), 1);
    }

    /// A depth above the maximum returns `CausationLimit`.
    ///
    /// The engine runs no action and writes no marker.
    #[tokio::test]
    async fn a_depth_above_the_maximum_returns_causation_limit() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]).with_max_causation_depth(2);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let mut ev = event(EntityEventKind::Created);
        ev.causation_depth = 3;

        let executions = engine.process(&ev).await.unwrap();

        assert_eq!(executions.len(), 1);
        assert_eq!(executions[0].rule_id, "alpha");
        assert_eq!(executions[0].outcome, ExecutionOutcome::CausationLimit);
        assert!(recorder.records().is_empty());
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    /// `run` advances the cursor for an over-depth event.
    ///
    /// The guard returns a result, not an error.
    /// The entry is therefore complete and the cursor can move.
    #[tokio::test]
    async fn run_advances_the_cursor_for_an_over_depth_event() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]).with_max_causation_depth(1);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        let mut ev = event(EntityEventKind::Created);
        ev.causation_depth = 2;
        wal.append(WalOp::Entity { event: ev }).await.unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });

        wait_for_cursor(&stores.rules, 1).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert!(recorder.records().is_empty());
        assert_eq!(stores.rules.cursor().await.unwrap(), 1);
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    /// The action helper adds one to the depth and carries the event id.
    ///
    /// An action that writes an entity must use this context.
    #[tokio::test]
    async fn child_write_context_increments_the_depth_and_carries_the_event_id() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();

        engine
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        let records = recorder.records();
        let child = records[0].child_write_context("writer");

        assert_eq!(child.actor, "writer");
        assert_eq!(child.causation_id.as_deref(), Some("evt-1"));
        assert_eq!(child.causation_depth, 1);
    }

    #[tokio::test]
    async fn a_disabled_rule_runs_no_action() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        let mut rule = draft("alpha", "record");
        rule.enabled = false;
        stores.rules.upsert(rule).await.unwrap();

        let executions = engine
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        assert!(executions.is_empty());
        assert!(recorder.records().is_empty());
    }

    #[tokio::test]
    async fn two_rules_run_in_priority_order() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        let mut high = draft("high", "record");
        high.priority = 10;
        let mut low = draft("low", "record");
        low.priority = 1;
        stores.rules.upsert(low).await.unwrap();
        stores.rules.upsert(high).await.unwrap();

        let executions = engine
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        let ids: Vec<String> = executions.into_iter().map(|item| item.rule_id).collect();
        assert_eq!(ids, vec!["high", "low"]);
        let recorded: Vec<String> = recorder
            .records()
            .into_iter()
            .map(|ctx| ctx.rule.id)
            .collect();
        assert_eq!(recorded, vec!["high", "low"]);
    }

    #[tokio::test]
    async fn an_unknown_action_kind_returns_unknown_action() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new());
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(draft("alpha", "missing"))
            .await
            .unwrap();

        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(
            result,
            Err(RuleError::UnknownAction(kind)) if kind == "missing"
        ));
    }

    #[tokio::test]
    async fn an_action_failure_returns_action_and_a_retry_runs_it() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let created = event(EntityEventKind::Created);
        recorder.set_failing(true);

        let result = engine.process(&created).await;

        assert!(matches!(result, Err(RuleError::Action(_))));
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());

        recorder.set_failing(false);
        let retry = engine.process(&created).await.unwrap();

        assert_eq!(retry[0].outcome, ExecutionOutcome::Executed);
        assert!(stores.rules.is_executed("alpha", "evt-1").await.unwrap());
        assert_eq!(recorder.records().len(), 2);
    }

    #[tokio::test]
    async fn the_action_context_carries_the_rule_event_entity_and_params() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();

        engine
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        let records = recorder.records();
        let ctx = &records[0];
        assert_eq!(ctx.rule.id, "alpha");
        assert_eq!(ctx.event.event_id, "evt-1");
        let entity = ctx.entity.as_ref().unwrap();
        assert_eq!(entity.id, "e1");
        assert_eq!(
            entity.attributes.get("total"),
            Some(&AttributeValue::Integer(10))
        );
        assert_eq!(ctx.params, serde_json::json!({ "note": "hello" }));
    }

    #[tokio::test]
    async fn a_delete_event_gives_no_entity() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        let created = make_entity(&stores.entities).await;
        stores
            .entities
            .delete("e1", created.version, &WriteContext::new("tester"))
            .await
            .unwrap();
        let mut rule = draft("alpha", "record");
        rule.trigger.events = vec![EntityEventKind::Deleted];
        stores.rules.upsert(rule).await.unwrap();

        let executions = engine
            .process(&event(EntityEventKind::Deleted))
            .await
            .unwrap();

        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);
        let records = recorder.records();
        assert!(records[0].entity.is_none());
    }

    #[tokio::test]
    async fn run_processes_an_entity_event() {
        let stores = stores().await;
        let notify = Arc::new(Notify::new());
        let recorder = Arc::new(RecordingAction::new("record").with_notify(notify.clone()));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity {
            event: event(EntityEventKind::Created),
        })
        .await
        .unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });

        tokio::time::timeout(Duration::from_secs(2), notify.notified())
            .await
            .unwrap();
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(recorder.records().len(), 1);
        assert_eq!(stores.rules.cursor().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn run_skips_a_non_entity_entry_and_advances_the_cursor() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        let wal = test_wal().await;
        wal.append(WalOp::Attach {
            row_type: "invoice".to_string(),
            row_id: "1".to_string(),
            file_id: "f1".to_string(),
        })
        .await
        .unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });

        wait_for_cursor(&stores.rules, 1).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert!(recorder.records().is_empty());
        assert_eq!(stores.rules.cursor().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn run_leaves_the_cursor_on_the_failed_entry() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        recorder.set_failing(true);
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity {
            event: event(EntityEventKind::Created),
        })
        .await
        .unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            engine.run(
                &wal,
                Arc::new(AtomicBool::new(false)),
                Duration::from_millis(5),
            ),
        )
        .await
        .unwrap();

        assert!(matches!(result, Err(RuleError::Action(_))));
        assert_eq!(stores.rules.cursor().await.unwrap(), 0);
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    /// `run` processes more entries than one cursor batch.
    ///
    /// Every event runs one time, and the cursor ends at the head.
    #[tokio::test]
    async fn run_processes_more_entries_than_one_batch_and_reaches_the_head() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        let total = CURSOR_BATCH_SIZE + 8;
        for seq in 1..=total {
            wal.append(WalOp::Entity {
                event: event_at(seq),
            })
            .await
            .unwrap();
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });
        wait_for_cursor(&stores.rules, total).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let executed: Vec<String> = recorder
            .records()
            .into_iter()
            .map(|ctx| ctx.event.event_id)
            .collect();
        let expected: Vec<String> = (1..=total).map(|seq| format!("evt-{seq}")).collect();
        assert_eq!(executed, expected);
        assert_eq!(stores.rules.cursor().await.unwrap(), total);
    }

    /// `run` processes every entry when the feed holds more than one rule
    /// batch.
    ///
    /// The batch size is small in tests, so a few entries cross the
    /// boundary. Every event runs one time, and the cursor ends at the head.
    #[tokio::test]
    async fn run_processes_more_entries_than_one_rule_batch() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        let total = (RULE_BATCH_SIZE as u64) + 2;
        for seq in 1..=total {
            wal.append(WalOp::Entity {
                event: event_at(seq),
            })
            .await
            .unwrap();
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });
        wait_for_cursor(&stores.rules, total).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let executed: Vec<String> = recorder
            .records()
            .into_iter()
            .map(|ctx| ctx.event.event_id)
            .collect();
        let expected: Vec<String> = (1..=total).map(|seq| format!("evt-{seq}")).collect();
        assert_eq!(executed, expected);
        assert_eq!(stores.rules.cursor().await.unwrap(), total);
    }

    /// A failed entry runs again after a new run and reaches the head.
    ///
    /// The action fails one time. The first run returns the action error and
    /// keeps the cursor before the entry. The second run retries the same
    /// entry and reaches the head.
    #[tokio::test]
    async fn run_retries_a_failed_entry_and_reaches_the_head() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity {
            event: event(EntityEventKind::Created),
        })
        .await
        .unwrap();
        recorder.fail_on_call(1);

        let first = tokio::time::timeout(
            Duration::from_secs(2),
            engine.run(
                &wal,
                Arc::new(AtomicBool::new(false)),
                Duration::from_millis(5),
            ),
        )
        .await
        .unwrap();

        assert!(matches!(first, Err(RuleError::Action(_))));
        assert_eq!(stores.rules.cursor().await.unwrap(), 0);
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });
        wait_for_cursor(&stores.rules, 1).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(recorder.records().len(), 2);
        assert_eq!(stores.rules.cursor().await.unwrap(), 1);
        assert!(stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    /// A failed entry stops the cursor before it.
    ///
    /// The failed entry and the later entries replay on the next run.
    #[tokio::test]
    async fn a_failure_leaves_the_cursor_before_the_entry_and_replays_it() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        for seq in 1..=5 {
            wal.append(WalOp::Entity {
                event: event_at(seq),
            })
            .await
            .unwrap();
        }
        recorder.fail_on_call(3);

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            engine.run(
                &wal,
                Arc::new(AtomicBool::new(false)),
                Duration::from_millis(5),
            ),
        )
        .await
        .unwrap();

        assert!(matches!(result, Err(RuleError::Action(_))));
        assert_eq!(stores.rules.cursor().await.unwrap(), 2);
        assert!(!stores.rules.is_executed("alpha", "evt-3").await.unwrap());
        assert!(!stores.rules.is_executed("alpha", "evt-4").await.unwrap());
        assert!(!stores.rules.is_executed("alpha", "evt-5").await.unwrap());

        recorder.fail_on_call(0);
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });
        wait_for_cursor(&stores.rules, 5).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(stores.rules.cursor().await.unwrap(), 5);
        assert!(stores.rules.is_executed("alpha", "evt-3").await.unwrap());
        assert!(stores.rules.is_executed("alpha", "evt-4").await.unwrap());
        assert!(stores.rules.is_executed("alpha", "evt-5").await.unwrap());
        let executed: Vec<String> = recorder
            .records()
            .into_iter()
            .map(|ctx| ctx.event.event_id)
            .collect();
        assert_eq!(
            executed,
            vec!["evt-1", "evt-2", "evt-3", "evt-3", "evt-4", "evt-5"]
        );
    }

    /// A restart that replays one entry does not run its action again.
    ///
    /// The execution marker stops the duplicate action.
    #[tokio::test]
    async fn a_restart_with_a_replayed_cursor_does_not_rerun_an_executed_event() {
        let stores = stores().await;
        let first = Arc::new(RecordingAction::new("record"));
        let subject = engine(&stores, vec![first.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        for seq in 1..=2 {
            wal.append(WalOp::Entity {
                event: event_at(seq),
            })
            .await
            .unwrap();
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = subject.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });
        wait_for_cursor(&stores.rules, 2).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(first.records().len(), 2);

        // A crash before the last cursor write replays one entry. Move the
        // stored cursor back one entry to model that replay window.
        stores.rules.set_cursor(1).await.unwrap();

        let second = Arc::new(RecordingAction::new("record"));
        let restarted = engine(&stores, vec![second.clone()]);
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = restarted.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });
        wait_for_cursor(&stores.rules, 2).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert!(second.records().is_empty());
        assert_eq!(stores.rules.cursor().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn the_cursor_persists_across_two_engines() {
        let stores = stores().await;
        let notify = Arc::new(Notify::new());
        let recorder = Arc::new(RecordingAction::new("record").with_notify(notify.clone()));
        let first = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity {
            event: event(EntityEventKind::Created),
        })
        .await
        .unwrap();

        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = first.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });
        tokio::time::timeout(Duration::from_secs(2), notify.notified())
            .await
            .unwrap();
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let second =
            RuleEngine::new(stores.rules.clone(), stores.entities.clone(), Vec::new()).unwrap();

        assert_eq!(second.rules.cursor().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_cursor_ahead_of_the_head_returns_an_error() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new());
        stores.rules.set_cursor(5).await.unwrap();
        let wal = test_wal().await;

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            engine.run(
                &wal,
                Arc::new(AtomicBool::new(false)),
                Duration::from_millis(5),
            ),
        )
        .await
        .unwrap();

        assert!(matches!(
            result,
            Err(RuleError::Wal(message)) if message.contains("ahead")
        ));
        assert_eq!(stores.rules.cursor().await.unwrap(), 5);
    }

    #[tokio::test]
    async fn has_action_reports_the_registered_kinds() {
        let stores = stores().await;
        let engine = engine(&stores, vec![Arc::new(RecordingAction::new("record"))]);

        assert!(engine.has_action("record"));
        assert!(!engine.has_action("ghost"));
    }

    #[tokio::test]
    async fn validate_action_rejects_an_unknown_kind() {
        let stores = stores().await;
        let engine = engine(&stores, vec![Arc::new(RecordingAction::new("record"))]);

        let result = engine.validate_action("ghost", &serde_json::json!({}));

        assert!(matches!(
            result,
            Err(RuleError::UnknownAction(kind)) if kind == "ghost"
        ));
    }

    #[tokio::test]
    async fn validate_action_accepts_a_default_valid_action() {
        let stores = stores().await;
        let engine = engine(&stores, vec![Arc::new(RecordingAction::new("record"))]);

        let result = engine.validate_action("record", &serde_json::json!({ "any": "value" }));

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn validate_action_rejects_a_failed_check_with_a_generic_error() {
        let stores = stores().await;
        let engine = engine(&stores, vec![Arc::new(RejectingAction)]);
        let params = serde_json::json!({ "url": "https://secret.example/hook" });

        let result = engine.validate_action("reject", &params);

        match result {
            Err(RuleError::Invalid(message)) => {
                assert_eq!(message, "rule action parameters are not valid");
                assert!(!message.contains("secret.example"));
            }
            other => panic!("expected a generic invalid error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn duplicate_and_empty_action_kinds_fail_in_new() {
        let stores = stores().await;
        let first = Arc::new(RecordingAction::new("dup"));
        let second = Arc::new(RecordingAction::new("dup"));

        let duplicate = RuleEngine::new(
            stores.rules.clone(),
            stores.entities.clone(),
            vec![first, second],
        );

        assert!(matches!(
            duplicate,
            Err(RuleError::DuplicateAction(kind)) if kind == "dup"
        ));

        let empty = Arc::new(RecordingAction::new(""));
        let result = RuleEngine::new(stores.rules.clone(), stores.entities.clone(), vec![empty]);

        assert!(matches!(result, Err(RuleError::Invalid(_))));
    }
}
