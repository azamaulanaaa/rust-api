//! The generic rule runner.
//!
//! [`RuleEngine::process`] runs the matching rules for one entity event.
//! [`RuleEngine::run`] tails the durable change feed and calls `process`.
//! Delivery is at least once.
//! An action must be idempotent because a crash can repeat one event.
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
use crate::eav::entity::EntityStore;
use crate::eav::entity_error::EntityError;
use crate::records::{EntityEvent, WalOp};
use crate::rules::action::{ActionContext, RuleAction};
use crate::rules::error::RuleError;
use crate::rules::rule::validate_identifier;
use crate::rules::store::RuleStore;
use crate::sync::wal::Wal;

/// The default maximum causation depth.
///
/// A chain deeper than this value is a runaway chain.
const DEFAULT_MAX_CAUSATION_DEPTH: u32 = 8;

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

/// The generic rule runner.
///
/// The engine holds one action for each registered kind.
/// One process mutex stops two calls from running one rule and one event
/// twice.
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
    /// Serializes processing, so one rule and one event run one time.
    process_lock: Arc<Mutex<()>>,
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
            process_lock: Arc::new(Mutex::new(())),
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

    /// Runs the matching rules for one entity event.
    ///
    /// The call loads the current entity first.
    /// A deleted entity gives `None`.
    /// It then lists the enabled matching rules in priority order.
    /// If the event depth is above the maximum, it returns one
    /// [`ExecutionOutcome::CausationLimit`] for each matching rule.
    /// It then runs no action and writes no marker.
    /// Otherwise, for each rule it checks the execution marker, evaluates the
    /// condition, finds the action, and calls the action.
    /// A successful action writes the marker for this rule and event.
    /// A failed action writes no marker, so a later retry can run it again.
    pub async fn process(&self, event: &EntityEvent) -> Result<Vec<RuleExecution>, RuleError> {
        let _process = self.process_lock.lock().await;
        let entity = self
            .entities
            .get(&event.entity_id)
            .await
            .map_err(map_entity_error)?;
        let rules = self.rules.matching(event).await?;
        if event.causation_depth > self.max_causation_depth {
            return Ok(rules
                .into_iter()
                .map(|rule| RuleExecution {
                    rule_id: rule.id,
                    outcome: ExecutionOutcome::CausationLimit,
                })
                .collect());
        }
        let mut executions = Vec::with_capacity(rules.len());

        for rule in rules {
            if self.rules.is_executed(&rule.id, &event.event_id).await? {
                executions.push(RuleExecution {
                    rule_id: rule.id,
                    outcome: ExecutionOutcome::AlreadyExecuted,
                });
                continue;
            }
            if !rule.condition.eval(entity.as_ref(), event) {
                executions.push(RuleExecution {
                    rule_id: rule.id,
                    outcome: ExecutionOutcome::ConditionFalse,
                });
                continue;
            }
            let Some(action) = self.actions.get(&rule.action.kind) else {
                return Err(RuleError::UnknownAction(rule.action.kind.clone()));
            };
            let kind = rule.action.kind.clone();
            let ctx = ActionContext {
                rule: rule.clone(),
                event: event.clone(),
                entity: entity.clone(),
                params: rule.action.params.clone(),
            };
            action
                .execute(ctx)
                .await
                .map_err(|_| RuleError::Action(kind))?;
            self.rules.mark_executed(&rule.id, &event.event_id).await?;
            executions.push(RuleExecution {
                rule_id: rule.id,
                outcome: ExecutionOutcome::Executed,
            });
        }
        Ok(executions)
    }

    /// Tails the change feed and processes each entity event until
    /// cancellation.
    ///
    /// The call starts at the persisted cursor.
    /// It reads the head and asks for the range after the cursor.
    /// It processes each entry in order and persists the cursor after each
    /// success.
    /// A non-entity entry does no rule work, but it still moves the cursor.
    /// A process failure returns the error, and the cursor stays on the
    /// failed entry.
    /// When the cursor is ahead of the head, the call returns an error and
    /// does not rewind.
    /// When the feed is caught up, the call sleeps for `poll_interval` and
    /// checks cancellation again.
    ///
    /// Delivery is at least once.
    /// A crash can repeat one event.
    /// An action must be idempotent.
    pub async fn run<C: CancelToken>(
        &self,
        wal: &Wal,
        cancel: C,
        poll_interval: Duration,
    ) -> Result<(), RuleError> {
        let mut cursor = self.rules.cursor().await?;
        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }
            let head = wal.head().await.map_err(map_wal_error)?;
            if cursor > head {
                return Err(RuleError::Wal(format!(
                    "rule cursor {cursor} is ahead of feed head {head}"
                )));
            }
            if cursor < head {
                let entries = wal.range(cursor + 1, head).await.map_err(map_wal_error)?;
                for entry in entries {
                    if let WalOp::Entity { event } = &entry.op {
                        self.process(event).await?;
                    }
                    self.rules.set_cursor(entry.seq).await?;
                    cursor = entry.seq;
                }
                continue;
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
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::sync::Notify;

    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::{AttributeValue, Entity, EntityDraft, WriteContext};
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft, SchemaRegistry};
    use crate::records::{ChangeSink, EntityEventKind};
    use crate::rules::rule::{ActionRef, CompareOp, Condition, RuleDraft, RuleTrigger};

    /// A [`RuleAction`] test double that records each context.
    ///
    /// The `failing` switch makes `execute` return an error.
    /// The optional notify signals one test when the action ran.
    struct RecordingAction {
        kind: String,
        records: std::sync::Mutex<Vec<ActionContext>>,
        failing: AtomicBool,
        notify: Option<Arc<Notify>>,
    }

    impl RecordingAction {
        fn new(kind: &str) -> Self {
            Self {
                kind: kind.to_string(),
                records: std::sync::Mutex::new(Vec::new()),
                failing: AtomicBool::new(false),
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
            if let Some(notify) = &self.notify {
                notify.notify_one();
            }
            if self.failing.load(Ordering::SeqCst) {
                return Err(anyhow::anyhow!("recording action failed"));
            }
            Ok(())
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
