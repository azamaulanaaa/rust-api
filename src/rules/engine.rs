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
//!
//! A failed entry can block the feed forever.
//! The engine counts failed attempts for one entry in
//! `rule-attempt:{seq}:{event_id}`.
//! The count is durable, so a restart continues it.
//! The limit is `MAX_ENTRY_ATTEMPTS`: 5 in a normal build and 2 in a test
//! build.
//! Below the limit, the run keeps the cursor before the failed entry.
//! The runtime supervisor restarts a failed run after a backoff delay.
//! The delay starts at one second and doubles up to 60 seconds.
//! A failed rule does not stop the later rules in the same entry.
//! The engine runs every matching rule and collects the failures.
//! At the limit, the engine writes one dead-letter row for each failed rule
//! in `rule-dead:{seq}:{event_id}:{rule_id}`.
//! It deletes the attempt row, writes the cursor at the failed sequence, and
//! continues with the next entry.
//! A dead-letter row holds the sequence, the event id, the rule id, the
//! attempt count, the sanitized error text, and the write time.
//! The execution-marker cleanup deletes a dead letter older than 7 days.
//!
//! A script action writes its execution marker in the entity-store
//! transaction.
//! The engine reads that marker from the entity store.
//! Every other action uses the rule-store marker.
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
//!
//! A [`Condition::Script`] runs through
//! [the script engine](crate::rules::script::ScriptEngine).
//! A script error is a rule error.
//! A stored script fails when the server disables scripts.
//!
//! A condition script obeys the read capability set of its rule, as an action
//! script does.
//! It sees only the entity attributes that the allowed pinned schemas define.
//! It sees only the `event.changed` entries for allowed attribute keys.
//! It keeps the entity identity fields: `id`, `version`, and `schemas`.
//! It also keeps the event metadata fields: `event_id`, `entity_id`, `kind`,
//! `schemas`, `correlation_id`, and `causation_id`.
//! An empty read set grants no attribute, so `entity.attributes` is empty and
//! `event.changed` is empty.
//! The engine evaluates a condition script on a blocking thread, as it does
//! for an action script.
//! The operation and wall-time limits still apply.
//!
//! [`RuleEngine::run_with_progress`] sends one health signal after a real
//! cursor advance and after one healthy idle poll.
//! A caller can clear a failure flag only after this signal.
//! A runner that makes no progress sends no signal.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use tokio::sync::Mutex;

use crate::CancelToken;
use crate::eav::entity::{Entity, EntityStore, WriteContext};
use crate::eav::entity_error::EntityError;
use crate::records::{EntityEvent, WalOp};
use crate::rules::action::{ActionContext, RuleAction};
use crate::rules::effect::EffectPlan;
use crate::rules::error::RuleError;
use crate::rules::rule::{Condition, Rule, validate_identifier};
use crate::rules::script::{
    MAX_SOURCE_BYTES, SCRIPT_ACTION_KIND, ScriptActionContext, ScriptContext, ScriptEngine,
    ScriptError, ScriptHost, visible_attribute_keys,
};
use crate::rules::store::{RuleDeadLetter, RuleStore};
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

/// The number of failed attempts before the engine dead-letters one entry.
#[cfg(not(test))]
const MAX_ENTRY_ATTEMPTS: u32 = 5;

/// The number of failed attempts before the engine dead-letters one entry.
///
/// Tests use a small limit, so a test reaches the limit with few runs.
#[cfg(test)]
const MAX_ENTRY_ATTEMPTS: u32 = 2;

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

    /// Records one or more dead-letter rows.
    ///
    /// The default does nothing.
    fn on_dead_letter(&self, _count: u64) {}

    /// Records the distance from the rule cursor to the feed head.
    ///
    /// The default does nothing.
    fn on_feed_lag(&self, _entries: u64) {}
}

/// Receives the health signal from [`RuleEngine::run_with_progress`].
///
/// The engine calls [`RuleProgress::record`] after it advances the cursor and
/// after one healthy idle poll.
/// A caller clears a failure flag only after this call.
/// A runner that makes no progress records nothing.
pub trait RuleProgress: Send + Sync {
    /// Records one real cursor advance or one healthy idle poll.
    fn record(&self);
}

/// A [`RuleProgress`] that records nothing.
///
/// [`RuleEngine::run`] uses this value.
pub struct NoProgress;

impl RuleProgress for NoProgress {
    fn record(&self) {}
}

impl<F> RuleProgress for F
where
    F: Fn() + Send + Sync,
{
    fn record(&self) {
        self();
    }
}

/// One rule that failed during one pass.
#[derive(Debug)]
struct RuleFailure {
    /// The id of the failed rule.
    rule_id: String,
    /// The rule error.
    error: RuleError,
}

/// The complete result of one pass over the matching rules.
#[derive(Debug)]
struct RulePass {
    /// The result for each rule that did not fail.
    executions: Vec<RuleExecution>,
    /// The rules that failed in this pass.
    failures: Vec<RuleFailure>,
}

impl RulePass {
    /// Returns one empty pass.
    fn empty() -> Self {
        Self {
            executions: Vec::new(),
            failures: Vec::new(),
        }
    }
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
    /// The sandboxed condition script engine.
    script: ScriptEngine,
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
            script: ScriptEngine::new(false),
            process_locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Returns true when the engine has a registered action of `kind`.
    ///
    /// A rule can name only a registered kind.
    /// The built-in `script` kind is always present.
    pub fn has_action(&self, kind: &str) -> bool {
        kind == SCRIPT_ACTION_KIND || self.actions.contains_key(kind)
    }

    /// Checks the parameters for one registered action kind.
    ///
    /// The API calls this check before it stores a rule.
    /// An unknown kind returns [`RuleError::UnknownAction`].
    /// A failed check returns [`RuleError::Invalid`] with a generic message.
    /// The message never repeats the parameter or the URL.
    ///
    /// A `script` action requires one non-empty `source` string of at most
    /// 64 KiB.
    /// The source must compile.
    /// An unknown parameter key is invalid.
    /// A disabled script feature is invalid.
    /// The error never repeats the source.
    pub fn validate_action(&self, kind: &str, params: &serde_json::Value) -> Result<(), RuleError> {
        if kind == SCRIPT_ACTION_KIND {
            let source = script_source(params)?;
            return self
                .script
                .compile(source)
                .map_err(|error| RuleError::Invalid(error.to_string()));
        }
        let action = self
            .actions
            .get(kind)
            .ok_or_else(|| RuleError::UnknownAction(kind.to_string()))?;
        action
            .validate(params)
            .map_err(|_| RuleError::Invalid("rule action parameters are not valid".to_string()))
    }

    /// Sets the condition-script feature flag.
    ///
    /// The default is `false`.
    /// A disabled engine rejects every script at save time and at run time.
    pub fn with_script_enabled(mut self, enabled: bool) -> Self {
        self.script = ScriptEngine::new(enabled);
        self
    }

    /// Checks one condition before the store writes the rule.
    ///
    /// A script condition must compile.
    /// A disabled script feature returns an invalid error.
    /// A compile failure returns an invalid error with a stable message.
    /// The error never repeats the script source.
    pub fn validate_condition(&self, condition: &Condition) -> Result<(), RuleError> {
        match condition {
            Condition::Script { source } => self
                .script
                .compile(source)
                .map_err(|error| RuleError::Invalid(error.to_string())),
            Condition::Not(child) => self.validate_condition(child),
            Condition::All(children) | Condition::Any(children) => {
                for child in children {
                    self.validate_condition(child)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
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

    /// Records dead-letter rows when an observer exists.
    fn observe_dead_letters(&self, count: u64) {
        if let Some(observer) = &self.observer {
            observer.on_dead_letter(count);
        }
    }

    /// Records the feed lag when an observer exists.
    fn observe_feed_lag(&self, entries: u64) {
        if let Some(observer) = &self.observer {
            observer.on_feed_lag(entries);
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
    /// A failed rule does not stop the later rules in the same pass.
    /// The call returns the first rule error after the pass finishes.
    /// The call removes the lock entry when the last caller releases it.
    pub async fn process(&self, event: &EntityEvent) -> Result<Vec<RuleExecution>, RuleError> {
        let pass = self.process_pass(event).await?;
        if let Some(failure) = pass.failures.into_iter().next() {
            return Err(failure.error);
        }
        Ok(pass.executions)
    }

    /// Runs one pass and keeps the rule failures.
    ///
    /// The caller uses the failures to name each failed rule.
    /// An entry-level error returns `Err`.
    /// A rule-level error enters the returned [`RulePass`].
    async fn process_pass(&self, event: &EntityEvent) -> Result<RulePass, RuleError> {
        let entity = self
            .entities
            .get(&event.entity_id)
            .await
            .map_err(map_entity_error)?;
        let rules = self.rules.matching(event).await?;
        if event.causation_depth > self.max_causation_depth {
            let mut pass = RulePass::empty();
            for rule in rules {
                let outcome = ExecutionOutcome::CausationLimit;
                self.observe(outcome);
                pass.executions.push(RuleExecution {
                    rule_id: rule.id,
                    outcome,
                });
            }
            return Ok(pass);
        }

        let lock = self.event_process_lock(&event.event_id).await;
        let guard = lock.lock().await;
        let pass = self.run_rules(event, entity, rules).await;
        drop(guard);
        self.release_process_lock(&event.event_id, &lock).await;
        Ok(pass)
    }

    /// Runs the loaded rules for one event under the event lock.
    ///
    /// The caller holds the lock for `event.event_id`.
    /// A successful action writes the marker for this rule and event.
    /// A failed action writes no marker.
    /// The call continues with the later rules after one rule fails.
    async fn run_rules(
        &self,
        event: &EntityEvent,
        entity: Option<Entity>,
        rules: Vec<Rule>,
    ) -> RulePass {
        let mut pass = RulePass::empty();
        for rule in rules {
            match self.run_one_rule(&rule, event, entity.as_ref()).await {
                Ok(outcome) => {
                    self.observe(outcome);
                    pass.executions.push(RuleExecution {
                        rule_id: rule.id,
                        outcome,
                    });
                }
                Err(error) => pass.failures.push(RuleFailure {
                    rule_id: rule.id,
                    error,
                }),
            }
        }
        pass
    }

    /// Runs one rule for one event.
    ///
    /// A script action reads its marker from the entity store.
    /// Every other action reads its marker from the rule store.
    /// A script action writes its marker in the effect transaction.
    async fn run_one_rule(
        &self,
        rule: &Rule,
        event: &EntityEvent,
        entity: Option<&Entity>,
    ) -> Result<ExecutionOutcome, RuleError> {
        let marker_exists = if rule.action.kind == SCRIPT_ACTION_KIND {
            let key = RuleStore::execution_key(&rule.id, &event.event_id);
            self.entities
                .has_execution_marker(&key)
                .await
                .map_err(map_entity_error)?
        } else {
            self.rules.is_executed(&rule.id, &event.event_id).await?
        };
        if marker_exists {
            return Ok(ExecutionOutcome::AlreadyExecuted);
        }
        if !self.eval_condition(rule, event, entity).await? {
            return Ok(ExecutionOutcome::ConditionFalse);
        }
        if rule.action.kind == SCRIPT_ACTION_KIND {
            self.run_script_action(rule, event, entity)
                .await
                .inspect_err(|_| self.observe_action_failure())?;
        } else {
            let Some(action) = self.actions.get(&rule.action.kind) else {
                self.observe_action_failure();
                return Err(RuleError::UnknownAction(rule.action.kind.clone()));
            };
            let kind = rule.action.kind.clone();
            let ctx = ActionContext {
                rule: rule.clone(),
                event: event.clone(),
                entity: entity.cloned(),
                params: rule.action.params.clone(),
            };
            action.execute(ctx).await.map_err(|_| {
                self.observe_action_failure();
                RuleError::Action(kind)
            })?;
            self.rules.mark_executed(&rule.id, &event.event_id).await?;
        }
        Ok(ExecutionOutcome::Executed)
    }

    /// Evaluates one condition tree, including every nested script.
    ///
    /// A script condition runs on a blocking thread through
    /// [`ScriptEngine::eval_bool`], so a script cannot block the async reactor.
    /// The call computes the visible attribute keys from the rule read set.
    /// It returns an empty set when the rule grants no read access.
    /// A tree with no script condition reads no schema.
    /// A script error stops the rule and returns the sanitized error.
    async fn eval_condition(
        &self,
        rule: &Rule,
        event: &EntityEvent,
        entity: Option<&Entity>,
    ) -> Result<bool, RuleError> {
        let ctx = ScriptContext {
            event,
            entity,
            now: chrono::Utc::now().timestamp(),
        };
        let visible = if has_script_condition(&rule.condition) {
            let read = rule.capabilities.to_script_capabilities()?;
            Some(
                visible_attribute_keys(&self.entities, &read, entity, event)
                    .await
                    .map_err(RuleError::Script)?,
            )
        } else {
            None
        };
        self.eval_condition_with(&rule.condition, &ctx, visible.as_ref())
            .await
    }

    /// Evaluates one condition node against one script context.
    ///
    /// A script node clones the entity and the event, because the blocking
    /// task must own its data.
    /// Every other node reads the borrowed context.
    fn eval_condition_with<'a>(
        &'a self,
        condition: &'a Condition,
        ctx: &'a ScriptContext<'a>,
        visible: Option<&'a BTreeSet<String>>,
    ) -> BoxFuture<'a, Result<bool, RuleError>> {
        Box::pin(async move {
            match condition {
                Condition::Script { source } => {
                    let script = self.script.clone();
                    let source = source.clone();
                    let event = ctx.event.clone();
                    let entity = ctx.entity.cloned();
                    let now = ctx.now;
                    let visible = visible.cloned();
                    tokio::task::spawn_blocking(move || {
                        let ctx = ScriptContext {
                            event: &event,
                            entity: entity.as_ref(),
                            now,
                        };
                        script.eval_bool(&source, &ctx, visible.as_ref())
                    })
                    .await
                    .map_err(|_| RuleError::Script(ScriptError::Runtime))?
                    .map_err(RuleError::Script)
                }
                Condition::All(children) => {
                    for child in children {
                        if !self.eval_condition_with(child, ctx, visible).await? {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                Condition::Any(children) => {
                    for child in children {
                        if self.eval_condition_with(child, ctx, visible).await? {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                Condition::Not(child) => Ok(!self.eval_condition_with(child, ctx, visible).await?),
                other => Ok(other.eval(ctx.entity, ctx.event)),
            }
        })
    }

    /// Runs one script action and commits its effects with the marker.
    ///
    /// The call builds a host with the read and write capability sets.
    /// It evaluates the script on a blocking thread.
    /// The host captures the runtime handle, so a host method can call
    /// `block_on` without blocking the async reactor.
    /// The call validates the effect plan and accepts an empty plan.
    /// It builds the execution marker with the rule id and the event id.
    /// One transaction commits the effects and the marker.
    /// A script error or an effect error writes no marker and no effect.
    async fn run_script_action(
        &self,
        rule: &Rule,
        event: &EntityEvent,
        entity: Option<&Entity>,
    ) -> Result<(), RuleError> {
        let source = script_source(&rule.action.params)?.to_string();
        let host = ScriptHost::new(
            self.entities.clone(),
            rule.capabilities.to_script_capabilities()?,
            rule.capabilities.write.clone(),
            rule.id.clone(),
            event.event_id.clone(),
            tokio::runtime::Handle::current(),
        );
        let ctx = ScriptActionContext {
            event: event.clone(),
            entity: entity.cloned(),
            now: chrono::Utc::now().timestamp(),
        };
        let script = self.script.clone();
        let effects = tokio::task::spawn_blocking(move || script.eval_action(&source, &ctx, host))
            .await
            .map_err(|_| RuleError::Script(ScriptError::Runtime))??;

        let plan = EffectPlan::new(effects);
        plan.validate_allow_empty().map_err(map_entity_error)?;
        let key = RuleStore::execution_key(&rule.id, &event.event_id);
        let value = RuleStore::execution_marker_value(chrono::Utc::now().timestamp())?;
        let ctx = WriteContext::new(format!("rule:{}", rule.id))
            .with_correlation_id(event.correlation_id.clone())
            .with_causation(
                event.event_id.clone(),
                event.causation_depth.saturating_add(1),
            );
        self.entities
            .apply_effects_with_marker(&plan, &ctx, Some((&key, &value)))
            .await
            .map_err(map_entity_error)?;
        Ok(())
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
    ///
    /// # Failure policy
    ///
    /// A process failure increments the attempt row
    /// `rule-attempt:{seq}:{event_id}`.
    /// The row holds a JSON `u32` and is durable, so a restart continues the
    /// count.
    /// The limit is `MAX_ENTRY_ATTEMPTS`: 5 in a normal build and 2 in a test
    /// build.
    /// A rule failure does not stop the later rules in the same entry.
    /// Below the limit, the call writes the last successful sequence and
    /// returns the first rule error.
    /// The cursor stays before the failed entry.
    /// The failed entry and the entries after it replay on the next run.
    /// The runtime supervisor restarts a failed run after a backoff delay.
    /// The delay starts at one second and doubles up to 60 seconds.
    /// The retried batch starts at the entry that failed.
    ///
    /// At the limit, the call writes one dead-letter row for each failed rule
    /// in `rule-dead:{seq}:{event_id}:{rule_id}`.
    /// Each row holds the sequence, the event id, the rule id, the attempt
    /// count, the sanitized error text, and the Unix time.
    /// An entry-level error writes one row with an empty rule id.
    /// The call then deletes the attempt row, writes the cursor at the failed
    /// sequence, resets the pending count, and continues with the next entry.
    /// A later entry can therefore make progress.
    /// The execution-marker cleanup deletes a dead letter older than 7 days.
    ///
    /// A successful entry deletes its attempt row.
    /// An entry never skips before the limit.
    ///
    /// When the cursor is ahead of the head, the call returns an error and
    /// does not rewind.
    /// When the feed is caught up, the call sleeps for `poll_interval` and
    /// checks cancellation again.
    ///
    /// Delivery is at least once for an entry below the limit.
    /// A crash can replay the last batch, so at most 32 entries repeat.
    /// An execution marker stops a duplicate action.
    /// An action must still be idempotent.
    /// A dead-lettered entry is failed by policy and stays visible in the
    /// dead-letter rows.
    ///
    /// # Progress signal
    ///
    /// [`RuleEngine::run`] records no progress.
    /// [`RuleEngine::run_with_progress`] calls [`RuleProgress::record`] after
    /// each real cursor advance and after one healthy idle poll.
    /// A failed entry below the attempt limit records no progress.
    /// A dead-lettered entry records progress after it moves the cursor.
    pub async fn run<C: CancelToken>(
        &self,
        wal: &Wal,
        cancel: C,
        poll_interval: Duration,
    ) -> Result<(), RuleError> {
        self.run_with_progress(wal, cancel, poll_interval, &NoProgress)
            .await
    }

    /// Tails the change feed and records a health signal for each real step.
    ///
    /// The call behaves as [`RuleEngine::run`] does.
    /// It also calls [`RuleProgress::record`] after each cursor advance and
    /// after one healthy idle poll.
    /// The call records no signal when a failed entry stops the run below the
    /// attempt limit.
    pub async fn run_with_progress<C: CancelToken, P: RuleProgress + ?Sized>(
        &self,
        wal: &Wal,
        cancel: C,
        poll_interval: Duration,
        progress: &P,
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
            self.observe_feed_lag(head.saturating_sub(cursor));
            if cursor > head {
                return Err(RuleError::Wal(format!(
                    "rule cursor {cursor} is ahead of feed head {head}"
                )));
            }
            if cursor < head {
                let end = head.min(cursor.saturating_add(RULE_BATCH_SIZE as u64));
                let entries = wal.range(cursor + 1, end).await.map_err(map_wal_error)?;
                for entry in entries {
                    if let WalOp::Entity { event } = &entry.op {
                        match self.process_pass(event).await {
                            Ok(pass) if pass.failures.is_empty() => {
                                self.rules
                                    .clear_entry_attempts(entry.seq, &event.event_id)
                                    .await?;
                            }
                            Ok(pass) => {
                                let attempts = self
                                    .rules
                                    .increment_entry_attempts(entry.seq, &event.event_id)
                                    .await?;
                                if attempts < MAX_ENTRY_ATTEMPTS {
                                    // Do not move the cursor past the failed
                                    // entry. Write the last successful
                                    // sequence, so the next run starts at the
                                    // failed entry.
                                    if pending > 0 {
                                        self.rules.set_cursor(cursor).await?;
                                    }
                                    let Some(failure) = pass.failures.into_iter().next() else {
                                        return Err(RuleError::Invalid(
                                            "rule pass holds no failure".to_string(),
                                        ));
                                    };
                                    return Err(failure.error);
                                }
                                for failure in pass.failures {
                                    let dead = RuleDeadLetter {
                                        seq: entry.seq,
                                        event_id: event.event_id.clone(),
                                        rule_id: failure.rule_id,
                                        attempts,
                                        error: failure.error.to_string(),
                                        at: chrono::Utc::now().timestamp(),
                                    };
                                    self.rules.write_dead_letter(&dead).await?;
                                    self.observe_dead_letters(1);
                                }
                                self.rules
                                    .clear_entry_attempts(entry.seq, &event.event_id)
                                    .await?;
                                // The entry is failed by policy. Move the
                                // cursor past it, so later entries can run.
                                self.rules.set_cursor(entry.seq).await?;
                                tracing::warn!(
                                    seq = entry.seq,
                                    event_id = %event.event_id,
                                    attempts,
                                    "rule entry dead-lettered after the attempt limit"
                                );
                                cursor = entry.seq;
                                pending = 0;
                                progress.record();
                                continue;
                            }
                            Err(error) => {
                                let attempts = self
                                    .rules
                                    .increment_entry_attempts(entry.seq, &event.event_id)
                                    .await?;
                                if attempts < MAX_ENTRY_ATTEMPTS {
                                    // Do not move the cursor past the failed
                                    // entry. Write the last successful
                                    // sequence, so the next run starts at the
                                    // failed entry.
                                    if pending > 0 {
                                        self.rules.set_cursor(cursor).await?;
                                    }
                                    return Err(error);
                                }
                                let dead = RuleDeadLetter {
                                    seq: entry.seq,
                                    event_id: event.event_id.clone(),
                                    rule_id: String::new(),
                                    attempts,
                                    error: error.to_string(),
                                    at: chrono::Utc::now().timestamp(),
                                };
                                self.rules.write_dead_letter(&dead).await?;
                                self.observe_dead_letters(1);
                                self.rules
                                    .clear_entry_attempts(entry.seq, &event.event_id)
                                    .await?;
                                // The entry is failed by policy. Move the
                                // cursor past it, so later entries can run.
                                self.rules.set_cursor(entry.seq).await?;
                                tracing::warn!(
                                    seq = entry.seq,
                                    event_id = %event.event_id,
                                    attempts,
                                    "rule entry dead-lettered after the attempt limit"
                                );
                                cursor = entry.seq;
                                pending = 0;
                                progress.record();
                                continue;
                            }
                        }
                    }
                    cursor = entry.seq;
                    pending += 1;
                    progress.record();
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
            // A caught-up feed is healthy: the engine read the head and found
            // the cursor equal to it.
            progress.record();
            tokio::time::sleep(poll_interval).await;
        }
    }
}

/// True when one condition tree holds a script node.
///
/// The engine reads no schema for a tree with no script node.
fn has_script_condition(condition: &Condition) -> bool {
    match condition {
        Condition::Script { .. } => true,
        Condition::All(children) | Condition::Any(children) => {
            children.iter().any(has_script_condition)
        }
        Condition::Not(child) => has_script_condition(child),
        _ => false,
    }
}

/// Returns the source of one script action.
///
/// The parameters must be an object with exactly one `source` string.
/// The source must not be empty.
/// The source must not be larger than 64 KiB.
/// Each failure returns a stable error that never repeats the source.
fn script_source(params: &serde_json::Value) -> Result<&str, RuleError> {
    let invalid = || RuleError::Invalid("rule script action parameters are not valid".to_string());
    let object = params.as_object().ok_or_else(invalid)?;
    if object.keys().any(|key| key != "source") {
        return Err(invalid());
    }
    let source = object
        .get("source")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    if source.is_empty() {
        return Err(invalid());
    }
    if source.len() > MAX_SOURCE_BYTES {
        return Err(RuleError::Invalid(ScriptError::SourceTooLarge.to_string()));
    }
    Ok(source)
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
    use crate::records::{AttributeChange, ChangeSink, EntityEventKind};
    use crate::rules::rule::{ActionRef, CompareOp, Condition, RuleDraft, RuleTrigger};
    use crate::rules::script::{MAX_SOURCE_BYTES, ScriptError};
    use oxkv::{GetSet as _, Hooks as _, KeyPrefix, OxKvStore, ScanExt as _};

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
        dead_letters: AtomicUsize,
        max_feed_lag: AtomicUsize,
    }

    impl RecordingObserver {
        fn new() -> Self {
            Self {
                outcomes: std::sync::Mutex::new(Vec::new()),
                failures: AtomicUsize::new(0),
                dead_letters: AtomicUsize::new(0),
                max_feed_lag: AtomicUsize::new(0),
            }
        }

        fn outcomes(&self) -> Vec<ExecutionOutcome> {
            self.outcomes.lock().unwrap().clone()
        }

        fn failures(&self) -> usize {
            self.failures.load(Ordering::SeqCst)
        }

        fn dead_letters(&self) -> usize {
            self.dead_letters.load(Ordering::SeqCst)
        }

        fn max_feed_lag(&self) -> usize {
            self.max_feed_lag.load(Ordering::SeqCst)
        }
    }

    impl RuleObserver for RecordingObserver {
        fn on_execution(&self, outcome: ExecutionOutcome) {
            self.outcomes.lock().unwrap().push(outcome);
        }

        fn on_action_failure(&self) {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }

        fn on_dead_letter(&self, count: u64) {
            self.dead_letters.fetch_add(
                usize::try_from(count).unwrap_or(usize::MAX),
                Ordering::SeqCst,
            );
        }

        fn on_feed_lag(&self, entries: u64) {
            self.max_feed_lag.fetch_max(
                usize::try_from(entries).unwrap_or(usize::MAX),
                Ordering::SeqCst,
            );
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
        raw: oxkv::OxKvStore,
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

    /// Returns the `secret` schema for the read-boundary tests.
    fn secret_schema() -> SchemaDraft {
        SchemaDraft {
            id: "secret".to_string(),
            extends: Vec::new(),
            attributes: BTreeMap::from([(
                "code".to_string(),
                AttributeDef {
                    name: "code".to_string(),
                    ty: AttributeType::String,
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
        registry.publish(secret_schema()).await.unwrap();
        let raw = build_test_store(&test_prefix("rules-engine")).await;
        TestStores {
            rules: RuleStore::new(raw.clone()),
            entities: EntityStore::new(raw.clone(), registry),
            raw,
        }
    }

    /// Builds one rule store and one entity store on different raw stores.
    ///
    /// The production runtime builds the two stores this way.
    async fn separate_stores() -> (RuleStore, EntityStore, OxKvStore, OxKvStore) {
        let registry =
            SchemaRegistry::new(build_test_store(&test_prefix("rules-engine-schema")).await);
        registry.publish(schema()).await.unwrap();
        registry.publish(secret_schema()).await.unwrap();
        let rule_raw = build_test_store(&test_prefix("rules-engine-rules")).await;
        let entity_raw = build_test_store(&test_prefix("rules-engine-entities")).await;
        (
            RuleStore::new(rule_raw.clone()),
            EntityStore::new(entity_raw.clone(), registry),
            rule_raw,
            entity_raw,
        )
    }

    fn engine(stores: &TestStores, actions: Vec<Arc<dyn RuleAction>>) -> RuleEngine {
        RuleEngine::new(stores.rules.clone(), stores.entities.clone(), actions).unwrap()
    }

    async fn make_entity(entities: &EntityStore) -> Entity {
        make_invoice(entities, "e1", 10).await
    }

    async fn make_invoice(entities: &EntityStore, id: &str, total: i64) -> Entity {
        entities
            .create(
                EntityDraft {
                    id: id.to_string(),
                    schemas: vec!["invoice".to_string()],
                    attributes: BTreeMap::from([(
                        "total".to_string(),
                        AttributeValue::Integer(total),
                    )]),
                },
                &WriteContext::new("tester"),
            )
            .await
            .unwrap()
            .after
            .unwrap()
    }

    /// Creates one entity that pins the allowed `invoice` and the denied
    /// `secret` schema.
    async fn make_invoice_and_secret(entities: &EntityStore, id: &str) -> Entity {
        entities
            .create(
                EntityDraft {
                    id: id.to_string(),
                    schemas: vec!["invoice".to_string(), "secret".to_string()],
                    attributes: BTreeMap::from([
                        ("total".to_string(), AttributeValue::Integer(10)),
                        ("code".to_string(), AttributeValue::String("s1".to_string())),
                    ]),
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
            capabilities: crate::rules::rule::RuleCapabilities::default(),
        }
    }

    fn script_rule(id: &str, source: &str, read: &[&str], write: &[&str]) -> RuleDraft {
        let mut rule = draft(id, "script");
        rule.action.params = serde_json::json!({ "source": source });
        rule.capabilities.read = read.iter().map(|schema| (*schema).to_string()).collect();
        rule.capabilities.write = write.iter().map(|schema| (*schema).to_string()).collect();
        rule
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

    /// Runs the engine one time and returns its result.
    ///
    /// The call expects a failure below the attempt limit, so the run returns
    /// before the timeout.
    async fn run_once(engine: &RuleEngine, wal: &Wal) -> Result<(), RuleError> {
        tokio::time::timeout(
            Duration::from_secs(2),
            engine.run(
                wal,
                Arc::new(AtomicBool::new(false)),
                Duration::from_millis(5),
            ),
        )
        .await
        .expect("the run must return before the timeout")
    }

    /// Runs the engine until the cursor reaches `target`, then cancels it.
    async fn run_to_cursor(engine: &RuleEngine, wal: &Wal, rules: &RuleStore, target: u64) {
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            async move { engine.run(&wal, cancel, Duration::from_millis(5)).await }
        });
        wait_for_cursor(rules, target).await;
        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("the run must stop after cancellation")
            .expect("the run task must not panic")
            .expect("the run must return no error");
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

    /// The default maximum is 8, and the maximum is inclusive.
    ///
    /// The config default and the engine default must agree.
    #[tokio::test]
    async fn the_default_maximum_causation_depth_is_eight() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();

        let mut at_default = event(EntityEventKind::Created);
        at_default.causation_depth = 8;
        let executions = engine.process(&at_default).await.unwrap();
        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);

        let mut above_default = event(EntityEventKind::Created);
        above_default.event_id = "evt-2".to_string();
        above_default.causation_depth = 9;
        let executions = engine.process(&above_default).await.unwrap();
        assert_eq!(executions[0].outcome, ExecutionOutcome::CausationLimit);
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
    async fn a_poison_rule_does_not_stop_a_later_rule() {
        let stores = stores().await;
        let poison = Arc::new(RecordingAction::new("poison"));
        poison.set_failing(true);
        let good = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![poison.clone(), good.clone()]);
        make_entity(&stores.entities).await;
        let mut bad = draft("bad", "poison");
        bad.priority = 10;
        let mut later = draft("later", "record");
        later.priority = 1;
        stores.rules.upsert(bad).await.unwrap();
        stores.rules.upsert(later).await.unwrap();

        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(
            result,
            Err(RuleError::Action(kind)) if kind == "poison"
        ));
        assert_eq!(good.records().len(), 1);
        assert!(stores.rules.is_executed("later", "evt-1").await.unwrap());
        assert!(!stores.rules.is_executed("bad", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn a_poison_rule_dead_letters_and_a_later_rule_keeps_its_progress() {
        let stores = stores().await;
        let poison = Arc::new(RecordingAction::new("poison"));
        poison.set_failing(true);
        let good = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![poison.clone(), good.clone()]);
        make_entity(&stores.entities).await;
        let mut bad = draft("bad", "poison");
        bad.priority = 10;
        let mut later = draft("later", "record");
        later.priority = 1;
        stores.rules.upsert(bad).await.unwrap();
        stores.rules.upsert(later).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity { event: event_at(1) })
            .await
            .unwrap();

        for _ in 1..MAX_ENTRY_ATTEMPTS {
            assert!(run_once(&engine, &wal).await.is_err());
            assert!(stores.rules.is_executed("later", "evt-1").await.unwrap());
            assert!(stores.rules.dead_letters().await.unwrap().is_empty());
        }
        run_to_cursor(&engine, &wal, &stores.rules, 1).await;

        assert_eq!(stores.rules.cursor().await.unwrap(), 1);
        assert_eq!(stores.rules.entry_attempts(1, "evt-1").await.unwrap(), 0);
        let dead = stores.rules.dead_letters().await.unwrap();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].seq, 1);
        assert_eq!(dead[0].event_id, "evt-1");
        assert_eq!(dead[0].rule_id, "bad");
        assert_eq!(dead[0].attempts, MAX_ENTRY_ATTEMPTS);
        assert_eq!(dead[0].error, "rule action failed: poison");
        assert_eq!(good.records().len(), 1);
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
            .delete("e1", created.version, false, &WriteContext::new("tester"))
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

    /// An idle run records one health signal on each poll.
    #[tokio::test]
    async fn an_idle_run_records_a_health_signal() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new());
        let wal = test_wal().await;
        let signals = Arc::new(AtomicUsize::new(0));
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            let signals = signals.clone();
            async move {
                let record = move || {
                    signals.fetch_add(1, Ordering::SeqCst);
                };
                engine
                    .run_with_progress(&wal, cancel, Duration::from_millis(5), &record)
                    .await
            }
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            while signals.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("an idle poll must record a health signal");

        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    /// A real cursor advance records one progress signal.
    #[tokio::test]
    async fn a_cursor_advance_records_a_progress_signal() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new());
        let wal = test_wal().await;
        wal.append(WalOp::Attach {
            row_type: "invoice".to_string(),
            row_id: "1".to_string(),
            file_id: "f1".to_string(),
        })
        .await
        .unwrap();
        let signals = Arc::new(AtomicUsize::new(0));
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn({
            let engine = engine.clone();
            let wal = wal.clone();
            let cancel = cancel.clone();
            let signals = signals.clone();
            async move {
                let record = move || {
                    signals.fetch_add(1, Ordering::SeqCst);
                };
                engine
                    .run_with_progress(&wal, cancel, Duration::from_millis(5), &record)
                    .await
            }
        });

        wait_for_cursor(&stores.rules, 1).await;
        assert!(
            signals.load(Ordering::SeqCst) > 0,
            "a cursor advance must record a progress signal"
        );

        cancel.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
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

    /// A poison entry dead-letters at the limit and a later event runs.
    #[tokio::test]
    async fn a_poison_entry_dead_letters_after_the_limit_and_a_later_event_runs() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let observer = Arc::new(RecordingObserver::new());
        let engine = engine(&stores, vec![recorder.clone()]).with_observer(observer.clone());
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity { event: event_at(1) })
            .await
            .unwrap();
        recorder.set_failing(true);

        for expected in 1..MAX_ENTRY_ATTEMPTS {
            let result = run_once(&engine, &wal).await;
            assert!(matches!(result, Err(RuleError::Action(_))));
            assert_eq!(
                stores.rules.entry_attempts(1, "evt-1").await.unwrap(),
                expected
            );
            assert_eq!(stores.rules.cursor().await.unwrap(), 0);
            assert!(stores.rules.dead_letters().await.unwrap().is_empty());
        }

        run_to_cursor(&engine, &wal, &stores.rules, 1).await;

        assert_eq!(stores.rules.cursor().await.unwrap(), 1);
        assert_eq!(stores.rules.entry_attempts(1, "evt-1").await.unwrap(), 0);
        let dead = stores.rules.dead_letters().await.unwrap();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].seq, 1);
        assert_eq!(dead[0].event_id, "evt-1");
        assert_eq!(dead[0].attempts, MAX_ENTRY_ATTEMPTS);
        assert_eq!(observer.dead_letters(), 1);
        assert!(
            observer.max_feed_lag() >= 1,
            "the runner must report the head-to-cursor distance"
        );

        recorder.set_failing(false);
        wal.append(WalOp::Entity { event: event_at(2) })
            .await
            .unwrap();
        run_to_cursor(&engine, &wal, &stores.rules, 2).await;

        assert_eq!(stores.rules.cursor().await.unwrap(), 2);
        assert!(stores.rules.is_executed("alpha", "evt-2").await.unwrap());
        assert_eq!(recorder.records().last().unwrap().event.event_id, "evt-2");
    }

    /// Below the limit, the cursor stays before the failed entry.
    #[tokio::test]
    async fn a_failed_entry_below_the_limit_keeps_the_cursor_and_counts_the_attempt() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity { event: event_at(1) })
            .await
            .unwrap();
        recorder.set_failing(true);

        let result = run_once(&engine, &wal).await;

        assert!(matches!(result, Err(RuleError::Action(_))));
        assert_eq!(stores.rules.cursor().await.unwrap(), 0);
        assert_eq!(stores.rules.entry_attempts(1, "evt-1").await.unwrap(), 1);
        assert!(stores.rules.dead_letters().await.unwrap().is_empty());
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    /// A transient failure retries and reaches the head without a dead letter.
    #[tokio::test]
    async fn a_transient_failure_retries_and_reaches_the_head_without_a_dead_letter() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity { event: event_at(1) })
            .await
            .unwrap();
        recorder.fail_on_call(1);

        let first = run_once(&engine, &wal).await;

        assert!(matches!(first, Err(RuleError::Action(_))));
        assert_eq!(stores.rules.cursor().await.unwrap(), 0);
        assert_eq!(stores.rules.entry_attempts(1, "evt-1").await.unwrap(), 1);

        run_to_cursor(&engine, &wal, &stores.rules, 1).await;

        assert_eq!(stores.rules.cursor().await.unwrap(), 1);
        assert_eq!(stores.rules.entry_attempts(1, "evt-1").await.unwrap(), 0);
        assert!(stores.rules.dead_letters().await.unwrap().is_empty());
        assert!(stores.rules.is_executed("alpha", "evt-1").await.unwrap());
        assert_eq!(recorder.records().len(), 2);
    }

    /// A dead-letter row holds the sequence, event id, attempts, error, and
    /// time.
    #[tokio::test]
    async fn a_dead_letter_holds_the_sequence_event_attempts_error_and_time() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity { event: event_at(1) })
            .await
            .unwrap();
        recorder.set_failing(true);

        for _ in 1..MAX_ENTRY_ATTEMPTS {
            assert!(run_once(&engine, &wal).await.is_err());
        }
        run_to_cursor(&engine, &wal, &stores.rules, 1).await;

        let dead = stores.rules.dead_letters().await.unwrap();
        assert_eq!(dead.len(), 1);
        let entry = &dead[0];
        assert_eq!(entry.seq, 1);
        assert_eq!(entry.event_id, "evt-1");
        assert_eq!(entry.attempts, MAX_ENTRY_ATTEMPTS);
        assert_eq!(entry.error, "rule action failed: record");
        assert!(entry.at > 0);
    }

    /// A restart after a failure continues the durable attempt count.
    #[tokio::test]
    async fn a_restart_after_a_failure_continues_the_attempt_count() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let first = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        stores.rules.upsert(draft("alpha", "record")).await.unwrap();
        let wal = test_wal().await;
        wal.append(WalOp::Entity { event: event_at(1) })
            .await
            .unwrap();
        recorder.set_failing(true);

        let result = run_once(&first, &wal).await;

        assert!(matches!(result, Err(RuleError::Action(_))));
        assert_eq!(stores.rules.entry_attempts(1, "evt-1").await.unwrap(), 1);

        let restarted = engine(&stores, vec![recorder.clone()]);
        run_to_cursor(&restarted, &wal, &stores.rules, 1).await;

        assert_eq!(stores.rules.cursor().await.unwrap(), 1);
        let dead = stores.rules.dead_letters().await.unwrap();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].attempts, MAX_ENTRY_ATTEMPTS);
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
    async fn a_script_condition_runs_next_to_a_json_condition() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let subject = engine(&stores, vec![recorder.clone()]).with_script_enabled(true);
        make_entity(&stores.entities).await;

        let mut scripted = draft("scripted", "record");
        scripted.capabilities.read = vec!["invoice".to_string()];
        scripted.condition = Condition::Script {
            source: r#"event.kind == "created" && entity.attributes.total == 10"#.to_string(),
        };
        let mut json = draft("json", "record");
        json.condition = Condition::Compare {
            key: "total".to_string(),
            op: CompareOp::Eq,
            value: serde_json::json!(10),
        };
        stores.rules.upsert(json).await.unwrap();
        stores.rules.upsert(scripted).await.unwrap();

        let executions = subject
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        assert_eq!(executions.len(), 2);
        assert!(
            executions
                .iter()
                .all(|item| item.outcome == ExecutionOutcome::Executed)
        );
        assert_eq!(recorder.records().len(), 2);
    }

    #[tokio::test]
    async fn nested_scripts_are_evaluated_in_all_any_and_not() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let subject = engine(&stores, vec![recorder.clone()]).with_script_enabled(true);
        make_entity(&stores.entities).await;
        let total = Condition::Compare {
            key: "total".to_string(),
            op: CompareOp::Eq,
            value: serde_json::json!(10),
        };
        let yes = Condition::Script {
            source: "true".to_string(),
        };
        let no = Condition::Script {
            source: "false".to_string(),
        };

        let mut all = draft("all", "record");
        all.priority = 30;
        all.condition = Condition::All(vec![yes.clone(), total.clone()]);
        let mut any = draft("any", "record");
        any.priority = 20;
        any.condition = Condition::Any(vec![no.clone(), total.clone()]);
        let mut not = draft("not", "record");
        not.priority = 10;
        not.condition = Condition::Not(Box::new(no));
        stores.rules.upsert(all).await.unwrap();
        stores.rules.upsert(any).await.unwrap();
        stores.rules.upsert(not).await.unwrap();

        let executions = subject
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        assert_eq!(executions.len(), 3);
        assert!(
            executions
                .iter()
                .all(|item| item.outcome == ExecutionOutcome::Executed)
        );
        assert_eq!(recorder.records().len(), 3);
    }

    #[tokio::test]
    async fn a_nested_script_error_propagates() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let subject = engine(&stores, vec![recorder.clone()]).with_script_enabled(true);
        make_entity(&stores.entities).await;
        let mut rule = draft("alpha", "record");
        rule.condition = Condition::All(vec![Condition::Script {
            source: r#"http_get("https://example.test")"#.to_string(),
        }]);
        stores.rules.upsert(rule).await.unwrap();

        let result = subject.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(
            result,
            Err(RuleError::Script(ScriptError::Runtime))
        ));
        assert!(recorder.records().is_empty());
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn a_false_top_level_script_skips_the_action() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let subject = engine(&stores, vec![recorder.clone()]).with_script_enabled(true);
        make_entity(&stores.entities).await;
        let mut rule = draft("alpha", "record");
        rule.condition = Condition::Script {
            source: "false".to_string(),
        };
        stores.rules.upsert(rule).await.unwrap();

        let executions = subject
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        assert_eq!(executions[0].outcome, ExecutionOutcome::ConditionFalse);
        assert!(recorder.records().is_empty());
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    /// A condition script applies the read set of its rule.
    ///
    /// The entity pins the allowed `invoice` schema and the denied `secret`
    /// schema.
    /// The condition sees `total` and not `code`.
    /// It sees the `total` change and not the `code` change.
    #[tokio::test]
    async fn a_condition_script_reads_only_the_allowed_attributes_and_changes() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let subject = engine(&stores, vec![recorder.clone()]).with_script_enabled(true);
        make_invoice_and_secret(&stores.entities, "e1").await;
        let mut rule = draft("alpha", "record");
        rule.trigger.events = vec![EntityEventKind::Updated];
        rule.capabilities.read = vec!["invoice".to_string()];
        rule.condition = Condition::Script {
            source: r#"
                entity.attributes.total == 10
                    && entity.attributes.code == ()
                    && event.changed.len() == 1
                    && event.changed[0].key == "total"
            "#
            .to_string(),
        };
        stores.rules.upsert(rule).await.unwrap();
        let mut updated = event(EntityEventKind::Updated);
        updated.schemas = vec!["invoice".to_string(), "secret".to_string()];
        updated.changed = vec![
            AttributeChange {
                key: "total".to_string(),
                old: Some(serde_json::json!(5)),
                new: Some(serde_json::json!(10)),
            },
            AttributeChange {
                key: "code".to_string(),
                old: Some(serde_json::json!("s0")),
                new: Some(serde_json::json!("s1")),
            },
        ];

        let executions = subject.process(&updated).await.unwrap();

        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);
    }

    /// A condition with no read grants sees only the identity fields.
    ///
    /// The trigger entity stays visible through `id`, `version`, and
    /// `schemas`.
    /// Every attribute and every change stays hidden.
    #[tokio::test]
    async fn a_condition_script_with_no_read_grants_sees_only_identity_fields() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let subject = engine(&stores, vec![recorder.clone()]).with_script_enabled(true);
        make_invoice_and_secret(&stores.entities, "e1").await;
        let mut rule = draft("alpha", "record");
        rule.trigger.events = vec![EntityEventKind::Updated];
        rule.condition = Condition::Script {
            source: r#"
                entity.id == "e1"
                    && entity.version.to_int() == 1
                    && entity.schemas.len() == 2
                    && entity.attributes.len() == 0
                    && event.entity_id == "e1"
                    && event.kind == "updated"
                    && event.changed.len() == 0
            "#
            .to_string(),
        };
        stores.rules.upsert(rule).await.unwrap();
        let mut updated = event(EntityEventKind::Updated);
        updated.schemas = vec!["invoice".to_string(), "secret".to_string()];
        updated.changed = vec![AttributeChange {
            key: "total".to_string(),
            old: Some(serde_json::json!(5)),
            new: Some(serde_json::json!(10)),
        }];

        let executions = subject.process(&updated).await.unwrap();

        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);
    }

    /// The engine evaluates a condition script on a blocking thread.
    ///
    /// The probe records the evaluation thread.
    /// A different thread runs the script, so the script cannot block the
    /// async reactor.
    #[tokio::test]
    async fn a_condition_script_runs_on_a_blocking_thread() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let mut subject = engine(&stores, vec![recorder.clone()]).with_script_enabled(true);
        let caller = std::thread::current().id();
        let seen = Arc::new(std::sync::Mutex::new(None));
        let seen_for_probe = seen.clone();
        subject.script = subject.script.with_probe(Arc::new(move || {
            *seen_for_probe.lock().unwrap() = Some(std::thread::current().id());
        }));
        make_entity(&stores.entities).await;
        let mut rule = draft("alpha", "record");
        rule.condition = Condition::Script {
            source: "true".to_string(),
        };
        stores.rules.upsert(rule).await.unwrap();

        let executions = subject
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);
        let evaluated = *seen.lock().unwrap();
        assert!(
            evaluated.is_some(),
            "the probe must see the condition evaluation"
        );
        assert_ne!(
            evaluated,
            Some(caller),
            "the condition script must run on a blocking thread"
        );
    }

    #[tokio::test]
    async fn a_stored_script_fails_when_the_feature_is_disabled() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let subject = engine(&stores, vec![recorder.clone()]);
        make_entity(&stores.entities).await;
        let mut rule = draft("alpha", "record");
        rule.condition = Condition::Script {
            source: "true".to_string(),
        };
        stores.rules.upsert(rule).await.unwrap();

        let result = subject.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(
            result,
            Err(RuleError::Script(ScriptError::Disabled))
        ));
        assert!(recorder.records().is_empty());
    }

    #[tokio::test]
    async fn validate_condition_rejects_a_bad_script_without_the_source() {
        let stores = stores().await;
        let subject = engine(&stores, Vec::new()).with_script_enabled(true);
        let source = "let x = ;";

        let result = subject.validate_condition(&Condition::Script {
            source: source.to_string(),
        });

        match result {
            Err(RuleError::Invalid(message)) => {
                assert_eq!(message, "rule script failed to compile");
                assert!(!message.contains(source));
            }
            other => panic!("expected an invalid script error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_condition_rejects_a_script_when_disabled() {
        let stores = stores().await;
        let subject = engine(&stores, Vec::new());

        let result = subject.validate_condition(&Condition::Script {
            source: "true".to_string(),
        });

        assert!(matches!(
            result,
            Err(RuleError::Invalid(message)) if message == "rule scripts are disabled"
        ));
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

    #[tokio::test]
    async fn has_action_reports_the_script_kind() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new());

        assert!(engine.has_action("script"));
        assert!(!engine.has_action("ghost"));
    }

    #[tokio::test]
    async fn a_script_action_reads_an_allowed_entity_and_writes_the_marker() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"let t = host.get_entity("e1"); if t == () { throw "missing"; } t.attributes.total == 10"#,
                &["invoice"],
                &[],
            ))
            .await
            .unwrap();

        let executions = engine
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);
        assert!(stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn a_script_action_creates_updates_and_deletes_entities() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        make_invoice(&stores.entities, "e2", 20).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"let t = host.get_entity("e1"); host.create_entity("e3", ["invoice"], #{ total: 5 }); host.update_entity("e1", t.version, #{ total: 20 }); host.delete_entity("e2", 1);"#,
                &["invoice"],
                &["invoice"],
            ))
            .await
            .unwrap();

        let executions = engine
            .process(&event(EntityEventKind::Created))
            .await
            .unwrap();

        assert_eq!(executions[0].outcome, ExecutionOutcome::Executed);
        let e1 = stores.entities.get("e1").await.unwrap().unwrap();
        assert_eq!(e1.version, 2);
        assert_eq!(
            e1.attributes.get("total"),
            Some(&AttributeValue::Integer(20))
        );
        assert!(stores.entities.get("e2").await.unwrap().is_none());
        let e3 = stores.entities.get("e3").await.unwrap().unwrap();
        assert_eq!(e3.version, 1);
        assert_eq!(
            e3.attributes.get("total"),
            Some(&AttributeValue::Integer(5))
        );
        assert!(stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn a_create_outside_the_write_set_writes_no_effect_and_no_marker() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"host.create_entity("e3", ["invoice"], #{ total: 5 });"#,
                &["invoice"],
                &["other"],
            ))
            .await
            .unwrap();

        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(
            result,
            Err(RuleError::Script(ScriptError::WriteDenied))
        ));
        assert!(stores.entities.get("e3").await.unwrap().is_none());
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn an_update_outside_the_write_set_writes_no_effect_and_no_marker() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"host.update_entity("e1", 1, #{ total: 99 });"#,
                &["invoice"],
                &["other"],
            ))
            .await
            .unwrap();

        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(
            result,
            Err(RuleError::Script(ScriptError::WriteDenied))
        ));
        let e1 = stores.entities.get("e1").await.unwrap().unwrap();
        assert_eq!(
            e1.attributes.get("total"),
            Some(&AttributeValue::Integer(10))
        );
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn a_marker_write_failure_rolls_back_every_effect() {
        struct RejectMarkerKey(String);

        #[async_trait::async_trait]
        impl oxkv::Validator for RejectMarkerKey {
            async fn validate(
                &self,
                _ctx: &dyn oxkv::StoreView,
                key: &str,
                _value: &[u8],
            ) -> Result<(), oxkv::StoreError> {
                if key == self.0 {
                    return Err(oxkv::StoreError::Other("write rejected".to_string()));
                }
                Ok(())
            }
        }

        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"host.create_entity("e3", ["invoice"], #{ total: 5 }); host.update_entity("e1", 1, #{ total: 99 });"#,
                &["invoice"],
                &["invoice"],
            ))
            .await
            .unwrap();
        stores
            .raw
            .add_validator(RejectMarkerKey("rule:exec:alpha:evt-1".to_string()));

        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(result, Err(RuleError::Store(_))));
        let e1 = stores.entities.get("e1").await.unwrap().unwrap();
        assert_eq!(e1.version, 1);
        assert_eq!(
            e1.attributes.get("total"),
            Some(&AttributeValue::Integer(10))
        );
        assert!(stores.entities.get("e3").await.unwrap().is_none());
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn an_effect_error_writes_no_effect_and_no_marker() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"host.create_entity("e1", ["invoice"], #{ total: 5 });"#,
                &["invoice"],
                &["invoice"],
            ))
            .await
            .unwrap();

        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(result, Err(RuleError::Invalid(_))));
        let e1 = stores.entities.get("e1").await.unwrap().unwrap();
        assert_eq!(e1.version, 1);
        assert_eq!(
            e1.attributes.get("total"),
            Some(&AttributeValue::Integer(10))
        );
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn a_script_error_discards_every_staged_effect() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"host.create_entity("e3", ["invoice"], #{ total: 5 }); host.create_entity("e4", ["secret"], #{ total: 6 });"#,
                &["invoice"],
                &["invoice"],
            ))
            .await
            .unwrap();

        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(
            result,
            Err(RuleError::Script(ScriptError::WriteDenied))
        ));
        assert!(stores.entities.get("e3").await.unwrap().is_none());
        assert!(stores.entities.get("e4").await.unwrap().is_none());
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn a_script_action_with_no_effects_writes_the_marker_and_does_not_rerun() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"let t = host.get_entity("e1");"#,
                &["invoice"],
                &[],
            ))
            .await
            .unwrap();
        let subject = event(EntityEventKind::Created);

        let first = engine.process(&subject).await.unwrap();
        let second = engine.process(&subject).await.unwrap();

        assert_eq!(first[0].outcome, ExecutionOutcome::Executed);
        assert_eq!(second[0].outcome, ExecutionOutcome::AlreadyExecuted);
        assert!(stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn a_script_marker_lives_in_the_entity_store_and_stops_a_replay() {
        let (rules, entities, rule_raw, entity_raw) = separate_stores().await;
        let engine = RuleEngine::new(rules.clone(), entities.clone(), Vec::new())
            .unwrap()
            .with_script_enabled(true);
        make_entity(&entities).await;
        rules
            .upsert(script_rule(
                "alpha",
                r#"host.create_entity("e3", ["invoice"], #{ total: 5 });"#,
                &["invoice"],
                &["invoice"],
            ))
            .await
            .unwrap();
        let subject = event(EntityEventKind::Created);

        let first = engine.process(&subject).await.unwrap();
        let second = engine.process(&subject).await.unwrap();

        assert_eq!(first[0].outcome, ExecutionOutcome::Executed);
        assert_eq!(second[0].outcome, ExecutionOutcome::AlreadyExecuted);
        let e3 = entities.get("e3").await.unwrap().unwrap();
        assert_eq!(e3.version, 1);
        assert_eq!(
            e3.attributes.get("total"),
            Some(&AttributeValue::Integer(5))
        );
        let key = RuleStore::execution_key("alpha", "evt-1");
        assert!(entities.has_execution_marker(&key).await.unwrap());
        assert_eq!(
            entity_raw
                .count_prefix(KeyPrefix::new("rule:exec:"), usize::MAX)
                .await
                .unwrap(),
            1
        );
        assert!(!rules.is_executed("alpha", "evt-1").await.unwrap());
        assert_eq!(
            rule_raw
                .count_prefix(KeyPrefix::new("rule:exec:"), usize::MAX)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn gc_execution_markers_deletes_an_old_script_marker() {
        let (_rules, entities, _rule_raw, entity_raw) = separate_stores().await;
        let key = RuleStore::execution_key("alpha", "evt-old");
        let bytes = RuleStore::execution_marker_value(100).unwrap();
        entity_raw.set_bytes(&key, &bytes).await.unwrap();

        let deleted = entities.gc_execution_markers(200).await.unwrap();

        assert_eq!(deleted, 1);
        assert!(!entities.has_execution_marker(&key).await.unwrap());
    }

    #[tokio::test]
    async fn a_replay_returns_already_executed_and_does_not_run_the_script() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"host.create_entity("e3", ["invoice"], #{ total: 5 });"#,
                &["invoice"],
                &["invoice"],
            ))
            .await
            .unwrap();
        let subject = event(EntityEventKind::Created);

        engine.process(&subject).await.unwrap();
        let second = engine.process(&subject).await.unwrap();

        assert_eq!(second[0].outcome, ExecutionOutcome::AlreadyExecuted);
        let e3 = stores.entities.get("e3").await.unwrap().unwrap();
        assert_eq!(e3.version, 1);
    }

    #[tokio::test]
    async fn a_condition_script_cannot_reach_the_host() {
        let stores = stores().await;
        let recorder = Arc::new(RecordingAction::new("record"));
        let engine = engine(&stores, vec![recorder.clone()]).with_script_enabled(true);
        make_entity(&stores.entities).await;
        let mut rule = draft("alpha", "record");
        rule.condition = Condition::Script {
            source: r#"host.get_entity("e1") == ()"#.to_string(),
        };
        stores.rules.upsert(rule).await.unwrap();

        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(result, Err(RuleError::Script(_))));
        assert!(recorder.records().is_empty());
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn an_http_function_name_fails_evaluation() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"http_get("https://example.test")"#,
                &[],
                &[],
            ))
            .await
            .unwrap();

        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(
            result,
            Err(RuleError::Script(ScriptError::Runtime))
        ));
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn a_script_action_is_rejected_at_save_and_fails_at_run_when_disabled() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new());
        let params = serde_json::json!({ "source": "let value = 1;" });

        let validation = engine.validate_action("script", &params);

        assert!(matches!(
            validation,
            Err(RuleError::Invalid(message)) if message == "rule scripts are disabled"
        ));

        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule("alpha", "let value = 1;", &[], &[]))
            .await
            .unwrap();
        let result = engine.process(&event(EntityEventKind::Created)).await;

        assert!(matches!(
            result,
            Err(RuleError::Script(ScriptError::Disabled))
        ));
        assert!(!stores.rules.is_executed("alpha", "evt-1").await.unwrap());
    }

    #[tokio::test]
    async fn validate_action_rejects_bad_script_parameters() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        let oversized = " ".repeat(MAX_SOURCE_BYTES + 1);
        let cases = [
            serde_json::json!({}),
            serde_json::json!({ "source": 5 }),
            serde_json::json!({ "source": "" }),
            serde_json::json!({ "source": "let value = ;" }),
            serde_json::json!({ "source": "let value = 1;", "extra": true }),
            serde_json::json!({ "source": oversized }),
        ];

        for params in cases {
            let result = engine.validate_action("script", &params);
            assert!(
                matches!(result, Err(RuleError::Invalid(_))),
                "parameters must fail validation: {params}"
            );
        }
    }

    /// The blocking bridge reads and writes on a multi-thread runtime.
    ///
    /// A host method calls `block_on` on the captured handle.
    /// The test fails on a deadlock with the timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_blocking_bridge_reads_and_writes_without_deadlock() {
        let stores = stores().await;
        let engine = engine(&stores, Vec::new()).with_script_enabled(true);
        make_entity(&stores.entities).await;
        stores
            .rules
            .upsert(script_rule(
                "alpha",
                r#"let t = host.get_entity("e1"); host.update_entity("e1", t.version, #{ total: 11 });"#,
                &["invoice"],
                &["invoice"],
            ))
            .await
            .unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            engine.process(&event(EntityEventKind::Created)),
        )
        .await
        .expect("the blocking bridge must not deadlock");

        assert_eq!(result.unwrap()[0].outcome, ExecutionOutcome::Executed);
        let e1 = stores.entities.get("e1").await.unwrap().unwrap();
        assert_eq!(
            e1.attributes.get("total"),
            Some(&AttributeValue::Integer(11))
        );
    }
}
