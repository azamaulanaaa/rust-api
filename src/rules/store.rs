//! Durable storage and index lookup for rules.
//!
//! # Key layout
//!
//! All keys live in one bounded key family:
//!
//! - `rule:meta:{id}` holds one [`Rule`] as JSON.
//! - `rule:idx:{event_kind}:{schema_id}:{rule_id}` is an empty marker.
//!
//! The event kind key is stable and lowercase.
//! The keys are `created`, `updated`, `deleted`, `schema_applied`, and
//! `schema_removed`.
//! All scans stop at the `prefix:` to `prefix;` bound.
//!
//! # Writes
//!
//! One publish mutex serializes writes.
//! An upsert writes the rule row and its index markers in one transaction.
//! The same transaction removes stale markers from an earlier trigger.
//! A delete removes the rule row and its index markers in one transaction.
//!
//! # Cursor and execution markers
//!
//! `rule:cursor` holds the last change-feed sequence that the engine
//! processed.
//! `rule:exec:{rule_id}:{event_id}` is one execution marker.
//! A marker stops a second run of one rule and one event.
//! Execution markers grow without bound.
//! A later cleanup job must remove old markers.

use std::collections::BTreeSet;
use std::sync::Arc;

use oxkv::{Direction, GetSet, KeyValue, OxKvStore, Store as _, Transaction as _};
use tokio::sync::{Mutex, RwLock};

use crate::records::{EntityEvent, EntityEventKind};
use crate::rules::error::RuleError;
use crate::rules::rule::{Rule, RuleDraft, RuleTrigger, validate_identifier};

/// Key prefix for the whole rule family.
const RULE_PREFIX: &str = "rule:";

/// Key prefix for rule rows.
const META_PREFIX: &str = "rule:meta:";

/// Key prefix for rule index markers.
const INDEX_PREFIX: &str = "rule:idx:";

/// Key that holds the durable change-feed cursor.
const CURSOR_KEY: &str = "rule:cursor";

/// Key prefix for execution markers.
const EXEC_PREFIX: &str = "rule:exec:";

/// A store of rules on one OxKV store.
///
/// The store keeps one shared handle.
/// One publish mutex serializes writes.
#[derive(Clone)]
pub struct RuleStore {
    /// Shared store handle.
    store: Arc<RwLock<OxKvStore>>,
    /// Serializes writes, so two callers cannot claim one version.
    publish_lock: Arc<Mutex<()>>,
}

impl RuleStore {
    /// Creates a rule store over `store`.
    pub fn new(store: OxKvStore) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
            publish_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Adds one rule or replaces the rule with the same id.
    ///
    /// The call validates the draft before it writes.
    /// It assigns the next monotonic version.
    /// The first version is 1.
    /// The rule row, the new index markers, and the removal of stale markers
    /// commit in one transaction.
    pub async fn upsert(&self, draft: RuleDraft) -> Result<Rule, RuleError> {
        draft.validate()?;

        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(RuleError::Store)?;
        let previous = load_rule(&tx, &draft.id).await?;
        let now = chrono::Utc::now().timestamp();
        let version = match &previous {
            Some(rule) => rule
                .version
                .checked_add(1)
                .ok_or_else(|| RuleError::Invalid("rule version overflow".to_string()))?,
            None => 1,
        };
        let rule = Rule {
            id: draft.id,
            version,
            name: draft.name,
            enabled: draft.enabled,
            priority: draft.priority,
            trigger: draft.trigger,
            condition: draft.condition,
            action: draft.action,
            created_at: previous.as_ref().map_or(now, |rule| rule.created_at),
            updated_at: now,
        };

        put_rule(&tx, &rule).await?;
        let new_markers: BTreeSet<String> =
            index_keys(&rule.trigger, &rule.id).into_iter().collect();
        for key in &new_markers {
            tx.set_bytes(key, b"").await.map_err(RuleError::Store)?;
        }
        if let Some(previous) = &previous {
            for key in index_keys(&previous.trigger, &previous.id) {
                if !new_markers.contains(&key) {
                    tx.delete(&key).await.map_err(RuleError::Store)?;
                }
            }
        }
        tx.commit().await.map_err(RuleError::Store)?;
        Ok(rule)
    }

    /// Reads one rule.
    ///
    /// The call returns `None` when the rule does not exist.
    pub async fn get(&self, id: &str) -> Result<Option<Rule>, RuleError> {
        validate_identifier("rule id", id)?;
        let g = self.store.read().await;
        load_rule(&*g, id).await
    }

    /// Lists every rule.
    ///
    /// The result is sorted by priority in descending order.
    /// Two rules with the same priority are sorted by id.
    pub async fn list(&self) -> Result<Vec<Rule>, RuleError> {
        let g = self.store.read().await;
        let rows = scan_prefix(&*g, META_PREFIX).await?;
        let mut rules = Vec::with_capacity(rows.len());
        for row in rows {
            let rule: Rule = serde_json::from_slice(&row.value)
                .map_err(|error| RuleError::Serialization(error.to_string()))?;
            rules.push(rule);
        }
        sort_rules(&mut rules);
        Ok(rules)
    }

    /// Deletes one rule.
    ///
    /// The call removes the rule row and its index markers in one
    /// transaction.
    /// It returns false when the rule does not exist.
    pub async fn delete(&self, id: &str) -> Result<bool, RuleError> {
        validate_identifier("rule id", id)?;

        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(RuleError::Store)?;
        let Some(rule) = load_rule(&tx, id).await? else {
            return Ok(false);
        };
        for key in index_keys(&rule.trigger, &rule.id) {
            tx.delete(&key).await.map_err(RuleError::Store)?;
        }
        tx.delete(&meta_key(id)).await.map_err(RuleError::Store)?;
        tx.commit().await.map_err(RuleError::Store)?;
        Ok(true)
    }

    /// Sets the enabled flag of one rule.
    ///
    /// The call changes the stored rule only.
    /// It does not change the index.
    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<Rule, RuleError> {
        validate_identifier("rule id", id)?;

        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(RuleError::Store)?;
        let Some(mut rule) = load_rule(&tx, id).await? else {
            return Err(RuleError::NotFound(id.to_string()));
        };
        rule.enabled = enabled;
        rule.version = rule
            .version
            .checked_add(1)
            .ok_or_else(|| RuleError::Invalid("rule version overflow".to_string()))?;
        rule.updated_at = chrono::Utc::now().timestamp();
        put_rule(&tx, &rule).await?;
        tx.commit().await.map_err(RuleError::Store)?;
        Ok(rule)
    }

    /// Lists the enabled rules that match `event`.
    ///
    /// A rule matches when its trigger lists the event kind and one event
    /// schema.
    /// The result is sorted by priority in descending order.
    /// Two rules with the same priority are sorted by id.
    pub async fn matching(&self, event: &EntityEvent) -> Result<Vec<Rule>, RuleError> {
        let kind = event_kind_key(event.kind);
        let mut ids = BTreeSet::new();
        {
            let g = self.store.read().await;
            for schema in &event.schemas {
                let prefix = format!("{INDEX_PREFIX}{kind}:{schema}:");
                for marker in scan_prefix(&*g, &prefix).await? {
                    let Some(id) = marker.key.strip_prefix(&prefix) else {
                        continue;
                    };
                    if !id.is_empty() && !id.contains(':') {
                        ids.insert(id.to_string());
                    }
                }
            }
        }

        let g = self.store.read().await;
        let mut rules = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(rule) = load_rule(&*g, &id).await?
                && rule.enabled
                && rule.trigger.matches(event)
            {
                rules.push(rule);
            }
        }
        sort_rules(&mut rules);
        Ok(rules)
    }

    /// Reads the durable change-feed cursor.
    ///
    /// A missing cursor is 0.
    pub(crate) async fn cursor(&self) -> Result<u64, RuleError> {
        let g = self.store.read().await;
        let Some(bytes) = g.get_bytes(CURSOR_KEY).await.map_err(RuleError::Store)? else {
            return Ok(0);
        };
        serde_json::from_slice(&bytes).map_err(|error| RuleError::Serialization(error.to_string()))
    }

    /// Writes the durable change-feed cursor.
    pub(crate) async fn set_cursor(&self, seq: u64) -> Result<(), RuleError> {
        let bytes = serde_json::to_vec(&seq)
            .map_err(|error| RuleError::Serialization(error.to_string()))?;
        let g = self.store.write().await;
        g.set_bytes(CURSOR_KEY, &bytes)
            .await
            .map(|_| ())
            .map_err(RuleError::Store)
    }

    /// True when an execution marker exists for one rule and one event.
    pub(crate) async fn is_executed(
        &self,
        rule_id: &str,
        event_id: &str,
    ) -> Result<bool, RuleError> {
        validate_identifier("rule id", rule_id)?;
        let g = self.store.read().await;
        Ok(g.get_bytes(&exec_key(rule_id, event_id))
            .await
            .map_err(RuleError::Store)?
            .is_some())
    }

    /// Writes one execution marker with the current Unix time.
    pub(crate) async fn mark_executed(
        &self,
        rule_id: &str,
        event_id: &str,
    ) -> Result<(), RuleError> {
        validate_identifier("rule id", rule_id)?;
        let now = chrono::Utc::now().timestamp();
        let bytes = serde_json::to_vec(&now)
            .map_err(|error| RuleError::Serialization(error.to_string()))?;
        let g = self.store.write().await;
        g.set_bytes(&exec_key(rule_id, event_id), &bytes)
            .await
            .map(|_| ())
            .map_err(RuleError::Store)
    }
}

/// Returns the stable lowercase key of one event kind.
fn event_kind_key(kind: EntityEventKind) -> &'static str {
    match kind {
        EntityEventKind::Created => "created",
        EntityEventKind::Updated => "updated",
        EntityEventKind::Deleted => "deleted",
        EntityEventKind::SchemaApplied => "schema_applied",
        EntityEventKind::SchemaRemoved => "schema_removed",
    }
}

/// Returns every index key for one trigger and rule id.
fn index_keys(trigger: &RuleTrigger, rule_id: &str) -> Vec<String> {
    let mut keys = Vec::with_capacity(trigger.events.len() * trigger.schemas.len());
    for event in &trigger.events {
        let kind = event_kind_key(*event);
        for schema in &trigger.schemas {
            keys.push(format!("{INDEX_PREFIX}{kind}:{schema}:{rule_id}"));
        }
    }
    keys
}

/// Writes one rule row.
async fn put_rule<S>(store: &S, rule: &Rule) -> Result<(), RuleError>
where
    S: GetSet + ?Sized,
{
    let bytes =
        serde_json::to_vec(rule).map_err(|error| RuleError::Serialization(error.to_string()))?;
    store
        .set_bytes(&meta_key(&rule.id), &bytes)
        .await
        .map(|_| ())
        .map_err(RuleError::Store)
}

/// Reads one rule row.
async fn load_rule<S>(store: &S, id: &str) -> Result<Option<Rule>, RuleError>
where
    S: GetSet + ?Sized,
{
    let Some(bytes) = store
        .get_bytes(&meta_key(id))
        .await
        .map_err(RuleError::Store)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| RuleError::Serialization(error.to_string()))
}

/// Scans a key range that ends at the `prefix:` family bound.
async fn scan_prefix<S>(store: &S, prefix: &str) -> Result<Vec<KeyValue>, RuleError>
where
    S: GetSet + ?Sized,
{
    debug_assert!(prefix.starts_with(RULE_PREFIX));
    debug_assert!(prefix.ends_with(':'));
    let cursor = (Some(prefix.to_string()), Some(prefix_scan_end(prefix)));
    store
        .gets_bytes(None, Direction::Next, cursor)
        .await
        .map_err(RuleError::Store)
}

/// The exclusive upper bound for a `prefix:` range scan (`:` to `;`).
fn prefix_scan_end(prefix: &str) -> String {
    debug_assert!(prefix.ends_with(':'));
    let mut end = prefix.to_string();
    end.pop();
    end.push(';');
    end
}

/// The key that holds one rule.
fn meta_key(id: &str) -> String {
    format!("{META_PREFIX}{id}")
}

/// The key that holds one execution marker.
fn exec_key(rule_id: &str, event_id: &str) -> String {
    format!("{EXEC_PREFIX}{rule_id}:{event_id}")
}

/// Sorts rules by priority in descending order and then by id.
fn sort_rules(rules: &mut [Rule]) {
    rules.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.id.cmp(&right.id))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::{AttributeValue, Entity};
    use crate::eav::schema::SchemaRef;
    use crate::records::AttributeChange;
    use crate::rules::rule::{ActionRef, CompareOp, Condition};
    use std::collections::BTreeMap;

    async fn new_store() -> RuleStore {
        RuleStore::new(build_test_store(&test_prefix("rules-store")).await)
    }

    async fn store_with_raw() -> (RuleStore, OxKvStore) {
        let raw = build_test_store(&test_prefix("rules-store")).await;
        (RuleStore::new(raw.clone()), raw)
    }

    fn draft(id: &str) -> RuleDraft {
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
                kind: "log".to_string(),
                params: serde_json::json!({}),
            },
        }
    }

    fn event(kind: EntityEventKind, schemas: &[&str], changed: &[&str]) -> EntityEvent {
        EntityEvent {
            event_id: "evt-1".to_string(),
            entity_id: "e1".to_string(),
            entity_version: 2,
            kind,
            schemas: schemas.iter().map(|id| (*id).to_string()).collect(),
            changed: changed
                .iter()
                .map(|key| AttributeChange {
                    key: (*key).to_string(),
                    old: None,
                    new: Some(serde_json::json!(1)),
                })
                .collect(),
            actor: "alice".to_string(),
            causation_id: None,
            causation_depth: 0,
            correlation_id: "req-1".to_string(),
            snapshot: None,
            occurred_at: 2,
        }
    }

    async fn all_keys(store: &OxKvStore) -> Vec<String> {
        store
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.key)
            .collect()
    }

    #[tokio::test]
    async fn upsert_get_list_and_delete_round_trip() {
        let store = new_store().await;
        let saved = store.upsert(draft("alpha")).await.unwrap();

        assert_eq!(saved.version, 1);
        assert_eq!(store.get("alpha").await.unwrap(), Some(saved.clone()));
        assert_eq!(store.list().await.unwrap(), vec![saved.clone()]);
        assert!(store.delete("alpha").await.unwrap());
        assert_eq!(store.get("alpha").await.unwrap(), None);
        assert!(store.list().await.unwrap().is_empty());
        assert!(!store.delete("alpha").await.unwrap());
    }

    #[tokio::test]
    async fn version_numbers_increase() {
        let store = new_store().await;
        let first = store.upsert(draft("alpha")).await.unwrap();
        let second = store.upsert(draft("alpha")).await.unwrap();

        assert_eq!(first.version, 1);
        assert_eq!(second.version, 2);
        assert_eq!(store.get("alpha").await.unwrap(), Some(second));
    }

    #[tokio::test]
    async fn list_sorts_by_priority_then_id() {
        let store = new_store().await;
        for (id, priority) in [("b", 5), ("a", 5), ("c", 9)] {
            let mut rule = draft(id);
            rule.priority = priority;
            store.upsert(rule).await.unwrap();
        }

        let ids: Vec<String> = store
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|rule| rule.id)
            .collect();

        assert_eq!(ids, vec!["c", "a", "b"]);
    }

    #[tokio::test]
    async fn a_rule_matches_an_event_by_kind_and_schema() {
        let store = new_store().await;
        store.upsert(draft("alpha")).await.unwrap();

        assert_eq!(
            store
                .matching(&event(EntityEventKind::Created, &["invoice"], &[]))
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .matching(&event(EntityEventKind::Updated, &["invoice"], &[]))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .matching(&event(EntityEventKind::Created, &["contact"], &[]))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_parent_schema_rule_matches_an_event_with_the_parent_id() {
        let store = new_store().await;
        let mut rule = draft("alpha");
        rule.trigger.schemas = vec!["parent".to_string()];
        store.upsert(rule).await.unwrap();

        let matches = store
            .matching(&event(EntityEventKind::Created, &["parent", "child"], &[]))
            .await
            .unwrap();

        assert_eq!(matches.len(), 1);
    }

    #[tokio::test]
    async fn a_rule_with_two_schemas_is_returned_once() {
        let store = new_store().await;
        let mut rule = draft("alpha");
        rule.trigger.schemas = vec!["alpha".to_string(), "beta".to_string()];
        store.upsert(rule).await.unwrap();

        let matches = store
            .matching(&event(EntityEventKind::Created, &["alpha", "beta"], &[]))
            .await
            .unwrap();

        assert_eq!(matches.len(), 1);
    }

    #[tokio::test]
    async fn a_disabled_rule_is_not_returned_by_matching() {
        let store = new_store().await;
        let mut rule = draft("alpha");
        rule.enabled = false;
        store.upsert(rule).await.unwrap();

        assert!(
            store
                .matching(&event(EntityEventKind::Created, &["invoice"], &[]))
                .await
                .unwrap()
                .is_empty()
        );

        let enabled = store.set_enabled("alpha", true).await.unwrap();
        assert!(enabled.enabled);
        assert_eq!(
            store
                .matching(&event(EntityEventKind::Created, &["invoice"], &[]))
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            store.set_enabled("ghost", true).await,
            Err(RuleError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn an_update_that_changes_the_trigger_removes_the_old_marker() {
        let (store, raw) = store_with_raw().await;
        let mut rule = draft("alpha");
        store.upsert(rule.clone()).await.unwrap();

        rule.trigger = RuleTrigger {
            events: vec![EntityEventKind::Updated],
            schemas: vec!["contact".to_string()],
        };
        store.upsert(rule).await.unwrap();

        assert!(
            store
                .matching(&event(EntityEventKind::Created, &["invoice"], &[]))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .matching(&event(EntityEventKind::Updated, &["contact"], &[]))
                .await
                .unwrap()
                .len(),
            1
        );

        let keys = all_keys(&raw).await;
        assert!(
            !keys
                .iter()
                .any(|key| key == "rule:idx:created:invoice:alpha")
        );
        assert!(
            keys.iter()
                .any(|key| key == "rule:idx:updated:contact:alpha")
        );
    }

    #[tokio::test]
    async fn delete_removes_the_rule_and_its_markers() {
        let (store, raw) = store_with_raw().await;
        store.upsert(draft("alpha")).await.unwrap();

        assert!(store.delete("alpha").await.unwrap());

        let keys = all_keys(&raw).await;
        assert!(
            keys.iter().all(|key| !key.starts_with(RULE_PREFIX)),
            "a delete left a rule key behind"
        );
    }

    #[tokio::test]
    async fn invalid_rule_ids_fail() {
        let store = new_store().await;
        let mut ids = vec![
            "".to_string(),
            "Upper".to_string(),
            "a:b".to_string(),
            "a/b".to_string(),
            "a b".to_string(),
        ];
        ids.push("a".repeat(129));

        for id in ids {
            let result = store.upsert(draft(&id)).await;
            assert!(
                matches!(result, Err(RuleError::Invalid(_))),
                "rule id {id:?} must fail"
            );
        }
    }

    #[tokio::test]
    async fn invalid_schema_ids_and_action_kinds_fail() {
        let store = new_store().await;

        let mut rule = draft("alpha");
        rule.trigger.schemas = vec!["a:b".to_string()];
        assert!(matches!(
            store.upsert(rule).await,
            Err(RuleError::Invalid(_))
        ));

        let mut rule = draft("alpha");
        rule.action.kind = "Bad Kind".to_string();
        assert!(matches!(
            store.upsert(rule).await,
            Err(RuleError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn empty_triggers_fail() {
        let store = new_store().await;

        let mut rule = draft("alpha");
        rule.trigger.events.clear();
        assert!(matches!(
            store.upsert(rule).await,
            Err(RuleError::Invalid(_))
        ));

        let mut rule = draft("alpha");
        rule.trigger.schemas.clear();
        assert!(matches!(
            store.upsert(rule).await,
            Err(RuleError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn duplicate_trigger_entries_fail() {
        let store = new_store().await;

        let mut rule = draft("alpha");
        rule.trigger.events = vec![EntityEventKind::Created, EntityEventKind::Created];
        assert!(matches!(
            store.upsert(rule).await,
            Err(RuleError::Invalid(_))
        ));

        let mut rule = draft("alpha");
        rule.trigger.schemas = vec!["invoice".to_string(), "invoice".to_string()];
        assert!(matches!(
            store.upsert(rule).await,
            Err(RuleError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn an_over_deep_condition_fails() {
        let store = new_store().await;
        let mut condition = Condition::Always;
        for _ in 0..16 {
            condition = Condition::Not(Box::new(condition));
        }
        let mut rule = draft("alpha");
        rule.condition = condition;

        assert!(matches!(
            store.upsert(rule).await,
            Err(RuleError::ConditionDepth)
        ));
    }

    #[tokio::test]
    async fn a_condition_at_depth_16_is_accepted() {
        let store = new_store().await;
        let mut condition = Condition::Always;
        for _ in 0..15 {
            condition = Condition::Not(Box::new(condition));
        }
        let mut rule = draft("alpha");
        rule.condition = condition;

        assert!(store.upsert(rule).await.is_ok());
    }

    #[tokio::test]
    async fn a_condition_can_compare_a_stored_attribute() {
        let store = new_store().await;
        let mut rule = draft("alpha");
        rule.condition = Condition::Compare {
            key: "total".to_string(),
            op: CompareOp::Gt,
            value: serde_json::json!(9),
        };
        store.upsert(rule).await.unwrap();

        let entity = Entity {
            id: "e1".to_string(),
            version: 1,
            schemas: vec![SchemaRef {
                id: "invoice".to_string(),
                version: 1,
            }],
            attributes: BTreeMap::from([("total".to_string(), AttributeValue::Integer(10))]),
            created_at: 1,
            updated_at: 1,
        };

        assert!(store.get("alpha").await.unwrap().unwrap().condition.eval(
            Some(&entity),
            &event(EntityEventKind::Created, &["invoice"], &[])
        ));
    }
}
