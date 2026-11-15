//! Durable storage and index lookup for rules.
//!
//! # Key layout
//!
//! Rule rows and markers live in one bounded key family:
//!
//! - `rule:meta:{id}` holds one [`Rule`] as JSON.
//! - `rule:idx:{event_kind}:{schema_id}:{rule_id}` is an empty marker.
//!
//! The event kind key is stable and lowercase.
//! The keys are `created`, `updated`, `deleted`, `schema_applied`,
//! `schema_removed`, and `timer`.
//! All scans stop at the `prefix:` to `prefix;` bound.
//!
//! The engine keeps two more key families:
//!
//! - `rule-attempt:{seq}:{event_id}` holds a JSON `u32` attempt count.
//! - `rule-dead:{seq}:{event_id}:{rule_id}` holds one [`RuleDeadLetter`]
//!   as JSON.
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
//! [`RuleStore::gc_executions`] deletes old markers.
//!
//! # Attempt and dead-letter rows
//!
//! The engine increments the attempt row when `process` fails for one entry.
//! The row is durable, so a runtime restart continues the count.
//! The engine deletes the attempt row after a success.
//! At the attempt limit, the engine writes one dead-letter row and deletes
//! the attempt row.
//! [`RuleStore::dead_letters`] lists the dead-letter rows, newest first.
//!
//! # Execution marker cleanup
//!
//! [`RuleStore::gc_executions`] walks the `rule:exec:` key family in pages.
//! One page holds at most `GC_BATCH` rows.
//! The batch size is 200 in a normal build and 2 in a test build.
//! The call reads one page, deletes the expired markers of that page, and
//! reads again.
//! The scan moves its cursor forward only when a page holds no expired
//! marker.
//! Therefore a delete cannot skip a live marker.
//! Memory use is proportional to `GC_BATCH` and not to the marker count.
//! [`RuleStore::execution_count`] walks the family in the same pages.
//! The marker of a deleted rule waits for the retention window.
//!
//! The same pass deletes the `rule-dead:` rows older than
//! `DEAD_LETTER_RETENTION_SECS`.
//! That retention is 7 days.
//! The pass does not touch the cursor.
//!
//! # Cleanup safety
//!
//! A delete of a marker can permit a duplicate action.
//! The duplicate happens when a replay of an old WAL event arrives after
//! the cursor is reset.
//! The retention window must be longer than any replay window.

use std::collections::BTreeSet;
use std::sync::Arc;

use oxkv::{
    Direction, GetSet, KeyPrefix, KeyValue, OxKvStore, ScanExt as _, Store as _, StoreError,
    Transaction as _, TxCas,
};
use tokio::sync::{Mutex, RwLock};

use crate::eav::MAX_PAGE_OFFSET;
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

/// Key prefix for failed-attempt rows.
const ATTEMPT_PREFIX: &str = "rule-attempt:";

/// Key prefix for dead-letter rows.
const DEAD_PREFIX: &str = "rule-dead:";

/// The number of seconds that a dead-letter row stays before cleanup.
///
/// The existing execution-marker cleanup pass deletes a dead letter when its
/// `at` time is older than this value.
/// The value is 7 days.
const DEAD_LETTER_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;

/// Maximum number of execution markers that one cleanup page reads.
///
/// The cleanup walks the `rule:exec:` family in pages of this size.
/// Test builds use a small page, so that a test can cross a page boundary
/// with a small marker set.
#[cfg(not(test))]
const GC_BATCH: usize = 200;

/// Maximum number of execution markers that one cleanup page reads.
///
/// Test builds use a small page, so that a test can cross a page boundary
/// with a small marker set.
#[cfg(test)]
const GC_BATCH: usize = 2;

/// One entry that the engine failed by policy.
///
/// The engine writes this row after `MAX_ENTRY_ATTEMPTS` failed attempts.
/// The row holds the feed sequence, the event id, the attempt count, the
/// sanitized error text, and the Unix time of the write.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleDeadLetter {
    /// The feed sequence of the failed entry.
    pub seq: u64,
    /// The id of the failed event.
    pub event_id: String,
    /// The id of the failed rule.
    ///
    /// An old row has no rule id and decodes as an empty string.
    #[serde(default)]
    pub rule_id: String,
    /// The number of failed attempts.
    pub attempts: u32,
    /// The sanitized error text.
    pub error: String,
    /// The Unix time of the dead-letter write, in seconds.
    pub at: i64,
}

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
    /// Largest execution-marker page that a cleanup read.
    ///
    /// The field exists only in a test build.
    #[cfg(test)]
    gc_page_high_water: Arc<std::sync::atomic::AtomicUsize>,
}

impl RuleStore {
    /// Creates a rule store over `store`.
    pub fn new(store: OxKvStore) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
            publish_lock: Arc::new(Mutex::new(())),
            #[cfg(test)]
            gc_page_high_water: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Adds one rule or replaces the rule with the same id.
    ///
    /// The call validates the draft before it writes.
    /// It assigns the next monotonic version.
    /// The first version is 1.
    /// The rule row, the new index markers, and the removal of stale markers
    /// commit in one transaction.
    /// The rule row uses a compare-and-set against the version that the call
    /// read. A concurrent writer fails at commit and writes nothing.
    pub async fn upsert(&self, draft: RuleDraft) -> Result<Rule, RuleError> {
        draft.validate()?;

        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(RuleError::Store)?;
        let rule = self.stage_upsert(&tx, draft).await?;
        match tx.commit().await {
            Ok(()) => {}
            Err(StoreError::TxConflict { key, .. }) if key == meta_key(&rule.id) => {
                return Err(RuleError::Invalid(
                    "rule changed during the write".to_string(),
                ));
            }
            Err(error) => return Err(RuleError::Store(error)),
        }
        Ok(rule)
    }

    /// Stages one rule write in `tx`.
    ///
    /// The call reads the previous row and sets the next version.
    /// The rule row precondition compares the committed row with the row that
    /// the call read.
    async fn stage_upsert<S>(&self, tx: &S, draft: RuleDraft) -> Result<Rule, RuleError>
    where
        S: TxCas + ?Sized,
    {
        let previous = load_rule(tx, &draft.id).await?;
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
            capabilities: draft.capabilities,
            created_at: previous.as_ref().map_or(now, |rule| rule.created_at),
            updated_at: now,
        };

        let expected = match &previous {
            Some(previous) => Some(
                serde_json::to_vec(previous)
                    .map_err(|error| RuleError::Serialization(error.to_string()))?,
            ),
            None => None,
        };
        let bytes = serde_json::to_vec(&rule)
            .map_err(|error| RuleError::Serialization(error.to_string()))?;
        tx.compare_and_set(&meta_key(&rule.id), expected.as_deref(), &bytes)
            .await
            .map_err(RuleError::Store)?;
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

    /// Lists one page of rules.
    ///
    /// The result is sorted by priority in descending order.
    /// Two rules with the same priority are sorted by id.
    /// The call skips `offset` rules.
    /// It then returns at most `limit` rules.
    /// A `limit` of 0 returns an empty list.
    /// An offset above `MAX_PAGE_OFFSET` returns an invalid-input error.
    /// Rules support offset paging only.
    pub async fn list_page(&self, limit: usize, offset: usize) -> Result<Vec<Rule>, RuleError> {
        if offset > MAX_PAGE_OFFSET {
            return Err(RuleError::Invalid(format!(
                "offset must be at most {MAX_PAGE_OFFSET}. Rules support offset paging only."
            )));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rules = self.list().await?;
        Ok(rules.into_iter().skip(offset).take(limit).collect())
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
                for key in scan_keys_prefix(&*g, &prefix).await? {
                    let Some(id) = key.strip_prefix(&prefix) else {
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
        g.put_bytes(CURSOR_KEY, &bytes)
            .await
            .map_err(RuleError::Store)
    }

    /// Returns the key of one execution marker.
    ///
    /// The key is `rule:exec:{rule_id}:{event_id}`.
    pub(crate) fn execution_key(rule_id: &str, event_id: &str) -> String {
        exec_key(rule_id, event_id)
    }

    /// Returns the value of one execution marker.
    ///
    /// The value is the JSON encoding of the Unix time in seconds.
    /// [`RuleStore::mark_executed`] and a script action use the same format.
    pub(crate) fn execution_marker_value(now: i64) -> Result<Vec<u8>, RuleError> {
        serde_json::to_vec(&now).map_err(|error| RuleError::Serialization(error.to_string()))
    }

    /// True when an execution marker exists for one rule and one event.
    pub(crate) async fn is_executed(
        &self,
        rule_id: &str,
        event_id: &str,
    ) -> Result<bool, RuleError> {
        validate_identifier("rule id", rule_id)?;
        let g = self.store.read().await;
        Ok(g.get_bytes(&Self::execution_key(rule_id, event_id))
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
        let bytes = Self::execution_marker_value(now)?;
        let g = self.store.write().await;
        g.put_bytes(&Self::execution_key(rule_id, event_id), &bytes)
            .await
            .map_err(RuleError::Store)
    }

    /// Returns the number of failed attempts for one feed entry.
    ///
    /// A missing row is 0.
    /// The key is `rule-attempt:{seq}:{event_id}`.
    /// The call exists only in a test build.
    #[cfg(test)]
    pub(crate) async fn entry_attempts(&self, seq: u64, event_id: &str) -> Result<u32, RuleError> {
        let g = self.store.read().await;
        let Some(bytes) = g
            .get_bytes(&attempt_key(seq, event_id))
            .await
            .map_err(RuleError::Store)?
        else {
            return Ok(0);
        };
        serde_json::from_slice(&bytes).map_err(|error| RuleError::Serialization(error.to_string()))
    }

    /// Records one failed attempt and returns the new count.
    ///
    /// The row is durable, so a runtime restart continues the count.
    /// The key is `rule-attempt:{seq}:{event_id}`.
    /// The value is a JSON `u32`.
    pub(crate) async fn increment_entry_attempts(
        &self,
        seq: u64,
        event_id: &str,
    ) -> Result<u32, RuleError> {
        let key = attempt_key(seq, event_id);
        let g = self.store.write().await;
        let attempts = match g.get_bytes(&key).await.map_err(RuleError::Store)? {
            Some(bytes) => serde_json::from_slice::<u32>(&bytes)
                .map_err(|error| RuleError::Serialization(error.to_string()))?
                .saturating_add(1),
            None => 1,
        };
        let bytes = serde_json::to_vec(&attempts)
            .map_err(|error| RuleError::Serialization(error.to_string()))?;
        g.put_bytes(&key, &bytes).await.map_err(RuleError::Store)?;
        Ok(attempts)
    }

    /// Deletes the attempt row for one feed entry.
    ///
    /// A missing row is not an error.
    pub(crate) async fn clear_entry_attempts(
        &self,
        seq: u64,
        event_id: &str,
    ) -> Result<(), RuleError> {
        let g = self.store.write().await;
        g.delete(&attempt_key(seq, event_id))
            .await
            .map(|_| ())
            .map_err(RuleError::Store)
    }

    /// Writes one dead-letter row.
    ///
    /// The key is `rule-dead:{seq}:{event_id}:{rule_id}`.
    /// The value holds a [`RuleDeadLetter`] as JSON.
    pub(crate) async fn write_dead_letter(&self, dead: &RuleDeadLetter) -> Result<(), RuleError> {
        let bytes = serde_json::to_vec(dead)
            .map_err(|error| RuleError::Serialization(error.to_string()))?;
        let g = self.store.write().await;
        g.put_bytes(&dead_key(dead.seq, &dead.event_id, &dead.rule_id), &bytes)
            .await
            .map_err(RuleError::Store)
    }

    /// Lists every dead-letter row, newest first.
    ///
    /// The result is sorted by `at` in descending order.
    /// Two rows with the same `at` are sorted by `seq` in descending order.
    /// The call is for tests and for a future operator surface.
    pub async fn dead_letters(&self) -> Result<Vec<RuleDeadLetter>, RuleError> {
        let g = self.store.read().await;
        let rows = scan_family(&*g, DEAD_PREFIX).await?;
        let mut dead = Vec::with_capacity(rows.len());
        for row in rows {
            let entry: RuleDeadLetter = serde_json::from_slice(&row.value)
                .map_err(|error| RuleError::Serialization(error.to_string()))?;
            dead.push(entry);
        }
        dead.sort_by(|left, right| {
            right
                .at
                .cmp(&left.at)
                .then_with(|| right.seq.cmp(&left.seq))
        });
        Ok(dead)
    }

    /// Deletes expired cleanup rows.
    ///
    /// The call scans the `rule:exec:` key family.
    /// Each marker holds a JSON Unix timestamp in seconds.
    /// The call deletes a marker when its timestamp is less than `older_than`.
    /// A marker that does not decode stays in place.
    /// The call logs a warning for that row and continues the pass.
    ///
    /// The same pass scans the `rule-dead:` key family.
    /// It deletes a dead letter when its `at` time is older than
    /// `DEAD_LETTER_RETENTION_SECS`.
    /// The dead-letter retention is 7 days.
    /// The pass does not touch the cursor.
    ///
    /// The return value is the number of deleted rows.
    ///
    /// # Paging
    ///
    /// The call reads one family in pages of `GC_BATCH` rows.
    /// It deletes the expired rows of one page, then reads again.
    /// It stops when a page holds zero rows.
    /// It moves its cursor forward only when a page holds no expired row.
    /// Thus a delete cannot skip a live row.
    /// Memory use is proportional to `GC_BATCH` and not to the row count.
    ///
    /// A marker of a deleted rule stays until the retention window ends.
    ///
    /// # Duplicate actions
    ///
    /// A delete can permit a duplicate action.
    /// The duplicate happens when a replay of an old WAL event arrives after
    /// the cursor is reset.
    /// The retention window must be longer than any replay window.
    pub async fn gc_executions(&self, older_than: i64) -> Result<usize, RuleError> {
        let markers = self
            .gc_family(EXEC_PREFIX, older_than, |row| {
                serde_json::from_slice::<i64>(&row.value).ok()
            })
            .await?;
        let dead_before = chrono::Utc::now()
            .timestamp()
            .saturating_sub(DEAD_LETTER_RETENTION_SECS);
        let dead = self
            .gc_family(DEAD_PREFIX, dead_before, |row| {
                serde_json::from_slice::<RuleDeadLetter>(&row.value)
                    .ok()
                    .map(|entry| entry.at)
            })
            .await?;
        Ok(markers + dead)
    }

    /// Deletes the rows of one family whose timestamp is below `older_than`.
    async fn gc_family<F>(
        &self,
        prefix: &str,
        older_than: i64,
        timestamp: F,
    ) -> Result<usize, RuleError>
    where
        F: Fn(&KeyValue) -> Option<i64>,
    {
        let mut deleted = 0usize;
        // None starts at the first row. A set value resumes at that key.
        let mut cursor: Option<String> = None;
        loop {
            let rows = {
                let g = self.store.read().await;
                family_page(&g, prefix, cursor.as_deref()).await?
            };
            if rows.is_empty() {
                break;
            }
            self.record_gc_page(rows.len());

            let last_key = rows.last().map(|row| row.key.clone());
            let mut expired = Vec::new();
            for row in rows {
                match timestamp(&row) {
                    Some(at) if at < older_than => expired.push(row.key),
                    Some(_) => {}
                    None => {
                        tracing::warn!(
                            key = %row.key,
                            "rule cleanup row does not decode; keep it"
                        );
                    }
                }
            }

            let Some(last_key) = last_key else {
                break;
            };
            if expired.is_empty() {
                // No delete in this page. The next page starts at the last key.
                cursor = Some(last_key);
                continue;
            }

            let count = expired.len();
            {
                let _publish = self.publish_lock.lock().await;
                let g = self.store.write().await;
                let tx = g.begin_tx().map_err(RuleError::Store)?;
                for key in &expired {
                    tx.delete(key).await.map_err(RuleError::Store)?;
                }
                tx.commit().await.map_err(RuleError::Store)?;
            }
            deleted += count;
            // Do not move the cursor. The next page starts at the same key,
            // because a delete can otherwise skip a live row.
        }
        Ok(deleted)
    }

    /// Returns the number of execution markers.
    ///
    /// The call counts the rows in the `rule:exec:` key family.
    /// It reads the family in pages of `GC_BATCH` rows.
    /// Memory use is proportional to `GC_BATCH` and not to the marker count.
    pub async fn execution_count(&self) -> Result<usize, RuleError> {
        let g = self.store.read().await;
        g.count_prefix(KeyPrefix::new(EXEC_PREFIX), usize::MAX)
            .await
            .map_err(RuleError::Store)
    }

    /// Records the size of one cleanup page.
    ///
    /// The counter exists only in a test build.
    fn record_gc_page(&self, len: usize) {
        #[cfg(test)]
        self.gc_page_high_water
            .fetch_max(len, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(test))]
        let _ = len;
    }

    /// Returns the largest cleanup page that this store read.
    ///
    /// The call exists only in a test build.
    #[cfg(test)]
    fn gc_page_high_water(&self) -> usize {
        self.gc_page_high_water
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns true when the store holds no rule row.
    ///
    /// The call reads the first key of the `rule:meta:` family.
    /// It writes no key.
    pub(crate) async fn is_empty(&self) -> Result<bool, RuleError> {
        let g = self.store.read().await;
        let rows = g
            .gets_keys(
                Some(1),
                Direction::Next,
                (
                    Some(META_PREFIX.to_string()),
                    KeyPrefix::new(META_PREFIX).upper_bound(),
                ),
            )
            .await
            .map_err(RuleError::Store)?;
        Ok(rows.is_empty())
    }

    /// Imports exact rule records into an empty store.
    ///
    /// The call validates every rule before it writes any key.
    /// It writes the rule rows and the index markers in one transaction.
    /// It returns the keys that it wrote, so a failed import can remove them.
    /// The call rejects a rule id that the store already holds.
    pub(crate) async fn import_rules(&self, rules: &[Rule]) -> Result<Vec<String>, RuleError> {
        let mut seen = BTreeSet::new();
        for rule in rules {
            let draft = RuleDraft {
                id: rule.id.clone(),
                name: rule.name.clone(),
                enabled: rule.enabled,
                priority: rule.priority,
                trigger: rule.trigger.clone(),
                condition: rule.condition.clone(),
                action: rule.action.clone(),
                capabilities: rule.capabilities.clone(),
            };
            draft.validate()?;
            if rule.version == 0 {
                return Err(RuleError::Invalid(format!(
                    "rule {} has version 0",
                    rule.id
                )));
            }
            if !seen.insert(rule.id.clone()) {
                return Err(RuleError::Invalid(format!(
                    "rule {} has two records",
                    rule.id
                )));
            }
        }

        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(RuleError::Store)?;
        let mut keys = Vec::new();
        for rule in rules {
            if load_rule(&tx, &rule.id).await?.is_some() {
                return Err(RuleError::Invalid(format!(
                    "rule {} already exists in the target prefix",
                    rule.id
                )));
            }
        }
        for rule in rules {
            let key = meta_key(&rule.id);
            let bytes = serde_json::to_vec(rule)
                .map_err(|error| RuleError::Serialization(error.to_string()))?;
            tx.set_bytes(&key, &bytes).await.map_err(RuleError::Store)?;
            keys.push(key);
            for key in index_keys(&rule.trigger, &rule.id) {
                tx.set_bytes(&key, b"").await.map_err(RuleError::Store)?;
                keys.push(key);
            }
        }
        tx.commit().await.map_err(RuleError::Store)?;
        Ok(keys)
    }

    /// Removes the keys that [`import_rules`](Self::import_rules) wrote.
    ///
    /// The call runs after a later import step failed.
    /// It is safe only when the target prefix was empty before the import.
    pub(crate) async fn remove_import_keys(&self, keys: &[String]) -> Result<(), RuleError> {
        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(RuleError::Store)?;
        for key in keys {
            tx.delete(key).await.map_err(RuleError::Store)?;
        }
        tx.commit().await.map_err(RuleError::Store)?;
        Ok(())
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
        EntityEventKind::Timer => "timer",
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

/// Reads one bounded page of one key family.
///
/// The call reads at most `GC_BATCH` rows.
/// The cursor is inclusive.
/// When `after` is set, the call drops the resume key itself, so that the
/// caller does not read one key twice.
async fn family_page(
    store: &OxKvStore,
    prefix: &str,
    after: Option<&str>,
) -> Result<Vec<KeyValue>, RuleError> {
    let start = after.map_or_else(|| prefix.to_string(), ToString::to_string);
    let cursor = (Some(start), KeyPrefix::new(prefix).upper_bound());
    let mut rows = store
        .gets_bytes(Some(GC_BATCH), Direction::Next, cursor)
        .await
        .map_err(RuleError::Store)?;
    if let Some(resume) = after
        && rows.first().is_some_and(|row| row.key == resume)
    {
        rows.remove(0);
    }
    Ok(rows)
}

/// Scans a key range that ends at the `prefix:` family bound.
async fn scan_prefix<S>(store: &S, prefix: &str) -> Result<Vec<KeyValue>, RuleError>
where
    S: GetSet + ?Sized,
{
    debug_assert!(prefix.starts_with(RULE_PREFIX));
    scan_family(store, prefix).await
}

/// Scans a key range that ends at the `prefix:` family bound and reads keys
/// only.
async fn scan_keys_prefix<S>(store: &S, prefix: &str) -> Result<Vec<String>, RuleError>
where
    S: GetSet + ?Sized + Sync,
{
    debug_assert!(prefix.starts_with(RULE_PREFIX));
    let cursor = (
        Some(prefix.to_string()),
        KeyPrefix::new(prefix).upper_bound(),
    );
    store
        .gets_keys(None, Direction::Next, cursor)
        .await
        .map_err(RuleError::Store)
}

/// Scans one key family that ends at the `prefix:` family bound.
async fn scan_family<S>(store: &S, prefix: &str) -> Result<Vec<KeyValue>, RuleError>
where
    S: GetSet + ?Sized,
{
    debug_assert!(prefix.ends_with(':'));
    let cursor = (
        Some(prefix.to_string()),
        KeyPrefix::new(prefix).upper_bound(),
    );
    store
        .gets_bytes(None, Direction::Next, cursor)
        .await
        .map_err(RuleError::Store)
}

/// The key that holds one rule.
fn meta_key(id: &str) -> String {
    format!("{META_PREFIX}{id}")
}

/// The key that holds one execution marker.
fn exec_key(rule_id: &str, event_id: &str) -> String {
    format!("{EXEC_PREFIX}{rule_id}:{event_id}")
}

/// The key that holds the failed-attempt count of one feed entry.
fn attempt_key(seq: u64, event_id: &str) -> String {
    format!("{ATTEMPT_PREFIX}{seq}:{event_id}")
}

/// The key that holds one dead-letter row.
fn dead_key(seq: u64, event_id: &str, rule_id: &str) -> String {
    format!("{DEAD_PREFIX}{seq}:{event_id}:{rule_id}")
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
    use crate::rules::rule::{ActionRef, CompareOp, Condition, RuleCapabilities};
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
            capabilities: RuleCapabilities::default(),
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
    async fn capabilities_round_trip_through_the_store() {
        let store = new_store().await;
        let mut rule = draft("alpha");
        rule.capabilities.read = vec!["task".to_string()];
        rule.capabilities.write = vec!["task".to_string(), "note".to_string()];

        let saved = store.upsert(rule).await.unwrap();
        assert_eq!(saved.capabilities.read, vec!["task".to_string()]);
        assert_eq!(
            saved.capabilities.write,
            vec!["task".to_string(), "note".to_string()]
        );
        assert_eq!(store.get("alpha").await.unwrap(), Some(saved.clone()));

        let mut replacement = draft("alpha");
        replacement.capabilities.read = vec!["invoice".to_string()];
        let replaced = store.upsert(replacement).await.unwrap();
        assert_eq!(replaced.version, 2);
        assert_eq!(replaced.capabilities.read, vec!["invoice".to_string()]);
        assert!(replaced.capabilities.write.is_empty());
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
    async fn two_upserts_from_one_version_commit_one() {
        let (store, raw) = store_with_raw().await;
        let first_tx = raw.begin_tx().unwrap();
        let second_tx = raw.begin_tx().unwrap();
        let first = store.stage_upsert(&first_tx, draft("alpha")).await.unwrap();
        let second = store
            .stage_upsert(&second_tx, draft("alpha"))
            .await
            .unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(second.version, 1);

        first_tx.commit().await.unwrap();
        let error = second_tx.commit().await.unwrap_err();

        assert!(matches!(error, StoreError::TxConflict { .. }));
        assert_eq!(store.get("alpha").await.unwrap().unwrap().version, 1);
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
    async fn list_page_returns_the_first_page() {
        let store = new_store().await;
        for id in ["a", "b", "c", "d"] {
            store.upsert(draft(id)).await.unwrap();
        }

        let page = store.list_page(2, 0).await.unwrap();
        let ids: Vec<String> = page.into_iter().map(|rule| rule.id).collect();

        assert_eq!(ids, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn list_page_returns_the_second_page() {
        let store = new_store().await;
        for id in ["a", "b", "c", "d"] {
            store.upsert(draft(id)).await.unwrap();
        }

        let page = store.list_page(2, 2).await.unwrap();
        let ids: Vec<String> = page.into_iter().map(|rule| rule.id).collect();

        assert_eq!(ids, vec!["c", "d"]);
    }

    #[tokio::test]
    async fn list_page_offset_past_the_end_is_empty() {
        let store = new_store().await;
        store.upsert(draft("a")).await.unwrap();

        let page = store.list_page(2, 9).await.unwrap();

        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_page_rejects_an_offset_above_the_maximum() {
        let store = new_store().await;
        store.upsert(draft("a")).await.unwrap();

        let result = store.list_page(2, MAX_PAGE_OFFSET + 1).await;

        assert!(matches!(result, Err(RuleError::Invalid(_))));
    }

    #[tokio::test]
    async fn list_page_with_limit_zero_is_empty() {
        let store = new_store().await;
        store.upsert(draft("a")).await.unwrap();

        let page = store.list_page(0, 0).await.unwrap();

        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_page_keeps_priority_then_id_order() {
        let store = new_store().await;
        for (id, priority) in [("b", 5), ("a", 5), ("c", 9), ("d", 1)] {
            let mut rule = draft(id);
            rule.priority = priority;
            store.upsert(rule).await.unwrap();
        }

        let page = store.list_page(2, 0).await.unwrap();
        let ids: Vec<String> = page.into_iter().map(|rule| rule.id).collect();
        let second = store.list_page(2, 2).await.unwrap();
        let second_ids: Vec<String> = second.into_iter().map(|rule| rule.id).collect();

        assert_eq!(ids, vec!["c", "a"]);
        assert_eq!(second_ids, vec!["b", "d"]);
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
    async fn a_timer_trigger_matches_a_timer_event() {
        let store = new_store().await;
        let mut rule = draft("alpha");
        rule.trigger.events = vec![EntityEventKind::Timer];
        store.upsert(rule).await.unwrap();

        let matches = store
            .matching(&event(EntityEventKind::Timer, &["invoice"], &[]))
            .await
            .unwrap();

        assert_eq!(matches.len(), 1);
        assert!(
            store
                .matching(&event(EntityEventKind::Created, &["invoice"], &[]))
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

    async fn put_execution_marker(store: &OxKvStore, rule_id: &str, event_id: &str, at: i64) {
        let bytes = serde_json::to_vec(&at).unwrap();
        store
            .set_bytes(&exec_key(rule_id, event_id), &bytes)
            .await
            .unwrap();
    }

    fn dead_letter(seq: u64, event_id: &str, at: i64) -> RuleDeadLetter {
        RuleDeadLetter {
            seq,
            event_id: event_id.to_string(),
            rule_id: "alpha".to_string(),
            attempts: 5,
            error: "rule action failed: record".to_string(),
            at,
        }
    }

    #[tokio::test]
    async fn gc_executions_deletes_old_markers() {
        let (store, raw) = store_with_raw().await;
        put_execution_marker(&raw, "alpha", "evt-old", 100).await;

        let deleted = store.gc_executions(200).await.unwrap();

        assert_eq!(deleted, 1);
        assert!(!store.is_executed("alpha", "evt-old").await.unwrap());
    }

    #[tokio::test]
    async fn gc_executions_keeps_new_markers() {
        let (store, raw) = store_with_raw().await;
        put_execution_marker(&raw, "alpha", "evt-new", 300).await;

        let deleted = store.gc_executions(200).await.unwrap();

        assert_eq!(deleted, 0);
        assert!(store.is_executed("alpha", "evt-new").await.unwrap());
    }

    #[tokio::test]
    async fn gc_executions_keeps_unreadable_markers() {
        let (store, raw) = store_with_raw().await;
        raw.set_bytes(&exec_key("alpha", "evt-bad"), b"not-json")
            .await
            .unwrap();

        let deleted = store.gc_executions(200).await.unwrap();

        assert_eq!(deleted, 0);
        assert!(store.is_executed("alpha", "evt-bad").await.unwrap());
    }

    #[tokio::test]
    async fn execution_count_returns_the_marker_count() {
        let (store, raw) = store_with_raw().await;
        assert_eq!(store.execution_count().await.unwrap(), 0);

        put_execution_marker(&raw, "alpha", "evt-1", 100).await;
        put_execution_marker(&raw, "beta", "evt-2", 300).await;

        assert_eq!(store.execution_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn entry_attempts_increment_and_clear() {
        let (store, raw) = store_with_raw().await;

        assert_eq!(store.entry_attempts(1, "evt-1").await.unwrap(), 0);
        assert_eq!(store.increment_entry_attempts(1, "evt-1").await.unwrap(), 1);
        assert_eq!(store.increment_entry_attempts(1, "evt-1").await.unwrap(), 2);
        assert_eq!(store.entry_attempts(1, "evt-1").await.unwrap(), 2);

        let bytes = raw
            .get_bytes(&attempt_key(1, "evt-1"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::from_slice::<u32>(&bytes).unwrap(), 2);

        store.clear_entry_attempts(1, "evt-1").await.unwrap();
        assert_eq!(store.entry_attempts(1, "evt-1").await.unwrap(), 0);
    }

    /// An old dead-letter row has no rule id and decodes as an empty string.
    #[test]
    fn an_old_dead_letter_without_a_rule_id_decodes() {
        let stored = serde_json::json!({
            "seq": 1,
            "event_id": "evt-1",
            "attempts": 5,
            "error": "rule action failed: record",
            "at": 10
        });

        let entry: RuleDeadLetter = serde_json::from_value(stored).expect("old row parses");

        assert_eq!(entry.rule_id, "");
        assert_eq!(entry.seq, 1);
    }

    #[tokio::test]
    async fn dead_letters_returns_newest_first() {
        let (store, _raw) = store_with_raw().await;
        store
            .write_dead_letter(&dead_letter(1, "evt-1", 100))
            .await
            .unwrap();
        store
            .write_dead_letter(&dead_letter(3, "evt-3", 300))
            .await
            .unwrap();
        store
            .write_dead_letter(&dead_letter(2, "evt-2", 200))
            .await
            .unwrap();

        let dead = store.dead_letters().await.unwrap();
        let seqs: Vec<u64> = dead.into_iter().map(|entry| entry.seq).collect();

        assert_eq!(seqs, vec![3, 2, 1]);
    }

    #[tokio::test]
    async fn gc_executions_deletes_old_dead_letters_and_keeps_new_ones() {
        let (store, _raw) = store_with_raw().await;
        let now = chrono::Utc::now().timestamp();
        let old = dead_letter(1, "evt-old", now - DEAD_LETTER_RETENTION_SECS - 60);
        let new = dead_letter(2, "evt-new", now);
        store.write_dead_letter(&old).await.unwrap();
        store.write_dead_letter(&new).await.unwrap();

        let deleted = store.gc_executions(200).await.unwrap();

        assert_eq!(deleted, 1);
        assert_eq!(store.dead_letters().await.unwrap(), vec![new]);
    }

    #[tokio::test]
    async fn dead_letter_cleanup_keeps_execution_markers_and_the_cursor() {
        let (store, raw) = store_with_raw().await;
        let now = chrono::Utc::now().timestamp();
        put_execution_marker(&raw, "alpha", "evt-live", now).await;
        store.set_cursor(9).await.unwrap();
        store
            .write_dead_letter(&dead_letter(
                1,
                "evt-old",
                now - DEAD_LETTER_RETENTION_SECS - 60,
            ))
            .await
            .unwrap();

        let deleted = store.gc_executions(200).await.unwrap();

        assert_eq!(deleted, 1);
        assert!(store.is_executed("alpha", "evt-live").await.unwrap());
        assert_eq!(store.cursor().await.unwrap(), 9);
        assert!(store.dead_letters().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn gc_executions_deletes_old_markers_across_pages() {
        let (store, raw) = store_with_raw().await;
        for index in 1..=7 {
            put_execution_marker(&raw, "alpha", &format!("evt-{index}"), 100).await;
        }

        let deleted = store.gc_executions(200).await.unwrap();

        assert_eq!(deleted, 7);
        assert_eq!(store.execution_count().await.unwrap(), 0);
        for index in 1..=7 {
            assert!(
                !store
                    .is_executed("alpha", &format!("evt-{index}"))
                    .await
                    .unwrap()
            );
        }
    }

    #[tokio::test]
    async fn gc_executions_keeps_live_markers_across_pages() {
        let (store, raw) = store_with_raw().await;
        for index in 1..=5 {
            let at = if index % 2 == 0 { 300 } else { 100 };
            put_execution_marker(&raw, "alpha", &format!("evt-{index}"), at).await;
        }

        let deleted = store.gc_executions(200).await.unwrap();

        assert_eq!(deleted, 3);
        assert!(!store.is_executed("alpha", "evt-1").await.unwrap());
        assert!(store.is_executed("alpha", "evt-2").await.unwrap());
        assert!(!store.is_executed("alpha", "evt-3").await.unwrap());
        assert!(store.is_executed("alpha", "evt-4").await.unwrap());
        assert!(!store.is_executed("alpha", "evt-5").await.unwrap());
    }

    #[tokio::test]
    async fn gc_executions_second_pass_finds_nothing() {
        let (store, raw) = store_with_raw().await;
        for index in 1..=5 {
            put_execution_marker(&raw, "alpha", &format!("evt-{index}"), 100).await;
        }

        assert_eq!(store.gc_executions(200).await.unwrap(), 5);
        assert_eq!(store.gc_executions(200).await.unwrap(), 0);
        assert_eq!(store.execution_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn gc_executions_reads_at_most_one_batch() {
        let (store, raw) = store_with_raw().await;
        for index in 1..=7 {
            put_execution_marker(&raw, "alpha", &format!("evt-{index}"), 100).await;
        }

        assert_eq!(store.gc_executions(200).await.unwrap(), 7);

        let largest = store.gc_page_high_water();
        assert_eq!(
            largest, GC_BATCH,
            "the cleanup must read one full page and no more"
        );
    }

    #[tokio::test]
    async fn execution_count_pages_the_family() {
        let (store, raw) = store_with_raw().await;
        for index in 1..=7 {
            put_execution_marker(&raw, "alpha", &format!("evt-{index}"), 100).await;
        }

        assert_eq!(store.execution_count().await.unwrap(), 7);
    }

    #[tokio::test]
    async fn execution_count_matches_every_marker_across_pages() {
        let (store, raw) = store_with_raw().await;
        for index in 0..300 {
            put_execution_marker(&raw, "alpha", &format!("evt-{index}"), 100).await;
        }

        let expected = raw
            .count_prefix(KeyPrefix::new(EXEC_PREFIX), usize::MAX)
            .await
            .unwrap();
        assert_eq!(expected, 300);
        assert_eq!(store.execution_count().await.unwrap(), expected);
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
