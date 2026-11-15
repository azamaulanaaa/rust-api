//! Casbin storage adapter backed by an [`oxkv`] key-value store.
//!
//! Every policy rule is stored as one key-value pair. The key is
//! deterministic. It encodes the section, the policy type, and a content
//! hash of the rule. The value is the rule vector in JSON. Deterministic keys
//! make duplicate detection a single `has` lookup and keep repeated adds
//! idempotent.
//!
//! All mutating adapter operations run inside an [`oxkv`] transaction, so
//! batch operations commit atomically.
//!
//! # Durable policy outbox
//!
//! An adapter that `OxkvAdapter::with_outbox` creates stages one outbox row
//! for each policy change. The row commits in the same transaction as the
//! policy rule. A crash therefore cannot separate the rule from the
//! announcement.
//! `Outbox` drains the rows to the change feed in sequence order.
//! A failed append leaves the row, so a later drain delivers it.

use async_trait::async_trait;
use casbin::{
    Adapter, Filter, Model,
    error::{AdapterError, Error as CasbinError},
};
use oxkv::{
    Direction, GetSet, KeyPrefix, Store, StoreError, StoreView, Transaction as _, TxCas, Validator,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::PolicyError;
use crate::records::{ChangeSink, WalOp};

/// Key prefix separator. The keys have the form `{sec}:{ptype}:{rule-hash}`.
const SEP: char = ':';

/// Key prefix for policy changes that wait for the change feed.
const OUTBOX_PREFIX: &str = "outbox:";

/// Key for the next outbox sequence number.
///
/// The key is outside [`OUTBOX_PREFIX`], so an outbox scan skips it.
const OUTBOX_NEXT_KEY: &str = "outbox-meta:next";

/// Encodes a string as hex so it is safe to embed in a store key.
fn hex_encode(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic storage key for a single policy rule.
fn rule_key(sec: &str, ptype: &str, rule: &[String]) -> String {
    let joined = rule.join("\u{1f}");
    format!("{sec}{SEP}{ptype}{SEP}{}", hex_encode(&joined))
}

/// Returns `true` when `key` names one policy rule.
///
/// The function accepts only the `p` and `g` sections. Foreign keys, such as
/// the outbox rows, stay out of the startup load.
fn is_rule_key(key: &str) -> bool {
    let mut parts = key.splitn(3, SEP);
    let (Some(sec), Some(ptype), Some(hash)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    matches!(sec, "p" | "g") && !ptype.is_empty() && !hash.is_empty()
}

/// The storage key for outbox row `seq`.
fn outbox_key(seq: u64) -> String {
    format!("{OUTBOX_PREFIX}{seq:020}")
}

/// Returns `true` when `key` names one outbox row.
fn is_outbox_row(key: &str) -> bool {
    key.strip_prefix(OUTBOX_PREFIX)
        .is_some_and(|seq| seq.len() == 20 && seq.bytes().all(|b| b.is_ascii_digit()))
}

/// One policy change that is durable but not yet in the change feed.
#[derive(Debug, Serialize, Deserialize)]
struct OutboxRow {
    /// Deterministic identifier of `op`.
    id: String,
    /// The change that waits for the feed.
    op: WalOp,
}

/// Returns a deterministic identifier for one change-feed operation.
///
/// The same operation always yields the same id. A retry can therefore
/// recognize the row that it already wrote.
fn op_id(op: &WalOp) -> Result<String, StoreError> {
    let bytes = serde_json::to_vec(op).map_err(StoreError::from)?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Returns the change-feed operation for one rule change.
///
/// The rule arity fixes the mapping. The section `p` carries three fields and
/// the section `g` carries two. [`PolicyRuleValidator`] rejects any other
/// shape before this function runs.
fn rule_op(sec: &str, rule: &[String], added: bool) -> Option<WalOp> {
    match (sec, rule) {
        ("p", [sub, obj, act]) => Some(if added {
            WalOp::PolicyRuleAdd {
                sub: sub.clone(),
                obj: obj.clone(),
                act: act.clone(),
            }
        } else {
            WalOp::PolicyRuleRemove {
                sub: sub.clone(),
                obj: obj.clone(),
                act: act.clone(),
            }
        }),
        ("g", [user, group]) => Some(if added {
            WalOp::GroupAdd {
                user: user.clone(),
                group: group.clone(),
            }
        } else {
            WalOp::GroupRemove {
                user: user.clone(),
                group: group.clone(),
            }
        }),
        _ => None,
    }
}

/// An operation that the outbox cannot represent.
fn outbox_unrepresentable() -> CasbinError {
    store_err(StoreError::Other(
        "the policy outbox cannot represent this change".to_string(),
    ))
}

/// Reads the next outbox sequence number. An absent key means zero.
async fn read_outbox_next<S>(store: &S) -> Result<u64, StoreError>
where
    S: GetSet + ?Sized,
{
    let Some(bytes) = store.get_bytes(OUTBOX_NEXT_KEY).await? else {
        return Ok(0);
    };
    serde_json::from_slice(&bytes).map_err(StoreError::from)
}

/// Stages one outbox row for each operation in `ops`.
///
/// The rows use the sequence numbers after the durable counter. The function
/// writes the rows and the new counter into `tx`, so they commit with the
/// policy change that produced them. A failed commit changes no row and no
/// counter.
async fn stage_outbox_rows<T>(tx: &T, ops: &[WalOp]) -> Result<(), StoreError>
where
    T: TxCas + Sync,
{
    if ops.is_empty() {
        return Ok(());
    }
    let start = read_outbox_next(tx).await?;
    for (offset, op) in ops.iter().enumerate() {
        let row = OutboxRow {
            id: op_id(op)?,
            op: op.clone(),
        };
        let bytes = serde_json::to_vec(&row).map_err(StoreError::from)?;
        let seq = start.saturating_add(offset as u64);
        tx.set_bytes(&outbox_key(seq), &bytes).await?;
    }
    let next = start.saturating_add(ops.len() as u64);
    let bytes = serde_json::to_vec(&next).map_err(StoreError::from)?;
    tx.set_bytes(OUTBOX_NEXT_KEY, &bytes).await?;
    Ok(())
}

/// Maps an [`oxkv::StoreError`] into casbin's adapter error type.
fn store_err(e: oxkv::StoreError) -> CasbinError {
    CasbinError::AdapterError(AdapterError(Box::new(e)))
}

/// Encodes one rule as a validated `(key, value)` pair.
///
/// The adapter enforces [`PolicyRuleValidator`] directly on every write path.
/// Callers therefore do not have to wrap their store in an
/// [`oxkv::Hooks`]. The validation runs before any transaction
/// opens, so rejected writes fail without touching the store.
async fn encode_rule<S>(
    store: &S,
    sec: &str,
    ptype: &str,
    rule: &[String],
) -> Result<(String, Vec<u8>), CasbinError>
where
    S: Store + Send + Sync,
{
    let key = rule_key(sec, ptype, rule);
    // StoreError implements From<serde_json::Error>. The code converts
    // the error before it crosses into the error domain of casbin.
    let value = serde_json::to_vec(rule)
        .map_err(oxkv::StoreError::from)
        .map_err(store_err)?;
    PolicyRuleValidator
        .validate(store, &key, &value)
        .await
        .map_err(store_err)?;
    Ok((key, value))
}

/// Validates every write into the policy store before the write becomes
/// durable.
///
/// The validator enforces the storage contract of the adapter at the storage
/// layer. A bug in the adapter itself, or in any future tooling that touches
/// the same file, is then rejected at write time. It does not poison the
/// startup load of [`OxkvAdapter`]:
///
/// - Keys must have the form `{sec}:{ptype}:{hex-hash}`, with a known
///   section (`p` or `g`).
/// - Values must decode as a JSON array of strings.
/// - Rules must match the field count of the RBAC model. That count is 3 for
///   `p` and 2 for `g`.
/// - The outbox row keys `outbox:{seq:020}` must hold an outbox row.
/// - The outbox counter key `outbox-meta:next` must hold a JSON `u64`.
pub struct PolicyRuleValidator;

impl PolicyRuleValidator {
    /// Returns the expected field count of a rule in a section of the RBAC
    /// model. The model is defined in
    /// [`PolicyEngine`](super::PolicyEngine). The count is coupled to that
    /// model on purpose. A change to the model requires a check of this
    /// validator again.
    fn expected_arity(sec: &str) -> usize {
        match sec {
            "p" => 3, // sub, obj, act
            "g" => 2, // user, group
            _ => unreachable!("section validated before arity check"),
        }
    }
}

#[async_trait]
impl Validator for PolicyRuleValidator {
    async fn validate(
        &self,
        _ctx: &dyn StoreView,
        key: &str,
        value: &[u8],
    ) -> Result<(), oxkv::StoreError> {
        if key == OUTBOX_NEXT_KEY {
            serde_json::from_slice::<u64>(value)
                .map_err(|e| format!("policy outbox counter must be a JSON number: {e}"))?;
            return Ok(());
        }
        if key.starts_with(OUTBOX_PREFIX) {
            if !is_outbox_row(key) {
                return Err(format!(
                    "policy outbox row keys must be '{OUTBOX_PREFIX}{{seq:020}}', got '{key}'"
                )
                .into());
            }
            let row: OutboxRow = serde_json::from_slice(value)
                .map_err(|e| format!("policy outbox row must be a JSON object: {e}"))?;
            if row.id.is_empty() {
                return Err(format!("policy outbox row '{key}' has no id").into());
            }
            return Ok(());
        }
        let mut parts = key.splitn(3, SEP);
        let (Some(sec), Some(ptype), Some(hash)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(
                format!("policy keys must be '{{sec}}:ptype:{{hash}}', got '{key}'").into(),
            );
        };
        if sec != "p" && sec != "g" {
            return Err(format!("unknown policy section '{sec}' in key '{key}'").into());
        }
        if ptype.is_empty() {
            return Err(format!("empty policy type segment in key '{key}'").into());
        }
        if hash.is_empty() || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("non-hex rule hash segment in key '{key}'").into());
        }

        let rule: Vec<String> = serde_json::from_slice(value)
            .map_err(|e| format!("policy rule must be a JSON string array: {e}"))?;
        let expected = Self::expected_arity(sec);
        if rule.len() != expected {
            return Err(format!("'{sec}' rules need {expected} fields, got {}", rule.len()).into());
        }
        Ok(())
    }
}

/// A Casbin [`Adapter`] persisting policies to any [`oxkv::Store`].
///
/// Generic over the backend. Production uses a prefix-scoped
/// `OxKvStore`. The tests use the in-memory B-tree store or an
/// `InMemory`-backed `OxKvStore`.
/// Every write path validates the rules through [`PolicyRuleValidator`]
/// before it stages them. The private helper `encode_rule` runs that
/// validation.
///
/// An adapter that `OxkvAdapter::with_outbox` creates also stages one
/// outbox row for each policy change, in the same transaction as the rule.
pub struct OxkvAdapter<S: Store> {
    /// The backend that holds the policy rules and the outbox rows.
    store: S,
    /// True when each change also stages a durable outbox row.
    outbox: bool,
}

impl<S: Store + Sync> OxkvAdapter<S>
where
    S::Transaction: TxCas,
{
    /// Wraps an existing store instance without an outbox.
    pub fn new(store: S) -> Self {
        Self {
            store,
            outbox: false,
        }
    }

    /// Wraps `store` and stages a durable outbox row with each policy change.
    ///
    /// The row commits in the same transaction as the rule. A caller that
    /// wants the rows delivered must also keep a clone of `store` for
    /// `Outbox`.
    pub(crate) fn with_outbox(store: S) -> Self {
        Self {
            store,
            outbox: true,
        }
    }

    /// Loads and decodes every stored `(sec, ptype, rule)` triple.
    async fn load_all(&self) -> Result<Vec<(String, String, Vec<String>)>, oxkv::StoreError> {
        let mut out = Vec::new();
        for kv in self
            .store
            .gets_bytes(None, Direction::Next, (None, None))
            .await?
        {
            let mut parts = kv.key.splitn(3, SEP);
            let (Some(sec), Some(ptype), Some(_)) = (parts.next(), parts.next(), parts.next())
            else {
                // A foreign or corrupt entry is skipped. It does not
                // poison the startup.
                continue;
            };
            if !matches!(sec, "p" | "g") {
                // The outbox rows and their counter are not rules.
                continue;
            }
            let rule: Vec<String> = serde_json::from_slice(&kv.value)?;
            out.push((sec.to_string(), ptype.to_string(), rule));
        }
        Ok(out)
    }

    /// Loads every stored policy rule with its storage key.
    async fn load_entries(&self) -> Result<Vec<(String, String, Vec<String>)>, oxkv::StoreError> {
        let mut out = Vec::new();
        for kv in self
            .store
            .gets_bytes(None, Direction::Next, (None, None))
            .await?
        {
            if !is_rule_key(&kv.key) {
                continue;
            }
            let mut parts = kv.key.splitn(3, SEP);
            let Some(sec) = parts.next() else {
                continue;
            };
            let sec = sec.to_string();
            let rule: Vec<String> = serde_json::from_slice(&kv.value)?;
            out.push((kv.key, sec, rule));
        }
        Ok(out)
    }

    /// Returns `true` when `rule[field_index + i] == field_values[i]` for
    /// all `i`. It implements the matching semantics of a filtered policy
    /// in casbin.
    fn rule_matches(rule: &[String], field_index: usize, field_values: &[String]) -> bool {
        field_values
            .iter()
            .enumerate()
            .all(|(i, v)| rule.get(field_index + i) == Some(v))
    }
}

#[async_trait]
impl<S> Adapter for OxkvAdapter<S>
where
    S: Store + Send + Sync + 'static,
    S::Transaction: TxCas,
{
    async fn load_policy(&mut self, m: &mut dyn Model) -> casbin::Result<()> {
        for (sec, ptype, rule) in self.load_all().await.map_err(store_err)? {
            m.add_policy(&sec, &ptype, rule);
        }
        Ok(())
    }

    async fn load_filtered_policy<'a>(
        &mut self,
        m: &mut dyn Model,
        f: Filter<'a>,
    ) -> casbin::Result<()> {
        for (sec, ptype, rule) in self.load_all().await.map_err(store_err)? {
            let filter = match sec.as_str() {
                "p" => Some(&f.p),
                "g" => Some(&f.g),
                _ => None,
            };
            if let Some(field_values) = filter
                && !Self::rule_matches(
                    &rule,
                    0,
                    &field_values
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>(),
                )
            {
                continue;
            }
            m.add_policy(&sec, &ptype, rule);
        }
        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> casbin::Result<()> {
        // Read the stored rules before the transaction. The read gives both
        // the keys to delete and the rules that the new model no longer has.
        let existing = self.load_entries().await.map_err(store_err)?;
        let old_keys: Vec<String> = existing.iter().map(|(key, _, _)| key.clone()).collect();

        let entries: Vec<(String, String, Vec<String>)> = m
            .get_model()
            .iter()
            .flat_map(|(sec, assertions)| {
                assertions.iter().flat_map(move |(ptype, assertion)| {
                    assertion
                        .policy
                        .clone()
                        .into_iter()
                        .map(move |rule| (sec.clone(), ptype.clone(), rule))
                })
            })
            .collect();

        // The code validates and encodes every entry before it opens
        // the transaction. A malformed rule then fails without touching the
        // store.
        let mut encoded = Vec::with_capacity(entries.len());
        let mut new_keys = std::collections::BTreeSet::new();
        let mut ops = Vec::new();
        for (sec, ptype, rule) in &entries {
            let (key, value) = encode_rule(&self.store, sec, ptype, rule).await?;
            if self.outbox {
                new_keys.insert(key.clone());
                if !old_keys.contains(&key) {
                    ops.push(rule_op(sec, rule, true).ok_or_else(outbox_unrepresentable)?);
                }
            }
            encoded.push((key, value));
        }
        if self.outbox {
            for (key, sec, rule) in &existing {
                if !new_keys.contains(key) {
                    ops.push(rule_op(sec, rule, false).ok_or_else(outbox_unrepresentable)?);
                }
            }
        }

        // One transaction removes the old rules, writes the new rules, and
        // stages the outbox rows. A crash cannot leave a half-written policy.
        let tx = self.store.begin_tx().map_err(store_err)?;
        for key in &old_keys {
            tx.delete(key).await.map_err(store_err)?;
        }
        for (key, value) in &encoded {
            tx.set_bytes(key, value).await.map_err(store_err)?;
        }
        stage_outbox_rows(&tx, &ops).await.map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    async fn clear_policy(&mut self) -> casbin::Result<()> {
        let existing = self.load_entries().await.map_err(store_err)?;
        let keys: Vec<String> = existing.iter().map(|(key, _, _)| key.clone()).collect();
        let mut ops = Vec::new();
        if self.outbox {
            for (_, sec, rule) in &existing {
                ops.push(rule_op(sec, rule, false).ok_or_else(outbox_unrepresentable)?);
            }
        }

        let tx = self.store.begin_tx().map_err(store_err)?;
        for key in &keys {
            tx.delete(key).await.map_err(store_err)?;
        }
        stage_outbox_rows(&tx, &ops).await.map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    fn is_filtered(&self) -> bool {
        false
    }

    async fn add_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> casbin::Result<bool> {
        self.add_policies(sec, ptype, vec![rule]).await
    }

    async fn add_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> casbin::Result<bool> {
        // The code validates and encodes every rule before it opens
        // the transaction. A malformed rule then fails without staging
        // partial state. The duplicate handling below stays the same.
        let mut encoded = Vec::with_capacity(rules.len());
        let mut ops = Vec::with_capacity(rules.len());
        for rule in &rules {
            encoded.push(encode_rule(&self.store, sec, ptype, rule).await?);
            if self.outbox {
                ops.push(rule_op(sec, rule, true).ok_or_else(outbox_unrepresentable)?);
            }
        }

        let tx = self.store.begin_tx().map_err(store_err)?;
        for (key, value) in &encoded {
            tx.set_if_absent(key, value).await.map_err(store_err)?;
        }
        stage_outbox_rows(&tx, &ops).await.map_err(store_err)?;
        match tx.commit().await {
            Ok(()) => Ok(true),
            Err(StoreError::TxConflict { .. }) => Ok(false),
            Err(error) => Err(store_err(error)),
        }
    }

    async fn remove_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        rule: Vec<String>,
    ) -> casbin::Result<bool> {
        self.remove_policies(sec, ptype, vec![rule]).await
    }

    async fn remove_policies(
        &mut self,
        sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> casbin::Result<bool> {
        let keys: Vec<String> = rules.iter().map(|r| rule_key(sec, ptype, r)).collect();
        let mut ops = Vec::with_capacity(rules.len());
        if self.outbox {
            for rule in &rules {
                ops.push(rule_op(sec, rule, false).ok_or_else(outbox_unrepresentable)?);
            }
        }

        let tx = self.store.begin_tx().map_err(store_err)?;
        for key in &keys {
            if oxkv::GetSet::has(&tx, key).await.map_err(store_err)? {
                tx.delete(key).await.map_err(store_err)?;
            } else {
                tx.rollback().await.map_err(store_err)?;
                return Ok(false);
            }
        }
        stage_outbox_rows(&tx, &ops).await.map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(true)
    }

    async fn remove_filtered_policy(
        &mut self,
        sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> casbin::Result<bool> {
        let prefix = format!("{sec}{SEP}{ptype}{SEP}");
        let mut to_delete = Vec::new();
        let mut removed = Vec::new();
        for kv in self
            .store
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .map_err(store_err)?
        {
            if !kv.key.starts_with(&prefix) {
                continue;
            }
            let rule: Vec<String> = serde_json::from_slice(&kv.value)
                .map_err(oxkv::StoreError::from)
                .map_err(store_err)?;
            if Self::rule_matches(&rule, field_index, &field_values) {
                to_delete.push(kv.key);
                removed.push(rule);
            }
        }

        let mut ops = Vec::new();
        if self.outbox && !to_delete.is_empty() {
            if sec == "g" && field_index == 1 && field_values.len() == 1 {
                // One group delete covers every membership link that the
                // filter removed.
                ops.push(WalOp::GroupDelete {
                    group: field_values[0].clone(),
                });
            } else {
                for rule in &removed {
                    ops.push(rule_op(sec, rule, false).ok_or_else(outbox_unrepresentable)?);
                }
            }
        }

        let tx = self.store.begin_tx().map_err(store_err)?;
        for key in &to_delete {
            tx.delete(key).await.map_err(store_err)?;
        }
        stage_outbox_rows(&tx, &ops).await.map_err(store_err)?;
        tx.commit().await.map_err(store_err)?;
        Ok(!to_delete.is_empty())
    }
}

/// The durable policy changes of one engine.
///
/// A rollback discards a pending row. A row is pending only after its
/// transaction commits, and the transaction commits the policy rule with it.
#[async_trait]
pub(crate) trait PolicyOutbox: Send + Sync {
    /// Delivers every pending row to `feed` in sequence order.
    ///
    /// The call stops at the first failed append. That row and the rows after
    /// it stay pending.
    /// `None` discards the rows, because the engine has no feed. A
    /// deployment with no feed has logging disabled.
    async fn drain(&self, feed: Option<&dyn ChangeSink>) -> Result<usize, PolicyError>;

    /// Returns the number of pending rows.
    #[cfg(test)]
    async fn pending(&self) -> Result<usize, PolicyError>;
}

/// A handle to the durable policy outbox of one store.
///
/// The adapter stages the rows. This handle delivers them, so the types that
/// own the enforcer and the feed can stay non-generic.
pub(crate) struct Outbox<S: Store> {
    /// The backend that holds the outbox rows.
    store: S,
}

impl<S> Outbox<S>
where
    S: Store + Send + Sync,
    S::Transaction: TxCas,
{
    /// Wraps `store`.
    pub(crate) fn new(store: S) -> Self {
        Self { store }
    }

    /// Returns every pending outbox row key in sequence order.
    async fn row_keys(&self) -> Result<Vec<String>, StoreError> {
        let cursor = (
            Some(OUTBOX_PREFIX.to_string()),
            KeyPrefix::new(OUTBOX_PREFIX).upper_bound(),
        );
        let keys = self.store.gets_keys(None, Direction::Next, cursor).await?;
        Ok(keys.into_iter().filter(|key| is_outbox_row(key)).collect())
    }
}

#[async_trait]
impl<S> PolicyOutbox for Outbox<S>
where
    S: Store + Send + Sync,
    S::Transaction: TxCas,
{
    async fn drain(&self, feed: Option<&dyn ChangeSink>) -> Result<usize, PolicyError> {
        let mut delivered = 0;
        for key in self.row_keys().await? {
            let Some(bytes) = self.store.get_bytes(&key).await? else {
                continue;
            };
            if let Some(feed) = feed {
                let row: OutboxRow = serde_json::from_slice(&bytes).map_err(|e| {
                    PolicyError::Store(StoreError::Other(format!(
                        "policy outbox row {key} is invalid: {e}"
                    )))
                })?;
                feed.append(row.op)
                    .await
                    .map_err(|e| PolicyError::ChangeFeed(e.to_string()))?;
            }
            self.store.delete(&key).await?;
            delivered += 1;
        }
        Ok(delivered)
    }

    #[cfg(test)]
    async fn pending(&self) -> Result<usize, PolicyError> {
        Ok(self.row_keys().await?.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fencing::Latch;
    use crate::policy::RBAC_MODEL;
    use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi, Model};
    use oxkv::{BTreeStore, Hooks};

    /// A store whose commits report a lost epoch.
    ///
    /// The reads come from a real `BTreeStore`, so the engine loads
    /// normally. Only the durability step fails. That is exactly when `oxkv`
    /// fences a writer. The test uses a real backend here instead of a
    /// hand-built error. The test must prove that casbin carries the
    /// `oxkv::StoreError` through `AdapterError` without change. The impl
    /// `From<casbin::Error> for PolicyError` depends on downcasting that
    /// box. It would degrade to an opaque 500 as soon as casbin flattened
    /// the error to a string.
    #[derive(Clone)]
    struct FencedStore(BTreeStore);

    #[async_trait::async_trait]
    impl oxkv::GetSet for FencedStore {
        async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, oxkv::StoreError> {
            oxkv::GetSet::get_bytes(&self.0, key).await
        }
        async fn has(&self, key: &str) -> Result<bool, oxkv::StoreError> {
            oxkv::GetSet::has(&self.0, key).await
        }
        async fn delete(&self, key: &str) -> Result<bool, oxkv::StoreError> {
            self.0.delete(key).await
        }
        async fn set_bytes(
            &self,
            key: &str,
            value: &[u8],
        ) -> Result<Option<Vec<u8>>, oxkv::StoreError> {
            self.0.set_bytes(key, value).await
        }
        async fn put_bytes(&self, key: &str, value: &[u8]) -> Result<(), oxkv::StoreError> {
            oxkv::GetSet::put_bytes(&self.0, key, value).await
        }
        async fn gets_bytes(
            &self,
            limit: Option<usize>,
            direction: oxkv::Direction,
            cursor: (Option<String>, Option<String>),
        ) -> Result<Vec<oxkv::KeyValue>, oxkv::StoreError> {
            oxkv::GetSet::gets_bytes(&self.0, limit, direction, cursor).await
        }
    }

    impl oxkv::Hooks for FencedStore {
        fn add_validator<V>(&self, validator: V)
        where
            V: oxkv::Validator + 'static,
        {
            self.0.add_validator(validator);
        }

        fn add_observer<O>(&self, observer: O)
        where
            O: oxkv::Observer + 'static,
        {
            self.0.add_observer(observer);
        }

        fn watch_scope(
            &self,
            scope: oxkv::Scope,
        ) -> futures_channel::mpsc::Receiver<oxkv::ChangeEvent> {
            self.0.watch_scope(scope)
        }

        fn current_seq(&self) -> u64 {
            self.0.current_seq()
        }

        fn events_since(&self, seq: u64) -> Option<Vec<oxkv::ChangeEvent>> {
            self.0.events_since(seq)
        }
    }

    #[async_trait::async_trait]
    impl oxkv::Store for FencedStore {
        type Transaction = FencedTx;
        fn begin_tx(&self) -> Result<Self::Transaction, oxkv::StoreError> {
            Ok(FencedTx)
        }
    }

    struct FencedTx;

    #[async_trait::async_trait]
    impl oxkv::GetSet for FencedTx {
        async fn get_bytes(&self, _key: &str) -> Result<Option<Vec<u8>>, oxkv::StoreError> {
            Ok(None)
        }
        async fn has(&self, _key: &str) -> Result<bool, oxkv::StoreError> {
            Ok(false)
        }
        async fn delete(&self, _key: &str) -> Result<bool, oxkv::StoreError> {
            Ok(false)
        }
        async fn set_bytes(
            &self,
            _key: &str,
            _value: &[u8],
        ) -> Result<Option<Vec<u8>>, oxkv::StoreError> {
            Ok(None)
        }
        async fn gets_bytes(
            &self,
            _limit: Option<usize>,
            _direction: oxkv::Direction,
            _cursor: (Option<String>, Option<String>),
        ) -> Result<Vec<oxkv::KeyValue>, oxkv::StoreError> {
            Ok(Vec::new())
        }
    }

    #[async_trait::async_trait]
    impl oxkv::Transaction for FencedTx {
        async fn commit(self) -> Result<(), oxkv::StoreError> {
            Err(oxkv::StoreError::Fenced("epoch 7 superseded".into()))
        }
        async fn rollback(self) -> Result<(), oxkv::StoreError> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl oxkv::TxCas for FencedTx {
        async fn set_if_absent(&self, _key: &str, _value: &[u8]) -> Result<(), oxkv::StoreError> {
            Ok(())
        }
        async fn compare_and_set(
            &self,
            _key: &str,
            _expected: Option<&[u8]>,
            _new: &[u8],
        ) -> Result<(), oxkv::StoreError> {
            Ok(())
        }
        async fn delete_if(&self, _key: &str, _expected: &[u8]) -> Result<(), oxkv::StoreError> {
            Ok(())
        }
    }

    /// A policy write that loses the epoch must be recognisable as such. It
    /// must also latch this instance out of the rotation.
    ///
    /// Before this change, every policy failure reached the client as a 500
    /// with the fencing reason inside the adapter wrapper of casbin. A
    /// process that had stopped being the writer then looked the same as a
    /// process with a flaky store. The condition, the prefix, and the log
    /// query are the same as for `FsError::Fenced`. The classification
    /// downcasts the box that casbin returns. The test notices as soon as
    /// casbin stops preserving that box.
    ///
    /// The second half of the test asserts against a PRIVATE latch, and not
    /// against `fencing::primary_loss()`. The global is a one-way
    /// `AtomicBool` with no reset. The test
    /// `fencing::tests::the_process_wide_signal_is_readable` trips it
    /// unconditionally. Cargo runs the tests in parallel threads in one
    /// binary. The call to `note_primary_loss` could therefore be deleted
    /// from the casbin `From` impl entirely. This assertion would still pass
    /// whenever the fencing test won the race. A test that cannot fail is
    /// worse than a missing test, because it reads as coverage.
    ///
    /// The code calls `Box::leak` because the field has the type
    /// `&'static`. That matches the way a production engine holds the
    /// process-wide latch.
    #[tokio::test]
    async fn a_fenced_policy_write_is_typed_as_a_fencing_loss() {
        let latch: &'static Latch = Box::leak(Box::new(Latch::new()));
        assert!(
            !latch.is_tripped(),
            "a fresh latch starts untripped, or this asserts nothing"
        );

        let engine =
            crate::policy::PolicyEngine::init_with_store(FencedStore(BTreeStore::default()))
                .await
                .expect("engine loads from a readable store")
                .with_latch(latch);

        let err = engine
            .add_rule(
                "alice".into(),
                "invoice:1".into(),
                crate::policy::Action::Write,
            )
            .await
            .expect_err("a fenced commit cannot succeed");

        assert!(
            err.is_fencing_loss(),
            "expected a fencing loss, got {err:?} ({err})"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("epoch lost to another writer"),
            "{rendered}"
        );
        assert!(rendered.contains("epoch 7 superseded"), "{rendered}");

        // The code also takes this instance out of the rotation.
        // That is the part that makes the classification worth having.
        // The route `/ready` reports on the latch. Before the latch
        // existed, a fenced policy write was a 500 on a server that still
        // claimed to be healthy.
        assert!(
            latch.is_tripped(),
            "a fenced policy write must latch the fencing signal, or /ready \
             keeps reporting 200 while every master policy write fails"
        );
    }

    #[tokio::test]
    async fn persists_rules_across_reopen() {
        use std::sync::Arc;

        // The backend is an in-memory LSM store that is shared. Reopening
        // rebuilds from it through WAL replay, in the same way as a second
        // `OxKvStore` session on real S3.
        let backend = Arc::new(oxkv::MemStorage::new());
        let open = |backend: Arc<oxkv::MemStorage>| async move {
            oxkv::OxKvStore::builder()
                .with_store(backend)
                .with_prefix(oxkv::ObjectPath::from("adapter-test"))
                .skip_probe(true)
                .build()
                .await
                .unwrap()
        };
        let model = DefaultModel::from_str(RBAC_MODEL).await.unwrap();

        {
            let adapter = OxkvAdapter::new(
                open(backend.clone())
                    .await
                    .with_validator(PolicyRuleValidator),
            );
            let mut enforcer = Enforcer::new(model, adapter).await.unwrap();
            enforcer
                .add_grouping_policy(vec!["user_1".to_string(), "admin".to_string()])
                .await
                .unwrap();
            enforcer
                .add_policy(vec![
                    "admin".to_string(),
                    "data_1".to_string(),
                    "read".to_string(),
                ])
                .await
                .unwrap();
            assert!(enforcer.enforce(("user_1", "data_1", "read")).unwrap());
        }

        {
            let model = DefaultModel::from_str(RBAC_MODEL).await.unwrap();
            let adapter = OxkvAdapter::new(
                open(backend.clone())
                    .await
                    .with_validator(PolicyRuleValidator),
            );
            let enforcer = Enforcer::new(model, adapter).await.unwrap();
            assert!(enforcer.enforce(("user_1", "data_1", "read")).unwrap());
            assert!(!enforcer.enforce(("user_1", "data_1", "write")).unwrap());
        }
    }

    #[tokio::test]
    async fn add_duplicate_returns_false() {
        let mut adapter = OxkvAdapter::new(BTreeStore::default());
        assert!(
            adapter
                .add_policy("p", "p", vec!["u".into(), "o".into(), "read".into()])
                .await
                .unwrap()
        );
        assert!(
            !adapter
                .add_policy("p", "p", vec!["u".into(), "o".into(), "read".into()])
                .await
                .unwrap()
        );
    }

    /// A failed encode must leave every stored rule in place.
    ///
    /// The old `save_policy` cleared the store in one transaction and wrote
    /// the new rules in a second transaction. A crash between them lost the
    /// whole policy. The encode also ran after the clear, so one malformed
    /// rule erased the store.
    ///
    /// The function now reads the old rules, encodes every new rule, and then
    /// removes and writes in one transaction. This test fails at the encode
    /// step and checks that the store did not change.
    #[tokio::test]
    async fn a_failed_save_leaves_the_store_unchanged() {
        let mut adapter = OxkvAdapter::new(BTreeStore::default());
        adapter
            .add_policy("p", "p", vec!["alice".into(), "doc".into(), "read".into()])
            .await
            .unwrap();

        // The model holds one valid rule and one rule with the wrong field
        // count. `PolicyRuleValidator` rejects the second rule.
        let mut model = DefaultModel::from_str(RBAC_MODEL).await.unwrap();
        assert!(model.add_policy(
            "p",
            "p",
            vec!["alice".to_string(), "doc".to_string(), "read".to_string()],
        ));
        assert!(model.add_policy("p", "p", vec!["only-two".to_string(), "fields".to_string()]));

        assert!(
            adapter.save_policy(&mut model).await.is_err(),
            "a malformed rule must fail the save"
        );

        let remaining = adapter.load_all().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].2, vec!["alice", "doc", "read"]);
    }

    /// A successful save replaces the whole policy in one transaction.
    #[tokio::test]
    async fn a_successful_save_replaces_every_rule() {
        let mut adapter = OxkvAdapter::new(BTreeStore::default());
        adapter
            .add_policy("p", "p", vec!["alice".into(), "doc".into(), "read".into()])
            .await
            .unwrap();
        adapter
            .add_policy("p", "p", vec!["bob".into(), "doc".into(), "write".into()])
            .await
            .unwrap();

        // The model drops alice and adds carol.
        let mut model = DefaultModel::from_str(RBAC_MODEL).await.unwrap();
        assert!(model.add_policy(
            "p",
            "p",
            vec!["bob".to_string(), "doc".to_string(), "write".to_string()],
        ));
        assert!(model.add_policy(
            "p",
            "p",
            vec!["carol".to_string(), "doc".to_string(), "read".to_string()],
        ));
        assert!(model.add_policy("g", "g", vec!["alice".to_string(), "readers".to_string()],));

        adapter.save_policy(&mut model).await.unwrap();

        let mut rules: Vec<Vec<String>> = adapter
            .load_all()
            .await
            .unwrap()
            .into_iter()
            .map(|(_, _, rule)| rule)
            .collect();
        rules.sort();
        assert_eq!(
            rules,
            vec![
                vec!["alice", "readers"],
                vec!["bob", "doc", "write"],
                vec!["carol", "doc", "read"],
            ]
        );
    }

    #[tokio::test]
    async fn remove_filtered_by_subject() {
        let mut adapter = OxkvAdapter::new(BTreeStore::default());
        adapter
            .add_policies(
                "p",
                "p",
                vec![
                    vec!["alice".into(), "doc_a".into(), "read".into()],
                    vec!["alice".into(), "doc_b".into(), "read".into()],
                    vec!["bob".into(), "doc_c".into(), "write".into()],
                ],
            )
            .await
            .unwrap();

        let removed = adapter
            .remove_filtered_policy("p", "p", 0, vec!["alice".into()])
            .await
            .unwrap();
        assert!(removed);

        let remaining = adapter.load_all().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].2[0], "bob");
    }

    #[tokio::test]
    async fn validator_rejects_malformed_writes() {
        use oxkv::Store as _;

        let store = BTreeStore::default().with_validator(PolicyRuleValidator);

        // The store accepts a valid p-rule.
        store
            .set_bytes("p:p:ab01", br#"["alice","doc_a","read"]"#)
            .await
            .unwrap();

        // The store rejects a value that is not JSON.
        let tx = store.begin_tx().unwrap();
        assert!(tx.set_bytes("p:p:cd02", b"not json").await.is_err());

        // The store rejects the wrong field count at the staging (g needs 2 fields).
        let tx = store.begin_tx().unwrap();
        assert!(tx.set_bytes("g:g:ef03", br#"["user"]"#).await.is_err());

        // The store rejects an unknown section at the staging.
        let tx = store.begin_tx().unwrap();
        assert!(tx.set_bytes("x:m:ff04", br#"["a","b"]"#).await.is_err());
    }

    /// The rejection of a bad key shape must name the segment that is
    /// actually missing. The message used to render `{sec}:{SEP}{hash}`.
    /// That format both interpolated the separator constant and dropped
    /// `ptype`. The message then reported a key with two segments as
    /// malformed, and the format in the message looked like the valid one.
    #[tokio::test]
    async fn validator_error_names_the_ptype_segment() {
        use oxkv::Store as _;

        let store = BTreeStore::default().with_validator(PolicyRuleValidator);
        let tx = store.begin_tx().unwrap();
        let err = tx
            .set_bytes("p:only-two", br#"["alice","doc","read"]"#)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("{sec}:ptype:{hash}"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn adapter_validates_writes_on_oxkv_store() {
        // The adapter enforces PolicyRuleValidator itself (see encode_rule),
        // so validation holds on the LSM backend without a HookStore wrap.
        let s3 = crate::db::build_test_store(&crate::db::test_prefix("adapter-validate")).await;
        let mut adapter = OxkvAdapter::new(s3);

        // The store rejects the wrong field count without a change.
        assert!(
            adapter
                .add_policy("p", "p", vec!["only-one-field".into()])
                .await
                .is_err()
        );
        assert!(adapter.load_all().await.unwrap().is_empty());

        // The store still accepts a valid rule.
        assert!(
            adapter
                .add_policy("p", "p", vec!["u".into(), "o".into(), "read".into()])
                .await
                .unwrap()
        );
    }
}
