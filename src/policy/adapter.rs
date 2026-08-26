//! Casbin storage adapter backed by an [`oxkv`] key-value store.
//!
//! Every policy rule is stored as one key-value pair: a deterministic key
//! encoding section, policy type, and a content hash of the rule, with the
//! rule vector JSON-serialized as value. Deterministic keys make duplicate
//! detection a single `has` lookup and keep repeated adds idempotent.
//!
//! All mutating adapter operations run inside an [`oxkv`] transaction, so
//! batch operations commit atomically.

use async_trait::async_trait;
use casbin::{
    Adapter,
    Filter,
    Model,
    error::{AdapterError, Error as CasbinError},
};
use oxkv::{Direction, GetSet, Store, StoreView, Transaction as _, Validator};

/// Key prefix separator; keys are `{sec}:{ptype}:{rule-hash}`.
const SEP: char = ':';

/// Hex-encodes a string so it is safe to embed in a store key.
fn hex_encode(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic storage key for a single policy rule.
fn rule_key(sec: &str, ptype: &str, rule: &[String]) -> String {
    let joined = rule.join("\u{1f}");
    format!("{sec}{SEP}{ptype}{SEP}{}", hex_encode(&joined))
}

/// Maps an [`oxkv::StoreError`] into casbin's adapter error type.
fn store_err(e: oxkv::StoreError) -> CasbinError {
    CasbinError::AdapterError(AdapterError(Box::new(e)))
}

/// Validates every write into the policy store before it becomes durable.
///
/// Enforces the adapter's storage contract at the storage layer so a bug in
/// the adapter itself (or any future tooling touching the same file) is
/// rejected at write time instead of poisoning [`OxkvAdapter`]'s startup
/// load:
///
/// - keys must be `{sec}:{ptype}:{hex-hash}` with a known section (`p`/`g`)
/// - values must decode as a JSON string array
/// - rules must match the RBAC model's field count (3 for `p`, 2 for `g`)
pub struct PolicyRuleValidator;

impl PolicyRuleValidator {
    /// Expected rule field count for a section of the RBAC model defined
    /// in [`PolicyEngine`](super::PolicyEngine). Coupled to that model on
    /// purpose: changing the model requires revisiting this validator.
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
        let mut parts = key.splitn(3, SEP);
        let (Some(sec), Some(ptype), Some(hash)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("policy keys must be '{{sec}}:{SEP}{{hash}}', got '{key}'").into());
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
            return Err(format!(
                "'{sec}' rules need {expected} fields, got {}",
                rule.len()
            )
            .into());
        }
        Ok(())
    }
}

/// A Casbin [`Adapter`] persisting policies to any [`oxkv::Store`].
///
/// Generic over the backend so production can use the persistent
/// [`oxkv::RedbStore`](https://docs.rs/oxkv) while tests use the in-memory
/// B-tree store.
pub struct OxkvAdapter<S: Store> {
    store: S,
}

impl<S: Store> OxkvAdapter<S> {
    /// Wraps an existing store instance.
    pub fn new(store: S) -> Self {
        Self { store }
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
            let (Some(sec), Some(ptype), Some(_)) =
                (parts.next(), parts.next(), parts.next())
            else {
                // Foreign or corrupt entry: skip rather than poison startup.
                continue;
            };
            let rule: Vec<String> = serde_json::from_slice(&kv.value)?;
            out.push((sec.to_string(), ptype.to_string(), rule));
        }
        Ok(out)
    }

    /// Deletes every key in the store inside one transaction.
    async fn clear_all(&mut self) -> Result<(), oxkv::StoreError> {
        let keys: Vec<String> = self
            .store
            .gets_bytes(None, Direction::Next, (None, None))
            .await?
            .into_iter()
            .map(|kv| kv.key)
            .collect();
        let mut tx = self.store.begin_tx()?;
        for key in &keys {
            tx.delete(key).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// True when `rule[field_index + i] == field_values[i]` for all i;
    /// implements casbin's filtered-policy matching semantics.
    fn rule_matches(
        rule: &[String],
        field_index: usize,
        field_values: &[String],
    ) -> bool {
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
                    &field_values.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                ) {
                    continue;
                }
            m.add_policy(&sec, &ptype, rule);
        }
        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> casbin::Result<()> {
        self.clear_all().await.map_err(store_err)?;

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

        let mut tx = self.store.begin_tx().map_err(store_err)?;
        for (sec, ptype, rule) in entries {
            // StoreError: From<serde_json::Error> — convert before crossing
            // into casbin's error domain.
            let value = serde_json::to_vec(&rule).map_err(oxkv::StoreError::from).map_err(store_err)?;
            tx.set_bytes(&rule_key(&sec, &ptype, &rule), &value)
                .await
                .map_err(store_err)?;
        }
        tx.commit().await.map_err(store_err)?;
        Ok(())
    }

    async fn clear_policy(&mut self) -> casbin::Result<()> {
        self.clear_all().await.map_err(store_err)
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
        let keys: Vec<String> =
            rules.iter().map(|r| rule_key(sec, ptype, r)).collect();
        let values: Vec<Vec<u8>> = rules
            .iter()
            .map(|r| serde_json::to_vec(r).map_err(oxkv::StoreError::from))
            .collect::<Result<_, _>>()
            .map_err(store_err)?;

        let mut tx = self.store.begin_tx().map_err(store_err)?;
        for (key, value) in keys.iter().zip(values) {
            if tx.has(key).await.map_err(store_err)? {
                tx.rollback().await.map_err(store_err)?;
                return Ok(false);
            }
            tx.set_bytes(key, &value).await.map_err(store_err)?;
        }
        tx.commit().await.map_err(store_err)?;
        Ok(true)
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
        let keys: Vec<String> =
            rules.iter().map(|r| rule_key(sec, ptype, r)).collect();

        let mut tx = self.store.begin_tx().map_err(store_err)?;
        for key in &keys {
            if tx.has(key).await.map_err(store_err)? {
                tx.delete(key).await.map_err(store_err)?;
            } else {
                tx.rollback().await.map_err(store_err)?;
                return Ok(false);
            }
        }
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
            }
        }

        let mut tx = self.store.begin_tx().map_err(store_err)?;
        for key in &to_delete {
            tx.delete(key).await.map_err(store_err)?;
        }
        tx.commit().await.map_err(store_err)?;
        Ok(!to_delete.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi};
    use oxkv::{BTreeStore, RedbStore};

    const MODEL: &str = r#"
        [request_definition]
        r = sub, obj, act
        [policy_definition]
        p = sub, obj, act
        [role_definition]
        g = _, _
        [policy_effect]
        e = some(where (p.eft == allow))
        [matchers]
        m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
    "#;

    #[tokio::test]
    async fn persists_rules_across_reopen() {
        let path = std::env::temp_dir().join(format!(
            "oxkv-adapter-test-{}",
            std::process::id()
        ));
        let model = DefaultModel::from_str(MODEL).await.unwrap();

        {
            let adapter = OxkvAdapter::new(
                oxkv::HookStore::new(RedbStore::new_file(&path).unwrap())
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
            assert!(
                enforcer
                    .enforce(("user_1", "data_1", "read"))
                    .unwrap()
            );
        }

        {
            let model = DefaultModel::from_str(MODEL).await.unwrap();
            let adapter = OxkvAdapter::new(
                oxkv::HookStore::new(RedbStore::new_file(&path).unwrap())
                    .with_validator(PolicyRuleValidator),
            );
            let enforcer = Enforcer::new(model, adapter).await.unwrap();
            assert!(
                enforcer
                    .enforce(("user_1", "data_1", "read"))
                    .unwrap()
            );
            assert!(
                !enforcer
                    .enforce(("user_1", "data_1", "write"))
                    .unwrap()
            );
        }

        std::fs::remove_file(path).ok();
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

        let mut store =
            oxkv::HookStore::new(BTreeStore::default())
                .with_validator(PolicyRuleValidator);

        // Valid p-rule passes.
        store
            .set_bytes(
                "p:p:ab01",
                br#"["alice","doc_a","read"]"#,
            )
            .await
            .unwrap();

        // Non-JSON value rejected.
        let mut tx = store.begin_tx().unwrap();
        assert!(tx.set_bytes("p:p:cd02", b"not json").await.is_err());

        // Wrong arity for section rejected at staging (g needs 2 fields).
        let mut tx = store.begin_tx().unwrap();
        assert!(tx.set_bytes("g:g:ef03", br#"["user"]"#).await.is_err());


        // Unknown section rejected at staging.
        let mut tx = store.begin_tx().unwrap();
        assert!(tx.set_bytes("x:m:ff04", br#"["a","b"]"#).await.is_err());

    }
}
