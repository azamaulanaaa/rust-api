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

use async_trait::async_trait;
use casbin::{
    Adapter, Filter, Model,
    error::{AdapterError, Error as CasbinError},
};
use oxkv::{Direction, GetSet, Store, StoreView, Transaction as _, Validator};

/// Key prefix separator. The keys have the form `{sec}:{ptype}:{rule-hash}`.
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

/// Encodes one rule as a validated `(key, value)` pair.
///
/// The adapter enforces [`PolicyRuleValidator`] directly on every write path.
/// Callers therefore do not have to wrap their store in an
/// [`oxkv::HookStore`]. The validation runs before any transaction
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
pub struct PolicyRuleValidator;

impl PolicyRuleValidator {
    /// It returns the expected field count of a rule in a section of the RBAC
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
            let (Some(sec), Some(ptype), Some(_)) = (parts.next(), parts.next(), parts.next())
            else {
                // A foreign or corrupt entry is skipped. It does not
                // poison the startup.
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
        let tx = self.store.begin_tx()?;
        for key in &keys {
            tx.delete(key).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// It returns `true` when `rule[field_index + i] == field_values[i]` for
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

        // The code validates and encodes every entry before it opens
        // the transaction. A malformed rule then fails without touching the
        // store.
        let mut encoded = Vec::with_capacity(entries.len());
        for (sec, ptype, rule) in &entries {
            encoded.push(encode_rule(&self.store, sec, ptype, rule).await?);
        }

        let tx = self.store.begin_tx().map_err(store_err)?;
        for (key, value) in &encoded {
            tx.set_bytes(key, value).await.map_err(store_err)?;
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
        // The code validates and encodes every rule before it opens
        // the transaction. A malformed rule then fails without staging
        // partial state. The duplicate handling below stays the same.
        let mut encoded = Vec::with_capacity(rules.len());
        for rule in &rules {
            encoded.push(encode_rule(&self.store, sec, ptype, rule).await?);
        }

        let tx = self.store.begin_tx().map_err(store_err)?;
        for (key, value) in &encoded {
            if tx.has(key).await.map_err(store_err)? {
                tx.rollback().await.map_err(store_err)?;
                return Ok(false);
            }
            tx.set_bytes(key, value).await.map_err(store_err)?;
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
        let keys: Vec<String> = rules.iter().map(|r| rule_key(sec, ptype, r)).collect();

        let tx = self.store.begin_tx().map_err(store_err)?;
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

        let tx = self.store.begin_tx().map_err(store_err)?;
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
    use crate::fencing::Latch;
    use crate::policy::RBAC_MODEL;
    use casbin::{CoreApi, DefaultModel, Enforcer, MgmtApi};
    use oxkv::BTreeStore;

    /// A store whose commits report a lost epoch.
    ///
    /// The reads come from a real `BTreeStore`, so the engine loads
    /// normally. Only the durability step fails. That is exactly when `oxkv`
    /// fences a writer. The test uses a real backend here instead of a
    /// hand-built error, because the test has to prove that casbin carries
    /// the `oxkv::StoreError` through `AdapterError` without change. The
    /// impl `From<casbin::Error> for PolicyError` depends on downcasting
    /// that box. It would degrade to an opaque 500 as soon as casbin
    /// flattened the error to a string.
    struct FencedStore(BTreeStore);

    #[async_trait::async_trait]
    impl oxkv::GetSet for FencedStore {
        async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, oxkv::StoreError> {
            self.0.get_bytes(key).await
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
        async fn gets_bytes(
            &self,
            limit: Option<u32>,
            direction: oxkv::Direction,
            cursor: (Option<String>, Option<String>),
        ) -> Result<Vec<oxkv::KeyValue>, oxkv::StoreError> {
            self.0.gets_bytes(limit, direction, cursor).await
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
            _limit: Option<u32>,
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

    /// A policy write that loses the epoch must be recognisable as such. It
    /// must also latch this instance out of the rotation.
    ///
    /// Before this change, every policy failure reached the client as a 500
    /// with the fencing reason inside the adapter wrapper of casbin. A
    /// process that had stopped being the writer then looked the same as a
    /// process with a flaky store. The condition, the prefix, and the log
    /// query are the same as for `FsError::Fenced`. The classification
    /// downcasts the box that casbin returns, so this test notices as soon as
    /// casbin stops preserving that box.
    ///
    /// The second half of the test asserts against a PRIVATE latch, and not
    /// against `fencing::primary_loss()`. The global is a one-way
    /// `AtomicBool` with no reset. The test
    /// `fencing::tests::the_process_wide_signal_is_readable` trips it
    /// unconditionally. Cargo runs the tests in parallel threads in one
    /// binary. The call to `note_primary_loss` could therefore be deleted
    /// from the casbin `From` impl entirely, and this assertion would still
    /// pass whenever the fencing test won the race. A test that cannot fail
    /// is worse than a missing test, because it reads as coverage.
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
                oxkv::HookStore::new(open(backend.clone()).await)
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
                oxkv::HookStore::new(open(backend.clone()).await)
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

        let store = oxkv::HookStore::new(BTreeStore::default()).with_validator(PolicyRuleValidator);

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

        let store = oxkv::HookStore::new(BTreeStore::default()).with_validator(PolicyRuleValidator);
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
