//! The EAV background runtime.
//!
//! [`EavRuntime`] builds the schema, entity, and rule stores.
//! It then starts two loops.
//! One loop relays the entity outbox to the change feed.
//! The other loop runs the matching rules.
//!
//! A host application builds the runtime with [`EavRuntime::build`].
//! The call takes the actions that the rule engine dispatches.
//! The binary passes an empty action list.
//!
//! The runtime has no HTTP routes and no concrete actions.
//! It adds no business rules.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::task::JoinHandle;

use crate::CancelToken;
use crate::db::build_s3_store;
use crate::eav::entity::EntityStore;
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
}

impl Default for EavRuntimeConfig {
    /// Returns the default settings.
    ///
    /// The outbox relay runs every second.
    /// The rule runner polls every 200 milliseconds.
    fn default() -> Self {
        Self {
            outbox_interval: Duration::from_secs(1),
            rule_poll_interval: Duration::from_millis(200),
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
    /// The rule runner.
    engine: RuleEngine,
    /// The shared change feed.
    wal: Wal,
}

impl EavRuntime {
    /// Builds the EAV stores under `db_prefix`.
    ///
    /// The call creates one store for each EAV domain.
    /// The schema store lives at `{db_prefix}/eav/schema`.
    /// The entity store lives at `{db_prefix}/eav/entity`.
    /// The rule store lives at `{db_prefix}/eav/rules`.
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

        let schemas = SchemaRegistry::new(schema_store);
        let entities =
            EntityStore::new(entity_store, schemas.clone()).with_change_sink(Arc::new(wal.clone()));
        let rules = RuleStore::new(rule_store);
        let engine = RuleEngine::new(rules.clone(), entities.clone(), actions)
            .context("build the EAV rule engine")?;

        Ok(Self {
            schemas,
            entities,
            rules,
            engine,
            wal,
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

    /// Returns the rule engine.
    pub fn engine(&self) -> &RuleEngine {
        &self.engine
    }

    /// Returns the shared change feed.
    pub fn wal(&self) -> &Wal {
        &self.wal
    }

    /// Runs the outbox relay and the rule runner until `cancel` fires.
    ///
    /// The call runs both loops at the same time.
    /// The first failure stops the runtime and returns the error.
    /// The outbox relay flushes the pending entity events.
    /// The rule runner tails the shared change feed.
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
        tokio::select! {
            result = relay => result,
            result = runner => result,
        }
    }

    /// Starts [`EavRuntime::run`] on a Tokio task.
    ///
    /// The call logs a runtime error and returns it.
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
            self.entities
                .flush_outbox()
                .await
                .context("flush the EAV entity outbox")?;
        }
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
    use crate::records::EntityEventKind;
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
        }
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
}
