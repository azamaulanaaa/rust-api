//! The `entity.create` job handler.
//!
//! The handler writes one entity through the EAV store and reports the new
//! change-feed head as a [`CommitReceipt`].

use async_trait::async_trait;
use rust_api_model::wire::CommitReceipt;

use crate::eav::entity::{EntityDraft, EntityStore, WriteContext};
use crate::eav::entity_error::EntityError;
use crate::queue::{Job, JobError, JobHandler};
use crate::sync::wal::Wal;

/// The job kind that this handler processes.
const JOB_KIND: &str = "entity.create";

/// Creates one entity from a queued `entity.create` job.
#[derive(Clone)]
pub struct EntityCreateHandler {
    entities: EntityStore,
    wal: Wal,
}

impl EntityCreateHandler {
    /// Builds a handler from the entity store and the change feed.
    ///
    /// The store and the feed must share the same prefix. The handler reads
    /// the feed head before and after the write.
    pub fn new(entities: EntityStore, wal: Wal) -> Self {
        Self { entities, wal }
    }
}

#[async_trait]
impl JobHandler for EntityCreateHandler {
    fn kind(&self) -> &'static str {
        JOB_KIND
    }

    /// Creates one entity with the job owner as the actor.
    ///
    /// The call decodes the draft from the job payload. It reads the change
    /// feed head before the write, creates the entity, and reads the head
    /// again. A new head returns a [`CommitReceipt`] as JSON bytes. An
    /// unchanged head returns `None`, so the client falls back to polling.
    async fn handle(&self, job: &Job) -> Result<Option<Vec<u8>>, JobError> {
        let draft: EntityDraft = serde_json::from_slice(&job.payload).map_err(|error| {
            JobError::permanent(format!("the entity draft is not valid: {error}"))
        })?;
        let owner = job
            .owner_sub
            .as_deref()
            .ok_or_else(|| JobError::permanent("the job has no owner"))?;
        let ctx = WriteContext::new(owner);

        let before = self
            .wal
            .head()
            .await
            .map_err(|error| JobError::retryable(error.to_string()))?;
        self.entities
            .create(draft, &ctx)
            .await
            .map_err(entity_error)?;
        let after = self
            .wal
            .head()
            .await
            .map_err(|error| JobError::retryable(error.to_string()))?;

        if after > before {
            let receipt = CommitReceipt { commit_seq: after };
            let bytes = serde_json::to_vec(&receipt).map_err(|error| {
                JobError::permanent(format!("the receipt does not encode: {error}"))
            })?;
            return Ok(Some(bytes));
        }
        Ok(None)
    }
}

/// Maps an entity store failure to a job error.
///
/// A store failure is retryable. The listed validation failures are
/// permanent, because a retry cannot make the same draft valid. Every other
/// failure is also permanent.
fn entity_error(error: EntityError) -> JobError {
    match error {
        EntityError::Store(_) => JobError::retryable("the entity store failed"),
        EntityError::Invalid(message)
        | EntityError::AlreadyExists(message)
        | EntityError::SchemaConflict(message) => JobError::permanent(message),
        EntityError::VersionConflict => JobError::permanent("entity version conflict"),
        other => JobError::permanent(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use uuid::Uuid;

    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::AttributeValue;
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft, SchemaRegistry};
    use crate::queue::JobRetry;

    /// Builds a handler, a store, and one `task` schema.
    ///
    /// The store uses the handler feed only when `with_feed` is true.
    async fn fixture(with_feed: bool) -> anyhow::Result<(EntityCreateHandler, EntityStore)> {
        let wal = Wal::new(build_test_store(&test_prefix("jobs-entity-wal")).await);
        let registry =
            SchemaRegistry::new(build_test_store(&test_prefix("jobs-entity-schema")).await);
        let mut store = EntityStore::new(
            build_test_store(&test_prefix("jobs-entity-store")).await,
            registry.clone(),
        );
        if with_feed {
            store = store.with_change_sink(Arc::new(wal.clone()));
        }
        registry
            .publish(SchemaDraft {
                id: "task".to_string(),
                extends: Vec::new(),
                attributes: BTreeMap::from([(
                    "title".to_string(),
                    AttributeDef {
                        name: "title".to_string(),
                        ty: AttributeType::String,
                        required: false,
                        indexed: false,
                        unique: false,
                        default: None,
                    },
                )]),
            })
            .await?;
        let handler = EntityCreateHandler::new(store.clone(), wal);
        Ok((handler, store))
    }

    /// Builds one `task` draft.
    fn draft() -> EntityDraft {
        EntityDraft {
            id: "e1".to_string(),
            schemas: vec!["task".to_string()],
            attributes: BTreeMap::from([(
                "title".to_string(),
                AttributeValue::String("hello".to_string()),
            )]),
        }
    }

    /// Builds one `entity.create` job.
    fn job(draft: &EntityDraft, owner: Option<&str>) -> Job {
        Job {
            id: Uuid::now_v7(),
            kind: JOB_KIND.to_string(),
            payload: serde_json::to_vec(draft).expect("the draft serializes"),
            priority: 0,
            attempt: 0,
            max_attempts: 5,
            created_at: 0,
            scheduled_at: 0,
            idempotency_key: None,
            owner_sub: owner.map(str::to_string),
            headers: BTreeMap::new(),
        }
    }

    /// The handler creates the entity and returns a receipt.
    #[tokio::test]
    async fn the_handler_creates_the_entity_and_returns_the_receipt() -> anyhow::Result<()> {
        let (handler, store) = fixture(true).await?;

        let result = handler.handle(&job(&draft(), Some("alice"))).await?;
        let bytes = result.expect("the feed head advances");
        let receipt: CommitReceipt = serde_json::from_slice(&bytes)?;
        assert!(receipt.commit_seq > 0);

        let entity = store.get("e1").await?.expect("the entity exists");
        assert_eq!(entity.version, 1);
        Ok(())
    }

    /// A payload that is not a draft is a permanent failure.
    #[tokio::test]
    async fn a_payload_that_is_not_a_draft_is_a_permanent_error() -> anyhow::Result<()> {
        let (handler, _) = fixture(false).await?;
        let mut job = job(&draft(), Some("alice"));
        job.payload = b"not json".to_vec();

        let error = handler
            .handle(&job)
            .await
            .expect_err("the payload must fail");
        assert!(matches!(error.retry(), JobRetry::NoRetry));
        Ok(())
    }

    /// A job without an owner is a permanent failure.
    #[tokio::test]
    async fn a_job_without_an_owner_is_a_permanent_error() -> anyhow::Result<()> {
        let (handler, _) = fixture(false).await?;

        let error = handler
            .handle(&job(&draft(), None))
            .await
            .expect_err("the owner is required");
        assert!(matches!(error.retry(), JobRetry::NoRetry));
        Ok(())
    }

    /// A create without a feed head returns no receipt.
    #[tokio::test]
    async fn a_create_without_a_feed_head_returns_no_receipt() -> anyhow::Result<()> {
        let (handler, store) = fixture(false).await?;

        let result = handler.handle(&job(&draft(), Some("alice"))).await?;
        assert!(result.is_none());
        assert!(store.get("e1").await?.is_some());
        Ok(())
    }
}
