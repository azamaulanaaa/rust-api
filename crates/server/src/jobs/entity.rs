//! The `entity.create` job handler.
//!
//! The handler writes one entity through the EAV store and reports the new
//! change-feed head as a [`CommitReceipt`].

use std::collections::BTreeSet;

use async_trait::async_trait;
use rust_api_model::wire::CommitReceipt;

use crate::eav::entity::{Entity, EntityDraft, EntityStore, WriteContext};
use crate::eav::entity_error::EntityError;
use crate::fs::error::FsError;
use crate::policy::{Action, Authorizer, PolicyError};
use crate::queue::{Job, JobError, JobHandler};
use crate::sync::wal::Wal;

/// The job kind that this handler processes.
const JOB_KIND: &str = "entity.create";

/// Creates one entity from a queued `entity.create` job.
#[derive(Clone)]
pub struct EntityCreateHandler {
    entities: EntityStore,
    wal: Wal,
    policy: Authorizer,
}

impl EntityCreateHandler {
    /// Builds a handler from the entity store, the change feed, and the
    /// authorizer.
    ///
    /// The store and the feed must share the same prefix. The handler reads
    /// the feed head before and after the write. It requires the
    /// `eav_entities` write grant for the job owner.
    pub fn new(entities: EntityStore, wal: Wal, policy: Authorizer) -> Self {
        Self {
            entities,
            wal,
            policy,
        }
    }

    /// Returns the result for a repeated create of the same draft.
    ///
    /// The function reads the stored entity. A version 1 entity with the same
    /// content returns `None`, because the first attempt committed. A
    /// different entity is a permanent failure. A read failure is retryable.
    async fn existing_entity(&self, draft: &EntityDraft) -> Result<Option<Vec<u8>>, JobError> {
        let entity = self
            .entities
            .get(&draft.id)
            .await
            .map_err(|error| JobError::retryable(error.to_string()))?;
        match entity {
            Some(entity) if matches_draft(&entity, draft) => Ok(None),
            Some(_) => Err(JobError::permanent(
                "the entity exists with different content",
            )),
            None => Err(JobError::permanent(
                "the entity is missing after a duplicate create",
            )),
        }
    }
}

#[async_trait]
impl JobHandler for EntityCreateHandler {
    fn kind(&self) -> &'static str {
        JOB_KIND
    }

    /// Creates one entity with the job owner as the actor.
    ///
    /// The call decodes the draft from the job payload and requires the
    /// `eav_entities` write grant for the owner. It reads the change feed head
    /// before the write, creates the entity, and reads the head again. A new
    /// head returns a [`CommitReceipt`] as JSON bytes. An unchanged head, or
    /// a failed after-head read, returns `None` so the client falls back to
    /// polling. A repeated create of the same draft also returns `None`.
    async fn handle(&self, job: &Job) -> Result<Option<Vec<u8>>, JobError> {
        let draft: EntityDraft = serde_json::from_slice(&job.payload).map_err(|error| {
            JobError::permanent(format!("the entity draft is not valid: {error}"))
        })?;
        let owner = job
            .owner_sub
            .as_deref()
            .ok_or_else(|| JobError::permanent("the job has no owner"))?;
        self.policy
            .require(owner, crate::eav::route::ENTITIES, Action::Write)
            .await
            .map_err(policy_error)?;
        let ctx = WriteContext::new(owner);

        let before = self
            .wal
            .head()
            .await
            .map_err(|error| JobError::retryable(error.to_string()))?;
        match self.entities.create(draft.clone(), &ctx).await {
            Ok(_) => {}
            Err(EntityError::AlreadyExists(_)) => return self.existing_entity(&draft).await,
            Err(error) => return Err(entity_error(error)),
        }
        after_head(before, self.wal.head().await)
    }
}

/// Builds the handler result from the head after the create.
///
/// A read failure means the create committed but the new head is unknown. The
/// function logs the failure and returns `None`, so the client falls back to
/// polling.
fn after_head(before: u64, after: Result<u64, FsError>) -> Result<Option<Vec<u8>>, JobError> {
    let after = match after {
        Ok(after) => after,
        Err(error) => {
            tracing::warn!(%error, "the head read failed after the create");
            return Ok(None);
        }
    };
    if after > before {
        let receipt = CommitReceipt { commit_seq: after };
        let bytes = serde_json::to_vec(&receipt).map_err(|error| {
            JobError::permanent(format!("the receipt does not encode: {error}"))
        })?;
        return Ok(Some(bytes));
    }
    Ok(None)
}

/// Reports whether a stored entity matches the draft that created it.
///
/// The store may assign schema versions, so the function compares schema ids
/// only. The attribute maps must match exactly.
fn matches_draft(entity: &Entity, draft: &EntityDraft) -> bool {
    if entity.version != 1 || entity.attributes != draft.attributes {
        return false;
    }
    let stored: BTreeSet<&str> = entity
        .schemas
        .iter()
        .map(|schema| schema.id.as_str())
        .collect();
    let wanted: BTreeSet<&str> = draft.schemas.iter().map(String::as_str).collect();
    stored == wanted
}

/// Maps a policy failure to a job error.
///
/// A denied write is permanent. Any other policy failure is retryable.
fn policy_error(error: PolicyError) -> JobError {
    match error {
        PolicyError::AccessDenied => JobError::permanent("not allowed to create entities"),
        other => JobError::retryable(other.to_string()),
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
    use crate::policy::PolicyEngine;
    use crate::queue::JobRetry;

    /// Builds a handler, a store, and one `task` schema.
    ///
    /// The store uses the handler feed only when `with_feed` is true. The
    /// owner `alice` gets the entity write grant only when `granted` is true.
    async fn fixture(
        with_feed: bool,
        granted: bool,
    ) -> anyhow::Result<(EntityCreateHandler, EntityStore)> {
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
        let engine =
            PolicyEngine::init_s3(build_test_store(&test_prefix("jobs-entity-policy")).await)
                .await?;
        if granted {
            engine
                .add_rule(
                    "alice".into(),
                    crate::eav::route::ENTITIES.into(),
                    Action::Write,
                )
                .await?;
        }
        let handler = EntityCreateHandler::new(store.clone(), wal, engine.authorizer());
        Ok((handler, store))
    }

    /// Builds one `task` draft with the given title.
    fn draft_with(title: &str) -> EntityDraft {
        EntityDraft {
            id: "e1".to_string(),
            schemas: vec!["task".to_string()],
            attributes: BTreeMap::from([(
                "title".to_string(),
                AttributeValue::String(title.to_string()),
            )]),
        }
    }

    /// Builds the default `task` draft.
    fn draft() -> EntityDraft {
        draft_with("hello")
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
        let (handler, store) = fixture(true, true).await?;

        let result = handler.handle(&job(&draft(), Some("alice"))).await?;
        let bytes = result.expect("the feed head advances");
        let receipt: CommitReceipt = serde_json::from_slice(&bytes)?;
        assert!(receipt.commit_seq > 0);

        let entity = store.get("e1").await?.expect("the entity exists");
        assert_eq!(entity.version, 1);
        Ok(())
    }

    /// An owner without the write grant cannot create an entity.
    #[tokio::test]
    async fn an_owner_without_the_grant_cannot_create() -> anyhow::Result<()> {
        let (handler, store) = fixture(false, false).await?;

        let error = handler
            .handle(&job(&draft(), Some("alice")))
            .await
            .expect_err("the write grant is required");
        assert!(matches!(error.retry(), JobRetry::NoRetry));
        assert!(store.get("e1").await?.is_none());
        Ok(())
    }

    /// A payload that is not a draft is a permanent failure.
    #[tokio::test]
    async fn a_payload_that_is_not_a_draft_is_a_permanent_error() -> anyhow::Result<()> {
        let (handler, _) = fixture(false, false).await?;
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
        let (handler, _) = fixture(false, false).await?;

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
        let (handler, store) = fixture(false, true).await?;

        let result = handler.handle(&job(&draft(), Some("alice"))).await?;
        assert!(result.is_none());
        assert!(store.get("e1").await?.is_some());
        Ok(())
    }

    /// A failed after-head read returns no receipt.
    #[test]
    fn an_after_head_error_returns_no_receipt() {
        let after = Err(FsError::Internal("injected head failure".to_string()));
        let result = after_head(0, after).expect("the failure is not a job error");
        assert!(result.is_none());
    }

    /// A repeated create of the same draft returns no receipt.
    #[tokio::test]
    async fn a_repeated_create_returns_ok_none() -> anyhow::Result<()> {
        let (handler, _) = fixture(true, true).await?;
        let draft = draft();

        let first = handler.handle(&job(&draft, Some("alice"))).await?;
        assert!(first.is_some());

        let second = handler.handle(&job(&draft, Some("alice"))).await?;
        assert!(second.is_none());
        Ok(())
    }

    /// A repeated create with a different draft is a permanent failure.
    #[tokio::test]
    async fn a_repeated_create_with_a_different_draft_is_permanent() -> anyhow::Result<()> {
        let (handler, _) = fixture(true, true).await?;

        let first = handler
            .handle(&job(&draft_with("hello"), Some("alice")))
            .await?;
        assert!(first.is_some());

        let error = handler
            .handle(&job(&draft_with("other"), Some("alice")))
            .await
            .expect_err("the different draft must fail");
        assert!(matches!(error.retry(), JobRetry::NoRetry));
        Ok(())
    }
}
