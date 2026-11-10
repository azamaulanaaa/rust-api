//! Storage, validation, and indexes for EAV entities.
//!
//! An entity is a data container.
//! It pins one or more schema versions and holds typed attributes.
//! The store validates every attribute against the merged effective schema.
//!
//! # Key layout
//!
//! All keys live in one bounded key family:
//!
//! - `entity:{id}:meta` holds the entity metadata as JSON.
//! - `entity:{id}:attr:{key}` holds one tagged JSON [`AttributeValue`].
//! - `idx:entity:{entity_id}` is an empty entity marker.
//! - `idx:entity-meta:backfilled` is an empty backfill marker.
//! - `idx:schema:{schema_id}:{entity_id}` is an empty schema marker.
//! - `idx:attr:{key}:{hash}:{entity_id}` is an empty attribute marker.
//! - `idx:attr-key:{key}` is an empty marker that records that the attribute
//!   is indexed. The marker is permanent. A stale marker only allows an
//!   empty result.
//! - `idx:unique:{key}:{hash}:{entity_id}` is a unique value marker.
//! - `idx:time:{key}:{encoded_ts}:{entity_id}` is an empty time marker.
//!   A timer retire removes the row when the timer fires. The index then
//!   holds only values that have not fired.
//! - `idx:time-key:{key}` is an empty marker for an attribute key with a
//!   time row.
//! - `idx:time-key-meta:backfilled` is an empty backfill marker.
//! - `timer:fired:{entity_id}:{key}:{encoded_ts}` is a fired timer marker.
//!   The marker stays after the timer retire removes the time row, so one
//!   value fires one time only.
//! - `outbox-meta:pending` holds the pending outbox row count as JSON `u64`.
//!   The key is not in the `outbox:` family, so an outbox scan does not
//!   include it.
//!
//! The `hash` is the lowercase SHA-256 hex of the canonical tagged JSON value.
//! The `encoded_ts` is the timestamp XORed with the sign bit, as 16 hex digits.
//! Lexicographic key order then equals numeric time order.
//! A schema marker exists for the pinned schema and for each inherited schema.
//! An entity marker exists for each entity.
//! The entity list scans this marker family in id order.
//! All scans stop at the `prefix:` to `prefix;` bound.
//!
//! An existing store can lack the entity markers.
//! [`EntityStore::list_after`] then backfills them one time.
//! The `idx:entity-meta:backfilled` marker records that pass.
//! The pass holds the write lock, so a create or a delete cannot race it.
//! A store without the markers still returns entity pages after the pass.
//!
//! # Entity events
//!
//! The store returns an [`EntityChange`].
//! A store with a change sink writes one [`EntityEvent`](crate::records::EntityEvent) to an outbox row.
//! The outbox row commits in the same transaction as the entity rows.
//! The write succeeds when the entity rows and the outbox row commit.
//! The store then flushes the outbox to the feed.
//! A feed failure after the commit leaves the outbox row for the relay.
//! The call still returns success.
//! [`EntityStore::flush_outbox`] can deliver the row again.
//! Delivery is at least once.
//! A consumer must be idempotent.
//!
//! The `outbox-meta:pending` counter holds the number of pending outbox
//! rows.
//! A write increments the counter in the transaction that writes the outbox
//! row.
//! A flush decrements the counter in the same write guard as the row delete.
//! The counter is always equal to the number of `outbox:` rows.
//! When the counter key is absent, [`EntityStore::outbox_count`] scans the
//! `outbox:` family one time and writes the exact count.
//! The backfill runs at most once.
//! A crash before the counter write retries safely.
//!
//! An update changes attributes only.
//! A later operation changes the pinned schemas.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oxkv::{Direction, GetSet, KeyValue, OxKvStore, Store as _, Transaction as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

use crate::eav::MAX_PAGE_OFFSET;
use crate::eav::entity_error::EntityError;
use crate::eav::error::SchemaError;
use crate::eav::schema::{AttributeDef, AttributeType, EffectiveSchema, SchemaRef, SchemaRegistry};
use crate::records::{AttributeChange, ChangeSink, EntityEvent, EntityEventKind, WalOp};

/// Key prefix for entity rows.
const ENTITY_PREFIX: &str = "entity:";

/// Key prefix for pending outbox rows.
const OUTBOX_PREFIX: &str = "outbox:";

/// Key for the durable pending outbox row counter.
///
/// The key does not start with [`OUTBOX_PREFIX`], so an outbox scan does not
/// count it as a row.
const OUTBOX_PENDING_KEY: &str = "outbox-meta:pending";

/// Suffix for the metadata row of an entity.
const META_SUFFIX: &str = ":meta";

/// Infix before an attribute key.
const ATTR_INFIX: &str = ":attr:";

/// Key prefix for entity markers.
const ENTITY_INDEX_PREFIX: &str = "idx:entity:";

/// Key prefix for entity marker metadata.
const ENTITY_META_PREFIX: &str = "idx:entity-meta:";

/// Key suffix for the one-time entity marker backfill.
const ENTITY_BACKFILL_SUFFIX: &str = "backfilled";

/// Key prefix for schema index markers.
const SCHEMA_INDEX_PREFIX: &str = "idx:schema:";

/// Key prefix for attribute index markers.
const ATTR_INDEX_PREFIX: &str = "idx:attr:";

/// Key prefix for the marker of an indexed attribute key.
const ATTR_KEY_PREFIX: &str = "idx:attr-key:";

/// Key prefix for unique index markers.
const UNIQUE_INDEX_PREFIX: &str = "idx:unique:";

/// Key prefix for time index markers.
const TIME_INDEX_PREFIX: &str = "idx:time:";

/// Key prefix for time key markers.
const TIME_KEY_INDEX_PREFIX: &str = "idx:time-key:";

/// Key prefix for time key metadata.
const TIME_KEY_META_PREFIX: &str = "idx:time-key-meta:";

/// Key suffix for the one-time time key backfill marker.
const TIME_KEY_BACKFILL_SUFFIX: &str = "backfilled";

/// Key prefix for fired timer markers.
const TIMER_MARKER_PREFIX: &str = "timer:fired:";

/// Maximum size of an entity id or an attribute name, in bytes.
const MAX_NAME_BYTES: usize = 128;

/// One typed attribute value.
///
/// The serde form is adjacent and tagged.
/// The `type` field makes the type explicit on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum AttributeValue {
    /// A UTF-8 string.
    String(String),
    /// A signed 64-bit integer.
    Integer(i64),
    /// A 64-bit floating point number.
    Float(f64),
    /// A boolean.
    Boolean(bool),
    /// A Unix timestamp in seconds.
    Timestamp(i64),
    /// An arbitrary JSON value.
    Json(serde_json::Value),
    /// A reference to another entity.
    EntityRef(String),
}

impl AttributeValue {
    /// Returns the plain JSON value of this attribute.
    ///
    /// The result holds no storage type tag.
    /// A string or an entity reference becomes a JSON string.
    /// An integer, a float, or a timestamp becomes a JSON number.
    /// A rule condition can then compare the value with a JSON literal.
    pub fn as_json(&self) -> serde_json::Value {
        match self {
            Self::String(value) | Self::EntityRef(value) => {
                serde_json::Value::String(value.clone())
            }
            Self::Integer(value) | Self::Timestamp(value) => {
                serde_json::Value::Number((*value).into())
            }
            Self::Float(value) => serde_json::Number::from_f64(*value)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            Self::Boolean(value) => serde_json::Value::Bool(*value),
            Self::Json(value) => value.clone(),
        }
    }
}

/// A new entity, before the store assigns a version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityDraft {
    /// The entity id.
    pub id: String,
    /// The schema ids that the entity pins.
    pub schemas: Vec<String>,
    /// The initial attributes, keyed by name.
    pub attributes: BTreeMap<String, AttributeValue>,
}

/// A set of attribute changes.
///
/// A `Some` value sets the attribute.
/// A `None` value removes the attribute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityPatch {
    /// The changes, keyed by attribute name.
    ///
    /// The OpenAPI schema names the value type.
    /// A JSON `null` removes the attribute.
    #[schema(value_type = BTreeMap<String, AttributeValue>)]
    pub attributes: BTreeMap<String, Option<AttributeValue>>,
}

/// One stored entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Entity {
    /// The entity id.
    pub id: String,
    /// The entity version. The first version is 1.
    pub version: u64,
    /// The pinned schema versions.
    pub schemas: Vec<SchemaRef>,
    /// The stored attributes, keyed by name.
    pub attributes: BTreeMap<String, AttributeValue>,
    /// The creation time as a Unix timestamp in seconds.
    pub created_at: i64,
    /// The last update time as a Unix timestamp in seconds.
    pub updated_at: i64,
}

/// One reason that an entity fails a target schema version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum RevalidationIssue {
    /// The entity stores an attribute that the target version does not define.
    UnknownAttribute(String),
    /// An attribute value does not match the target type.
    TypeMismatch(String),
    /// The target version requires an attribute that the entity lacks.
    MissingRequired(String),
    /// The effective target schemas conflict.
    SchemaConflict(String),
}

/// One entity that fails a target schema version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InvalidEntity {
    /// The entity id.
    pub entity_id: String,
    /// The first issue that the entity has.
    pub issue: RevalidationIssue,
}

/// A dry-run result for one target schema version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RevalidationReport {
    /// The number of entities that the call checked.
    pub scanned: usize,
    /// The number of entities that pass the target version.
    pub compatible: usize,
    /// The entities that fail the target version.
    pub invalid: Vec<InvalidEntity>,
    /// The id to resume after for the next page.
    /// `None` means the pass is complete.
    pub next: Option<String>,
}

/// The result of one schema migration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MigrationReport {
    /// The number of entities that the call checked.
    pub scanned: usize,
    /// The number of entities that the call migrated or would migrate.
    pub migrated: usize,
    /// The number of entities that already pin the target version.
    pub unchanged: usize,
    /// The entities that fail the target version.
    pub invalid: Vec<InvalidEntity>,
    /// True when the call wrote no key and no event.
    pub dry_run: bool,
    /// The id to resume after for the next page.
    /// `None` means the pass is complete.
    pub next: Option<String>,
}

/// The counts from one atomic schema migration batch.
#[derive(Debug, Default)]
struct MigrationBatchResult {
    /// The number of entities that the batch migrated.
    migrated: usize,
    /// The number of entities that already pin the target version.
    unchanged: usize,
    /// The entities that fail the target version.
    invalid: Vec<InvalidEntity>,
}

/// One meta row and one optional outbox row for a batch write.
struct SchemaMigrationWrite {
    /// The entity after the migration.
    entity: Entity,
    /// The outbox key and bytes, when a feed is configured.
    outbox: Option<(String, Vec<u8>)>,
}

/// The before and after state of one entity change.
///
/// This type is the seam for the later event-delivery issue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityChange {
    /// The entity before the change. `None` means that the entity did not exist.
    pub before: Option<Entity>,
    /// The entity after the change. `None` means that the entity no longer exists.
    pub after: Option<Entity>,
}

/// Who made one change and why.
///
/// The store copies these values into the event.
/// The actor is the subject that made the change.
/// The correlation id groups events from one request or workflow.
/// The causation id names the event that caused this change.
/// The causation depth counts the links before this change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteContext {
    /// The subject that made the change.
    pub actor: String,
    /// Identifier that groups events from one request or workflow.
    pub correlation_id: Option<String>,
    /// Identifier of the event that caused this change.
    pub causation_id: Option<String>,
    /// Number of links in the causation chain before this change.
    pub causation_depth: u32,
}

impl WriteContext {
    /// Creates a context for `actor` with no correlation id and no cause.
    ///
    /// The causation depth is 0, which marks a user-driven change.
    pub fn new(actor: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            correlation_id: None,
            causation_id: None,
            causation_depth: 0,
        }
    }

    /// Sets the correlation id.
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Sets the causation id.
    ///
    /// The call does not change the causation depth.
    pub fn with_causation_id(mut self, id: impl Into<String>) -> Self {
        self.causation_id = Some(id.into());
        self
    }

    /// Sets the causation id and the causation depth.
    ///
    /// An action that writes an entity uses this method.
    /// The new depth is one more than the depth of the cause.
    pub fn with_causation(mut self, id: impl Into<String>, depth: u32) -> Self {
        self.causation_id = Some(id.into());
        self.causation_depth = depth;
        self
    }
}

/// A store of validated entities on one OxKV store.
///
/// One write mutex serializes mutations.
/// The mutex keeps versions and unique indexes free of races.
/// One flush mutex serializes outbox delivery.
#[derive(Clone)]
pub struct EntityStore {
    /// Shared store handle.
    store: Arc<RwLock<OxKvStore>>,
    /// The schema registry that supplies the effective schemas.
    schemas: SchemaRegistry,
    /// Serializes mutations, so two callers cannot claim one version.
    write_lock: Arc<Mutex<()>>,
    /// Serializes outbox flushes, so one row is appended one time at once.
    flush_lock: Arc<Mutex<()>>,
    /// The change feed that receives committed entity events.
    feed: Option<Arc<dyn ChangeSink>>,
    /// True when a write checks that every `EntityRef` target exists.
    ///
    /// The check is on by default.
    /// A host can turn it off for a store that holds legacy references.
    check_entity_refs: bool,
}

impl EntityStore {
    /// Creates an entity store over `store` with `schemas`.
    pub fn new(store: OxKvStore, schemas: SchemaRegistry) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
            schemas,
            write_lock: Arc::new(Mutex::new(())),
            flush_lock: Arc::new(Mutex::new(())),
            feed: None,
            check_entity_refs: true,
        }
    }

    /// Sets whether a write checks that every `EntityRef` target exists.
    ///
    /// The default is `true`.
    /// With `false`, the write still validates each target as an entity id.
    /// It skips only the existence read.
    pub fn with_entity_ref_check(mut self, check: bool) -> Self {
        self.check_entity_refs = check;
        self
    }

    /// Checks every `EntityRef` value in one write.
    ///
    /// The call validates each target as an entity id.
    /// With the reference check on, it also requires that the target exists.
    /// A self-reference is valid, because the entity is about to exist.
    /// The call reads one row for each distinct target.
    async fn check_entity_refs<S>(
        &self,
        store: &S,
        entity_id: &str,
        attributes: &BTreeMap<String, AttributeValue>,
        defs: &BTreeMap<String, AttributeDef>,
    ) -> Result<(), EntityError>
    where
        S: GetSet + ?Sized,
    {
        let mut targets = BTreeSet::new();
        for (name, value) in attributes {
            if !defs
                .get(name)
                .is_some_and(|def| def.ty == AttributeType::EntityRef)
            {
                continue;
            }
            let AttributeValue::EntityRef(target) = value else {
                continue;
            };
            validate_name("entity id", target)?;
            if target != entity_id {
                targets.insert((name.clone(), target.clone()));
            }
        }
        if !self.check_entity_refs {
            return Ok(());
        }
        for (name, target) in targets {
            if store
                .get_bytes(&meta_key(&target))
                .await
                .map_err(EntityError::Store)?
                .is_none()
            {
                return Err(EntityError::DanglingRef(name, target));
            }
        }
        Ok(())
    }

    /// Attaches a [`ChangeSink`] for event delivery.
    ///
    /// A mutation then writes its event to the outbox in the same
    /// transaction as the entity rows.
    /// The mutation flushes the outbox after the commit.
    pub fn with_change_sink(mut self, feed: Arc<dyn ChangeSink>) -> Self {
        self.feed = Some(feed);
        self
    }

    /// Creates an entity and returns the change.
    ///
    /// The call resolves each schema id to its latest version.
    /// It applies the schema defaults and checks every attribute.
    /// The metadata row, the attribute rows, and all index rows commit in
    /// one transaction.
    /// With a feed, one outbox row commits in the same transaction.
    /// The write succeeds when the entity rows and the outbox row commit.
    /// A feed failure after the commit leaves the outbox row for the relay.
    /// The call still returns success.
    /// The first version is 1.
    pub async fn create(
        &self,
        draft: EntityDraft,
        ctx: &WriteContext,
    ) -> Result<EntityChange, EntityError> {
        validate_name("entity id", &draft.id)?;
        let effective = self.resolve_schemas(&draft.schemas).await?;
        let merged = merge_schemas(&effective)?;
        let mut attributes = draft.attributes;
        check_known(&attributes, &merged.attributes)?;
        validate_defaults(&merged.attributes)?;
        apply_defaults(&mut attributes, &merged.attributes)?;
        check_types(&attributes, &merged.attributes)?;
        check_required(&attributes, &merged.attributes)?;

        let now = chrono::Utc::now().timestamp();
        let entity = Entity {
            id: draft.id,
            version: 1,
            schemas: effective_refs(&effective),
            attributes,
            created_at: now,
            updated_at: now,
        };
        let pending = {
            let _write = self.write_lock.lock().await;
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(EntityError::Store)?;
            if tx
                .get_bytes(&meta_key(&entity.id))
                .await
                .map_err(EntityError::Store)?
                .is_some()
            {
                return Err(EntityError::AlreadyExists(entity.id));
            }
            self.check_entity_refs(&tx, &entity.id, &entity.attributes, &merged.attributes)
                .await?;
            let outbox =
                self.prepare_outbox(None, Some(&entity), event_schema_ids(&effective), ctx)?;
            check_unique_values(&tx, &entity, &merged.attributes).await?;
            put_entity_rows(&tx, &entity, &merged).await?;
            if outbox.is_some() {
                increment_outbox_pending(&tx, 1).await?;
            }
            if let Some((key, bytes)) = &outbox {
                tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
            }
            tx.commit().await.map_err(EntityError::Store)?;
            outbox.is_some()
        };
        if pending && let Err(error) = self.flush_after_commit().await {
            tracing::warn!(
                %error,
                "entity outbox flush failed after commit; the relay will deliver the event"
            );
        }
        Ok(EntityChange {
            before: None,
            after: Some(entity),
        })
    }

    /// Reads one entity.
    ///
    /// The call returns `None` when the entity does not exist.
    pub async fn get(&self, id: &str) -> Result<Option<Entity>, EntityError> {
        validate_name("entity id", id)?;
        let g = self.store.read().await;
        load_entity(&*g, id).await
    }

    /// Updates the attributes of one entity and returns the change.
    ///
    /// The expected version must match the stored version.
    /// A mismatch is a version conflict and changes nothing.
    /// The call applies the schema defaults after the patch and checks every
    /// attribute.
    /// The version increases by one.
    /// The write succeeds when the entity rows and the outbox row commit.
    /// A feed failure after the commit leaves the outbox row for the relay.
    /// The call still returns success.
    pub async fn update(
        &self,
        id: &str,
        expected_version: u64,
        patch: EntityPatch,
        ctx: &WriteContext,
    ) -> Result<EntityChange, EntityError> {
        validate_name("entity id", id)?;
        if patch.attributes.is_empty() {
            return Err(EntityError::Invalid("patch is empty".to_string()));
        }

        let (change, pending) = {
            let _write = self.write_lock.lock().await;
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(EntityError::Store)?;
            let Some(before) = load_entity(&tx, id).await? else {
                return Err(EntityError::NotFound(id.to_string()));
            };
            if before.version != expected_version {
                return Err(EntityError::VersionConflict);
            }

            let effective = self.resolve_refs(&before.schemas).await?;
            let merged = merge_schemas(&effective)?;
            validate_defaults(&merged.attributes)?;
            let mut attributes = before.attributes.clone();
            for (key, value) in &patch.attributes {
                if !merged.attributes.contains_key(key) {
                    return Err(EntityError::UnknownAttribute(key.clone()));
                }
                match value {
                    Some(value) => {
                        attributes.insert(key.clone(), value.clone());
                    }
                    None => {
                        attributes.remove(key);
                    }
                }
            }
            apply_defaults(&mut attributes, &merged.attributes)?;
            check_types(&attributes, &merged.attributes)?;
            check_required(&attributes, &merged.attributes)?;

            let version = before
                .version
                .checked_add(1)
                .ok_or_else(|| EntityError::Internal("entity version overflow".to_string()))?;
            let after = Entity {
                id: id.to_string(),
                version,
                schemas: before.schemas.clone(),
                attributes,
                created_at: before.created_at,
                updated_at: chrono::Utc::now().timestamp(),
            };
            self.check_entity_refs(&tx, &after.id, &after.attributes, &merged.attributes)
                .await?;
            let outbox = self.prepare_outbox(
                Some(&before),
                Some(&after),
                event_schema_ids(&effective),
                ctx,
            )?;

            check_unique_values(&tx, &after, &merged.attributes).await?;
            delete_changed_timer_markers(&tx, &before, &after, &merged).await?;
            delete_mutable_rows(&tx, &before, &merged).await?;
            put_entity_rows(&tx, &after, &merged).await?;
            if outbox.is_some() {
                increment_outbox_pending(&tx, 1).await?;
            }
            if let Some((key, bytes)) = &outbox {
                tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
            }
            tx.commit().await.map_err(EntityError::Store)?;
            (
                EntityChange {
                    before: Some(before),
                    after: Some(after),
                },
                outbox.is_some(),
            )
        };
        if pending && let Err(error) = self.flush_after_commit().await {
            tracing::warn!(
                %error,
                "entity outbox flush failed after commit; the relay will deliver the event"
            );
        }
        Ok(change)
    }

    /// Deletes one entity and returns the change.
    ///
    /// The expected version must match the stored version.
    /// A mismatch is a version conflict and changes nothing.
    /// The call removes the metadata row and every attribute and index row.
    /// The write succeeds when the entity rows and the outbox row commit.
    /// A feed failure after the commit leaves the outbox row for the relay.
    /// The call still returns success.
    pub async fn delete(
        &self,
        id: &str,
        expected_version: u64,
        ctx: &WriteContext,
    ) -> Result<EntityChange, EntityError> {
        validate_name("entity id", id)?;
        let (change, pending) = {
            let _write = self.write_lock.lock().await;
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(EntityError::Store)?;
            let Some(before) = load_entity(&tx, id).await? else {
                return Err(EntityError::NotFound(id.to_string()));
            };
            if before.version != expected_version {
                return Err(EntityError::VersionConflict);
            }

            let effective = self.resolve_refs(&before.schemas).await?;
            let merged = merge_schemas(&effective)?;
            let outbox =
                self.prepare_outbox(Some(&before), None, event_schema_ids(&effective), ctx)?;
            delete_mutable_rows(&tx, &before, &merged).await?;
            delete_all_timer_markers(&tx, &before, &merged).await?;
            for schema_id in &merged.schema_ids {
                tx.delete(&schema_index_key(schema_id, id))
                    .await
                    .map_err(EntityError::Store)?;
            }
            tx.delete(&entity_index_key(id))
                .await
                .map_err(EntityError::Store)?;
            tx.delete(&meta_key(id)).await.map_err(EntityError::Store)?;
            if outbox.is_some() {
                increment_outbox_pending(&tx, 1).await?;
            }
            if let Some((key, bytes)) = &outbox {
                tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
            }
            tx.commit().await.map_err(EntityError::Store)?;
            (
                EntityChange {
                    before: Some(before),
                    after: None,
                },
                outbox.is_some(),
            )
        };
        if pending && let Err(error) = self.flush_after_commit().await {
            tracing::warn!(
                %error,
                "entity outbox flush failed after commit; the relay will deliver the event"
            );
        }
        Ok(change)
    }

    /// Delivers every pending outbox row to the change feed.
    ///
    /// The call returns `Ok(0)` when no feed is configured.
    /// Before it reads the rows, the call ensures that the
    /// `outbox-meta:pending` counter exists.
    /// An old store without the counter gets the one-time backfill.
    /// It reads the rows in key order.
    /// For each row, it appends the event and then deletes the row.
    /// It decrements the counter in the same write guard as the delete.
    /// The counter never goes below zero.
    /// It stops at the first append failure.
    /// That row and every later row stay in the outbox.
    /// The call does not hold the store write guard during the append.
    ///
    /// The counter is equal to the number of `outbox:` rows.
    /// Delivery is at least once.
    /// A crash after an append and before a delete can deliver one event
    /// again.
    /// A consumer must be idempotent.
    pub async fn flush_outbox(&self) -> Result<usize, EntityError> {
        let Some(feed) = &self.feed else {
            return Ok(0);
        };
        let _flush = self.flush_lock.lock().await;
        self.ensure_outbox_pending().await?;
        let rows = {
            let g = self.store.read().await;
            scan_prefix(&*g, OUTBOX_PREFIX).await?
        };
        let mut delivered = 0;
        for row in rows {
            let event: EntityEvent = serde_json::from_slice(&row.value)
                .map_err(|e| EntityError::Internal(format!("outbox event is invalid: {e}")))?;
            feed.append(WalOp::Entity { event })
                .await
                .map_err(|_| EntityError::Feed("entity feed append failed".to_string()))?;
            let g = self.store.write().await;
            g.delete(&row.key).await.map_err(EntityError::Store)?;
            decrement_outbox_pending(&*g, 1).await?;
            drop(g);
            delivered += 1;
        }
        Ok(delivered)
    }

    /// Returns the number of pending outbox rows.
    ///
    /// The call reads the `outbox-meta:pending` counter.
    /// The counter is equal to the number of `outbox:` rows.
    /// A normal call does not scan the outbox family.
    /// When the counter key is absent, the call takes the write lock and the
    /// store write guard.
    /// It re-checks the key inside the guard.
    /// It then scans the `outbox:` family one time and writes the exact count.
    /// The backfill runs at most once.
    /// A crash before the counter write retries safely.
    pub async fn outbox_count(&self) -> Result<usize, EntityError> {
        let count = self.ensure_outbox_pending().await?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    /// Returns the pending outbox count and backfills the key when absent.
    ///
    /// The call reads the counter on the normal path.
    /// When the key is absent, it takes the write lock and the store write
    /// guard, re-checks the key, scans the `outbox:` family one time, and
    /// writes the exact count.
    /// The backfill runs at most once.
    /// A crash before the counter write retries safely.
    async fn ensure_outbox_pending(&self) -> Result<u64, EntityError> {
        {
            let g = self.store.read().await;
            if let Some(count) = read_outbox_pending(&*g).await? {
                return Ok(count);
            }
        }

        let _write = self.write_lock.lock().await;
        let g = self.store.write().await;
        if let Some(count) = read_outbox_pending(&*g).await? {
            return Ok(count);
        }
        let count = u64::try_from(scan_prefix(&*g, OUTBOX_PREFIX).await?.len()).unwrap_or(u64::MAX);
        write_outbox_pending(&*g, count).await?;
        Ok(count)
    }

    /// Flushes the outbox after a commit.
    ///
    /// The transaction already made the write durable, so this call is best
    /// effort.
    /// The call returns the number of delivered rows.
    /// A feed or store failure returns an error.
    /// The error does not cancel the write.
    /// The outbox row stays committed for [`EntityStore::flush_outbox`].
    /// The relay delivers that row later.
    async fn flush_after_commit(&self) -> Result<usize, EntityError> {
        self.flush_outbox().await
    }

    /// Builds an outbox row when a feed is configured.
    fn prepare_outbox(
        &self,
        before: Option<&Entity>,
        after: Option<&Entity>,
        schemas: Vec<String>,
        ctx: &WriteContext,
    ) -> Result<Option<(String, Vec<u8>)>, EntityError> {
        if self.feed.is_none() {
            return Ok(None);
        }
        let event = build_event(before, after, schemas, ctx)?;
        let key = outbox_key(&event.event_id);
        let bytes = serde_json::to_vec(&event).map_err(|e| EntityError::Internal(e.to_string()))?;
        Ok(Some((key, bytes)))
    }

    /// Builds an outbox row for one schema-applied event.
    ///
    /// The call returns `None` when no feed is configured.
    fn prepare_schema_applied_outbox(
        &self,
        entity: &Entity,
        schemas: Vec<String>,
        ctx: &WriteContext,
    ) -> Result<Option<(String, Vec<u8>)>, EntityError> {
        if self.feed.is_none() {
            return Ok(None);
        }
        let event = build_schema_applied_event(entity, schemas, ctx)?;
        let key = outbox_key(&event.event_id);
        let bytes = serde_json::to_vec(&event).map_err(|e| EntityError::Internal(e.to_string()))?;
        Ok(Some((key, bytes)))
    }

    /// Lists the entities that pin `schema_id` or an inherited schema.
    ///
    /// The result is sorted by entity id.
    pub async fn list_by_schema(&self, schema_id: &str) -> Result<Vec<Entity>, EntityError> {
        validate_name("schema id", schema_id)?;
        let g = self.store.read().await;
        let prefix = format!("{SCHEMA_INDEX_PREFIX}{schema_id}:");
        let markers = scan_prefix(&*g, &prefix).await?;
        let mut entities = Vec::new();
        let mut seen = BTreeSet::new();
        for marker in markers {
            let Some(id) = marker.key.strip_prefix(&prefix) else {
                continue;
            };
            if id.is_empty() || id.contains(':') || !seen.insert(id.to_string()) {
                continue;
            }
            if let Some(entity) = load_entity(&*g, id).await? {
                entities.push(entity);
            }
        }
        entities.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entities)
    }

    /// Lists one page of the entities that pin `schema_id` or an inherited schema.
    ///
    /// The result is sorted by entity id.
    /// The call skips `offset` ids.
    /// It then loads at most `limit` entities.
    /// A `limit` of 0 returns an empty list.
    pub async fn list_by_schema_page(
        &self,
        schema_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Entity>, EntityError> {
        validate_name("schema id", schema_id)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let g = self.store.read().await;
        let prefix = format!("{SCHEMA_INDEX_PREFIX}{schema_id}:");
        let max = offset.saturating_add(limit);
        let markers = scan_prefix_bounded(&*g, &prefix, max).await?;
        let mut ids = Vec::new();
        let mut seen = BTreeSet::new();
        for marker in markers {
            let Some(id) = marker.key.strip_prefix(&prefix) else {
                continue;
            };
            if id.is_empty() || id.contains(':') || !seen.insert(id.to_string()) {
                continue;
            }
            ids.push(id.to_string());
        }
        ids.sort();
        let mut entities = Vec::with_capacity(limit.min(ids.len()));
        for id in ids.iter().skip(offset).take(limit) {
            if let Some(entity) = load_entity(&*g, id).await? {
                entities.push(entity);
            }
        }
        Ok(entities)
    }

    /// Lists one page of the entities that pin `schema_id` or an inherited schema.
    ///
    /// The result is sorted by entity id.
    /// The scan starts after the `after` id when the caller gives a cursor.
    /// The call returns the entities and the cursor for the next page.
    /// The cursor is the last id of a full page.
    /// The cursor is `None` when the scan is exhausted.
    /// A `limit` of 0 returns an empty list and no cursor.
    pub async fn list_by_schema_after(
        &self,
        schema_id: &str,
        limit: usize,
        after: Option<&str>,
    ) -> Result<(Vec<Entity>, Option<String>), EntityError> {
        validate_name("schema id", schema_id)?;
        if limit == 0 {
            return Ok((Vec::new(), None));
        }
        let g = self.store.read().await;
        let prefix = format!("{SCHEMA_INDEX_PREFIX}{schema_id}:");
        let start = match after {
            Some(cursor) => {
                validate_name("entity id", cursor)?;
                format!("{prefix}{cursor}\0")
            }
            None => prefix.clone(),
        };
        let max = u32::try_from(limit).ok();
        let cursor = (Some(start), Some(prefix_scan_end(&prefix)));
        let markers = g
            .gets_bytes(max, Direction::Next, cursor)
            .await
            .map_err(EntityError::Store)?;
        let full = markers.len() == limit;
        let mut ids = Vec::new();
        let mut seen = BTreeSet::new();
        for marker in markers {
            let Some(id) = marker.key.strip_prefix(&prefix) else {
                continue;
            };
            if id.is_empty() || id.contains(':') || !seen.insert(id.to_string()) {
                continue;
            }
            ids.push(id.to_string());
        }
        ids.sort();
        let next = if full { ids.last().cloned() } else { None };
        let mut entities = Vec::with_capacity(limit.min(ids.len()));
        for id in &ids {
            if let Some(entity) = load_entity(&*g, id).await? {
                entities.push(entity);
            }
        }
        Ok((entities, next))
    }

    /// Checks stored entities against a target schema version.
    ///
    /// The call reads at most `limit` entities that pin `schema_id`.
    /// The scan starts after the `after` id when the caller gives a cursor.
    /// It changes no key, no entity version, and no pinned schema.
    /// It records one issue for each invalid entity.
    /// The report holds the cursor for the next page.
    /// A missing target version is [`EntityError::UnknownSchema`].
    pub async fn revalidation_report(
        &self,
        schema_id: &str,
        target_version: u64,
        limit: usize,
        after: Option<&str>,
    ) -> Result<RevalidationReport, EntityError> {
        validate_name("schema id", schema_id)?;
        if self
            .schemas
            .get(schema_id, target_version)
            .await
            .map_err(map_schema_error)?
            .is_none()
        {
            return Err(EntityError::UnknownSchema(schema_id.to_string()));
        }

        let (entities, next) = self.list_by_schema_after(schema_id, limit, after).await?;
        let mut report = RevalidationReport {
            scanned: 0,
            compatible: 0,
            invalid: Vec::new(),
            next,
        };
        for entity in entities {
            if !entity.schemas.iter().any(|schema| schema.id == schema_id) {
                continue;
            }
            report.scanned += 1;
            match self
                .revalidate_one(&entity, schema_id, target_version)
                .await
            {
                Ok(()) => report.compatible += 1,
                Err(issue) => report.invalid.push(InvalidEntity {
                    entity_id: entity.id.clone(),
                    issue,
                }),
            }
        }
        Ok(report)
    }

    /// Applies one target schema version to compatible entities.
    ///
    /// The call reads at most `limit` entities that pin `schema_id`.
    /// The scan starts after the `after` id when the caller gives a cursor.
    /// It checks each entity with the target version.
    /// An invalid entity stays unchanged and goes into `invalid`.
    /// A valid entity that already pins `target_version` counts as unchanged.
    /// Any other valid entity counts as migrated.
    /// A dry run writes no key and no event.
    /// An apply writes every meta row and every outbox row in one transaction.
    /// A stale entity version aborts the batch with no write.
    /// A store error aborts the batch with no write.
    /// A missing target version is [`EntityError::UnknownSchema`].
    /// The report holds the cursor for the next page.
    /// A `limit` of 0 returns an empty report.
    pub async fn migrate_schema(
        &self,
        schema_id: &str,
        target_version: u64,
        limit: usize,
        after: Option<&str>,
        dry_run: bool,
        ctx: &WriteContext,
    ) -> Result<MigrationReport, EntityError> {
        validate_name("schema id", schema_id)?;
        if self
            .schemas
            .get(schema_id, target_version)
            .await
            .map_err(map_schema_error)?
            .is_none()
        {
            return Err(EntityError::UnknownSchema(schema_id.to_string()));
        }

        let mut report = MigrationReport {
            scanned: 0,
            migrated: 0,
            unchanged: 0,
            invalid: Vec::new(),
            dry_run,
            next: None,
        };
        if limit == 0 {
            return Ok(report);
        }

        let (entities, next) = self.list_by_schema_after(schema_id, limit, after).await?;
        report.next = next;
        if dry_run {
            for entity in entities {
                if !entity.schemas.iter().any(|schema| schema.id == schema_id) {
                    continue;
                }
                report.scanned += 1;
                match self
                    .revalidate_one(&entity, schema_id, target_version)
                    .await
                {
                    Ok(()) => {
                        if entity.schemas.iter().any(|schema| {
                            schema.id == schema_id && schema.version == target_version
                        }) {
                            report.unchanged += 1;
                        } else {
                            report.migrated += 1;
                        }
                    }
                    Err(issue) => report.invalid.push(InvalidEntity {
                        entity_id: entity.id.clone(),
                        issue,
                    }),
                }
            }
            return Ok(report);
        }

        let candidates: Vec<Entity> = entities
            .into_iter()
            .filter(|entity| entity.schemas.iter().any(|schema| schema.id == schema_id))
            .collect();
        report.scanned = candidates.len();
        let applied = self
            .apply_schema_migration_batch(&candidates, schema_id, target_version, ctx)
            .await?;
        report.migrated = applied.migrated;
        report.unchanged = applied.unchanged;
        report.invalid = applied.invalid;
        Ok(report)
    }

    /// Applies one target schema version to one batch of entities.
    ///
    /// The call holds the write lock for the whole batch.
    /// It reloads each entity and rejects a stale version.
    /// An invalid entity goes into `invalid` and is skipped.
    /// It builds every after entity and every outbox row in memory.
    /// One transaction writes every row and increments the pending counter,
    /// or it writes no row.
    /// The call flushes the outbox one time after the commit.
    /// A feed failure after the commit leaves the outbox rows for the relay.
    async fn apply_schema_migration_batch(
        &self,
        entities: &[Entity],
        schema_id: &str,
        target_version: u64,
        ctx: &WriteContext,
    ) -> Result<MigrationBatchResult, EntityError> {
        let _write = self.write_lock.lock().await;
        let mut result = MigrationBatchResult::default();
        let mut writes: Vec<SchemaMigrationWrite> = Vec::new();

        for entity in entities {
            let current = {
                let g = self.store.read().await;
                load_entity(&*g, &entity.id).await?
            };
            let Some(current) = current else {
                return Err(EntityError::VersionConflict);
            };
            // Reject a stale decision.
            // Another write changed the entity after the validation.
            // A migration on the old attributes could lose that write.
            if current.version != entity.version {
                return Err(EntityError::VersionConflict);
            }
            if !current.schemas.iter().any(|schema| schema.id == schema_id) {
                continue;
            }
            match self
                .revalidate_one(&current, schema_id, target_version)
                .await
            {
                Ok(()) => {}
                Err(issue) => {
                    result.invalid.push(InvalidEntity {
                        entity_id: current.id.clone(),
                        issue,
                    });
                    continue;
                }
            }
            if current
                .schemas
                .iter()
                .any(|schema| schema.id == schema_id && schema.version == target_version)
            {
                result.unchanged += 1;
                continue;
            }
            let schemas: Vec<SchemaRef> = current
                .schemas
                .iter()
                .map(|schema| {
                    if schema.id == schema_id {
                        SchemaRef {
                            id: schema_id.to_string(),
                            version: target_version,
                        }
                    } else {
                        schema.clone()
                    }
                })
                .collect();
            let version = current
                .version
                .checked_add(1)
                .ok_or_else(|| EntityError::Internal("entity version overflow".to_string()))?;
            let after = Entity {
                id: current.id.clone(),
                version,
                schemas,
                attributes: current.attributes.clone(),
                created_at: current.created_at,
                updated_at: chrono::Utc::now().timestamp(),
            };
            let effective = self.resolve_refs(&after.schemas).await?;
            let merged = merge_schemas(&effective)?;
            {
                let g = self.store.read().await;
                self.check_entity_refs(&*g, &after.id, &after.attributes, &merged.attributes)
                    .await?;
            }
            let outbox =
                self.prepare_schema_applied_outbox(&after, event_schema_ids(&effective), ctx)?;
            result.migrated += 1;
            writes.push(SchemaMigrationWrite {
                entity: after,
                outbox,
            });
        }

        if writes.is_empty() {
            return Ok(result);
        }

        let pending = writes.iter().any(|write| write.outbox.is_some());
        let outbox_rows = writes.iter().filter(|write| write.outbox.is_some()).count();
        {
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(EntityError::Store)?;
            if outbox_rows > 0 {
                increment_outbox_pending(&tx, u64::try_from(outbox_rows).unwrap_or(u64::MAX))
                    .await?;
            }
            for write in &writes {
                put_meta_row(&tx, &write.entity).await?;
                if let Some((key, bytes)) = &write.outbox {
                    tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
                }
            }
            tx.commit().await.map_err(EntityError::Store)?;
        }
        drop(_write);
        if pending && let Err(error) = self.flush_after_commit().await {
            tracing::warn!(
                %error,
                "entity outbox flush failed after commit; the relay will deliver the event"
            );
        }
        Ok(result)
    }

    /// Validates one entity against a candidate pinned list.
    ///
    /// The candidate replaces `schema_id` with `target_version`.
    /// The call clones the attributes before it applies defaults.
    async fn revalidate_one(
        &self,
        entity: &Entity,
        schema_id: &str,
        target_version: u64,
    ) -> Result<(), RevalidationIssue> {
        let refs: Vec<SchemaRef> = entity
            .schemas
            .iter()
            .map(|schema| {
                if schema.id == schema_id {
                    SchemaRef {
                        id: schema_id.to_string(),
                        version: target_version,
                    }
                } else {
                    schema.clone()
                }
            })
            .collect();
        let effective = self
            .resolve_refs(&refs)
            .await
            .map_err(|error| RevalidationIssue::SchemaConflict(error.to_string()))?;
        let merged = merge_schemas(&effective)
            .map_err(|error| RevalidationIssue::SchemaConflict(error.to_string()))?;
        validate_attributes(&entity.attributes, &merged.attributes)
    }

    /// Lists the entities with an indexed attribute equal to `value`.
    ///
    /// The call checks the permanent key marker before it reads the schema.
    /// A stale marker only allows an empty result.
    /// The call returns an error when no applied schema indexes `key`.
    /// The result is sorted by entity id.
    pub async fn list_by_attribute(
        &self,
        key: &str,
        value: &AttributeValue,
    ) -> Result<Vec<Entity>, EntityError> {
        let (entities, _) = self
            .list_by_attribute_after(key, value, usize::MAX, None)
            .await?;
        Ok(entities)
    }

    /// Lists one page of the entities with an indexed attribute equal to `value`.
    ///
    /// The key marker is permanent.
    /// A present marker skips the schema check.
    /// A stale marker only allows an empty result.
    /// The scan starts after the `after` id when the caller gives a cursor.
    /// The scan verifies each hash match against the exact value.
    /// The result is in entity id order.
    /// The call returns the cursor for the next page when the page is full.
    /// The cursor is `None` when the scan is exhausted.
    /// A `limit` of 0 returns an empty list and no cursor.
    /// The call returns [`EntityError::NotIndexed`] when no applied schema
    /// indexes `key`.
    pub async fn list_by_attribute_after(
        &self,
        key: &str,
        value: &AttributeValue,
        limit: usize,
        after: Option<&str>,
    ) -> Result<(Vec<Entity>, Option<String>), EntityError> {
        validate_name("attribute name", key)?;
        if limit == 0 {
            return Ok((Vec::new(), None));
        }
        let hash = value_hash(value)?;
        let g = self.store.read().await;
        let marker_present = g
            .get_bytes(&attr_key_index_key(key))
            .await
            .map_err(EntityError::Store)?
            .is_some();
        if !marker_present && !self.attribute_is_indexed(key).await? {
            return Err(EntityError::NotIndexed(key.to_string()));
        }

        let prefix = format!("{ATTR_INDEX_PREFIX}{key}:{hash}:");
        let end = prefix_scan_end(&prefix);
        let mut start = match after {
            Some(cursor) => {
                validate_name("entity id", cursor)?;
                format!("{prefix}{cursor}\0")
            }
            None => prefix.clone(),
        };
        let max = u32::try_from(limit).ok();
        let mut entities = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            let rows = g
                .gets_bytes(
                    max,
                    Direction::Next,
                    (Some(start.clone()), Some(end.clone())),
                )
                .await
                .map_err(EntityError::Store)?;
            let full = rows.len() == limit;
            for row in &rows {
                start = format!("{}\0", row.key);
                let Some(id) = row.key.strip_prefix(&prefix) else {
                    continue;
                };
                if id.is_empty() || id.contains(':') || !seen.insert(id.to_string()) {
                    continue;
                }
                if let Some(entity) = load_entity(&*g, id).await?
                    && entity.attributes.get(key) == Some(value)
                {
                    entities.push(entity);
                }
            }
            if entities.len() >= limit || !full {
                break;
            }
        }
        entities.sort_by(|a, b| a.id.cmp(&b.id));
        let next = if entities.len() >= limit {
            entities.last().map(|entity| entity.id.clone())
        } else {
            None
        };
        Ok((entities, next))
    }

    /// Returns the attribute keys that have a time index row.
    ///
    /// The call scans only the `idx:time-key:` family.
    /// The result is sorted and has no duplicates.
    /// An attribute key contains no colon.
    /// A delete keeps the key marker. A stale marker costs one empty scan.
    /// The `idx:time-key-meta:backfilled` marker records the one-time
    /// backfill. When it is absent, the call scans the `idx:time:` family one
    /// time. It writes every missing key marker and the backfill marker. It
    /// returns the union of the marker keys and the scanned keys.
    /// The backfill runs at most one time per store.
    pub async fn time_keys(&self) -> Result<Vec<String>, EntityError> {
        let backfill_marker = time_key_backfill_marker();
        let g = self.store.read().await;
        let markers: BTreeSet<String> =
            time_key_marker_keys(scan_prefix(&*g, TIME_KEY_INDEX_PREFIX).await?)
                .into_iter()
                .collect();
        let backfilled = g
            .get_bytes(&backfill_marker)
            .await
            .map_err(EntityError::Store)?
            .is_some();
        if backfilled {
            return Ok(markers.into_iter().collect());
        }
        let keys = time_row_keys(scan_prefix(&*g, TIME_INDEX_PREFIX).await?);
        drop(g);

        let mut all = markers.clone();
        all.extend(keys);
        let g = self.store.write().await;
        for key in &all {
            if !markers.contains(key) {
                g.set_bytes(&time_key_index_key(key), b"")
                    .await
                    .map_err(EntityError::Store)?;
            }
        }
        g.set_bytes(&backfill_marker, b"")
            .await
            .map_err(EntityError::Store)?;
        Ok(all.into_iter().collect())
    }

    /// Lists the entities whose indexed timestamp `key` is due.
    ///
    /// The call scans only the `idx:time:{key}:` family.
    /// The index holds only values that have not fired.
    /// A timer retire removes the time row after the timer fires.
    /// The scan stops at the inclusive upper bound for `at_or_before`.
    /// The result is in time order.
    /// An entity appears only when its current value for `key` is a
    /// [`AttributeValue::Timestamp`] at or before `at_or_before`.
    /// That check drops a stale index row.
    /// A `limit` of 0 returns an empty list.
    pub async fn list_due(
        &self,
        key: &str,
        at_or_before: i64,
        limit: usize,
    ) -> Result<Vec<Entity>, EntityError> {
        validate_name("attribute name", key)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let g = self.store.read().await;
        let prefix = format!("{TIME_INDEX_PREFIX}{key}:");
        let upper = format!("{prefix}{};", encode_timestamp(at_or_before));
        let cursor = (Some(prefix.clone()), Some(upper));
        let rows = g
            .gets_bytes(None, Direction::Next, cursor)
            .await
            .map_err(EntityError::Store)?;
        let mut entities = Vec::new();
        let mut seen = BTreeSet::new();
        for row in rows {
            let Some(rest) = row.key.strip_prefix(&prefix) else {
                continue;
            };
            let Some((encoded, id)) = rest.split_once(':') else {
                continue;
            };
            if encoded.len() != 16 || id.is_empty() || !seen.insert(id.to_string()) {
                continue;
            }
            let Some(entity) = load_entity(&*g, id).await? else {
                continue;
            };
            if let Some(AttributeValue::Timestamp(value)) = entity.attributes.get(key)
                && *value <= at_or_before
            {
                entities.push(entity);
            }
            if entities.len() >= limit {
                break;
            }
        }
        Ok(entities)
    }

    /// Emits one timer event for a due value and appends it to the feed.
    ///
    /// The event has kind [`EntityEventKind::Timer`].
    /// It has an empty `changed` list and a snapshot of the current entity.
    /// The event id is stable for one entity, key, and due value.
    /// The call appends through the change feed and writes no outbox row.
    pub async fn emit_timer(
        &self,
        entity: &Entity,
        key: &str,
        due_at: i64,
        now: i64,
    ) -> Result<EntityEvent, EntityError> {
        let Some(feed) = &self.feed else {
            return Err(EntityError::Feed(
                "timer event needs a change feed".to_string(),
            ));
        };
        validate_name("attribute name", key)?;
        let effective = self.resolve_refs(&entity.schemas).await?;
        let event_id = format!("timer-{}-{key}-{}", entity.id, encode_timestamp(due_at));
        let snapshot = Some(
            entity
                .attributes
                .iter()
                .map(|(name, value)| (name.clone(), value.as_json()))
                .collect(),
        );
        let event = EntityEvent {
            event_id: event_id.clone(),
            entity_id: entity.id.clone(),
            entity_version: entity.version,
            kind: EntityEventKind::Timer,
            schemas: event_schema_ids(&effective),
            changed: Vec::new(),
            actor: "system:timer".to_string(),
            causation_id: None,
            causation_depth: 0,
            correlation_id: event_id,
            snapshot,
            occurred_at: now,
        };
        feed.append(WalOp::Entity {
            event: event.clone(),
        })
        .await
        .map_err(|_| EntityError::Feed("timer feed append failed".to_string()))?;
        Ok(event)
    }

    /// True when a timer marker exists for one entity, key, and due value.
    pub async fn is_timer_fired(
        &self,
        entity_id: &str,
        key: &str,
        due_at: i64,
    ) -> Result<bool, EntityError> {
        let g = self.store.read().await;
        Ok(g.get_bytes(&timer_marker_key(entity_id, key, due_at))
            .await
            .map_err(EntityError::Store)?
            .is_some())
    }

    /// Writes a timer marker for one entity, key, and due value.
    ///
    /// The call takes the write lock and then the store write guard.
    /// It reloads the entity inside the lock.
    /// It writes the marker only when the entity exists and its current value
    /// for `key` is [`AttributeValue::Timestamp`] with `due_at`.
    /// The call returns `true` when it writes the marker.
    /// It returns `false` when the entity is absent or the value differs.
    /// The value is the current Unix time as JSON.
    /// The call is idempotent.
    pub async fn mark_timer_fired(
        &self,
        entity_id: &str,
        key: &str,
        due_at: i64,
    ) -> Result<bool, EntityError> {
        let now = chrono::Utc::now().timestamp();
        let bytes = serde_json::to_vec(&now).map_err(|e| EntityError::Internal(e.to_string()))?;
        let _write = self.write_lock.lock().await;
        let g = self.store.write().await;
        let Some(entity) = load_entity(&*g, entity_id).await? else {
            return Ok(false);
        };
        if entity.attributes.get(key) != Some(&AttributeValue::Timestamp(due_at)) {
            return Ok(false);
        }
        g.set_bytes(&timer_marker_key(entity_id, key, due_at), &bytes)
            .await
            .map(|_| true)
            .map_err(EntityError::Store)
    }

    /// Writes a timer marker and removes the time index row in one transaction.
    ///
    /// The call takes the write lock and then the store write guard.
    /// It reloads the current entity inside the lock.
    /// It returns `false` and changes nothing when the entity is absent.
    /// It returns `false` and changes nothing when the current value for
    /// `key` is not [`AttributeValue::Timestamp`] with `due_at`.
    /// The call writes the marker in the same value format as
    /// [`EntityStore::mark_timer_fired`].
    /// It deletes the `idx:time:` row for the entity and value.
    /// The marker write and the row delete commit in one transaction.
    /// A crash cannot leave one without the other.
    /// The call returns `true` when the transaction commits.
    pub async fn retire_timer(
        &self,
        entity_id: &str,
        key: &str,
        due_at: i64,
    ) -> Result<bool, EntityError> {
        let now = chrono::Utc::now().timestamp();
        let bytes = serde_json::to_vec(&now).map_err(|e| EntityError::Internal(e.to_string()))?;
        let _write = self.write_lock.lock().await;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(EntityError::Store)?;
        let Some(entity) = load_entity(&tx, entity_id).await? else {
            return Ok(false);
        };
        if entity.attributes.get(key) != Some(&AttributeValue::Timestamp(due_at)) {
            return Ok(false);
        }
        tx.set_bytes(&timer_marker_key(entity_id, key, due_at), &bytes)
            .await
            .map_err(EntityError::Store)?;
        tx.delete(&time_index_key(key, due_at, entity_id))
            .await
            .map_err(EntityError::Store)?;
        tx.commit().await.map_err(EntityError::Store)?;
        Ok(true)
    }

    /// Lists every entity, sorted by id.
    pub async fn list(&self) -> Result<Vec<Entity>, EntityError> {
        let g = self.store.read().await;
        let rows = scan_prefix(&*g, ENTITY_PREFIX).await?;
        let mut entities = Vec::new();
        for row in rows {
            let Some(rest) = row.key.strip_prefix(ENTITY_PREFIX) else {
                continue;
            };
            let Some(id) = rest.strip_suffix(META_SUFFIX) else {
                continue;
            };
            if id.is_empty() || id.contains(':') {
                continue;
            }
            if let Some(entity) = load_entity(&*g, id).await? {
                entities.push(entity);
            }
        }
        entities.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entities)
    }

    /// Backfills the entity index markers one time.
    ///
    /// The call returns early when the backfill marker exists.
    /// It takes the write lock and then the store write guard.
    /// It re-checks the marker inside the lock.
    /// It scans every `entity:{id}:meta` row and writes each missing marker.
    /// It writes the backfill marker last.
    /// A crash before the last write retries on the next call.
    /// Every write is idempotent.
    async fn backfill_entity_index(&self) -> Result<(), EntityError> {
        let marker = entity_backfill_marker();
        {
            let g = self.store.read().await;
            if g.get_bytes(&marker)
                .await
                .map_err(EntityError::Store)?
                .is_some()
            {
                return Ok(());
            }
        }

        let _write = self.write_lock.lock().await;
        let g = self.store.write().await;
        if g.get_bytes(&marker)
            .await
            .map_err(EntityError::Store)?
            .is_some()
        {
            return Ok(());
        }
        let rows = scan_prefix(&*g, ENTITY_PREFIX).await?;
        let mut seen = BTreeSet::new();
        for row in rows {
            let Some(rest) = row.key.strip_prefix(ENTITY_PREFIX) else {
                continue;
            };
            let Some(id) = rest.strip_suffix(META_SUFFIX) else {
                continue;
            };
            if id.is_empty() || id.contains(':') || !seen.insert(id.to_string()) {
                continue;
            }
            g.set_bytes(&entity_index_key(id), b"")
                .await
                .map_err(EntityError::Store)?;
        }
        g.set_bytes(&marker, b"")
            .await
            .map_err(EntityError::Store)?;
        Ok(())
    }

    /// Lists one page of every entity.
    ///
    /// The result is sorted by id.
    /// The call skips `offset` ids.
    /// It then loads at most `limit` entities.
    /// The call scans at most `offset + limit` entity markers.
    /// A `limit` of 0 returns an empty list.
    /// An offset above `MAX_PAGE_OFFSET` returns an invalid-input error.
    /// Use `after` for a deeper page.
    pub async fn list_page(&self, limit: usize, offset: usize) -> Result<Vec<Entity>, EntityError> {
        if offset > MAX_PAGE_OFFSET {
            return Err(EntityError::Invalid(format!(
                "offset must be at most {MAX_PAGE_OFFSET}. Use after to page deeper."
            )));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let max = offset.saturating_add(limit);
        let (mut entities, _) = self.list_after(max, None).await?;
        let skip = offset.min(entities.len());
        entities.drain(..skip);
        Ok(entities)
    }

    /// Lists one page of every entity in id order.
    ///
    /// An old store can lack the entity markers.
    /// The call then backfills every missing marker one time.
    /// The `idx:entity-meta:backfilled` marker records the pass.
    /// The pass takes the write lock and the store write guard.
    /// It re-checks the marker inside the lock.
    /// It scans the `entity:` family and writes one marker for each meta row.
    /// It writes the backfill marker last.
    /// A crash before that write retries on the next call.
    /// Every write is idempotent.
    /// The call then scans only the `idx:entity:` family.
    /// It starts after the `after` id when the caller gives a cursor.
    /// The call returns the entities and the cursor for the next page.
    /// The cursor is the last id of a full page.
    /// The cursor is `None` when the scan is exhausted.
    /// A stale or unknown cursor returns the ids after its sort position.
    /// A `limit` of 0 returns an empty list and no cursor.
    pub async fn list_after(
        &self,
        limit: usize,
        after: Option<&str>,
    ) -> Result<(Vec<Entity>, Option<String>), EntityError> {
        if limit == 0 {
            return Ok((Vec::new(), None));
        }
        self.backfill_entity_index().await?;
        let g = self.store.read().await;
        let start = match after {
            Some(cursor) => {
                validate_name("entity id", cursor)?;
                format!("{ENTITY_INDEX_PREFIX}{cursor}\0")
            }
            None => ENTITY_INDEX_PREFIX.to_string(),
        };
        let max = u32::try_from(limit).ok();
        let cursor = (Some(start), Some(prefix_scan_end(ENTITY_INDEX_PREFIX)));
        let markers = g
            .gets_bytes(max, Direction::Next, cursor)
            .await
            .map_err(EntityError::Store)?;
        let full = markers.len() == limit;
        let mut ids = Vec::with_capacity(markers.len());
        let mut seen = BTreeSet::new();
        for marker in markers {
            let Some(id) = marker.key.strip_prefix(ENTITY_INDEX_PREFIX) else {
                continue;
            };
            if id.is_empty() || id.contains(':') || !seen.insert(id.to_string()) {
                continue;
            }
            ids.push(id.to_string());
        }
        ids.sort();
        let next = if full { ids.last().cloned() } else { None };
        let mut entities = Vec::with_capacity(ids.len());
        for id in &ids {
            if let Some(entity) = load_entity(&*g, id).await? {
                entities.push(entity);
            }
        }
        Ok((entities, next))
    }

    /// Resolves schema ids to their latest versions and flattens them.
    async fn resolve_schemas(&self, ids: &[String]) -> Result<Vec<EffectiveSchema>, EntityError> {
        if ids.is_empty() {
            return Err(EntityError::Invalid(
                "at least one schema is required".to_string(),
            ));
        }
        let mut seen = BTreeSet::new();
        let mut refs = Vec::with_capacity(ids.len());
        for id in ids {
            validate_name("schema id", id)?;
            if !seen.insert(id.clone()) {
                return Err(EntityError::Invalid("duplicate schema id".to_string()));
            }
            let Some(def) = self.schemas.latest(id).await.map_err(map_schema_error)? else {
                return Err(EntityError::UnknownSchema(id.clone()));
            };
            refs.push(SchemaRef {
                id: def.id,
                version: def.version,
            });
        }
        self.resolve_refs(&refs).await
    }

    /// Flattens the exact pinned schema versions.
    async fn resolve_refs(&self, refs: &[SchemaRef]) -> Result<Vec<EffectiveSchema>, EntityError> {
        let mut effective = Vec::with_capacity(refs.len());
        for schema in refs {
            let Some(flat) = self
                .schemas
                .effective(&schema.id, schema.version)
                .await
                .map_err(map_schema_error)?
            else {
                return Err(EntityError::Internal(
                    "pinned schema version is missing".to_string(),
                ));
            };
            effective.push(flat);
        }
        Ok(effective)
    }

    /// True when any stored schema marks `key` as indexed.
    async fn attribute_is_indexed(&self, key: &str) -> Result<bool, EntityError> {
        for def in self.schemas.list().await.map_err(map_schema_error)? {
            let Some(effective) = self
                .schemas
                .effective(&def.id, def.version)
                .await
                .map_err(map_schema_error)?
            else {
                continue;
            };
            if effective
                .attributes
                .get(key)
                .is_some_and(|attribute| attribute.indexed)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Returns the schema ids that apply to one entity.
///
/// The list holds each pinned id and every ancestor id.
/// The list is sorted and has no duplicates.
fn event_schema_ids(effective: &[EffectiveSchema]) -> Vec<String> {
    let mut ids = BTreeSet::new();
    for schema in effective {
        ids.insert(schema.id.clone());
        ids.extend(schema.ancestors.iter().cloned());
    }
    ids.into_iter().collect()
}

/// Builds one entity event from the before and after states.
///
/// The event id is a fresh UUID v7 string.
/// The correlation id falls back to the event id.
/// The snapshot holds the after state.
/// A delete has no after state, so its snapshot holds the before state.
fn build_event(
    before: Option<&Entity>,
    after: Option<&Entity>,
    schemas: Vec<String>,
    ctx: &WriteContext,
) -> Result<EntityEvent, EntityError> {
    let kind = match (before, after) {
        (None, _) => EntityEventKind::Created,
        (_, None) => EntityEventKind::Deleted,
        _ => EntityEventKind::Updated,
    };
    let entity = after
        .or(before)
        .ok_or_else(|| EntityError::Internal("entity change has no state".to_string()))?;
    let event_id = uuid::Uuid::now_v7().to_string();
    let correlation_id = ctx
        .correlation_id
        .clone()
        .unwrap_or_else(|| event_id.clone());
    let snapshot = Some(
        entity
            .attributes
            .iter()
            .map(|(key, value)| (key.clone(), value.as_json()))
            .collect(),
    );
    Ok(EntityEvent {
        event_id,
        entity_id: entity.id.clone(),
        entity_version: entity.version,
        kind,
        schemas,
        changed: changed_attributes(before, after)?,
        actor: ctx.actor.clone(),
        causation_id: ctx.causation_id.clone(),
        causation_depth: ctx.causation_depth,
        correlation_id,
        snapshot,
        occurred_at: chrono::Utc::now().timestamp(),
    })
}

/// Builds one schema-applied event from the after state.
///
/// The event has an empty `changed` list.
/// The event id is a fresh UUID v7 string.
/// The correlation id falls back to the event id.
fn build_schema_applied_event(
    entity: &Entity,
    schemas: Vec<String>,
    ctx: &WriteContext,
) -> Result<EntityEvent, EntityError> {
    let event_id = uuid::Uuid::now_v7().to_string();
    let correlation_id = ctx
        .correlation_id
        .clone()
        .unwrap_or_else(|| event_id.clone());
    let snapshot = Some(
        entity
            .attributes
            .iter()
            .map(|(key, value)| (key.clone(), value.as_json()))
            .collect(),
    );
    Ok(EntityEvent {
        event_id,
        entity_id: entity.id.clone(),
        entity_version: entity.version,
        kind: EntityEventKind::SchemaApplied,
        schemas,
        changed: Vec::new(),
        actor: ctx.actor.clone(),
        causation_id: ctx.causation_id.clone(),
        causation_depth: ctx.causation_depth,
        correlation_id,
        snapshot,
        occurred_at: chrono::Utc::now().timestamp(),
    })
}

/// Returns one change for each attribute whose value differs.
///
/// An absent value before the change sets `old` to `None`.
/// An absent value after the change sets `new` to `None`.
fn changed_attributes(
    before: Option<&Entity>,
    after: Option<&Entity>,
) -> Result<Vec<AttributeChange>, EntityError> {
    let empty: BTreeMap<String, AttributeValue> = BTreeMap::new();
    let before_attrs = before.map(|entity| &entity.attributes).unwrap_or(&empty);
    let after_attrs = after.map(|entity| &entity.attributes).unwrap_or(&empty);
    let mut keys = BTreeSet::new();
    keys.extend(before_attrs.keys().map(String::as_str));
    keys.extend(after_attrs.keys().map(String::as_str));

    let mut changes = Vec::new();
    for key in keys {
        let old = before_attrs.get(key);
        let new = after_attrs.get(key);
        if old == new {
            continue;
        }
        changes.push(AttributeChange {
            key: key.to_string(),
            old: old.map(attribute_json).transpose()?,
            new: new.map(attribute_json).transpose()?,
        });
    }
    Ok(changes)
}

/// Returns the tagged JSON form of one attribute value.
fn attribute_json(value: &AttributeValue) -> Result<serde_json::Value, EntityError> {
    serde_json::to_value(value).map_err(|e| EntityError::Internal(e.to_string()))
}

/// The key for one pending outbox event.
fn outbox_key(event_id: &str) -> String {
    format!("{OUTBOX_PREFIX}{event_id}")
}

/// The key that holds the durable pending outbox row count.
fn outbox_pending_key() -> &'static str {
    OUTBOX_PENDING_KEY
}

/// Reads the pending outbox count.
///
/// The call returns `None` when the counter key is absent.
async fn read_outbox_pending<S>(store: &S) -> Result<Option<u64>, EntityError>
where
    S: GetSet + ?Sized,
{
    let Some(bytes) = store
        .get_bytes(outbox_pending_key())
        .await
        .map_err(EntityError::Store)?
    else {
        return Ok(None);
    };
    let count = serde_json::from_slice(&bytes)
        .map_err(|e| EntityError::Internal(format!("outbox counter is invalid: {e}")))?;
    Ok(Some(count))
}

/// Writes the pending outbox count as JSON.
async fn write_outbox_pending<S>(store: &S, count: u64) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let bytes = serde_json::to_vec(&count).map_err(|e| EntityError::Internal(e.to_string()))?;
    store
        .set_bytes(outbox_pending_key(), &bytes)
        .await
        .map(|_| ())
        .map_err(EntityError::Store)
}

/// Adds `delta` to the pending outbox count.
///
/// When the counter key is absent, the call counts the outbox rows one time.
/// The caller must run the call in the same transaction as the outbox row
/// writes and before those writes.
/// The count then excludes the new rows.
/// The addition saturates at [`u64::MAX`].
async fn increment_outbox_pending<S>(store: &S, delta: u64) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let current = match read_outbox_pending(store).await? {
        Some(count) => count,
        None => u64::try_from(scan_prefix(store, OUTBOX_PREFIX).await?.len()).unwrap_or(u64::MAX),
    };
    write_outbox_pending(store, current.saturating_add(delta)).await
}

/// Subtracts `delta` from the pending outbox count.
///
/// The subtraction saturates at zero.
/// The counter never goes below zero.
async fn decrement_outbox_pending<S>(store: &S, delta: u64) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let current = read_outbox_pending(store).await?.unwrap_or(0);
    write_outbox_pending(store, current.saturating_sub(delta)).await
}

/// The merged attribute definitions of every pinned schema.
struct MergedSchema {
    /// The merged attributes, keyed by name.
    attributes: BTreeMap<String, AttributeDef>,
    /// The pinned schema ids and their inherited ids.
    schema_ids: BTreeSet<String>,
}

/// The metadata row of an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EntityMeta {
    /// The entity id.
    id: String,
    /// The entity version.
    version: u64,
    /// The pinned schema versions.
    schemas: Vec<SchemaRef>,
    /// The creation time as a Unix timestamp in seconds.
    created_at: i64,
    /// The last update time as a Unix timestamp in seconds.
    updated_at: i64,
}

/// Merges the effective attributes of every pinned schema.
///
/// A repeated attribute must have the same type.
/// The call merges the `required`, `indexed`, and `unique` flags with OR.
/// Two different defaults for one attribute are a conflict.
fn merge_schemas(effective: &[EffectiveSchema]) -> Result<MergedSchema, EntityError> {
    let mut attributes: BTreeMap<String, AttributeDef> = BTreeMap::new();
    let mut schema_ids = BTreeSet::new();
    for schema in effective {
        schema_ids.insert(schema.id.clone());
        schema_ids.extend(schema.ancestors.iter().cloned());
        for (name, def) in &schema.attributes {
            match attributes.get_mut(name) {
                None => {
                    attributes.insert(name.clone(), def.clone());
                }
                Some(existing) => {
                    if existing.ty != def.ty {
                        return Err(EntityError::SchemaConflict(format!(
                            "attribute type conflict: {name}"
                        )));
                    }
                    existing.required |= def.required;
                    existing.indexed |= def.indexed;
                    existing.unique |= def.unique;
                    match (&existing.default, &def.default) {
                        (Some(left), Some(right)) if left != right => {
                            return Err(EntityError::SchemaConflict(format!(
                                "attribute default conflict: {name}"
                            )));
                        }
                        (None, Some(_)) => {
                            existing.default = def.default.clone();
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(MergedSchema {
        attributes,
        schema_ids,
    })
}

/// Returns the pinned references of the effective schemas.
fn effective_refs(effective: &[EffectiveSchema]) -> Vec<SchemaRef> {
    effective
        .iter()
        .map(|schema| SchemaRef {
            id: schema.id.clone(),
            version: schema.version,
        })
        .collect()
}

/// Rejects attributes that no applied schema defines.
fn check_known(
    attributes: &BTreeMap<String, AttributeValue>,
    defs: &BTreeMap<String, AttributeDef>,
) -> Result<(), EntityError> {
    for key in attributes.keys() {
        if !defs.contains_key(key) {
            return Err(EntityError::UnknownAttribute(key.clone()));
        }
    }
    Ok(())
}

/// Checks that every schema default matches its declared type.
fn validate_defaults(defs: &BTreeMap<String, AttributeDef>) -> Result<(), EntityError> {
    for (name, def) in defs {
        if let Some(raw) = &def.default
            && value_from_json(raw, def.ty).is_none()
        {
            return Err(EntityError::SchemaConflict(format!(
                "attribute default type mismatch: {name}"
            )));
        }
    }
    Ok(())
}

/// Fills each missing attribute from its schema default.
fn apply_defaults(
    attributes: &mut BTreeMap<String, AttributeValue>,
    defs: &BTreeMap<String, AttributeDef>,
) -> Result<(), EntityError> {
    for (name, def) in defs {
        if attributes.contains_key(name) {
            continue;
        }
        let Some(raw) = &def.default else {
            continue;
        };
        let value = value_from_json(raw, def.ty).ok_or_else(|| {
            EntityError::SchemaConflict(format!("attribute default type mismatch: {name}"))
        })?;
        attributes.insert(name.clone(), value);
    }
    Ok(())
}

/// Converts one JSON default into the declared type.
fn value_from_json(value: &serde_json::Value, ty: AttributeType) -> Option<AttributeValue> {
    match ty {
        AttributeType::String => value
            .as_str()
            .map(|value| AttributeValue::String(value.to_string())),
        AttributeType::Integer => value.as_i64().map(AttributeValue::Integer),
        AttributeType::Float => value.as_f64().map(AttributeValue::Float),
        AttributeType::Boolean => value.as_bool().map(AttributeValue::Boolean),
        AttributeType::Timestamp => value.as_i64().map(AttributeValue::Timestamp),
        AttributeType::Json => Some(AttributeValue::Json(value.clone())),
        AttributeType::EntityRef => value
            .as_str()
            .map(|value| AttributeValue::EntityRef(value.to_string())),
    }
}

/// Checks that every value matches its declared type.
fn check_types(
    attributes: &BTreeMap<String, AttributeValue>,
    defs: &BTreeMap<String, AttributeDef>,
) -> Result<(), EntityError> {
    for (key, value) in attributes {
        let Some(def) = defs.get(key) else {
            return Err(EntityError::UnknownAttribute(key.clone()));
        };
        if !type_matches(def.ty, value) {
            return Err(EntityError::TypeMismatch(key.clone()));
        }
    }
    Ok(())
}

/// True when `value` has the declared type.
fn type_matches(ty: AttributeType, value: &AttributeValue) -> bool {
    matches!(
        (ty, value),
        (AttributeType::String, AttributeValue::String(_))
            | (AttributeType::Integer, AttributeValue::Integer(_))
            | (AttributeType::Float, AttributeValue::Float(_))
            | (AttributeType::Boolean, AttributeValue::Boolean(_))
            | (AttributeType::Timestamp, AttributeValue::Timestamp(_))
            | (AttributeType::Json, AttributeValue::Json(_))
            | (AttributeType::EntityRef, AttributeValue::EntityRef(_))
    )
}

/// Checks that every required attribute has a value.
fn check_required(
    attributes: &BTreeMap<String, AttributeValue>,
    defs: &BTreeMap<String, AttributeDef>,
) -> Result<(), EntityError> {
    for (name, def) in defs {
        if def.required && !attributes.contains_key(name) {
            return Err(EntityError::MissingRequired(name.clone()));
        }
    }
    Ok(())
}

/// Validates cloned attributes against a target attribute map.
///
/// The call applies defaults to the clone only.
/// The call returns the first issue.
fn validate_attributes(
    attributes: &BTreeMap<String, AttributeValue>,
    defs: &BTreeMap<String, AttributeDef>,
) -> Result<(), RevalidationIssue> {
    let mut candidate = attributes.clone();
    check_known(&candidate, defs).map_err(revalidation_issue)?;
    validate_defaults(defs).map_err(revalidation_issue)?;
    apply_defaults(&mut candidate, defs).map_err(revalidation_issue)?;
    check_types(&candidate, defs).map_err(revalidation_issue)?;
    check_required(&candidate, defs).map_err(revalidation_issue)?;
    Ok(())
}

/// Converts an entity error into one revalidation issue.
fn revalidation_issue(error: EntityError) -> RevalidationIssue {
    match error {
        EntityError::UnknownAttribute(name) => RevalidationIssue::UnknownAttribute(name),
        EntityError::TypeMismatch(name) => RevalidationIssue::TypeMismatch(name),
        EntityError::MissingRequired(name) => RevalidationIssue::MissingRequired(name),
        other => RevalidationIssue::SchemaConflict(other.to_string()),
    }
}

/// Checks every unique value against the unique index.
async fn check_unique_values<S>(
    store: &S,
    entity: &Entity,
    defs: &BTreeMap<String, AttributeDef>,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    for (key, value) in &entity.attributes {
        if let Some(def) = defs.get(key)
            && def.unique
        {
            check_unique(store, &entity.id, key, value).await?;
        }
    }
    Ok(())
}

/// Checks one unique value against the unique index.
///
/// The scan reads every marker for the value hash.
/// A marker that names the same entity is idempotent.
/// A marker that names another entity is a violation only when the exact
/// stored value is the same.
async fn check_unique<S>(
    store: &S,
    entity_id: &str,
    key: &str,
    value: &AttributeValue,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let hash = value_hash(value)?;
    let prefix = unique_prefix(key, &hash);
    for marker in scan_prefix(store, &prefix).await? {
        let Some(owner) = marker.key.strip_prefix(&prefix) else {
            continue;
        };
        if owner.is_empty() || owner.contains(':') || owner == entity_id {
            continue;
        }
        let Some(existing) = load_entity(store, owner).await? else {
            continue;
        };
        if existing.attributes.get(key) == Some(value) {
            return Err(EntityError::UniqueViolation(key.to_string()));
        }
    }
    Ok(())
}

/// Writes the metadata row of one entity.
///
/// The call changes no attribute row and no index row.
async fn put_meta_row<S>(store: &S, entity: &Entity) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let meta = EntityMeta {
        id: entity.id.clone(),
        version: entity.version,
        schemas: entity.schemas.clone(),
        created_at: entity.created_at,
        updated_at: entity.updated_at,
    };
    let meta_bytes = serde_json::to_vec(&meta).map_err(|e| EntityError::Internal(e.to_string()))?;
    store
        .set_bytes(&meta_key(&entity.id), &meta_bytes)
        .await
        .map(|_| ())
        .map_err(EntityError::Store)
}

/// Writes the metadata, attribute, and index rows of one entity.
async fn put_entity_rows<S>(
    store: &S,
    entity: &Entity,
    merged: &MergedSchema,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let meta = EntityMeta {
        id: entity.id.clone(),
        version: entity.version,
        schemas: entity.schemas.clone(),
        created_at: entity.created_at,
        updated_at: entity.updated_at,
    };
    let meta_bytes = serde_json::to_vec(&meta).map_err(|e| EntityError::Internal(e.to_string()))?;
    store
        .set_bytes(&meta_key(&entity.id), &meta_bytes)
        .await
        .map_err(EntityError::Store)?;
    store
        .set_bytes(&entity_index_key(&entity.id), b"")
        .await
        .map_err(EntityError::Store)?;

    for (key, value) in &entity.attributes {
        let def = merged
            .attributes
            .get(key)
            .ok_or_else(|| EntityError::UnknownAttribute(key.clone()))?;
        let bytes = serde_json::to_vec(value).map_err(|e| EntityError::Internal(e.to_string()))?;
        store
            .set_bytes(&attr_key(&entity.id, key), &bytes)
            .await
            .map_err(EntityError::Store)?;
        if def.indexed {
            store
                .set_bytes(&attr_index_key(key, value, &entity.id)?, b"")
                .await
                .map_err(EntityError::Store)?;
            store
                .set_bytes(&attr_key_index_key(key), b"")
                .await
                .map_err(EntityError::Store)?;
        }
        if is_time_attribute(def)
            && let AttributeValue::Timestamp(timestamp) = value
        {
            store
                .set_bytes(&time_index_key(key, *timestamp, &entity.id), b"")
                .await
                .map_err(EntityError::Store)?;
            store
                .set_bytes(&time_key_index_key(key), b"")
                .await
                .map_err(EntityError::Store)?;
        }
        if def.unique {
            store
                .set_bytes(
                    &unique_key(key, &value_hash(value)?, &entity.id),
                    entity.id.as_bytes(),
                )
                .await
                .map_err(EntityError::Store)?;
        }
    }

    for schema_id in &merged.schema_ids {
        store
            .set_bytes(&schema_index_key(schema_id, &entity.id), b"")
            .await
            .map_err(EntityError::Store)?;
    }
    Ok(())
}

/// Deletes every mutable row of one entity.
///
/// The call removes the attribute rows, the attribute markers, and the
/// unique markers.
async fn delete_mutable_rows<S>(
    store: &S,
    entity: &Entity,
    merged: &MergedSchema,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    for (key, value) in &entity.attributes {
        store
            .delete(&attr_key(&entity.id, key))
            .await
            .map_err(EntityError::Store)?;
        let Some(def) = merged.attributes.get(key) else {
            continue;
        };
        if def.indexed {
            store
                .delete(&attr_index_key(key, value, &entity.id)?)
                .await
                .map_err(EntityError::Store)?;
        }
        if is_time_attribute(def)
            && let AttributeValue::Timestamp(timestamp) = value
        {
            store
                .delete(&time_index_key(key, *timestamp, &entity.id))
                .await
                .map_err(EntityError::Store)?;
        }
        if def.unique {
            delete_unique_if_owned(store, key, value, &entity.id).await?;
        }
    }
    Ok(())
}

/// Deletes the timer markers of timestamp values that changed.
///
/// A removed attribute also counts as a change.
/// The marker of an unchanged value stays, so the value fires one time only.
async fn delete_changed_timer_markers<S>(
    store: &S,
    before: &Entity,
    after: &Entity,
    merged: &MergedSchema,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    for (key, value) in &before.attributes {
        let Some(def) = merged.attributes.get(key) else {
            continue;
        };
        if !is_time_attribute(def) || after.attributes.get(key) == Some(value) {
            continue;
        }
        if let AttributeValue::Timestamp(timestamp) = value {
            store
                .delete(&timer_marker_key(&before.id, key, *timestamp))
                .await
                .map_err(EntityError::Store)?;
        }
    }
    Ok(())
}

/// Deletes every timer marker of one entity.
async fn delete_all_timer_markers<S>(
    store: &S,
    entity: &Entity,
    merged: &MergedSchema,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    for (key, value) in &entity.attributes {
        let Some(def) = merged.attributes.get(key) else {
            continue;
        };
        if !is_time_attribute(def) {
            continue;
        }
        if let AttributeValue::Timestamp(timestamp) = value {
            store
                .delete(&timer_marker_key(&entity.id, key, *timestamp))
                .await
                .map_err(EntityError::Store)?;
        }
    }
    Ok(())
}

/// Deletes the unique marker of this entity for one value.
async fn delete_unique_if_owned<S>(
    store: &S,
    key: &str,
    value: &AttributeValue,
    entity_id: &str,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let marker = unique_key(key, &value_hash(value)?, entity_id);
    store.delete(&marker).await.map_err(EntityError::Store)?;
    Ok(())
}

/// Reads the metadata and attributes of one entity.
async fn load_entity<S>(store: &S, id: &str) -> Result<Option<Entity>, EntityError>
where
    S: GetSet + ?Sized,
{
    let Some(bytes) = store
        .get_bytes(&meta_key(id))
        .await
        .map_err(EntityError::Store)?
    else {
        return Ok(None);
    };
    let meta: EntityMeta =
        serde_json::from_slice(&bytes).map_err(|e| EntityError::Internal(e.to_string()))?;
    let attributes = load_attributes(store, id).await?;
    Ok(Some(Entity {
        id: meta.id,
        version: meta.version,
        schemas: meta.schemas,
        attributes,
        created_at: meta.created_at,
        updated_at: meta.updated_at,
    }))
}

/// Reads every attribute row of one entity.
async fn load_attributes<S>(
    store: &S,
    id: &str,
) -> Result<BTreeMap<String, AttributeValue>, EntityError>
where
    S: GetSet + ?Sized,
{
    let prefix = attr_prefix(id);
    let rows = scan_prefix(store, &prefix).await?;
    let mut attributes = BTreeMap::new();
    for row in rows {
        let Some(key) = row.key.strip_prefix(&prefix) else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        let value: AttributeValue =
            serde_json::from_slice(&row.value).map_err(|e| EntityError::Internal(e.to_string()))?;
        attributes.insert(key.to_string(), value);
    }
    Ok(attributes)
}

/// Scans a key range that ends at the `prefix:` family bound.
async fn scan_prefix<S>(store: &S, prefix: &str) -> Result<Vec<KeyValue>, EntityError>
where
    S: GetSet + ?Sized,
{
    debug_assert!(prefix.ends_with(':'));
    let cursor = (Some(prefix.to_string()), Some(prefix_scan_end(prefix)));
    store
        .gets_bytes(None, Direction::Next, cursor)
        .await
        .map_err(EntityError::Store)
}

/// Scans at most `limit` rows of a key range that ends at the `prefix:` bound.
async fn scan_prefix_bounded<S>(
    store: &S,
    prefix: &str,
    limit: usize,
) -> Result<Vec<KeyValue>, EntityError>
where
    S: GetSet + ?Sized,
{
    debug_assert!(prefix.ends_with(':'));
    let max = u32::try_from(limit).ok();
    let cursor = (Some(prefix.to_string()), Some(prefix_scan_end(prefix)));
    store
        .gets_bytes(max, Direction::Next, cursor)
        .await
        .map_err(EntityError::Store)
}

/// The exclusive upper bound for a `prefix:` range scan (`:` to `;`).
fn prefix_scan_end(prefix: &str) -> String {
    debug_assert!(prefix.ends_with(':'));
    let mut end = prefix.to_string();
    end.pop();
    end.push(';');
    end
}

/// The key that holds the metadata of an entity.
fn meta_key(id: &str) -> String {
    format!("{ENTITY_PREFIX}{id}{META_SUFFIX}")
}

/// The marker key for one entity.
fn entity_index_key(id: &str) -> String {
    format!("{ENTITY_INDEX_PREFIX}{id}")
}

/// The marker key for the one-time entity marker backfill.
fn entity_backfill_marker() -> String {
    format!("{ENTITY_META_PREFIX}{ENTITY_BACKFILL_SUFFIX}")
}

/// The key that holds one attribute of an entity.
fn attr_key(id: &str, key: &str) -> String {
    format!("{ENTITY_PREFIX}{id}{ATTR_INFIX}{key}")
}

/// The scan prefix for every attribute of one entity.
fn attr_prefix(id: &str) -> String {
    format!("{ENTITY_PREFIX}{id}{ATTR_INFIX}")
}

/// The marker key for one schema and entity pair.
fn schema_index_key(schema_id: &str, entity_id: &str) -> String {
    format!("{SCHEMA_INDEX_PREFIX}{schema_id}:{entity_id}")
}

/// The marker key for one indexed attribute value.
fn attr_index_key(
    key: &str,
    value: &AttributeValue,
    entity_id: &str,
) -> Result<String, EntityError> {
    Ok(format!(
        "{ATTR_INDEX_PREFIX}{key}:{}:{entity_id}",
        value_hash(value)?
    ))
}

/// The marker key for one indexed attribute key.
fn attr_key_index_key(key: &str) -> String {
    format!("{ATTR_KEY_PREFIX}{key}")
}

/// The marker key for one unique attribute value and entity.
fn unique_key(key: &str, hash: &str, entity_id: &str) -> String {
    format!("{UNIQUE_INDEX_PREFIX}{key}:{hash}:{entity_id}")
}

/// The scan prefix for every unique marker of one value hash.
fn unique_prefix(key: &str, hash: &str) -> String {
    format!("{UNIQUE_INDEX_PREFIX}{key}:{hash}:")
}

/// The marker key for one indexed timestamp value.
fn time_index_key(key: &str, timestamp: i64, entity_id: &str) -> String {
    format!(
        "{TIME_INDEX_PREFIX}{key}:{}:{entity_id}",
        encode_timestamp(timestamp)
    )
}

/// The marker key for one attribute key with a time row.
fn time_key_index_key(key: &str) -> String {
    format!("{TIME_KEY_INDEX_PREFIX}{key}")
}

/// The marker key for the one-time time key backfill.
fn time_key_backfill_marker() -> String {
    format!("{TIME_KEY_META_PREFIX}{TIME_KEY_BACKFILL_SUFFIX}")
}

/// Returns the sorted attribute keys of a set of time key markers.
fn time_key_marker_keys(rows: Vec<KeyValue>) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for row in rows {
        let Some(key) = row.key.strip_prefix(TIME_KEY_INDEX_PREFIX) else {
            continue;
        };
        if !key.is_empty() {
            keys.insert(key.to_string());
        }
    }
    keys.into_iter().collect()
}

/// Returns the sorted attribute keys of a set of time rows.
fn time_row_keys(rows: Vec<KeyValue>) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for row in rows {
        let Some(rest) = row.key.strip_prefix(TIME_INDEX_PREFIX) else {
            continue;
        };
        let Some((key, _)) = rest.split_once(':') else {
            continue;
        };
        if !key.is_empty() {
            keys.insert(key.to_string());
        }
    }
    keys.into_iter().collect()
}

/// The marker key for one fired timer value.
fn timer_marker_key(entity_id: &str, key: &str, timestamp: i64) -> String {
    format!(
        "{TIMER_MARKER_PREFIX}{entity_id}:{key}:{}",
        encode_timestamp(timestamp)
    )
}

/// Encodes a timestamp so that key order equals numeric time order.
///
/// The call XORs the `i64` bits with the sign bit.
/// The result is 16 lowercase hex digits.
fn encode_timestamp(value: i64) -> String {
    format!("{:016x}", (value as u64) ^ 0x8000_0000_0000_0000)
}

/// True when an attribute is an indexed timestamp.
fn is_time_attribute(def: &AttributeDef) -> bool {
    def.ty == AttributeType::Timestamp && def.indexed
}

/// Returns the lowercase SHA-256 hex of the canonical tagged JSON value.
fn value_hash(value: &AttributeValue) -> Result<String, EntityError> {
    let bytes = serde_json::to_vec(value).map_err(|e| EntityError::Internal(e.to_string()))?;
    let digest = Sha256::digest(&bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(out)
}

/// Maps a schema registry error into an entity error.
fn map_schema_error(error: SchemaError) -> EntityError {
    match error {
        SchemaError::Store(error) => EntityError::Store(error),
        SchemaError::TypeConflict(name) => {
            EntityError::SchemaConflict(format!("attribute type conflict: {name}"))
        }
        SchemaError::Cycle => EntityError::SchemaConflict("schema inheritance cycle".to_string()),
        SchemaError::Invalid(message) | SchemaError::NotFound(message) => {
            EntityError::Invalid(message)
        }
        SchemaError::Internal(message) => EntityError::Internal(message),
    }
}

/// Checks an id or a name against the storage key rules.
///
/// The value must be 1 to 128 bytes.
/// It may contain only lowercase ASCII letters, digits, `_`, and `-`.
/// These rules reject `:` and `/`, so a value cannot inject a key.
fn validate_name(kind: &str, value: &str) -> Result<(), EntityError> {
    if value.is_empty() {
        return Err(EntityError::Invalid(format!("{kind} is empty")));
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(EntityError::Invalid(format!(
            "{kind} is longer than 128 bytes"
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(EntityError::Invalid(format!(
            "{kind} has an invalid character"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::eav::schema::SchemaDraft;

    async fn new_store() -> (EntityStore, SchemaRegistry, OxKvStore) {
        let registry =
            SchemaRegistry::new(build_test_store(&test_prefix("eav-store-schema")).await);
        let raw = build_test_store(&test_prefix("eav-store")).await;
        let store = EntityStore::new(raw.clone(), registry.clone());
        (store, registry, raw)
    }

    fn attr(name: &str, ty: AttributeType) -> AttributeDef {
        AttributeDef {
            name: name.to_string(),
            ty,
            required: false,
            indexed: false,
            unique: false,
            default: None,
        }
    }

    fn full_attr(
        name: &str,
        ty: AttributeType,
        required: bool,
        indexed: bool,
        unique: bool,
        default: Option<serde_json::Value>,
    ) -> AttributeDef {
        AttributeDef {
            name: name.to_string(),
            ty,
            required,
            indexed,
            unique,
            default,
        }
    }

    fn schema(id: &str, extends: &[&str], attrs: Vec<AttributeDef>) -> SchemaDraft {
        SchemaDraft {
            id: id.to_string(),
            extends: extends.iter().map(|value| value.to_string()).collect(),
            attributes: attrs.into_iter().map(|a| (a.name.clone(), a)).collect(),
        }
    }

    fn draft(id: &str, schemas: &[&str], attrs: Vec<(&str, AttributeValue)>) -> EntityDraft {
        EntityDraft {
            id: id.to_string(),
            schemas: schemas.iter().map(|value| value.to_string()).collect(),
            attributes: attrs
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
        }
    }

    fn patch(attrs: Vec<(&str, Option<AttributeValue>)>) -> EntityPatch {
        EntityPatch {
            attributes: attrs
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
        }
    }

    fn s(value: &str) -> AttributeValue {
        AttributeValue::String(value.to_string())
    }

    fn i(value: i64) -> AttributeValue {
        AttributeValue::Integer(value)
    }

    fn t(value: i64) -> AttributeValue {
        AttributeValue::Timestamp(value)
    }

    fn ctx() -> WriteContext {
        WriteContext::new("tester")
    }

    /// Builds a store with one `task` schema that has a timestamp `due`
    /// and a string `title`.
    async fn timer_store() -> (EntityStore, OxKvStore) {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    full_attr("due", AttributeType::Timestamp, false, true, false, None),
                    attr("title", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        (store, raw)
    }

    /// Creates one `task` entity with a `due` value.
    async fn create_task(store: &EntityStore, id: &str, due: i64) {
        store
            .create(draft(id, &["task"], vec![("due", t(due))]), &ctx())
            .await
            .unwrap();
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

    async fn outbox_keys(store: &OxKvStore) -> Vec<String> {
        all_keys(store)
            .await
            .into_iter()
            .filter(|key| key.starts_with(OUTBOX_PREFIX))
            .collect()
    }

    async fn pending_counter(store: &OxKvStore) -> Option<u64> {
        store
            .get_bytes(outbox_pending_key())
            .await
            .unwrap()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }

    fn tagged(value: &AttributeValue) -> serde_json::Value {
        serde_json::to_value(value).unwrap()
    }

    /// A [`ChangeSink`] test double that records every operation.
    ///
    /// `fail_next` makes a given number of appends fail.
    struct RecordingFeed {
        ops: std::sync::Mutex<Vec<WalOp>>,
        failures: std::sync::atomic::AtomicUsize,
    }

    impl RecordingFeed {
        fn new() -> Self {
            Self {
                ops: std::sync::Mutex::new(Vec::new()),
                failures: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn set_failing(&self, failing: bool) {
            self.failures.store(
                if failing { usize::MAX } else { 0 },
                std::sync::atomic::Ordering::SeqCst,
            );
        }

        fn fail_next(&self, count: usize) {
            self.failures
                .store(count, std::sync::atomic::Ordering::SeqCst);
        }

        fn ops(&self) -> Vec<WalOp> {
            self.ops.lock().unwrap().clone()
        }

        fn events(&self) -> Vec<EntityEvent> {
            self.ops()
                .into_iter()
                .filter_map(|op| match op {
                    WalOp::Entity { event } => Some(event),
                    _ => None,
                })
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl ChangeSink for RecordingFeed {
        async fn append(&self, op: WalOp) -> anyhow::Result<()> {
            let remaining = self.failures.load(std::sync::atomic::Ordering::SeqCst);
            if remaining > 0 {
                self.failures
                    .store(remaining - 1, std::sync::atomic::Ordering::SeqCst);
                return Err(anyhow::anyhow!("feed down"));
            }
            self.ops.lock().unwrap().push(op);
            Ok(())
        }
    }

    #[tokio::test]
    async fn create_get_and_delete_round_trip() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![
                    attr("name", AttributeType::String),
                    attr("age", AttributeType::Integer),
                ],
            ))
            .await
            .unwrap();

        let change = store
            .create(
                draft(
                    "e1",
                    &["person"],
                    vec![("name", s("Alice")), ("age", i(30))],
                ),
                &ctx(),
            )
            .await
            .unwrap();

        assert!(change.before.is_none());
        let created = change.after.unwrap();
        assert_eq!(created.version, 1);
        assert_eq!(store.get("e1").await.unwrap(), Some(created.clone()));

        let deleted = store.delete("e1", 1, &ctx()).await.unwrap();
        assert_eq!(deleted.before, Some(created));
        assert_eq!(deleted.after, None);
        assert_eq!(store.get("e1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn version_starts_at_one_and_update_increments_it() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("age", AttributeType::Integer)],
            ))
            .await
            .unwrap();
        let created = store
            .create(draft("e1", &["person"], vec![("age", i(30))]), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();
        assert_eq!(created.version, 1);

        let changed = store
            .update("e1", 1, patch(vec![("age", Some(i(31)))]), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();

        assert_eq!(changed.version, 2);
        assert_eq!(store.get("e1").await.unwrap().unwrap(), changed);
    }

    #[tokio::test]
    async fn version_conflict_changes_nothing() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("age", AttributeType::Integer)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["person"], vec![("age", i(30))]), &ctx())
            .await
            .unwrap();

        let result = store
            .update("e1", 2, patch(vec![("age", Some(i(31)))]), &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::VersionConflict)));
        let entity = store.get("e1").await.unwrap().unwrap();
        assert_eq!(entity.version, 1);
        assert_eq!(entity.attributes["age"], i(30));
    }

    #[tokio::test]
    async fn unknown_schema_fails() {
        let (store, _registry, raw) = new_store().await;

        let result = store.create(draft("e1", &["ghost"], vec![]), &ctx()).await;

        assert!(matches!(result, Err(EntityError::UnknownSchema(id)) if id == "ghost"));
        assert!(all_keys(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn duplicate_entity_id_fails() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();

        let result = store.create(draft("e1", &["person"], vec![]), &ctx()).await;

        assert!(matches!(result, Err(EntityError::AlreadyExists(id)) if id == "e1"));
    }

    #[tokio::test]
    async fn unknown_attribute_fails() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("name", AttributeType::String)],
            ))
            .await
            .unwrap();

        let result = store
            .create(draft("e1", &["person"], vec![("ghost", s("x"))]), &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::UnknownAttribute(key)) if key == "ghost"));
    }

    #[tokio::test]
    async fn type_mismatch_fails() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("age", AttributeType::Integer)],
            ))
            .await
            .unwrap();

        let result = store
            .create(draft("e1", &["person"], vec![("age", s("30"))]), &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::TypeMismatch(key)) if key == "age"));
    }

    #[tokio::test]
    async fn missing_required_attribute_fails() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![full_attr(
                    "name",
                    AttributeType::String,
                    true,
                    false,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();

        let result = store.create(draft("e1", &["person"], vec![]), &ctx()).await;

        assert!(matches!(result, Err(EntityError::MissingRequired(key)) if key == "name"));
    }

    #[tokio::test]
    async fn schema_default_fills_a_missing_attribute() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "status",
                    AttributeType::String,
                    false,
                    false,
                    false,
                    Some(serde_json::json!("new")),
                )],
            ))
            .await
            .unwrap();

        let entity = store
            .create(draft("e1", &["task"], vec![]), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();

        assert_eq!(entity.attributes["status"], s("new"));
    }

    #[tokio::test]
    async fn update_adds_changes_and_removes_attributes() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("priority", AttributeType::Integer),
                ],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("title", s("one"))]), &ctx())
            .await
            .unwrap();

        let added = store
            .update(
                "e1",
                1,
                patch(vec![("title", Some(s("two"))), ("priority", Some(i(2)))]),
                &ctx(),
            )
            .await
            .unwrap()
            .after
            .unwrap();
        assert_eq!(added.attributes["title"], s("two"));
        assert_eq!(added.attributes["priority"], i(2));

        let removed = store
            .update(
                "e1",
                2,
                patch(vec![("title", None), ("priority", None)]),
                &ctx(),
            )
            .await
            .unwrap()
            .after
            .unwrap();
        assert!(!removed.attributes.contains_key("title"));
        assert!(!removed.attributes.contains_key("priority"));
        assert_eq!(removed.version, 3);
    }

    #[tokio::test]
    async fn delete_removes_value_markers_and_keeps_the_key_marker() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "base",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    false,
                    true,
                    true,
                    None,
                )],
            ))
            .await
            .unwrap();
        registry
            .publish(schema("child", &["base"], vec![]))
            .await
            .unwrap();
        store
            .create(draft("e1", &["child"], vec![("tag", s("alpha"))]), &ctx())
            .await
            .unwrap();
        assert!(!all_keys(&raw).await.is_empty());

        store.delete("e1", 1, &ctx()).await.unwrap();

        assert_eq!(all_keys(&raw).await, vec![attr_key_index_key("tag")]);
        let found = store.list_by_attribute("tag", &s("alpha")).await.unwrap();
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn list_by_schema_finds_an_entity_through_a_parent_schema() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("base", &[], vec![])).await.unwrap();
        registry
            .publish(schema("child", &["base"], vec![]))
            .await
            .unwrap();
        store
            .create(draft("e1", &["child"], vec![]), &ctx())
            .await
            .unwrap();

        let found = store.list_by_schema("base").await.unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "e1");
    }

    #[tokio::test]
    async fn list_by_attribute_finds_an_indexed_attribute() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("tag", s("alpha"))]), &ctx())
            .await
            .unwrap();

        let found = store.list_by_attribute("tag", &s("alpha")).await.unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "e1");
    }

    #[tokio::test]
    async fn list_by_attribute_ignores_a_hash_collision_with_a_different_value() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(draft("a", &["task"], vec![("tag", s("alpha"))]), &ctx())
            .await
            .unwrap();
        store
            .create(draft("b", &["task"], vec![("tag", s("beta"))]), &ctx())
            .await
            .unwrap();
        raw.set_bytes(&attr_index_key("tag", &s("alpha"), "b").unwrap(), b"")
            .await
            .unwrap();

        let found = store.list_by_attribute("tag", &s("alpha")).await.unwrap();
        let ids: Vec<&str> = found.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["a"]);
    }

    #[tokio::test]
    async fn list_by_attribute_rejects_an_attribute_that_is_not_indexed() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("tag", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("tag", s("alpha"))]), &ctx())
            .await
            .unwrap();

        let result = store.list_by_attribute("tag", &s("alpha")).await;

        assert!(matches!(result, Err(EntityError::NotIndexed(key)) if key == "tag"));
    }

    #[tokio::test]
    async fn list_by_attribute_accepts_an_indexed_attribute_with_no_value() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let found = store.list_by_attribute("tag", &s("alpha")).await.unwrap();

        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn an_indexed_write_adds_the_attribute_key_marker() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("tag", s("alpha"))]), &ctx())
            .await
            .unwrap();

        assert!(
            raw.get_bytes(&attr_key_index_key("tag"))
                .await
                .unwrap()
                .is_some()
        );
        let found = store.list_by_attribute("tag", &s("alpha")).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "e1");
    }

    #[tokio::test]
    async fn list_by_attribute_accepts_the_key_marker_without_a_family_scan() {
        let (store, _registry, raw) = new_store().await;
        raw.set_bytes(&attr_key_index_key("ghost"), b"")
            .await
            .unwrap();

        let found = store.list_by_attribute("ghost", &s("alpha")).await.unwrap();

        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn list_by_attribute_after_pages_without_duplicates() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        for id in ["e1", "e2", "e3"] {
            store
                .create(draft(id, &["task"], vec![("tag", s("alpha"))]), &ctx())
                .await
                .unwrap();
        }
        store
            .create(draft("e4", &["task"], vec![("tag", s("beta"))]), &ctx())
            .await
            .unwrap();

        let (first, next) = store
            .list_by_attribute_after("tag", &s("alpha"), 2, None)
            .await
            .unwrap();
        let first_ids: Vec<&str> = first.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(first_ids, vec!["e1", "e2"]);
        assert_eq!(next.as_deref(), Some("e2"));

        let (second, next) = store
            .list_by_attribute_after("tag", &s("alpha"), 2, next.as_deref())
            .await
            .unwrap();
        let second_ids: Vec<&str> = second.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(second_ids, vec!["e3"]);
        assert!(next.is_none());

        let mut all: Vec<String> = first
            .into_iter()
            .chain(second)
            .map(|entity| entity.id)
            .collect();
        all.sort();
        assert_eq!(all, vec!["e1", "e2", "e3"]);
    }

    #[tokio::test]
    async fn list_by_attribute_after_ignores_a_hash_collision_with_a_different_value() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(draft("a", &["task"], vec![("tag", s("alpha"))]), &ctx())
            .await
            .unwrap();
        store
            .create(draft("b", &["task"], vec![("tag", s("beta"))]), &ctx())
            .await
            .unwrap();
        raw.set_bytes(&attr_index_key("tag", &s("alpha"), "b").unwrap(), b"")
            .await
            .unwrap();

        let (found, next) = store
            .list_by_attribute_after("tag", &s("alpha"), 2, None)
            .await
            .unwrap();
        let ids: Vec<&str> = found.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["a"]);
        assert!(next.is_none());
    }

    #[tokio::test]
    async fn list_returns_entities_sorted_by_id() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        store
            .create(draft("z", &["task"], vec![]), &ctx())
            .await
            .unwrap();
        store
            .create(draft("a", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let entities = store.list().await.unwrap();
        let ids: Vec<&str> = entities.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["a", "z"]);
    }

    #[tokio::test]
    async fn list_page_returns_the_first_page() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let page = store.list_page(2, 0).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn list_page_returns_the_second_page() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let page = store.list_page(2, 2).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["c", "d"]);
    }

    #[tokio::test]
    async fn list_page_offset_past_the_end_is_empty() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        store
            .create(draft("a", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let page = store.list_page(2, 9).await.unwrap();

        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_page_rejects_an_offset_above_the_maximum() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        store
            .create(draft("a", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let result = store.list_page(2, MAX_PAGE_OFFSET + 1).await;

        assert!(matches!(result, Err(EntityError::Invalid(_))));
    }

    #[tokio::test]
    async fn list_page_with_limit_zero_is_empty() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        store
            .create(draft("a", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let page = store.list_page(0, 0).await.unwrap();

        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_page_keeps_the_id_order_across_pages() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d", "e"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let mut paged = store.list_page(2, 0).await.unwrap();
        paged.extend(store.list_page(2, 2).await.unwrap());
        paged.extend(store.list_page(2, 4).await.unwrap());

        assert_eq!(paged, store.list().await.unwrap());
    }

    #[tokio::test]
    async fn the_entity_index_marker_survives_update_and_is_removed_on_delete() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("title", s("a"))]), &ctx())
            .await
            .unwrap();
        assert!(
            raw.get_bytes(&entity_index_key("e1"))
                .await
                .unwrap()
                .is_some()
        );

        store
            .update("e1", 1, patch(vec![("title", Some(s("b")))]), &ctx())
            .await
            .unwrap();
        assert!(
            raw.get_bytes(&entity_index_key("e1"))
                .await
                .unwrap()
                .is_some()
        );

        store.delete("e1", 2, &ctx()).await.unwrap();
        assert!(
            raw.get_bytes(&entity_index_key("e1"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn list_after_pages_through_every_entity_once() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d", "e"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let mut ids = Vec::new();
        let mut after: Option<String> = None;
        let mut pages = 0;
        loop {
            let (page, next) = store.list_after(2, after.as_deref()).await.unwrap();
            ids.extend(page.into_iter().map(|entity| entity.id));
            pages += 1;
            match next {
                Some(cursor) => after = Some(cursor),
                None => break,
            }
        }

        assert_eq!(ids, vec!["a", "b", "c", "d", "e"]);
        assert_eq!(pages, 3);
    }

    #[tokio::test]
    async fn list_after_skips_a_stale_cursor_without_repeating_it() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "c", "d"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let (page, next) = store.list_after(10, Some("b")).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["c", "d"]);
        assert_eq!(next, None);
    }

    /// An old store without the entity markers gets them on the first page.
    #[tokio::test]
    async fn list_after_backfills_the_markers_for_an_old_store() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        for id in ["a", "b", "c"] {
            raw.delete(&entity_index_key(id)).await.unwrap();
        }
        raw.delete(&entity_backfill_marker()).await.unwrap();
        assert!(
            all_keys(&raw)
                .await
                .iter()
                .all(|key| !key.starts_with(ENTITY_INDEX_PREFIX))
        );

        let (page, next) = store.list_after(10, None).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["a", "b", "c"]);
        assert_eq!(next, None);
        for id in ["a", "b", "c"] {
            assert!(
                raw.get_bytes(&entity_index_key(id))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            raw.get_bytes(&entity_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A fresh store keeps the same page and gains the backfill marker.
    #[tokio::test]
    async fn list_after_keeps_a_fresh_store_page_and_sets_the_marker() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let (page, next) = store.list_after(10, None).await.unwrap();

        assert_eq!(page, store.list().await.unwrap());
        assert_eq!(next, None);
        assert!(
            raw.get_bytes(&entity_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A set backfill marker writes no duplicate entity marker.
    #[tokio::test]
    async fn list_after_with_the_backfill_marker_does_not_duplicate_entities() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        raw.set_bytes(&entity_backfill_marker(), b"").await.unwrap();

        let (first, first_next) = store.list_after(2, None).await.unwrap();
        let first_ids: Vec<&str> = first.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(first_ids, vec!["a", "b"]);
        assert_eq!(first_next.as_deref(), Some("b"));

        let (second, second_next) = store.list_after(2, first_next.as_deref()).await.unwrap();
        let second_ids: Vec<&str> = second.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(second_ids, vec!["c"]);
        assert_eq!(second_next, None);

        let mut all: Vec<String> = first.into_iter().map(|entity| entity.id).collect();
        all.extend(second.into_iter().map(|entity| entity.id));
        assert_eq!(all, vec!["a", "b", "c"]);
        let markers = all_keys(&raw)
            .await
            .into_iter()
            .filter(|key| key.starts_with(ENTITY_INDEX_PREFIX))
            .count();
        assert_eq!(markers, 3);
    }

    /// The offset page path works through the backfill.
    #[tokio::test]
    async fn list_page_pages_an_old_store_after_the_backfill() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d", "e"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        for id in ["a", "b", "c", "d", "e"] {
            raw.delete(&entity_index_key(id)).await.unwrap();
        }

        let mut paged = store.list_page(2, 0).await.unwrap();
        paged.extend(store.list_page(2, 2).await.unwrap());
        paged.extend(store.list_page(2, 4).await.unwrap());

        assert_eq!(paged, store.list().await.unwrap());
        assert!(
            raw.get_bytes(&entity_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A deleted entity stays out of the pages after a later backfill.
    #[tokio::test]
    async fn list_after_does_not_restore_a_deleted_entity() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        store.delete("b", 1, &ctx()).await.unwrap();
        for id in ["a", "b"] {
            raw.delete(&entity_index_key(id)).await.unwrap();
        }
        raw.delete(&entity_backfill_marker()).await.unwrap();

        let (page, next) = store.list_after(10, None).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["a"]);
        assert_eq!(next, None);
        assert!(
            raw.get_bytes(&entity_index_key("a"))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            raw.get_bytes(&entity_index_key("b"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            raw.get_bytes(&entity_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn list_by_schema_page_returns_sorted_pages() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let first = store.list_by_schema_page("task", 2, 0).await.unwrap();
        let second = store.list_by_schema_page("task", 2, 2).await.unwrap();
        let first_ids: Vec<&str> = first.iter().map(|entity| entity.id.as_str()).collect();
        let second_ids: Vec<&str> = second.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(first_ids, vec!["a", "b"]);
        assert_eq!(second_ids, vec!["c", "d"]);
    }

    #[tokio::test]
    async fn list_by_schema_page_offset_past_the_end_is_empty() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        store
            .create(draft("a", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let page = store.list_by_schema_page("task", 2, 9).await.unwrap();

        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_by_schema_page_with_limit_zero_is_empty() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        store
            .create(draft("a", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let page = store.list_by_schema_page("task", 0, 0).await.unwrap();

        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_by_schema_after_skips_exactly_the_cursor() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "ab", "b"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let (page, next) = store
            .list_by_schema_after("task", 2, Some("a"))
            .await
            .unwrap();
        let ids: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["ab", "b"]);
        assert_eq!(next.as_deref(), Some("b"));
    }

    #[tokio::test]
    async fn list_by_schema_after_returns_no_cursor_for_a_partial_page() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let (page, next) = store.list_by_schema_after("task", 5, None).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(ids, vec!["a", "b", "c"]);
        assert_eq!(next, None);
    }

    #[tokio::test]
    async fn list_by_schema_after_with_limit_zero_is_empty() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        store
            .create(draft("a", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let (page, next) = store.list_by_schema_after("task", 0, None).await.unwrap();

        assert!(page.is_empty());
        assert_eq!(next, None);
    }

    #[tokio::test]
    async fn a_unique_attribute_rejects_a_second_entity_with_the_same_value() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![full_attr(
                    "email",
                    AttributeType::String,
                    false,
                    false,
                    true,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("e1", &["person"], vec![("email", s("a@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();

        let result = store
            .create(
                draft("e2", &["person"], vec![("email", s("a@example.com"))]),
                &ctx(),
            )
            .await;

        assert!(matches!(result, Err(EntityError::UniqueViolation(key)) if key == "email"));
        assert_eq!(store.get("e2").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_unique_hash_collision_keeps_every_marker() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![full_attr(
                    "email",
                    AttributeType::String,
                    false,
                    false,
                    true,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("a", &["person"], vec![("email", s("a@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();
        store
            .create(
                draft("b", &["person"], vec![("email", s("b@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();
        let old_hash = value_hash(&s("a@example.com")).unwrap();
        raw.set_bytes(&unique_key("email", &old_hash, "b"), b"b")
            .await
            .unwrap();

        // The collision marker does not remove the marker of `a`.
        let duplicate = store
            .create(
                draft("c", &["person"], vec![("email", s("a@example.com"))]),
                &ctx(),
            )
            .await;
        assert!(matches!(duplicate, Err(EntityError::UniqueViolation(key)) if key == "email"));
        assert!(
            raw.get_bytes(&unique_key("email", &old_hash, "a"))
                .await
                .unwrap()
                .is_some()
        );

        // After `a` releases the value, the collision marker does not block
        // `c`.
        store
            .update(
                "a",
                1,
                patch(vec![("email", Some(s("new@example.com")))]),
                &ctx(),
            )
            .await
            .unwrap();
        store
            .create(
                draft("c", &["person"], vec![("email", s("a@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();

        let new_hash = value_hash(&s("new@example.com")).unwrap();
        let marker_a = raw
            .get_bytes(&unique_key("email", &new_hash, "a"))
            .await
            .unwrap();
        let marker_c = raw
            .get_bytes(&unique_key("email", &old_hash, "c"))
            .await
            .unwrap();
        assert!(marker_a.is_some());
        assert!(marker_c.is_some());

        let result = store
            .create(
                draft("d", &["person"], vec![("email", s("a@example.com"))]),
                &ctx(),
            )
            .await;

        assert!(matches!(result, Err(EntityError::UniqueViolation(key)) if key == "email"));
    }

    #[tokio::test]
    async fn a_unique_attribute_allows_the_same_entity_to_keep_its_value() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![
                    full_attr("email", AttributeType::String, false, false, true, None),
                    attr("name", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        store
            .create(
                draft(
                    "e1",
                    &["person"],
                    vec![("email", s("a@example.com")), ("name", s("Alice"))],
                ),
                &ctx(),
            )
            .await
            .unwrap();

        let changed = store
            .update(
                "e1",
                1,
                patch(vec![
                    ("email", Some(s("a@example.com"))),
                    ("name", Some(s("Bob"))),
                ]),
                &ctx(),
            )
            .await;

        assert!(changed.is_ok());
        assert_eq!(changed.unwrap().after.unwrap().version, 2);
    }

    #[tokio::test]
    async fn a_failed_unique_update_leaves_the_old_value_and_indexes_intact() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![full_attr(
                    "email",
                    AttributeType::String,
                    false,
                    true,
                    true,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("e1", &["person"], vec![("email", s("a@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();
        store
            .create(
                draft("e2", &["person"], vec![("email", s("b@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();

        let result = store
            .update(
                "e1",
                1,
                patch(vec![("email", Some(s("b@example.com")))]),
                &ctx(),
            )
            .await;

        assert!(matches!(result, Err(EntityError::UniqueViolation(key)) if key == "email"));
        let entity = store.get("e1").await.unwrap().unwrap();
        assert_eq!(entity.version, 1);
        assert_eq!(entity.attributes["email"], s("a@example.com"));

        let old = store
            .list_by_attribute("email", &s("a@example.com"))
            .await
            .unwrap();
        let new = store
            .list_by_attribute("email", &s("b@example.com"))
            .await
            .unwrap();
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].id, "e1");
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].id, "e2");
    }

    #[tokio::test]
    async fn failed_validation_writes_no_key() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![full_attr(
                    "name",
                    AttributeType::String,
                    true,
                    false,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();

        let result = store.create(draft("e1", &["person"], vec![]), &ctx()).await;

        assert!(matches!(result, Err(EntityError::MissingRequired(_))));
        assert!(all_keys(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn two_schemas_with_the_same_type_merge_their_flags() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "left",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        registry
            .publish(schema(
                "right",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    true,
                    false,
                    true,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("e1", &["left", "right"], vec![("tag", s("x"))]),
                &ctx(),
            )
            .await
            .unwrap();

        let found = store.list_by_attribute("tag", &s("x")).await.unwrap();
        assert_eq!(found.len(), 1);

        let result = store
            .create(
                draft("e2", &["left", "right"], vec![("tag", s("x"))]),
                &ctx(),
            )
            .await;
        assert!(matches!(result, Err(EntityError::UniqueViolation(_))));
    }

    #[tokio::test]
    async fn two_schemas_with_different_types_for_one_attribute_fail() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "left",
                &[],
                vec![attr("tag", AttributeType::String)],
            ))
            .await
            .unwrap();
        registry
            .publish(schema(
                "right",
                &[],
                vec![attr("tag", AttributeType::Integer)],
            ))
            .await
            .unwrap();

        let result = store
            .create(
                draft("e1", &["left", "right"], vec![("tag", s("x"))]),
                &ctx(),
            )
            .await;

        assert!(matches!(result, Err(EntityError::SchemaConflict(_))));
    }

    #[tokio::test]
    async fn invalid_entity_ids_fail() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let mut ids = vec![
            String::new(),
            "Upper".to_string(),
            "a:b".to_string(),
            "a/b".to_string(),
            "a b".to_string(),
        ];
        ids.push("a".repeat(MAX_NAME_BYTES + 1));

        for id in ids {
            let result = store.create(draft(&id, &["person"], vec![]), &ctx()).await;
            assert!(
                matches!(result, Err(EntityError::Invalid(_))),
                "entity id {id:?} must fail"
            );
        }
    }

    #[tokio::test]
    async fn a_draft_needs_one_unique_schema_id() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();

        let empty = store.create(draft("e1", &[], vec![]), &ctx()).await;
        let duplicate = store
            .create(draft("e2", &["person", "person"], vec![]), &ctx())
            .await;

        assert!(matches!(empty, Err(EntityError::Invalid(_))));
        assert!(matches!(duplicate, Err(EntityError::Invalid(_))));
    }

    #[test]
    fn an_attribute_value_has_an_explicit_wire_type() {
        let value = s("hello");
        let wire = serde_json::to_value(&value).unwrap();

        assert_eq!(wire["type"], "string");
        assert_eq!(wire["value"], "hello");
        let back: AttributeValue = serde_json::from_value(wire).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn attribute_values_become_plain_json() {
        assert_eq!(
            AttributeValue::String("a".to_string()).as_json(),
            serde_json::json!("a")
        );
        assert_eq!(AttributeValue::Integer(7).as_json(), serde_json::json!(7));
        assert_eq!(AttributeValue::Float(1.5).as_json(), serde_json::json!(1.5));
        assert_eq!(
            AttributeValue::Boolean(true).as_json(),
            serde_json::json!(true)
        );
        assert_eq!(AttributeValue::Timestamp(9).as_json(), serde_json::json!(9));
        assert_eq!(
            AttributeValue::Json(serde_json::json!({"a": 1})).as_json(),
            serde_json::json!({"a": 1})
        );
        assert_eq!(
            AttributeValue::EntityRef("e2".to_string()).as_json(),
            serde_json::json!("e2")
        );
    }

    #[tokio::test]
    async fn create_update_and_delete_emit_events() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![
                    attr("name", AttributeType::String),
                    attr("age", AttributeType::Integer),
                ],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        let create_ctx = WriteContext::new("alice").with_correlation_id("req-1");
        store
            .create(
                draft(
                    "e1",
                    &["person"],
                    vec![("name", s("Alice")), ("age", i(30))],
                ),
                &create_ctx,
            )
            .await
            .unwrap();

        let events = feed.events();
        assert_eq!(events.len(), 1);
        let created = &events[0];
        assert_eq!(created.kind, EntityEventKind::Created);
        assert_eq!(created.actor, "alice");
        assert_eq!(created.entity_version, 1);
        assert_eq!(created.correlation_id, "req-1");
        assert_eq!(created.changed.len(), 2);
        let age = created
            .changed
            .iter()
            .find(|item| item.key == "age")
            .unwrap();
        assert_eq!(age.old, None);
        assert_eq!(age.new, Some(tagged(&i(30))));
        let name = created
            .changed
            .iter()
            .find(|item| item.key == "name")
            .unwrap();
        assert_eq!(name.old, None);
        assert_eq!(name.new, Some(tagged(&s("Alice"))));

        let update_ctx = WriteContext::new("bob").with_causation_id("evt-0");
        store
            .update(
                "e1",
                1,
                patch(vec![("name", Some(s("Bob"))), ("age", None)]),
                &update_ctx,
            )
            .await
            .unwrap();

        let events = feed.events();
        assert_eq!(events.len(), 2);
        let updated = &events[1];
        assert_eq!(updated.kind, EntityEventKind::Updated);
        assert_eq!(updated.actor, "bob");
        assert_eq!(updated.entity_version, 2);
        assert_eq!(updated.causation_id.as_deref(), Some("evt-0"));
        let age = updated
            .changed
            .iter()
            .find(|item| item.key == "age")
            .unwrap();
        assert_eq!(age.old, Some(tagged(&i(30))));
        assert_eq!(age.new, None);
        let name = updated
            .changed
            .iter()
            .find(|item| item.key == "name")
            .unwrap();
        assert_eq!(name.old, Some(tagged(&s("Alice"))));
        assert_eq!(name.new, Some(tagged(&s("Bob"))));

        let delete_ctx = WriteContext::new("carol");
        store.delete("e1", 2, &delete_ctx).await.unwrap();

        let events = feed.events();
        assert_eq!(events.len(), 3);
        let deleted = &events[2];
        assert_eq!(deleted.kind, EntityEventKind::Deleted);
        assert_eq!(deleted.actor, "carol");
        assert_eq!(deleted.entity_version, 2);
        assert_eq!(deleted.changed.len(), 1);
        let name = deleted
            .changed
            .iter()
            .find(|item| item.key == "name")
            .unwrap();
        assert_eq!(name.old, Some(tagged(&s("Bob"))));
        assert_eq!(name.new, None);

        assert!(outbox_keys(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn event_schemas_include_a_parent_schema() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("base", &[], vec![])).await.unwrap();
        registry
            .publish(schema("child", &["base"], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        store
            .create(draft("e1", &["child"], vec![]), &ctx())
            .await
            .unwrap();

        let events = feed.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].schemas,
            vec!["base".to_string(), "child".to_string()]
        );
    }

    #[tokio::test]
    async fn correlation_id_defaults_to_the_event_id() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();

        let events = feed.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].correlation_id, events[0].event_id);
    }

    /// A normal create records depth 0 and a snapshot of every attribute.
    ///
    /// The snapshot holds plain JSON.
    /// A rule then reads the values without the storage type tag.
    #[tokio::test]
    async fn a_create_records_depth_zero_and_a_full_snapshot() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![
                    attr("name", AttributeType::String),
                    attr("age", AttributeType::Integer),
                ],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        store
            .create(
                draft(
                    "e1",
                    &["person"],
                    vec![("name", s("Alice")), ("age", i(30))],
                ),
                &ctx(),
            )
            .await
            .unwrap();

        let events = feed.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.causation_depth, 0);
        let snapshot = event.snapshot.as_ref().expect("a new event has a snapshot");
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot["name"], serde_json::json!("Alice"));
        assert_eq!(snapshot["age"], serde_json::json!(30));
    }

    /// A delete records the before state in its snapshot.
    ///
    /// The entity has no after state.
    /// A rule must still compare the attributes that the event removed.
    #[tokio::test]
    async fn a_delete_records_the_before_state_in_the_snapshot() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![
                    attr("name", AttributeType::String),
                    attr("age", AttributeType::Integer),
                ],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        store
            .create(
                draft(
                    "e1",
                    &["person"],
                    vec![("name", s("Alice")), ("age", i(30))],
                ),
                &ctx(),
            )
            .await
            .unwrap();

        store.delete("e1", 1, &ctx()).await.unwrap();

        let events = feed.events();
        assert_eq!(events.len(), 2);
        let deleted = &events[1];
        assert_eq!(deleted.kind, EntityEventKind::Deleted);
        let snapshot = deleted
            .snapshot
            .as_ref()
            .expect("a delete has a snapshot of the before state");
        assert_eq!(snapshot["name"], serde_json::json!("Alice"));
        assert_eq!(snapshot["age"], serde_json::json!(30));
    }

    #[tokio::test]
    async fn outbox_is_empty_after_a_successful_append() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();

        assert_eq!(feed.events().len(), 1);
        assert!(outbox_keys(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn a_create_succeeds_when_the_feed_append_fails() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        feed.fail_next(1);
        let change = store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();

        assert!(change.after.is_some());
        assert!(store.get("e1").await.unwrap().is_some());
        assert_eq!(store.outbox_count().await.unwrap(), 1);
        assert_eq!(outbox_keys(&raw).await.len(), 1);

        assert_eq!(store.flush_outbox().await.unwrap(), 1);
        assert!(store.get("e1").await.unwrap().is_some());
        assert_eq!(store.outbox_count().await.unwrap(), 0);
        let events = feed.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].entity_id, "e1");
    }

    #[tokio::test]
    async fn an_update_succeeds_when_the_feed_append_fails() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("age", AttributeType::Integer)],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        store
            .create(draft("e1", &["person"], vec![("age", i(30))]), &ctx())
            .await
            .unwrap();
        assert_eq!(store.outbox_count().await.unwrap(), 0);

        feed.fail_next(1);
        let change = store
            .update("e1", 1, patch(vec![("age", Some(i(31)))]), &ctx())
            .await
            .unwrap();

        assert_eq!(change.after.unwrap().version, 2);
        assert_eq!(
            store.get("e1").await.unwrap().unwrap().attributes["age"],
            i(31)
        );
        assert_eq!(store.outbox_count().await.unwrap(), 1);

        assert_eq!(store.flush_outbox().await.unwrap(), 1);
        assert_eq!(store.outbox_count().await.unwrap(), 0);
        assert_eq!(feed.events().len(), 2);
    }

    #[tokio::test]
    async fn a_delete_succeeds_when_the_feed_append_fails() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();
        assert_eq!(store.outbox_count().await.unwrap(), 0);

        feed.fail_next(1);
        let change = store.delete("e1", 1, &ctx()).await.unwrap();

        assert_eq!(change.after, None);
        assert!(store.get("e1").await.unwrap().is_none());
        assert_eq!(store.outbox_count().await.unwrap(), 1);

        assert_eq!(store.flush_outbox().await.unwrap(), 1);
        assert_eq!(store.outbox_count().await.unwrap(), 0);
        assert_eq!(feed.events().len(), 2);
    }

    #[tokio::test]
    async fn a_later_flush_delivers_a_pending_row() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        feed.fail_next(1);
        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();
        assert_eq!(store.outbox_count().await.unwrap(), 1);
        assert!(feed.events().is_empty());

        assert_eq!(store.flush_outbox().await.unwrap(), 1);
        assert_eq!(store.outbox_count().await.unwrap(), 0);
        let events = feed.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].entity_id, "e1");
    }

    #[tokio::test]
    async fn a_successful_write_flushes_immediately() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();

        assert_eq!(store.outbox_count().await.unwrap(), 0);
        assert_eq!(feed.events().len(), 1);
    }

    #[tokio::test]
    async fn a_create_without_a_feed_writes_no_outbox_row() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();

        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();

        assert!(outbox_keys(&raw).await.is_empty());
        assert_eq!(store.flush_outbox().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn outbox_count_reports_the_pending_rows() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        feed.set_failing(true);
        let store = store.with_change_sink(feed.clone());

        for id in ["e1", "e2", "e3"] {
            store
                .create(draft(id, &["person"], vec![]), &ctx())
                .await
                .unwrap();
        }
        assert_eq!(store.outbox_count().await.unwrap(), 3);

        feed.set_failing(false);
        assert_eq!(store.flush_outbox().await.unwrap(), 3);
        assert_eq!(store.outbox_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn outbox_count_tracks_create_update_and_delete() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("age", AttributeType::Integer)],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        feed.set_failing(true);
        let store = store.with_change_sink(feed.clone());

        store
            .create(draft("e1", &["person"], vec![("age", i(30))]), &ctx())
            .await
            .unwrap();
        assert_eq!(store.outbox_count().await.unwrap(), 1);

        store
            .update("e1", 1, patch(vec![("age", Some(i(31)))]), &ctx())
            .await
            .unwrap();
        assert_eq!(store.outbox_count().await.unwrap(), 2);

        store.delete("e1", 2, &ctx()).await.unwrap();
        assert_eq!(store.outbox_count().await.unwrap(), 3);

        assert_eq!(outbox_keys(&raw).await.len(), 3);
        assert_eq!(pending_counter(&raw).await, Some(3));
    }

    #[tokio::test]
    async fn flush_outbox_decrements_the_pending_counter() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        feed.set_failing(true);
        let store = store.with_change_sink(feed.clone());

        for id in ["e1", "e2"] {
            store
                .create(draft(id, &["person"], vec![]), &ctx())
                .await
                .unwrap();
        }
        assert_eq!(store.outbox_count().await.unwrap(), 2);

        feed.set_failing(false);
        assert_eq!(store.flush_outbox().await.unwrap(), 2);
        assert_eq!(store.outbox_count().await.unwrap(), 0);
        assert_eq!(pending_counter(&raw).await, Some(0));
    }

    #[tokio::test]
    async fn outbox_count_backfills_a_missing_counter() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        feed.set_failing(true);
        let store = store.with_change_sink(feed.clone());

        for id in ["e1", "e2", "e3"] {
            store
                .create(draft(id, &["person"], vec![]), &ctx())
                .await
                .unwrap();
        }
        raw.delete(outbox_pending_key()).await.unwrap();
        assert_eq!(pending_counter(&raw).await, None);

        assert_eq!(store.outbox_count().await.unwrap(), 3);
        assert_eq!(pending_counter(&raw).await, Some(3));
        assert_eq!(store.outbox_count().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn flush_outbox_backfills_a_missing_counter() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        feed.set_failing(true);
        let store = store.with_change_sink(feed.clone());

        for id in ["e1", "e2", "e3"] {
            store
                .create(draft(id, &["person"], vec![]), &ctx())
                .await
                .unwrap();
        }
        raw.delete(outbox_pending_key()).await.unwrap();
        assert_eq!(pending_counter(&raw).await, None);

        feed.set_failing(false);
        assert_eq!(store.flush_outbox().await.unwrap(), 3);
        assert_eq!(store.outbox_count().await.unwrap(), 0);
        assert_eq!(pending_counter(&raw).await, Some(0));
    }

    #[tokio::test]
    async fn outbox_count_without_a_feed_stays_zero() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();

        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();
        assert_eq!(pending_counter(&raw).await, None);

        assert_eq!(store.outbox_count().await.unwrap(), 0);
        assert_eq!(pending_counter(&raw).await, Some(0));

        store
            .create(draft("e2", &["person"], vec![]), &ctx())
            .await
            .unwrap();
        assert_eq!(store.outbox_count().await.unwrap(), 0);
        assert_eq!(pending_counter(&raw).await, Some(0));
    }

    #[tokio::test]
    async fn a_failed_feed_append_keeps_the_pending_counter() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        feed.fail_next(1);
        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();
        assert_eq!(store.outbox_count().await.unwrap(), 1);
        assert_eq!(pending_counter(&raw).await, Some(1));

        feed.fail_next(1);
        assert!(store.flush_outbox().await.is_err());
        assert_eq!(store.outbox_count().await.unwrap(), 1);
        assert_eq!(pending_counter(&raw).await, Some(1));
        assert_eq!(outbox_keys(&raw).await.len(), 1);
    }

    #[tokio::test]
    async fn events_flush_in_key_order() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        feed.set_failing(true);
        let store = store.with_change_sink(feed.clone());

        for id in ["e1", "e2", "e3"] {
            store
                .create(draft(id, &["person"], vec![]), &ctx())
                .await
                .unwrap();
        }
        let mut keys = outbox_keys(&raw).await;
        keys.sort();
        assert_eq!(keys.len(), 3);
        let expected: Vec<String> = keys
            .iter()
            .map(|key| key.strip_prefix(OUTBOX_PREFIX).unwrap().to_string())
            .collect();

        feed.set_failing(false);
        assert_eq!(store.flush_outbox().await.unwrap(), 3);

        let delivered: Vec<String> = feed
            .events()
            .into_iter()
            .map(|event| event.event_id)
            .collect();
        assert_eq!(delivered, expected);
        assert!(outbox_keys(&raw).await.is_empty());
    }

    /// An indexed timestamp writes one time row with the biased encoding.
    #[tokio::test]
    async fn an_indexed_timestamp_writes_a_time_index_row() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "due",
                    AttributeType::Timestamp,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("due", t(100))]), &ctx())
            .await
            .unwrap();

        let keys = all_keys(&raw).await;
        assert!(keys.contains(&time_index_key("due", 100, "e1")));
        assert!(keys.contains(&"idx:time:due:8000000000000064:e1".to_string()));
    }

    /// A non-indexed timestamp and a non-timestamp attribute write no time row.
    #[tokio::test]
    async fn only_an_indexed_timestamp_writes_a_time_row() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    full_attr("due", AttributeType::Timestamp, false, false, false, None),
                    full_attr("tag", AttributeType::String, false, true, false, None),
                ],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("e1", &["task"], vec![("due", t(100)), ("tag", s("alpha"))]),
                &ctx(),
            )
            .await
            .unwrap();

        let keys = all_keys(&raw).await;
        assert!(
            keys.iter().all(|key| !key.starts_with(TIME_INDEX_PREFIX)),
            "a time row exists for an attribute that is not an indexed timestamp"
        );
    }

    #[tokio::test]
    async fn time_keys_returns_the_unique_sorted_keys() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    full_attr("start", AttributeType::Timestamp, false, true, false, None),
                    full_attr("due", AttributeType::Timestamp, false, true, false, None),
                ],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("e1", &["task"], vec![("due", t(100)), ("start", t(50))]),
                &ctx(),
            )
            .await
            .unwrap();
        store
            .create(
                draft("e2", &["task"], vec![("due", t(200)), ("start", t(60))]),
                &ctx(),
            )
            .await
            .unwrap();

        assert_eq!(
            store.time_keys().await.unwrap(),
            vec!["due".to_string(), "start".to_string()]
        );
    }

    /// One indexed timestamp writes one key marker.
    #[tokio::test]
    async fn time_keys_returns_the_key_after_one_indexed_timestamp() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "due",
                    AttributeType::Timestamp,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        create_task(&store, "e1", 100).await;

        assert_eq!(store.time_keys().await.unwrap(), vec!["due".to_string()]);
        assert!(all_keys(&raw).await.contains(&time_key_index_key("due")));
    }

    /// Two entities with the same key and value write one key marker.
    #[tokio::test]
    async fn time_keys_returns_one_key_after_a_second_matching_entity() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "due",
                    AttributeType::Timestamp,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        create_task(&store, "e1", 100).await;
        create_task(&store, "e2", 100).await;

        assert_eq!(store.time_keys().await.unwrap(), vec!["due".to_string()]);
        let markers: Vec<String> = all_keys(&raw)
            .await
            .into_iter()
            .filter(|key| key.starts_with(TIME_KEY_INDEX_PREFIX))
            .collect();
        assert_eq!(markers, vec![time_key_index_key("due")]);
    }

    /// Two different indexed timestamp keys come back in sorted order.
    #[tokio::test]
    async fn time_keys_returns_two_keys_in_sorted_order() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    full_attr("start", AttributeType::Timestamp, false, true, false, None),
                    full_attr("due", AttributeType::Timestamp, false, true, false, None),
                ],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("e1", &["task"], vec![("start", t(50)), ("due", t(100))]),
                &ctx(),
            )
            .await
            .unwrap();

        assert_eq!(
            store.time_keys().await.unwrap(),
            vec!["due".to_string(), "start".to_string()]
        );
    }

    /// A delete keeps the key marker and the next scan succeeds.
    #[tokio::test]
    async fn time_keys_returns_the_key_after_every_entity_is_deleted() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "due",
                    AttributeType::Timestamp,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        create_task(&store, "e1", 100).await;
        create_task(&store, "e2", 200).await;

        store.delete("e1", 1, &ctx()).await.unwrap();
        store.delete("e2", 1, &ctx()).await.unwrap();

        let keys = store.time_keys().await.unwrap();
        assert_eq!(keys, vec!["due".to_string()]);
        assert!(all_keys(&raw).await.contains(&time_key_index_key("due")));
    }

    /// An old store with no key marker gets the marker on the first call.
    #[tokio::test]
    async fn time_keys_backfills_the_marker_for_an_old_store() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        raw.set_bytes(&time_index_key("due", 100, "e1"), b"")
            .await
            .unwrap();
        assert!(!all_keys(&raw).await.contains(&time_key_index_key("due")));

        assert_eq!(store.time_keys().await.unwrap(), vec!["due".to_string()]);

        let marker = raw.get_bytes(&time_key_index_key("due")).await.unwrap();
        assert_eq!(marker.as_deref(), Some(&b""[..]));
        assert_eq!(store.time_keys().await.unwrap(), vec!["due".to_string()]);
    }

    /// A mixed store gets the missing marker and the backfill marker.
    #[tokio::test]
    async fn time_keys_backfills_a_mixed_store_one_time() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        raw.set_bytes(&time_index_key("beta", 100, "e1"), b"")
            .await
            .unwrap();
        raw.set_bytes(&time_key_index_key("alpha"), b"")
            .await
            .unwrap();
        assert!(
            raw.get_bytes(&time_key_backfill_marker())
                .await
                .unwrap()
                .is_none()
        );

        assert_eq!(
            store.time_keys().await.unwrap(),
            vec!["alpha".to_string(), "beta".to_string()]
        );

        assert!(all_keys(&raw).await.contains(&time_key_index_key("beta")));
        assert!(
            raw.get_bytes(&time_key_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A second call returns every marker key after the backfill marker.
    #[tokio::test]
    async fn time_keys_keeps_every_key_after_the_backfill_marker_exists() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        raw.set_bytes(&time_index_key("beta", 100, "e1"), b"")
            .await
            .unwrap();
        raw.set_bytes(&time_key_index_key("alpha"), b"")
            .await
            .unwrap();
        let first = store.time_keys().await.unwrap();
        assert_eq!(first, vec!["alpha".to_string(), "beta".to_string()]);
        assert!(
            raw.get_bytes(&time_key_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );

        raw.delete(&time_index_key("beta", 100, "e1"))
            .await
            .unwrap();
        assert_eq!(
            store.time_keys().await.unwrap(),
            vec!["alpha".to_string(), "beta".to_string()]
        );
    }

    #[tokio::test]
    async fn list_due_returns_due_entities_in_time_order_with_a_limit() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "due",
                    AttributeType::Timestamp,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        for (id, due) in [("e1", 50), ("e2", 10), ("e3", 100)] {
            store
                .create(draft(id, &["task"], vec![("due", t(due))]), &ctx())
                .await
                .unwrap();
        }

        let due = store.list_due("due", 60, 100).await.unwrap();
        let ids: Vec<&str> = due.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(ids, vec!["e2", "e1"]);

        let limited = store.list_due("due", 60, 1).await.unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].id, "e2");

        assert!(store.list_due("due", 60, 0).await.unwrap().is_empty());

        // A stale row below the bound must not return the entity when the
        // current value is above the bound.
        raw.set_bytes(&time_index_key("due", 10, "e1"), b"")
            .await
            .unwrap();
        let stale = store.list_due("due", 20, 100).await.unwrap();
        assert!(stale.iter().all(|entity| entity.id != "e1"));
    }

    #[tokio::test]
    async fn update_moves_the_time_row_and_delete_removes_it() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "due",
                    AttributeType::Timestamp,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("due", t(100))]), &ctx())
            .await
            .unwrap();

        store
            .update("e1", 1, patch(vec![("due", Some(t(200)))]), &ctx())
            .await
            .unwrap();
        let keys = all_keys(&raw).await;
        assert!(!keys.contains(&time_index_key("due", 100, "e1")));
        assert!(keys.contains(&time_index_key("due", 200, "e1")));

        store.delete("e1", 2, &ctx()).await.unwrap();
        let keys = all_keys(&raw).await;
        assert!(
            keys.iter().all(|key| !key.starts_with(TIME_INDEX_PREFIX)),
            "a delete left a time row behind"
        );
    }

    #[tokio::test]
    async fn emit_timer_appends_one_timer_event_with_a_stable_id() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "due",
                    AttributeType::Timestamp,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        let entity = store
            .create(draft("e1", &["task"], vec![("due", t(100))]), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();

        let event = store.emit_timer(&entity, "due", 100, 1_234).await.unwrap();

        assert_eq!(event.kind, EntityEventKind::Timer);
        assert_eq!(event.entity_id, "e1");
        assert_eq!(event.entity_version, 1);
        assert_eq!(event.schemas, vec!["task".to_string()]);
        assert!(event.changed.is_empty());
        assert_eq!(
            event.snapshot.as_ref().unwrap()["due"],
            serde_json::json!(100)
        );
        assert_eq!(event.actor, "system:timer");
        assert_eq!(event.causation_id, None);
        assert_eq!(event.causation_depth, 0);
        assert_eq!(event.occurred_at, 1_234);
        assert_eq!(event.event_id, "timer-e1-due-8000000000000064");
        assert_eq!(event.correlation_id, event.event_id);
        assert!(!event.event_id.contains(':'));

        let events = feed.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1], event);
        assert!(outbox_keys(&raw).await.is_empty());

        let again = store.emit_timer(&entity, "due", 100, 1_234).await.unwrap();
        assert_eq!(again.event_id, event.event_id);
    }

    #[tokio::test]
    async fn emit_timer_needs_a_change_feed() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "due",
                    AttributeType::Timestamp,
                    false,
                    true,
                    false,
                    None,
                )],
            ))
            .await
            .unwrap();
        let entity = store
            .create(draft("e1", &["task"], vec![("due", t(100))]), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();

        let result = store.emit_timer(&entity, "due", 100, 1_234).await;

        assert!(matches!(result, Err(EntityError::Feed(_))));
    }

    #[tokio::test]
    async fn a_timer_marker_is_idempotent() {
        let (store, raw) = timer_store().await;
        create_task(&store, "e1", 100).await;

        assert!(!store.is_timer_fired("e1", "due", 100).await.unwrap());
        assert!(store.mark_timer_fired("e1", "due", 100).await.unwrap());
        assert!(store.is_timer_fired("e1", "due", 100).await.unwrap());
        assert!(store.mark_timer_fired("e1", "due", 100).await.unwrap());
        assert!(store.is_timer_fired("e1", "due", 100).await.unwrap());

        let bytes = raw
            .get_bytes(&timer_marker_key("e1", "due", 100))
            .await
            .unwrap()
            .unwrap();
        let fired_at: i64 = serde_json::from_slice(&bytes).unwrap();
        assert!(fired_at > 0);
    }

    #[tokio::test]
    async fn a_timer_marker_is_written_for_the_current_value() {
        let (store, _raw) = timer_store().await;
        create_task(&store, "e1", 100).await;

        assert!(store.mark_timer_fired("e1", "due", 100).await.unwrap());
        assert!(store.is_timer_fired("e1", "due", 100).await.unwrap());
    }

    #[tokio::test]
    async fn a_timer_marker_for_an_old_value_is_not_written() {
        let (store, _raw) = timer_store().await;
        create_task(&store, "e1", 100).await;
        assert!(store.mark_timer_fired("e1", "due", 100).await.unwrap());

        store
            .update("e1", 1, patch(vec![("due", Some(t(200)))]), &ctx())
            .await
            .unwrap();

        assert!(!store.mark_timer_fired("e1", "due", 100).await.unwrap());
        assert!(!store.is_timer_fired("e1", "due", 100).await.unwrap());
    }

    #[tokio::test]
    async fn a_timer_fires_again_after_the_value_returns() {
        let (store, _raw) = timer_store().await;
        create_task(&store, "e1", 100).await;
        assert!(store.mark_timer_fired("e1", "due", 100).await.unwrap());
        store
            .update("e1", 1, patch(vec![("due", Some(t(200)))]), &ctx())
            .await
            .unwrap();
        assert!(!store.mark_timer_fired("e1", "due", 100).await.unwrap());
        store
            .update("e1", 2, patch(vec![("due", Some(t(100)))]), &ctx())
            .await
            .unwrap();

        assert!(!store.is_timer_fired("e1", "due", 100).await.unwrap());
        assert!(store.mark_timer_fired("e1", "due", 100).await.unwrap());
    }

    #[tokio::test]
    async fn a_timer_marker_for_a_deleted_entity_is_not_written() {
        let (store, _raw) = timer_store().await;
        create_task(&store, "e1", 100).await;
        store.delete("e1", 1, &ctx()).await.unwrap();

        assert!(!store.mark_timer_fired("e1", "due", 100).await.unwrap());
        assert!(!store.is_timer_fired("e1", "due", 100).await.unwrap());
    }

    #[tokio::test]
    async fn a_timer_marker_for_a_value_the_entity_never_had_is_not_written() {
        let (store, _raw) = timer_store().await;
        create_task(&store, "e1", 100).await;

        assert!(!store.mark_timer_fired("e1", "due", 999).await.unwrap());
        assert!(!store.is_timer_fired("e1", "due", 999).await.unwrap());
    }

    #[tokio::test]
    async fn retire_timer_removes_the_time_row_and_writes_the_marker() {
        let (store, raw) = timer_store().await;
        create_task(&store, "e1", 100).await;
        let keys = all_keys(&raw).await;
        assert!(keys.contains(&time_index_key("due", 100, "e1")));
        assert!(!keys.contains(&timer_marker_key("e1", "due", 100)));

        assert!(store.retire_timer("e1", "due", 100).await.unwrap());

        let keys = all_keys(&raw).await;
        assert!(!keys.contains(&time_index_key("due", 100, "e1")));
        assert!(keys.contains(&timer_marker_key("e1", "due", 100)));
        assert!(store.is_timer_fired("e1", "due", 100).await.unwrap());
        assert!(store.list_due("due", 100, 100).await.unwrap().is_empty());
        let bytes = raw
            .get_bytes(&timer_marker_key("e1", "due", 100))
            .await
            .unwrap()
            .unwrap();
        let fired_at: i64 = serde_json::from_slice(&bytes).unwrap();
        assert!(fired_at > 0);
    }

    #[tokio::test]
    async fn retire_timer_returns_false_after_the_value_changes() {
        let (store, raw) = timer_store().await;
        create_task(&store, "e1", 100).await;
        let first = store.list_due("due", 100, 100).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].id, "e1");

        store
            .update("e1", 1, patch(vec![("due", Some(t(200)))]), &ctx())
            .await
            .unwrap();

        assert!(!store.retire_timer("e1", "due", 100).await.unwrap());
        assert!(!store.is_timer_fired("e1", "due", 100).await.unwrap());

        let keys = all_keys(&raw).await;
        assert!(!keys.contains(&time_index_key("due", 100, "e1")));
        assert!(keys.contains(&time_index_key("due", 200, "e1")));

        let next = store.list_due("due", 200, 100).await.unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].attributes.get("due"), Some(&t(200)));
    }

    #[tokio::test]
    async fn retire_timer_for_an_absent_entity_writes_nothing() {
        let (store, raw) = timer_store().await;
        let before = all_keys(&raw).await;

        assert!(!store.retire_timer("missing", "due", 100).await.unwrap());

        assert_eq!(all_keys(&raw).await, before);
    }

    #[tokio::test]
    async fn update_and_delete_remove_timer_markers() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    full_attr("due", AttributeType::Timestamp, false, true, false, None),
                    attr("title", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("e1", &["task"], vec![("due", t(100)), ("title", s("one"))]),
                &ctx(),
            )
            .await
            .unwrap();
        store.mark_timer_fired("e1", "due", 100).await.unwrap();

        // An update that keeps the value keeps the marker.
        store
            .update("e1", 1, patch(vec![("title", Some(s("two")))]), &ctx())
            .await
            .unwrap();
        assert!(store.is_timer_fired("e1", "due", 100).await.unwrap());

        // An update that changes the value removes the old marker.
        store
            .update("e1", 2, patch(vec![("due", Some(t(200)))]), &ctx())
            .await
            .unwrap();
        assert!(!store.is_timer_fired("e1", "due", 100).await.unwrap());
        store.mark_timer_fired("e1", "due", 200).await.unwrap();
        assert!(store.is_timer_fired("e1", "due", 200).await.unwrap());

        // A delete removes every marker of the entity.
        store.delete("e1", 3, &ctx()).await.unwrap();
        assert!(!store.is_timer_fired("e1", "due", 200).await.unwrap());
    }

    #[tokio::test]
    async fn revalidation_accepts_an_entity_that_matches_the_new_version() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        let created = store
            .create(draft("e1", &["task"], vec![("title", s("one"))]), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("note", AttributeType::String),
                ],
            ))
            .await
            .unwrap();

        let report = store
            .revalidation_report("task", 2, 100, None)
            .await
            .unwrap();

        assert_eq!(report.scanned, 1);
        assert_eq!(report.compatible, 1);
        assert!(report.invalid.is_empty());
        assert_eq!(store.get("e1").await.unwrap(), Some(created));
    }

    #[tokio::test]
    async fn revalidation_reports_a_missing_required_attribute() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("title", s("one"))]), &ctx())
            .await
            .unwrap();
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    full_attr("owner", AttributeType::String, true, false, false, None),
                ],
            ))
            .await
            .unwrap();

        let report = store
            .revalidation_report("task", 2, 100, None)
            .await
            .unwrap();

        assert_eq!(report.scanned, 1);
        assert_eq!(report.compatible, 0);
        assert_eq!(report.invalid.len(), 1);
        assert_eq!(report.invalid[0].entity_id, "e1");
        assert_eq!(
            report.invalid[0].issue,
            RevalidationIssue::MissingRequired("owner".to_string())
        );
    }

    #[tokio::test]
    async fn revalidation_reports_a_type_change() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("total", AttributeType::Integer)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("total", i(10))]), &ctx())
            .await
            .unwrap();
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("total", AttributeType::String)],
            ))
            .await
            .unwrap();

        let report = store
            .revalidation_report("task", 2, 100, None)
            .await
            .unwrap();

        assert_eq!(report.compatible, 0);
        assert_eq!(
            report.invalid[0].issue,
            RevalidationIssue::TypeMismatch("total".to_string())
        );
    }

    #[tokio::test]
    async fn revalidation_reports_a_removed_attribute() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("title", s("one"))]), &ctx())
            .await
            .unwrap();
        registry.publish(schema("task", &[], vec![])).await.unwrap();

        let report = store
            .revalidation_report("task", 2, 100, None)
            .await
            .unwrap();

        assert_eq!(report.compatible, 0);
        assert_eq!(
            report.invalid[0].issue,
            RevalidationIssue::UnknownAttribute("title".to_string())
        );
    }

    #[tokio::test]
    async fn revalidation_rejects_a_missing_target_version() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();

        let result = store.revalidation_report("task", 2, 100, None).await;

        assert!(matches!(result, Err(EntityError::UnknownSchema(id)) if id == "task"));
    }

    #[tokio::test]
    async fn a_migration_dry_run_reports_the_change_without_a_write() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        let created = store
            .create(draft("e1", &["task"], vec![("title", s("one"))]), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("note", AttributeType::String),
                ],
            ))
            .await
            .unwrap();

        let report = store
            .migrate_schema("task", 2, 100, None, true, &ctx())
            .await
            .unwrap();

        assert_eq!(report.scanned, 1);
        assert_eq!(report.migrated, 1);
        assert_eq!(report.unchanged, 0);
        assert!(report.invalid.is_empty());
        assert!(report.dry_run);
        assert_eq!(store.get("e1").await.unwrap(), Some(created));
    }

    #[tokio::test]
    async fn a_migration_apply_repins_the_entity_and_emits_one_event() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("title", s("one"))]), &ctx())
            .await
            .unwrap();
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("note", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        let write_ctx = WriteContext::new("alice")
            .with_correlation_id("req-1")
            .with_causation("evt-0", 1);

        let report = store
            .migrate_schema("task", 2, 100, None, false, &write_ctx)
            .await
            .unwrap();

        assert_eq!(report.scanned, 1);
        assert_eq!(report.migrated, 1);
        assert!(!report.dry_run);
        let entity = store.get("e1").await.unwrap().unwrap();
        assert_eq!(entity.version, 2);
        assert_eq!(
            entity.schemas,
            vec![SchemaRef {
                id: "task".to_string(),
                version: 2,
            }]
        );
        assert_eq!(entity.attributes["title"], s("one"));
        assert!(!entity.attributes.contains_key("note"));

        let events = feed.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.kind, EntityEventKind::SchemaApplied);
        assert_eq!(event.entity_id, "e1");
        assert_eq!(event.entity_version, 2);
        assert_eq!(event.schemas, vec!["task".to_string()]);
        assert!(event.changed.is_empty());
        assert_eq!(event.actor, "alice");
        assert_eq!(event.causation_id.as_deref(), Some("evt-0"));
        assert_eq!(event.causation_depth, 1);
        assert_eq!(event.correlation_id, "req-1");
        assert_eq!(
            event.snapshot.as_ref().unwrap()["title"],
            serde_json::json!("one")
        );
        assert!(outbox_keys(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn a_migration_reports_an_invalid_entity_and_leaves_it_unchanged() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        let created = store
            .create(draft("e1", &["task"], vec![("title", s("one"))]), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    full_attr("owner", AttributeType::String, true, false, false, None),
                ],
            ))
            .await
            .unwrap();

        let report = store
            .migrate_schema("task", 2, 100, None, false, &ctx())
            .await
            .unwrap();

        assert_eq!(report.scanned, 1);
        assert_eq!(report.migrated, 0);
        assert_eq!(report.invalid.len(), 1);
        assert_eq!(report.invalid[0].entity_id, "e1");
        assert_eq!(
            report.invalid[0].issue,
            RevalidationIssue::MissingRequired("owner".to_string())
        );
        assert_eq!(store.get("e1").await.unwrap(), Some(created));
    }

    #[tokio::test]
    async fn a_migration_counts_an_entity_that_already_pins_the_target_as_unchanged() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("title", s("one"))]), &ctx())
            .await
            .unwrap();

        let report = store
            .migrate_schema("task", 1, 100, None, false, &ctx())
            .await
            .unwrap();

        assert_eq!(report.scanned, 1);
        assert_eq!(report.migrated, 0);
        assert_eq!(report.unchanged, 1);
        assert_eq!(store.get("e1").await.unwrap().unwrap().version, 1);
    }

    #[tokio::test]
    async fn a_migration_honors_the_limit_and_limit_zero() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();

        let limited = store
            .migrate_schema("task", 2, 2, None, true, &ctx())
            .await
            .unwrap();
        assert_eq!(limited.scanned, 2);
        assert_eq!(limited.migrated, 2);
        assert_eq!(limited.next.as_deref(), Some("b"));

        let empty = store
            .migrate_schema("task", 2, 0, None, true, &ctx())
            .await
            .unwrap();
        assert_eq!(empty.scanned, 0);
        assert_eq!(empty.migrated, 0);
        assert_eq!(empty.unchanged, 0);
        assert!(empty.invalid.is_empty());
        assert!(empty.dry_run);
        assert_eq!(empty.next, None);
    }

    #[tokio::test]
    async fn a_migration_pages_through_every_entity_by_cursor() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d", "e"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();

        let mut after = None;
        let mut migrated = 0;
        let mut pages = 0;
        loop {
            let report = store
                .migrate_schema("task", 2, 2, after.as_deref(), false, &ctx())
                .await
                .unwrap();
            migrated += report.migrated;
            after = report.next;
            pages += 1;
            assert!(pages <= 10, "the cursor loop did not terminate");
            if after.is_none() {
                break;
            }
        }

        assert_eq!(migrated, 5);
        assert_eq!(pages, 3);
        for id in ["a", "b", "c", "d", "e"] {
            let entity = store.get(id).await.unwrap().unwrap();
            assert_eq!(entity.version, 2);
            assert_eq!(
                entity.schemas,
                vec![SchemaRef {
                    id: "task".to_string(),
                    version: 2,
                }]
            );
        }
    }

    #[tokio::test]
    async fn a_migration_that_reads_a_partial_page_returns_no_cursor() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();

        let report = store
            .migrate_schema("task", 2, 5, None, true, &ctx())
            .await
            .unwrap();

        assert_eq!(report.scanned, 3);
        assert_eq!(report.next, None);
    }

    #[tokio::test]
    async fn a_revalidation_pages_through_every_entity_by_cursor() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d", "e"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();

        let mut after = None;
        let mut scanned = 0;
        let mut compatible = 0;
        let mut pages = 0;
        loop {
            let report = store
                .revalidation_report("task", 2, 2, after.as_deref())
                .await
                .unwrap();
            scanned += report.scanned;
            compatible += report.compatible;
            after = report.next;
            pages += 1;
            assert!(pages <= 10, "the cursor loop did not terminate");
            if after.is_none() {
                break;
            }
        }

        assert_eq!(scanned, 5);
        assert_eq!(compatible, 5);
        assert_eq!(pages, 3);
    }

    #[tokio::test]
    async fn a_migration_rejects_a_missing_target_version() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();

        let result = store
            .migrate_schema("task", 2, 100, None, true, &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::UnknownSchema(id)) if id == "task"));
    }

    #[tokio::test]
    async fn a_migration_rejects_a_stale_entity_version() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![("title", s("one"))]), &ctx())
            .await
            .unwrap();
        let stale = store.get("e1").await.unwrap().unwrap();
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("note", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        store
            .update("e1", 1, patch(vec![("title", Some(s("two")))]), &ctx())
            .await
            .unwrap();

        let result = store
            .apply_schema_migration_batch(std::slice::from_ref(&stale), "task", 2, &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::VersionConflict)));
        let entity = store.get("e1").await.unwrap().unwrap();
        assert_eq!(entity.version, 2);
        assert_eq!(entity.schemas[0].version, 1);
        assert_eq!(entity.attributes["title"], s("two"));
    }

    #[tokio::test]
    async fn a_migration_batch_repins_two_entities_and_emits_two_events() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        for id in ["e1", "e2"] {
            store
                .create(draft(id, &["task"], vec![("title", s(id))]), &ctx())
                .await
                .unwrap();
        }
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("note", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        let report = store
            .migrate_schema("task", 2, 100, None, false, &ctx())
            .await
            .unwrap();

        assert_eq!(report.scanned, 2);
        assert_eq!(report.migrated, 2);
        assert_eq!(report.unchanged, 0);
        assert!(report.invalid.is_empty());
        for id in ["e1", "e2"] {
            let entity = store.get(id).await.unwrap().unwrap();
            assert_eq!(entity.version, 2);
            assert_eq!(
                entity.schemas,
                vec![SchemaRef {
                    id: "task".to_string(),
                    version: 2,
                }]
            );
        }
        let events = feed.events();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event.kind == EntityEventKind::SchemaApplied)
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.entity_id == "e1")
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.entity_id == "e2")
                .count(),
            1
        );
        assert!(outbox_keys(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn a_migration_batch_skips_one_invalid_entity_and_repins_the_valid_one() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("owner", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        store
            .create(
                draft(
                    "e1",
                    &["task"],
                    vec![("title", s("one")), ("owner", s("alice"))],
                ),
                &ctx(),
            )
            .await
            .unwrap();
        store
            .create(draft("e2", &["task"], vec![("title", s("two"))]), &ctx())
            .await
            .unwrap();
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    full_attr("owner", AttributeType::String, true, false, false, None),
                ],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        let report = store
            .migrate_schema("task", 2, 100, None, false, &ctx())
            .await
            .unwrap();

        assert_eq!(report.scanned, 2);
        assert_eq!(report.migrated, 1);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.invalid.len(), 1);
        assert_eq!(report.invalid[0].entity_id, "e2");
        assert_eq!(
            report.invalid[0].issue,
            RevalidationIssue::MissingRequired("owner".to_string())
        );
        let valid = store.get("e1").await.unwrap().unwrap();
        assert_eq!(valid.version, 2);
        assert_eq!(valid.schemas[0].version, 2);
        let invalid = store.get("e2").await.unwrap().unwrap();
        assert_eq!(invalid.version, 1);
        assert_eq!(invalid.schemas[0].version, 1);
        let events = feed.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].entity_id, "e1");
        assert!(outbox_keys(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn a_migration_dry_run_writes_no_key_and_no_event() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        for id in ["e1", "e2"] {
            store
                .create(draft(id, &["task"], vec![("title", s(id))]), &ctx())
                .await
                .unwrap();
        }
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("note", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        let report = store
            .migrate_schema("task", 2, 100, None, true, &ctx())
            .await
            .unwrap();

        assert_eq!(report.scanned, 2);
        assert_eq!(report.migrated, 2);
        assert!(report.dry_run);
        for id in ["e1", "e2"] {
            let entity = store.get(id).await.unwrap().unwrap();
            assert_eq!(entity.version, 1);
            assert_eq!(entity.schemas[0].version, 1);
        }
        assert!(feed.events().is_empty());
        assert!(outbox_keys(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn a_stale_version_leaves_every_entity_in_the_batch_unchanged() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        for id in ["e1", "e2"] {
            store
                .create(draft(id, &["task"], vec![("title", s(id))]), &ctx())
                .await
                .unwrap();
        }
        let checked = store.list_by_schema("task").await.unwrap();
        assert_eq!(checked.len(), 2);
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("note", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        store
            .update("e2", 1, patch(vec![("title", Some(s("two")))]), &ctx())
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());

        let result = store
            .apply_schema_migration_batch(&checked, "task", 2, &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::VersionConflict)));
        let first = store.get("e1").await.unwrap().unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(first.schemas[0].version, 1);
        let second = store.get("e2").await.unwrap().unwrap();
        assert_eq!(second.version, 2);
        assert_eq!(second.schemas[0].version, 1);
        assert!(feed.events().is_empty());
    }

    #[tokio::test]
    async fn a_store_failure_leaves_every_entity_in_the_batch_unchanged() {
        use oxkv::Hooks as _;

        struct RejectMetaKey(String);

        #[async_trait::async_trait]
        impl oxkv::Validator for RejectMetaKey {
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

        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();
        for id in ["e1", "e2"] {
            store
                .create(draft(id, &["task"], vec![("title", s(id))]), &ctx())
                .await
                .unwrap();
        }
        registry
            .publish(schema(
                "task",
                &[],
                vec![
                    attr("title", AttributeType::String),
                    attr("note", AttributeType::String),
                ],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        raw.add_validator(RejectMetaKey(meta_key("e2")));

        let result = store
            .migrate_schema("task", 2, 100, None, false, &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::Store(_))));
        for id in ["e1", "e2"] {
            let entity = store.get(id).await.unwrap().unwrap();
            assert_eq!(entity.version, 1);
            assert_eq!(entity.schemas[0].version, 1);
        }
        assert!(feed.events().is_empty());
        assert!(outbox_keys(&raw).await.is_empty());
    }

    async fn reference_store(check: bool) -> (EntityStore, SchemaRegistry) {
        let registry = SchemaRegistry::new(build_test_store(&test_prefix("eav-ref-schema")).await);
        let raw = build_test_store(&test_prefix("eav-ref")).await;
        let store = EntityStore::new(raw, registry.clone()).with_entity_ref_check(check);
        registry
            .publish(schema(
                "customer",
                &[],
                vec![attr("name", AttributeType::String)],
            ))
            .await
            .unwrap();
        registry
            .publish(schema(
                "order",
                &[],
                vec![attr("customer", AttributeType::EntityRef)],
            ))
            .await
            .unwrap();
        (store, registry)
    }

    fn customer(id: &str) -> EntityDraft {
        draft(id, &["customer"], vec![("name", s(id))])
    }

    fn order(id: &str, target: &str) -> EntityDraft {
        draft(
            id,
            &["order"],
            vec![("customer", AttributeValue::EntityRef(target.to_string()))],
        )
    }

    #[tokio::test]
    async fn a_dangling_reference_is_rejected_on_create() {
        let (store, _) = reference_store(true).await;

        let error = store
            .create(order("o1", "missing"), &ctx())
            .await
            .unwrap_err();

        assert!(
            matches!(
                &error,
                EntityError::DanglingRef(name, target)
                    if name == "customer" && target == "missing"
            ),
            "unexpected error: {error}"
        );
        assert!(store.get("o1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_reference_to_an_existing_entity_and_a_self_reference_are_accepted() {
        let (store, registry) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();

        store.create(order("o1", "c1"), &ctx()).await.unwrap();
        registry
            .publish(schema(
                "node",
                &[],
                vec![attr("parent", AttributeType::EntityRef)],
            ))
            .await
            .unwrap();
        store
            .create(
                draft(
                    "n1",
                    &["node"],
                    vec![("parent", AttributeValue::EntityRef("n1".to_string()))],
                ),
                &ctx(),
            )
            .await
            .unwrap();

        let stored = store.get("o1").await.unwrap().unwrap();
        assert_eq!(
            stored.attributes.get("customer"),
            Some(&AttributeValue::EntityRef("c1".to_string()))
        );
    }

    #[tokio::test]
    async fn an_update_to_a_missing_reference_keeps_the_old_row() {
        let (store, _) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();
        let patch = EntityPatch {
            attributes: [(
                "customer".to_string(),
                Some(AttributeValue::EntityRef("missing".to_string())),
            )]
            .into_iter()
            .collect(),
        };

        let error = store.update("o1", 1, patch, &ctx()).await.unwrap_err();

        assert!(matches!(error, EntityError::DanglingRef(_, _)));
        let stored = store.get("o1").await.unwrap().unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(
            stored.attributes.get("customer"),
            Some(&AttributeValue::EntityRef("c1".to_string()))
        );
    }

    #[tokio::test]
    async fn the_check_can_be_turned_off_but_the_target_form_is_still_checked() {
        let (store, _) = reference_store(false).await;

        store.create(order("o1", "missing"), &ctx()).await.unwrap();
        let error = store
            .create(order("o2", "bad:id"), &ctx())
            .await
            .unwrap_err();

        assert!(store.get("o1").await.unwrap().is_some());
        assert!(matches!(error, EntityError::Invalid(_)));
    }

    #[tokio::test]
    async fn a_default_reference_to_a_missing_entity_is_rejected() {
        let (store, registry) = reference_store(true).await;
        registry
            .publish(schema(
                "ticket",
                &[],
                vec![full_attr(
                    "owner",
                    AttributeType::EntityRef,
                    false,
                    false,
                    false,
                    Some(serde_json::json!("missing")),
                )],
            ))
            .await
            .unwrap();

        let error = store
            .create(draft("t1", &["ticket"], vec![]), &ctx())
            .await
            .unwrap_err();

        assert!(matches!(error, EntityError::DanglingRef(_, _)));
        assert!(store.get("t1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_delete_does_not_remove_a_reference() {
        let (store, _) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();

        store.delete("c1", 1, &ctx()).await.unwrap();

        let stored = store.get("o1").await.unwrap().unwrap();
        assert_eq!(
            stored.attributes.get("customer"),
            Some(&AttributeValue::EntityRef("c1".to_string()))
        );
        let error = store.create(order("o2", "c1"), &ctx()).await.unwrap_err();
        assert!(matches!(error, EntityError::DanglingRef(_, _)));
    }

    #[tokio::test]
    async fn a_migration_that_introduces_a_dangling_reference_writes_no_row() {
        let (store, registry) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();
        store.delete("c1", 1, &ctx()).await.unwrap();
        registry
            .publish(schema(
                "order",
                &[],
                vec![
                    attr("customer", AttributeType::EntityRef),
                    attr("note", AttributeType::String),
                ],
            ))
            .await
            .unwrap();

        let result = store
            .migrate_schema("order", 2, 100, None, false, &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::DanglingRef(_, _))));
        let stored = store.get("o1").await.unwrap().unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(stored.schemas[0].version, 1);
    }
}
