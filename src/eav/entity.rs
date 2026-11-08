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
//! - `idx:schema:{schema_id}:{entity_id}` is an empty schema marker.
//! - `idx:attr:{key}:{hash}:{entity_id}` is an empty attribute marker.
//! - `idx:unique:{key}:{hash}:{entity_id}` is a unique value marker.
//!
//! The `hash` is the lowercase SHA-256 hex of the canonical tagged JSON value.
//! A schema marker exists for the pinned schema and for each inherited schema.
//! All scans stop at the `prefix:` to `prefix;` bound.
//!
//! # Entity events
//!
//! The store returns an [`EntityChange`].
//! A store with a change sink writes one [`EntityEvent`] to an outbox row.
//! The outbox row commits in the same transaction as the entity rows.
//! The store then flushes the outbox to the feed.
//! A failure after the commit is [`EntityError::Feed`].
//! The data and the outbox row stay committed in that case.
//! The caller can call [`EntityStore::flush_outbox`] again.
//! Delivery is at least once.
//! A consumer must be idempotent.
//!
//! An update changes attributes only.
//! A later operation changes the pinned schemas.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oxkv::{Direction, GetSet, KeyValue, OxKvStore, Store as _, Transaction as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

use crate::eav::entity_error::EntityError;
use crate::eav::error::SchemaError;
use crate::eav::schema::{AttributeDef, AttributeType, EffectiveSchema, SchemaRef, SchemaRegistry};
use crate::records::{AttributeChange, ChangeSink, EntityEvent, EntityEventKind, WalOp};

/// Key prefix for entity rows.
const ENTITY_PREFIX: &str = "entity:";

/// Key prefix for pending outbox rows.
const OUTBOX_PREFIX: &str = "outbox:";

/// Suffix for the metadata row of an entity.
const META_SUFFIX: &str = ":meta";

/// Infix before an attribute key.
const ATTR_INFIX: &str = ":attr:";

/// Key prefix for schema index markers.
const SCHEMA_INDEX_PREFIX: &str = "idx:schema:";

/// Key prefix for attribute index markers.
const ATTR_INDEX_PREFIX: &str = "idx:attr:";

/// Key prefix for unique index markers.
const UNIQUE_INDEX_PREFIX: &str = "idx:unique:";

/// Maximum size of an entity id or an attribute name, in bytes.
const MAX_NAME_BYTES: usize = 128;

/// One typed attribute value.
///
/// The serde form is adjacent and tagged.
/// The `type` field makes the type explicit on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// A new entity, before the store assigns a version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityPatch {
    /// The changes, keyed by attribute name.
    pub attributes: BTreeMap<String, Option<AttributeValue>>,
}

/// One stored entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteContext {
    /// The subject that made the change.
    pub actor: String,
    /// Identifier that groups events from one request or workflow.
    pub correlation_id: Option<String>,
    /// Identifier of the event that caused this change.
    pub causation_id: Option<String>,
}

impl WriteContext {
    /// Creates a context for `actor` with no correlation id and no cause.
    pub fn new(actor: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            correlation_id: None,
            causation_id: None,
        }
    }

    /// Sets the correlation id.
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Sets the causation id.
    pub fn with_causation_id(mut self, id: impl Into<String>) -> Self {
        self.causation_id = Some(id.into());
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
        }
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
            let outbox =
                self.prepare_outbox(None, Some(&entity), event_schema_ids(&effective), ctx)?;
            check_unique_values(&tx, &entity, &merged.attributes).await?;
            put_entity_rows(&tx, &entity, &merged).await?;
            if let Some((key, bytes)) = &outbox {
                tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
            }
            tx.commit().await.map_err(EntityError::Store)?;
            outbox.is_some()
        };
        if pending {
            self.flush_after_commit().await?;
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
            let outbox = self.prepare_outbox(
                Some(&before),
                Some(&after),
                event_schema_ids(&effective),
                ctx,
            )?;

            check_unique_values(&tx, &after, &merged.attributes).await?;
            delete_mutable_rows(&tx, &before, &merged).await?;
            put_entity_rows(&tx, &after, &merged).await?;
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
        if pending {
            self.flush_after_commit().await?;
        }
        Ok(change)
    }

    /// Deletes one entity and returns the change.
    ///
    /// The expected version must match the stored version.
    /// A mismatch is a version conflict and changes nothing.
    /// The call removes the metadata row and every attribute and index row.
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
            for schema_id in &merged.schema_ids {
                tx.delete(&schema_index_key(schema_id, id))
                    .await
                    .map_err(EntityError::Store)?;
            }
            tx.delete(&meta_key(id)).await.map_err(EntityError::Store)?;
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
        if pending {
            self.flush_after_commit().await?;
        }
        Ok(change)
    }

    /// Delivers every pending outbox row to the change feed.
    ///
    /// The call returns `Ok(0)` when no feed is configured.
    /// It reads the rows in key order.
    /// For each row, it appends the event and then deletes the row.
    /// It stops at the first append failure.
    /// That row and every later row stay in the outbox.
    /// The call does not hold the store write guard during the append.
    ///
    /// Delivery is at least once.
    /// A crash after an append and before a delete can deliver one event
    /// again.
    /// A consumer must be idempotent.
    pub async fn flush_outbox(&self) -> Result<usize, EntityError> {
        let Some(feed) = &self.feed else {
            return Ok(0);
        };
        let _flush = self.flush_lock.lock().await;
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
            drop(g);
            delivered += 1;
        }
        Ok(delivered)
    }

    /// Flushes the outbox after a commit.
    ///
    /// A flush failure is a delivery error.
    /// The data and the outbox row stay committed.
    async fn flush_after_commit(&self) -> Result<(), EntityError> {
        self.flush_outbox()
            .await
            .map(|_| ())
            .map_err(|_| EntityError::Feed("entity feed append failed".to_string()))
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

    /// Lists the entities with an indexed attribute equal to `value`.
    ///
    /// The call returns an error when no applied schema indexes `key`.
    /// The result is sorted by entity id.
    pub async fn list_by_attribute(
        &self,
        key: &str,
        value: &AttributeValue,
    ) -> Result<Vec<Entity>, EntityError> {
        validate_name("attribute name", key)?;
        let hash = value_hash(value)?;
        let g = self.store.read().await;
        let family = format!("{ATTR_INDEX_PREFIX}{key}:");
        if scan_prefix(&*g, &family).await?.is_empty() && !self.attribute_is_indexed(key).await? {
            return Err(EntityError::NotIndexed(key.to_string()));
        }

        let prefix = format!("{family}{hash}:");
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
            if let Some(entity) = load_entity(&*g, id).await?
                && entity.attributes.get(key) == Some(value)
            {
                entities.push(entity);
            }
        }
        entities.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entities)
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
    Ok(EntityEvent {
        event_id,
        entity_id: entity.id.clone(),
        entity_version: entity.version,
        kind,
        schemas,
        changed: changed_attributes(before, after)?,
        actor: ctx.actor.clone(),
        causation_id: ctx.causation_id.clone(),
        correlation_id,
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
        if def.unique {
            delete_unique_if_owned(store, key, value, &entity.id).await?;
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

/// The marker key for one unique attribute value and entity.
fn unique_key(key: &str, hash: &str, entity_id: &str) -> String {
    format!("{UNIQUE_INDEX_PREFIX}{key}:{hash}:{entity_id}")
}

/// The scan prefix for every unique marker of one value hash.
fn unique_prefix(key: &str, hash: &str) -> String {
    format!("{UNIQUE_INDEX_PREFIX}{key}:{hash}:")
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

    fn ctx() -> WriteContext {
        WriteContext::new("tester")
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

    fn tagged(value: &AttributeValue) -> serde_json::Value {
        serde_json::to_value(value).unwrap()
    }

    /// A [`ChangeSink`] test double that records every operation.
    ///
    /// The `failing` switch makes every append fail.
    struct RecordingFeed {
        ops: std::sync::Mutex<Vec<WalOp>>,
        failing: std::sync::atomic::AtomicBool,
    }

    impl RecordingFeed {
        fn new() -> Self {
            Self {
                ops: std::sync::Mutex::new(Vec::new()),
                failing: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn set_failing(&self, failing: bool) {
            self.failing
                .store(failing, std::sync::atomic::Ordering::SeqCst);
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
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
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
    async fn delete_removes_entity_and_index_markers() {
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

        assert!(all_keys(&raw).await.is_empty());
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
    async fn a_failed_append_keeps_the_entity_and_the_outbox_row() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        feed.set_failing(true);
        let store = store.with_change_sink(feed.clone());

        let result = store.create(draft("e1", &["person"], vec![]), &ctx()).await;

        assert!(matches!(result, Err(EntityError::Feed(_))));
        assert!(store.get("e1").await.unwrap().is_some());
        assert_eq!(outbox_keys(&raw).await.len(), 1);

        feed.set_failing(false);
        assert_eq!(store.flush_outbox().await.unwrap(), 1);
        assert!(store.get("e1").await.unwrap().is_some());
        assert!(outbox_keys(&raw).await.is_empty());
        let events = feed.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].entity_id, "e1");
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
            let result = store.create(draft(id, &["person"], vec![]), &ctx()).await;
            assert!(matches!(result, Err(EntityError::Feed(_))));
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
}
