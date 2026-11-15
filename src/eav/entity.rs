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
//! - `idx:ref:{target_id}:{source_id}:{attribute}` is an empty reverse
//!   reference marker. The marker records that `source_id` holds an
//!   `EntityRef` value for `attribute` that names `target_id`.
//!   A self-reference has `source_id == target_id`.
//! - `idx:ref-meta:backfilled` is an empty backfill marker.
//! - `idx:schema:{schema_id}:{entity_id}` is an empty schema marker.
//! - `idx:attr:{key}:{hash}:{entity_id}` is an empty attribute marker.
//! - `idx:attr-key:{key}` is an empty name marker that records that some
//!   schema version marks the attribute as indexed. A schema publish writes
//!   the marker. The marker is permanent.
//! - `idx:unique-key:{key}` is an empty name marker that records that some
//!   schema version marks the attribute as unique. A schema publish writes
//!   the marker. The marker is permanent.
//! - `idx:unique:{key}:{hash}` is the claim for one unique value. The value
//!   is the owning entity id. The key holds no entity id, so a write from
//!   another handle conflicts at commit.
//! - `idx:unique-c:{key}:{hash}:{entity_id}` is a claim for a value whose
//!   hash collides with the primary claim.
//! - `idx:unique:{key}:{hash}:{entity_id}` is a legacy unique value marker.
//!   A write still checks it and releases it. No new marker uses this form.
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
//! The pass reads 200 `entity:` rows in one page.
//! A test build reads 2 rows in one page.
//! Each page holds the write lock and the store write guard.
//! The pass writes the page markers, commits, and releases both guards.
//! It re-checks each metadata row inside the page lock.
//! The cursor is the last key plus a NUL byte, so a deleted key does not
//! reset progress.
//! The memory bound is one page of rows.
//! A concurrent create or delete writes its own markers on the normal path.
//! A store without the markers still returns entity pages after the pass.
//!
//! An existing store can also lack the reverse reference markers.
//! [`EntityStore::delete`] then backfills them one time.
//! The `idx:ref-meta:backfilled` marker records that pass.
//! The pass reads 200 entity markers in one page.
//! A test build reads 2 entity markers in one page.
//! Each page holds the write lock and the store write guard.
//! The pass writes the page markers, commits, and releases both guards.
//! It re-checks that the entity marker and the entity row exist inside the
//! page lock.
//! The cursor is the last key plus a NUL byte.
//! The memory bound is one page of entity ids and the attributes of one
//! entity.
//!
//! An existing store can also lack the time key markers.
//! [`EntityStore::time_keys`] then backfills them one time.
//! The `idx:time-key-meta:backfilled` marker records that pass.
//! The pass reads 200 `idx:time:` rows in one page.
//! A test build reads 2 rows in one page.
//! Each page holds the write lock and the store write guard.
//! The pass writes the page markers, commits, and releases both guards.
//! It re-checks that a time row still exists for each key inside the page
//! lock.
//! The cursor is the last key plus a NUL byte.
//! The memory bound is one page of keys.
//!
//! A delete scans the `idx:ref:{id}:` family before it writes.
//! A distinct source other than `id` blocks the delete with
//! [`EntityError::Referenced`] unless the caller sets `force`.
//! A self-reference does not block the delete.
//! The delete holds the write lock for the scan and the write, so a
//! reference write cannot appear after the scan.
//!
//! # Attribute and unique index scope
//!
//! The attribute index and the unique constraint key on the attribute name.
//! The key includes no schema id.
//! An attribute index and a unique constraint therefore apply across every
//! schema that uses the name.
//! A unique value blocks a second entity in any schema with that attribute
//! name.
//! Use a distinct name when two schemas must not share the domain.
//! A write checks the name markers, so a schema that does not set the flag
//! still participates when another schema sets it.
//! A query checks the latest schema version instead of the name marker, so a
//! removed index returns [`EntityError::NotIndexed`](crate::eav::entity_error::EntityError::NotIndexed).
//! A query also accepts a key when a stored row for that key still exists.
//! An entity that pins an older version that indexes the name stays
//! queryable.
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
//! A flush deletes one row and decrements the counter in one transaction.
//! The transaction commits both changes or neither change.
//! The counter is always equal to the number of `outbox:` rows.
//! One flush reads at most 100 rows at one time.
//! A test build reads at most 2 rows at one time.
//! A failed feed append stops the flush and changes no row and no counter.
//! A failed transaction stops the flush and changes no row and no counter.
//! When the counter key is absent, [`EntityStore::outbox_count`] scans the
//! `outbox:` family one time and writes the exact count.
//! The backfill runs at most once.
//! A crash before the counter write retries safely.
//!
//! An update changes attributes only.
//! A later operation changes the pinned schemas.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oxkv::{
    Direction, GetSet, KeyPrefix, KeyValue, OxKvStore, ScanExt as _, Store as _, StoreError,
    Transaction as _, TxCas,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock};

use crate::eav::MAX_PAGE_OFFSET;
use crate::eav::entity_error::EntityError;
use crate::eav::error::SchemaError;
use crate::eav::schema::{AttributeDef, AttributeType, EffectiveSchema, SchemaRef, SchemaRegistry};
use crate::records::{AttributeChange, ChangeSink, EntityEvent, EntityEventKind, WalOp};
use crate::rules::effect::{EffectPlan, EntityEffect};

/// Key prefix for entity rows.
const ENTITY_PREFIX: &str = "entity:";

/// Key prefix for pending outbox rows.
const OUTBOX_PREFIX: &str = "outbox:";

/// Key prefix for outbox rows that no consumer can decode.
///
/// The key does not start with [`OUTBOX_PREFIX`], so a poison row does not
/// appear in a later outbox scan.
const OUTBOX_POISON_PREFIX: &str = "outbox-poison:";

/// Key for the durable pending outbox row counter.
///
/// The key does not start with [`OUTBOX_PREFIX`], so an outbox scan does not
/// count it as a row.
const OUTBOX_PENDING_KEY: &str = "outbox-meta:pending";

/// Maximum number of outbox rows to read in one flush batch.
#[cfg(not(test))]
const OUTBOX_FLUSH_BATCH: usize = 100;

/// Maximum number of outbox rows to read in one flush batch.
#[cfg(test)]
const OUTBOX_FLUSH_BATCH: usize = 2;

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

/// Key prefix for reverse reference markers.
const REF_INDEX_PREFIX: &str = "idx:ref:";

/// Key prefix for reverse reference metadata.
const REF_META_PREFIX: &str = "idx:ref-meta:";

/// Key suffix for the one-time reverse reference backfill marker.
const REF_BACKFILL_SUFFIX: &str = "backfilled";

/// Maximum number of rows that one lazy backfill page reads.
#[cfg(not(test))]
const BACKFILL_PAGE: usize = 200;

/// Maximum number of rows that one lazy backfill page reads.
#[cfg(test)]
const BACKFILL_PAGE: usize = 2;

/// Number of reverse reference keys that one incoming scan reads.
#[cfg(not(test))]
const REF_SCAN_PAGE: usize = 512;

/// Number of reverse reference keys that one incoming scan reads.
#[cfg(test)]
const REF_SCAN_PAGE: usize = 2;

/// A test hook that runs after a lazy backfill page releases its locks.
#[cfg(test)]
type BackfillPageHook =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

/// Key prefix for attribute index markers.
const ATTR_INDEX_PREFIX: &str = "idx:attr:";

/// Key prefix for the name marker of an indexed attribute.
pub(crate) const ATTR_KEY_PREFIX: &str = "idx:attr-key:";

/// Key prefix for unique value claims.
const UNIQUE_CLAIM_PREFIX: &str = "idx:unique:";

/// Key prefix for the name marker of a unique attribute.
pub(crate) const UNIQUE_KEY_PREFIX: &str = "idx:unique-key:";

/// Key prefix for a unique claim that resolves a hash collision.
const UNIQUE_EXTRA_PREFIX: &str = "idx:unique-c:";

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
    /// Another entity already holds the same unique attribute value.
    DuplicateUnique(String),
    /// An `EntityRef` value names an entity that does not exist.
    ///
    /// The field is the attribute name.
    DanglingRef(String),
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

/// One entity state and one optional outbox row for a batch write.
struct SchemaMigrationWrite {
    /// The entity before the migration.
    before: Entity,
    /// The merged schema before the migration.
    before_merged: MergedSchema,
    /// The entity after the migration.
    entity: Entity,
    /// The merged schema after the migration.
    after_merged: MergedSchema,
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
    /// The number of outbox row deletes to fail in a test.
    #[cfg(test)]
    outbox_delete_failures: Arc<std::sync::atomic::AtomicUsize>,
    /// The largest outbox batch that a flush read in a test.
    #[cfg(test)]
    outbox_batch_peak: Arc<std::sync::atomic::AtomicUsize>,
    /// The number of lazy backfill pages that committed in a test.
    #[cfg(test)]
    backfill_page_commits: Arc<std::sync::atomic::AtomicUsize>,
    /// A hook that runs after a lazy backfill page releases its locks in a
    /// test.
    #[cfg(test)]
    backfill_page_hook: Arc<std::sync::Mutex<Option<BackfillPageHook>>>,
    /// A hook that runs after a delete prepares and before it commits in a
    /// test.
    #[cfg(test)]
    delete_prepare_hook: Arc<std::sync::Mutex<Option<BackfillPageHook>>>,
}

/// One create after validation.
struct PreparedCreate {
    /// The entity with version 1 and the schema defaults applied.
    entity: Entity,
    /// The effective schemas that the entity pins.
    effective: Vec<EffectiveSchema>,
    /// The merged attribute definitions.
    merged: MergedSchema,
}

/// One update after validation.
struct PreparedUpdate {
    /// The entity before the update.
    before: Entity,
    /// The entity after the update.
    after: Entity,
    /// The effective schemas that the entity pins.
    effective: Vec<EffectiveSchema>,
    /// The merged attribute definitions.
    merged: MergedSchema,
}

/// One delete after validation.
struct PreparedDelete {
    /// The entity before the delete.
    before: Entity,
    /// The effective schemas that the entity pins.
    effective: Vec<EffectiveSchema>,
    /// The merged attribute definitions.
    merged: MergedSchema,
}

/// One entity after validation against a target schema version.
struct RevalidatedEntity {
    /// The stored attributes with the schema defaults applied.
    attributes: BTreeMap<String, AttributeValue>,
    /// The effective schemas of the target version.
    effective: Vec<EffectiveSchema>,
    /// The merged attribute definitions of the target version.
    merged: MergedSchema,
}

/// One failed revalidation.
enum RevalidationFailure {
    /// The entity fails the target schema version.
    Issue(RevalidationIssue),
    /// The store failed, so the call must propagate the error.
    Error(EntityError),
}

/// The name-level index facts for one write.
///
/// A durable name marker is the fast path.
/// A schema scan covers a store that has no marker for the name.
#[derive(Default)]
struct NameFacts {
    /// The attribute names that some schema version marks as indexed.
    indexed: BTreeSet<String>,
    /// The attribute names that some schema version marks as unique.
    unique: BTreeSet<String>,
}

/// The commit-time state of one transaction.
///
/// One plan applies several effects in one transaction.
/// The state stops a later effect from staging a second conflicting guard.
#[derive(Default)]
struct WriteState {
    /// The metadata keys with a staged commit-time guard.
    guarded_meta: BTreeSet<String>,
    /// The metadata keys that this transaction deletes.
    released_meta: BTreeSet<String>,
    /// The unique claim keys that this transaction releases.
    released_claims: BTreeSet<String>,
    /// The unique claim keys that this transaction stages, with the attribute
    /// name.
    claimed: BTreeMap<String, String>,
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
            #[cfg(test)]
            outbox_delete_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            outbox_batch_peak: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            backfill_page_commits: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            backfill_page_hook: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            delete_prepare_hook: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Records one committed lazy backfill page in a test.
    #[cfg(test)]
    fn note_backfill_page(&self) {
        self.backfill_page_commits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Records one committed lazy backfill page.
    #[cfg(not(test))]
    fn note_backfill_page(&self) {}

    /// Runs the test hook that stands in for a write between two pages.
    #[cfg(test)]
    async fn run_backfill_page_hook(&self) {
        let hook = self
            .backfill_page_hook
            .lock()
            .expect("backfill page hook lock")
            .clone();
        if let Some(hook) = hook {
            hook().await;
        }
    }

    /// Runs the hook that stands in for a write between two pages.
    #[cfg(not(test))]
    async fn run_backfill_page_hook(&self) {}

    /// Runs the hook that stands in for a concurrent write during a delete.
    #[cfg(test)]
    async fn run_delete_hook(&self) {
        let hook = self
            .delete_prepare_hook
            .lock()
            .expect("delete prepare hook lock")
            .clone();
        if let Some(hook) = hook {
            hook().await;
        }
    }

    /// Runs the hook that stands in for a concurrent write during a delete.
    #[cfg(not(test))]
    async fn run_delete_hook(&self) {}

    /// Sets the test hook that runs during a delete.
    #[cfg(test)]
    fn set_delete_hook(&self, hook: Option<BackfillPageHook>) {
        *self
            .delete_prepare_hook
            .lock()
            .expect("delete prepare hook lock") = hook;
    }

    /// Sets the test hook that runs after a lazy backfill page.
    #[cfg(test)]
    fn set_backfill_page_hook(&self, hook: Option<BackfillPageHook>) {
        *self
            .backfill_page_hook
            .lock()
            .expect("backfill page hook lock") = hook;
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

    /// Validates one create and builds the entity.
    ///
    /// The call resolves each schema id to its latest version.
    /// It applies the schema defaults and checks every attribute.
    /// The call writes no row.
    async fn prepare_create(&self, draft: EntityDraft) -> Result<PreparedCreate, EntityError> {
        validate_name("entity id", &draft.id)?;
        let effective = self.resolve_schemas(&draft.schemas).await?;
        let merged = merge_schemas(&effective)?;
        let mut attributes = draft.attributes;
        check_known(&attributes, &merged.attributes)?;
        validate_defaults(&merged.attributes)?;
        apply_defaults(&mut attributes, &merged.attributes, &BTreeSet::new())?;
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
        Ok(PreparedCreate {
            entity,
            effective,
            merged,
        })
    }

    /// Checks one create against the store and writes its rows.
    ///
    /// The call rejects an existing entity.
    /// It checks every entity reference and every unique value.
    /// It writes the metadata, attribute, and index rows.
    /// With `guard_meta`, the metadata write requires an absent committed
    /// row. Without it, a delete earlier in the plan already removed the row.
    /// The call returns the outbox row when a feed is configured.
    async fn stage_create<S>(
        &self,
        store: &S,
        prepared: &PreparedCreate,
        ctx: &WriteContext,
        state: &mut WriteState,
        guard_meta: bool,
    ) -> Result<Option<(String, Vec<u8>)>, EntityError>
    where
        S: TxCas + ?Sized + Sync,
    {
        let entity = &prepared.entity;
        // A duplicate create in one transaction must fail before commit.
        // The transaction reads its own staged writes, so this check sees an
        // earlier create in the same plan.
        if store
            .get_bytes(&meta_key(&entity.id))
            .await
            .map_err(EntityError::Store)?
            .is_some()
        {
            return Err(EntityError::AlreadyExists(entity.id.clone()));
        }
        self.check_entity_refs(
            store,
            &entity.id,
            &entity.attributes,
            &prepared.merged.attributes,
        )
        .await?;
        let facts = self
            .name_facts(
                store,
                &entity.attributes.keys().cloned().collect::<BTreeSet<_>>(),
            )
            .await?;
        let outbox = self.prepare_outbox(
            None,
            Some(entity),
            event_schema_ids(&prepared.effective),
            ctx,
        )?;
        check_unique_values(store, entity, &prepared.merged.attributes, &facts).await?;
        let meta = meta_key(&entity.id);
        let meta_bytes = meta_bytes(entity)?;
        if guard_meta {
            store
                .set_if_absent(&meta, &meta_bytes)
                .await
                .map_err(EntityError::Store)?;
            state.guarded_meta.insert(meta);
        } else {
            store
                .set_bytes(&meta, &meta_bytes)
                .await
                .map_err(EntityError::Store)?;
        }
        put_entity_rows_except_meta(store, entity, &prepared.merged, &facts, state).await?;
        Ok(outbox)
    }

    /// Validates one update and builds the after state.
    ///
    /// The call loads the entity and checks the expected version.
    /// It applies the patch and the schema defaults.
    /// A key that the patch removes stays removed.
    /// It checks every attribute.
    /// The call writes no row.
    async fn prepare_update<S>(
        &self,
        store: &S,
        id: &str,
        expected_version: u64,
        patch: &EntityPatch,
    ) -> Result<PreparedUpdate, EntityError>
    where
        S: GetSet + ?Sized,
    {
        validate_update_input(id, patch)?;
        let Some(before) = load_entity(store, id).await? else {
            return Err(EntityError::NotFound(id.to_string()));
        };
        if before.version != expected_version {
            return Err(EntityError::VersionConflict);
        }

        let effective = self.resolve_refs(&before.schemas).await?;
        let merged = merge_schemas(&effective)?;
        validate_defaults(&merged.attributes)?;
        let mut attributes = before.attributes.clone();
        let mut removed: BTreeSet<String> = BTreeSet::new();
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
                    removed.insert(key.clone());
                }
            }
        }
        apply_defaults(&mut attributes, &merged.attributes, &removed)?;
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
        Ok(PreparedUpdate {
            before,
            after,
            effective,
            merged,
        })
    }

    /// Checks one update against the store and writes its rows.
    ///
    /// The call checks every entity reference and every unique value.
    /// It removes the rows of the before state and writes the rows of the
    /// after state.
    /// With `guard_meta`, the metadata write requires the committed before
    /// row. Without it, an earlier effect in the plan already staged a guard.
    /// The call returns the outbox row when a feed is configured.
    async fn stage_update<S>(
        &self,
        store: &S,
        prepared: &PreparedUpdate,
        ctx: &WriteContext,
        guard_meta: bool,
        state: &mut WriteState,
    ) -> Result<Option<(String, Vec<u8>)>, EntityError>
    where
        S: TxCas + ?Sized + Sync,
    {
        let before = &prepared.before;
        let after = &prepared.after;
        self.check_entity_refs(
            store,
            &after.id,
            &after.attributes,
            &prepared.merged.attributes,
        )
        .await?;
        let outbox = self.prepare_outbox(
            Some(before),
            Some(after),
            event_schema_ids(&prepared.effective),
            ctx,
        )?;
        let facts = self
            .name_facts(store, &name_keys(before, Some(after)))
            .await?;
        check_unique_values(store, after, &prepared.merged.attributes, &facts).await?;
        delete_changed_timer_markers(store, before, after, &prepared.merged).await?;
        delete_mutable_rows(store, before, Some(after), &prepared.merged, &facts, state).await?;
        delete_ref_rows(store, before, &prepared.merged).await?;
        let before_meta = meta_bytes(before)?;
        let after_meta = meta_bytes(after)?;
        if guard_meta {
            store
                .compare_and_set(&meta_key(&after.id), Some(&before_meta), &after_meta)
                .await
                .map_err(EntityError::Store)?;
            state.guarded_meta.insert(meta_key(&after.id));
        } else {
            // An earlier effect in the same plan already staged the guard.
            // Its precondition covers the committed state.
            store
                .set_bytes(&meta_key(&after.id), &after_meta)
                .await
                .map_err(EntityError::Store)?;
        }
        put_entity_rows_except_meta(store, after, &prepared.merged, &facts, state).await?;
        Ok(outbox)
    }

    /// Validates one delete.
    ///
    /// The call loads the entity and checks the expected version.
    /// It counts the incoming references and rejects them unless `force` is
    /// true.
    /// The call writes no row.
    async fn prepare_delete<S>(
        &self,
        store: &S,
        id: &str,
        expected_version: u64,
        force: bool,
    ) -> Result<PreparedDelete, EntityError>
    where
        S: GetSet + ?Sized + Sync,
    {
        validate_name("entity id", id)?;
        let Some(before) = load_entity(store, id).await? else {
            return Err(EntityError::NotFound(id.to_string()));
        };
        if before.version != expected_version {
            return Err(EntityError::VersionConflict);
        }
        let count = count_incoming_refs(store, id).await?;
        if count > 0 && !force {
            return Err(EntityError::Referenced {
                id: id.to_string(),
                count,
            });
        }

        let effective = self.resolve_refs(&before.schemas).await?;
        let merged = merge_schemas(&effective)?;
        Ok(PreparedDelete {
            before,
            effective,
            merged,
        })
    }

    /// Writes the delete rows of one prepared delete.
    ///
    /// The call removes the metadata, attribute, and index rows.
    /// With `guard_meta`, the metadata delete requires the committed before
    /// row. Without it, an earlier effect in the plan already staged a guard.
    /// It returns the outbox row when a feed is configured.
    async fn stage_delete<S>(
        &self,
        store: &S,
        prepared: &PreparedDelete,
        ctx: &WriteContext,
        state: &mut WriteState,
        guard_meta: bool,
    ) -> Result<Option<(String, Vec<u8>)>, EntityError>
    where
        S: TxCas + ?Sized + Sync,
    {
        let before = &prepared.before;
        let facts = self.name_facts(store, &name_keys(before, None)).await?;
        let outbox = self.prepare_outbox(
            Some(before),
            None,
            event_schema_ids(&prepared.effective),
            ctx,
        )?;
        delete_mutable_rows(store, before, None, &prepared.merged, &facts, state).await?;
        delete_ref_rows(store, before, &prepared.merged).await?;
        delete_all_timer_markers(store, before, &prepared.merged).await?;
        for schema_id in &prepared.merged.schema_ids {
            store
                .delete(&schema_index_key(schema_id, &before.id))
                .await
                .map_err(EntityError::Store)?;
        }
        store
            .delete(&entity_index_key(&before.id))
            .await
            .map_err(EntityError::Store)?;
        let meta = meta_key(&before.id);
        if guard_meta {
            store
                .delete_if(&meta, &meta_bytes(before)?)
                .await
                .map_err(EntityError::Store)?;
            state.guarded_meta.insert(meta.clone());
        } else {
            store.delete(&meta).await.map_err(EntityError::Store)?;
        }
        state.released_meta.insert(meta);
        Ok(outbox)
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
        let prepared = self.prepare_create(draft).await?;
        let pending = {
            let _write = self.write_lock.lock().await;
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(EntityError::Store)?;
            let mut state = WriteState::default();
            let outbox = self
                .stage_create(&tx, &prepared, ctx, &mut state, true)
                .await?;
            if outbox.is_some() {
                increment_outbox_pending(&tx, 1).await?;
            }
            if let Some((key, bytes)) = &outbox {
                tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
            }
            match tx.commit().await {
                Ok(()) => {}
                Err(StoreError::TxConflict { key, .. }) if key == meta_key(&prepared.entity.id) => {
                    return Err(EntityError::AlreadyExists(prepared.entity.id.clone()));
                }
                Err(StoreError::TxConflict { key, .. }) => {
                    return Err(conflict_error(&state, &key));
                }
                Err(error) => return Err(EntityError::Store(error)),
            }
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
            after: Some(prepared.entity),
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
    /// A key that the patch removes stays removed.
    /// A required key that the patch removes returns an error.
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
        validate_update_input(id, &patch)?;

        let (change, pending) = {
            let _write = self.write_lock.lock().await;
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(EntityError::Store)?;
            let prepared = self
                .prepare_update(&tx, id, expected_version, &patch)
                .await?;
            let mut state = WriteState::default();
            let outbox = self
                .stage_update(&tx, &prepared, ctx, true, &mut state)
                .await?;
            if outbox.is_some() {
                increment_outbox_pending(&tx, 1).await?;
            }
            if let Some((key, bytes)) = &outbox {
                tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
            }
            match tx.commit().await {
                Ok(()) => {}
                Err(StoreError::TxConflict { key, .. }) => {
                    return Err(conflict_error(&state, &key));
                }
                Err(error) => return Err(EntityError::Store(error)),
            }
            (
                EntityChange {
                    before: Some(prepared.before),
                    after: Some(prepared.after),
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
    /// The call backfills the reverse reference markers for an old store.
    /// It then scans the markers for this entity.
    /// A distinct source entity blocks the delete with
    /// [`EntityError::Referenced`] unless `force` is true.
    /// The count excludes a self-reference.
    /// The call takes the write lock before the scan, so a reference write
    /// cannot appear after the scan.
    /// With `force`, the call leaves each incoming reference in place.
    /// Those references are dangling by request.
    /// The call does not edit the referring entities.
    /// The call removes the metadata row and every attribute and index row.
    /// The write succeeds when the entity rows and the outbox row commit.
    /// A feed failure after the commit leaves the outbox row for the relay.
    /// The call still returns success.
    pub async fn delete(
        &self,
        id: &str,
        expected_version: u64,
        force: bool,
        ctx: &WriteContext,
    ) -> Result<EntityChange, EntityError> {
        validate_name("entity id", id)?;
        self.backfill_ref_index().await?;
        let (change, pending) = {
            let _write = self.write_lock.lock().await;
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(EntityError::Store)?;
            let prepared = self
                .prepare_delete(&tx, id, expected_version, force)
                .await?;
            self.run_delete_hook().await;
            let mut state = WriteState::default();
            let outbox = self
                .stage_delete(&tx, &prepared, ctx, &mut state, true)
                .await?;
            if outbox.is_some() {
                increment_outbox_pending(&tx, 1).await?;
            }
            if let Some((key, bytes)) = &outbox {
                tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
            }
            match tx.commit().await {
                Ok(()) => {}
                Err(StoreError::TxConflict { key, .. }) => {
                    return Err(conflict_error(&state, &key));
                }
                Err(error) => return Err(EntityError::Store(error)),
            }
            (
                EntityChange {
                    before: Some(prepared.before),
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

    /// Applies an effect plan as one atomic write.
    ///
    /// The call delegates to [`EntityStore::apply_effects_with_marker`] with
    /// no marker.
    /// An empty plan returns an empty result and changes nothing.
    pub async fn apply_effects(
        &self,
        plan: &EffectPlan,
        ctx: &WriteContext,
    ) -> Result<Vec<EntityChange>, EntityError> {
        self.apply_effects_with_marker(plan, ctx, None).await
    }

    /// Applies an effect plan and an optional execution marker as one atomic
    /// write.
    ///
    /// The call validates the plan before it takes a lock.
    /// It rejects more than 100 effects.
    ///
    /// The marker is one key and one value.
    /// With a marker, the call writes the marker in the plan transaction.
    /// The marker and every effect commit together or not at all.
    /// A marker write failure rolls back every entity row, index row, outbox
    /// row, and the pending counter.
    /// An effect failure also rolls back the marker.
    ///
    /// An empty plan with a marker writes the marker only.
    /// An empty plan without a marker returns an empty result and changes
    /// nothing.
    ///
    /// The call holds the write lock and the store write guard for the whole
    /// plan.
    /// It opens one transaction and applies the effects in plan order.
    /// A plan with a delete runs the one-time reverse-reference backfill
    /// before the plan transaction, as the single delete call does.
    ///
    /// The OxKV transaction reads its own uncommitted writes.
    /// A later effect therefore sees every earlier create, update, and delete.
    /// The plan needs no separate overlay.
    /// A reference to an entity that an earlier effect created is valid.
    /// A self-reference is valid.
    ///
    /// Each effect uses the same validation and row helpers as the single
    /// effect methods.
    /// The call checks schemas, defaults, types, required fields, unique
    /// values, entity references, and expected versions.
    ///
    /// With a feed, the call writes one outbox event for each effect in plan
    /// order.
    /// It increments `outbox-meta:pending` by the number of outbox rows in
    /// the same transaction.
    ///
    /// One commit writes every entity row, index row, outbox row, the
    /// counter, and the marker.
    /// An error in any effect rolls back the whole plan and the marker.
    /// No row that an effect or the marker writes commits.
    ///
    /// The call flushes the outbox after the commit.
    /// A flush failure leaves the rows for the relay.
    /// The call returns the changes in plan order.
    pub async fn apply_effects_with_marker(
        &self,
        plan: &EffectPlan,
        ctx: &WriteContext,
        marker: Option<(&str, &[u8])>,
    ) -> Result<Vec<EntityChange>, EntityError> {
        plan.validate_allow_empty()?;
        if plan.is_empty() && marker.is_none() {
            return Ok(Vec::new());
        }
        if plan
            .effects()
            .iter()
            .any(|effect| matches!(effect, EntityEffect::Delete { .. }))
        {
            self.backfill_ref_index().await?;
        }

        let (changes, pending) = {
            let _write = self.write_lock.lock().await;
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(EntityError::Store)?;
            let mut changes = Vec::with_capacity(plan.len());
            let mut outbox_rows = Vec::new();
            let mut state = WriteState::default();
            for effect in plan.effects() {
                let (change, outbox) = match effect {
                    EntityEffect::Create {
                        id,
                        schemas,
                        attributes,
                    } => {
                        let prepared = self
                            .prepare_create(EntityDraft {
                                id: id.clone(),
                                schemas: schemas.clone(),
                                attributes: attributes.clone(),
                            })
                            .await?;
                        // A delete earlier in the plan removed the committed
                        // row, so a create then writes without a guard.
                        let guard_meta = !state.released_meta.contains(&meta_key(id));
                        let outbox = self
                            .stage_create(&tx, &prepared, ctx, &mut state, guard_meta)
                            .await?;
                        (
                            EntityChange {
                                before: None,
                                after: Some(prepared.entity),
                            },
                            outbox,
                        )
                    }
                    EntityEffect::Update {
                        id,
                        expected_version,
                        attributes,
                    } => {
                        let patch = EntityPatch {
                            attributes: attributes.clone(),
                        };
                        let prepared = self
                            .prepare_update(&tx, id, *expected_version, &patch)
                            .await?;
                        // A guard earlier in the plan covers the committed
                        // state for this id.
                        let guard_meta = !state.guarded_meta.contains(&meta_key(id));
                        let outbox = self
                            .stage_update(&tx, &prepared, ctx, guard_meta, &mut state)
                            .await?;
                        (
                            EntityChange {
                                before: Some(prepared.before),
                                after: Some(prepared.after),
                            },
                            outbox,
                        )
                    }
                    EntityEffect::Delete {
                        id,
                        expected_version,
                        force,
                    } => {
                        let prepared = self
                            .prepare_delete(&tx, id, *expected_version, *force)
                            .await?;
                        let guard_meta = !state.guarded_meta.contains(&meta_key(id));
                        let outbox = self
                            .stage_delete(&tx, &prepared, ctx, &mut state, guard_meta)
                            .await?;
                        (
                            EntityChange {
                                before: Some(prepared.before),
                                after: None,
                            },
                            outbox,
                        )
                    }
                };
                changes.push(change);
                if let Some(row) = outbox {
                    outbox_rows.push(row);
                }
            }
            if !outbox_rows.is_empty() {
                let count = u64::try_from(outbox_rows.len()).unwrap_or(u64::MAX);
                increment_outbox_pending(&tx, count).await?;
                for (key, bytes) in &outbox_rows {
                    tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
                }
            }
            if let Some((key, bytes)) = marker {
                tx.set_bytes(key, bytes).await.map_err(EntityError::Store)?;
            }
            match tx.commit().await {
                Ok(()) => {}
                Err(StoreError::TxConflict { key, .. }) => {
                    return Err(conflict_error(&state, &key));
                }
                Err(error) => return Err(EntityError::Store(error)),
            }
            (changes, !outbox_rows.is_empty())
        };
        if pending && let Err(error) = self.flush_after_commit().await {
            tracing::warn!(
                %error,
                "entity outbox flush failed after commit; the relay will deliver the event"
            );
        }
        Ok(changes)
    }

    /// Delivers pending outbox rows to the change feed in batches.
    ///
    /// The call returns `Ok(0)` when no feed is configured.
    /// Before it reads the rows, the call ensures that the
    /// `outbox-meta:pending` counter exists.
    /// An old store without the counter gets the one-time backfill.
    /// One batch reads at most 100 rows in key order.
    /// A test build reads at most 2 rows.
    /// For each row, the call appends the event to the feed.
    /// The call then deletes the row and decrements the counter in one
    /// transaction.
    /// A row that does not decode moves to an `outbox-poison:` key in one
    /// transaction with the counter decrement.
    /// The call writes a warning with the key and continues the batch.
    /// The transaction commits both changes or neither change.
    /// The counter never goes below zero.
    /// The call stops when a batch returns zero rows.
    /// A failed append stops the loop and returns the error.
    /// The row and the counter stay unchanged.
    /// A failed transaction stops the loop and returns the error.
    /// The row and the counter stay unchanged.
    /// The call does not hold the store write guard during the append.
    ///
    /// The counter is equal to the number of `outbox:` rows.
    /// Delivery is at least once.
    /// A crash after an append and before a commit can deliver one event
    /// again.
    /// A consumer must be idempotent.
    pub async fn flush_outbox(&self) -> Result<usize, EntityError> {
        let Some(feed) = &self.feed else {
            return Ok(0);
        };
        let _flush = self.flush_lock.lock().await;
        self.ensure_outbox_pending().await?;
        let mut delivered = 0;
        loop {
            let rows = {
                let g = self.store.read().await;
                scan_prefix_bounded(&*g, OUTBOX_PREFIX, OUTBOX_FLUSH_BATCH).await?
            };
            if rows.is_empty() {
                break;
            }
            #[cfg(test)]
            {
                let peak = self
                    .outbox_batch_peak
                    .load(std::sync::atomic::Ordering::SeqCst);
                if rows.len() > peak {
                    self.outbox_batch_peak
                        .store(rows.len(), std::sync::atomic::Ordering::SeqCst);
                }
            }
            for row in rows {
                let event: EntityEvent = match serde_json::from_slice(&row.value) {
                    Ok(event) => event,
                    Err(error) => {
                        let event_id = row.key.strip_prefix(OUTBOX_PREFIX).unwrap_or(&row.key);
                        tracing::warn!(
                            key = %row.key,
                            %error,
                            "outbox event is invalid, moved to the poison key"
                        );
                        let g = self.store.write().await;
                        let tx = g.begin_tx().map_err(EntityError::Store)?;
                        decrement_outbox_pending(&tx, 1).await?;
                        tx.set_bytes(&outbox_poison_key(event_id), &row.value)
                            .await
                            .map_err(EntityError::Store)?;
                        tx.delete(&row.key).await.map_err(EntityError::Store)?;
                        tx.commit().await.map_err(EntityError::Store)?;
                        drop(g);
                        continue;
                    }
                };
                feed.append(WalOp::Entity { event })
                    .await
                    .map_err(|_| EntityError::Feed("entity feed append failed".to_string()))?;
                let g = self.store.write().await;
                let tx = g.begin_tx().map_err(EntityError::Store)?;
                decrement_outbox_pending(&tx, 1).await?;
                #[cfg(test)]
                if self
                    .outbox_delete_failures
                    .load(std::sync::atomic::Ordering::SeqCst)
                    > 0
                {
                    self.outbox_delete_failures
                        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    return Err(EntityError::Store(oxkv::StoreError::Other(
                        "injected outbox delete failure".to_string(),
                    )));
                }
                tx.delete(&row.key).await.map_err(EntityError::Store)?;
                tx.commit().await.map_err(EntityError::Store)?;
                drop(g);
                delivered += 1;
            }
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
        let count = u64::try_from(
            g.count_prefix(KeyPrefix::new(OUTBOX_PREFIX), usize::MAX)
                .await
                .map_err(EntityError::Store)?,
        )
        .unwrap_or(u64::MAX);
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
        let markers = scan_keys_prefix(&*g, &prefix).await?;
        let mut entities = Vec::new();
        let mut seen = BTreeSet::new();
        for key in markers {
            let Some(id) = key.strip_prefix(&prefix) else {
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
        let markers = scan_keys_prefix_bounded(&*g, &prefix, max).await?;
        let mut ids = Vec::new();
        let mut seen = BTreeSet::new();
        for key in markers {
            let Some(id) = key.strip_prefix(&prefix) else {
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
    /// The scan reads one extra id as a look-ahead.
    /// The cursor is the last id of the page when the extra id exists.
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
        let max = Some(limit.saturating_add(1));
        let cursor = (Some(start), KeyPrefix::new(&prefix).upper_bound());
        let markers = g
            .gets_keys(max, Direction::Next, cursor)
            .await
            .map_err(EntityError::Store)?;
        let mut ids = Vec::new();
        let mut seen = BTreeSet::new();
        for key in markers {
            let Some(id) = key.strip_prefix(&prefix) else {
                continue;
            };
            if id.is_empty() || id.contains(':') || !seen.insert(id.to_string()) {
                continue;
            }
            ids.push(id.to_string());
        }
        ids.sort();
        let has_more = ids.len() > limit;
        ids.truncate(limit);
        let next = if has_more { ids.last().cloned() } else { None };
        let mut entities = Vec::with_capacity(ids.len());
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
    /// The check applies the schema defaults.
    /// It also checks the unique values and the references.
    /// It records one issue for each invalid entity.
    /// A store failure is an error and not an issue.
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
        let mut seen_unique: BTreeSet<(String, String)> = BTreeSet::new();
        for entity in entities {
            if !entity.schemas.iter().any(|schema| schema.id == schema_id) {
                continue;
            }
            report.scanned += 1;
            match self
                .revalidate_one(&entity, schema_id, target_version)
                .await
            {
                Ok(revalidated) => {
                    if let Some(issue) = note_unique_values(
                        &revalidated.attributes,
                        &revalidated.merged.attributes,
                        &mut seen_unique,
                    )? {
                        report.invalid.push(InvalidEntity {
                            entity_id: entity.id.clone(),
                            issue,
                        });
                    } else {
                        report.compatible += 1;
                    }
                }
                Err(RevalidationFailure::Issue(issue)) => report.invalid.push(InvalidEntity {
                    entity_id: entity.id.clone(),
                    issue,
                }),
                Err(RevalidationFailure::Error(error)) => return Err(error),
            }
        }
        Ok(report)
    }

    /// Applies one target schema version to compatible entities.
    ///
    /// The call reads at most `limit` entities that pin `schema_id`.
    /// The scan starts after the `after` id when the caller gives a cursor.
    /// It checks each entity with the target version.
    /// The check applies the schema defaults.
    /// It also checks the unique values and the references.
    /// An invalid entity stays unchanged and goes into `invalid`.
    /// A valid entity that already pins `target_version` counts as unchanged.
    /// Any other valid entity counts as migrated.
    /// A dry run writes no key and no event.
    /// An apply removes the index rows of the previous schema and writes the
    /// index rows of the target schema.
    /// An apply writes every entity row and every outbox row in one
    /// transaction.
    /// A duplicate unique value marks the entity as invalid.
    /// A dangling reference marks the entity as invalid.
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
            let mut seen_unique: BTreeSet<(String, String)> = BTreeSet::new();
            for entity in entities {
                if !entity.schemas.iter().any(|schema| schema.id == schema_id) {
                    continue;
                }
                report.scanned += 1;
                match self
                    .revalidate_one(&entity, schema_id, target_version)
                    .await
                {
                    Ok(revalidated) => {
                        if let Some(issue) = note_unique_values(
                            &revalidated.attributes,
                            &revalidated.merged.attributes,
                            &mut seen_unique,
                        )? {
                            report.invalid.push(InvalidEntity {
                                entity_id: entity.id.clone(),
                                issue,
                            });
                        } else if entity.schemas.iter().any(|schema| {
                            schema.id == schema_id && schema.version == target_version
                        }) {
                            report.unchanged += 1;
                        } else {
                            report.migrated += 1;
                        }
                    }
                    Err(RevalidationFailure::Issue(issue)) => {
                        report.invalid.push(InvalidEntity {
                            entity_id: entity.id.clone(),
                            issue,
                        });
                    }
                    Err(RevalidationFailure::Error(error)) => return Err(error),
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
    /// It builds every after entity from the defaulted attributes.
    /// It builds every outbox row in memory.
    /// It checks every unique value against the target schema.
    /// One transaction removes the rows of the previous schema and writes the
    /// rows of the target schema.
    /// It writes the metadata row and the outbox row in the same transaction,
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
        let mut seen_unique: BTreeSet<(String, String)> = BTreeSet::new();

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
            let revalidated = match self
                .revalidate_one(&current, schema_id, target_version)
                .await
            {
                Ok(revalidated) => revalidated,
                Err(RevalidationFailure::Issue(issue)) => {
                    result.invalid.push(InvalidEntity {
                        entity_id: current.id.clone(),
                        issue,
                    });
                    continue;
                }
                Err(RevalidationFailure::Error(error)) => return Err(error),
            };
            if let Some(issue) = note_unique_values(
                &revalidated.attributes,
                &revalidated.merged.attributes,
                &mut seen_unique,
            )? {
                result.invalid.push(InvalidEntity {
                    entity_id: current.id.clone(),
                    issue,
                });
                continue;
            }
            if current
                .schemas
                .iter()
                .any(|schema| schema.id == schema_id && schema.version == target_version)
            {
                result.unchanged += 1;
                continue;
            }
            let before_effective = self.resolve_refs(&current.schemas).await?;
            let before_merged = merge_schemas(&before_effective)?;
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
            let effective = revalidated.effective;
            let merged = revalidated.merged;
            let after = Entity {
                id: current.id.clone(),
                version,
                schemas,
                attributes: revalidated.attributes,
                created_at: current.created_at,
                updated_at: chrono::Utc::now().timestamp(),
            };
            let outbox =
                self.prepare_schema_applied_outbox(&after, event_schema_ids(&effective), ctx)?;
            result.migrated += 1;
            writes.push(SchemaMigrationWrite {
                before: current,
                before_merged,
                entity: after,
                after_merged: merged,
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
            let mut state = WriteState::default();
            if outbox_rows > 0 {
                increment_outbox_pending(&tx, u64::try_from(outbox_rows).unwrap_or(u64::MAX))
                    .await?;
            }
            for write in &writes {
                let facts = self
                    .name_facts(&tx, &name_keys(&write.before, Some(&write.entity)))
                    .await?;
                check_unique_values(&tx, &write.entity, &write.after_merged.attributes, &facts)
                    .await?;
                delete_mutable_rows(
                    &tx,
                    &write.before,
                    Some(&write.entity),
                    &write.before_merged,
                    &facts,
                    &mut state,
                )
                .await?;
                delete_ref_rows(&tx, &write.before, &write.before_merged).await?;
                for schema_id in &write.before_merged.schema_ids {
                    tx.delete(&schema_index_key(schema_id, &write.entity.id))
                        .await
                        .map_err(EntityError::Store)?;
                }
                put_meta_row(&tx, &write.entity).await?;
                put_entity_rows_except_meta(
                    &tx,
                    &write.entity,
                    &write.after_merged,
                    &facts,
                    &mut state,
                )
                .await?;
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
    /// The call clones the attributes and applies the schema defaults.
    /// It checks the types, the required attributes, the unique values, and
    /// the references.
    /// A store failure is an error and not a schema conflict.
    async fn revalidate_one(
        &self,
        entity: &Entity,
        schema_id: &str,
        target_version: u64,
    ) -> Result<RevalidatedEntity, RevalidationFailure> {
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
            .map_err(revalidation_failure)?;
        let merged = merge_schemas(&effective).map_err(revalidation_failure)?;
        let mut attributes = entity.attributes.clone();
        check_known(&attributes, &merged.attributes).map_err(revalidation_failure)?;
        validate_defaults(&merged.attributes).map_err(revalidation_failure)?;
        apply_defaults(&mut attributes, &merged.attributes, &BTreeSet::new())
            .map_err(revalidation_failure)?;
        check_types(&attributes, &merged.attributes).map_err(revalidation_failure)?;
        check_required(&attributes, &merged.attributes).map_err(revalidation_failure)?;
        let candidate = Entity {
            id: entity.id.clone(),
            version: entity.version,
            schemas: refs,
            attributes,
            created_at: entity.created_at,
            updated_at: entity.updated_at,
        };
        {
            let g = self.store.read().await;
            let keys: BTreeSet<String> = candidate.attributes.keys().cloned().collect();
            let facts = self
                .name_facts(&*g, &keys)
                .await
                .map_err(revalidation_failure)?;
            self.check_entity_refs(
                &*g,
                &candidate.id,
                &candidate.attributes,
                &merged.attributes,
            )
            .await
            .map_err(revalidation_failure)?;
            check_unique_values(&*g, &candidate, &merged.attributes, &facts)
                .await
                .map_err(revalidation_failure)?;
        }
        Ok(RevalidatedEntity {
            attributes: candidate.attributes,
            effective,
            merged,
        })
    }

    /// Lists the entities with an indexed attribute equal to `value`.
    ///
    /// The call checks the latest schema versions.
    /// It also accepts a name that has a stored index row.
    /// The call returns an error when no current schema indexes `key` and the
    /// store has no index row for `key`.
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
    /// The call checks the latest schema versions.
    /// The name marker alone does not allow a query, because an old schema
    /// can leave the marker behind.
    /// The call also accepts a name with a stored index row, so an entity
    /// that pins an older version that indexes the name stays queryable.
    /// The scan starts after the `after` id when the caller gives a cursor.
    /// The scan verifies each hash match against the exact value.
    /// The result is in entity id order.
    /// The scan reads one extra matching entity as a look-ahead.
    /// The call returns the cursor for the next page only when the extra
    /// entity exists.
    /// The cursor is `None` when the scan is exhausted.
    /// A `limit` of 0 returns an empty list and no cursor.
    /// The call returns [`EntityError::NotIndexed`] when no current schema
    /// indexes `key` and the store has no index row for `key`.
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
        if !self.attribute_is_indexed(key).await?
            && !self.attribute_has_index_rows(&*g, key).await?
        {
            return Err(EntityError::NotIndexed(key.to_string()));
        }

        let prefix = format!("{ATTR_INDEX_PREFIX}{key}:{hash}:");
        let end = KeyPrefix::new(&prefix).upper_bound();
        let mut start = match after {
            Some(cursor) => {
                validate_name("entity id", cursor)?;
                format!("{prefix}{cursor}\0")
            }
            None => prefix.clone(),
        };
        let target = limit.saturating_add(1);
        let max = Some(target);
        let mut entities = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            let rows = g
                .gets_keys(max, Direction::Next, (Some(start.clone()), end.clone()))
                .await
                .map_err(EntityError::Store)?;
            let full = rows.len() == target;
            for marker in &rows {
                start = format!("{marker}\0");
                let Some(id) = marker.strip_prefix(&prefix) else {
                    continue;
                };
                if id.is_empty() || id.contains(':') || !seen.insert(id.to_string()) {
                    continue;
                }
                if let Some(entity) = load_entity(&*g, id).await?
                    && entity.attributes.get(key) == Some(value)
                {
                    entities.push(entity);
                    if entities.len() >= target {
                        break;
                    }
                }
            }
            if entities.len() >= target || !full {
                break;
            }
        }
        entities.sort_by(|a, b| a.id.cmp(&b.id));
        let has_more = entities.len() > limit;
        entities.truncate(limit);
        let next = if has_more {
            entities.last().map(|entity| entity.id.clone())
        } else {
            None
        };
        Ok((entities, next))
    }

    /// Returns the attribute keys that have a time index row.
    ///
    /// The call scans only the `idx:time-key:` family after the backfill.
    /// The result is sorted and has no duplicates.
    /// An attribute key contains no colon.
    /// A delete keeps the key marker. A stale marker costs one empty scan.
    /// The `idx:time-key-meta:backfilled` marker records the one-time
    /// backfill. When it is absent, the call scans the `idx:time:` family in
    /// pages. It writes every missing key marker and the backfill marker. It
    /// returns the marker keys.
    /// The backfill runs at most one time per store.
    /// Each page holds the write lock and the store write guard.
    /// The call reads 200 `idx:time:` rows in one page. A test build reads 2.
    /// It re-checks that a time row still exists for each key inside the page
    /// lock, writes the page markers, commits, and releases both guards.
    /// The cursor is the last key plus a NUL byte, so a deleted key does not
    /// reset progress.
    /// It writes the backfill marker last, under the write lock.
    /// The memory bound is one page of keys.
    pub async fn time_keys(&self) -> Result<Vec<String>, EntityError> {
        let backfill_marker = time_key_backfill_marker();
        {
            let g = self.store.read().await;
            if g.get_bytes(&backfill_marker)
                .await
                .map_err(EntityError::Store)?
                .is_some()
            {
                return Ok(time_key_marker_keys(
                    scan_keys_prefix(&*g, TIME_KEY_INDEX_PREFIX).await?,
                ));
            }
        }

        let end = KeyPrefix::new(TIME_INDEX_PREFIX).upper_bound();
        let max = Some(BACKFILL_PAGE);
        let mut cursor = TIME_INDEX_PREFIX.to_string();
        loop {
            let page = {
                let _write = self.write_lock.lock().await;
                let g = self.store.write().await;
                if g.get_bytes(&backfill_marker)
                    .await
                    .map_err(EntityError::Store)?
                    .is_some()
                {
                    None
                } else {
                    let rows = g
                        .gets_keys(max, Direction::Next, (Some(cursor.clone()), end.clone()))
                        .await
                        .map_err(EntityError::Store)?;
                    if rows.is_empty() {
                        None
                    } else {
                        let full = rows.len() == BACKFILL_PAGE;
                        let last = rows.last().cloned().unwrap_or_default();
                        let keys = time_row_keys(rows);
                        let tx = g.begin_tx().map_err(EntityError::Store)?;
                        for key in &keys {
                            let prefix = format!("{TIME_INDEX_PREFIX}{key}:");
                            // Re-check the source row inside the page lock.
                            if scan_keys_prefix_bounded(&tx, &prefix, 1).await?.is_empty() {
                                continue;
                            }
                            let marker_key = time_key_index_key(key);
                            if tx
                                .get_bytes(&marker_key)
                                .await
                                .map_err(EntityError::Store)?
                                .is_none()
                            {
                                tx.set_bytes(&marker_key, b"")
                                    .await
                                    .map_err(EntityError::Store)?;
                            }
                        }
                        tx.commit().await.map_err(EntityError::Store)?;
                        self.note_backfill_page();
                        Some((last, full))
                    }
                }
            };
            let Some((last, full)) = page else {
                break;
            };
            self.run_backfill_page_hook().await;
            if !full {
                break;
            }
            cursor = format!("{last}\0");
        }

        {
            let _write = self.write_lock.lock().await;
            let g = self.store.write().await;
            if g.get_bytes(&backfill_marker)
                .await
                .map_err(EntityError::Store)?
                .is_none()
            {
                g.put_bytes(&backfill_marker, b"")
                    .await
                    .map_err(EntityError::Store)?;
            }
        }
        let g = self.store.read().await;
        Ok(time_key_marker_keys(
            scan_keys_prefix(&*g, TIME_KEY_INDEX_PREFIX).await?,
        ))
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
    /// The call reads at most `limit` rows in one page.
    /// When a page holds stale rows, the scan continues from a cursor until
    /// the result holds `limit` entities or the range ends.
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
        let mut cursor = prefix.clone();
        let mut entities = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            let rows = g
                .gets_keys(
                    Some(limit),
                    Direction::Next,
                    (Some(cursor.clone()), Some(upper.clone())),
                )
                .await
                .map_err(EntityError::Store)?;
            let full = rows.len() == limit;
            for marker_key in rows {
                cursor = format!("{marker_key}\0");
                let Some(rest) = marker_key.strip_prefix(&prefix) else {
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
            if entities.len() >= limit || !full {
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
        g.put_bytes(&timer_marker_key(entity_id, key, due_at), &bytes)
            .await
            .map(|()| true)
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
        let rows = scan_keys_prefix(&*g, ENTITY_PREFIX).await?;
        let mut entities = Vec::new();
        for key in rows {
            let Some(rest) = key.strip_prefix(ENTITY_PREFIX) else {
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
    /// It scans the `entity:` family in pages.
    /// Each page holds the write lock and the store write guard.
    /// The call reads 200 `entity:` rows in one page. A test build reads 2.
    /// It re-checks each metadata row inside the page lock.
    /// It writes the page markers, commits, and releases both guards.
    /// The cursor is the last key plus a NUL byte, so a deleted key does not
    /// reset progress.
    /// It writes the backfill marker last, under the write lock.
    /// A crash before the last write retries on the next call.
    /// Every write is idempotent.
    /// The memory bound is one page of rows.
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

        let end = KeyPrefix::new(ENTITY_PREFIX).upper_bound();
        let max = Some(BACKFILL_PAGE);
        let mut cursor = ENTITY_PREFIX.to_string();
        loop {
            let page = {
                let _write = self.write_lock.lock().await;
                let g = self.store.write().await;
                if g.get_bytes(&marker)
                    .await
                    .map_err(EntityError::Store)?
                    .is_some()
                {
                    None
                } else {
                    let rows = g
                        .gets_keys(max, Direction::Next, (Some(cursor.clone()), end.clone()))
                        .await
                        .map_err(EntityError::Store)?;
                    if rows.is_empty() {
                        None
                    } else {
                        let full = rows.len() == BACKFILL_PAGE;
                        let last = rows.last().cloned().unwrap_or_default();
                        let tx = g.begin_tx().map_err(EntityError::Store)?;
                        for key in &rows {
                            let Some(rest) = key.strip_prefix(ENTITY_PREFIX) else {
                                continue;
                            };
                            let Some(id) = rest.strip_suffix(META_SUFFIX) else {
                                continue;
                            };
                            if id.is_empty() || id.contains(':') {
                                continue;
                            }
                            // Re-check the source row inside the page lock.
                            if tx
                                .get_bytes(&meta_key(id))
                                .await
                                .map_err(EntityError::Store)?
                                .is_none()
                            {
                                continue;
                            }
                            tx.set_bytes(&entity_index_key(id), b"")
                                .await
                                .map_err(EntityError::Store)?;
                        }
                        tx.commit().await.map_err(EntityError::Store)?;
                        self.note_backfill_page();
                        Some((last, full))
                    }
                }
            };
            let Some((last, full)) = page else {
                break;
            };
            self.run_backfill_page_hook().await;
            if !full {
                break;
            }
            cursor = format!("{last}\0");
        }

        let _write = self.write_lock.lock().await;
        let g = self.store.write().await;
        if g.get_bytes(&marker)
            .await
            .map_err(EntityError::Store)?
            .is_none()
        {
            g.put_bytes(&marker, b"")
                .await
                .map_err(EntityError::Store)?;
        }
        Ok(())
    }

    /// Backfills the reverse reference markers one time.
    ///
    /// The call returns early when the `idx:ref-meta:backfilled` marker
    /// exists.
    /// It first ensures that the entity index markers exist.
    /// It pages every entity marker in id order.
    /// Each page holds the write lock and the store write guard.
    /// The call reads 200 entity markers in one page. A test build reads 2.
    /// For each entity, the call resolves the pinned schemas and merges them.
    /// It re-checks the entity marker and the entity row inside the page lock.
    /// It then writes one marker for each `EntityRef` attribute, commits, and
    /// releases both guards.
    /// The cursor is the last key plus a NUL byte.
    /// It writes the backfill marker last, under the write lock.
    /// A crash before that write retries on the next call.
    /// Every marker write is idempotent.
    /// The memory bound is one page of entity ids and the attributes of one
    /// entity.
    async fn backfill_ref_index(&self) -> Result<(), EntityError> {
        let marker = ref_backfill_marker();
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

        self.backfill_entity_index().await?;
        let end = KeyPrefix::new(ENTITY_INDEX_PREFIX).upper_bound();
        let max = Some(BACKFILL_PAGE);
        let mut cursor = ENTITY_INDEX_PREFIX.to_string();
        loop {
            let page = {
                let _write = self.write_lock.lock().await;
                let g = self.store.write().await;
                if g.get_bytes(&marker)
                    .await
                    .map_err(EntityError::Store)?
                    .is_some()
                {
                    None
                } else {
                    let rows = g
                        .gets_keys(max, Direction::Next, (Some(cursor.clone()), end.clone()))
                        .await
                        .map_err(EntityError::Store)?;
                    if rows.is_empty() {
                        None
                    } else {
                        let full = rows.len() == BACKFILL_PAGE;
                        let last = rows.last().cloned().unwrap_or_default();
                        let tx = g.begin_tx().map_err(EntityError::Store)?;
                        for key in &rows {
                            let Some(id) = key.strip_prefix(ENTITY_INDEX_PREFIX) else {
                                continue;
                            };
                            if id.is_empty() || id.contains(':') {
                                continue;
                            }
                            // Re-check the source entity inside the page lock.
                            if tx
                                .get_bytes(&entity_index_key(id))
                                .await
                                .map_err(EntityError::Store)?
                                .is_none()
                            {
                                continue;
                            }
                            let Some(entity) = load_entity(&tx, id).await? else {
                                continue;
                            };
                            let effective = self.resolve_refs(&entity.schemas).await?;
                            let merged = merge_schemas(&effective)?;
                            put_ref_rows(&tx, &entity, &merged).await?;
                        }
                        tx.commit().await.map_err(EntityError::Store)?;
                        self.note_backfill_page();
                        Some((last, full))
                    }
                }
            };
            let Some((last, full)) = page else {
                break;
            };
            self.run_backfill_page_hook().await;
            if !full {
                break;
            }
            cursor = format!("{last}\0");
        }

        let _write = self.write_lock.lock().await;
        let g = self.store.write().await;
        if g.get_bytes(&marker)
            .await
            .map_err(EntityError::Store)?
            .is_none()
        {
            g.put_bytes(&marker, b"")
                .await
                .map_err(EntityError::Store)?;
        }
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
    /// The pass reads 200 `entity:` rows in one page.
    /// A test build reads 2 rows in one page.
    /// Each page holds the write lock and the store write guard.
    /// The pass writes the page markers, commits, and releases both guards.
    /// It re-checks each metadata row inside the page lock.
    /// The cursor is the last key plus a NUL byte.
    /// It writes the backfill marker last, under the write lock.
    /// A crash before that write retries on the next call.
    /// Every write is idempotent.
    /// The call then scans only the `idx:entity:` family.
    /// It starts after the `after` id when the caller gives a cursor.
    /// The call returns the entities and the cursor for the next page.
    /// The scan reads one extra id as a look-ahead.
    /// The cursor is the last id of the page when the extra id exists.
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
        let max = Some(limit.saturating_add(1));
        let cursor = (
            Some(start),
            KeyPrefix::new(ENTITY_INDEX_PREFIX).upper_bound(),
        );
        let markers = g
            .gets_keys(max, Direction::Next, cursor)
            .await
            .map_err(EntityError::Store)?;
        let mut ids = Vec::with_capacity(markers.len());
        let mut seen = BTreeSet::new();
        for key in markers {
            let Some(id) = key.strip_prefix(ENTITY_INDEX_PREFIX) else {
                continue;
            };
            if id.is_empty() || id.contains(':') || !seen.insert(id.to_string()) {
                continue;
            }
            ids.push(id.to_string());
        }
        ids.sort();
        let has_more = ids.len() > limit;
        ids.truncate(limit);
        let next = if has_more { ids.last().cloned() } else { None };
        let mut entities = Vec::with_capacity(ids.len());
        for id in &ids {
            if let Some(entity) = load_entity(&*g, id).await? {
                entities.push(entity);
            }
        }
        Ok((entities, next))
    }

    /// Resolves schema ids to their latest versions and flattens them.
    pub(crate) async fn resolve_schemas(
        &self,
        ids: &[String],
    ) -> Result<Vec<EffectiveSchema>, EntityError> {
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
    pub(crate) async fn resolve_refs(
        &self,
        refs: &[SchemaRef],
    ) -> Result<Vec<EffectiveSchema>, EntityError> {
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

    /// True when the latest version of any schema marks `key` as indexed.
    ///
    /// The call reads the current schema versions only.
    /// It ignores the permanent name marker.
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

    /// True when one attribute index row exists for `key`.
    ///
    /// The call reads one key of the `idx:attr:{key}:` family.
    /// An entity that pins an older version that indexes the name keeps such
    /// a row.
    async fn attribute_has_index_rows<S>(&self, store: &S, key: &str) -> Result<bool, EntityError>
    where
        S: GetSet + ?Sized + Sync,
    {
        let prefix = format!("{ATTR_INDEX_PREFIX}{key}:");
        Ok(!scan_keys_prefix_bounded(store, &prefix, 1)
            .await?
            .is_empty())
    }

    /// Returns the name-level index facts for `keys`.
    ///
    /// A durable name marker written at schema publish is the fast path.
    /// A missing marker makes the call scan the stored schemas one time.
    /// The scan covers a store that a schema publish did not reach.
    async fn name_facts<S>(
        &self,
        store: &S,
        keys: &BTreeSet<String>,
    ) -> Result<NameFacts, EntityError>
    where
        S: GetSet + ?Sized,
    {
        let mut facts = NameFacts::default();
        let mut pending = Vec::new();
        for key in keys {
            let mut missing = false;
            if store
                .get_bytes(&attr_key_index_key(key))
                .await
                .map_err(EntityError::Store)?
                .is_some()
            {
                facts.indexed.insert(key.clone());
            } else {
                missing = true;
            }
            if store
                .get_bytes(&unique_name_key(key))
                .await
                .map_err(EntityError::Store)?
                .is_some()
            {
                facts.unique.insert(key.clone());
            } else {
                missing = true;
            }
            if missing {
                pending.push(key.clone());
            }
        }
        if pending.is_empty() {
            return Ok(facts);
        }
        for def in self.schemas.list().await.map_err(map_schema_error)? {
            let Some(effective) = self
                .schemas
                .effective(&def.id, def.version)
                .await
                .map_err(map_schema_error)?
            else {
                continue;
            };
            for key in &pending {
                let Some(attribute) = effective.attributes.get(key) else {
                    continue;
                };
                if attribute.indexed {
                    facts.indexed.insert(key.clone());
                }
                if attribute.unique {
                    facts.unique.insert(key.clone());
                }
            }
        }
        Ok(facts)
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

/// The key for one outbox row that no consumer can decode.
fn outbox_poison_key(event_id: &str) -> String {
    format!("{OUTBOX_POISON_PREFIX}{event_id}")
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
    S: GetSet + ?Sized + Sync,
{
    let current = match read_outbox_pending(store).await? {
        Some(count) => count,
        None => u64::try_from(
            store
                .count_prefix(KeyPrefix::new(OUTBOX_PREFIX), usize::MAX)
                .await
                .map_err(EntityError::Store)?,
        )
        .unwrap_or(u64::MAX),
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
///
/// The call skips each name in `removed`, because the caller removed it
/// explicitly.
fn apply_defaults(
    attributes: &mut BTreeMap<String, AttributeValue>,
    defs: &BTreeMap<String, AttributeDef>,
    removed: &BTreeSet<String>,
) -> Result<(), EntityError> {
    for (name, def) in defs {
        if attributes.contains_key(name) || removed.contains(name) {
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
        AttributeType::Float => value
            .as_f64()
            .filter(|value| value.is_finite())
            .map(AttributeValue::Float),
        AttributeType::Boolean => value.as_bool().map(AttributeValue::Boolean),
        AttributeType::Timestamp => value.as_i64().map(AttributeValue::Timestamp),
        AttributeType::Json => Some(AttributeValue::Json(value.clone())),
        AttributeType::EntityRef => value
            .as_str()
            .map(|value| AttributeValue::EntityRef(value.to_string())),
    }
}

/// Checks that every value matches its declared type.
///
/// The call rejects a float that is not finite.
fn check_types(
    attributes: &BTreeMap<String, AttributeValue>,
    defs: &BTreeMap<String, AttributeDef>,
) -> Result<(), EntityError> {
    for (key, value) in attributes {
        let Some(def) = defs.get(key) else {
            return Err(EntityError::UnknownAttribute(key.clone()));
        };
        if let AttributeValue::Float(value) = value
            && !value.is_finite()
        {
            return Err(EntityError::Invalid(format!(
                "attribute float is not finite: {key}"
            )));
        }
        if !type_matches(def.ty, value) {
            return Err(EntityError::TypeMismatch(key.clone()));
        }
    }
    Ok(())
}

/// True when `value` has the declared type.
fn type_matches(ty: AttributeType, value: &AttributeValue) -> bool {
    match (ty, value) {
        (AttributeType::Float, AttributeValue::Float(value)) => value.is_finite(),
        (AttributeType::String, AttributeValue::String(_))
        | (AttributeType::Integer, AttributeValue::Integer(_))
        | (AttributeType::Boolean, AttributeValue::Boolean(_))
        | (AttributeType::Timestamp, AttributeValue::Timestamp(_))
        | (AttributeType::Json, AttributeValue::Json(_))
        | (AttributeType::EntityRef, AttributeValue::EntityRef(_)) => true,
        _ => false,
    }
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

/// Converts an entity error into one revalidation issue.
fn revalidation_issue(error: EntityError) -> RevalidationIssue {
    match error {
        EntityError::UnknownAttribute(name) => RevalidationIssue::UnknownAttribute(name),
        EntityError::TypeMismatch(name) => RevalidationIssue::TypeMismatch(name),
        EntityError::MissingRequired(name) => RevalidationIssue::MissingRequired(name),
        EntityError::UniqueViolation(name) => RevalidationIssue::DuplicateUnique(name),
        EntityError::DanglingRef(name, _) => RevalidationIssue::DanglingRef(name),
        other => RevalidationIssue::SchemaConflict(other.to_string()),
    }
}

/// Converts an entity error into a revalidation failure.
///
/// A store failure and an internal failure stay errors.
/// The other failures are issues for one entity.
fn revalidation_failure(error: EntityError) -> RevalidationFailure {
    match error {
        EntityError::Store(_) | EntityError::Internal(_) => RevalidationFailure::Error(error),
        other => RevalidationFailure::Issue(revalidation_issue(other)),
    }
}

/// Records the unique values of one candidate entity.
///
/// The call uses `seen` to detect a duplicate across one page.
/// A duplicate leaves `seen` unchanged.
fn note_unique_values(
    attributes: &BTreeMap<String, AttributeValue>,
    defs: &BTreeMap<String, AttributeDef>,
    seen: &mut BTreeSet<(String, String)>,
) -> Result<Option<RevalidationIssue>, EntityError> {
    let mut values: Vec<(String, String)> = Vec::new();
    for (key, value) in attributes {
        if !defs.get(key).is_some_and(|def| def.unique) {
            continue;
        }
        values.push((key.clone(), value_hash(value)?));
    }
    if let Some((key, _)) = values.iter().find(|value| seen.contains(*value)) {
        return Ok(Some(RevalidationIssue::DuplicateUnique(key.clone())));
    }
    seen.extend(values);
    Ok(None)
}

/// Checks every unique value against the name-level facts.
///
/// The call checks an attribute that the facts mark as unique.
/// It also checks an attribute that the pinned schema marks as unique, so an
/// entity on an older version keeps the constraint.
async fn check_unique_values<S>(
    store: &S,
    entity: &Entity,
    defs: &BTreeMap<String, AttributeDef>,
    facts: &NameFacts,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized + Sync,
{
    for (key, value) in &entity.attributes {
        let unique =
            facts.unique.contains(key) || defs.get(key).is_some_and(|attribute| attribute.unique);
        if unique {
            check_unique(store, &entity.id, key, value).await?;
        }
    }
    Ok(())
}

/// Checks one unique value against the claims.
///
/// The primary claim holds the owning entity id.
/// An entity that holds the same value is idempotent.
/// A claim that names another entity is a violation only when the exact
/// stored value is the same.
/// The call also checks the collision claims and the legacy markers.
async fn check_unique<S>(
    store: &S,
    entity_id: &str,
    key: &str,
    value: &AttributeValue,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized + Sync,
{
    let hash = value_hash(value)?;
    let claim = unique_claim_key(key, &hash);
    if let Some(bytes) = store.get_bytes(&claim).await.map_err(EntityError::Store)?
        && let Some(owner) = claim_owner(&bytes)
        && owner != entity_id
    {
        check_unique_owner(store, owner, key, value).await?;
    }
    for owner in claim_owners(store, &unique_extra_prefix(key, &hash)).await? {
        if owner != entity_id {
            check_unique_owner(store, &owner, key, value).await?;
        }
    }
    for owner in claim_owners(store, &unique_legacy_prefix(key, &hash)).await? {
        if owner != entity_id {
            check_unique_owner(store, &owner, key, value).await?;
        }
    }
    Ok(())
}

/// Checks one claim owner against one exact value.
///
/// A missing owner is a stale claim and does not block the write.
async fn check_unique_owner<S>(
    store: &S,
    owner: &str,
    key: &str,
    value: &AttributeValue,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let Some(existing) = load_entity(store, owner).await? else {
        return Ok(());
    };
    if existing.attributes.get(key) == Some(value) {
        return Err(EntityError::UniqueViolation(key.to_string()));
    }
    Ok(())
}

/// Returns the owners named by the keys under `prefix`.
///
/// The call reads the suffix of each key as the owner.
async fn claim_owners<S>(store: &S, prefix: &str) -> Result<Vec<String>, EntityError>
where
    S: GetSet + ?Sized + Sync,
{
    let mut owners = Vec::new();
    for key in scan_keys_prefix(store, prefix).await? {
        if let Some(owner) = key.strip_prefix(prefix)
            && !owner.is_empty()
            && !owner.contains(':')
        {
            owners.push(owner.to_string());
        }
    }
    Ok(owners)
}

/// Reads an entity id from a claim value.
fn claim_owner(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|owner| !owner.is_empty())
}

/// Returns the JSON bytes of the metadata row of one entity.
fn meta_bytes(entity: &Entity) -> Result<Vec<u8>, EntityError> {
    let meta = EntityMeta {
        id: entity.id.clone(),
        version: entity.version,
        schemas: entity.schemas.clone(),
        created_at: entity.created_at,
        updated_at: entity.updated_at,
    };
    serde_json::to_vec(&meta).map_err(|e| EntityError::Internal(e.to_string()))
}

/// Writes the metadata row of one entity.
///
/// The call changes no attribute row and no index row.
async fn put_meta_row<S>(store: &S, entity: &Entity) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let meta_bytes = meta_bytes(entity)?;
    store
        .set_bytes(&meta_key(&entity.id), &meta_bytes)
        .await
        .map(|_| ())
        .map_err(EntityError::Store)
}

/// Writes the attribute and index rows of one entity.
///
/// The caller writes the metadata row.
/// The call uses the name-level facts, so a schema that does not set a flag
/// still writes the row when another schema sets it.
/// The call stages one unique claim for each unique value.
async fn put_entity_rows_except_meta<S>(
    store: &S,
    entity: &Entity,
    merged: &MergedSchema,
    facts: &NameFacts,
    state: &mut WriteState,
) -> Result<(), EntityError>
where
    S: TxCas + ?Sized,
{
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
        let indexed = facts.indexed.contains(key) || def.indexed;
        let unique = facts.unique.contains(key) || def.unique;
        if indexed {
            store
                .set_bytes(&attr_index_key(key, value, &entity.id)?, b"")
                .await
                .map_err(EntityError::Store)?;
            store
                .set_bytes(&attr_key_index_key(key), b"")
                .await
                .map_err(EntityError::Store)?;
        }
        if def.ty == AttributeType::Timestamp
            && indexed
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
        if unique {
            store
                .set_bytes(&unique_name_key(key), b"")
                .await
                .map_err(EntityError::Store)?;
            claim_unique(store, entity, key, value, state).await?;
        }
    }

    for schema_id in &merged.schema_ids {
        store
            .set_bytes(&schema_index_key(schema_id, &entity.id), b"")
            .await
            .map_err(EntityError::Store)?;
    }
    put_ref_rows(store, entity, merged).await?;
    Ok(())
}

/// Stages the unique claim of one value.
///
/// The call requires the claim to be absent at commit, so two handles that
/// write the same value produce one success and one conflict.
/// A claim key that this transaction released uses an unconditional write.
/// A hash collision uses a second claim key that holds the entity id.
async fn claim_unique<S>(
    store: &S,
    entity: &Entity,
    key: &str,
    value: &AttributeValue,
    state: &mut WriteState,
) -> Result<(), EntityError>
where
    S: TxCas + ?Sized,
{
    let hash = value_hash(value)?;
    let claim = unique_claim_key(key, &hash);
    let owner = entity.id.as_bytes();
    let current = store.get_bytes(&claim).await.map_err(EntityError::Store)?;
    match current.as_deref().and_then(claim_owner) {
        None => {
            if state.released_claims.contains(&claim) {
                store
                    .set_bytes(&claim, owner)
                    .await
                    .map_err(EntityError::Store)?;
            } else {
                store
                    .set_if_absent(&claim, owner)
                    .await
                    .map_err(EntityError::Store)?;
            }
            state.claimed.insert(claim, key.to_string());
        }
        Some(owner_id) if owner_id == entity.id => {
            if state.released_claims.contains(&claim) {
                store
                    .set_bytes(&claim, owner)
                    .await
                    .map_err(EntityError::Store)?;
                state.claimed.insert(claim, key.to_string());
            }
        }
        Some(owner_id) => {
            check_unique_owner(store, owner_id, key, value).await?;
            let extra = unique_extra_key(key, &hash, &entity.id);
            if state.released_claims.contains(&extra) {
                store
                    .set_bytes(&extra, owner)
                    .await
                    .map_err(EntityError::Store)?;
            } else {
                store
                    .set_if_absent(&extra, owner)
                    .await
                    .map_err(EntityError::Store)?;
            }
            state.claimed.insert(extra, key.to_string());
        }
    }
    Ok(())
}

/// Returns one error for a commit-time conflict.
///
/// A conflict on a unique claim is a unique violation.
/// A conflict on any other guarded key is a version conflict.
fn conflict_error(state: &WriteState, key: &str) -> EntityError {
    if let Some(name) = state.claimed.get(key) {
        return EntityError::UniqueViolation(name.clone());
    }
    EntityError::VersionConflict
}

/// Returns the attribute names of a before state and an optional after
/// state.
fn name_keys(before: &Entity, after: Option<&Entity>) -> BTreeSet<String> {
    let mut keys: BTreeSet<String> = before.attributes.keys().cloned().collect();
    if let Some(after) = after {
        keys.extend(after.attributes.keys().cloned());
    }
    keys
}

/// Writes one reverse reference marker for each `EntityRef` attribute.
///
/// The marker key is `idx:ref:{target_id}:{source_id}:{attribute}`.
/// A self-reference writes a marker where the source and target are equal.
async fn put_ref_rows<S>(
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
        if def.ty != AttributeType::EntityRef {
            continue;
        }
        let AttributeValue::EntityRef(target) = value else {
            continue;
        };
        store
            .set_bytes(&ref_index_key(target, &entity.id, key), b"")
            .await
            .map_err(EntityError::Store)?;
    }
    Ok(())
}

/// Deletes every mutable row of one entity.
///
/// The call removes the attribute rows, the attribute markers, and the
/// unique claims.
/// The `after` state keeps a claim when it holds the same value.
/// A release of a claim that the write keeps would remove the claim at
/// commit, because a claim guard reads the committed state.
async fn delete_mutable_rows<S>(
    store: &S,
    entity: &Entity,
    after: Option<&Entity>,
    merged: &MergedSchema,
    facts: &NameFacts,
    state: &mut WriteState,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    for (key, value) in &entity.attributes {
        store
            .delete(&attr_key(&entity.id, key))
            .await
            .map_err(EntityError::Store)?;
        let def = merged.attributes.get(key);
        let indexed = facts.indexed.contains(key) || def.is_some_and(|def| def.indexed);
        let unique = facts.unique.contains(key) || def.is_some_and(|def| def.unique);
        if indexed {
            store
                .delete(&attr_index_key(key, value, &entity.id)?)
                .await
                .map_err(EntityError::Store)?;
        }
        if indexed && let AttributeValue::Timestamp(timestamp) = value {
            store
                .delete(&time_index_key(key, *timestamp, &entity.id))
                .await
                .map_err(EntityError::Store)?;
        }
        let unchanged = after.and_then(|after| after.attributes.get(key)) == Some(value);
        if unique && !unchanged {
            release_unique(store, key, value, &entity.id, state).await?;
        }
    }
    Ok(())
}

/// Deletes every outgoing reverse reference marker of one entity.
///
/// The call reads the stored attributes and the merged definitions.
/// It builds the exact key for each `EntityRef` value.
/// It does not scan the `idx:ref:` family.
async fn delete_ref_rows<S>(
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
        if def.ty != AttributeType::EntityRef {
            continue;
        }
        let AttributeValue::EntityRef(target) = value else {
            continue;
        };
        store
            .delete(&ref_index_key(target, &entity.id, key))
            .await
            .map_err(EntityError::Store)?;
    }
    Ok(())
}

/// Counts the distinct entities that reference `target_id` from another entity.
///
/// The call scans the `idx:ref:{target_id}:` family only.
/// A marker from `target_id` itself does not count.
async fn count_incoming_refs<S>(store: &S, target_id: &str) -> Result<usize, EntityError>
where
    S: GetSet + ?Sized + Sync,
{
    let prefix = ref_target_prefix(target_id);
    let mut sources = BTreeSet::new();
    let mut after = None;
    loop {
        let page = store
            .scan_keys(KeyPrefix::new(&prefix), after, REF_SCAN_PAGE)
            .await
            .map_err(EntityError::Store)?;
        for key in &page.items {
            let Some(rest) = key.strip_prefix(&prefix) else {
                continue;
            };
            let Some((source, attribute)) = rest.split_once(':') else {
                continue;
            };
            if source.is_empty() || attribute.is_empty() || source == target_id {
                continue;
            }
            sources.insert(source.to_string());
        }
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    Ok(sources.len())
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

/// Releases the unique claim of one value.
///
/// The call deletes the primary claim only when this entity owns it.
/// It deletes the collision claim and the legacy marker of this entity.
/// The transaction remembers each deleted claim key, so a later claim in the
/// same plan writes it without a guard.
async fn release_unique<S>(
    store: &S,
    key: &str,
    value: &AttributeValue,
    entity_id: &str,
    state: &mut WriteState,
) -> Result<(), EntityError>
where
    S: GetSet + ?Sized,
{
    let hash = value_hash(value)?;
    let claim = unique_claim_key(key, &hash);
    let owned = store
        .get_bytes(&claim)
        .await
        .map_err(EntityError::Store)?
        .as_deref()
        .and_then(claim_owner)
        == Some(entity_id);
    if owned {
        store.delete(&claim).await.map_err(EntityError::Store)?;
        state.released_claims.insert(claim);
    }
    let extra = unique_extra_key(key, &hash, entity_id);
    if store
        .get_bytes(&extra)
        .await
        .map_err(EntityError::Store)?
        .is_some()
    {
        store.delete(&extra).await.map_err(EntityError::Store)?;
        state.released_claims.insert(extra);
    }
    store
        .delete(&unique_legacy_key(key, &hash, entity_id))
        .await
        .map_err(EntityError::Store)?;
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
    let cursor = (
        Some(prefix.to_string()),
        KeyPrefix::new(prefix).upper_bound(),
    );
    store
        .gets_bytes(None, Direction::Next, cursor)
        .await
        .map_err(EntityError::Store)
}

/// Scans a key range that ends at the `prefix:` family bound and reads keys
/// only.
async fn scan_keys_prefix<S>(store: &S, prefix: &str) -> Result<Vec<String>, EntityError>
where
    S: GetSet + ?Sized + Sync,
{
    debug_assert!(prefix.ends_with(':'));
    let cursor = (
        Some(prefix.to_string()),
        KeyPrefix::new(prefix).upper_bound(),
    );
    store
        .gets_keys(None, Direction::Next, cursor)
        .await
        .map_err(EntityError::Store)
}

/// Scans at most `limit` rows of a key range and reads keys only.
async fn scan_keys_prefix_bounded<S>(
    store: &S,
    prefix: &str,
    limit: usize,
) -> Result<Vec<String>, EntityError>
where
    S: GetSet + ?Sized + Sync,
{
    debug_assert!(prefix.ends_with(':'));
    let max = Some(limit);
    let cursor = (
        Some(prefix.to_string()),
        KeyPrefix::new(prefix).upper_bound(),
    );
    store
        .gets_keys(max, Direction::Next, cursor)
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
    let max = Some(limit);
    let cursor = (
        Some(prefix.to_string()),
        KeyPrefix::new(prefix).upper_bound(),
    );
    store
        .gets_bytes(max, Direction::Next, cursor)
        .await
        .map_err(EntityError::Store)
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

/// The marker key for one reverse reference.
fn ref_index_key(target_id: &str, source_id: &str, attribute: &str) -> String {
    format!("{REF_INDEX_PREFIX}{target_id}:{source_id}:{attribute}")
}

/// The scan prefix for every reverse reference to one target entity.
fn ref_target_prefix(target_id: &str) -> String {
    format!("{REF_INDEX_PREFIX}{target_id}:")
}

/// The marker key for the one-time reverse reference backfill.
fn ref_backfill_marker() -> String {
    format!("{REF_META_PREFIX}{REF_BACKFILL_SUFFIX}")
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

/// The name marker key for one unique attribute key.
pub(crate) fn unique_name_key(key: &str) -> String {
    format!("{UNIQUE_KEY_PREFIX}{key}")
}

/// The claim key for one unique attribute value.
///
/// The key holds no entity id, so two writers of one value contend for one
/// key.
fn unique_claim_key(key: &str, hash: &str) -> String {
    format!("{UNIQUE_CLAIM_PREFIX}{key}:{hash}")
}

/// The claim key for one hash collision and entity.
fn unique_extra_key(key: &str, hash: &str, entity_id: &str) -> String {
    format!("{UNIQUE_EXTRA_PREFIX}{key}:{hash}:{entity_id}")
}

/// The scan prefix for the collision claims of one value hash.
fn unique_extra_prefix(key: &str, hash: &str) -> String {
    format!("{UNIQUE_EXTRA_PREFIX}{key}:{hash}:")
}

/// The legacy marker key for one unique value and entity.
fn unique_legacy_key(key: &str, hash: &str, entity_id: &str) -> String {
    format!("{UNIQUE_CLAIM_PREFIX}{key}:{hash}:{entity_id}")
}

/// The scan prefix for the legacy markers of one value hash.
fn unique_legacy_prefix(key: &str, hash: &str) -> String {
    format!("{UNIQUE_CLAIM_PREFIX}{key}:{hash}:")
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
fn time_key_marker_keys(keys: Vec<String>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for key in keys {
        let Some(key) = key.strip_prefix(TIME_KEY_INDEX_PREFIX) else {
            continue;
        };
        if !key.is_empty() {
            out.insert(key.to_string());
        }
    }
    out.into_iter().collect()
}

/// Returns the sorted attribute keys of a set of time rows.
fn time_row_keys(keys: Vec<String>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for key in keys {
        let Some(rest) = key.strip_prefix(TIME_INDEX_PREFIX) else {
            continue;
        };
        let Some((key, _)) = rest.split_once(':') else {
            continue;
        };
        if !key.is_empty() {
            out.insert(key.to_string());
        }
    }
    out.into_iter().collect()
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

/// Checks the id and the patch of one update.
///
/// The call rejects an invalid id and an empty patch.
fn validate_update_input(id: &str, patch: &EntityPatch) -> Result<(), EntityError> {
    validate_name("entity id", id)?;
    if patch.attributes.is_empty() {
        return Err(EntityError::Invalid("patch is empty".to_string()));
    }
    Ok(())
}

/// Checks an id or a name against the storage key rules.
///
/// The value must be 1 to 128 bytes.
/// It may contain only lowercase ASCII letters, digits, `_`, and `-`.
/// These rules reject `:` and `/`, so a value cannot inject a key.
pub(crate) fn validate_name(kind: &str, value: &str) -> Result<(), EntityError> {
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
    use std::sync::atomic::Ordering;

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
        attempts: std::sync::atomic::AtomicUsize,
        fail_at: std::sync::atomic::AtomicUsize,
    }

    impl RecordingFeed {
        fn new() -> Self {
            Self {
                ops: std::sync::Mutex::new(Vec::new()),
                failures: std::sync::atomic::AtomicUsize::new(0),
                attempts: std::sync::atomic::AtomicUsize::new(0),
                fail_at: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        /// Makes the append that follows `successes` appends fail.
        fn fail_after(&self, successes: usize) {
            let next = self
                .attempts
                .load(std::sync::atomic::Ordering::SeqCst)
                .saturating_add(successes)
                .saturating_add(1);
            self.fail_at
                .store(next, std::sync::atomic::Ordering::SeqCst);
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
            let attempt = self
                .attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .saturating_add(1);
            if self.fail_at.load(std::sync::atomic::Ordering::SeqCst) == attempt {
                return Err(anyhow::anyhow!("feed down"));
            }
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

        let deleted = store.delete("e1", 1, false, &ctx()).await.unwrap();
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
    async fn two_updates_from_one_version_commit_one() {
        let (store, registry, raw) = new_store().await;
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

        let first_patch = patch(vec![("age", Some(i(31)))]);
        let second_patch = patch(vec![("age", Some(i(32)))]);
        let first_tx = raw.begin_tx().unwrap();
        let second_tx = raw.begin_tx().unwrap();
        let first = store
            .prepare_update(&first_tx, "e1", 1, &first_patch)
            .await
            .unwrap();
        let second = store
            .prepare_update(&second_tx, "e1", 1, &second_patch)
            .await
            .unwrap();
        store
            .stage_update(&first_tx, &first, &ctx(), true, &mut WriteState::default())
            .await
            .unwrap();
        store
            .stage_update(
                &second_tx,
                &second,
                &ctx(),
                true,
                &mut WriteState::default(),
            )
            .await
            .unwrap();

        first_tx.commit().await.unwrap();
        let error = second_tx.commit().await.unwrap_err();

        assert!(matches!(error, StoreError::TxConflict { .. }));
        let entity = store.get("e1").await.unwrap().unwrap();
        assert_eq!(entity.version, 2);
        assert_eq!(entity.attributes["age"], i(31));
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
    async fn a_duplicate_create_writes_no_attribute_row() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("name", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["person"], vec![("name", s("Alice"))]), &ctx())
            .await
            .unwrap();

        let result = store
            .create(draft("e1", &["person"], vec![("name", s("Bob"))]), &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::AlreadyExists(id)) if id == "e1"));
        let stored = raw
            .get_bytes(&attr_key("e1", "name"))
            .await
            .unwrap()
            .expect("the first attribute row must stay");
        assert_eq!(
            serde_json::from_slice::<AttributeValue>(&stored).unwrap(),
            s("Alice")
        );
        let mut keys: Vec<String> = all_keys(&raw)
            .await
            .into_iter()
            .filter(|key| key.starts_with(&attr_prefix("e1")))
            .collect();
        keys.sort();
        assert_eq!(keys, vec![attr_key("e1", "name")]);
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
    async fn a_create_rejects_a_non_finite_float_and_writes_nothing() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("score", AttributeType::Float)],
            ))
            .await
            .unwrap();

        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let result = store
                .create(
                    draft(
                        "e1",
                        &["person"],
                        vec![("score", AttributeValue::Float(value))],
                    ),
                    &ctx(),
                )
                .await;

            assert!(
                matches!(result, Err(EntityError::Invalid(message)) if message.contains("score"))
            );
            assert!(store.get("e1").await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn an_update_rejects_a_non_finite_float_and_keeps_the_stored_value() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("score", AttributeType::Float)],
            ))
            .await
            .unwrap();
        store
            .create(
                draft(
                    "e1",
                    &["person"],
                    vec![("score", AttributeValue::Float(1.5))],
                ),
                &ctx(),
            )
            .await
            .unwrap();

        let result = store
            .update(
                "e1",
                1,
                patch(vec![("score", Some(AttributeValue::Float(f64::NAN)))]),
                &ctx(),
            )
            .await;

        assert!(matches!(result, Err(EntityError::Invalid(message)) if message.contains("score")));
        let stored = store.get("e1").await.unwrap().unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(
            stored.attributes.get("score"),
            Some(&AttributeValue::Float(1.5))
        );
    }

    #[tokio::test]
    async fn a_finite_float_survives_the_json_round_trip() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("score", AttributeType::Float)],
            ))
            .await
            .unwrap();
        store
            .create(
                draft(
                    "e1",
                    &["person"],
                    vec![("score", AttributeValue::Float(1.5))],
                ),
                &ctx(),
            )
            .await
            .unwrap();

        let entity = store.get("e1").await.unwrap().unwrap();
        let bytes = serde_json::to_vec(&entity).unwrap();
        let decoded: Entity = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(decoded, entity);
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
    async fn a_patch_removes_an_optional_attribute_that_has_a_default() {
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
        store
            .create(draft("e1", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let after = store
            .update("e1", 1, patch(vec![("status", None)]), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();

        assert!(!after.attributes.contains_key("status"));
        assert_eq!(store.get("e1").await.unwrap(), Some(after));
    }

    #[tokio::test]
    async fn a_patch_rejects_the_removal_of_a_required_attribute_that_has_a_default() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "status",
                    AttributeType::String,
                    true,
                    false,
                    false,
                    Some(serde_json::json!("new")),
                )],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["task"], vec![]), &ctx())
            .await
            .unwrap();

        let result = store
            .update("e1", 1, patch(vec![("status", None)]), &ctx())
            .await;

        assert!(matches!(result, Err(EntityError::MissingRequired(key)) if key == "status"));
        let stored = store.get("e1").await.unwrap().unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(stored.attributes.get("status"), Some(&s("new")));
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

        store.delete("e1", 1, false, &ctx()).await.unwrap();

        assert_eq!(
            all_keys(&raw).await,
            vec![
                attr_key_index_key("tag"),
                entity_backfill_marker(),
                ref_backfill_marker(),
                unique_name_key("tag"),
            ]
        );
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
    async fn list_by_attribute_rejects_a_removed_index() {
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
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("tag", AttributeType::String)],
            ))
            .await
            .unwrap();

        let result = store.list_by_attribute("tag", &s("alpha")).await;

        assert!(matches!(result, Err(EntityError::NotIndexed(key)) if key == "tag"));
    }

    #[tokio::test]
    async fn list_by_attribute_keeps_an_entity_pinned_to_an_older_index() {
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
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("tag", AttributeType::String)],
            ))
            .await
            .unwrap();

        let found = store.list_by_attribute("tag", &s("alpha")).await.unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "e1");
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
    async fn list_by_attribute_rejects_a_name_marker_without_a_current_schema() {
        let (store, _registry, raw) = new_store().await;
        raw.set_bytes(&attr_key_index_key("ghost"), b"")
            .await
            .unwrap();

        let result = store.list_by_attribute("ghost", &s("alpha")).await;

        assert!(matches!(result, Err(EntityError::NotIndexed(key)) if key == "ghost"));
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
    async fn list_by_attribute_after_full_final_page_returns_no_cursor() {
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
        for id in ["e1", "e2", "e3", "e4"] {
            store
                .create(draft(id, &["task"], vec![("tag", s("alpha"))]), &ctx())
                .await
                .unwrap();
        }

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
        assert_eq!(second_ids, vec!["e3", "e4"]);
        assert_eq!(next, None);

        let mut all: Vec<String> = first.into_iter().map(|entity| entity.id).collect();
        all.extend(second.into_iter().map(|entity| entity.id));
        assert_eq!(all, vec!["e1", "e2", "e3", "e4"]);
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

        store.delete("e1", 2, false, &ctx()).await.unwrap();
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
    async fn list_after_full_final_page_returns_no_cursor() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let (first, next) = store.list_after(2, None).await.unwrap();
        let first_ids: Vec<&str> = first.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(first_ids, vec!["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));

        let (second, next) = store.list_after(2, next.as_deref()).await.unwrap();
        let second_ids: Vec<&str> = second.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(second_ids, vec!["c", "d"]);
        assert_eq!(next, None);

        let mut all: Vec<String> = first.into_iter().map(|entity| entity.id).collect();
        all.extend(second.into_iter().map(|entity| entity.id));
        assert_eq!(all, vec!["a", "b", "c", "d"]);
    }

    #[tokio::test]
    async fn list_after_pages_five_entities_with_a_short_final_page() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d", "e"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let (first, next) = store.list_after(2, None).await.unwrap();
        let first_ids: Vec<&str> = first.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(first_ids, vec!["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));

        let (second, next) = store.list_after(2, next.as_deref()).await.unwrap();
        let second_ids: Vec<&str> = second.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(second_ids, vec!["c", "d"]);
        assert_eq!(next.as_deref(), Some("d"));

        let (third, next) = store.list_after(2, next.as_deref()).await.unwrap();
        let third_ids: Vec<&str> = third.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(third_ids, vec!["e"]);
        assert_eq!(next, None);

        let mut all: Vec<String> = first.into_iter().map(|entity| entity.id).collect();
        all.extend(second.into_iter().map(|entity| entity.id));
        all.extend(third.into_iter().map(|entity| entity.id));
        assert_eq!(all, vec!["a", "b", "c", "d", "e"]);
    }

    #[tokio::test]
    async fn list_after_pages_three_entities_with_a_short_final_page() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let (first, next) = store.list_after(2, None).await.unwrap();
        let first_ids: Vec<&str> = first.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(first_ids, vec!["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));

        let (second, next) = store.list_after(2, next.as_deref()).await.unwrap();
        let second_ids: Vec<&str> = second.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(second_ids, vec!["c"]);
        assert_eq!(next, None);

        let mut all: Vec<String> = first.into_iter().map(|entity| entity.id).collect();
        all.extend(second.into_iter().map(|entity| entity.id));
        assert_eq!(all, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn list_after_empty_store_returns_no_cursor() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();

        let (page, next) = store.list_after(2, None).await.unwrap();

        assert!(page.is_empty());
        assert_eq!(next, None);
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

    /// The entity index backfill covers several pages and lists every entity.
    ///
    /// The page counter shows that more than one page committed.
    /// It does not observe the lock state directly. The lock release is a
    /// structural property of the page loop.
    #[tokio::test]
    async fn list_after_backfills_more_entities_than_one_page() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        let ids = ["a", "b", "c", "d", "e", "f"];
        for id in ids {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        for id in ids {
            raw.delete(&entity_index_key(id)).await.unwrap();
        }
        raw.delete(&entity_backfill_marker()).await.unwrap();
        store.backfill_page_commits.store(0, Ordering::SeqCst);

        let (page, next) = store.list_after(10, None).await.unwrap();
        let listed: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();

        assert_eq!(listed, ids.to_vec());
        assert_eq!(next, None);
        assert!(store.backfill_page_commits.load(Ordering::SeqCst) > 1);

        // A second call keeps the marker and commits no page.
        store.backfill_page_commits.store(0, Ordering::SeqCst);
        let (page, next) = store.list_after(10, None).await.unwrap();
        let listed: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(listed, ids.to_vec());
        assert_eq!(next, None);
        assert_eq!(store.backfill_page_commits.load(Ordering::SeqCst), 0);
        assert!(
            raw.get_bytes(&entity_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );
    }

    /// A marker is not written for an entity that is deleted between pages.
    #[tokio::test]
    async fn the_entity_index_backfill_skips_an_entity_deleted_between_pages() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        let ids = ["a", "b", "c", "d", "e", "f"];
        for id in ids {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }
        for id in ids {
            raw.delete(&entity_index_key(id)).await.unwrap();
        }
        raw.delete(&entity_backfill_marker()).await.unwrap();

        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_store = store.clone();
        let hook_fired = fired.clone();
        store.set_backfill_page_hook(Some(Arc::new(move || {
            let hook_store = hook_store.clone();
            let hook_fired = hook_fired.clone();
            Box::pin(async move {
                if !hook_fired.swap(true, Ordering::SeqCst) {
                    hook_store.delete("e", 1, false, &ctx()).await.unwrap();
                }
            })
        })));

        let (page, next) = store.list_after(10, None).await.unwrap();
        store.set_backfill_page_hook(None);

        let listed: Vec<&str> = page.iter().map(|entity| entity.id.as_str()).collect();

        assert!(fired.load(Ordering::SeqCst));
        assert_eq!(listed, vec!["a", "b", "c", "d", "f"]);
        assert_eq!(next, None);
        assert!(
            raw.get_bytes(&entity_index_key("e"))
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
        store.delete("b", 1, false, &ctx()).await.unwrap();
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
    async fn list_by_schema_after_skips_exactly_the_cursor_and_returns_no_cursor() {
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
        assert_eq!(next, None);
    }

    #[tokio::test]
    async fn list_by_schema_after_full_final_page_returns_no_cursor() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        for id in ["a", "b", "c", "d"] {
            store
                .create(draft(id, &["task"], vec![]), &ctx())
                .await
                .unwrap();
        }

        let (first, next) = store.list_by_schema_after("task", 2, None).await.unwrap();
        let first_ids: Vec<&str> = first.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(first_ids, vec!["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));

        let (second, next) = store
            .list_by_schema_after("task", 2, next.as_deref())
            .await
            .unwrap();
        let second_ids: Vec<&str> = second.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(second_ids, vec!["c", "d"]);
        assert_eq!(next, None);

        let mut all: Vec<String> = first.into_iter().map(|entity| entity.id).collect();
        all.extend(second.into_iter().map(|entity| entity.id));
        assert_eq!(all, vec!["a", "b", "c", "d"]);
    }

    #[tokio::test]
    async fn list_by_schema_after_empty_store_returns_no_cursor() {
        let (store, registry, _raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();

        let (page, next) = store.list_by_schema_after("task", 2, None).await.unwrap();

        assert!(page.is_empty());
        assert_eq!(next, None);
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
    async fn a_unique_name_blocks_a_second_schema() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "account",
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
        registry
            .publish(schema(
                "contact",
                &[],
                vec![attr("email", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("a1", &["account"], vec![("email", s("x@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();
        let before = all_keys(&raw).await;

        let result = store
            .create(
                draft("c1", &["contact"], vec![("email", s("x@example.com"))]),
                &ctx(),
            )
            .await;

        assert!(matches!(result, Err(EntityError::UniqueViolation(key)) if key == "email"));
        assert_eq!(all_keys(&raw).await, before);
        assert!(store.get("c1").await.unwrap().is_none());

        // An update releases the claim.
        store
            .update(
                "a1",
                1,
                patch(vec![("email", Some(s("y@example.com")))]),
                &ctx(),
            )
            .await
            .unwrap();
        store
            .create(
                draft("c1", &["contact"], vec![("email", s("x@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();

        // A delete releases the claim.
        store.delete("c1", 1, false, &ctx()).await.unwrap();
        store
            .create(
                draft("c2", &["contact"], vec![("email", s("x@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();
        assert!(store.get("c2").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn an_indexed_name_adds_a_row_for_a_second_schema() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "account",
                &[],
                vec![full_attr(
                    "email",
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
                "contact",
                &[],
                vec![attr("email", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(
                draft("c1", &["contact"], vec![("email", s("x@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();

        let found = store
            .list_by_attribute("email", &s("x@example.com"))
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "c1");
    }

    #[tokio::test]
    async fn two_handles_claim_one_unique_value_once() {
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
        let other = EntityStore::new(raw.clone(), registry.clone());
        let write = ctx();

        let (left, right) = tokio::join!(
            store.create(
                draft("e1", &["person"], vec![("email", s("x@example.com"))]),
                &write
            ),
            other.create(
                draft("e2", &["person"], vec![("email", s("x@example.com"))]),
                &write
            ),
        );

        let successes = usize::from(left.is_ok()) + usize::from(right.is_ok());
        assert_eq!(successes, 1, "left: {left:?}, right: {right:?}");
        let failure = if left.is_err() { left } else { right };
        assert!(
            matches!(&failure, Err(EntityError::UniqueViolation(key)) if key == "email"),
            "unexpected error: {failure:?}"
        );
        let stored = usize::from(store.get("e1").await.unwrap().is_some())
            + usize::from(store.get("e2").await.unwrap().is_some());
        assert_eq!(stored, 1);
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
    async fn a_unique_hash_collision_keeps_the_exact_value_check() {
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
        // Simulate a collision: `b` also claims the hash of the value of `a`.
        // The exact value of `b` is different, so the claim does not block a
        // different value.
        raw.set_bytes(&unique_extra_key("email", &old_hash, "b"), b"b")
            .await
            .unwrap();

        // The primary claim of `a` still blocks a duplicate of its value.
        let duplicate = store
            .create(
                draft("c", &["person"], vec![("email", s("a@example.com"))]),
                &ctx(),
            )
            .await;
        assert!(matches!(duplicate, Err(EntityError::UniqueViolation(key)) if key == "email"));
        let claim_a = raw
            .get_bytes(&unique_claim_key("email", &old_hash))
            .await
            .unwrap();
        assert_eq!(claim_a.as_deref(), Some(b"a".as_slice()));

        // After `a` releases the value, `c` takes the claim. The collision
        // claim of `b` stays.
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
        let claim_new = raw
            .get_bytes(&unique_claim_key("email", &new_hash))
            .await
            .unwrap();
        let claim_old = raw
            .get_bytes(&unique_claim_key("email", &old_hash))
            .await
            .unwrap();
        let extra_b = raw
            .get_bytes(&unique_extra_key("email", &old_hash, "b"))
            .await
            .unwrap();
        assert_eq!(claim_new.as_deref(), Some(b"a".as_slice()));
        assert_eq!(claim_old.as_deref(), Some(b"c".as_slice()));
        assert_eq!(extra_b.as_deref(), Some(b"b".as_slice()));

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
        store.delete("e1", 2, false, &delete_ctx).await.unwrap();

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

        store.delete("e1", 1, false, &ctx()).await.unwrap();

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
    async fn a_conflicting_delete_returns_a_version_conflict_without_orphan_rows() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("name", AttributeType::String)],
            ))
            .await
            .unwrap();
        store
            .create(draft("e1", &["person"], vec![("name", s("Alice"))]), &ctx())
            .await
            .unwrap();
        // A second handle commits an update after the delete prepares.
        let other = EntityStore::new(raw.clone(), registry.clone());
        store.set_delete_hook(Some(Arc::new(move || {
            let other = other.clone();
            Box::pin(async move {
                other
                    .update("e1", 1, patch(vec![("name", Some(s("Bob")))]), &ctx())
                    .await
                    .unwrap();
            })
        })));

        let result = store.delete("e1", 1, false, &ctx()).await;

        assert!(matches!(result, Err(EntityError::VersionConflict)));
        let stored = store.get("e1").await.unwrap().unwrap();
        assert_eq!(stored.version, 2);
        assert_eq!(stored.attributes.get("name"), Some(&s("Bob")));
        let attr_rows = all_keys(&raw)
            .await
            .into_iter()
            .filter(|key| key.starts_with("entity:e1:attr:"))
            .count();
        assert_eq!(attr_rows, 1);
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
        let change = store.delete("e1", 1, false, &ctx()).await.unwrap();

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

        store.delete("e1", 2, false, &ctx()).await.unwrap();
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

    /// Builds a store with one pending outbox row for each id.
    async fn outbox_store(ids: &[&str]) -> (EntityStore, Arc<RecordingFeed>, OxKvStore) {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        feed.set_failing(true);
        let store = store.with_change_sink(feed.clone());
        for id in ids {
            store
                .create(draft(id, &["person"], vec![]), &ctx())
                .await
                .unwrap();
        }
        (store, feed, raw)
    }

    #[tokio::test]
    async fn flush_outbox_delivers_five_rows_in_key_order_in_batches_of_two() {
        let ids = ["e1", "e2", "e3", "e4", "e5"];
        let (store, feed, raw) = outbox_store(&ids).await;
        let keys = outbox_keys(&raw).await;
        assert_eq!(keys.len(), 5);

        feed.set_failing(false);
        assert_eq!(store.flush_outbox().await.unwrap(), 5);

        let events = feed.events();
        let delivered: Vec<String> = events
            .iter()
            .map(|event| outbox_key(&event.event_id))
            .collect();
        assert_eq!(delivered, keys);
        assert!(outbox_keys(&raw).await.is_empty());
        assert_eq!(pending_counter(&raw).await, Some(0));
    }

    #[tokio::test]
    async fn flush_outbox_delivers_every_row_across_more_than_one_batch() {
        let ids = ["e1", "e2", "e3", "e4", "e5", "e6", "e7"];
        let (store, feed, raw) = outbox_store(&ids).await;
        let keys = outbox_keys(&raw).await;
        assert_eq!(keys.len(), 7);

        feed.set_failing(false);
        assert_eq!(store.flush_outbox().await.unwrap(), 7);

        let events = feed.events();
        let delivered: Vec<String> = events
            .iter()
            .map(|event| outbox_key(&event.event_id))
            .collect();
        assert_eq!(delivered, keys);
        assert!(outbox_keys(&raw).await.is_empty());
        assert_eq!(pending_counter(&raw).await, Some(0));
    }

    #[tokio::test]
    async fn a_feed_failure_on_the_second_row_keeps_later_rows() {
        let ids = ["e1", "e2", "e3", "e4", "e5"];
        let (store, feed, raw) = outbox_store(&ids).await;
        let keys = outbox_keys(&raw).await;

        feed.set_failing(false);
        feed.fail_after(1);
        let result = store.flush_outbox().await;

        assert!(matches!(result, Err(EntityError::Feed(_))));
        assert_eq!(feed.events().len(), 1);
        assert_eq!(outbox_keys(&raw).await, keys[1..]);
        assert_eq!(pending_counter(&raw).await, Some(4));
    }

    #[tokio::test]
    async fn a_counter_write_failure_keeps_the_row_and_the_counter() {
        use oxkv::Hooks as _;

        struct RejectCounterKey;

        #[async_trait::async_trait]
        impl oxkv::Validator for RejectCounterKey {
            async fn validate(
                &self,
                _ctx: &dyn oxkv::StoreView,
                key: &str,
                _value: &[u8],
            ) -> Result<(), oxkv::StoreError> {
                if key == OUTBOX_PENDING_KEY {
                    return Err(oxkv::StoreError::Other("write rejected".to_string()));
                }
                Ok(())
            }
        }

        let ids = ["e1", "e2"];
        let (store, feed, raw) = outbox_store(&ids).await;
        let keys = outbox_keys(&raw).await;

        feed.set_failing(false);
        raw.add_validator(RejectCounterKey);
        let result = store.flush_outbox().await;

        assert!(matches!(result, Err(EntityError::Store(_))));
        assert_eq!(feed.events().len(), 1);
        assert_eq!(outbox_keys(&raw).await, keys);
        assert_eq!(pending_counter(&raw).await, Some(2));
    }

    #[tokio::test]
    async fn a_delete_failure_keeps_the_row_and_the_counter() {
        let ids = ["e1", "e2"];
        let (store, feed, raw) = outbox_store(&ids).await;
        let keys = outbox_keys(&raw).await;

        feed.set_failing(false);
        store
            .outbox_delete_failures
            .store(1, std::sync::atomic::Ordering::SeqCst);
        let result = store.flush_outbox().await;

        assert!(matches!(result, Err(EntityError::Store(_))));
        assert_eq!(feed.events().len(), 1);
        assert_eq!(outbox_keys(&raw).await, keys);
        assert_eq!(pending_counter(&raw).await, Some(2));
    }

    #[tokio::test]
    async fn flush_outbox_reads_at_most_two_rows_at_one_time() {
        let ids = ["e1", "e2", "e3", "e4", "e5"];
        let (store, feed, _raw) = outbox_store(&ids).await;

        feed.set_failing(false);
        assert_eq!(store.flush_outbox().await.unwrap(), 5);

        assert_eq!(OUTBOX_FLUSH_BATCH, 2);
        assert_eq!(
            store
                .outbox_batch_peak
                .load(std::sync::atomic::Ordering::SeqCst),
            OUTBOX_FLUSH_BATCH
        );
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

    #[tokio::test]
    async fn a_poison_outbox_row_does_not_block_the_good_row() {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema("person", &[], vec![]))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        feed.set_failing(true);
        store
            .create(draft("e1", &["person"], vec![]), &ctx())
            .await
            .unwrap();
        feed.set_failing(false);
        assert_eq!(outbox_keys(&raw).await.len(), 1);
        let poison_id = "00000000-0000-7000-8000-000000000000";
        raw.set_bytes(&outbox_key(poison_id), b"not an event")
            .await
            .unwrap();
        raw.set_bytes(outbox_pending_key(), b"2").await.unwrap();

        let delivered = store.flush_outbox().await.unwrap();

        assert_eq!(delivered, 1);
        let events = feed.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].entity_id, "e1");
        assert!(outbox_keys(&raw).await.is_empty());
        assert_eq!(
            raw.get_bytes(&outbox_poison_key(poison_id)).await.unwrap(),
            Some(b"not an event".to_vec())
        );
        assert_eq!(pending_counter(&raw).await, Some(0));
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

        store.delete("e1", 1, false, &ctx()).await.unwrap();
        store.delete("e2", 1, false, &ctx()).await.unwrap();

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

    /// The time key backfill writes every distinct key across several pages.
    ///
    /// The page counter shows that more than one page committed.
    /// It does not observe the lock state directly. The lock release is a
    /// structural property of the page loop.
    #[tokio::test]
    async fn time_keys_backfills_more_keys_than_one_page() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        let keys = ["alpha", "beta", "delta", "epsilon", "gamma"];
        for (offset, key) in keys.iter().enumerate() {
            raw.set_bytes(&time_index_key(key, offset as i64, "e1"), b"")
                .await
                .unwrap();
        }
        assert!(
            !all_keys(&raw)
                .await
                .iter()
                .any(|key| key.starts_with(TIME_KEY_INDEX_PREFIX))
        );
        store.backfill_page_commits.store(0, Ordering::SeqCst);

        let found = store.time_keys().await.unwrap();

        assert_eq!(found, keys.map(str::to_string).to_vec());
        assert!(store.backfill_page_commits.load(Ordering::SeqCst) > 1);
        let markers: Vec<String> = all_keys(&raw)
            .await
            .into_iter()
            .filter(|key| key.starts_with(TIME_KEY_INDEX_PREFIX))
            .collect();
        assert_eq!(markers.len(), keys.len());

        // A second call keeps the marker and commits no page.
        store.backfill_page_commits.store(0, Ordering::SeqCst);
        assert_eq!(
            store.time_keys().await.unwrap(),
            keys.map(str::to_string).to_vec()
        );
        assert_eq!(store.backfill_page_commits.load(Ordering::SeqCst), 0);
        assert!(
            raw.get_bytes(&time_key_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn time_keys_stop_at_the_family_bound() {
        let (store, registry, raw) = new_store().await;
        registry.publish(schema("task", &[], vec![])).await.unwrap();
        raw.set_bytes(&time_key_index_key("alpha"), b"")
            .await
            .unwrap();
        raw.set_bytes("idx:time-key;outside", b"").await.unwrap();

        let found = store.time_keys().await.unwrap();

        assert_eq!(found, vec!["alpha".to_string()]);
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
    async fn list_due_continues_past_a_full_page_of_stale_rows() {
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
        for (id, due) in [("e1", 100), ("e2", 10), ("e3", 20)] {
            create_task(&store, id, due).await;
        }
        raw.set_bytes(&time_index_key("due", 1, "ghost"), b"")
            .await
            .unwrap();
        raw.set_bytes(&time_index_key("due", 2, "e1"), b"")
            .await
            .unwrap();

        let due = store.list_due("due", 60, 2).await.unwrap();
        let ids: Vec<&str> = due.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(ids, vec!["e2", "e3"]);

        let all = store.list_due("due", 60, 100).await.unwrap();
        let ids: Vec<&str> = all.iter().map(|entity| entity.id.as_str()).collect();
        assert_eq!(ids, vec!["e2", "e3"]);
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

        store.delete("e1", 2, false, &ctx()).await.unwrap();
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
        store.delete("e1", 1, false, &ctx()).await.unwrap();

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
        store.delete("e1", 3, false, &ctx()).await.unwrap();
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
    async fn a_migration_stores_the_schema_default_and_indexes_it() {
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
                    full_attr(
                        "owner",
                        AttributeType::String,
                        true,
                        true,
                        false,
                        Some(serde_json::json!("system")),
                    ),
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

        assert_eq!(report.migrated, 1);
        assert!(report.invalid.is_empty());
        let entity = store.get("e1").await.unwrap().unwrap();
        assert_eq!(entity.version, 2);
        assert_eq!(entity.attributes.get("owner"), Some(&s("system")));
        let found = store
            .list_by_attribute("owner", &s("system"))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "e1");
        let events = feed.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EntityEventKind::SchemaApplied);
        assert_eq!(
            events[0].snapshot.as_ref().unwrap()["owner"],
            serde_json::json!("system")
        );
    }

    #[tokio::test]
    async fn schema_migration_adds_an_index_row() {
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

        let report = store
            .migrate_schema("task", 2, 100, None, false, &ctx())
            .await
            .unwrap();

        assert_eq!(report.migrated, 1);
        let found = store.list_by_attribute("tag", &s("alpha")).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "e1");
    }

    #[tokio::test]
    async fn schema_migration_reports_a_duplicate_unique_value_in_the_dry_run_and_the_apply() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema(
                "task",
                &[],
                vec![attr("tag", AttributeType::String)],
            ))
            .await
            .unwrap();
        for id in ["e1", "e2"] {
            store
                .create(draft(id, &["task"], vec![("tag", s("alpha"))]), &ctx())
                .await
                .unwrap();
        }
        registry
            .publish(schema(
                "task",
                &[],
                vec![full_attr(
                    "tag",
                    AttributeType::String,
                    false,
                    false,
                    true,
                    None,
                )],
            ))
            .await
            .unwrap();

        let dry_run = store
            .migrate_schema("task", 2, 100, None, true, &ctx())
            .await
            .unwrap();
        let applied = store
            .migrate_schema("task", 2, 100, None, false, &ctx())
            .await
            .unwrap();

        for report in [&dry_run, &applied] {
            assert_eq!(report.migrated, 1);
            assert_eq!(report.invalid.len(), 1);
            assert_eq!(report.invalid[0].entity_id, "e2");
            assert_eq!(
                report.invalid[0].issue,
                RevalidationIssue::DuplicateUnique("tag".to_string())
            );
        }
        assert_eq!(store.get("e1").await.unwrap().unwrap().version, 2);
        assert_eq!(store.get("e2").await.unwrap().unwrap().version, 1);
    }

    #[tokio::test]
    async fn schema_migration_adds_a_parent_schema_row() {
        let (store, registry, _raw) = new_store().await;
        registry
            .publish(schema("parent", &[], vec![]))
            .await
            .unwrap();
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
                &["parent"],
                vec![attr("title", AttributeType::String)],
            ))
            .await
            .unwrap();

        let report = store
            .migrate_schema("task", 2, 100, None, false, &ctx())
            .await
            .unwrap();

        assert_eq!(report.migrated, 1);
        let parents = store.list_by_schema("parent").await.unwrap();
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].id, "e1");
        let tasks = store.list_by_schema("task").await.unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, "e1");
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

    async fn reference_store(check: bool) -> (EntityStore, SchemaRegistry, OxKvStore) {
        let registry = SchemaRegistry::new(build_test_store(&test_prefix("eav-ref-schema")).await);
        let raw = build_test_store(&test_prefix("eav-ref")).await;
        let store = EntityStore::new(raw.clone(), registry.clone()).with_entity_ref_check(check);
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
        (store, registry, raw)
    }

    async fn ref_markers(raw: &OxKvStore) -> Vec<String> {
        all_keys(raw)
            .await
            .into_iter()
            .filter(|key| key.starts_with(REF_INDEX_PREFIX))
            .collect()
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
        let (store, _, _) = reference_store(true).await;

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
        let (store, registry, _) = reference_store(true).await;
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
        let (store, _, _) = reference_store(true).await;
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
        let (store, _, _) = reference_store(false).await;

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
        let (store, registry, _) = reference_store(true).await;
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
        let (store, _, _) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();

        store.delete("c1", 1, true, &ctx()).await.unwrap();

        let stored = store.get("o1").await.unwrap().unwrap();
        assert_eq!(
            stored.attributes.get("customer"),
            Some(&AttributeValue::EntityRef("c1".to_string()))
        );
        let error = store.create(order("o2", "c1"), &ctx()).await.unwrap_err();
        assert!(matches!(error, EntityError::DanglingRef(_, _)));
    }

    #[tokio::test]
    async fn a_migration_reports_a_dangling_reference_in_the_dry_run_and_the_apply() {
        let (store, registry, _) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();
        store.delete("c1", 1, true, &ctx()).await.unwrap();
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

        let dry_run = store
            .migrate_schema("order", 2, 100, None, true, &ctx())
            .await
            .unwrap();
        let applied = store
            .migrate_schema("order", 2, 100, None, false, &ctx())
            .await
            .unwrap();

        for report in [&dry_run, &applied] {
            assert_eq!(report.migrated, 0);
            assert_eq!(report.invalid.len(), 1);
            assert_eq!(report.invalid[0].entity_id, "o1");
            assert_eq!(
                report.invalid[0].issue,
                RevalidationIssue::DanglingRef("customer".to_string())
            );
        }
        let stored = store.get("o1").await.unwrap().unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(stored.schemas[0].version, 1);
    }

    #[tokio::test]
    async fn a_referenced_entity_delete_is_blocked_and_changes_nothing() {
        let (store, _, _) = reference_store(true).await;
        let customer_before = store
            .create(customer("c1"), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();
        let order_before = store
            .create(order("o1", "c1"), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();

        let error = store.delete("c1", 1, false, &ctx()).await.unwrap_err();

        match &error {
            EntityError::Referenced { id, count } => {
                assert_eq!(id, "c1");
                assert_eq!(*count, 1);
            }
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(store.get("c1").await.unwrap(), Some(customer_before));
        assert_eq!(store.get("o1").await.unwrap(), Some(order_before));
    }

    #[tokio::test]
    async fn a_forced_delete_removes_the_entity_and_keeps_the_source_reference() {
        let (store, _, raw) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();

        let change = store.delete("c1", 1, true, &ctx()).await.unwrap();

        assert_eq!(
            change.before.map(|entity| entity.id),
            Some("c1".to_string())
        );
        assert!(change.after.is_none());
        assert!(store.get("c1").await.unwrap().is_none());
        let stored = store.get("o1").await.unwrap().unwrap();
        assert_eq!(
            stored.attributes.get("customer"),
            Some(&AttributeValue::EntityRef("c1".to_string()))
        );
        assert!(
            ref_markers(&raw)
                .await
                .contains(&"idx:ref:c1:o1:customer".to_string())
        );
    }

    #[tokio::test]
    async fn a_self_reference_does_not_block_its_own_delete() {
        let (store, registry, _) = reference_store(true).await;
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

        store.delete("n1", 1, false, &ctx()).await.unwrap();

        assert!(store.get("n1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_update_that_removes_a_reference_removes_the_marker() {
        let (store, _, raw) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();

        store
            .update("o1", 1, patch(vec![("customer", None)]), &ctx())
            .await
            .unwrap();

        assert!(ref_markers(&raw).await.is_empty());
        store.delete("c1", 1, false, &ctx()).await.unwrap();
    }

    #[tokio::test]
    async fn an_update_that_points_to_a_new_target_moves_the_marker() {
        let (store, _, raw) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(customer("c2"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();

        store
            .update(
                "o1",
                1,
                patch(vec![(
                    "customer",
                    Some(AttributeValue::EntityRef("c2".to_string())),
                )]),
                &ctx(),
            )
            .await
            .unwrap();

        assert_eq!(
            ref_markers(&raw).await,
            vec!["idx:ref:c2:o1:customer".to_string()]
        );
        store.delete("c1", 1, false, &ctx()).await.unwrap();
        let error = store.delete("c2", 1, false, &ctx()).await.unwrap_err();
        assert!(matches!(error, EntityError::Referenced { count: 1, .. }));
    }

    #[tokio::test]
    async fn deleting_the_source_removes_its_outgoing_marker() {
        let (store, _, raw) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();

        store.delete("o1", 1, false, &ctx()).await.unwrap();

        assert!(ref_markers(&raw).await.is_empty());
        store.delete("c1", 1, false, &ctx()).await.unwrap();
    }

    #[tokio::test]
    async fn two_referrers_give_a_count_and_the_message_names_no_referrer() {
        let (store, _, _) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();
        store.create(order("o2", "c1"), &ctx()).await.unwrap();

        let error = store.delete("c1", 1, false, &ctx()).await.unwrap_err();

        assert!(matches!(error, EntityError::Referenced { count: 2, .. }));
        let message = error.to_string();
        assert!(message.contains("c1"), "{message}");
        assert!(message.contains('2'), "{message}");
        assert!(!message.contains("o1"), "{message}");
        assert!(!message.contains("o2"), "{message}");
    }

    #[tokio::test]
    async fn count_incoming_refs_covers_every_page_of_sources() {
        let (store, _, _) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        for id in ["o1", "o2", "o3"] {
            store.create(order(id, "c1"), &ctx()).await.unwrap();
        }

        let error = store.delete("c1", 1, false, &ctx()).await.unwrap_err();

        assert!(
            matches!(error, EntityError::Referenced { count: 3, .. }),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn the_first_delete_backfills_the_markers_for_an_old_store() {
        let (store, _, raw) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        store.create(order("o1", "c1"), &ctx()).await.unwrap();
        for key in all_keys(&raw).await {
            if key.starts_with(REF_INDEX_PREFIX) {
                raw.delete(&key).await.unwrap();
            }
        }
        raw.delete(&ref_backfill_marker()).await.unwrap();
        assert!(ref_markers(&raw).await.is_empty());

        let error = store.delete("c1", 1, false, &ctx()).await.unwrap_err();

        assert!(matches!(error, EntityError::Referenced { count: 1, .. }));
        assert!(
            raw.get_bytes(&ref_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            ref_markers(&raw)
                .await
                .contains(&"idx:ref:c1:o1:customer".to_string())
        );
    }

    /// The ref backfill writes every marker across several pages.
    ///
    /// The page counter shows that more than one page committed.
    /// It does not observe the lock state directly. The lock release is a
    /// structural property of the page loop.
    #[tokio::test]
    async fn the_first_delete_backfills_more_entities_than_one_page() {
        let (store, _, raw) = reference_store(true).await;
        let targets = ["c1", "c2", "c3", "c4", "c5"];
        for target in targets {
            store.create(customer(target), &ctx()).await.unwrap();
        }
        for (index, target) in targets.iter().enumerate() {
            let order_id = format!("o{}", index + 1);
            store
                .create(order(&order_id, target), &ctx())
                .await
                .unwrap();
        }
        for key in all_keys(&raw).await {
            if key.starts_with(REF_INDEX_PREFIX) {
                raw.delete(&key).await.unwrap();
            }
        }
        raw.delete(&ref_backfill_marker()).await.unwrap();
        assert!(ref_markers(&raw).await.is_empty());
        store.backfill_page_commits.store(0, Ordering::SeqCst);

        let error = store.delete("c1", 1, false, &ctx()).await.unwrap_err();

        assert!(matches!(error, EntityError::Referenced { count: 1, .. }));
        assert!(store.backfill_page_commits.load(Ordering::SeqCst) > 1);
        for (index, target) in targets.iter().enumerate() {
            let expected = format!("idx:ref:{target}:o{}:customer", index + 1);
            assert!(ref_markers(&raw).await.contains(&expected));
        }

        // A present marker keeps its value and commits no page.
        store.create(customer("c9"), &ctx()).await.unwrap();
        store.backfill_page_commits.store(0, Ordering::SeqCst);
        store.delete("c9", 1, false, &ctx()).await.unwrap();
        assert_eq!(store.backfill_page_commits.load(Ordering::SeqCst), 0);
        assert!(
            raw.get_bytes(&ref_backfill_marker())
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_non_reference_attribute_writes_no_marker() {
        let (store, _, raw) = reference_store(true).await;

        store.create(customer("c1"), &ctx()).await.unwrap();

        assert!(ref_markers(&raw).await.is_empty());
    }

    #[tokio::test]
    async fn a_forced_delete_of_an_unreferenced_entity_matches_a_normal_delete() {
        let (store, _, _) = reference_store(true).await;
        let created = store
            .create(customer("c1"), &ctx())
            .await
            .unwrap()
            .after
            .unwrap();

        let change = store.delete("c1", 1, true, &ctx()).await.unwrap();

        assert_eq!(change.before, Some(created));
        assert!(change.after.is_none());
        assert!(store.get("c1").await.unwrap().is_none());
    }

    fn effect_create(
        id: &str,
        schemas: &[&str],
        attrs: Vec<(&str, AttributeValue)>,
    ) -> EntityEffect {
        EntityEffect::Create {
            id: id.to_string(),
            schemas: schemas.iter().map(|value| value.to_string()).collect(),
            attributes: attrs
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
        }
    }

    fn effect_update(
        id: &str,
        expected_version: u64,
        attrs: Vec<(&str, Option<AttributeValue>)>,
    ) -> EntityEffect {
        EntityEffect::Update {
            id: id.to_string(),
            expected_version,
            attributes: attrs
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
        }
    }

    fn effect_delete(id: &str, expected_version: u64, force: bool) -> EntityEffect {
        EntityEffect::Delete {
            id: id.to_string(),
            expected_version,
            force,
        }
    }

    async fn person_store() -> (EntityStore, SchemaRegistry, OxKvStore) {
        let (store, registry, raw) = new_store().await;
        registry
            .publish(schema(
                "person",
                &[],
                vec![attr("name", AttributeType::String)],
            ))
            .await
            .unwrap();
        (store, registry, raw)
    }

    #[tokio::test]
    async fn three_creates_commit_together_and_return_changes_in_plan_order() {
        let (store, _, _) = person_store().await;
        let plan = EffectPlan::new(vec![
            effect_create("e1", &["person"], vec![("name", s("Alice"))]),
            effect_create("e2", &["person"], vec![("name", s("Bob"))]),
            effect_create("e3", &["person"], vec![("name", s("Carol"))]),
        ]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 3);
        let ids: Vec<&str> = changes
            .iter()
            .map(|change| change.after.as_ref().unwrap().id.as_str())
            .collect();
        assert_eq!(ids, ["e1", "e2", "e3"]);
        for change in &changes {
            assert!(change.before.is_none());
            assert_eq!(change.after.as_ref().unwrap().version, 1);
        }
        for id in ["e1", "e2", "e3"] {
            assert!(store.get(id).await.unwrap().is_some());
        }
    }

    /// The second effect reads the uncommitted create of the first effect.
    ///
    /// The OxKV transaction supplies read-your-writes, so the plan needs no
    /// separate overlay.
    #[tokio::test]
    async fn a_create_then_an_update_of_one_entity_commits_the_final_state() {
        let (store, _, _) = person_store().await;
        let plan = EffectPlan::new(vec![
            effect_create("e1", &["person"], vec![("name", s("Alice"))]),
            effect_update("e1", 1, vec![("name", Some(s("Bob")))]),
        ]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].after.as_ref().unwrap().version, 1);
        assert_eq!(changes[1].before.as_ref().unwrap().version, 1);
        let after = changes[1].after.as_ref().unwrap();
        assert_eq!(after.version, 2);
        assert_eq!(after.attributes.get("name"), Some(&s("Bob")));
        let stored = store.get("e1").await.unwrap().unwrap();
        assert_eq!(stored.version, 2);
        assert_eq!(stored.attributes.get("name"), Some(&s("Bob")));
    }

    #[tokio::test]
    async fn a_delete_then_a_create_in_one_plan_keeps_a_unique_claim() {
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
                draft("e1", &["person"], vec![("email", s("x@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();
        let plan = EffectPlan::new(vec![
            effect_delete("e1", 1, false),
            effect_create("e1", &["person"], vec![("email", s("x@example.com"))]),
        ]);

        store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(
            store
                .get("e1")
                .await
                .unwrap()
                .unwrap()
                .attributes
                .get("email"),
            Some(&s("x@example.com"))
        );
        let duplicate = store
            .create(
                draft("e2", &["person"], vec![("email", s("x@example.com"))]),
                &ctx(),
            )
            .await;
        assert!(matches!(duplicate, Err(EntityError::UniqueViolation(key)) if key == "email"));
    }

    #[tokio::test]
    async fn two_updates_of_one_entity_in_one_plan_commit_the_final_state() {
        let (store, _, _) = person_store().await;
        store
            .create(draft("e1", &["person"], vec![("name", s("Alice"))]), &ctx())
            .await
            .unwrap();
        let plan = EffectPlan::new(vec![
            effect_update("e1", 1, vec![("name", Some(s("Bob")))]),
            effect_update("e1", 2, vec![("name", Some(s("Carol")))]),
        ]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 2);
        let stored = store.get("e1").await.unwrap().unwrap();
        assert_eq!(stored.version, 3);
        assert_eq!(stored.attributes.get("name"), Some(&s("Carol")));
    }

    #[tokio::test]
    async fn a_delete_then_a_create_of_one_entity_commits_the_new_state() {
        let (store, _, raw) = person_store().await;
        store
            .create(draft("e1", &["person"], vec![("name", s("Alice"))]), &ctx())
            .await
            .unwrap();
        let plan = EffectPlan::new(vec![
            effect_delete("e1", 1, false),
            effect_create("e1", &["person"], vec![("name", s("Bob"))]),
        ]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 2);
        let stored = store.get("e1").await.unwrap().unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(stored.attributes.get("name"), Some(&s("Bob")));
        let attr_rows = all_keys(&raw)
            .await
            .into_iter()
            .filter(|key| key == &attr_key("e1", "name"))
            .count();
        assert_eq!(attr_rows, 1);
    }

    #[tokio::test]
    async fn a_plan_rejects_an_update_after_a_delete_of_one_entity() {
        let (store, _, raw) = person_store().await;
        store
            .create(draft("e1", &["person"], vec![("name", s("Alice"))]), &ctx())
            .await
            .unwrap();
        let before = all_keys(&raw).await;
        let plan = EffectPlan::new(vec![
            effect_delete("e1", 1, false),
            effect_update("e1", 1, vec![("name", Some(s("Bob")))]),
        ]);

        let error = store.apply_effects(&plan, &ctx()).await.unwrap_err();

        assert!(
            matches!(&error, EntityError::Invalid(message) if message.contains("after a delete")),
            "unexpected error: {error}"
        );
        assert_eq!(all_keys(&raw).await, before);
        assert!(store.get("e1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_create_then_a_delete_of_one_entity_leaves_no_entity() {
        let (store, _, _) = person_store().await;
        let plan = EffectPlan::new(vec![
            effect_create("e1", &["person"], vec![("name", s("Alice"))]),
            effect_delete("e1", 1, false),
        ]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 2);
        assert!(changes[0].after.is_some());
        assert!(changes[1].after.is_none());
        assert_eq!(changes[1].before.as_ref().unwrap().id, "e1");
        assert!(store.get("e1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_update_then_a_delete_of_one_entity_commits_both_changes() {
        let (store, _, _) = person_store().await;
        store
            .create(draft("e1", &["person"], vec![("name", s("Alice"))]), &ctx())
            .await
            .unwrap();
        let plan = EffectPlan::new(vec![
            effect_update("e1", 1, vec![("name", Some(s("Bob")))]),
            effect_delete("e1", 2, false),
        ]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].after.as_ref().unwrap().version, 2);
        assert_eq!(changes[1].before.as_ref().unwrap().version, 2);
        assert!(changes[1].after.is_none());
        assert!(store.get("e1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_failure_in_the_last_effect_rolls_back_the_whole_plan() {
        let (store, _, raw) = person_store().await;
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        let before = all_keys(&raw).await;
        let plan = EffectPlan::new(vec![
            effect_create("e1", &["person"], vec![("name", s("Alice"))]),
            effect_create("e2", &["person"], vec![("name", s("Bob"))]),
            effect_create("e1", &["person"], vec![("name", s("Carol"))]),
        ]);

        let error = store.apply_effects(&plan, &ctx()).await.unwrap_err();

        assert!(
            matches!(&error, EntityError::AlreadyExists(id) if id == "e1"),
            "unexpected error: {error}"
        );
        assert_eq!(all_keys(&raw).await, before);
        assert!(store.get("e1").await.unwrap().is_none());
        assert!(store.get("e2").await.unwrap().is_none());
        assert!(outbox_keys(&raw).await.is_empty());
        assert_eq!(pending_counter(&raw).await, None);
        assert!(feed.events().is_empty());
    }

    #[tokio::test]
    async fn a_version_conflict_in_the_middle_rolls_back_the_whole_plan() {
        let (store, _, raw) = person_store().await;
        store
            .create(draft("e1", &["person"], vec![("name", s("Alice"))]), &ctx())
            .await
            .unwrap();
        let before = all_keys(&raw).await;
        let plan = EffectPlan::new(vec![
            effect_create("e2", &["person"], vec![("name", s("Bob"))]),
            effect_update("e1", 99, vec![("name", Some(s("Bob")))]),
            effect_create("e3", &["person"], vec![("name", s("Carol"))]),
        ]);

        let error = store.apply_effects(&plan, &ctx()).await.unwrap_err();

        assert!(matches!(error, EntityError::VersionConflict));
        assert_eq!(all_keys(&raw).await, before);
        assert!(store.get("e2").await.unwrap().is_none());
        assert!(store.get("e3").await.unwrap().is_none());
        let stored = store.get("e1").await.unwrap().unwrap();
        assert_eq!(stored.version, 1);
        assert_eq!(stored.attributes.get("name"), Some(&s("Alice")));
    }

    #[tokio::test]
    async fn a_unique_conflict_in_the_middle_rolls_back_the_whole_plan() {
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
                draft("owner", &["person"], vec![("email", s("a@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();
        let before = all_keys(&raw).await;
        let plan = EffectPlan::new(vec![
            effect_create("e2", &["person"], vec![("email", s("b@example.com"))]),
            effect_create("e3", &["person"], vec![("email", s("a@example.com"))]),
            effect_create("e4", &["person"], vec![("email", s("c@example.com"))]),
        ]);

        let error = store.apply_effects(&plan, &ctx()).await.unwrap_err();

        assert!(
            matches!(&error, EntityError::UniqueViolation(key) if key == "email"),
            "unexpected error: {error}"
        );
        assert_eq!(all_keys(&raw).await, before);
        for id in ["e2", "e3", "e4"] {
            assert!(store.get(id).await.unwrap().is_none());
        }
        let owner = store.get("owner").await.unwrap().unwrap();
        assert_eq!(owner.attributes.get("email"), Some(&s("a@example.com")));
        store
            .create(
                draft("e5", &["person"], vec![("email", s("b@example.com"))]),
                &ctx(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_dangling_reference_in_the_middle_rolls_back_the_whole_plan() {
        let (store, _, raw) = reference_store(true).await;
        store.create(customer("c1"), &ctx()).await.unwrap();
        let before = all_keys(&raw).await;
        let plan = EffectPlan::new(vec![
            effect_create(
                "o1",
                &["order"],
                vec![("customer", AttributeValue::EntityRef("c1".to_string()))],
            ),
            effect_create(
                "o2",
                &["order"],
                vec![("customer", AttributeValue::EntityRef("missing".to_string()))],
            ),
            effect_create(
                "o3",
                &["order"],
                vec![("customer", AttributeValue::EntityRef("c1".to_string()))],
            ),
        ]);

        let error = store.apply_effects(&plan, &ctx()).await.unwrap_err();

        assert!(
            matches!(&error, EntityError::DanglingRef(name, target) if name == "customer" && target == "missing"),
            "unexpected error: {error}"
        );
        assert_eq!(all_keys(&raw).await, before);
        for id in ["o1", "o2", "o3"] {
            assert!(store.get(id).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn a_reference_to_an_entity_created_earlier_in_the_plan_succeeds() {
        let (store, _, raw) = reference_store(true).await;
        let plan = EffectPlan::new(vec![
            effect_create("c1", &["customer"], vec![("name", s("c1"))]),
            effect_create(
                "o1",
                &["order"],
                vec![("customer", AttributeValue::EntityRef("c1".to_string()))],
            ),
        ]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 2);
        assert!(store.get("c1").await.unwrap().is_some());
        let order = store.get("o1").await.unwrap().unwrap();
        assert_eq!(
            order.attributes.get("customer"),
            Some(&AttributeValue::EntityRef("c1".to_string()))
        );
        assert!(
            ref_markers(&raw)
                .await
                .contains(&"idx:ref:c1:o1:customer".to_string())
        );
    }

    #[tokio::test]
    async fn a_self_reference_to_an_entity_created_in_the_plan_succeeds() {
        let (store, registry, _) = reference_store(true).await;
        registry
            .publish(schema(
                "node",
                &[],
                vec![attr("parent", AttributeType::EntityRef)],
            ))
            .await
            .unwrap();
        let plan = EffectPlan::new(vec![effect_create(
            "n1",
            &["node"],
            vec![("parent", AttributeValue::EntityRef("n1".to_string()))],
        )]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 1);
        let node = store.get("n1").await.unwrap().unwrap();
        assert_eq!(
            node.attributes.get("parent"),
            Some(&AttributeValue::EntityRef("n1".to_string()))
        );
    }

    #[tokio::test]
    async fn a_plan_of_one_hundred_effects_is_applied() {
        let (store, _, _) = person_store().await;
        let effects = (0..100)
            .map(|index| effect_create(&format!("e{index}"), &["person"], vec![]))
            .collect();
        let plan = EffectPlan::new(effects);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 100);
        assert!(store.get("e0").await.unwrap().is_some());
        assert!(store.get("e99").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_plan_of_one_hundred_and_one_effects_is_rejected() {
        let (store, _, raw) = person_store().await;
        let before = all_keys(&raw).await;
        let effects = (0..=100)
            .map(|index| effect_create(&format!("e{index}"), &["person"], vec![]))
            .collect();
        let plan = EffectPlan::new(effects);

        let error = store.apply_effects(&plan, &ctx()).await.unwrap_err();

        assert!(
            matches!(&error, EntityError::Invalid(message) if message.contains("more than 100")),
            "unexpected error: {error}"
        );
        assert_eq!(all_keys(&raw).await, before);
    }

    #[tokio::test]
    async fn an_empty_plan_returns_an_empty_result_and_changes_nothing() {
        let (store, _, raw) = person_store().await;
        let before = all_keys(&raw).await;

        let changes = store
            .apply_effects(&EffectPlan::default(), &ctx())
            .await
            .unwrap();

        assert!(changes.is_empty());
        assert_eq!(all_keys(&raw).await, before);
    }

    #[tokio::test]
    async fn the_outbox_has_one_row_for_each_effect_in_plan_order() {
        let (store, _, raw) = person_store().await;
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        feed.set_failing(true);
        let plan = EffectPlan::new(vec![
            effect_create("e1", &["person"], vec![("name", s("Alice"))]),
            effect_update("e1", 1, vec![("name", Some(s("Bob")))]),
            effect_create("e2", &["person"], vec![("name", s("Carol"))]),
        ]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 3);
        assert!(feed.events().is_empty());
        let keys = outbox_keys(&raw).await;
        assert_eq!(keys.len(), 3);
        assert_eq!(pending_counter(&raw).await, Some(3));
        let mut events = Vec::new();
        for key in &keys {
            let bytes = raw.get_bytes(key).await.unwrap().unwrap();
            events.push(serde_json::from_slice::<EntityEvent>(&bytes).unwrap());
        }
        let ids: Vec<&str> = events
            .iter()
            .map(|event| event.entity_id.as_str())
            .collect();
        assert_eq!(ids, ["e1", "e1", "e2"]);
        let kinds: Vec<EntityEventKind> = events.iter().map(|event| event.kind).collect();
        assert_eq!(
            kinds,
            [
                EntityEventKind::Created,
                EntityEventKind::Updated,
                EntityEventKind::Created
            ]
        );

        feed.set_failing(false);
        assert_eq!(store.flush_outbox().await.unwrap(), 3);
        assert_eq!(pending_counter(&raw).await, Some(0));
        assert!(outbox_keys(&raw).await.is_empty());
        let delivered = feed.events();
        let ids: Vec<&str> = delivered
            .iter()
            .map(|event| event.entity_id.as_str())
            .collect();
        assert_eq!(ids, ["e1", "e1", "e2"]);
    }

    #[tokio::test]
    async fn effects_and_a_marker_commit_together() {
        let (store, _, raw) = person_store().await;
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        feed.set_failing(true);
        let marker_key = "rule:exec:greet:ev1";
        let marker_value = b"1700000000";
        let plan = EffectPlan::new(vec![
            effect_create("e1", &["person"], vec![("name", s("Alice"))]),
            effect_update("e1", 1, vec![("name", Some(s("Bob")))]),
        ]);

        let changes = store
            .apply_effects_with_marker(&plan, &ctx(), Some((marker_key, marker_value)))
            .await
            .unwrap();

        assert_eq!(changes.len(), 2);
        assert_eq!(
            raw.get_bytes(marker_key).await.unwrap().as_deref(),
            Some(&marker_value[..])
        );
        let stored = store.get("e1").await.unwrap().unwrap();
        assert_eq!(stored.version, 2);
        assert_eq!(stored.attributes.get("name"), Some(&s("Bob")));
        assert_eq!(outbox_keys(&raw).await.len(), 2);
        assert_eq!(pending_counter(&raw).await, Some(2));
        assert!(feed.events().is_empty());
    }

    #[tokio::test]
    async fn a_marker_write_failure_rolls_back_the_whole_plan() {
        use oxkv::Hooks as _;

        struct RejectMarkerKey(&'static str);

        #[async_trait::async_trait]
        impl oxkv::Validator for RejectMarkerKey {
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
                "person",
                &[],
                vec![
                    attr("name", AttributeType::String),
                    full_attr("tag", AttributeType::String, false, true, false, None),
                ],
            ))
            .await
            .unwrap();
        let feed = Arc::new(RecordingFeed::new());
        let store = store.with_change_sink(feed.clone());
        feed.set_failing(true);
        let before = all_keys(&raw).await;
        let marker_key = "rule:exec:greet:ev1";
        let plan = EffectPlan::new(vec![
            effect_create(
                "e1",
                &["person"],
                vec![("name", s("Alice")), ("tag", s("alpha"))],
            ),
            effect_create("e2", &["person"], vec![("name", s("Bob"))]),
        ]);
        raw.add_validator(RejectMarkerKey(marker_key));

        let error = store
            .apply_effects_with_marker(&plan, &ctx(), Some((marker_key, b"1")))
            .await
            .unwrap_err();

        assert!(matches!(error, EntityError::Store(_)));
        assert_eq!(all_keys(&raw).await, before);
        for id in ["e1", "e2"] {
            assert!(store.get(id).await.unwrap().is_none());
        }
        let keys = all_keys(&raw).await;
        assert!(keys.iter().all(|key| !key.starts_with(ENTITY_INDEX_PREFIX)));
        assert!(keys.iter().all(|key| !key.starts_with(ATTR_INDEX_PREFIX)));
        assert!(keys.iter().all(|key| !key.starts_with(SCHEMA_INDEX_PREFIX)));
        assert!(outbox_keys(&raw).await.is_empty());
        assert_eq!(pending_counter(&raw).await, None);
        assert!(raw.get_bytes(marker_key).await.unwrap().is_none());
        assert!(feed.events().is_empty());
    }

    #[tokio::test]
    async fn an_effect_failure_rolls_back_the_marker() {
        let (store, _, raw) = person_store().await;
        let before = all_keys(&raw).await;
        let marker_key = "rule:exec:greet:ev1";
        let plan = EffectPlan::new(vec![
            effect_create("e1", &["person"], vec![("name", s("Alice"))]),
            effect_create("e1", &["person"], vec![("name", s("Bob"))]),
        ]);

        let error = store
            .apply_effects_with_marker(&plan, &ctx(), Some((marker_key, b"1")))
            .await
            .unwrap_err();

        assert!(
            matches!(&error, EntityError::AlreadyExists(id) if id == "e1"),
            "unexpected error: {error}"
        );
        assert_eq!(all_keys(&raw).await, before);
        assert!(store.get("e1").await.unwrap().is_none());
        assert!(outbox_keys(&raw).await.is_empty());
        assert_eq!(pending_counter(&raw).await, None);
        assert!(raw.get_bytes(marker_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_empty_plan_with_a_marker_writes_only_the_marker() {
        let (store, _, raw) = person_store().await;
        let before = all_keys(&raw).await;
        let marker_key = "rule:exec:greet:ev1";
        let marker_value = b"1700000000";

        let changes = store
            .apply_effects_with_marker(
                &EffectPlan::default(),
                &ctx(),
                Some((marker_key, marker_value)),
            )
            .await
            .unwrap();

        assert!(changes.is_empty());
        let mut expected = before.clone();
        expected.push(marker_key.to_string());
        expected.sort();
        assert_eq!(all_keys(&raw).await, expected);
        assert_eq!(
            raw.get_bytes(marker_key).await.unwrap().as_deref(),
            Some(&marker_value[..])
        );
        assert!(outbox_keys(&raw).await.is_empty());
        assert_eq!(pending_counter(&raw).await, None);
    }

    #[tokio::test]
    async fn an_empty_plan_without_a_marker_changes_nothing() {
        let (store, _, raw) = person_store().await;
        let before = all_keys(&raw).await;

        let changes = store
            .apply_effects_with_marker(&EffectPlan::default(), &ctx(), None)
            .await
            .unwrap();

        assert!(changes.is_empty());
        assert_eq!(all_keys(&raw).await, before);
    }

    #[tokio::test]
    async fn an_existing_marker_key_is_overwritten() {
        let (store, _, raw) = person_store().await;
        let marker_key = "rule:exec:greet:ev1";
        raw.set_bytes(marker_key, b"old").await.unwrap();

        let changes = store
            .apply_effects_with_marker(&EffectPlan::default(), &ctx(), Some((marker_key, b"new")))
            .await
            .unwrap();

        assert!(changes.is_empty());
        assert_eq!(
            raw.get_bytes(marker_key).await.unwrap().as_deref(),
            Some(&b"new"[..])
        );
        let keys = all_keys(&raw).await;
        assert_eq!(
            keys.iter().filter(|key| key.as_str() == marker_key).count(),
            1
        );
    }

    #[tokio::test]
    async fn apply_effects_writes_no_marker_row() {
        let (store, _, raw) = person_store().await;
        let plan = EffectPlan::new(vec![effect_create(
            "e1",
            &["person"],
            vec![("name", s("Alice"))],
        )]);

        let changes = store.apply_effects(&plan, &ctx()).await.unwrap();

        assert_eq!(changes.len(), 1);
        assert!(store.get("e1").await.unwrap().is_some());
        assert!(
            all_keys(&raw)
                .await
                .iter()
                .all(|key| !key.starts_with("rule:exec:"))
        );
    }
}
