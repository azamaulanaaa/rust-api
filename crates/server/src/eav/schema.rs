//! Versioned EAV schemas, attribute definitions, and inheritance.
//!
//! Keys live in one bounded family.
//! The keys are `schema:head:{id}`, `schema:version:{id}:{version}`, and
//! `schema:child:{parent}:{child}`.
//! A head key holds the latest version as JSON `u64`.
//! A version key holds one [`SchemaDef`](crate::eav::schema::SchemaDef) as JSON.
//! A child key is an empty marker.
//! All scans stop at the `schema;` bound, so a scan reads only this family.
//!
//! A [`SchemaRegistry`](crate::eav::schema::SchemaRegistry) also caches every
//! effective schema that
//! [`SchemaRegistry::effective`](crate::eav::schema::SchemaRegistry::effective)
//! builds. The cache is per registry instance,
//! and a clone of the registry shares that cache.
//! Schema versions are immutable, so a cache entry never changes and no code
//! invalidates it. A new schema version gets a new cache key.
//!
//! The cache has a fixed cap of 1024 entries in a normal build.
//! A test build uses a cap of 2 entries, so a test can cross the boundary
//! quickly.
//! A cache miss at or above the cap removes arbitrary entries until one slot is
//! free.
//! A `HashMap` has no order, so the eviction order is not defined.
//! Eviction costs one reload and never changes the result, because a schema
//! version is immutable.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use oxkv::{
    Direction, GetSet, KeyPrefix, KeyValue, OxKvStore, Store as _, StoreError, Transaction as _,
    TxCas as _,
};
use serde::{Deserialize, Deserializer, Serialize, de};
use tokio::sync::{Mutex, RwLock};

use crate::eav::MAX_PAGE_OFFSET;
use crate::eav::entity::{ATTR_KEY_PREFIX, UNIQUE_KEY_PREFIX};
use crate::eav::error::SchemaError;

/// Key prefix for the whole schema family.
const SCHEMA_PREFIX: &str = "schema:";

/// Key prefix for head pointers.
const HEAD_PREFIX: &str = "schema:head:";

/// Key prefix for immutable schema versions.
const VERSION_PREFIX: &str = "schema:version:";

/// Key prefix for child markers.
const CHILD_PREFIX: &str = "schema:child:";

/// Number of times a publish retries after a head conflict.
const PUBLISH_ATTEMPTS: usize = 4;

/// Maximum number of schemas on one inheritance path.
const MAX_DEPTH: usize = 16;

/// Maximum number of cached effective schemas in a normal build.
#[cfg(not(test))]
const MAX_EFFECTIVE_CACHE: usize = 1024;

/// Maximum number of cached effective schemas in a test build.
#[cfg(test)]
const MAX_EFFECTIVE_CACHE: usize = 2;

/// The storage type of one attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributeType {
    /// A UTF-8 string.
    String,
    /// A signed 64-bit integer.
    Integer,
    /// A 64-bit floating point number.
    Float,
    /// A boolean.
    Boolean,
    /// A Unix timestamp in seconds.
    Timestamp,
    /// An arbitrary JSON value.
    Json,
    /// A reference to another entity.
    EntityRef,
}

/// The definition of one attribute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AttributeDef {
    /// The attribute name.
    pub name: String,
    /// The storage type.
    pub ty: AttributeType,
    /// True when a value is required.
    #[serde(default)]
    pub required: bool,
    /// True when the registry indexes the attribute.
    #[serde(default)]
    pub indexed: bool,
    /// True when values must be unique.
    #[serde(default)]
    pub unique: bool,
    /// The default value for the attribute.
    #[serde(default)]
    pub default: Option<serde_json::Value>,
}

/// A new schema version, before the registry assigns a version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SchemaDraft {
    /// The schema id.
    pub id: String,
    /// The parent schema ids.
    #[serde(default)]
    pub extends: Vec<String>,
    /// The attributes of this schema, keyed by name.
    #[serde(default, deserialize_with = "deserialize_attributes")]
    pub attributes: BTreeMap<String, AttributeDef>,
}

/// A pinned reference to one schema version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SchemaRef {
    /// The schema id.
    pub id: String,
    /// The exact schema version.
    pub version: u64,
}

/// One immutable schema version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SchemaDef {
    /// The schema id.
    pub id: String,
    /// The assigned version. The first version is 1.
    pub version: u64,
    /// The exact parent schema versions.
    pub extends: Vec<SchemaRef>,
    /// The attributes of this schema, keyed by name.
    pub attributes: BTreeMap<String, AttributeDef>,
    /// The publish time as a Unix timestamp in seconds.
    pub created_at: i64,
}

/// A schema with all inherited attributes in one map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EffectiveSchema {
    /// The schema id.
    pub id: String,
    /// The schema version.
    pub version: u64,
    /// The parent ids on the inheritance chain, sorted.
    pub ancestors: Vec<String>,
    /// The flattened attributes, keyed by name.
    pub attributes: BTreeMap<String, AttributeDef>,
}

/// One attribute definition before and after a schema change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AttributeTransition {
    /// The definition in the source version.
    pub from: AttributeDef,
    /// The definition in the target version.
    pub to: AttributeDef,
}

/// The differences between two schema versions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SchemaDiff {
    /// The attributes that the target version adds, keyed by name.
    pub added: BTreeMap<String, AttributeDef>,
    /// The attributes that the target version removes, keyed by name.
    pub removed: BTreeMap<String, AttributeDef>,
    /// The attributes that differ between the versions, keyed by name.
    pub changed: BTreeMap<String, AttributeTransition>,
    /// False when the target version breaks a stored entity.
    pub compatible: bool,
    /// One stable code for each breaking change.
    pub breaking: Vec<String>,
}

/// A registry of versioned EAV schemas on one OxKV store.
#[derive(Clone)]
pub struct SchemaRegistry {
    /// Shared store handle.
    store: Arc<RwLock<OxKvStore>>,
    /// Serializes publishes, so two callers cannot claim one version.
    publish_lock: Arc<Mutex<()>>,
    /// Effective schemas keyed by exact schema id and version.
    ///
    /// An entry is immutable, because a schema version is immutable.
    /// The map holds at most 1024 entries in a normal build.
    cache: Arc<RwLock<HashMap<(String, u64), EffectiveSchema>>>,
}

impl SchemaRegistry {
    /// Creates a registry over `store`.
    pub fn new(store: OxKvStore) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
            publish_lock: Arc::new(Mutex::new(())),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the number of cached effective schemas.
    #[cfg(test)]
    async fn cache_len(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Publishes a schema draft and returns the stored definition.
    ///
    /// The call assigns the next monotonic version.
    /// A mutex serializes concurrent publishes.
    /// The version row and the head row commit in one transaction.
    /// Parent markers update in the same transaction.
    /// The head row uses a compare-and-set against the version that the call
    /// read. A concurrent publish on another registry handle conflicts and
    /// retries with the new head.
    pub async fn publish(&self, draft: SchemaDraft) -> Result<SchemaDef, SchemaError> {
        validate_draft(&draft)?;

        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
        for _attempt in 0..PUBLISH_ATTEMPTS {
            let tx = g.begin_tx().map_err(SchemaError::Store)?;

            let head = read_head(&tx, &draft.id).await?;
            let previous = match head {
                Some(version) => load_version(&tx, &draft.id, version)
                    .await?
                    .ok_or_else(|| {
                        SchemaError::Internal("schema head points to a missing version".to_string())
                    })?,
                None => SchemaDef {
                    id: draft.id.clone(),
                    version: 0,
                    extends: Vec::new(),
                    attributes: BTreeMap::new(),
                    created_at: 0,
                },
            };
            let version = head
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| SchemaError::Internal("schema version overflow".to_string()))?;
            let mut extends = Vec::with_capacity(draft.extends.len());
            for parent in &draft.extends {
                let parent_def = load_latest(&tx, parent)
                    .await?
                    .ok_or_else(|| SchemaError::NotFound("parent schema not found".to_string()))?;
                extends.push(SchemaRef {
                    id: parent_def.id,
                    version: parent_def.version,
                });
            }
            let def = SchemaDef {
                id: draft.id.clone(),
                version,
                extends,
                attributes: draft.attributes.clone(),
                created_at: chrono::Utc::now().timestamp(),
            };

            let effective = flatten(&tx, &def).await?;

            // The index and unique names are name-level facts.
            // The name markers make a later write check every schema that
            // uses the name.
            for (name, attribute) in &effective.attributes {
                if attribute.indexed {
                    tx.set_bytes(&format!("{ATTR_KEY_PREFIX}{name}"), b"")
                        .await
                        .map_err(SchemaError::Store)?;
                }
                if attribute.unique {
                    tx.set_bytes(&format!("{UNIQUE_KEY_PREFIX}{name}"), b"")
                        .await
                        .map_err(SchemaError::Store)?;
                }
            }

            let version_bytes =
                serde_json::to_vec(&def).map_err(|e| SchemaError::Internal(e.to_string()))?;
            let head_key = head_key(&def.id);
            let expected_head = match head {
                Some(version) => Some(
                    serde_json::to_vec(&version)
                        .map_err(|e| SchemaError::Internal(e.to_string()))?,
                ),
                None => None,
            };
            let head_bytes =
                serde_json::to_vec(&version).map_err(|e| SchemaError::Internal(e.to_string()))?;
            tx.set_bytes(&version_key(&def.id, version), &version_bytes)
                .await
                .map_err(SchemaError::Store)?;
            tx.compare_and_set(&head_key, expected_head.as_deref(), &head_bytes)
                .await
                .map_err(SchemaError::Store)?;

            let new_parents: HashSet<&str> = def
                .extends
                .iter()
                .map(|parent| parent.id.as_str())
                .collect();
            for parent in &def.extends {
                tx.set_bytes(&child_key(&parent.id, &def.id), b"")
                    .await
                    .map_err(SchemaError::Store)?;
            }
            for parent in &previous.extends {
                if !new_parents.contains(parent.id.as_str()) {
                    tx.delete(&child_key(&parent.id, &def.id))
                        .await
                        .map_err(SchemaError::Store)?;
                }
            }

            match tx.commit().await {
                Ok(()) => return Ok(def),
                Err(StoreError::TxConflict { key, .. }) if key == head_key => continue,
                Err(error) => return Err(SchemaError::Store(error)),
            }
        }
        Err(SchemaError::Internal(
            "schema publish conflicted with another writer".to_string(),
        ))
    }

    /// Reads one exact schema version.
    ///
    /// The call returns `None` when the version does not exist.
    pub async fn get(&self, id: &str, version: u64) -> Result<Option<SchemaDef>, SchemaError> {
        validate_name("schema id", id)?;
        let g = self.store.read().await;
        load_version(&*g, id, version).await
    }

    /// Reports whether a schema exists.
    ///
    /// The call reads only the head key.
    /// It does not load the schema version.
    /// Use this call when a route needs the existence status and no schema data.
    pub async fn exists(&self, id: &str) -> Result<bool, SchemaError> {
        validate_name("schema id", id)?;
        let g = self.store.read().await;
        Ok(read_head(&*g, id).await?.is_some())
    }

    /// Reads the latest schema version.
    ///
    /// The call returns `None` when the schema does not exist.
    pub async fn latest(&self, id: &str) -> Result<Option<SchemaDef>, SchemaError> {
        validate_name("schema id", id)?;
        let g = self.store.read().await;
        load_latest(&*g, id).await
    }

    /// Lists the latest version of every schema, sorted by id.
    pub async fn list(&self) -> Result<Vec<SchemaDef>, SchemaError> {
        let g = self.store.read().await;
        let heads = scan_prefix(&*g, HEAD_PREFIX).await?;
        let mut out = Vec::with_capacity(heads.len());
        for head in heads {
            let id = head
                .key
                .strip_prefix(HEAD_PREFIX)
                .ok_or_else(|| SchemaError::Internal("schema head key is malformed".to_string()))?;
            let version: u64 = serde_json::from_slice(&head.value)
                .map_err(|e| SchemaError::Internal(e.to_string()))?;
            let def = load_version(&*g, id, version).await?.ok_or_else(|| {
                SchemaError::Internal("schema head points to a missing version".to_string())
            })?;
            out.push(def);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// Lists one page of the latest schema versions.
    ///
    /// The result is sorted by id.
    /// The call skips `offset` schemas.
    /// It then loads at most `limit` versions.
    /// A `limit` of 0 returns an empty list.
    /// An offset above `MAX_PAGE_OFFSET` returns an invalid-input error.
    /// Use `after` for a deeper page.
    pub async fn list_page(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<SchemaDef>, SchemaError> {
        if offset > MAX_PAGE_OFFSET {
            return Err(SchemaError::Invalid(format!(
                "offset must be at most {MAX_PAGE_OFFSET}. Use after to page deeper."
            )));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let g = self.store.read().await;
        let max = offset.saturating_add(limit);
        let mut heads = scan_prefix_bounded(&*g, HEAD_PREFIX, max).await?;
        heads.sort_by(|a, b| a.key.cmp(&b.key));
        let mut out = Vec::with_capacity(limit.min(heads.len()));
        for head in heads.iter().skip(offset).take(limit) {
            let id = head
                .key
                .strip_prefix(HEAD_PREFIX)
                .ok_or_else(|| SchemaError::Internal("schema head key is malformed".to_string()))?;
            let version: u64 = serde_json::from_slice(&head.value)
                .map_err(|e| SchemaError::Internal(e.to_string()))?;
            let def = load_version(&*g, id, version).await?.ok_or_else(|| {
                SchemaError::Internal("schema head points to a missing version".to_string())
            })?;
            out.push(def);
        }
        Ok(out)
    }

    /// Lists one page of the latest schema versions in id order.
    ///
    /// The scan reads only the `schema:head:` family.
    /// It starts after the `after` id when the caller gives a cursor.
    /// The call returns the versions and the cursor for the next page.
    /// The scan reads one extra id as a look-ahead.
    /// The cursor is the last id of the page when the extra id exists.
    /// The cursor is `None` when the scan is exhausted.
    /// A stale or unknown cursor returns the ids after its sort position.
    /// A `limit` of 0 returns an empty list and no cursor.
    pub async fn list_after(
        &self,
        limit: usize,
        after: Option<&str>,
    ) -> Result<(Vec<SchemaDef>, Option<String>), SchemaError> {
        if limit == 0 {
            return Ok((Vec::new(), None));
        }
        let g = self.store.read().await;
        let start = match after {
            Some(cursor) => {
                validate_name("schema id", cursor)?;
                format!("{HEAD_PREFIX}{cursor}\0")
            }
            None => HEAD_PREFIX.to_string(),
        };
        let max = Some(limit.saturating_add(1));
        let cursor = (Some(start), KeyPrefix::new(HEAD_PREFIX).upper_bound());
        let heads = g
            .gets_bytes(max, Direction::Next, cursor)
            .await
            .map_err(SchemaError::Store)?;
        let mut rows = Vec::with_capacity(heads.len());
        for head in heads {
            let Some(id) = head.key.strip_prefix(HEAD_PREFIX) else {
                continue;
            };
            if id.is_empty() || id.contains(':') {
                continue;
            }
            let version: u64 = serde_json::from_slice(&head.value)
                .map_err(|e| SchemaError::Internal(e.to_string()))?;
            rows.push((id.to_string(), version));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next = if has_more {
            rows.last().map(|(id, _)| id.clone())
        } else {
            None
        };
        let mut out = Vec::with_capacity(rows.len());
        for (id, version) in rows {
            let def = load_version(&*g, &id, version).await?.ok_or_else(|| {
                SchemaError::Internal("schema head points to a missing version".to_string())
            })?;
            out.push(def);
        }
        Ok((out, next))
    }

    /// Lists every stored schema version, sorted by id and version.
    ///
    /// The call scans the `schema:version:` family.
    /// A portable export uses the result, because a latest-only list leaves
    /// out the versions that an entity can pin.
    pub async fn versions(&self) -> Result<Vec<SchemaDef>, SchemaError> {
        let g = self.store.read().await;
        let rows = scan_prefix(&*g, VERSION_PREFIX).await?;
        let mut defs = Vec::with_capacity(rows.len());
        for row in rows {
            let def: SchemaDef = serde_json::from_slice(&row.value)
                .map_err(|e| SchemaError::Internal(e.to_string()))?;
            defs.push(def);
        }
        defs.sort_by(|a, b| (a.id.as_str(), a.version).cmp(&(b.id.as_str(), b.version)));
        Ok(defs)
    }

    /// Imports exact schema versions into an empty store.
    ///
    /// The call validates every version before it writes any key.
    /// It writes the version rows, the head rows, the child markers, and the
    /// name markers in one transaction.
    /// It returns the keys that it wrote, so a failed import can remove them.
    /// The call rejects a schema id that the store already holds.
    pub(crate) async fn import_versions(
        &self,
        defs: &[SchemaDef],
    ) -> Result<Vec<String>, SchemaError> {
        validate_import_versions(defs)?;

        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
        for def in defs {
            if read_head(&*g, &def.id).await?.is_some() {
                return Err(SchemaError::Invalid(format!(
                    "schema {} already exists in the target prefix",
                    def.id
                )));
            }
        }

        let tx = g.begin_tx().map_err(SchemaError::Store)?;
        let mut keys = Vec::new();
        for def in defs {
            let key = version_key(&def.id, def.version);
            let bytes =
                serde_json::to_vec(def).map_err(|e| SchemaError::Internal(e.to_string()))?;
            tx.set_bytes(&key, &bytes)
                .await
                .map_err(SchemaError::Store)?;
            keys.push(key);
            for parent in &def.extends {
                let key = child_key(&parent.id, &def.id);
                tx.set_bytes(&key, b"").await.map_err(SchemaError::Store)?;
                keys.push(key);
            }
        }

        let mut heads: BTreeMap<String, u64> = BTreeMap::new();
        for def in defs {
            let effective = flatten(&tx, def).await?;
            for (name, attribute) in &effective.attributes {
                if attribute.indexed {
                    let key = format!("{ATTR_KEY_PREFIX}{name}");
                    tx.set_bytes(&key, b"").await.map_err(SchemaError::Store)?;
                    keys.push(key);
                }
                if attribute.unique {
                    let key = format!("{UNIQUE_KEY_PREFIX}{name}");
                    tx.set_bytes(&key, b"").await.map_err(SchemaError::Store)?;
                    keys.push(key);
                }
            }
            heads
                .entry(def.id.clone())
                .and_modify(|version| *version = (*version).max(def.version))
                .or_insert(def.version);
        }
        for (id, version) in heads {
            let key = head_key(&id);
            let bytes =
                serde_json::to_vec(&version).map_err(|e| SchemaError::Internal(e.to_string()))?;
            tx.set_bytes(&key, &bytes)
                .await
                .map_err(SchemaError::Store)?;
            keys.push(key);
        }
        tx.commit().await.map_err(SchemaError::Store)?;
        self.cache.write().await.clear();
        Ok(keys)
    }

    /// Removes the keys that [`import_versions`](Self::import_versions) wrote.
    ///
    /// The call runs after a later import step failed.
    /// It is safe only when the target prefix was empty before the import.
    pub(crate) async fn remove_import_keys(&self, keys: &[String]) -> Result<(), SchemaError> {
        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(SchemaError::Store)?;
        for key in keys {
            tx.delete(key).await.map_err(SchemaError::Store)?;
        }
        tx.commit().await.map_err(SchemaError::Store)?;
        self.cache.write().await.clear();
        Ok(())
    }

    /// Reads one schema version with all inherited attributes flattened.
    ///
    /// The call returns `None` when the version does not exist.
    /// A child attribute overrides an inherited attribute with the same type.
    /// A different type is a type conflict.
    ///
    /// The result is cached under the exact schema id and version.
    /// A cache hit returns a clone of the stored result without a store read.
    /// A cache entry is immutable, because a schema version is immutable.
    /// The cache belongs to this registry instance, and a clone of the
    /// registry shares the same cache.
    /// The cache holds at most 1024 entries in a normal build.
    /// A miss at or above the cap removes arbitrary entries before it inserts
    /// the new entry.
    /// Eviction costs one store reload and never changes the result.
    pub async fn effective(
        &self,
        id: &str,
        version: u64,
    ) -> Result<Option<EffectiveSchema>, SchemaError> {
        validate_name("schema id", id)?;
        let key = (id.to_string(), version);
        let cached = self.cache.read().await.get(&key).cloned();
        if let Some(cached) = cached {
            return Ok(Some(cached));
        }

        let g = self.store.read().await;
        let Some(root) = load_version(&*g, id, version).await? else {
            return Ok(None);
        };
        let effective = flatten(&*g, &root).await?;
        drop(g);

        let mut cache = self.cache.write().await;
        if cache.len() >= MAX_EFFECTIVE_CACHE {
            evict_for_one_slot(&mut cache);
        }
        cache.insert(key, effective.clone());
        Ok(Some(effective))
    }

    /// Compares two effective schema versions.
    ///
    /// The call returns `None` when either version does not exist.
    /// An added required attribute without a default breaks the target.
    /// A removed attribute, a type change, a new required flag, and a new
    /// unique flag break the target.
    /// A default change, an index change, and a removed required flag are
    /// additive.
    pub async fn diff(
        &self,
        id: &str,
        from: u64,
        to: u64,
    ) -> Result<Option<SchemaDiff>, SchemaError> {
        validate_name("schema id", id)?;
        let Some(source) = self.effective(id, from).await? else {
            return Ok(None);
        };
        let Some(target) = self.effective(id, to).await? else {
            return Ok(None);
        };

        let mut added = BTreeMap::new();
        let mut removed = BTreeMap::new();
        let mut changed = BTreeMap::new();
        for (name, def) in &target.attributes {
            match source.attributes.get(name) {
                None => {
                    added.insert(name.clone(), def.clone());
                }
                Some(old) if old != def => {
                    changed.insert(
                        name.clone(),
                        AttributeTransition {
                            from: old.clone(),
                            to: def.clone(),
                        },
                    );
                }
                Some(_) => {}
            }
        }
        for (name, def) in &source.attributes {
            if !target.attributes.contains_key(name) {
                removed.insert(name.clone(), def.clone());
            }
        }

        let mut breaking = Vec::new();
        for name in removed.keys() {
            breaking.push(format!("attribute-removed:{name}"));
        }
        for (name, def) in &added {
            if def.required && def.default.is_none() {
                breaking.push(format!("required-added:{name}"));
            }
        }
        for (name, transition) in &changed {
            if transition.from.ty != transition.to.ty {
                breaking.push(format!("type-changed:{name}"));
            }
            if !transition.from.required
                && transition.to.required
                && transition.to.default.is_none()
            {
                breaking.push(format!("required-added:{name}"));
            }
            if !transition.from.unique && transition.to.unique {
                breaking.push(format!("unique-added:{name}"));
            }
        }

        Ok(Some(SchemaDiff {
            added,
            removed,
            changed,
            compatible: breaking.is_empty(),
            breaking,
        }))
    }

    /// Lists the schemas whose latest version extends `id`.
    ///
    /// The list is sorted and has no duplicates.
    pub async fn children(&self, id: &str) -> Result<Vec<String>, SchemaError> {
        validate_name("schema id", id)?;
        let g = self.store.read().await;
        let prefix = format!("{CHILD_PREFIX}{id}:");
        let markers = scan_keys_prefix(&*g, &prefix).await?;
        let mut out: Vec<String> = markers
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(str::to_string))
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
    }
}

/// Removes arbitrary entries until the cache has one free slot.
///
/// A `HashMap` has no order, so the removal order is not defined.
/// Eviction costs one reload on the next `effective` call for each removed key.
fn evict_for_one_slot(cache: &mut HashMap<(String, u64), EffectiveSchema>) {
    while cache.len() >= MAX_EFFECTIVE_CACHE {
        let Some(key) = cache.keys().next().cloned() else {
            break;
        };
        cache.remove(&key);
    }
}

/// Deserializes an attribute map and rejects duplicate names.
fn deserialize_attributes<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, AttributeDef>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AttributeVisitor;

    impl<'de> de::Visitor<'de> for AttributeVisitor {
        type Value = BTreeMap<String, AttributeDef>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a map of attribute names to definitions")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            let mut out = BTreeMap::new();
            while let Some((name, def)) = map.next_entry::<String, AttributeDef>()? {
                if out.contains_key(&name) {
                    return Err(de::Error::custom("duplicate attribute name"));
                }
                out.insert(name, def);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_map(AttributeVisitor)
}

/// Walks the inheritance graph and merges every attribute.
///
/// The walk detects cycles and depth overflow.
/// The walk loads each exact parent version from its [`SchemaRef`].
/// The walk merges the deepest parent first, so a child wins on a type match.
async fn flatten<S>(store: &S, root: &SchemaDef) -> Result<EffectiveSchema, SchemaError>
where
    S: GetSet + ?Sized,
{
    enum Frame {
        Enter(String, u64),
        Exit(String, u64),
    }

    let mut stack = vec![Frame::Enter(root.id.clone(), root.version)];
    let mut on_path: Vec<String> = Vec::new();
    let mut done: HashSet<(String, u64)> = HashSet::new();
    let mut defs: HashMap<(String, u64), SchemaDef> = HashMap::new();
    let mut order: Vec<(String, u64)> = Vec::new();
    defs.insert((root.id.clone(), root.version), root.clone());

    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(id, version) => {
                if on_path.contains(&id) {
                    return Err(SchemaError::Cycle);
                }
                let key = (id.clone(), version);
                if done.contains(&key) {
                    continue;
                }
                if on_path.len() >= MAX_DEPTH {
                    return Err(SchemaError::Invalid(
                        "schema inheritance depth exceeds 16".to_string(),
                    ));
                }
                let def = match defs.get(&key) {
                    Some(def) => def.clone(),
                    None => {
                        let Some(def) = load_version(store, &id, version).await? else {
                            return Err(SchemaError::Internal(
                                "parent schema version is missing".to_string(),
                            ));
                        };
                        defs.insert(key, def.clone());
                        def
                    }
                };
                on_path.push(id.clone());
                stack.push(Frame::Exit(id, version));
                for parent in def.extends.iter().rev() {
                    stack.push(Frame::Enter(parent.id.clone(), parent.version));
                }
            }
            Frame::Exit(id, version) => {
                on_path.pop();
                done.insert((id.clone(), version));
                order.push((id, version));
            }
        }
    }

    let mut attributes: BTreeMap<String, AttributeDef> = BTreeMap::new();
    for key in &order {
        let Some(def) = defs.get(key) else {
            continue;
        };
        for (name, attr) in &def.attributes {
            match attributes.get(name) {
                Some(existing) if existing.ty != attr.ty => {
                    return Err(SchemaError::TypeConflict(name.clone()));
                }
                _ => {
                    attributes.insert(name.clone(), attr.clone());
                }
            }
        }
    }

    let mut ancestors: Vec<String> = order
        .into_iter()
        .map(|(id, _)| id)
        .filter(|id| id != &root.id)
        .collect();
    ancestors.sort();
    ancestors.dedup();

    Ok(EffectiveSchema {
        id: root.id.clone(),
        version: root.version,
        ancestors,
        attributes,
    })
}

/// Reads the latest version of a schema.
async fn load_latest<S>(store: &S, id: &str) -> Result<Option<SchemaDef>, SchemaError>
where
    S: GetSet + ?Sized,
{
    let Some(version) = read_head(store, id).await? else {
        return Ok(None);
    };
    load_version(store, id, version)
        .await?
        .map(Some)
        .ok_or_else(|| SchemaError::Internal("schema head points to a missing version".to_string()))
}

/// Reads one exact schema version.
async fn load_version<S>(
    store: &S,
    id: &str,
    version: u64,
) -> Result<Option<SchemaDef>, SchemaError>
where
    S: GetSet + ?Sized,
{
    let Some(bytes) = store
        .get_bytes(&version_key(id, version))
        .await
        .map_err(SchemaError::Store)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| SchemaError::Internal(e.to_string()))
}

/// Reads the latest version number of a schema.
async fn read_head<S>(store: &S, id: &str) -> Result<Option<u64>, SchemaError>
where
    S: GetSet + ?Sized,
{
    let Some(bytes) = store
        .get_bytes(&head_key(id))
        .await
        .map_err(SchemaError::Store)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| SchemaError::Internal(e.to_string()))
}

/// Scans a key range that ends at the `prefix:` family bound.
async fn scan_prefix<S>(store: &S, prefix: &str) -> Result<Vec<KeyValue>, SchemaError>
where
    S: GetSet + ?Sized,
{
    debug_assert!(prefix.starts_with(SCHEMA_PREFIX));
    let cursor = (
        Some(prefix.to_string()),
        KeyPrefix::new(prefix).upper_bound(),
    );
    store
        .gets_bytes(None, Direction::Next, cursor)
        .await
        .map_err(SchemaError::Store)
}

/// Scans a key range that ends at the `prefix:` family bound and reads keys
/// only.
async fn scan_keys_prefix<S>(store: &S, prefix: &str) -> Result<Vec<String>, SchemaError>
where
    S: GetSet + ?Sized + Sync,
{
    debug_assert!(prefix.starts_with(SCHEMA_PREFIX));
    let cursor = (
        Some(prefix.to_string()),
        KeyPrefix::new(prefix).upper_bound(),
    );
    store
        .gets_keys(None, Direction::Next, cursor)
        .await
        .map_err(SchemaError::Store)
}

/// Scans at most `limit` rows of a key range that ends at the `prefix:` bound.
async fn scan_prefix_bounded<S>(
    store: &S,
    prefix: &str,
    limit: usize,
) -> Result<Vec<KeyValue>, SchemaError>
where
    S: GetSet + ?Sized,
{
    debug_assert!(prefix.starts_with(SCHEMA_PREFIX));
    let max = Some(limit);
    let cursor = (
        Some(prefix.to_string()),
        KeyPrefix::new(prefix).upper_bound(),
    );
    store
        .gets_bytes(max, Direction::Next, cursor)
        .await
        .map_err(SchemaError::Store)
}

/// The key that holds the latest version of `id`.
fn head_key(id: &str) -> String {
    format!("{HEAD_PREFIX}{id}")
}

/// The key that holds one schema version.
fn version_key(id: &str, version: u64) -> String {
    format!("{VERSION_PREFIX}{id}:{version}")
}

/// The marker key for one parent and child pair.
fn child_key(parent: &str, child: &str) -> String {
    format!("{CHILD_PREFIX}{parent}:{child}")
}

/// Checks a schema draft before the registry stores it.
fn validate_draft(draft: &SchemaDraft) -> Result<(), SchemaError> {
    validate_name("schema id", &draft.id)?;
    let mut seen: HashSet<&str> = HashSet::new();
    for parent in &draft.extends {
        validate_name("parent schema id", parent)?;
        if !seen.insert(parent.as_str()) {
            return Err(SchemaError::Invalid(
                "duplicate parent schema id".to_string(),
            ));
        }
        if parent == &draft.id {
            return Err(SchemaError::Cycle);
        }
    }
    for (name, def) in &draft.attributes {
        validate_name("attribute name", name)?;
        validate_name("attribute name", &def.name)?;
        if name != &def.name {
            return Err(SchemaError::Invalid(
                "attribute name does not match its key".to_string(),
            ));
        }
        validate_default(def)?;
    }
    Ok(())
}

/// Checks a set of exact schema versions before an import writes them.
///
/// Each id must have the versions `1..=max` and no gaps.
/// Each parent reference must name a version in the same set.
/// Each draft must pass the publish check.
fn validate_import_versions(defs: &[SchemaDef]) -> Result<(), SchemaError> {
    let mut versions: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
    for def in defs {
        if def.version == 0 {
            return Err(SchemaError::Invalid(format!(
                "schema {} has version 0",
                def.id
            )));
        }
        let draft = SchemaDraft {
            id: def.id.clone(),
            extends: def.extends.iter().map(|parent| parent.id.clone()).collect(),
            attributes: def.attributes.clone(),
        };
        validate_draft(&draft)?;
        if !versions.entry(&def.id).or_default().insert(def.version) {
            return Err(SchemaError::Invalid(format!(
                "schema {} has two records for version {}",
                def.id, def.version
            )));
        }
    }

    for (id, found) in &versions {
        let max = found.iter().next_back().copied().unwrap_or(0);
        for version in 1..=max {
            if !found.contains(&version) {
                return Err(SchemaError::Invalid(format!(
                    "schema {id} is missing version {version}"
                )));
            }
        }
    }

    for def in defs {
        for parent in &def.extends {
            let found = versions
                .get(parent.id.as_str())
                .is_some_and(|versions| versions.contains(&parent.version));
            if !found {
                return Err(SchemaError::Invalid(format!(
                    "schema {} pins a parent version that is not in the import: {}@{}",
                    def.id, parent.id, parent.version
                )));
            }
        }
    }
    Ok(())
}

/// Checks one attribute default before the registry stores it.
///
/// The default must match the declared type.
/// A float default must be finite.
/// An `EntityRef` default must be a valid entity id.
fn validate_default(def: &AttributeDef) -> Result<(), SchemaError> {
    let Some(default) = &def.default else {
        return Ok(());
    };
    if !default_matches_type(default, def.ty) {
        return Err(SchemaError::Invalid(format!(
            "attribute default type mismatch: {}",
            def.name
        )));
    }
    if def.ty == AttributeType::EntityRef
        && let Some(target) = default.as_str()
    {
        validate_name("entity ref default", target)?;
    }
    Ok(())
}

/// True when `value` has the declared type.
fn default_matches_type(value: &serde_json::Value, ty: AttributeType) -> bool {
    match ty {
        AttributeType::String | AttributeType::EntityRef => value.is_string(),
        AttributeType::Integer | AttributeType::Timestamp => value.as_i64().is_some(),
        AttributeType::Float => value.as_f64().is_some_and(f64::is_finite),
        AttributeType::Boolean => value.is_boolean(),
        AttributeType::Json => true,
    }
}

/// Checks an id or a name against the storage key rules.
///
/// The value must be 1 to 128 bytes.
/// It may contain only lowercase ASCII letters, digits, `_`, and `-`.
/// These rules reject `:` and `/`, so a value cannot inject a key.
/// The shared core crate implements the rule.
fn validate_name(kind: &str, value: &str) -> Result<(), SchemaError> {
    crate::core::eav::validate_name(kind, value)
        .map_err(|error| SchemaError::Invalid(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{build_test_store, test_prefix};

    async fn new_registry() -> SchemaRegistry {
        SchemaRegistry::new(build_test_store(&test_prefix("eav-schema")).await)
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

    fn draft(id: &str, extends: &[&str], attrs: Vec<AttributeDef>) -> SchemaDraft {
        SchemaDraft {
            id: id.to_string(),
            extends: extends.iter().map(|s| s.to_string()).collect(),
            attributes: attrs.into_iter().map(|a| (a.name.clone(), a)).collect(),
        }
    }

    #[tokio::test]
    async fn concurrent_publishes_get_distinct_versions() {
        let raw = build_test_store(&test_prefix("eav-schema-race")).await;
        let first = SchemaRegistry::new(raw.clone());
        let second = SchemaRegistry::new(raw.clone());
        let first_draft = draft("user", &[], vec![attr("email", AttributeType::String)]);
        let second_draft = first_draft.clone();

        let (first_def, second_def) =
            tokio::join!(first.publish(first_draft), second.publish(second_draft));
        let first_def = first_def.unwrap();
        let second_def = second_def.unwrap();

        let mut versions = [first_def.version, second_def.version];
        versions.sort_unstable();
        assert_eq!(versions, [1, 2], "each publish must get its own version");
        let head = read_head(&raw, "user").await.unwrap();
        assert_eq!(head, Some(2), "the head must point at the last version");
    }

    #[tokio::test]
    async fn publish_stores_exact_and_latest_versions() {
        let reg = new_registry().await;
        let def = reg
            .publish(draft(
                "user",
                &[],
                vec![attr("email", AttributeType::String)],
            ))
            .await
            .unwrap();

        assert_eq!(def.version, 1);
        assert_eq!(reg.get("user", 1).await.unwrap(), Some(def.clone()));
        assert_eq!(reg.latest("user").await.unwrap(), Some(def));
        assert_eq!(reg.get("user", 2).await.unwrap(), None);
    }

    #[tokio::test]
    async fn publish_rejects_a_default_with_the_wrong_type_and_stores_nothing() {
        let reg = new_registry().await;

        let result = reg
            .publish(draft(
                "metric",
                &[],
                vec![full_attr(
                    "count",
                    AttributeType::Integer,
                    false,
                    false,
                    false,
                    Some(serde_json::json!("x")),
                )],
            ))
            .await;

        assert!(
            matches!(&result, Err(SchemaError::Invalid(message)) if message.contains("count")),
            "the error must name the attribute"
        );
        assert!(!reg.exists("metric").await.unwrap());
        assert_eq!(reg.latest("metric").await.unwrap(), None);
    }

    #[tokio::test]
    async fn publish_accepts_a_default_with_the_declared_type() {
        let reg = new_registry().await;

        let def = reg
            .publish(draft(
                "metric",
                &[],
                vec![full_attr(
                    "count",
                    AttributeType::Integer,
                    false,
                    false,
                    false,
                    Some(serde_json::json!(3)),
                )],
            ))
            .await
            .unwrap();

        assert_eq!(def.attributes["count"].default, Some(serde_json::json!(3)));
    }

    #[tokio::test]
    async fn version_numbers_increase() {
        let reg = new_registry().await;
        let first = reg.publish(draft("user", &[], vec![])).await.unwrap();
        let second = reg.publish(draft("user", &[], vec![])).await.unwrap();

        assert_eq!(second.version, first.version + 1);
    }

    #[tokio::test]
    async fn inheritance_flattens_parent_attributes() {
        let reg = new_registry().await;
        reg.publish(draft(
            "base",
            &[],
            vec![
                attr("email", AttributeType::String),
                attr("age", AttributeType::Integer),
            ],
        ))
        .await
        .unwrap();
        reg.publish(draft(
            "user",
            &["base"],
            vec![attr("name", AttributeType::String)],
        ))
        .await
        .unwrap();

        let effective = reg.effective("user", 1).await.unwrap().unwrap();
        assert_eq!(effective.ancestors, vec!["base".to_string()]);
        assert_eq!(effective.attributes.len(), 3);
        assert!(effective.attributes.contains_key("email"));
        assert!(effective.attributes.contains_key("age"));
        assert!(effective.attributes.contains_key("name"));
    }

    #[tokio::test]
    async fn child_override_with_same_type_wins() {
        let reg = new_registry().await;
        reg.publish(draft(
            "base",
            &[],
            vec![AttributeDef {
                required: false,
                ..attr("email", AttributeType::String)
            }],
        ))
        .await
        .unwrap();
        reg.publish(draft(
            "user",
            &["base"],
            vec![AttributeDef {
                required: true,
                ..attr("email", AttributeType::String)
            }],
        ))
        .await
        .unwrap();

        let effective = reg.effective("user", 1).await.unwrap().unwrap();
        assert!(effective.attributes["email"].required);
    }

    #[tokio::test]
    async fn child_keeps_the_pinned_parent_version() {
        let reg = new_registry().await;
        reg.publish(draft("base", &[], vec![attr("a", AttributeType::String)]))
            .await
            .unwrap();
        reg.publish(draft("child", &["base"], vec![]))
            .await
            .unwrap();
        reg.publish(draft("base", &[], vec![attr("b", AttributeType::String)]))
            .await
            .unwrap();

        let child = reg.latest("child").await.unwrap().unwrap();
        assert_eq!(
            child.extends,
            vec![SchemaRef {
                id: "base".to_string(),
                version: 1,
            }]
        );

        let effective = reg.effective("child", 1).await.unwrap().unwrap();
        assert!(effective.attributes.contains_key("a"));
        assert!(!effective.attributes.contains_key("b"));
    }

    #[tokio::test]
    async fn child_override_with_different_type_fails() {
        let reg = new_registry().await;
        reg.publish(draft(
            "base",
            &[],
            vec![attr("email", AttributeType::String)],
        ))
        .await
        .unwrap();

        let result = reg
            .publish(draft(
                "user",
                &["base"],
                vec![attr("email", AttributeType::Integer)],
            ))
            .await;

        assert!(matches!(result, Err(SchemaError::TypeConflict(_))));
    }

    #[tokio::test]
    async fn unknown_parent_fails() {
        let reg = new_registry().await;

        let result = reg.publish(draft("user", &["ghost"], vec![])).await;

        assert!(matches!(result, Err(SchemaError::NotFound(_))));
    }

    #[tokio::test]
    async fn duplicate_parent_ids_fail() {
        let reg = new_registry().await;
        reg.publish(draft("base", &[], vec![])).await.unwrap();

        let result = reg.publish(draft("child", &["base", "base"], vec![])).await;

        assert!(matches!(result, Err(SchemaError::Invalid(_))));
    }

    #[tokio::test]
    async fn cycle_fails() {
        let reg = new_registry().await;
        reg.publish(draft("a", &[], vec![])).await.unwrap();
        reg.publish(draft("b", &["a"], vec![])).await.unwrap();

        let result = reg.publish(draft("a", &["b"], vec![])).await;

        assert!(matches!(result, Err(SchemaError::Cycle)));
    }

    #[tokio::test]
    async fn parent_type_conflict_fails_without_an_override() {
        let reg = new_registry().await;
        reg.publish(draft(
            "left",
            &[],
            vec![attr("email", AttributeType::String)],
        ))
        .await
        .unwrap();
        reg.publish(draft(
            "right",
            &[],
            vec![attr("email", AttributeType::Integer)],
        ))
        .await
        .unwrap();

        let result = reg.publish(draft("user", &["left", "right"], vec![])).await;

        assert!(matches!(result, Err(SchemaError::TypeConflict(_))));
    }

    #[tokio::test]
    async fn children_tracks_removed_parents() {
        let reg = new_registry().await;
        reg.publish(draft("base", &[], vec![])).await.unwrap();
        reg.publish(draft("user", &["base"], vec![])).await.unwrap();
        assert_eq!(
            reg.children("base").await.unwrap(),
            vec!["user".to_string()]
        );

        reg.publish(draft("user", &[], vec![])).await.unwrap();

        assert!(reg.children("base").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_returns_one_latest_definition_per_schema() {
        let reg = new_registry().await;
        reg.publish(draft("a", &[], vec![])).await.unwrap();
        reg.publish(draft("b", &[], vec![])).await.unwrap();
        reg.publish(draft("a", &[], vec![])).await.unwrap();

        let list = reg.list().await.unwrap();
        let ids: Vec<&str> = list.iter().map(|def| def.id.as_str()).collect();

        assert_eq!(ids, vec!["a", "b"]);
        assert_eq!(list[0].version, 2);
        assert_eq!(list[1].version, 1);
    }

    #[tokio::test]
    async fn list_page_returns_the_first_page() {
        let reg = new_registry().await;
        for id in ["a", "b", "c", "d"] {
            reg.publish(draft(id, &[], vec![])).await.unwrap();
        }

        let page = reg.list_page(2, 0).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|def| def.id.as_str()).collect();

        assert_eq!(ids, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn list_page_returns_the_second_page() {
        let reg = new_registry().await;
        for id in ["a", "b", "c", "d"] {
            reg.publish(draft(id, &[], vec![])).await.unwrap();
        }

        let page = reg.list_page(2, 2).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|def| def.id.as_str()).collect();

        assert_eq!(ids, vec!["c", "d"]);
    }

    #[tokio::test]
    async fn list_page_offset_past_the_end_is_empty() {
        let reg = new_registry().await;
        reg.publish(draft("a", &[], vec![])).await.unwrap();

        let page = reg.list_page(2, 9).await.unwrap();

        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_page_rejects_an_offset_above_the_maximum() {
        let reg = new_registry().await;
        reg.publish(draft("a", &[], vec![])).await.unwrap();

        let result = reg.list_page(2, MAX_PAGE_OFFSET + 1).await;

        assert!(matches!(result, Err(SchemaError::Invalid(_))));
    }

    #[tokio::test]
    async fn list_page_with_limit_zero_is_empty() {
        let reg = new_registry().await;
        reg.publish(draft("a", &[], vec![])).await.unwrap();

        let page = reg.list_page(0, 0).await.unwrap();

        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn list_page_keeps_the_id_order_across_pages() {
        let reg = new_registry().await;
        for id in ["a", "b", "c", "d", "e"] {
            reg.publish(draft(id, &[], vec![])).await.unwrap();
        }

        let mut paged = reg.list_page(2, 0).await.unwrap();
        paged.extend(reg.list_page(2, 2).await.unwrap());
        paged.extend(reg.list_page(2, 4).await.unwrap());

        assert_eq!(paged, reg.list().await.unwrap());
    }

    #[tokio::test]
    async fn list_after_pages_through_every_schema_once() {
        let reg = new_registry().await;
        for id in ["a", "b", "c", "d", "e"] {
            reg.publish(draft(id, &[], vec![])).await.unwrap();
        }

        let mut ids = Vec::new();
        let mut after: Option<String> = None;
        let mut pages = 0;
        loop {
            let (page, next) = reg.list_after(2, after.as_deref()).await.unwrap();
            ids.extend(page.into_iter().map(|def| def.id));
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
        let reg = new_registry().await;
        for id in ["a", "b", "c", "d"] {
            reg.publish(draft(id, &[], vec![])).await.unwrap();
        }

        let (first, next) = reg.list_after(2, None).await.unwrap();
        let first_ids: Vec<&str> = first.iter().map(|def| def.id.as_str()).collect();
        assert_eq!(first_ids, vec!["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));

        let (second, next) = reg.list_after(2, next.as_deref()).await.unwrap();
        let second_ids: Vec<&str> = second.iter().map(|def| def.id.as_str()).collect();
        assert_eq!(second_ids, vec!["c", "d"]);
        assert_eq!(next, None);

        let mut all: Vec<String> = first.into_iter().map(|def| def.id).collect();
        all.extend(second.into_iter().map(|def| def.id));
        assert_eq!(all, vec!["a", "b", "c", "d"]);
    }

    #[tokio::test]
    async fn list_after_pages_five_schemas_with_a_short_final_page() {
        let reg = new_registry().await;
        for id in ["a", "b", "c", "d", "e"] {
            reg.publish(draft(id, &[], vec![])).await.unwrap();
        }

        let (first, next) = reg.list_after(2, None).await.unwrap();
        let first_ids: Vec<&str> = first.iter().map(|def| def.id.as_str()).collect();
        assert_eq!(first_ids, vec!["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));

        let (second, next) = reg.list_after(2, next.as_deref()).await.unwrap();
        let second_ids: Vec<&str> = second.iter().map(|def| def.id.as_str()).collect();
        assert_eq!(second_ids, vec!["c", "d"]);
        assert_eq!(next.as_deref(), Some("d"));

        let (third, next) = reg.list_after(2, next.as_deref()).await.unwrap();
        let third_ids: Vec<&str> = third.iter().map(|def| def.id.as_str()).collect();
        assert_eq!(third_ids, vec!["e"]);
        assert_eq!(next, None);

        let mut all: Vec<String> = first.into_iter().map(|def| def.id).collect();
        all.extend(second.into_iter().map(|def| def.id));
        all.extend(third.into_iter().map(|def| def.id));
        assert_eq!(all, vec!["a", "b", "c", "d", "e"]);
    }

    #[tokio::test]
    async fn list_after_pages_three_schemas_with_a_short_final_page() {
        let reg = new_registry().await;
        for id in ["a", "b", "c"] {
            reg.publish(draft(id, &[], vec![])).await.unwrap();
        }

        let (first, next) = reg.list_after(2, None).await.unwrap();
        let first_ids: Vec<&str> = first.iter().map(|def| def.id.as_str()).collect();
        assert_eq!(first_ids, vec!["a", "b"]);
        assert_eq!(next.as_deref(), Some("b"));

        let (second, next) = reg.list_after(2, next.as_deref()).await.unwrap();
        let second_ids: Vec<&str> = second.iter().map(|def| def.id.as_str()).collect();
        assert_eq!(second_ids, vec!["c"]);
        assert_eq!(next, None);

        let mut all: Vec<String> = first.into_iter().map(|def| def.id).collect();
        all.extend(second.into_iter().map(|def| def.id));
        assert_eq!(all, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn list_after_empty_registry_returns_no_cursor() {
        let reg = new_registry().await;

        let (page, next) = reg.list_after(2, None).await.unwrap();

        assert!(page.is_empty());
        assert_eq!(next, None);
    }

    #[tokio::test]
    async fn list_after_skips_a_stale_cursor_without_repeating_it() {
        let reg = new_registry().await;
        for id in ["a", "c", "d"] {
            reg.publish(draft(id, &[], vec![])).await.unwrap();
        }

        let (page, next) = reg.list_after(10, Some("b")).await.unwrap();
        let ids: Vec<&str> = page.iter().map(|def| def.id.as_str()).collect();

        assert_eq!(ids, vec!["c", "d"]);
        assert_eq!(next, None);
    }

    #[tokio::test]
    async fn invalid_schema_ids_fail() {
        let reg = new_registry().await;
        let mut ids = vec![
            "".to_string(),
            "Upper".to_string(),
            "a:b".to_string(),
            "a/b".to_string(),
            "a b".to_string(),
        ];
        ids.push("a".repeat(crate::core::eav::MAX_NAME_BYTES + 1));

        for id in ids {
            let result = reg.publish(draft(&id, &[], vec![])).await;
            assert!(
                matches!(result, Err(SchemaError::Invalid(_))),
                "schema id {id:?} must fail"
            );
        }
    }

    #[tokio::test]
    async fn invalid_attribute_names_fail() {
        let reg = new_registry().await;
        let mut names = vec![
            "".to_string(),
            "Upper".to_string(),
            "a:b".to_string(),
            "a/b".to_string(),
            "a b".to_string(),
        ];
        names.push("a".repeat(crate::core::eav::MAX_NAME_BYTES + 1));

        for name in names {
            let result = reg
                .publish(draft("user", &[], vec![attr(&name, AttributeType::String)]))
                .await;
            assert!(
                matches!(result, Err(SchemaError::Invalid(_))),
                "attribute name {name:?} must fail"
            );
        }
    }

    #[tokio::test]
    async fn attribute_name_mismatch_fails() {
        let reg = new_registry().await;
        let mut bad = attr("email", AttributeType::String);
        bad.name = "mail".to_string();
        let input = SchemaDraft {
            id: "user".to_string(),
            extends: Vec::new(),
            attributes: BTreeMap::from([("email".to_string(), bad)]),
        };

        let result = reg.publish(input).await;

        assert!(matches!(result, Err(SchemaError::Invalid(_))));
    }

    #[tokio::test]
    async fn colon_in_a_key_is_rejected() {
        let reg = new_registry().await;

        assert!(matches!(
            reg.publish(draft("a:b", &[], vec![])).await,
            Err(SchemaError::Invalid(_))
        ));
        assert!(matches!(
            reg.get("a:b", 1).await,
            Err(SchemaError::Invalid(_))
        ));
        assert!(matches!(
            reg.effective("a:b", 1).await,
            Err(SchemaError::Invalid(_))
        ));
        assert!(matches!(
            reg.children("a:b").await,
            Err(SchemaError::Invalid(_))
        ));

        let g = reg.store.read().await;
        let cursor = (
            Some(SCHEMA_PREFIX.to_string()),
            KeyPrefix::new(SCHEMA_PREFIX).upper_bound(),
        );
        let keys = g.gets_bytes(None, Direction::Next, cursor).await.unwrap();
        assert!(keys.is_empty(), "a rejected publish must write no key");
    }

    #[test]
    fn duplicate_json_attribute_names_are_rejected() {
        let json = r#"{
            "id": "user",
            "extends": [],
            "attributes": {
                "email": {"name": "email", "ty": "string"},
                "email": {"name": "email", "ty": "string"}
            }
        }"#;

        let result: Result<SchemaDraft, _> = serde_json::from_str(json);

        assert!(result.is_err(), "duplicate JSON attribute names must fail");
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

    async fn diff_for(v1: Vec<AttributeDef>, v2: Vec<AttributeDef>) -> SchemaDiff {
        let reg = new_registry().await;
        reg.publish(draft("user", &[], v1)).await.unwrap();
        reg.publish(draft("user", &[], v2)).await.unwrap();
        reg.diff("user", 1, 2).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn diff_of_equal_versions_is_empty_and_compatible() {
        let diff = diff_for(
            vec![attr("email", AttributeType::String)],
            vec![attr("email", AttributeType::String)],
        )
        .await;

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
        assert!(diff.compatible);
        assert!(diff.breaking.is_empty());
    }

    #[tokio::test]
    async fn an_added_optional_attribute_is_compatible() {
        let diff = diff_for(vec![], vec![attr("email", AttributeType::String)]).await;

        assert!(diff.added.contains_key("email"));
        assert!(diff.compatible);
    }

    #[tokio::test]
    async fn an_added_required_attribute_without_a_default_is_breaking() {
        let diff = diff_for(
            vec![],
            vec![full_attr(
                "email",
                AttributeType::String,
                true,
                false,
                false,
                None,
            )],
        )
        .await;

        assert!(!diff.compatible);
        assert_eq!(diff.breaking, vec!["required-added:email"]);
    }

    #[tokio::test]
    async fn an_added_required_attribute_with_a_default_is_compatible() {
        let diff = diff_for(
            vec![],
            vec![full_attr(
                "email",
                AttributeType::String,
                true,
                false,
                false,
                Some(serde_json::json!("none")),
            )],
        )
        .await;

        assert!(diff.compatible);
    }

    #[tokio::test]
    async fn a_removed_attribute_is_breaking() {
        let diff = diff_for(vec![attr("email", AttributeType::String)], vec![]).await;

        assert!(diff.removed.contains_key("email"));
        assert!(!diff.compatible);
        assert_eq!(diff.breaking, vec!["attribute-removed:email"]);
    }

    #[tokio::test]
    async fn a_type_change_is_breaking() {
        let diff = diff_for(
            vec![attr("total", AttributeType::Integer)],
            vec![attr("total", AttributeType::String)],
        )
        .await;

        assert!(diff.changed.contains_key("total"));
        assert!(!diff.compatible);
        assert_eq!(diff.breaking, vec!["type-changed:total"]);
    }

    #[tokio::test]
    async fn a_new_required_flag_without_a_default_is_breaking() {
        let diff = diff_for(
            vec![attr("expires_at", AttributeType::Timestamp)],
            vec![full_attr(
                "expires_at",
                AttributeType::Timestamp,
                true,
                false,
                false,
                None,
            )],
        )
        .await;

        assert!(!diff.compatible);
        assert_eq!(diff.breaking, vec!["required-added:expires_at"]);
    }

    #[tokio::test]
    async fn a_new_required_flag_with_a_default_is_compatible() {
        let diff = diff_for(
            vec![attr("expires_at", AttributeType::Timestamp)],
            vec![full_attr(
                "expires_at",
                AttributeType::Timestamp,
                true,
                false,
                false,
                Some(serde_json::json!(0)),
            )],
        )
        .await;

        assert!(diff.compatible);
    }

    #[tokio::test]
    async fn a_new_unique_flag_is_breaking() {
        let diff = diff_for(
            vec![attr("email", AttributeType::String)],
            vec![full_attr(
                "email",
                AttributeType::String,
                false,
                false,
                true,
                None,
            )],
        )
        .await;

        assert!(!diff.compatible);
        assert_eq!(diff.breaking, vec!["unique-added:email"]);
    }

    #[tokio::test]
    async fn a_default_change_is_compatible() {
        let diff = diff_for(
            vec![full_attr(
                "status",
                AttributeType::String,
                false,
                false,
                false,
                Some(serde_json::json!("new")),
            )],
            vec![full_attr(
                "status",
                AttributeType::String,
                false,
                false,
                false,
                Some(serde_json::json!("open")),
            )],
        )
        .await;

        assert!(diff.changed.contains_key("status"));
        assert!(diff.compatible);
    }

    #[tokio::test]
    async fn an_index_change_is_compatible() {
        let diff = diff_for(
            vec![attr("tag", AttributeType::String)],
            vec![full_attr(
                "tag",
                AttributeType::String,
                false,
                true,
                false,
                None,
            )],
        )
        .await;

        assert!(diff.compatible);
    }

    #[tokio::test]
    async fn a_removed_required_flag_is_compatible() {
        let diff = diff_for(
            vec![full_attr(
                "name",
                AttributeType::String,
                true,
                false,
                false,
                None,
            )],
            vec![attr("name", AttributeType::String)],
        )
        .await;

        assert!(diff.compatible);
    }

    #[tokio::test]
    async fn diff_returns_none_for_a_missing_version() {
        let reg = new_registry().await;
        reg.publish(draft("user", &[], vec![])).await.unwrap();

        assert!(reg.diff("user", 1, 2).await.unwrap().is_none());
        assert!(reg.diff("user", 0, 1).await.unwrap().is_none());
        assert!(reg.diff("ghost", 1, 2).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn effective_returns_equal_results_for_the_same_version() {
        let reg = new_registry().await;
        reg.publish(draft(
            "user",
            &[],
            vec![attr("email", AttributeType::String)],
        ))
        .await
        .unwrap();

        let first = reg.effective("user", 1).await.unwrap();
        let second = reg.effective("user", 1).await.unwrap();

        assert_eq!(first, second);
        assert!(first.is_some());
        assert_eq!(reg.cache.read().await.len(), 1);
    }

    #[tokio::test]
    async fn effective_keeps_versions_isolated_after_a_publish() {
        let reg = new_registry().await;
        reg.publish(draft(
            "user",
            &[],
            vec![attr("email", AttributeType::String)],
        ))
        .await
        .unwrap();

        let v1_before = reg.effective("user", 1).await.unwrap().unwrap();
        assert_eq!(v1_before.attributes.len(), 1);

        reg.publish(draft(
            "user",
            &[],
            vec![
                attr("email", AttributeType::String),
                attr("age", AttributeType::Integer),
            ],
        ))
        .await
        .unwrap();

        let v1_after = reg.effective("user", 1).await.unwrap().unwrap();
        let v2 = reg.effective("user", 2).await.unwrap().unwrap();

        assert_eq!(v1_after, v1_before);
        assert_eq!(v1_after.attributes.len(), 1);
        assert!(!v1_after.attributes.contains_key("age"));
        assert_eq!(v2.attributes.len(), 2);
        assert!(v2.attributes.contains_key("age"));
    }

    #[tokio::test]
    async fn child_effective_result_is_cached_independently_from_the_parent() {
        let reg = new_registry().await;
        reg.publish(draft(
            "base",
            &[],
            vec![attr("base_only", AttributeType::String)],
        ))
        .await
        .unwrap();
        reg.publish(draft(
            "child",
            &["base"],
            vec![attr("child_only", AttributeType::String)],
        ))
        .await
        .unwrap();

        let parent = reg.effective("base", 1).await.unwrap().unwrap();
        let child = reg.effective("child", 1).await.unwrap().unwrap();

        assert!(parent.attributes.contains_key("base_only"));
        assert!(!parent.attributes.contains_key("child_only"));
        assert!(child.attributes.contains_key("base_only"));
        assert!(child.attributes.contains_key("child_only"));

        let cache = reg.cache.read().await;
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&("base".to_string(), 1)), Some(&parent));
        assert_eq!(cache.get(&("child".to_string(), 1)), Some(&child));
    }

    #[tokio::test]
    async fn effective_returns_none_for_a_missing_version_and_caches_nothing() {
        let reg = new_registry().await;
        reg.publish(draft("user", &[], vec![])).await.unwrap();

        assert!(reg.effective("user", 2).await.unwrap().is_none());
        assert!(reg.effective("ghost", 1).await.unwrap().is_none());
        assert!(reg.cache.read().await.is_empty());
    }

    #[tokio::test]
    async fn effective_returns_a_cached_entry_before_it_reads_the_store() {
        let reg = new_registry().await;
        let sentinel = EffectiveSchema {
            id: "ghost".to_string(),
            version: 7,
            ancestors: Vec::new(),
            attributes: BTreeMap::new(),
        };
        reg.cache
            .write()
            .await
            .insert(("ghost".to_string(), 7), sentinel.clone());

        assert_eq!(reg.effective("ghost", 7).await.unwrap(), Some(sentinel));
        assert!(reg.effective("ghost", 8).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_registry_clone_shares_the_cache() {
        let reg = new_registry().await;
        reg.publish(draft(
            "user",
            &[],
            vec![attr("email", AttributeType::String)],
        ))
        .await
        .unwrap();
        let clone = reg.clone();

        assert!(Arc::ptr_eq(&reg.cache, &clone.cache));

        let from_clone = clone.effective("user", 1).await.unwrap().unwrap();
        assert_eq!(reg.cache.read().await.len(), 1);
        assert_eq!(reg.effective("user", 1).await.unwrap(), Some(from_clone));
        assert_eq!(reg.cache.read().await.len(), 1);
    }

    #[tokio::test]
    async fn effective_returns_the_correct_schema_after_more_versions_than_the_cap() {
        let reg = new_registry().await;
        let versions = MAX_EFFECTIVE_CACHE + 4;
        for i in 0..versions {
            reg.publish(draft(
                "user",
                &[],
                vec![attr(&format!("field{i}"), AttributeType::String)],
            ))
            .await
            .unwrap();
        }

        for i in 0..versions {
            let version = (i + 1) as u64;
            let effective = reg.effective("user", version).await.unwrap().unwrap();
            assert_eq!(effective.version, version);
            assert_eq!(effective.attributes.len(), 1);
            assert!(
                effective.attributes.contains_key(&format!("field{i}")),
                "version {version} must keep its own attribute"
            );
        }
    }

    #[tokio::test]
    async fn the_cache_stays_at_or_below_the_cap() {
        let reg = new_registry().await;
        for i in 0..(MAX_EFFECTIVE_CACHE + 4) {
            reg.publish(draft(
                "user",
                &[],
                vec![attr(&format!("field{i}"), AttributeType::String)],
            ))
            .await
            .unwrap();
            reg.effective("user", (i + 1) as u64).await.unwrap();
        }

        let len = reg.cache_len().await;
        assert!(len > 0, "a cache miss must insert one entry");
        assert!(
            len <= MAX_EFFECTIVE_CACHE,
            "cache length {len} must not exceed the cap {MAX_EFFECTIVE_CACHE}"
        );
    }

    #[tokio::test]
    async fn a_cached_entry_that_survives_eviction_is_still_a_hit() {
        let reg = new_registry().await;
        reg.publish(draft(
            "user",
            &[],
            vec![attr("email", AttributeType::String)],
        ))
        .await
        .unwrap();

        let sentinels: Vec<(String, EffectiveSchema)> = (0..MAX_EFFECTIVE_CACHE)
            .map(|i| {
                let id = format!("ghost{i}");
                let value = EffectiveSchema {
                    id: id.clone(),
                    version: 1,
                    ancestors: Vec::new(),
                    attributes: BTreeMap::new(),
                };
                (id, value)
            })
            .collect();
        {
            let mut cache = reg.cache.write().await;
            for (id, value) in &sentinels {
                cache.insert((id.clone(), 1), value.clone());
            }
        }
        assert_eq!(reg.cache_len().await, MAX_EFFECTIVE_CACHE);

        // This miss crosses the cap, so the insert removes one arbitrary entry.
        reg.effective("user", 1).await.unwrap().unwrap();
        assert_eq!(reg.cache_len().await, MAX_EFFECTIVE_CACHE);

        // A hit returns the sentinel value without a store read. An evicted
        // sentinel reads the store and returns `None`, because it has no row.
        let mut hits = 0;
        for (id, value) in &sentinels {
            if reg.effective(id, 1).await.unwrap().as_ref() == Some(value) {
                hits += 1;
            }
        }
        assert_eq!(
            hits,
            MAX_EFFECTIVE_CACHE - 1,
            "every sentinel except the evicted one must be a cache hit"
        );
    }

    #[tokio::test]
    async fn a_missing_version_returns_none_and_does_not_insert_an_entry() {
        let reg = new_registry().await;
        for i in 0..MAX_EFFECTIVE_CACHE {
            reg.publish(draft(
                "user",
                &[],
                vec![attr(&format!("field{i}"), AttributeType::String)],
            ))
            .await
            .unwrap();
            reg.effective("user", (i + 1) as u64).await.unwrap();
        }
        let before = reg.cache_len().await;
        assert_eq!(before, MAX_EFFECTIVE_CACHE);

        let missing = reg
            .effective("user", (MAX_EFFECTIVE_CACHE + 1) as u64)
            .await
            .unwrap();

        assert!(missing.is_none());
        assert_eq!(reg.cache_len().await, before);
    }

    #[tokio::test]
    async fn parent_and_child_versions_stay_isolated_after_many_resolutions() {
        let reg = new_registry().await;
        reg.publish(draft(
            "base",
            &[],
            vec![attr("base_only", AttributeType::String)],
        ))
        .await
        .unwrap();
        reg.publish(draft(
            "child",
            &["base"],
            vec![attr("child_only", AttributeType::String)],
        ))
        .await
        .unwrap();

        for i in 0..(MAX_EFFECTIVE_CACHE + 2) {
            reg.publish(draft(
                "base",
                &[],
                vec![attr(&format!("base{i}"), AttributeType::String)],
            ))
            .await
            .unwrap();
            reg.publish(draft(
                "child",
                &["base"],
                vec![attr(&format!("child{i}"), AttributeType::String)],
            ))
            .await
            .unwrap();
            reg.effective("base", (i + 2) as u64).await.unwrap();
            reg.effective("child", (i + 2) as u64).await.unwrap();
        }

        let parent = reg.effective("base", 1).await.unwrap().unwrap();
        let child = reg.effective("child", 1).await.unwrap().unwrap();

        assert!(parent.attributes.contains_key("base_only"));
        assert!(!parent.attributes.contains_key("child_only"));
        assert!(child.attributes.contains_key("base_only"));
        assert!(child.attributes.contains_key("child_only"));
        assert!(reg.cache_len().await <= MAX_EFFECTIVE_CACHE);
    }
}
