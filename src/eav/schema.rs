//! Versioned EAV schemas, attribute definitions, and inheritance.
//!
//! Keys live in one bounded family.
//! The keys are `schema:head:{id}`, `schema:version:{id}:{version}`, and
//! `schema:child:{parent}:{child}`.
//! A head key holds the latest version as JSON `u64`.
//! A version key holds one [`SchemaDef`] as JSON.
//! A child key is an empty marker.
//! All scans stop at the `schema;` bound, so a scan reads only this family.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use oxkv::{Direction, GetSet, KeyValue, OxKvStore, Store as _, Transaction as _};
use serde::{Deserialize, Deserializer, Serialize, de};
use tokio::sync::{Mutex, RwLock};

use crate::eav::error::SchemaError;

/// Key prefix for the whole schema family.
const SCHEMA_PREFIX: &str = "schema:";

/// Key prefix for head pointers.
const HEAD_PREFIX: &str = "schema:head:";

/// Key prefix for immutable schema versions.
const VERSION_PREFIX: &str = "schema:version:";

/// Key prefix for child markers.
const CHILD_PREFIX: &str = "schema:child:";

/// Maximum size of a schema id or an attribute name, in bytes.
const MAX_NAME_BYTES: usize = 128;

/// Maximum number of schemas on one inheritance path.
const MAX_DEPTH: usize = 16;

/// The storage type of one attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRef {
    /// The schema id.
    pub id: String,
    /// The exact schema version.
    pub version: u64,
}

/// One immutable schema version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// A registry of versioned EAV schemas on one OxKV store.
#[derive(Clone)]
pub struct SchemaRegistry {
    /// Shared store handle.
    store: Arc<RwLock<OxKvStore>>,
    /// Serializes publishes, so two callers cannot claim one version.
    publish_lock: Arc<Mutex<()>>,
}

impl SchemaRegistry {
    /// Creates a registry over `store`.
    pub fn new(store: OxKvStore) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
            publish_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Publishes a schema draft and returns the stored definition.
    ///
    /// The call assigns the next monotonic version.
    /// A mutex serializes concurrent publishes.
    /// The version row and the head row commit in one transaction.
    /// Parent markers update in the same transaction.
    pub async fn publish(&self, draft: SchemaDraft) -> Result<SchemaDef, SchemaError> {
        validate_draft(&draft)?;

        let _publish = self.publish_lock.lock().await;
        let g = self.store.write().await;
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

        flatten(&tx, &def).await?;

        let version_bytes =
            serde_json::to_vec(&def).map_err(|e| SchemaError::Internal(e.to_string()))?;
        let head_bytes =
            serde_json::to_vec(&version).map_err(|e| SchemaError::Internal(e.to_string()))?;
        tx.set_bytes(&version_key(&def.id, version), &version_bytes)
            .await
            .map_err(SchemaError::Store)?;
        tx.set_bytes(&head_key(&def.id), &head_bytes)
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

        tx.commit().await.map_err(SchemaError::Store)?;
        Ok(def)
    }

    /// Reads one exact schema version.
    ///
    /// The call returns `None` when the version does not exist.
    pub async fn get(&self, id: &str, version: u64) -> Result<Option<SchemaDef>, SchemaError> {
        validate_name("schema id", id)?;
        let g = self.store.read().await;
        load_version(&*g, id, version).await
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

    /// Reads one schema version with all inherited attributes flattened.
    ///
    /// The call returns `None` when the version does not exist.
    /// A child attribute overrides an inherited attribute with the same type.
    /// A different type is a type conflict.
    pub async fn effective(
        &self,
        id: &str,
        version: u64,
    ) -> Result<Option<EffectiveSchema>, SchemaError> {
        validate_name("schema id", id)?;
        let g = self.store.read().await;
        let Some(root) = load_version(&*g, id, version).await? else {
            return Ok(None);
        };
        Ok(Some(flatten(&*g, &root).await?))
    }

    /// Lists the schemas whose latest version extends `id`.
    ///
    /// The list is sorted and has no duplicates.
    pub async fn children(&self, id: &str) -> Result<Vec<String>, SchemaError> {
        validate_name("schema id", id)?;
        let g = self.store.read().await;
        let prefix = format!("{CHILD_PREFIX}{id}:");
        let markers = scan_prefix(&*g, &prefix).await?;
        let mut out: Vec<String> = markers
            .into_iter()
            .filter_map(|kv| kv.key.strip_prefix(&prefix).map(str::to_string))
            .collect();
        out.sort();
        out.dedup();
        Ok(out)
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
    let cursor = (Some(prefix.to_string()), Some(prefix_scan_end(prefix)));
    store
        .gets_bytes(None, Direction::Next, cursor)
        .await
        .map_err(SchemaError::Store)
}

/// The exclusive upper bound for a `prefix:` range scan (`:` -> `;`).
fn prefix_scan_end(prefix: &str) -> String {
    debug_assert!(prefix.ends_with(':'));
    let mut end = prefix.to_string();
    end.pop();
    end.push(';');
    end
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
    }
    Ok(())
}

/// Checks an id or a name against the storage key rules.
///
/// The value must be 1 to 128 bytes.
/// It may contain only lowercase ASCII letters, digits, `_`, and `-`.
/// These rules reject `:` and `/`, so a value cannot inject a key.
fn validate_name(kind: &str, value: &str) -> Result<(), SchemaError> {
    if value.is_empty() {
        return Err(SchemaError::Invalid(format!("{kind} is empty")));
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(SchemaError::Invalid(format!(
            "{kind} is longer than 128 bytes"
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(SchemaError::Invalid(format!(
            "{kind} has an invalid character"
        )));
    }
    Ok(())
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
    async fn invalid_schema_ids_fail() {
        let reg = new_registry().await;
        let mut ids = vec![
            "".to_string(),
            "Upper".to_string(),
            "a:b".to_string(),
            "a/b".to_string(),
            "a b".to_string(),
        ];
        ids.push("a".repeat(MAX_NAME_BYTES + 1));

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
        names.push("a".repeat(MAX_NAME_BYTES + 1));

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
            Some(prefix_scan_end(SCHEMA_PREFIX)),
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
}
