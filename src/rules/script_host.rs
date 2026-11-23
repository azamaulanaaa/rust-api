//! A read-only data API for the future script engine.
//!
//! [`ScriptReadHost`] reads entities and returns plain JSON values.
//! The host has no write method, no delete method, and no request method.
//! It has no Rhai dependency.
//!
//! Every method checks [`ScriptCapabilities`] before it reads data.
//! A schema that is not in the set is denied.
//! A denied schema returns `None` or [`ScriptHostError::Denied`].
//! No result holds an attribute from a schema that the set does not allow.
//!
//! [`ScriptReadHost::get_entity`] returns one entity when at least one
//! pinned schema id is allowed.
//! The JSON shape is `{ "id", "version", "schemas": [ids], "attributes":
//! { plain JSON values } }`.
//! The `schemas` list holds only the pinned ids that the capability set
//! allows.
//! The attributes hold only the keys that those schemas define.
//! The attributes use
//! [`AttributeValue::as_json`](crate::eav::entity::AttributeValue::as_json),
//! so they hold no storage type tag.
//!
//! [`ScriptReadHost::find_by_schema`] and
//! [`ScriptReadHost::find_by_attribute`] return entity ids in id order.
//! Both methods return at most `limit` ids.
//! [`ScriptReadHost::find_by_attribute`] reads the attribute index.
//! It never scans the whole entity family.
//!
//! [`MAX_FIND_RESULTS`] bounds every find result.
//! A limit of 0 or a limit above the bound is an error.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::eav::entity::{AttributeValue, Entity, EntityStore};
use crate::eav::entity_error::EntityError;
use crate::eav::schema::SchemaRef;
use crate::rules::rule::validate_identifier;

/// The largest number of ids that one find method returns.
pub const MAX_FIND_RESULTS: usize = 100;

/// The stable message for a limit outside the allowed range.
const LIMIT_RANGE_MESSAGE: &str = "limit must be between 1 and 100";

/// The stable message for an attribute key with no index.
const NOT_INDEXED_MESSAGE: &str = "attribute is not indexed";

/// The stable message for a key and value pair with one absent part.
const BOTH_OR_NEITHER_MESSAGE: &str = "key and value must be both present or both absent";

/// The stable message for a failed store operation.
const STORE_MESSAGE: &str = "script host store operation failed";

/// The set of schema ids that a script can read.
///
/// An empty set allows no schema.
/// [`ScriptCapabilities::new`] rejects an invalid schema id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptCapabilities {
    /// The allowed schema ids.
    schemas: BTreeSet<String>,
}

impl ScriptCapabilities {
    /// Builds a capability set from `schemas`.
    ///
    /// The call validates each schema id.
    /// An invalid id returns [`ScriptHostError::Invalid`].
    /// An empty iterator builds an empty set, which allows no schema.
    pub fn new<I, S>(schemas: I) -> Result<Self, ScriptHostError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut allowed = BTreeSet::new();
        for schema in schemas {
            let schema = schema.into();
            validate_identifier("schema id", &schema)
                .map_err(|error| ScriptHostError::Invalid(error.to_string()))?;
            allowed.insert(schema);
        }
        Ok(Self { schemas: allowed })
    }

    /// True when the set contains `schema`.
    pub fn allows(&self, schema: &str) -> bool {
        self.schemas.contains(schema)
    }
}

/// An error from the script host.
///
/// Each message is stable.
/// No message contains an attribute value or the queried value.
#[derive(Debug, Error)]
pub enum ScriptHostError {
    // Equality compares the sanitized message only. The typed source is for
    // server logs and must not affect a caller's comparison.
    /// The capability set does not allow the schema.
    #[error("schema access denied")]
    Denied,
    /// The input is not valid.
    #[error("{0}")]
    Invalid(String),
    /// The entity store failed.
    ///
    /// The message is generic, so store internals do not leak.
    #[error("script host store operation failed")]
    Store {
        /// Sanitized detail for server logs.
        message: String,
        /// Cause from the entity store.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl PartialEq for ScriptHostError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Denied, Self::Denied) => true,
            (Self::Invalid(left), Self::Invalid(right)) => left == right,
            (Self::Store { message: left, .. }, Self::Store { message: right, .. }) => {
                left == right
            }
            _ => false,
        }
    }
}

impl Eq for ScriptHostError {}

/// A read-only host over one [`EntityStore`].
///
/// The host holds one entity store and one capability set.
/// It exposes no method that writes, deletes, or sends a request.
#[derive(Clone)]
pub struct ScriptReadHost {
    /// The store that supplies the entity data.
    entities: EntityStore,
    /// The schema ids that the host can read.
    capabilities: ScriptCapabilities,
}

impl std::fmt::Debug for ScriptReadHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptReadHost")
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl ScriptReadHost {
    /// Creates a read-only host over `entities` with `capabilities`.
    pub fn new(entities: EntityStore, capabilities: ScriptCapabilities) -> Self {
        Self {
            entities,
            capabilities,
        }
    }

    /// Returns one entity as plain JSON.
    ///
    /// The call returns `None` when the entity is absent.
    /// It also returns `None` when no pinned schema id is allowed.
    /// A caller cannot tell an absent entity from a denied entity.
    /// The JSON shape is `{ "id", "version", "schemas": [ids], "attributes":
    /// { plain JSON values } }`.
    /// The `schemas` list holds only the pinned ids that the capability set
    /// allows.
    /// The attributes hold only the keys that those schemas define.
    /// The attributes use
    /// [`AttributeValue::as_json`](crate::eav::entity::AttributeValue::as_json).
    pub async fn get_entity(&self, id: &str) -> Result<Option<serde_json::Value>, ScriptHostError> {
        let Some(entity) = self.entities.get(id).await.map_err(map_entity_error)? else {
            return Ok(None);
        };
        let pinned: Vec<SchemaRef> = entity
            .schemas
            .iter()
            .filter(|schema| self.capabilities.allows(&schema.id))
            .cloned()
            .collect();
        if pinned.is_empty() {
            return Ok(None);
        }

        let effective = self
            .entities
            .resolve_refs(&pinned)
            .await
            .map_err(map_entity_error)?;
        let allowed: BTreeSet<String> = effective
            .iter()
            .flat_map(|schema| schema.attributes.keys().cloned())
            .collect();
        let attributes: BTreeMap<String, serde_json::Value> = entity
            .attributes
            .iter()
            .filter(|(key, _)| allowed.contains(*key))
            .map(|(key, value)| (key.clone(), value.as_json()))
            .collect();
        let schemas: Vec<String> = pinned.into_iter().map(|schema| schema.id).collect();
        Ok(Some(serde_json::json!({
            "id": entity.id,
            "version": entity.version,
            "schemas": schemas,
            "attributes": attributes,
        })))
    }

    /// Returns the ids of the entities that pin `schema`.
    ///
    /// The call requires the `schema` capability.
    /// The result is in id order and holds at most `limit` ids.
    /// A `limit` of 0 or a `limit` above [`MAX_FIND_RESULTS`] is an error.
    pub async fn find_by_schema(
        &self,
        schema: &str,
        limit: usize,
    ) -> Result<Vec<String>, ScriptHostError> {
        check_limit(limit)?;
        require_capability(&self.capabilities, schema)?;

        let mut ids = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let (entities, next) = self
                .entities
                .list_by_schema_after(schema, limit, after.as_deref())
                .await
                .map_err(map_entity_error)?;
            for entity in entities {
                if !pins_schema(&entity, schema) {
                    continue;
                }
                ids.push(entity.id);
                if ids.len() >= limit {
                    return Ok(ids);
                }
            }
            match next {
                Some(cursor) => after = Some(cursor),
                None => return Ok(ids),
            }
        }
    }

    /// Returns the ids of the entities with an indexed attribute value.
    ///
    /// The call requires the `schema` capability.
    /// It requires that `schema` defines and indexes `key`.
    /// It reads the attribute index and keeps only entities that pin
    /// `schema`.
    /// The result is in id order and holds at most `limit` ids.
    /// The call never scans the whole entity family.
    /// A key that `schema` does not define or index returns
    /// [`ScriptHostError::Invalid`] with the stable message
    /// `attribute is not indexed`.
    /// A `limit` of 0 or a `limit` above [`MAX_FIND_RESULTS`] is an error.
    pub async fn find_by_attribute(
        &self,
        schema: &str,
        key: &str,
        value: &serde_json::Value,
        limit: usize,
    ) -> Result<Vec<String>, ScriptHostError> {
        check_limit(limit)?;
        require_capability(&self.capabilities, schema)?;
        self.require_indexed_key(schema, key).await?;

        let mut ids = BTreeSet::new();
        for candidate in attribute_candidates(value) {
            ids.extend(
                self.collect_attribute_ids(schema, key, &candidate, limit)
                    .await?,
            );
        }
        let mut ids: Vec<String> = ids.into_iter().collect();
        ids.truncate(limit);
        Ok(ids)
    }

    /// Returns the ids that match one schema and one optional attribute.
    ///
    /// The call dispatches to [`ScriptReadHost::find_by_schema`] when `key`
    /// and `value` are absent.
    /// It dispatches to [`ScriptReadHost::find_by_attribute`] when both are
    /// present.
    /// One absent part returns [`ScriptHostError::Invalid`] with the stable
    /// message `key and value must be both present or both absent`.
    pub async fn find(
        &self,
        schema: &str,
        key: Option<&str>,
        value: Option<&serde_json::Value>,
        limit: usize,
    ) -> Result<Vec<String>, ScriptHostError> {
        match (key, value) {
            (None, None) => self.find_by_schema(schema, limit).await,
            (Some(key), Some(value)) => self.find_by_attribute(schema, key, value, limit).await,
            _ => Err(ScriptHostError::Invalid(
                BOTH_OR_NEITHER_MESSAGE.to_string(),
            )),
        }
    }

    /// Returns an error unless `schema` defines and indexes `key`.
    ///
    /// The call reads the latest version of `schema`.
    /// An inherited attribute counts as a definition of `schema`.
    /// A missing key or a key without an index returns
    /// [`ScriptHostError::Invalid`] with the stable message
    /// `attribute is not indexed`.
    async fn require_indexed_key(&self, schema: &str, key: &str) -> Result<(), ScriptHostError> {
        let effective = match self.entities.resolve_schemas(&[schema.to_string()]).await {
            Ok(effective) => effective,
            Err(EntityError::UnknownSchema(_)) | Err(EntityError::Invalid(_)) => {
                return Err(ScriptHostError::Invalid(NOT_INDEXED_MESSAGE.to_string()));
            }
            Err(error) => return Err(map_entity_error(error)),
        };
        let indexed = effective.iter().any(|schema| {
            schema
                .attributes
                .get(key)
                .is_some_and(|definition| definition.indexed)
        });
        if indexed {
            Ok(())
        } else {
            Err(ScriptHostError::Invalid(NOT_INDEXED_MESSAGE.to_string()))
        }
    }

    /// Collects the first `limit` ids for one stored value form.
    ///
    /// The scan uses the attribute index and pages with a cursor.
    /// Only entities that pin `schema` enter the result.
    async fn collect_attribute_ids(
        &self,
        schema: &str,
        key: &str,
        value: &AttributeValue,
        limit: usize,
    ) -> Result<Vec<String>, ScriptHostError> {
        let mut ids = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let (entities, next) = self
                .entities
                .list_by_attribute_after(key, value, limit, after.as_deref())
                .await
                .map_err(map_entity_error)?;
            for entity in entities {
                if !pins_schema(&entity, schema) {
                    continue;
                }
                ids.push(entity.id);
                if ids.len() >= limit {
                    return Ok(ids);
                }
            }
            match next {
                Some(cursor) => after = Some(cursor),
                None => return Ok(ids),
            }
        }
    }
}

/// Checks one find limit against [`MAX_FIND_RESULTS`].
fn check_limit(limit: usize) -> Result<(), ScriptHostError> {
    if limit == 0 || limit > MAX_FIND_RESULTS {
        return Err(ScriptHostError::Invalid(LIMIT_RANGE_MESSAGE.to_string()));
    }
    Ok(())
}

/// Returns an error when the capability set does not allow `schema`.
fn require_capability(
    capabilities: &ScriptCapabilities,
    schema: &str,
) -> Result<(), ScriptHostError> {
    if capabilities.allows(schema) {
        Ok(())
    } else {
        Err(ScriptHostError::Denied)
    }
}

/// True when `entity` pins `schema`.
fn pins_schema(entity: &Entity, schema: &str) -> bool {
    entity.schemas.iter().any(|pinned| pinned.id == schema)
}

/// Maps one store error to a script host error.
///
/// A missing index is a stable invalid query.
/// Every other store error becomes a generic store error.
fn map_entity_error(error: EntityError) -> ScriptHostError {
    match error {
        EntityError::NotIndexed(_) => ScriptHostError::Invalid(NOT_INDEXED_MESSAGE.to_string()),
        other => ScriptHostError::Store {
            message: STORE_MESSAGE.to_string(),
            source: Box::new(other),
        },
    }
}

/// Returns the stored value forms that can hold the plain JSON `value`.
///
/// The attribute index hashes the tagged storage form.
/// One plain JSON value can therefore match more than one stored type.
/// A string matches `String` and `EntityRef`.
/// An integer matches `Integer` and `Timestamp`.
/// A `Json` attribute can hold any plain value.
fn attribute_candidates(value: &serde_json::Value) -> Vec<AttributeValue> {
    let mut candidates = Vec::new();
    match value {
        serde_json::Value::String(text) => {
            candidates.push(AttributeValue::String(text.clone()));
            candidates.push(AttributeValue::EntityRef(text.clone()));
        }
        serde_json::Value::Bool(flag) => candidates.push(AttributeValue::Boolean(*flag)),
        serde_json::Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                candidates.push(AttributeValue::Integer(integer));
                candidates.push(AttributeValue::Timestamp(integer));
            } else if let Some(float) = number.as_f64() {
                candidates.push(AttributeValue::Float(float));
            }
        }
        _ => {}
    }
    candidates.push(AttributeValue::Json(value.clone()));
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::{EntityDraft, WriteContext};
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft, SchemaRegistry};

    fn attr(name: &str, ty: AttributeType, indexed: bool) -> AttributeDef {
        AttributeDef {
            name: name.to_string(),
            ty,
            required: false,
            indexed,
            unique: false,
            default: None,
        }
    }

    fn schema(id: &str, attrs: Vec<AttributeDef>) -> SchemaDraft {
        SchemaDraft {
            id: id.to_string(),
            extends: Vec::new(),
            attributes: attrs.into_iter().map(|a| (a.name.clone(), a)).collect(),
        }
    }

    async fn host_with(capabilities: &[&str]) -> (ScriptReadHost, EntityStore) {
        let registry =
            SchemaRegistry::new(build_test_store(&test_prefix("script-host-schema")).await);
        let raw = build_test_store(&test_prefix("script-host")).await;
        let store = EntityStore::new(raw, registry.clone());
        registry
            .publish(schema(
                "invoice",
                vec![
                    attr("title", AttributeType::String, true),
                    attr("total", AttributeType::Integer, true),
                    attr("active", AttributeType::Boolean, false),
                    attr("meta", AttributeType::Json, false),
                    attr("note", AttributeType::String, false),
                ],
            ))
            .await
            .unwrap();
        registry
            .publish(schema(
                "secret",
                vec![
                    attr("title", AttributeType::String, true),
                    attr("code", AttributeType::String, true),
                ],
            ))
            .await
            .unwrap();
        let capabilities = ScriptCapabilities::new(capabilities.iter().copied()).unwrap();
        (ScriptReadHost::new(store.clone(), capabilities), store)
    }

    async fn create(
        store: &EntityStore,
        id: &str,
        schemas: &[&str],
        attrs: Vec<(&str, AttributeValue)>,
    ) {
        store
            .create(
                EntityDraft {
                    id: id.to_string(),
                    schemas: schemas.iter().map(|schema| (*schema).to_string()).collect(),
                    attributes: attrs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value))
                        .collect::<BTreeMap<_, _>>(),
                },
                &WriteContext::new("tester"),
            )
            .await
            .unwrap();
    }

    fn text(value: &str) -> AttributeValue {
        AttributeValue::String(value.to_string())
    }

    #[tokio::test]
    async fn get_entity_returns_plain_json_values() {
        let (host, store) = host_with(&["invoice"]).await;
        create(
            &store,
            "e1",
            &["invoice"],
            vec![
                ("title", text("alpha")),
                ("total", AttributeValue::Integer(7)),
                ("active", AttributeValue::Boolean(true)),
                (
                    "meta",
                    AttributeValue::Json(serde_json::json!({"nested": [1, 2]})),
                ),
            ],
        )
        .await;

        let entity = host.get_entity("e1").await.unwrap().unwrap();

        assert_eq!(
            entity,
            serde_json::json!({
                "id": "e1",
                "version": 1,
                "schemas": ["invoice"],
                "attributes": {
                    "title": "alpha",
                    "total": 7,
                    "active": true,
                    "meta": {"nested": [1, 2]},
                },
            })
        );
    }

    #[tokio::test]
    async fn get_entity_returns_none_for_a_missing_entity() {
        let (host, _store) = host_with(&["invoice"]).await;

        assert_eq!(host.get_entity("missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_entity_hides_an_entity_with_no_allowed_schema() {
        let (host, store) = host_with(&["invoice"]).await;
        create(&store, "secret-1", &["secret"], vec![("code", text("x"))]).await;

        assert_eq!(host.get_entity("secret-1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_entity_returns_when_one_pinned_schema_is_allowed() {
        let (host, store) = host_with(&["invoice"]).await;
        create(
            &store,
            "shared",
            &["invoice", "secret"],
            vec![("title", text("shared"))],
        )
        .await;

        let entity = host.get_entity("shared").await.unwrap().unwrap();

        assert_eq!(entity["id"], "shared");
        assert_eq!(entity["schemas"], serde_json::json!(["invoice"]));
    }

    #[tokio::test]
    async fn get_entity_returns_only_the_attributes_of_allowed_schemas() {
        let (host, store) = host_with(&["invoice"]).await;
        create(
            &store,
            "shared",
            &["invoice", "secret"],
            vec![
                ("title", text("shared")),
                ("total", AttributeValue::Integer(3)),
                ("code", text("s1")),
            ],
        )
        .await;

        let entity = host.get_entity("shared").await.unwrap().unwrap();

        assert_eq!(
            entity["attributes"],
            serde_json::json!({"title": "shared", "total": 3})
        );
    }

    #[tokio::test]
    async fn get_entity_hides_the_attributes_of_a_denied_schema() {
        let (host, store) = host_with(&["secret"]).await;
        create(
            &store,
            "shared",
            &["invoice", "secret"],
            vec![
                ("title", text("shared")),
                ("total", AttributeValue::Integer(3)),
                ("code", text("s1")),
            ],
        )
        .await;

        let entity = host.get_entity("shared").await.unwrap().unwrap();

        assert_eq!(
            entity["attributes"],
            serde_json::json!({"title": "shared", "code": "s1"})
        );
    }

    #[tokio::test]
    async fn find_by_schema_returns_ids_in_order_and_respects_the_limit() {
        let (host, store) = host_with(&["invoice"]).await;
        create(&store, "beta", &["invoice"], vec![("title", text("b"))]).await;
        create(&store, "alpha", &["invoice"], vec![("title", text("a"))]).await;
        create(&store, "gamma", &["invoice"], vec![("title", text("g"))]).await;
        create(&store, "delta", &["secret"], vec![("code", text("d"))]).await;

        assert_eq!(
            host.find_by_schema("invoice", 2).await.unwrap(),
            vec!["alpha", "beta"]
        );
        assert_eq!(
            host.find_by_schema("invoice", 10).await.unwrap(),
            vec!["alpha", "beta", "gamma"]
        );
    }

    #[tokio::test]
    async fn a_denied_schema_returns_denied() {
        let (host, store) = host_with(&["invoice"]).await;
        create(&store, "secret-1", &["secret"], vec![("code", text("x"))]).await;

        assert_eq!(
            host.find_by_schema("secret", 10).await.unwrap_err(),
            ScriptHostError::Denied
        );
        assert_eq!(
            host.find_by_attribute("secret", "code", &serde_json::json!("x"), 10)
                .await
                .unwrap_err(),
            ScriptHostError::Denied
        );
    }

    #[tokio::test]
    async fn find_by_attribute_filters_by_schema_and_respects_the_limit() {
        let (host, store) = host_with(&["invoice"]).await;
        create(&store, "a", &["invoice"], vec![("title", text("alpha"))]).await;
        create(&store, "b", &["invoice"], vec![("title", text("alpha"))]).await;
        create(&store, "c", &["secret"], vec![("title", text("alpha"))]).await;
        create(&store, "d", &["invoice"], vec![("title", text("alpha"))]).await;

        assert_eq!(
            host.find_by_attribute("invoice", "title", &serde_json::json!("alpha"), 2)
                .await
                .unwrap(),
            vec!["a", "b"]
        );
        assert_eq!(
            host.find_by_attribute("invoice", "title", &serde_json::json!("alpha"), 10)
                .await
                .unwrap(),
            vec!["a", "b", "d"]
        );
    }

    #[tokio::test]
    async fn a_non_indexed_attribute_returns_the_stable_error() {
        let (host, store) = host_with(&["invoice"]).await;
        create(&store, "e1", &["invoice"], vec![("note", text("x"))]).await;

        let error = host
            .find_by_attribute("invoice", "note", &serde_json::json!("x"), 10)
            .await
            .unwrap_err();

        assert_eq!(
            error,
            ScriptHostError::Invalid("attribute is not indexed".to_string())
        );
    }

    #[tokio::test]
    async fn find_by_attribute_requires_the_requested_schema_to_index_the_key() {
        let (host, store) = host_with(&["invoice"]).await;
        create(
            &store,
            "shared",
            &["invoice", "secret"],
            vec![("title", text("shared")), ("code", text("x"))],
        )
        .await;

        let error = host
            .find_by_attribute("invoice", "code", &serde_json::json!("x"), 10)
            .await
            .unwrap_err();

        assert_eq!(
            error,
            ScriptHostError::Invalid("attribute is not indexed".to_string())
        );
        assert_eq!(
            host.find(
                "invoice",
                Some("title"),
                Some(&serde_json::json!("shared")),
                10
            )
            .await
            .unwrap(),
            vec!["shared"]
        );
    }

    #[tokio::test]
    async fn a_limit_outside_the_range_returns_the_stable_error() {
        let (host, _store) = host_with(&["invoice"]).await;
        let expected = ScriptHostError::Invalid("limit must be between 1 and 100".to_string());

        assert_eq!(
            host.find_by_schema("invoice", 0).await.unwrap_err(),
            expected
        );
        assert_eq!(
            host.find_by_schema("invoice", MAX_FIND_RESULTS + 1)
                .await
                .unwrap_err(),
            expected
        );
    }

    #[tokio::test]
    async fn find_requires_a_key_and_a_value_or_neither() {
        let (host, _store) = host_with(&["invoice"]).await;
        let expected = ScriptHostError::Invalid(
            "key and value must be both present or both absent".to_string(),
        );

        assert_eq!(
            host.find("invoice", Some("title"), None, 10)
                .await
                .unwrap_err(),
            expected
        );
        assert_eq!(
            host.find("invoice", None, Some(&serde_json::json!("alpha")), 10)
                .await
                .unwrap_err(),
            expected
        );
    }

    #[tokio::test]
    async fn no_method_changes_an_entity_version() {
        let (host, store) = host_with(&["invoice"]).await;
        create(
            &store,
            "probe-before",
            &["invoice"],
            vec![("title", text("probe"))],
        )
        .await;
        let before = store.get("probe-before").await.unwrap().unwrap();

        host.get_entity("probe-before").await.unwrap();
        host.find_by_schema("invoice", 10).await.unwrap();
        host.find_by_attribute("invoice", "title", &serde_json::json!("probe"), 10)
            .await
            .unwrap();
        host.find("invoice", None, None, 10).await.unwrap();

        let after = store.get("probe-before").await.unwrap().unwrap();
        assert_eq!(after.version, before.version);
        assert_eq!(after.attributes, before.attributes);

        create(
            &store,
            "probe-after",
            &["invoice"],
            vec![("title", text("probe"))],
        )
        .await;
        let fresh = store.get("probe-after").await.unwrap().unwrap();
        assert_eq!(fresh.version, 1);
    }
}
