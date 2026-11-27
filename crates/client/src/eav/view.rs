//! The entity view of one EAV oxkv replica generation.
//!
//! The view scans the `entity:` key family one time. It decodes the metadata
//! row and the attribute rows of every entity. It builds the shared
//! `SearchEntity` values, so a query calls the same core function as the
//! server.
//!
//! The server materializes every schema default in the stored attribute
//! rows. The view therefore needs no schema and no default rule.
//!
//! The view holds no JSON attribute value. A query cannot match a JSON value
//! and a JSON value has no `SearchValue` form.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use oxkv::{KeyPrefix, ObjectPath, OxKvReader, OxKvStore, ScanExt as _, StoreError};
use rust_api_core::eav::{QueryWindow, SearchEntity, SearchValue, search_by_attribute};
use serde::Deserialize;

use crate::eav::storage::ReplicaStorage;

/// The key prefix of the entity rows.
const ENTITY_PREFIX: &str = "entity:";

/// The number of rows that one scan page reads.
const SCAN_PAGE: usize = 512;

/// The stored metadata row of one entity.
///
/// The view reads the id only. The other fields of the server type are not
/// part of a local query.
#[derive(Debug, Deserialize)]
struct EntityMeta {
    /// The entity id.
    id: String,
}

/// The stored value of one attribute row.
///
/// The serde form matches the adjacent tagged form of the server
/// `AttributeValue`. The query layer also parses a tagged query value with
/// this type.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub(crate) enum StoredAttributeValue {
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
    ///
    /// The view skips this value. The field keeps the serde form of the
    /// server value.
    Json(#[allow(dead_code)] serde_json::Value),
    /// A reference to another entity.
    EntityRef(String),
}

impl StoredAttributeValue {
    /// Convert the stored value to a search value.
    ///
    /// The call returns `None` for a JSON value. A JSON value has no exact
    /// search form, so the view skips it.
    pub(crate) fn into_search(self) -> Option<SearchValue> {
        match self {
            Self::String(value) => Some(SearchValue::String(value)),
            Self::Integer(value) => Some(SearchValue::Integer(value)),
            Self::Float(value) => Some(SearchValue::Float(value)),
            Self::Boolean(value) => Some(SearchValue::Boolean(value)),
            Self::Timestamp(value) => Some(SearchValue::Timestamp(value)),
            Self::EntityRef(value) => Some(SearchValue::EntityRef(value)),
            Self::Json(_) => None,
        }
    }
}

/// The part of an `entity:` key after the id.
enum RowKind<'a> {
    /// The metadata row of one entity.
    Meta,
    /// One attribute row, with the attribute name.
    Attribute(&'a str),
}

/// Split one `entity:` key into its id and its row kind.
///
/// The call returns `None` for a key outside the family, for an empty id,
/// and for an id that holds a `:`.
fn parse_key(key: &str) -> Option<(&str, RowKind<'_>)> {
    let rest = key.strip_prefix(ENTITY_PREFIX)?;
    let (id, tail) = rest.split_once(':')?;
    if id.is_empty() {
        return None;
    }
    if tail == "meta" {
        return Some((id, RowKind::Meta));
    }
    let name = tail.strip_prefix("attr:")?;
    if name.is_empty() {
        return None;
    }
    Some((id, RowKind::Attribute(name)))
}

/// One entity in the view.
#[derive(Debug, Clone, PartialEq)]
struct ViewEntity {
    /// The entity id.
    id: String,
    /// The attribute name and value pairs.
    attributes: Vec<(String, SearchValue)>,
}

/// One page of a local entity query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryPage {
    /// The matching entity ids, sorted by id.
    pub items: Vec<String>,
    /// The id for the next page when more matches remain.
    ///
    /// The value is the last id on this page.
    /// `None` means that the query is complete.
    pub next: Option<String>,
}

/// A failure to read the entity view.
///
/// The query layer maps this error to a stable query error.
/// The enum is non-exhaustive. A caller must treat a new variant as an error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ViewError {
    /// The replica holds a row that is not valid.
    Corrupt,
    /// The oxkv reader failed.
    Replica(StoreError),
}

impl fmt::Display for ViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt => formatter.write_str("the replica holds a row that is not valid"),
            Self::Replica(error) => write!(formatter, "the replica read failed: {error}"),
        }
    }
}

impl std::error::Error for ViewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Replica(error) => Some(error),
            Self::Corrupt => None,
        }
    }
}

impl From<StoreError> for ViewError {
    fn from(error: StoreError) -> Self {
        Self::Replica(error)
    }
}

/// The entities of one replica generation.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityView {
    /// The replica generation of this view.
    generation: u64,
    /// The decoded entities in id order.
    entities: Vec<ViewEntity>,
}

impl EntityView {
    /// Open the entity view of one replica generation.
    ///
    /// The call opens a read-only [`OxKvReader`] at the empty prefix and
    /// scans the `entity:` key family one time.
    pub async fn open(
        objects: &Arc<BTreeMap<String, Arc<[u8]>>>,
        generation: u64,
    ) -> Result<Self, ViewError> {
        let storage = Arc::new(ReplicaStorage::new(Arc::clone(objects)));
        let reader = OxKvStore::builder()
            .with_store(storage)
            .with_prefix(ObjectPath::default())
            .build_reader()
            .await?;
        Self::read(&reader, generation).await
    }

    /// Read every entity row from one reader.
    async fn read(reader: &OxKvReader, generation: u64) -> Result<Self, ViewError> {
        let mut rows = Vec::new();
        let mut after = None;
        loop {
            let page = reader
                .scan(KeyPrefix::new(ENTITY_PREFIX), after, SCAN_PAGE, true)
                .await?;
            rows.extend(page.items.into_iter().map(|row| (row.key, row.value)));
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Self::from_rows(generation, rows)
    }

    /// Decode the rows of the `entity:` key family.
    ///
    /// A row without a metadata row is skipped. An index, outbox, or timer
    /// row is not in the family and is skipped. A JSON attribute is skipped.
    pub(crate) fn from_rows<I>(generation: u64, rows: I) -> Result<Self, ViewError>
    where
        I: IntoIterator<Item = (String, Vec<u8>)>,
    {
        let mut ids = BTreeSet::new();
        let mut pending: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
        for (key, value) in rows {
            let Some((id, kind)) = parse_key(&key) else {
                continue;
            };
            match kind {
                RowKind::Meta => {
                    let meta: EntityMeta =
                        serde_json::from_slice(&value).map_err(|_| ViewError::Corrupt)?;
                    if meta.id != id {
                        return Err(ViewError::Corrupt);
                    }
                    ids.insert(id.to_string());
                }
                RowKind::Attribute(name) => {
                    pending
                        .entry(id.to_string())
                        .or_default()
                        .push((name.to_string(), value));
                }
            }
        }

        let mut entities = Vec::with_capacity(ids.len());
        for id in ids {
            let mut attributes = Vec::new();
            for (name, value) in pending.remove(&id).unwrap_or_default() {
                let value: StoredAttributeValue =
                    serde_json::from_slice(&value).map_err(|_| ViewError::Corrupt)?;
                if let Some(value) = value.into_search() {
                    attributes.push((name, value));
                }
            }
            entities.push(ViewEntity { id, attributes });
        }
        Ok(Self {
            generation,
            entities,
        })
    }

    /// Return the replica generation of this view.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the number of entities in the view.
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// Return `true` when the view holds no entity.
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Return the entity id at one position.
    pub fn id(&self, index: usize) -> Option<&str> {
        self.entities.get(index).map(|entity| entity.id.as_str())
    }

    /// Return the attribute value of one entity.
    ///
    /// The call returns `None` when the entity or the attribute is absent.
    pub fn attribute(&self, id: &str, name: &str) -> Option<&SearchValue> {
        let entity = self.entities.iter().find(|entity| entity.id == id)?;
        entity
            .attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }

    /// Search the view for one exact attribute value.
    ///
    /// The call passes a borrowed view to the shared core search. The page
    /// holds owned ids, so the caller can keep it after the view changes.
    pub fn query(&self, attribute: &str, value: &SearchValue, window: &QueryWindow) -> QueryPage {
        let attributes: Vec<Vec<(&str, SearchValue)>> = self
            .entities
            .iter()
            .map(|entity| {
                entity
                    .attributes
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.clone()))
                    .collect()
            })
            .collect();
        let views: Vec<SearchEntity<'_>> = self
            .entities
            .iter()
            .zip(&attributes)
            .map(|(entity, attributes)| SearchEntity {
                id: entity.id.as_str(),
                attributes,
            })
            .collect();
        let page = search_by_attribute(&views, attribute, value, window);
        QueryPage {
            items: page.ids.into_iter().map(str::to_owned).collect(),
            next: page.next.map(str::to_owned),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one string value.
    fn string(value: &str) -> SearchValue {
        SearchValue::String(value.to_string())
    }

    /// Encode one stored attribute value.
    fn attribute(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("the attribute serializes")
    }

    /// Build the metadata row of one entity.
    fn meta(id: &str) -> (String, Vec<u8>) {
        let value = serde_json::json!({
            "id": id,
            "version": 1,
            "schemas": [],
            "created_at": 0,
            "updated_at": 0,
        });
        (
            format!("entity:{id}:meta"),
            serde_json::to_vec(&value).expect("the meta serializes"),
        )
    }

    /// Build one attribute row.
    fn attr(id: &str, name: &str, value: serde_json::Value) -> (String, Vec<u8>) {
        (format!("entity:{id}:attr:{name}"), attribute(&value))
    }

    /// Build one view from rows.
    fn view(rows: Vec<(String, Vec<u8>)>) -> EntityView {
        EntityView::from_rows(4, rows).expect("the view decodes")
    }

    /// Every stored attribute variant becomes a search value.
    #[test]
    fn every_attribute_variant_decodes() {
        let rows = vec![
            meta("e1"),
            attr(
                "e1",
                "text",
                serde_json::json!({"type": "string", "value": "alpha"}),
            ),
            attr(
                "e1",
                "count",
                serde_json::json!({"type": "integer", "value": 7}),
            ),
            attr(
                "e1",
                "ratio",
                serde_json::json!({"type": "float", "value": 1.5}),
            ),
            attr(
                "e1",
                "flag",
                serde_json::json!({"type": "boolean", "value": true}),
            ),
            attr(
                "e1",
                "when",
                serde_json::json!({"type": "timestamp", "value": 1700}),
            ),
            attr(
                "e1",
                "link",
                serde_json::json!({"type": "entity_ref", "value": "e2"}),
            ),
        ];
        let view = view(rows);

        assert_eq!(view.generation(), 4);
        assert_eq!(view.len(), 1);
        assert_eq!(view.id(0), Some("e1"));
        assert_eq!(view.attribute("e1", "text"), Some(&string("alpha")));
        assert_eq!(
            view.attribute("e1", "count"),
            Some(&SearchValue::Integer(7))
        );
        assert_eq!(
            view.attribute("e1", "ratio"),
            Some(&SearchValue::Float(1.5))
        );
        assert_eq!(
            view.attribute("e1", "flag"),
            Some(&SearchValue::Boolean(true))
        );
        assert_eq!(
            view.attribute("e1", "when"),
            Some(&SearchValue::Timestamp(1700))
        );
        assert_eq!(
            view.attribute("e1", "link"),
            Some(&SearchValue::EntityRef("e2".to_string()))
        );
    }

    /// The view exposes the default values that the server stored.
    #[test]
    fn a_stored_default_is_part_of_the_view() {
        let rows = vec![
            meta("e1"),
            attr(
                "e1",
                "state",
                serde_json::json!({"type": "string", "value": "open"}),
            ),
        ];
        let view = view(rows);

        assert_eq!(view.attribute("e1", "state"), Some(&string("open")));
    }

    /// A deleted entity has no metadata row, so it is absent.
    #[test]
    fn a_deleted_entity_is_absent() {
        let rows = vec![
            meta("e1"),
            attr(
                "e2",
                "tag",
                serde_json::json!({"type": "string", "value": "gone"}),
            ),
        ];
        let view = view(rows);

        assert_eq!(view.len(), 1);
        assert_eq!(view.id(0), Some("e1"));
        assert_eq!(view.attribute("e2", "tag"), None);
    }

    /// An index, outbox, or timer row does not enter the view.
    #[test]
    fn index_rows_are_ignored() {
        let rows = vec![
            meta("e1"),
            attr(
                "e1",
                "tag",
                serde_json::json!({"type": "string", "value": "alpha"}),
            ),
            ("idx:entity:e2".to_string(), Vec::new()),
            ("idx:attr:tag:hash:e2".to_string(), Vec::new()),
            ("outbox:1".to_string(), b"{}".to_vec()),
            ("timer:fired:e2:when:00".to_string(), Vec::new()),
        ];
        let view = view(rows);

        assert_eq!(view.len(), 1);
        assert_eq!(view.id(0), Some("e1"));
    }

    /// A corrupt metadata row is a typed error.
    #[test]
    fn a_corrupt_meta_row_is_an_error() {
        let rows = vec![("entity:e1:meta".to_string(), b"not json".to_vec())];

        let error = EntityView::from_rows(1, rows).expect_err("the row is not valid");

        assert!(matches!(error, ViewError::Corrupt));
    }

    /// A corrupt attribute row is a typed error.
    #[test]
    fn a_corrupt_attribute_row_is_an_error() {
        let rows = vec![
            meta("e1"),
            ("entity:e1:attr:tag".to_string(), b"not json".to_vec()),
        ];

        let error = EntityView::from_rows(1, rows).expect_err("the row is not valid");

        assert!(matches!(error, ViewError::Corrupt));
    }

    /// A JSON attribute is skipped, so a query cannot match it.
    #[test]
    fn a_json_attribute_is_unsupported() {
        let rows = vec![
            meta("e1"),
            attr(
                "e1",
                "payload",
                serde_json::json!({"type": "json", "value": {"key": "value"}}),
            ),
            attr(
                "e1",
                "tag",
                serde_json::json!({"type": "string", "value": "alpha"}),
            ),
        ];
        let view = view(rows);

        assert_eq!(view.attribute("e1", "payload"), None);
        assert_eq!(view.attribute("e1", "tag"), Some(&string("alpha")));

        let window = QueryWindow::resolve(None, None).expect("the window is valid");
        let page = view.query("payload", &string("value"), &window);
        assert!(page.items.is_empty());
    }

    /// An id with a colon does not enter the view.
    #[test]
    fn an_id_with_a_colon_is_skipped() {
        let rows = vec![
            meta("ok"),
            (
                "entity:bad:id:meta".to_string(),
                b"{\"id\":\"bad:id\"}".to_vec(),
            ),
            (
                "entity:bad:id:attr:tag".to_string(),
                b"{\"type\":\"string\",\"value\":\"x\"}".to_vec(),
            ),
        ];
        let view = view(rows);

        assert_eq!(view.len(), 1);
        assert_eq!(view.id(0), Some("ok"));
    }

    /// An empty view is valid.
    #[test]
    fn an_empty_replica_is_an_empty_view() {
        let view = view(Vec::new());

        assert!(view.is_empty());
        assert_eq!(view.len(), 0);
        assert_eq!(view.generation(), 4);
    }
}
