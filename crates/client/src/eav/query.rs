//! Local entity queries over one EAV oxkv replica.
//!
//! [`ReplicaQuery`] owns the replica loader. The first query of an object map
//! opens the entity view and caches it. A later query reuses the view while
//! the loaded object map stays the same. A new load, even at the same
//! generation, rebuilds the view.
//!
//! The query calls the shared `search_by_attribute` function, so the
//! client and the server use one search rule. The client makes no
//! authorization decision. It reads the replica that the server built for
//! the authenticated subject.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use oxkv::StoreError;
use rust_api_core::eav::{QueryWindow, SearchValue};
use serde_json::Value;

use crate::auth::Transport;
use crate::eav::view::{EntityView, QueryPage, StoredAttributeValue, ViewError};
use crate::replica::{ReplicaClient, ReplicaError, ReplicaSource, ReplicaState};

/// A failure to run one local query.
///
/// The enum is non-exhaustive. A caller must treat a new variant as an error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueryError {
    /// No replica load has succeeded, or a clear removed the replica.
    NotLoaded,
    /// The replica holds a row that is not valid.
    CorruptReplica,
    /// The query value is not a scalar or a tagged attribute value.
    UnsupportedValue,
    /// The page window is not valid.
    InvalidQuery,
    /// The oxkv reader failed. The value keeps the reader cause.
    Replica(StoreError),
}

impl QueryError {
    /// Return the stable JavaScript error name.
    ///
    /// A name, once added, stays part of the stable surface.
    pub fn status_name(&self) -> &'static str {
        match self {
            Self::NotLoaded => "not_loaded",
            Self::CorruptReplica => "corrupt_replica",
            Self::UnsupportedValue => "unsupported_value",
            Self::InvalidQuery => "invalid_query",
            Self::Replica(_) => "replica",
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLoaded => formatter.write_str("the replica is not loaded"),
            Self::CorruptReplica => {
                formatter.write_str("the replica holds a row that is not valid")
            }
            Self::UnsupportedValue => {
                formatter.write_str("the query value must be a scalar or a tagged attribute value")
            }
            Self::InvalidQuery => formatter.write_str("the query window is not valid"),
            Self::Replica(error) => write!(formatter, "the replica read failed: {error}"),
        }
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Replica(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ViewError> for QueryError {
    fn from(error: ViewError) -> Self {
        match error {
            ViewError::Corrupt => Self::CorruptReplica,
            ViewError::Replica(error) => Self::Replica(error),
        }
    }
}

/// The cached view of one replica object map.
#[derive(Debug)]
struct CachedView {
    /// The replica generation of the view.
    generation: u64,
    /// The object map that the view decodes.
    objects: Arc<BTreeMap<String, Arc<[u8]>>>,
    /// The decoded entities.
    view: EntityView,
}

/// A test hook that runs after the view open and before the commit.
#[cfg(test)]
type AfterOpen<T> = fn(&ReplicaQuery<T>);

/// Runs local entity queries over one EAV oxkv replica.
#[derive(Debug)]
pub struct ReplicaQuery<T: Transport> {
    /// The EAV replica loader.
    replica: ReplicaClient<T>,
    /// The entity view of the last queried object map.
    cache: RefCell<Option<CachedView>>,
    /// A test hook that runs after the view open and before the commit.
    #[cfg(test)]
    after_open: RefCell<Option<AfterOpen<T>>>,
}

impl<T: Transport> ReplicaQuery<T> {
    /// Build a query client over one transport for the EAV oxkv replica.
    ///
    /// This constructor does no network work.
    pub fn new(transport: T) -> Self {
        Self::with_source(transport, ReplicaSource::EAV_OXKV)
    }

    /// Build a query client over one transport for one replica source.
    ///
    /// This constructor does no network work.
    pub fn with_source(transport: T, source: ReplicaSource) -> Self {
        Self {
            replica: ReplicaClient::with_source(transport, source),
            cache: RefCell::new(None),
            #[cfg(test)]
            after_open: RefCell::new(None),
        }
    }

    /// Return the replica loader.
    pub fn replica(&self) -> &ReplicaClient<T> {
        &self.replica
    }

    /// Download the EAV replica and return its state.
    ///
    /// The call keeps the cached view. The next query rebuilds the view when
    /// the loaded object map changes.
    pub async fn load(&self) -> Result<ReplicaState, ReplicaError> {
        self.replica.load().await
    }

    /// Remove the replica and the cached view.
    pub fn clear(&self) {
        self.replica.clear();
        self.cache.replace(None);
    }

    /// Run one local query for an exact attribute value.
    ///
    /// The call resolves the page window, then converts the JSON value to a
    /// search value. A scalar keeps its JSON type. A tagged value such as
    /// `{"type":"timestamp","value":1700}` keeps the server attribute type.
    /// A JSON `null`, array, or untagged object has no search value and
    /// returns [`QueryError::UnsupportedValue`]. The call opens the entity
    /// view on the first query of an object map and caches it.
    ///
    /// The cache key is the generation and the object map. A load at an equal
    /// generation replaces the map, so the old view cannot serve the new
    /// bytes. A clear or a newer load during the open aborts the query.
    pub async fn query_attribute(
        &self,
        attribute: &str,
        value: &Value,
        limit: Option<usize>,
        after: Option<&str>,
    ) -> Result<QueryPage, QueryError> {
        let window = QueryWindow::resolve(limit, after).map_err(|_| QueryError::InvalidQuery)?;
        let value = search_value(value)?;
        let Some(state) = self.replica.state() else {
            return Err(QueryError::NotLoaded);
        };
        let Some(objects) = self.replica.objects() else {
            return Err(QueryError::NotLoaded);
        };
        if let Some(cached) = self.cache.borrow().as_ref()
            && cached.generation == state.generation
            && Arc::ptr_eq(&cached.objects, &objects)
        {
            return Ok(cached.view.query(attribute, &value, &window));
        }
        let view = EntityView::open(&objects, state.generation).await?;
        #[cfg(test)]
        if let Some(hook) = self.after_open.borrow_mut().take() {
            hook(self);
        }
        // A clear or a newer load can finish during the open. Cache and
        // return only the view of the object map that is still stored.
        let Some(current) = self.replica.objects() else {
            return Err(QueryError::NotLoaded);
        };
        if !Arc::ptr_eq(&current, &objects) {
            return Err(QueryError::NotLoaded);
        }
        let page = view.query(attribute, &value, &window);
        *self.cache.borrow_mut() = Some(CachedView {
            generation: state.generation,
            objects,
            view,
        });
        Ok(page)
    }
}

/// Convert one JSON query value to a search value.
///
/// A plain JSON scalar keeps its JSON type. A tagged object uses the server
/// attribute form, for example a timestamp or an entity reference. A JSON
/// `null`, array, untagged object, or tagged `json` value has no exact search
/// form.
fn search_value(value: &Value) -> Result<SearchValue, QueryError> {
    match value {
        Value::String(value) => Ok(SearchValue::String(value.clone())),
        Value::Number(value) => match (value.as_i64(), value.as_f64()) {
            (Some(value), _) => Ok(SearchValue::Integer(value)),
            (None, Some(value)) => Ok(SearchValue::Float(value)),
            _ => Err(QueryError::UnsupportedValue),
        },
        Value::Bool(value) => Ok(SearchValue::Boolean(*value)),
        Value::Object(_) => serde_json::from_value::<StoredAttributeValue>(value.clone())
            .ok()
            .and_then(StoredAttributeValue::into_search)
            .ok_or(QueryError::UnsupportedValue),
        Value::Null | Value::Array(_) => Err(QueryError::UnsupportedValue),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Request, Response, TransportError};
    use crate::eav::test_support::{ScriptedTransport, build_objects, entity_rows, script_replica};
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    /// A transport that answers `200` with an empty body.
    struct FakeTransport;

    impl Transport for FakeTransport {
        async fn send(&self, _request: Request) -> Result<Response, TransportError> {
            Ok(Response {
                status: 200,
                body: Vec::new(),
            })
        }
    }

    /// Poll one future to completion. The fake transport is always ready.
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// Build one view from entity id and count pairs.
    fn view(ids: &[(&str, i64)]) -> EntityView {
        let rows: Vec<(String, Vec<u8>)> = ids
            .iter()
            .flat_map(|(id, count)| {
                let meta = serde_json::json!({"id": id});
                let value = serde_json::json!({"type": "integer", "value": count});
                [
                    (
                        format!("entity:{id}:meta"),
                        serde_json::to_vec(&meta).expect("the meta serializes"),
                    ),
                    (
                        format!("entity:{id}:attr:count"),
                        serde_json::to_vec(&value).expect("the value serializes"),
                    ),
                ]
            })
            .collect();
        EntityView::from_rows(1, rows).expect("the view decodes")
    }

    /// Build a query window.
    fn window(limit: Option<usize>, after: Option<&str>) -> QueryWindow {
        QueryWindow::resolve(limit, after).expect("the window is valid")
    }

    /// A full page reports the last id as the cursor.
    #[test]
    fn a_full_page_reports_the_last_id_as_the_cursor() {
        let view = view(&[("e1", 1), ("e2", 1), ("e3", 1)]);

        let page = view.query("count", &SearchValue::Integer(1), &window(Some(2), None));

        assert_eq!(page.items, ["e1", "e2"]);
        assert_eq!(page.next.as_deref(), Some("e2"));

        let page = view.query(
            "count",
            &SearchValue::Integer(1),
            &window(Some(2), page.next.as_deref()),
        );

        assert_eq!(page.items, ["e3"]);
        assert_eq!(page.next, None);
    }

    /// A page that holds every match has no cursor.
    #[test]
    fn a_page_at_the_limit_has_no_cursor() {
        let view = view(&[("e1", 1), ("e2", 1)]);

        let page = view.query("count", &SearchValue::Integer(1), &window(Some(2), None));

        assert_eq!(page.items, ["e1", "e2"]);
        assert_eq!(page.next, None);
    }

    /// A cursor skips ids at or below it.
    #[test]
    fn a_cursor_skips_ids_at_or_below_it() {
        let view = view(&[("e1", 1), ("e2", 1)]);

        let page = view.query("count", &SearchValue::Integer(1), &window(None, Some("e1")));

        assert_eq!(page.items, ["e2"]);
        assert_eq!(page.next, None);
    }

    /// A cursor in the middle returns the next ids in id order.
    #[test]
    fn a_cursor_in_the_middle_returns_the_next_ids() {
        let ids: Vec<String> = (1..=10).rev().map(|n| format!("e{n:02}")).collect();
        let pairs: Vec<(&str, i64)> = ids.iter().map(|id| (id.as_str(), 1)).collect();
        let view = view(&pairs);

        let page = view.query(
            "count",
            &SearchValue::Integer(1),
            &window(Some(3), Some("e04")),
        );

        assert_eq!(page.items, ["e05", "e06", "e07"]);
        assert_eq!(page.next.as_deref(), Some("e07"));
    }

    /// Repeated rows of one entity do not use a second page slot.
    #[test]
    fn repeated_rows_do_not_repeat_an_id() {
        let mut rows = Vec::new();
        for id in ["e1", "e1", "e2", "e2", "e3", "e3", "e4"] {
            let meta = serde_json::json!({"id": id});
            let value = serde_json::json!({"type": "integer", "value": 1});
            rows.push((
                format!("entity:{id}:meta"),
                serde_json::to_vec(&meta).expect("the meta serializes"),
            ));
            rows.push((
                format!("entity:{id}:attr:count"),
                serde_json::to_vec(&value).expect("the value serializes"),
            ));
        }
        let view = EntityView::from_rows(1, rows).expect("the view decodes");

        let page = view.query("count", &SearchValue::Integer(1), &window(Some(2), None));

        assert_eq!(page.items, ["e1", "e2"]);
        assert_eq!(page.next.as_deref(), Some("e2"));
    }

    /// A page larger than the match set has no cursor.
    #[test]
    fn a_page_larger_than_the_match_set_has_no_cursor() {
        let view = view(&[("e1", 1), ("e2", 1), ("e3", 1)]);

        let page = view.query("count", &SearchValue::Integer(1), &window(Some(10), None));

        assert_eq!(page.items, ["e1", "e2", "e3"]);
        assert_eq!(page.next, None);
    }

    /// The empty view returns an empty page.
    #[test]
    fn the_empty_view_returns_an_empty_page() {
        let view = view(&[]);

        let page = view.query("count", &SearchValue::Integer(1), &window(None, None));

        assert!(page.items.is_empty());
        assert_eq!(page.next, None);
    }

    /// A query before a load returns the not-loaded error.
    #[test]
    fn a_query_before_a_load_is_not_loaded() {
        let transport = FakeTransport;
        let query = ReplicaQuery::new(transport);

        let error =
            block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
                .expect_err("the replica is not loaded");

        assert_eq!(error, QueryError::NotLoaded);
        assert_eq!(error.status_name(), "not_loaded");
    }

    /// A JSON null, array, or untagged object is an unsupported value.
    #[test]
    fn an_unsupported_value_is_rejected() {
        for value in [
            Value::Null,
            serde_json::json!(["alpha"]),
            serde_json::json!({"key": "value"}),
            serde_json::json!({"type": "json", "value": {"key": "value"}}),
        ] {
            let error = search_value(&value).expect_err("the value has no search form");
            assert_eq!(error, QueryError::UnsupportedValue);
        }
    }

    /// A zero or a high page size is an invalid query.
    #[test]
    fn an_invalid_window_is_an_invalid_query() {
        for limit in [0, 201] {
            let transport = FakeTransport;
            let query = ReplicaQuery::new(transport);

            let error = block_on(query.query_attribute(
                "tag",
                &Value::String("alpha".into()),
                Some(limit),
                None,
            ))
            .expect_err("the window is not valid");

            assert_eq!(error, QueryError::InvalidQuery);
        }
    }

    /// A query value converts to the matching search value.
    #[test]
    fn a_query_value_converts_to_a_search_value() {
        assert_eq!(
            search_value(&Value::String("alpha".into())),
            Ok(SearchValue::String("alpha".into()))
        );
        assert_eq!(
            search_value(&serde_json::json!(7)),
            Ok(SearchValue::Integer(7))
        );
        assert_eq!(
            search_value(&serde_json::json!(1.5)),
            Ok(SearchValue::Float(1.5))
        );
        assert_eq!(
            search_value(&Value::Bool(true)),
            Ok(SearchValue::Boolean(true))
        );
        assert_eq!(
            search_value(&serde_json::json!({"type": "timestamp", "value": 1700})),
            Ok(SearchValue::Timestamp(1700))
        );
        assert_eq!(
            search_value(&serde_json::json!({"type": "entity_ref", "value": "e2"})),
            Ok(SearchValue::EntityRef("e2".to_string()))
        );
        assert_eq!(
            search_value(&serde_json::json!({"type": "string", "value": "alpha"})),
            Ok(SearchValue::String("alpha".to_string()))
        );
        assert_eq!(
            search_value(&serde_json::json!({"type": "boolean", "value": true})),
            Ok(SearchValue::Boolean(true))
        );
    }

    /// A clear during a query cannot commit a stale view.
    #[test]
    fn a_clear_during_a_query_cannot_commit_a_stale_view() {
        let objects = build_objects(entity_rows("e1", false));
        let (replies, transport) = ScriptedTransport::new();
        script_replica(&replies, &objects, 1, 1);
        let query = ReplicaQuery::new(transport);
        block_on(query.load()).expect("the replica loads");

        *query.after_open.borrow_mut() =
            Some(|query: &ReplicaQuery<ScriptedTransport>| query.clear());
        let error =
            block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
                .expect_err("the clear aborts the query");

        assert_eq!(error, QueryError::NotLoaded);
        assert!(query.cache.borrow().is_none());

        // A later map at the same generation serves only the new bytes.
        let next = build_objects(entity_rows("e2", false));
        script_replica(&replies, &next, 1, 1);
        block_on(query.load()).expect("the new replica loads");
        let page =
            block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
                .expect("the query succeeds");
        assert_eq!(page.items, ["e2"]);
    }

    /// The error names are stable.
    #[test]
    fn the_query_error_names_are_stable() {
        assert_eq!(QueryError::NotLoaded.status_name(), "not_loaded");
        assert_eq!(QueryError::CorruptReplica.status_name(), "corrupt_replica");
        assert_eq!(
            QueryError::UnsupportedValue.status_name(),
            "unsupported_value"
        );
        assert_eq!(QueryError::InvalidQuery.status_name(), "invalid_query");
        assert_eq!(
            QueryError::Replica(StoreError::Other("reader failed".to_string())).status_name(),
            "replica"
        );
    }

    /// The replica query error keeps its source.
    #[test]
    fn the_replica_error_keeps_its_source() {
        let error = QueryError::from(ViewError::Replica(StoreError::Other(
            "reader failed".to_string(),
        )));

        assert_eq!(error.status_name(), "replica");
        assert_eq!(error.to_string(), "the replica read failed: reader failed");
        assert!(std::error::Error::source(&error).is_some());
    }
}
