//! End-to-end tests for the local EAV query.
//!
//! The test writes an `entity:` key family to a real in-memory oxkv store.
//! It flushes and compacts the store. It exports the raw objects into the
//! replica map and serves them over a fake transport. Then it loads the
//! replica and runs the public query.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oxkv::{MemStorage, ObjectPath, OxKvStore, Storage as _};
use rust_api_client::auth::{Request, Response, Transport, TransportError};
use rust_api_client::eav::{QueryError, ReplicaQuery};
use rust_api_model::wire::{ReplicaManifest, ReplicaObject};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// One scripted transport answer.
#[derive(Clone, Debug)]
struct Reply {
    /// The HTTP status code.
    status: u16,
    /// The response body.
    body: Vec<u8>,
}

impl Reply {
    /// Build a `200` answer with one body.
    fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body }
    }
}

/// The scripted answers of the fake transport.
type Replies = Rc<RefCell<VecDeque<Reply>>>;

/// A transport that returns scripted answers.
struct FakeTransport {
    /// The scripted answers.
    replies: Replies,
}

impl FakeTransport {
    /// Build a transport with no scripted answers.
    fn new() -> (Replies, Self) {
        let replies = Rc::new(RefCell::new(VecDeque::new()));
        (Rc::clone(&replies), Self { replies })
    }
}

impl Transport for FakeTransport {
    async fn send(&self, _request: Request) -> Result<Response, TransportError> {
        let reply = self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("a scripted reply");
        Ok(Response {
            status: reply.status,
            body: reply.body,
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

/// Encode bytes as lowercase hexadecimal text.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    text
}

/// Build one manifest object with the correct size and hash.
fn object(key: &str, bytes: &[u8]) -> ReplicaObject {
    ReplicaObject {
        key: key.to_string(),
        size: bytes.len() as u64,
        sha256: hex_lower(&Sha256::digest(bytes)),
    }
}

/// Build the rows of one entity with a tag and an optional large value.
fn entity_rows(id: &str, large: bool) -> Vec<(String, Vec<u8>)> {
    let meta = json!({
        "id": id,
        "version": 1,
        "schemas": [],
        "created_at": 0,
        "updated_at": 0,
    });
    let tag = json!({"type": "string", "value": "alpha"});
    let mut rows = vec![
        (
            format!("entity:{id}:meta"),
            serde_json::to_vec(&meta).expect("the meta serializes"),
        ),
        (
            format!("entity:{id}:attr:tag"),
            serde_json::to_vec(&tag).expect("the tag serializes"),
        ),
    ];
    if large {
        let payload = json!({"type": "string", "value": "x".repeat(40 * 1024)});
        rows.push((
            format!("entity:{id}:attr:payload"),
            serde_json::to_vec(&payload).expect("the payload serializes"),
        ));
    }
    rows
}

/// Write one in-memory OxKV store and return its raw objects.
fn build_objects(rows: Vec<(String, Vec<u8>)>) -> BTreeMap<String, Arc<[u8]>> {
    let storage = Arc::new(MemStorage::new());
    let store = block_on(
        OxKvStore::builder()
            .with_store(storage.clone())
            .with_prefix(ObjectPath::default())
            .skip_probe(true)
            .build(),
    )
    .expect("the store opens");
    for (key, value) in rows {
        block_on(store.stage_set(&key, &value));
    }
    block_on(store.flush()).expect("the flush succeeds");
    block_on(store.flush_mem_to_sst_force()).expect("the SST write succeeds");
    block_on(store.compact()).expect("the compact succeeds");

    let keys = block_on(storage.list(&ObjectPath::default())).expect("the list succeeds");
    let mut objects = BTreeMap::new();
    for key in keys {
        let output = block_on(storage.get(&key)).expect("the object exists");
        objects.insert(key.as_str().to_string(), Arc::<[u8]>::from(output.bytes));
    }
    objects
}

/// Script one replica load for an object map.
fn script_replica(
    replies: &Replies,
    objects: &BTreeMap<String, Arc<[u8]>>,
    generation: u64,
    head: u64,
) {
    let manifest = ReplicaManifest {
        generation,
        head,
        objects: objects
            .iter()
            .map(|(key, bytes)| object(key, bytes))
            .collect(),
    };
    replies.borrow_mut().push_back(Reply::ok(
        serde_json::to_vec(&manifest).expect("the manifest serializes"),
    ));
    for key in &manifest.objects {
        replies
            .borrow_mut()
            .push_back(Reply::ok(objects[&key.key].to_vec()));
    }
}

/// Build the replica through a real OxKV store and query it.
#[test]
fn a_real_replica_answers_a_query() {
    let objects = build_objects(entity_rows("e1", true));
    let (replies, transport) = FakeTransport::new();
    script_replica(&replies, &objects, 9, 5);
    let query = ReplicaQuery::new(transport);

    let state = block_on(query.load()).expect("the replica loads");
    assert_eq!(state.generation, 9);
    let page = block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
        .expect("the query succeeds");
    assert_eq!(page.items, ["e1"]);

    // A 40 KiB value spills to a blob object. The reader dereferences it.
    let page = block_on(query.query_attribute(
        "payload",
        &Value::String("x".repeat(40 * 1024)),
        None,
        None,
    ))
    .expect("the large query succeeds");
    assert_eq!(page.items, ["e1"]);
}

/// A corrupt replica returns the corrupt-replica error.
#[test]
fn a_corrupt_replica_is_a_typed_error() {
    let objects = build_objects(vec![("entity:e1:meta".to_string(), b"not json".to_vec())]);
    let (replies, transport) = FakeTransport::new();
    script_replica(&replies, &objects, 1, 1);
    let query = ReplicaQuery::new(transport);

    block_on(query.load()).expect("the replica loads");
    let error = block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
        .expect_err("the row is not valid");

    assert_eq!(error, QueryError::CorruptReplica);
}

/// A new replica generation rebuilds the cached view.
#[test]
fn a_new_generation_rebuilds_the_cached_view() {
    let first = build_objects(entity_rows("e1", false));
    let second = build_objects(entity_rows("e2", false));
    let (replies, transport) = FakeTransport::new();
    script_replica(&replies, &first, 1, 1);
    script_replica(&replies, &second, 2, 2);
    let query = ReplicaQuery::new(transport);

    block_on(query.load()).expect("the first replica loads");
    let page = block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
        .expect("the first query succeeds");
    assert_eq!(page.items, ["e1"]);

    block_on(query.load()).expect("the second replica loads");
    let page = block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
        .expect("the second query succeeds");
    assert_eq!(page.items, ["e2"]);
}

/// An equal generation with a new object map rebuilds the cached view.
#[test]
fn an_equal_generation_rebuilds_the_cached_view() {
    let first = build_objects(entity_rows("e1", false));
    let second = build_objects(entity_rows("e2", false));
    let (replies, transport) = FakeTransport::new();
    script_replica(&replies, &first, 1, 1);
    script_replica(&replies, &second, 1, 1);
    let query = ReplicaQuery::new(transport);

    block_on(query.load()).expect("the first replica loads");
    let page = block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
        .expect("the first query succeeds");
    assert_eq!(page.items, ["e1"]);

    let state = block_on(query.load()).expect("the equal generation loads");
    assert_eq!(state.generation, 1);
    let page = block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
        .expect("the second query succeeds");
    assert_eq!(page.items, ["e2"]);
}

/// A tagged timestamp and a tagged entity reference match their rows.
#[test]
fn a_tagged_value_matches_a_typed_attribute() {
    let meta = json!({
        "id": "e1",
        "version": 1,
        "schemas": [],
        "created_at": 0,
        "updated_at": 0,
    });
    let when = json!({"type": "timestamp", "value": 1700});
    let link = json!({"type": "entity_ref", "value": "e2"});
    let objects = build_objects(vec![
        (
            "entity:e1:meta".to_string(),
            serde_json::to_vec(&meta).expect("the meta serializes"),
        ),
        (
            "entity:e1:attr:when".to_string(),
            serde_json::to_vec(&when).expect("the timestamp serializes"),
        ),
        (
            "entity:e1:attr:link".to_string(),
            serde_json::to_vec(&link).expect("the reference serializes"),
        ),
    ]);
    let (replies, transport) = FakeTransport::new();
    script_replica(&replies, &objects, 1, 1);
    let query = ReplicaQuery::new(transport);
    block_on(query.load()).expect("the replica loads");

    let page = block_on(query.query_attribute(
        "when",
        &json!({"type": "timestamp", "value": 1700}),
        None,
        None,
    ))
    .expect("the timestamp query succeeds");
    assert_eq!(page.items, ["e1"]);

    let page = block_on(query.query_attribute(
        "link",
        &json!({"type": "entity_ref", "value": "e2"}),
        None,
        None,
    ))
    .expect("the reference query succeeds");
    assert_eq!(page.items, ["e1"]);

    // A plain number is an integer, not a timestamp.
    let page = block_on(query.query_attribute("when", &json!(1700), None, None))
        .expect("the integer query succeeds");
    assert!(page.items.is_empty());

    let error =
        block_on(query.query_attribute("when", &json!({"type": "json", "value": 1}), None, None))
            .expect_err("a tagged JSON value is rejected");
    assert_eq!(error, QueryError::UnsupportedValue);
}
