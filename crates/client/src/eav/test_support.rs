//! Shared helpers for the local EAV unit tests.
//!
//! The helpers build a real in-memory OxKV store and serve its raw objects
//! over a scripted transport. A test can then load the replica exactly as
//! the browser does.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oxkv::{MemStorage, ObjectPath, OxKvStore, Storage as _};
use rust_api_model::wire::{ReplicaManifest, ReplicaObject};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth::{Request, Response, Transport, TransportError};

/// One scripted transport answer.
#[derive(Clone, Debug)]
pub(crate) struct Reply {
    /// The HTTP status code.
    pub(crate) status: u16,
    /// The response body.
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// Build a `200` answer with one body.
    pub(crate) fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body }
    }
}

/// The scripted answers of the fake transport.
pub(crate) type Replies = Rc<RefCell<VecDeque<Reply>>>;

/// A transport that returns scripted answers.
pub(crate) struct ScriptedTransport {
    /// The scripted answers.
    replies: Replies,
}

impl ScriptedTransport {
    /// Build a transport with no scripted answers.
    pub(crate) fn new() -> (Replies, Self) {
        let replies = Rc::new(RefCell::new(VecDeque::new()));
        (Rc::clone(&replies), Self { replies })
    }
}

impl Transport for ScriptedTransport {
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

/// Poll one future to completion. The scripted transport is always ready.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
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
pub(crate) fn entity_rows(id: &str, large: bool) -> Vec<(String, Vec<u8>)> {
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
pub(crate) fn build_objects(rows: Vec<(String, Vec<u8>)>) -> BTreeMap<String, Arc<[u8]>> {
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
pub(crate) fn script_replica(
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
