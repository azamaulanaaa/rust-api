//! A read-only OxKV storage adapter over the replica object map.
//!
//! The replica loader stores the raw objects of one generation in a
//! `BTreeMap`. The adapter gives that map to [`OxKvReader`](oxkv::OxKvReader).
//! The key of the map is relative to the replica root, so the reader opens
//! with an empty prefix.
//!
//! The adapter rejects every write. The client never treats the replica as a
//! write target.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use oxkv::{
    GetOptions, GetOutput, ObjectPath, PutMode, PutOutcome, Storage, StorageCause, StoreError,
};

/// The stored objects of one replica generation.
///
/// The map holds the bytes of the manifest and of every object that the
/// manifest names.
#[derive(Clone, Debug, Default)]
pub struct ReplicaStorage {
    /// The object bytes, keyed by the key relative to the replica root.
    objects: Arc<BTreeMap<String, Arc<[u8]>>>,
}

impl ReplicaStorage {
    /// Build a storage adapter over one object map.
    pub fn new(objects: Arc<BTreeMap<String, Arc<[u8]>>>) -> Self {
        Self { objects }
    }

    /// Return the number of stored objects.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Return `true` when the map holds no object.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Return one object, or a not-found error.
    fn read(&self, path: &ObjectPath) -> oxkv::Result<GetOutput> {
        let bytes = self.objects.get(path.as_str()).ok_or_else(|| {
            StoreError::storage_with_cause(
                format!("the replica has no object {path}"),
                StorageCause::NotFound,
            )
        })?;
        Ok(GetOutput {
            bytes: bytes.to_vec(),
            e_tag: None,
            version: None,
        })
    }
}

#[async_trait]
impl Storage for ReplicaStorage {
    async fn get(&self, path: &ObjectPath) -> oxkv::Result<GetOutput> {
        self.read(path)
    }

    async fn get_opts(&self, path: &ObjectPath, _options: GetOptions) -> oxkv::Result<GetOutput> {
        // The map holds no ETag. A conditional read with an ETag cannot
        // match an object, so the call returns the object bytes.
        self.read(path)
    }

    async fn put_opts(
        &self,
        _path: &ObjectPath,
        _payload: Vec<u8>,
        _mode: PutMode,
    ) -> oxkv::Result<PutOutcome> {
        Err(read_only())
    }

    async fn delete(&self, _path: &ObjectPath) -> oxkv::Result<()> {
        Err(read_only())
    }

    async fn list(&self, prefix: &ObjectPath) -> oxkv::Result<Vec<ObjectPath>> {
        let prefix = prefix.as_str();
        let keys = self
            .objects
            .keys()
            .filter(|key| is_in_prefix(prefix, key))
            .map(|key| ObjectPath::from(key.as_str()))
            .collect();
        Ok(keys)
    }
}

/// Return the error of a write against the read-only replica.
fn read_only() -> StoreError {
    StoreError::Other("the replica is read-only: the client rejects a write".to_string())
}

/// Return `true` when `key` is at or below the whole segment `prefix`.
///
/// The prefix matches only at a segment boundary. The prefix `e0` does not
/// match the key `e01/sst/a.sst`.
fn is_in_prefix(prefix: &str, key: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if key == prefix {
        return true;
    }
    key.strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    /// Build one map from key and body pairs.
    fn storage(objects: &[(&str, &[u8])]) -> ReplicaStorage {
        let map: BTreeMap<String, Arc<[u8]>> = objects
            .iter()
            .map(|(key, bytes)| ((*key).to_string(), Arc::<[u8]>::from(*bytes)))
            .collect();
        ReplicaStorage::new(Arc::new(map))
    }

    /// A read returns the stored bytes.
    #[test]
    fn a_get_returns_a_stored_object() {
        let storage = storage(&[("e0/manifest.json", b"manifest")]);

        let output = block_on(storage.get(&ObjectPath::from("e0/manifest.json")));

        let output = output.expect("the object exists");
        assert_eq!(output.bytes, b"manifest");
        assert_eq!(output.e_tag, None);
        assert_eq!(output.version, None);
    }

    /// A read of a missing object returns a not-found error.
    #[test]
    fn a_get_of_a_missing_object_is_not_found() {
        let storage = storage(&[("e0/manifest.json", b"manifest")]);

        let error = block_on(storage.get(&ObjectPath::from("e0/missing")))
            .expect_err("the object is absent");

        assert_eq!(error.storage_cause(), Some(StorageCause::NotFound));
    }

    /// A list returns the keys under a whole segment prefix.
    #[test]
    fn a_list_uses_whole_segment_prefixes() {
        let storage = storage(&[
            ("e0/sst/a.sst", b"a"),
            ("e0/wal/b.wal", b"b"),
            ("e01/sst/c.sst", b"c"),
            ("e1/other", b"d"),
        ]);

        let keys = block_on(storage.list(&ObjectPath::from("e0"))).expect("the list succeeds");
        let keys: Vec<&str> = keys.iter().map(ObjectPath::as_str).collect();

        assert_eq!(keys, ["e0/sst/a.sst", "e0/wal/b.wal"]);
    }

    /// An empty list prefix returns every object.
    #[test]
    fn an_empty_list_prefix_returns_every_object() {
        let storage = storage(&[("manifest.json", b"m"), ("e0/sst/a.sst", b"a")]);

        let keys = block_on(storage.list(&ObjectPath::default())).expect("the list succeeds");

        assert_eq!(keys.len(), 2);
    }

    /// A put is rejected as a write against a read-only store.
    #[test]
    fn a_put_returns_a_read_only_error() {
        let storage = storage(&[]);

        let error = block_on(storage.put_opts(
            &ObjectPath::from("e0/manifest.json"),
            b"new".to_vec(),
            PutMode::Create,
        ))
        .expect_err("the write is rejected");

        assert!(matches!(error, StoreError::Other(_)));
        assert_eq!(
            error.to_string(),
            "the replica is read-only: the client rejects a write"
        );
    }

    /// A delete is rejected as a write against a read-only store.
    #[test]
    fn a_delete_returns_a_read_only_error() {
        let storage = storage(&[("e0/manifest.json", b"m")]);

        let error = block_on(storage.delete(&ObjectPath::from("e0/manifest.json")))
            .expect_err("the write is rejected");

        assert!(matches!(error, StoreError::Other(_)));
    }

    /// A conditional read returns the same bytes as a plain read.
    #[test]
    fn a_conditional_read_returns_the_object() {
        let storage = storage(&[("e0/manifest.json", b"manifest")]);

        let output = block_on(storage.get_opts(
            &ObjectPath::from("e0/manifest.json"),
            GetOptions {
                if_none_match: Some("etag".to_string()),
            },
        ))
        .expect("the object exists");

        assert_eq!(output.bytes, b"manifest");
    }

    /// The adapter uses keys relative to the replica root.
    #[test]
    fn keys_are_relative_to_the_replica_root() {
        let storage = storage(&[("manifest.json", b"m"), ("e0/wal/a.wal", b"a")]);

        assert_eq!(storage.len(), 2);
        assert!(!storage.is_empty());
        assert!(block_on(storage.get(&ObjectPath::from("e0/wal/a.wal"))).is_ok());
        assert!(block_on(storage.get(&ObjectPath::from("/e0/wal/a.wal"))).is_err());
    }

    /// Poll one future to completion.
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
            std::thread::yield_now();
        }
    }
}
