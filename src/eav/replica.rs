//! Stored per-user entity replicas.
//!
//! A replica is a head-anchored JSON snapshot, not an incremental store.
//! The build reads the feed head first. It then pages the entities.
//! A change that commits after the head can appear in the snapshot.
//! The client applies the events after the returned head.
//! An apply must be idempotent and version-aware.
//! The client builds one replica, then applies the event feed for each delta.
//! The store keeps one head row, one manifest row, and one row for each chunk.
//! The head row names the manifest, and the manifest names the chunk count.
//! All rows commit in one transaction.
//! The head is monotonic: a build with a lower head never replaces a newer
//! snapshot.
//!
//! Keys:
//!
//! - `replica:{sub_hash}:head` holds a JSON `u64`.
//! - `replica:{sub_hash}:generation` holds a JSON `u64`.
//! - `replica:{sub_hash}:meta:{head}` holds JSON `{ "chunks": u64 }`.
//! - `replica:{sub_hash}:data:{head}:{index:08}` holds one JSON chunk.
//!
//! The chunk index is zero-based and zero-padded, so key order equals chunk
//! order.
//! `sub_hash` is the lowercase SHA-256 hex of the subject.
//! The hash keeps the subject text out of the key.
//!
//! A put writes every chunk, the manifest, the head, and the generation in
//! one transaction.
//! The same transaction deletes the old manifest and every old chunk row.
//! A head equal to the stored head replaces the snapshot.
//! The put increments the generation on each replacement.
//! Thus a read detects an equal-head rebuild that changes the snapshot.
//!
//! A reset removes the snapshot, the chunks, the manifest, the generation, and
//! the head.
//! A reset commits in one transaction under the store write guard.
//! Thus a concurrent put and reset cannot leave a partial replica.
//!
//! A read sees consistent chunks when the head and the generation do not
//! change during the read.
//! The read checks the head and the generation before and after it reads the
//! manifest and the chunk rows.
//! It retries when the head, the generation, or a row changed or is absent.
//! A missing generation row means a legacy replica at generation 0.
//!
//! The store adds no business logic.
//! It does not filter the data and it does not read the event feed.

use std::sync::Arc;

use oxkv::{GetSet, OxKvStore, Store as _, StoreError, Transaction as _, TxCas as _};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::eav::entity_error::EntityError;

/// The number of times a read tries to read one consistent snapshot.
const GET_ATTEMPTS: u32 = 16;

/// The number of times a put retries after a head or generation conflict.
const PUT_ATTEMPTS: u32 = 8;

/// One stored replica snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaSnapshot {
    /// The head of the stored replica.
    pub head: u64,
    /// The build generation of the stored replica.
    pub generation: u64,
    /// The JSON chunks in index order.
    pub chunks: Vec<Vec<u8>>,
}

/// One stored replica chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaChunk {
    /// The head of the stored replica.
    pub head: u64,
    /// The build generation of the stored replica.
    pub generation: u64,
    /// The zero-based index of this chunk.
    pub index: usize,
    /// The number of chunks in the stored replica.
    pub chunks: usize,
    /// The JSON bytes of this chunk.
    pub data: Vec<u8>,
}

/// The manifest of one stored replica.
#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
struct ReplicaMeta {
    /// The number of chunk rows.
    chunks: u64,
}

/// A test hook that runs inside one read attempt.
#[cfg(test)]
type ReadHook = std::sync::Arc<
    dyn for<'a> Fn(
            &'a OxKvStore,
            u32,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>
        + Send
        + Sync,
>;

/// A stored per-user entity replica.
///
/// A build replaces the previous snapshot for the same subject.
/// A build with a lower head fails with [`EntityError::StaleHead`].
/// A build increments the generation, including a build with a head equal to
/// the stored head.
/// A read checks the head and the generation before and after it reads the
/// manifest and the chunk rows.
/// It retries when the head, the generation, or a row changed or is absent.
/// A missing generation row means a legacy replica at generation 0.
/// All rows commit in one transaction, so a head and a generation that did not
/// change name rows from the same snapshot.
#[derive(Clone)]
pub struct ReplicaStore {
    /// The shared replica store handle.
    store: Arc<RwLock<OxKvStore>>,
    /// Runs inside each read attempt before the final check.
    #[cfg(test)]
    read_hook: Option<ReadHook>,
}

impl ReplicaStore {
    /// Creates a store over `store`.
    pub fn new(store: OxKvStore) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
            #[cfg(test)]
            read_hook: None,
        }
    }

    /// Sets a hook that runs inside each read attempt.
    #[cfg(test)]
    fn with_read_hook(mut self, hook: ReadHook) -> Self {
        self.read_hook = Some(hook);
        self
    }

    /// Stores `chunks` for `sub` at `head`.
    ///
    /// Every chunk, the manifest, the head, and the generation commit in one
    /// transaction.
    /// The same transaction deletes the old manifest and every old chunk row.
    /// The call reads the stored generation in the same transaction and writes
    /// the next value.
    /// A missing generation row counts as `0`, so the first put writes `1`.
    /// A `head` lower than the stored head is stale.
    /// A stale build returns [`EntityError::StaleHead`] and changes nothing,
    /// including the generation.
    /// A `head` equal to the stored head replaces the snapshot and increments
    /// the generation.
    /// Thus the stored head never goes backwards, and the generation is
    /// monotonic per subject.
    /// The call returns the new generation.
    pub async fn put(
        &self,
        sub: &str,
        head: u64,
        chunks: Vec<Vec<u8>>,
    ) -> Result<u64, EntityError> {
        let hash = sub_hash(sub);
        let head_bytes =
            serde_json::to_vec(&head).map_err(|e| EntityError::Internal(e.to_string()))?;
        let meta = ReplicaMeta {
            chunks: chunks.len() as u64,
        };
        let meta_bytes =
            serde_json::to_vec(&meta).map_err(|e| EntityError::Internal(e.to_string()))?;
        let g = self.store.write().await;
        for _attempt in 0..PUT_ATTEMPTS {
            let tx = g.begin_tx().map_err(EntityError::Store)?;
            let old_head = read_head(&tx, &hash).await?;
            if let Some(stored) = old_head
                && head < stored
            {
                return Err(EntityError::StaleHead {
                    stored,
                    incoming: head,
                });
            }
            let stored_generation = read_generation(&tx, &hash).await?;
            let generation = stored_generation
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| {
                    EntityError::Internal("replica generation is exhausted".to_string())
                })?;
            let generation_bytes = serde_json::to_vec(&generation)
                .map_err(|e| EntityError::Internal(e.to_string()))?;
            let expected_generation = match stored_generation {
                Some(value) => Some(
                    serde_json::to_vec(&value).map_err(|e| EntityError::Internal(e.to_string()))?,
                ),
                None => None,
            };
            if let Some(old_head) = old_head {
                let old_chunks = read_meta(&tx, &hash, old_head)
                    .await?
                    .map(|meta| meta.chunks)
                    .unwrap_or(0);
                for index in 0..old_chunks {
                    tx.delete(&data_key(&hash, old_head, index as usize))
                        .await
                        .map_err(EntityError::Store)?;
                }
                tx.delete(&meta_key(&hash, old_head))
                    .await
                    .map_err(EntityError::Store)?;
            }
            for (index, data) in chunks.iter().enumerate() {
                tx.set_bytes(&data_key(&hash, head, index), data)
                    .await
                    .map_err(EntityError::Store)?;
            }
            tx.set_bytes(&meta_key(&hash, head), &meta_bytes)
                .await
                .map_err(EntityError::Store)?;
            let expected_head = match old_head {
                Some(value) => Some(
                    serde_json::to_vec(&value).map_err(|e| EntityError::Internal(e.to_string()))?,
                ),
                None => None,
            };
            tx.compare_and_set(&head_key(&hash), expected_head.as_deref(), &head_bytes)
                .await
                .map_err(EntityError::Store)?;
            tx.compare_and_set(
                &generation_key(&hash),
                expected_generation.as_deref(),
                &generation_bytes,
            )
            .await
            .map_err(EntityError::Store)?;
            match tx.commit().await {
                Ok(()) => return Ok(generation),
                Err(StoreError::TxConflict { key, current }) if key == head_key(&hash) => {
                    let stored = match current {
                        Some(bytes) => serde_json::from_slice::<u64>(&bytes)
                            .map_err(|e| EntityError::Internal(e.to_string()))?,
                        None => 0,
                    };
                    if head < stored {
                        return Err(EntityError::StaleHead {
                            stored,
                            incoming: head,
                        });
                    }
                }
                Err(StoreError::TxConflict { .. }) => {}
                Err(error) => return Err(EntityError::Store(error)),
            }
        }
        Err(EntityError::Internal(
            "replica put conflicted with another writer".to_string(),
        ))
    }

    /// Removes the stored replica for `sub`.
    ///
    /// The call reads the stored head and generation, then deletes the head
    /// row, the generation row, the manifest row for that head, and every
    /// chunk row for that head.
    /// All reads and deletes commit in one transaction.
    /// The call takes the store write guard for the whole operation, so a
    /// concurrent [`ReplicaStore::put`] and clear cannot leave a partial
    /// replica.
    /// The call returns `true` when a replica existed and was removed.
    /// It returns `false` when no head row existed, and it writes nothing.
    ///
    /// The removed keys are:
    ///
    /// - `replica:{sub_hash}:head`
    /// - `replica:{sub_hash}:generation`
    /// - `replica:{sub_hash}:meta:{head}`
    /// - `replica:{sub_hash}:data:{head}:{index:08}` for every chunk index
    ///
    /// A later build starts at generation 1.
    pub async fn clear(&self, sub: &str) -> Result<bool, EntityError> {
        let hash = sub_hash(sub);
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(EntityError::Store)?;
        let Some(head) = read_head(&tx, &hash).await? else {
            return Ok(false);
        };
        let _generation = read_generation(&tx, &hash).await?;
        let chunks = read_meta(&tx, &hash, head)
            .await?
            .map(|meta| meta.chunks)
            .unwrap_or(0);
        for index in 0..chunks {
            tx.delete(&data_key(&hash, head, index as usize))
                .await
                .map_err(EntityError::Store)?;
        }
        tx.delete(&meta_key(&hash, head))
            .await
            .map_err(EntityError::Store)?;
        tx.delete(&generation_key(&hash))
            .await
            .map_err(EntityError::Store)?;
        tx.delete(&head_key(&hash))
            .await
            .map_err(EntityError::Store)?;
        tx.commit().await.map_err(EntityError::Store)?;
        Ok(true)
    }

    /// Returns the stored snapshot for `sub`.
    ///
    /// The call returns `None` only when the subject has no replica.
    /// A `put` can replace the head or the generation while a read runs.
    /// The call reads the head, the generation, the manifest, every chunk, then
    /// the head and the generation again.
    /// It retries when the head, the generation, or a row changed or is absent.
    /// A missing generation row means a legacy replica at generation 0.
    /// A head and a generation that did not change name rows from the same
    /// committed snapshot, so the chunks are consistent.
    /// An equal-head rebuild changes the generation, so a read across it
    /// retries.
    /// The loop has a fixed limit.
    /// The call returns an internal error when every attempt loses the race.
    pub async fn get(&self, sub: &str) -> Result<Option<ReplicaSnapshot>, EntityError> {
        let hash = sub_hash(sub);
        let g = self.store.read().await;
        for _attempt in 0..GET_ATTEMPTS {
            let Some(head) = read_head(&*g, &hash).await? else {
                return Ok(None);
            };
            let generation = read_generation(&*g, &hash).await?.unwrap_or(0);
            let Some(meta) = read_meta(&*g, &hash, head).await? else {
                continue;
            };
            let chunks = decode_chunk_count(meta)?;
            let mut data = Vec::with_capacity(chunks);
            let mut missing = false;
            for index in 0..chunks {
                match g
                    .get_bytes(&data_key(&hash, head, index))
                    .await
                    .map_err(EntityError::Store)?
                {
                    Some(chunk) => data.push(chunk),
                    None => {
                        missing = true;
                        break;
                    }
                }
            }
            #[cfg(test)]
            if let Some(hook) = &self.read_hook {
                hook(&g, _attempt).await;
            }
            if read_head(&*g, &hash).await? != Some(head) {
                continue;
            }
            if read_generation(&*g, &hash).await?.unwrap_or(0) != generation {
                continue;
            }
            if missing {
                continue;
            }
            return Ok(Some(ReplicaSnapshot {
                head,
                generation,
                chunks: data,
            }));
        }
        Err(EntityError::Internal(
            "replica read did not settle".to_string(),
        ))
    }

    /// Returns one stored chunk for `sub`.
    ///
    /// The call returns `None` when the subject has no replica or when `index`
    /// is out of range.
    /// The call reads the head, the generation, the manifest, one chunk, then
    /// the head and the generation again.
    /// It retries when the head, the generation, or a row changed or is absent.
    /// A missing generation row means a legacy replica at generation 0.
    /// The loop has a fixed limit.
    /// The call returns an internal error when every attempt loses the race.
    pub async fn get_chunk(
        &self,
        sub: &str,
        index: usize,
    ) -> Result<Option<ReplicaChunk>, EntityError> {
        let hash = sub_hash(sub);
        let g = self.store.read().await;
        for _attempt in 0..GET_ATTEMPTS {
            let Some(head) = read_head(&*g, &hash).await? else {
                return Ok(None);
            };
            let generation = read_generation(&*g, &hash).await?.unwrap_or(0);
            let Some(meta) = read_meta(&*g, &hash, head).await? else {
                continue;
            };
            let chunks = decode_chunk_count(meta)?;
            if index >= chunks {
                if read_head(&*g, &hash).await? != Some(head) {
                    continue;
                }
                if read_generation(&*g, &hash).await?.unwrap_or(0) != generation {
                    continue;
                }
                return Ok(None);
            }
            let data = g
                .get_bytes(&data_key(&hash, head, index))
                .await
                .map_err(EntityError::Store)?;
            #[cfg(test)]
            if let Some(hook) = &self.read_hook {
                hook(&g, _attempt).await;
            }
            if read_head(&*g, &hash).await? != Some(head) {
                continue;
            }
            if read_generation(&*g, &hash).await?.unwrap_or(0) != generation {
                continue;
            }
            let Some(data) = data else {
                continue;
            };
            return Ok(Some(ReplicaChunk {
                head,
                generation,
                index,
                chunks,
                data,
            }));
        }
        Err(EntityError::Internal(
            "replica read did not settle".to_string(),
        ))
    }

    /// Returns the stored head for `sub`, or `None` when no replica exists.
    pub async fn status(&self, sub: &str) -> Result<Option<u64>, EntityError> {
        let hash = sub_hash(sub);
        let g = self.store.read().await;
        read_head(&*g, &hash).await
    }
}

/// Converts a manifest chunk count to a row index count.
fn decode_chunk_count(meta: ReplicaMeta) -> Result<usize, EntityError> {
    usize::try_from(meta.chunks).map_err(|e| EntityError::Internal(e.to_string()))
}

/// Returns the lowercase SHA-256 hex of `sub`.
fn sub_hash(sub: &str) -> String {
    Sha256::digest(sub.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Returns the head key for one subject hash.
fn head_key(hash: &str) -> String {
    format!("replica:{hash}:head")
}

/// Returns the generation key for one subject hash.
fn generation_key(hash: &str) -> String {
    format!("replica:{hash}:generation")
}

/// Returns the manifest key for one subject hash and head.
fn meta_key(hash: &str, head: u64) -> String {
    format!("replica:{hash}:meta:{head}")
}

/// Returns the data key for one subject hash, head, and chunk index.
fn data_key(hash: &str, head: u64, index: usize) -> String {
    format!("replica:{hash}:data:{head}:{index:08}")
}

/// Reads and decodes the head row for one subject hash.
async fn read_head<S>(store: &S, hash: &str) -> Result<Option<u64>, EntityError>
where
    S: GetSet + ?Sized,
{
    let Some(bytes) = store
        .get_bytes(&head_key(hash))
        .await
        .map_err(EntityError::Store)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| EntityError::Internal(e.to_string()))
}

/// Reads and decodes the manifest row for one subject hash and head.
async fn read_meta<S>(store: &S, hash: &str, head: u64) -> Result<Option<ReplicaMeta>, EntityError>
where
    S: GetSet + ?Sized,
{
    let Some(bytes) = store
        .get_bytes(&meta_key(hash, head))
        .await
        .map_err(EntityError::Store)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| EntityError::Internal(e.to_string()))
}

/// Reads and decodes the generation row for one subject hash.
async fn read_generation<S>(store: &S, hash: &str) -> Result<Option<u64>, EntityError>
where
    S: GetSet + ?Sized,
{
    let Some(bytes) = store
        .get_bytes(&generation_key(hash))
        .await
        .map_err(EntityError::Store)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| EntityError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{build_test_store, test_prefix};

    async fn store() -> ReplicaStore {
        ReplicaStore::new(build_test_store(&test_prefix("eav-replica")).await)
    }

    fn chunks(values: &[&[u8]]) -> Vec<Vec<u8>> {
        values.iter().map(|value| value.to_vec()).collect()
    }

    /// Writes a replica as an older build did: head, manifest, and chunks, with
    /// no generation row.
    async fn seed_legacy_replica(store: &ReplicaStore, sub: &str, head: u64, values: &[&[u8]]) {
        let hash = sub_hash(sub);
        let g = store.store.write().await;
        g.set_bytes(&head_key(&hash), head.to_string().as_bytes())
            .await
            .unwrap();
        g.set_bytes(
            &meta_key(&hash, head),
            format!("{{\"chunks\":{}}}", values.len()).as_bytes(),
        )
        .await
        .unwrap();
        for (index, value) in values.iter().enumerate() {
            g.set_bytes(&data_key(&hash, head, index), value)
                .await
                .unwrap();
        }
        assert!(
            g.get_bytes(&generation_key(&hash)).await.unwrap().is_none(),
            "the legacy replica must have no generation row"
        );
    }

    #[tokio::test]
    async fn get_returns_a_legacy_replica_at_generation_zero() {
        let store = store().await;
        seed_legacy_replica(&store, "alice", 7, &[b"one", b"two"]).await;

        let snapshot = store.get("alice").await.unwrap().expect("snapshot");

        assert_eq!(snapshot.head, 7);
        assert_eq!(snapshot.generation, 0);
        assert_eq!(snapshot.chunks, chunks(&[b"one", b"two"]));
    }

    #[tokio::test]
    async fn get_chunk_returns_a_legacy_chunk_at_generation_zero() {
        let store = store().await;
        seed_legacy_replica(&store, "alice", 7, &[b"one", b"two"]).await;

        let chunk = store.get_chunk("alice", 1).await.unwrap().expect("chunk");

        assert_eq!(chunk.head, 7);
        assert_eq!(chunk.generation, 0);
        assert_eq!(chunk.index, 1);
        assert_eq!(chunk.chunks, 2);
        assert_eq!(chunk.data, b"two".to_vec());
    }

    #[tokio::test]
    async fn a_put_after_a_legacy_replica_writes_generation_one() {
        let store = store().await;
        seed_legacy_replica(&store, "alice", 7, &[b"old"]).await;

        assert_eq!(store.put("alice", 8, chunks(&[b"new"])).await.unwrap(), 1);

        let snapshot = store.get("alice").await.unwrap().expect("snapshot");

        assert_eq!(snapshot.head, 8);
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.chunks, chunks(&[b"new"]));
    }

    #[tokio::test]
    async fn put_stores_the_head_and_the_chunks() {
        let store = store().await;
        store
            .put("alice", 7, chunks(&[b"[{\"id\":\"e1\"}]"]))
            .await
            .unwrap();

        assert_eq!(
            store.get("alice").await.unwrap(),
            Some(ReplicaSnapshot {
                head: 7,
                generation: 1,
                chunks: chunks(&[b"[{\"id\":\"e1\"}]"]),
            })
        );
        assert_eq!(store.status("alice").await.unwrap(), Some(7));
    }

    #[tokio::test]
    async fn a_missing_replica_returns_none() {
        let store = store().await;

        assert_eq!(store.get("alice").await.unwrap(), None);
        assert_eq!(store.get_chunk("alice", 0).await.unwrap(), None);
        assert_eq!(store.status("alice").await.unwrap(), None);
    }

    #[tokio::test]
    async fn one_user_cannot_read_the_replica_of_another_user() {
        let store = store().await;
        store
            .put("alice", 3, chunks(&[b"alice-data"]))
            .await
            .unwrap();

        assert_eq!(store.get("bob").await.unwrap(), None);
        assert_eq!(store.get_chunk("bob", 0).await.unwrap(), None);
        assert_eq!(store.status("bob").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_three_chunk_put_returns_the_chunks_in_order() {
        let store = store().await;
        store
            .put("alice", 11, chunks(&[b"one", b"two", b"three"]))
            .await
            .unwrap();

        let snapshot = store.get("alice").await.unwrap().expect("snapshot");

        assert_eq!(snapshot.head, 11);
        assert_eq!(snapshot.chunks, chunks(&[b"one", b"two", b"three"]));
    }

    #[tokio::test]
    async fn get_chunk_returns_one_chunk_and_rejects_an_out_of_range_index() {
        let store = store().await;
        store
            .put("alice", 11, chunks(&[b"one", b"two", b"three"]))
            .await
            .unwrap();

        let chunk = store.get_chunk("alice", 1).await.unwrap().expect("chunk");

        assert_eq!(chunk.head, 11);
        assert_eq!(chunk.index, 1);
        assert_eq!(chunk.chunks, 3);
        assert_eq!(chunk.data, b"two".to_vec());
        assert_eq!(store.get_chunk("alice", 3).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_second_put_replaces_the_head_and_keeps_the_new_data() {
        let store = store().await;
        store.put("alice", 3, chunks(&[b"old"])).await.unwrap();
        store
            .put("alice", 9, chunks(&[b"new", b"data"]))
            .await
            .unwrap();

        assert_eq!(
            store.get("alice").await.unwrap(),
            Some(ReplicaSnapshot {
                head: 9,
                generation: 2,
                chunks: chunks(&[b"new", b"data"]),
            })
        );
    }

    #[tokio::test]
    async fn a_second_put_deletes_every_old_chunk_row_and_the_old_manifest() {
        let store = store().await;
        store
            .put("alice", 3, chunks(&[b"old-0", b"old-1", b"old-2"]))
            .await
            .unwrap();
        store.put("alice", 9, chunks(&[b"new"])).await.unwrap();

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        for index in 0..3 {
            assert!(
                g.get_bytes(&data_key(&hash, 3, index))
                    .await
                    .unwrap()
                    .is_none(),
                "old chunk row {index} remains"
            );
        }
        assert!(
            g.get_bytes(&meta_key(&hash, 3)).await.unwrap().is_none(),
            "old manifest row remains"
        );
        assert_eq!(
            g.get_bytes(&data_key(&hash, 9, 0)).await.unwrap(),
            Some(b"new".to_vec())
        );
        assert_eq!(
            g.get_bytes(&meta_key(&hash, 9)).await.unwrap(),
            Some(br#"{"chunks":1}"#.to_vec())
        );
    }

    #[tokio::test]
    async fn clear_removes_the_head_the_generation_the_manifest_and_every_chunk() {
        let store = store().await;
        store
            .put("alice", 7, chunks(&[b"one", b"two"]))
            .await
            .unwrap();

        assert!(store.clear("alice").await.unwrap());

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        assert!(g.get_bytes(&head_key(&hash)).await.unwrap().is_none());
        assert!(g.get_bytes(&generation_key(&hash)).await.unwrap().is_none());
        assert!(g.get_bytes(&meta_key(&hash, 7)).await.unwrap().is_none());
        for index in 0..2 {
            assert!(
                g.get_bytes(&data_key(&hash, 7, index))
                    .await
                    .unwrap()
                    .is_none(),
                "chunk row {index} remains"
            );
        }
        drop(g);
        assert_eq!(store.get("alice").await.unwrap(), None);
        assert_eq!(store.get_chunk("alice", 0).await.unwrap(), None);
        assert_eq!(store.status("alice").await.unwrap(), None);
    }

    #[tokio::test]
    async fn clear_after_a_multi_chunk_put_removes_every_chunk() {
        let store = store().await;
        store
            .put("alice", 12, chunks(&[b"one", b"two", b"three", b"four"]))
            .await
            .unwrap();

        assert!(store.clear("alice").await.unwrap());

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        for index in 0..4 {
            assert!(
                g.get_bytes(&data_key(&hash, 12, index))
                    .await
                    .unwrap()
                    .is_none(),
                "chunk row {index} remains"
            );
        }
        assert_eq!(store.status("alice").await.unwrap(), None);
    }

    #[tokio::test]
    async fn clear_on_a_missing_replica_returns_false_and_writes_nothing() {
        let store = store().await;

        assert!(!store.clear("alice").await.unwrap());

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        assert!(g.get_bytes(&head_key(&hash)).await.unwrap().is_none());
        assert!(g.get_bytes(&generation_key(&hash)).await.unwrap().is_none());
        assert!(g.get_bytes(&meta_key(&hash, 0)).await.unwrap().is_none());
        assert!(g.get_bytes(&data_key(&hash, 0, 0)).await.unwrap().is_none());
        drop(g);
        assert_eq!(store.status("alice").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_stale_put_keeps_the_old_chunks_and_head() {
        let store = store().await;
        store
            .put("alice", 9, chunks(&[b"new-0", b"new-1"]))
            .await
            .unwrap();

        let error = store
            .put("alice", 3, chunks(&[b"old-0", b"old-1", b"old-2"]))
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                EntityError::StaleHead {
                    stored: 9,
                    incoming: 3
                }
            ),
            "unexpected error: {error}"
        );
        assert_eq!(
            store.get("alice").await.unwrap(),
            Some(ReplicaSnapshot {
                head: 9,
                generation: 1,
                chunks: chunks(&[b"new-0", b"new-1"]),
            })
        );
        assert_eq!(store.status("alice").await.unwrap(), Some(9));

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        for index in 0..3 {
            assert!(
                g.get_bytes(&data_key(&hash, 3, index))
                    .await
                    .unwrap()
                    .is_none(),
                "stale chunk row {index} was written"
            );
        }
        assert!(
            g.get_bytes(&meta_key(&hash, 3)).await.unwrap().is_none(),
            "stale manifest row was written"
        );
        assert_eq!(
            g.get_bytes(&meta_key(&hash, 9)).await.unwrap(),
            Some(br#"{"chunks":2}"#.to_vec())
        );
    }

    #[tokio::test]
    async fn a_zero_chunk_replica_reports_zero_and_returns_no_chunks() {
        let store = store().await;
        store.put("alice", 5, Vec::new()).await.unwrap();

        assert_eq!(
            store.get("alice").await.unwrap(),
            Some(ReplicaSnapshot {
                head: 5,
                generation: 1,
                chunks: Vec::new(),
            })
        );
        assert_eq!(store.get_chunk("alice", 0).await.unwrap(), None);

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        assert_eq!(
            g.get_bytes(&meta_key(&hash, 5)).await.unwrap(),
            Some(br#"{"chunks":0}"#.to_vec())
        );
        assert!(
            g.get_bytes(&data_key(&hash, 5, 0)).await.unwrap().is_none(),
            "a zero-chunk replica wrote a chunk row"
        );
    }

    #[tokio::test]
    async fn a_same_head_put_replaces_the_old_chunks() {
        let store = store().await;
        store
            .put("alice", 4, chunks(&[b"old-0", b"old-1", b"old-2"]))
            .await
            .unwrap();
        store.put("alice", 4, chunks(&[b"new-0"])).await.unwrap();

        assert_eq!(
            store.get("alice").await.unwrap(),
            Some(ReplicaSnapshot {
                head: 4,
                generation: 2,
                chunks: chunks(&[b"new-0"]),
            })
        );

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        for index in 1..3 {
            assert!(
                g.get_bytes(&data_key(&hash, 4, index))
                    .await
                    .unwrap()
                    .is_none(),
                "old chunk row {index} remains"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_get_during_concurrent_puts_never_mixes_heads() {
        let store = store().await;
        store
            .put("alice", 0, chunks(&[b"v0-0", b"v0-1", b"v0-2"]))
            .await
            .unwrap();

        let writer = store.clone();
        let writer = tokio::spawn(async move {
            for head in 1..=25u64 {
                let data = chunks(&[
                    format!("v{head}-0").as_bytes(),
                    format!("v{head}-1").as_bytes(),
                    format!("v{head}-2").as_bytes(),
                ]);
                writer.put("alice", head, data).await.unwrap();
            }
        });

        let reader = store.clone();
        let reader = tokio::spawn(async move {
            for _ in 0..200 {
                let got = reader.get("alice").await.unwrap();
                let snapshot = got.expect("get returned None while a replica exists");
                assert_eq!(snapshot.chunks.len(), 3);
                for (index, chunk) in snapshot.chunks.iter().enumerate() {
                    assert_eq!(
                        chunk,
                        &format!("v{}-{index}", snapshot.head).into_bytes(),
                        "chunk {index} came from another head"
                    );
                }
            }
        });

        writer.await.unwrap();
        reader.await.unwrap();
        assert_eq!(
            store.get("alice").await.unwrap(),
            Some(ReplicaSnapshot {
                head: 25,
                generation: 26,
                chunks: chunks(&[b"v25-0", b"v25-1", b"v25-2"]),
            })
        );
    }

    #[tokio::test]
    async fn the_first_put_writes_generation_one_and_the_next_put_increments_it() {
        let store = store().await;

        assert_eq!(store.put("alice", 3, chunks(&[b"one"])).await.unwrap(), 1);
        assert_eq!(store.put("alice", 4, chunks(&[b"two"])).await.unwrap(), 2);

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        assert_eq!(
            g.get_bytes(&generation_key(&hash)).await.unwrap(),
            Some(b"2".to_vec())
        );
    }

    #[tokio::test]
    async fn a_stale_put_does_not_change_the_head_the_generation_or_the_chunks() {
        let store = store().await;
        store
            .put("alice", 9, chunks(&[b"new-0", b"new-1"]))
            .await
            .unwrap();

        let error = store
            .put("alice", 3, chunks(&[b"old-0"]))
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                EntityError::StaleHead {
                    stored: 9,
                    incoming: 3
                }
            ),
            "unexpected error: {error}"
        );
        assert_eq!(
            store.get("alice").await.unwrap(),
            Some(ReplicaSnapshot {
                head: 9,
                generation: 1,
                chunks: chunks(&[b"new-0", b"new-1"]),
            })
        );

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        assert_eq!(
            g.get_bytes(&generation_key(&hash)).await.unwrap(),
            Some(b"1".to_vec()),
            "a stale put changed the generation"
        );
    }

    #[tokio::test]
    async fn concurrent_puts_keep_the_higher_head() {
        let raw = build_test_store(&test_prefix("eav-replica-race")).await;
        let higher = ReplicaStore::new(raw.clone());
        let lower = ReplicaStore::new(raw.clone());

        let high = tokio::spawn(async move { higher.put("alice", 9, chunks(&[b"high"])).await });
        let low = tokio::spawn(async move { lower.put("alice", 3, chunks(&[b"low"])).await });
        let (high_result, low_result) = tokio::join!(high, low);

        high_result.unwrap().unwrap();
        let _ = low_result.unwrap();
        let snapshot = ReplicaStore::new(raw)
            .get("alice")
            .await
            .unwrap()
            .expect("the higher head must stay");
        assert_eq!(snapshot.head, 9);
        assert_eq!(snapshot.chunks, chunks(&[b"high"]));
    }

    #[tokio::test]
    async fn a_same_head_put_replaces_the_content_and_increments_the_generation() {
        let store = store().await;
        store
            .put("alice", 4, chunks(&[b"old-0", b"old-1"]))
            .await
            .unwrap();

        assert_eq!(store.put("alice", 4, chunks(&[b"new-0"])).await.unwrap(), 2);

        let snapshot = store.get("alice").await.unwrap().expect("snapshot");

        assert_eq!(snapshot.head, 4);
        assert_eq!(snapshot.generation, 2);
        assert_eq!(snapshot.chunks, chunks(&[b"new-0"]));
    }

    #[tokio::test]
    async fn get_returns_the_generation_with_the_snapshot() {
        let store = store().await;
        store
            .put("alice", 7, chunks(&[b"one", b"two"]))
            .await
            .unwrap();

        let snapshot = store.get("alice").await.unwrap().expect("snapshot");

        assert_eq!(snapshot.head, 7);
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.chunks, chunks(&[b"one", b"two"]));
    }

    #[tokio::test]
    async fn get_chunk_returns_the_generation() {
        let store = store().await;
        store.put("alice", 5, chunks(&[b"one"])).await.unwrap();
        store
            .put("alice", 6, chunks(&[b"one", b"two"]))
            .await
            .unwrap();

        let chunk = store.get_chunk("alice", 1).await.unwrap().expect("chunk");

        assert_eq!(chunk.head, 6);
        assert_eq!(chunk.generation, 2);
        assert_eq!(chunk.index, 1);
        assert_eq!(chunk.chunks, 2);
        assert_eq!(chunk.data, b"two".to_vec());
    }

    /// The hook writes a new generation after the chunk read.
    /// The shared store lock would stop a second writer, so the test uses the
    /// hook instead of a second store session.
    #[tokio::test]
    async fn a_read_retries_when_the_generation_changes_under_it() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let store = store().await;
        store.put("alice", 5, chunks(&[b"one"])).await.unwrap();
        let hash = sub_hash("alice");
        let generation_key = generation_key(&hash);
        let calls = Arc::new(AtomicU32::new(0));
        let hook_calls = Arc::clone(&calls);
        let hook: ReadHook = Arc::new(move |store, _attempt| {
            let calls = Arc::clone(&hook_calls);
            let generation_key = generation_key.clone();
            Box::pin(async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    // Simulate an equal-head rebuild that changes only the
                    // generation.
                    store
                        .set_bytes(&generation_key, b"2")
                        .await
                        .expect("hook write");
                }
            })
        });
        let store = store.with_read_hook(hook);

        let snapshot = store.get("alice").await.unwrap().expect("snapshot");

        assert_eq!(snapshot.head, 5);
        assert_eq!(snapshot.generation, 2);
        assert_eq!(snapshot.chunks, chunks(&[b"one"]));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the read must retry after the generation changes"
        );
    }

    #[test]
    fn the_subject_hash_is_lowercase_hex_of_length_64() {
        let hash = sub_hash("alice");

        assert_eq!(hash.len(), 64);
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(hash, sub_hash("bob"));
    }
}
