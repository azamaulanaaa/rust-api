//! Stored per-user entity replicas.
//!
//! A replica is a point-in-time JSON snapshot, not an incremental store.
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
//! - `replica:{sub_hash}:meta:{head}` holds JSON `{ "chunks": u64 }`.
//! - `replica:{sub_hash}:data:{head}:{index:08}` holds one JSON chunk.
//!
//! The chunk index is zero-based and zero-padded, so key order equals chunk
//! order.
//! `sub_hash` is the lowercase SHA-256 hex of the subject.
//! The hash keeps the subject text out of the key.
//!
//! A put writes every chunk, the manifest, and the head in one transaction.
//! The same transaction deletes the old manifest and every old chunk row.
//! A head equal to the stored head replaces the snapshot.
//!
//! A read sees consistent chunks when the head does not change during the
//! read.
//! The read checks the head before and after it reads the manifest and the
//! chunk rows.
//! It retries when the head changed or a row is absent.
//!
//! The store adds no business logic.
//! It does not filter the data and it does not read the event feed.

use std::sync::Arc;

use oxkv::{GetSet, OxKvStore, Store as _, Transaction as _};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::eav::entity_error::EntityError;

/// The number of times a read tries to read one consistent snapshot.
const GET_ATTEMPTS: u32 = 16;

/// One stored replica snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaSnapshot {
    /// The head of the stored replica.
    pub head: u64,
    /// The JSON chunks in index order.
    pub chunks: Vec<Vec<u8>>,
}

/// One stored replica chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaChunk {
    /// The head of the stored replica.
    pub head: u64,
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

/// A stored per-user entity replica.
///
/// A build replaces the previous snapshot for the same subject.
/// A build with a lower head fails with [`EntityError::StaleHead`].
/// A read checks the head before and after it reads the manifest and the
/// chunk rows.
/// It retries when the head changed or a row is absent.
/// All rows commit in one transaction, so a head that did not change names
/// rows from the same snapshot.
#[derive(Clone)]
pub struct ReplicaStore {
    /// The shared replica store handle.
    store: Arc<RwLock<OxKvStore>>,
}

impl ReplicaStore {
    /// Creates a store over `store`.
    pub fn new(store: OxKvStore) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
        }
    }

    /// Stores `chunks` for `sub` at `head`.
    ///
    /// Every chunk, the manifest, and the head commit in one transaction.
    /// The same transaction deletes the old manifest and every old chunk row.
    /// A `head` lower than the stored head is stale.
    /// A stale build returns [`EntityError::StaleHead`] and changes nothing.
    /// A `head` equal to the stored head replaces the snapshot.
    /// Thus the stored head never goes backwards.
    pub async fn put(&self, sub: &str, head: u64, chunks: Vec<Vec<u8>>) -> Result<(), EntityError> {
        let hash = sub_hash(sub);
        let head_bytes =
            serde_json::to_vec(&head).map_err(|e| EntityError::Internal(e.to_string()))?;
        let meta = ReplicaMeta {
            chunks: chunks.len() as u64,
        };
        let meta_bytes =
            serde_json::to_vec(&meta).map_err(|e| EntityError::Internal(e.to_string()))?;
        let g = self.store.write().await;
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
        tx.set_bytes(&head_key(&hash), &head_bytes)
            .await
            .map_err(EntityError::Store)?;
        tx.commit().await.map_err(EntityError::Store)?;
        Ok(())
    }

    /// Returns the stored snapshot for `sub`.
    ///
    /// The call returns `None` only when the subject has no replica.
    /// A `put` can replace the head while a read runs.
    /// The call reads the head, the manifest, every chunk, then the head
    /// again.
    /// It retries when the head changed or a row is absent.
    /// A head that did not change names rows from the same committed
    /// snapshot, so the chunks are consistent.
    /// The loop has a fixed limit.
    /// The call returns an internal error when every attempt loses the race.
    pub async fn get(&self, sub: &str) -> Result<Option<ReplicaSnapshot>, EntityError> {
        let hash = sub_hash(sub);
        let g = self.store.read().await;
        for _ in 0..GET_ATTEMPTS {
            let Some(head) = read_head(&*g, &hash).await? else {
                return Ok(None);
            };
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
            if read_head(&*g, &hash).await? != Some(head) {
                continue;
            }
            if missing {
                continue;
            }
            return Ok(Some(ReplicaSnapshot { head, chunks: data }));
        }
        Err(EntityError::Internal(
            "replica read did not settle".to_string(),
        ))
    }

    /// Returns one stored chunk for `sub`.
    ///
    /// The call returns `None` when the subject has no replica or when `index`
    /// is out of range.
    /// The call reads the head, the manifest, one chunk, then the head again.
    /// It retries when the head changed or a row is absent.
    /// The loop has a fixed limit.
    /// The call returns an internal error when every attempt loses the race.
    pub async fn get_chunk(
        &self,
        sub: &str,
        index: usize,
    ) -> Result<Option<ReplicaChunk>, EntityError> {
        let hash = sub_hash(sub);
        let g = self.store.read().await;
        for _ in 0..GET_ATTEMPTS {
            let Some(head) = read_head(&*g, &hash).await? else {
                return Ok(None);
            };
            let Some(meta) = read_meta(&*g, &hash, head).await? else {
                continue;
            };
            let chunks = decode_chunk_count(meta)?;
            if index >= chunks {
                if read_head(&*g, &hash).await? != Some(head) {
                    continue;
                }
                return Ok(None);
            }
            let data = g
                .get_bytes(&data_key(&hash, head, index))
                .await
                .map_err(EntityError::Store)?;
            if read_head(&*g, &hash).await? != Some(head) {
                continue;
            }
            let Some(data) = data else {
                continue;
            };
            return Ok(Some(ReplicaChunk {
                head,
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
                chunks: chunks(&[b"v25-0", b"v25-1", b"v25-2"]),
            })
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
