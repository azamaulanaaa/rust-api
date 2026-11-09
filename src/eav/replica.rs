//! Stored per-user entity replicas.
//!
//! A replica is a point-in-time JSON snapshot, not an incremental store.
//! The client builds one replica, then applies the event feed for each delta.
//! The store keeps one head row and one data row for each subject.
//! The head row points to the data row.
//! Both rows commit in one transaction.
//!
//! Keys:
//!
//! - `replica:{sub_hash}:head` holds a JSON `u64`.
//! - `replica:{sub_hash}:data:{head}` holds the JSON bytes.
//!
//! `sub_hash` is the lowercase SHA-256 hex of the subject.
//! The hash keeps the subject text out of the key.
//!
//! The store adds no business logic.
//! It does not filter the data and it does not read the event feed.

use std::sync::Arc;

use oxkv::{GetSet, OxKvStore, Store as _, Transaction as _};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::eav::entity_error::EntityError;

/// A stored per-user entity replica.
///
/// A build replaces the previous snapshot for the same subject.
/// A get reads the head first, then the data row that the head names.
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

    /// Stores one JSON snapshot for `sub` at `head`.
    ///
    /// The data row and the head row commit in one transaction.
    /// The head row points to the data row.
    /// A later build replaces the head and writes a new data row.
    /// The same transaction deletes the old data row.
    pub async fn put(&self, sub: &str, head: u64, data: Vec<u8>) -> Result<(), EntityError> {
        let hash = sub_hash(sub);
        let head_bytes =
            serde_json::to_vec(&head).map_err(|e| EntityError::Internal(e.to_string()))?;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(EntityError::Store)?;
        let old_head = read_head(&tx, &hash).await?;
        tx.set_bytes(&data_key(&hash, head), &data)
            .await
            .map_err(EntityError::Store)?;
        tx.set_bytes(&head_key(&hash), &head_bytes)
            .await
            .map_err(EntityError::Store)?;
        if let Some(old_head) = old_head
            && old_head != head
        {
            tx.delete(&data_key(&hash, old_head))
                .await
                .map_err(EntityError::Store)?;
        }
        tx.commit().await.map_err(EntityError::Store)?;
        Ok(())
    }

    /// Returns the stored head and JSON bytes for `sub`.
    ///
    /// The call returns `None` when the head or the data row is absent.
    pub async fn get(&self, sub: &str) -> Result<Option<(u64, Vec<u8>)>, EntityError> {
        let hash = sub_hash(sub);
        let g = self.store.read().await;
        let Some(head) = read_head(&*g, &hash).await? else {
            return Ok(None);
        };
        let Some(data) = g
            .get_bytes(&data_key(&hash, head))
            .await
            .map_err(EntityError::Store)?
        else {
            return Ok(None);
        };
        Ok(Some((head, data)))
    }

    /// Returns the stored head for `sub`, or `None` when no replica exists.
    pub async fn status(&self, sub: &str) -> Result<Option<u64>, EntityError> {
        let hash = sub_hash(sub);
        let g = self.store.read().await;
        read_head(&*g, &hash).await
    }
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

/// Returns the data key for one subject hash and head.
fn data_key(hash: &str, head: u64) -> String {
    format!("replica:{hash}:data:{head}")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{build_test_store, test_prefix};

    async fn store() -> ReplicaStore {
        ReplicaStore::new(build_test_store(&test_prefix("eav-replica")).await)
    }

    #[tokio::test]
    async fn put_stores_the_head_and_the_data() {
        let store = store().await;
        store
            .put("alice", 7, b"[{\"id\":\"e1\"}]".to_vec())
            .await
            .unwrap();

        assert_eq!(
            store.get("alice").await.unwrap(),
            Some((7, b"[{\"id\":\"e1\"}]".to_vec()))
        );
        assert_eq!(store.status("alice").await.unwrap(), Some(7));
    }

    #[tokio::test]
    async fn a_missing_replica_returns_none() {
        let store = store().await;

        assert_eq!(store.get("alice").await.unwrap(), None);
        assert_eq!(store.status("alice").await.unwrap(), None);
    }

    #[tokio::test]
    async fn one_user_cannot_read_the_replica_of_another_user() {
        let store = store().await;
        store.put("alice", 3, b"alice-data".to_vec()).await.unwrap();

        assert_eq!(store.get("bob").await.unwrap(), None);
        assert_eq!(store.status("bob").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_second_put_replaces_the_head_and_keeps_the_new_data() {
        let store = store().await;
        store.put("alice", 3, b"old".to_vec()).await.unwrap();
        store.put("alice", 9, b"new".to_vec()).await.unwrap();

        assert_eq!(
            store.get("alice").await.unwrap(),
            Some((9, b"new".to_vec()))
        );
    }

    #[tokio::test]
    async fn a_second_put_removes_the_old_data_row() {
        let store = store().await;
        store.put("alice", 3, b"old".to_vec()).await.unwrap();
        store.put("alice", 9, b"new".to_vec()).await.unwrap();

        let hash = sub_hash("alice");
        let g = store.store.read().await;
        assert!(
            g.get_bytes(&data_key(&hash, 3)).await.unwrap().is_none(),
            "old data row remains"
        );
        assert_eq!(
            g.get_bytes(&data_key(&hash, 9)).await.unwrap(),
            Some(b"new".to_vec())
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
