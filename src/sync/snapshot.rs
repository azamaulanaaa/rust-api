//! Per-user filtered snapshots as `Redb` files on `S3`.
//!
//! Master stays `Redb` file; snapshots are `Redb` files cached as `S3` objects.
//! Full recalc when far behind; WAL replay later via `wal` range.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fs::error::FsError;
use crate::fs::s3::S3Client;
use crate::fs::store::FsStore;
use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, PolicyEngine};

use super::wal::Wal;

/// Snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMeta {
    /// Master `wal` head at build time.
    pub applied_seq: u64,
    /// Snapshot version (same as `applied_seq`).
    pub version: u64,
}

/// Manager for per-user snapshots.
#[derive(Clone)]
pub struct SnapshotManager {
    /// WAL for version tracking.
    pub wal: Wal,
    /// Master file store.
    pub store: FsStore,
    /// Policy for filtering.
    pub policy: PolicyEngine,
    /// `S3` client for snapshot objects.
    pub s3: std::sync::Arc<dyn S3Client>,
    /// Bucket for snapshots.
    pub bucket: String,
}

impl SnapshotManager {
    /// Create a manager.
    pub fn new(
        wal: Wal,
        store: FsStore,
        policy: PolicyEngine,
        s3: std::sync::Arc<dyn S3Client>,
        bucket: String,
    ) -> Self {
        Self {
            wal,
            store,
            policy,
            s3,
            bucket,
        }
    }

    /// `S3` key for a snapshot.
    pub fn snapshot_key(sub: &str, seq: u64) -> String {
        format!("snapshots/{sub}/{seq:020}.redb")
    }

    /// `S3` key for metadata.
    pub fn meta_key(sub: &str) -> String {
        format!("snapshots/{sub}/meta.json")
    }

    /// Load metadata from `S3`.
    pub async fn load_meta(&self, sub: &str) -> Result<Option<SnapshotMeta>, FsError> {
        let key = Self::meta_key(sub);
        match self.s3.get_object(&self.bucket, &key).await {
            Ok(b) => Ok(serde_json::from_slice(&b).ok()),
            Err(FsError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Build a full filtered snapshot for `sub` at current `wal` head.
    pub async fn build_full(&self, sub: &str) -> Result<SnapshotMeta, FsError> {
        let seq = self.wal.head().await?;
        let tmp = std::env::temp_dir().join(format!(
            "snapshot-{}-{seq}.redb",
            sub.replace(['/', ':'], "_")
        ));
        let _ = std::fs::remove_file(&tmp);
        let snap_store = FsStore::open(&tmp).await?;
        self.copy_filtered(sub, &snap_store).await?;
        let data = std::fs::read(&tmp).map_err(|e| FsError::Internal(e.to_string()))?;
        let key = Self::snapshot_key(sub, seq);
        self.s3
            .put_object(&self.bucket, &key, data.into(), None, None)
            .await?;
        let meta = SnapshotMeta {
            applied_seq: seq,
            version: seq,
        };
        let meta_bytes = serde_json::to_vec(&meta).map_err(|e| FsError::Internal(e.to_string()))?;
        self.s3
            .put_object(
                &self.bucket,
                &Self::meta_key(sub),
                meta_bytes.into(),
                None,
                None,
            )
            .await?;
        let _ = std::fs::remove_file(&tmp);
        Ok(meta)
    }

    async fn copy_filtered(&self, sub: &str, dst: &FsStore) -> Result<(), FsError> {
        for rec in self.store.list_files().await? {
            if !self.can_read(sub, &rec.id).await? {
                continue;
            }
            dst.save_file(&rec).await?;
            let info = self.store.get_ref_info(&rec.id).await?;
            if info.count > 0 {
                // copy relations where row readable
                for (ty, rid) in self.store.rows_for_file(&rec.id).await? {
                    if self
                        .policy
                        .authorize_row(sub, &ty, &rid, Action::Read)
                        .await
                        .unwrap_or(false)
                    {
                        dst.attach(&ty, &rid, &rec.id).await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn can_read(&self, sub: &str, file_id: &str) -> Result<bool, FsError> {
        let Some(rec) = self.store.get_file(file_id).await? else {
            return Ok(false);
        };
        if rec.owner_sub == sub {
            return Ok(true);
        }
        for (ty, rid) in self.store.rows_for_file(file_id).await? {
            if self
                .policy
                .authorize_row(sub, &ty, &rid, Action::Read)
                .await
                .unwrap_or(false)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Remove temp file helper.
    pub fn _tmp_path(_sub: &str) -> std::path::PathBuf {
        Path::new("").to_path_buf()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fs::object_store::ObjectStoreClient;
    use crate::fs::store::{FileRecord, FsStore};
    use crate::policy::{Action, PolicyEngine};

    fn tmp_path(label: &str) -> std::path::PathBuf {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        std::env::temp_dir().join(format!(
            "snap-test-{}-{}-{}.redb",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>()),
            label
        ))
    }

    #[tokio::test]
    async fn build_full_filters() -> anyhow::Result<()> {
        let wal_path = tmp_path("wal");
        let _ = std::fs::remove_file(&wal_path);
        let wal = Wal::open(&wal_path).await?;
        let store_path = tmp_path("store");
        let _ = std::fs::remove_file(&store_path);
        let store = FsStore::open(&store_path).await?;
        let policy_path = tmp_path("policy");
        let _ = std::fs::remove_file(&policy_path);
        let policy = PolicyEngine::init(&policy_path).await?;
        policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        let rec = FileRecord {
            id: "f1".into(),
            name: "a".into(),
            mimetype: "x".into(),
            size: 1,
            s3_key: "k".into(),
            owner_sub: "alice".into(),
            created_at: 0,
        };
        store.save_file(&rec).await?;
        store.attach("invoice", "1", "f1").await?;
        let rec2 = FileRecord {
            id: "f2".into(),
            name: "b".into(),
            mimetype: "x".into(),
            size: 1,
            s3_key: "k2".into(),
            owner_sub: "bob".into(),
            created_at: 0,
        };
        store.save_file(&rec2).await?;
        let s3 = ObjectStoreClient::in_memory();
        let mgr = SnapshotManager::new(wal, store, policy, s3, "b".into());
        let meta = mgr.build_full("alice").await?;
        assert_eq!(meta.applied_seq, 0);
        let loaded = mgr.load_meta("alice").await?.unwrap();
        assert_eq!(loaded.version, 0);
        let _ = std::fs::remove_file(&wal_path);
        let _ = std::fs::remove_file(&store_path);
        let _ = std::fs::remove_file(&policy_path);
        Ok(())
    }
}
