//! Per-user filtered replicas on versioned `OxKvStore` prefixes.
//!
//! The master [`FsStore`] remains the sole write path. Each snapshot version
//! is a filtered copy under `{db_prefix}/u/{sub}/{seq:020}/` with its own
//! oxkv `manifest.json` — the segment list. `snapshots/{sub}/meta.json`
//! points at the latest version. Version prefixes are immutable after build,
//! so readers always see a consistent view and old versions are cheap to GC.
//!
//! Served read-only via `/sync/db/`; wasm clients open an `OxKvReader` over
//! the version prefix and follow it like any other oxkv store.

use serde::{Deserialize, Serialize};

use crate::fs::error::FsError;
use crate::fs::s3::S3Client;
use crate::fs::store::FsStore;
use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, PolicyEngine};

use super::wal::Wal;

/// Snapshot metadata (pointer at the latest replica version for `sub`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotMeta {
    /// Master `wal` head at build time.
    pub applied_seq: u64,
    /// Snapshot version (same as `applied_seq`).
    pub version: u64,
}

/// Manager for per-user replicas.
#[derive(Clone)]
pub struct SnapshotManager {
    /// WAL for version tracking.
    pub wal: Wal,
    /// Master file store.
    pub store: FsStore,
    /// Policy for filtering.
    pub policy: PolicyEngine,
    /// `S3` client for `meta.json` pointers.
    pub s3: std::sync::Arc<dyn S3Client>,
    /// Bucket for `meta.json` pointers.
    pub bucket: String,
    /// Shared object store backing every replica prefix.
    pub(crate) object_store: std::sync::Arc<dyn object_store::ObjectStore>,
    /// Root prefix for replica prefixes (e.g. `"oxkv"`).
    pub(crate) db_prefix: String,
    /// Skip the oxkv storage probe (tests on `InMemory`).
    skip_probe: bool,
}

impl SnapshotManager {
    /// Create a manager.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wal: Wal,
        store: FsStore,
        policy: PolicyEngine,
        s3: std::sync::Arc<dyn S3Client>,
        bucket: String,
        object_store: std::sync::Arc<dyn object_store::ObjectStore>,
        db_prefix: String,
        skip_probe: bool,
    ) -> Self {
        Self {
            wal,
            store,
            policy,
            s3,
            bucket,
            object_store,
            db_prefix,
            skip_probe,
        }
    }

    /// Replica prefix for one snapshot version (`{db}/u/{sub}/{seq:020}`).
    pub fn user_prefix(&self, sub: &str, seq: u64) -> String {
        format!(
            "{}/u/{}/{seq:020}",
            self.db_prefix.trim_matches('/'),
            safe_sub(sub)
        )
    }

    /// Full object key for `tail` inside a version replica.
    ///
    /// Rejects path traversal (`..`) so the gateway cannot escape the
    /// version prefix.
    pub fn resolve_object(&self, sub: &str, seq: u64, tail: &str) -> Result<String, FsError> {
        if tail.is_empty() || tail.split('/').any(|seg| seg == "..") {
            return Err(FsError::BadRequest("invalid object path".into()));
        }
        Ok(format!("{}/{tail}", self.user_prefix(sub, seq)))
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

    /// Build a full filtered replica for `sub` at current `wal` head.
    ///
    /// Files are filtered through the policy into a fresh version prefix;
    /// the prefix is written once and never mutated afterwards, so readers
    /// see an atomic snapshot. `meta.json` is written last so the pointer
    /// cutover is atomic with the WAL head.
    pub async fn build_full(&self, sub: &str) -> Result<SnapshotMeta, FsError> {
        let seq = self.wal.head().await?;
        let prefix = self.user_prefix(sub, seq);
        let replica = oxkv::OxKvStore::builder()
            .with_object_store(self.object_store.clone())
            .with_prefix(oxkv::ObjectPath::from(prefix.as_str()))
            .skip_probe(self.skip_probe)
            .build()
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        self.copy_filtered(sub, &FsStore::new(replica)).await?;
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
}

/// Makes a subject safe for embedding in an object prefix.
fn safe_sub(sub: &str) -> String {
    sub.replace(['/', ':'], "_")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fs::object_store::ObjectStoreClient;
    use crate::fs::store::FileRecord;
    use object_store::memory::InMemory;
    use oxkv::{
        Direction, GetSet as _, ObjectPath as OxPath, OxKvReader, Store as _, Transaction as _,
    };

    async fn test_manager() -> (SnapshotManager, std::sync::Arc<InMemory>) {
        let mem = std::sync::Arc::new(InMemory::new());
        let wal = Wal::new(crate::db::build_test_store("snap-test-wal").await);
        let store = FsStore::new(crate::db::build_test_store("snap-test-store").await);
        let policy = PolicyEngine::init_s3(crate::db::build_test_store("snap-test-policy").await)
            .await
            .unwrap();
        let s3 = ObjectStoreClient::in_memory();
        let mgr = SnapshotManager::new(
            wal,
            store,
            policy,
            s3,
            "b".into(),
            mem.clone() as std::sync::Arc<dyn object_store::ObjectStore>,
            "test-db".into(),
            true,
        );
        (mgr, mem)
    }

    fn file_record(id: &str, owner: &str) -> FileRecord {
        FileRecord {
            id: id.into(),
            name: format!("{id}.txt"),
            mimetype: "text/plain".into(),
            size: 1,
            s3_key: format!("k/{id}"),
            owner_sub: owner.into(),
            created_at: 0,
        }
    }

    async fn open_reader(mem: &std::sync::Arc<InMemory>, prefix: &str) -> OxKvReader {
        // `Arc<InMemory>` coerces to the `Storage` blanket impl through
        // `Arc<dyn ObjectStore>`; the reader never fences, so reopening the
        // same prefix across test phases is safe.
        let store: std::sync::Arc<dyn object_store::ObjectStore> = mem.clone();
        let storage: std::sync::Arc<dyn oxkv::Storage> = std::sync::Arc::new(store);
        OxKvReader::open(storage, OxPath::from(prefix))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn build_full_filters_into_reader_visible_prefix() -> anyhow::Result<()> {
        let (mgr, mem) = test_manager().await;
        mgr.policy
            .add_rule("alice".into(), "invoice:1".into(), Action::Read)
            .await?;
        let rec = file_record("f1", "alice");
        mgr.store.save_file(&rec).await?;
        mgr.store.attach("invoice", "1", "f1").await?;
        mgr.store.save_file(&file_record("f2", "bob")).await?;

        let meta = mgr.build_full("alice").await?;
        assert_eq!(meta.applied_seq, 0);
        assert_eq!(meta.version, 0);
        assert_eq!(mgr.load_meta("alice").await?.unwrap(), meta);

        // A read-only follower over the version prefix sees exactly alice's files.
        let prefix = mgr.user_prefix("alice", 0);
        let reader = open_reader(&mem, &prefix).await;
        let tx = reader.begin_tx().unwrap();
        let f1 = tx.get_bytes("fs:files:f1:meta").await?;
        assert!(f1.is_some(), "alice's file must be replicated");
        let f2 = tx.get_bytes("fs:files:f2:meta").await?;
        assert!(f2.is_none(), "bob's file must be filtered out");
        let rel = tx.get_bytes("fs:rel:invoice:1:f1").await?;
        assert!(rel.is_some(), "readable relations must be replicated");
        tx.rollback().await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn empty_replica_opens_cleanly() -> anyhow::Result<()> {
        let (mgr, mem) = test_manager().await;
        // Bob owns a file alice cannot read: her replica is valid but empty.
        mgr.store.save_file(&file_record("f9", "bob")).await?;
        let meta = mgr.build_full("alice").await?;
        let reader = open_reader(&mem, &mgr.user_prefix("alice", meta.version)).await;
        let tx = reader.begin_tx().unwrap();
        let rows = tx
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .unwrap();
        assert!(rows.is_empty());
        tx.rollback().await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn prefixes_are_stable_and_safe() {
        let (mgr, _) = test_manager().await;
        assert_eq!(
            mgr.user_prefix("alice", 3),
            "test-db/u/alice/00000000000000000003"
        );
        assert_eq!(
            mgr.resolve_object("a/b:c", 3, "manifest.json").unwrap(),
            "test-db/u/a_b_c/00000000000000000003/manifest.json"
        );
        assert!(mgr.resolve_object("alice", 3, "../escape").is_err());
        assert!(mgr.resolve_object("alice", 3, "a/../../escape").is_err());
        assert!(mgr.resolve_object("alice", 3, "").is_err());
        assert_eq!(SnapshotManager::meta_key("alice"), "snapshots/alice/meta.json");
    }
}
