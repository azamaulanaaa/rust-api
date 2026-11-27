//! Per-user, generation-scoped OxKV replicas for the WASM client.
//!
//! Each build writes one filtered `OxKvStore` under `{root}/{sub_hash}/{generation}`.
//! The store holds only the `entity:{id}:meta` and `entity:{id}:attr:{name}`
//! rows that the caller can read.
//! The client scans that key family through a read-only `OxKvReader`.
//!
//! The store is built at an empty virtual prefix over a storage adapter that
//! maps every path into the generation prefix.
//! The objects in `manifest.json` therefore name keys relative to the replica
//! root, and the client opens the reader with an empty prefix.
//!
//! A build publishes a wrapper `ReplicaManifest` at
//! `{root}/{sub_hash}/manifest.json` only after every OxKV object is written.
//! The wrapper names the generation, the feed head, and each raw object with
//! its size and SHA-256.
//! A lower head never replaces a higher head.
//! A rebuild keeps the current and the previous generation, and removes older
//! generations after the new wrapper is visible.
//!
//! A failed build leaves the old wrapper and the old generation readable.
//! A failed generation is removed on the next build of the same subject.
//!
//! The module adds no client query and no business rule.
//! It does not read the change feed.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use oxkv::{
    GetOptions, GetOutput, ObjectPath, ObjectVersion, OxKvStore, PutMode, PutOutcome, Storage,
    StorageCause, StoreError,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::db::{build_object_store, default_sst_cache};
use crate::eav::entity::Entity;
use crate::eav::entity_error::EntityError;
use crate::eav::replica::sub_hash;
use crate::fs::s3::{S3Backend, S3ClientConfig};
use rust_api_model::wire::{ReplicaManifest, ReplicaObject};

/// The number of times a wrapper publish retries after a CAS conflict.
const WRAPPER_PUT_ATTEMPTS: u32 = 8;

/// The number of generations that the store keeps for one subject.
///
/// The current generation and the one before it stay readable.
/// An older generation is removed after the new wrapper is visible.
const RETAINED_GENERATIONS: usize = 2;

/// A storage view that maps every path under one root prefix.
///
/// The inner storage is the bucket-rooted backend.
/// `list` returns keys relative to `root`, so an OxKV store that uses this
/// adapter at an empty prefix sees the same layout that the client sees.
#[derive(Clone)]
struct PrefixedStorage {
    /// The bucket-rooted storage.
    inner: Arc<dyn Storage>,
    /// The root of this view.
    root: ObjectPath,
}

impl PrefixedStorage {
    /// Maps a view path to the inner storage path.
    fn scoped(&self, path: &ObjectPath) -> ObjectPath {
        if self.root.is_empty() {
            return path.clone();
        }
        if path.is_empty() {
            return self.root.clone();
        }
        self.root.child(path.as_str())
    }
}

#[async_trait]
impl Storage for PrefixedStorage {
    async fn get(&self, path: &ObjectPath) -> oxkv::Result<GetOutput> {
        self.inner.get(&self.scoped(path)).await
    }

    async fn get_opts(&self, path: &ObjectPath, options: GetOptions) -> oxkv::Result<GetOutput> {
        self.inner.get_opts(&self.scoped(path), options).await
    }

    async fn put_opts(
        &self,
        path: &ObjectPath,
        payload: Vec<u8>,
        mode: PutMode,
    ) -> oxkv::Result<PutOutcome> {
        self.inner.put_opts(&self.scoped(path), payload, mode).await
    }

    async fn delete(&self, path: &ObjectPath) -> oxkv::Result<()> {
        self.inner.delete(&self.scoped(path)).await
    }

    async fn list(&self, prefix: &ObjectPath) -> oxkv::Result<Vec<ObjectPath>> {
        let scoped = self.scoped(prefix);
        let keys = self.inner.list(&scoped).await?;
        let root = self.root.as_str();
        let mut relative = Vec::with_capacity(keys.len());
        for key in keys {
            let text = key.as_str();
            let text = if root.is_empty() {
                Some(text)
            } else {
                text.strip_prefix(root)
                    .and_then(|rest| rest.strip_prefix('/'))
            };
            if let Some(text) = text {
                relative.push(ObjectPath::from(text));
            }
        }
        Ok(relative)
    }
}

/// One generation that is fully written and ready to publish.
pub(crate) struct PreparedGeneration {
    /// The replica generation.
    generation: u64,
    /// The change-feed head of the build.
    head: u64,
    /// The raw OxKV objects relative to the replica root.
    objects: Vec<ReplicaObject>,
}

/// A generation that a build is still filling.
pub(crate) struct OxkvGeneration {
    /// The writer for the generation.
    store: OxKvStore,
    /// The generation-rooted storage view.
    storage: Arc<dyn Storage>,
    /// The replica generation.
    generation: u64,
    /// The change-feed head of the build.
    head: u64,
}

impl OxkvGeneration {
    /// Stages the rows of one entity into the generation.
    ///
    /// The rows use the `entity:` key family and the entity store encoding.
    /// The call does not write to storage.
    pub(crate) async fn add_entity(&self, entity: &Entity) -> Result<(), EntityError> {
        for (key, value) in crate::eav::entity::replica_rows(entity)? {
            self.store.stage_set(&key, &value).await;
        }
        Ok(())
    }

    /// Flushes and compacts the generation, then lists its raw objects.
    ///
    /// The call writes one WAL, one SST, the manifest, and the ownership
    /// record.
    /// The object list is in key order and holds the size and SHA-256 of every
    /// object.
    pub(crate) async fn finish(self) -> Result<PreparedGeneration, EntityError> {
        self.store.flush().await.map_err(EntityError::Store)?;
        self.store
            .flush_mem_to_sst_force()
            .await
            .map_err(EntityError::Store)?;
        self.store.compact().await.map_err(EntityError::Store)?;
        let keys = self
            .storage
            .list(&ObjectPath::default())
            .await
            .map_err(EntityError::Store)?;
        let mut objects = Vec::with_capacity(keys.len());
        for key in keys {
            let output = self.storage.get(&key).await.map_err(EntityError::Store)?;
            objects.push(ReplicaObject {
                key: key.as_str().to_string(),
                size: output.bytes.len() as u64,
                sha256: sha256_hex(&output.bytes),
            });
        }
        objects.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(PreparedGeneration {
            generation: self.generation,
            head: self.head,
            objects,
        })
    }

    /// Removes every object of this generation.
    ///
    /// The call is best effort at the caller. It never touches the wrapper or
    /// another generation.
    pub(crate) async fn abort(self) -> Result<(), EntityError> {
        delete_all(&self.storage, &ObjectPath::default()).await
    }
}

/// The per-user OxKV replica store.
///
/// One instance serves every subject.
/// The store enforces one build at a time for each subject in this process.
#[derive(Clone)]
pub struct OxkvReplicaStore {
    /// The bucket-rooted storage.
    inner: Arc<dyn Storage>,
    /// The root prefix of every replica.
    root: String,
    /// True for the in-memory backend, which has no conditional-write probe.
    skip_probe: bool,
    /// One build lock for each subject hash.
    builds: Arc<std::sync::Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

impl OxkvReplicaStore {
    /// Builds a replica store under `root` inside the bucket of `cfg`.
    ///
    /// `root` is a slash-separated object prefix, for example
    /// `"{db}/eav-oxkv"`.
    pub fn new(cfg: &S3ClientConfig, root: &str) -> Result<Self, EntityError> {
        let inner = build_object_store(cfg).map_err(|error| {
            EntityError::Internal(format!("build oxkv replica storage: {error}"))
        })?;
        let inner = Arc::new(oxkv_s3::ObjectStoreStorage::new(inner)) as Arc<dyn Storage>;
        Ok(Self {
            inner,
            root: root.trim_matches('/').to_string(),
            skip_probe: cfg.backend == S3Backend::Memory,
            builds: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Locks one subject for a build in this process.
    ///
    /// The caller holds the guard until the build commits or aborts.
    pub(crate) async fn lock_subject(&self, sub: &str) -> OwnedMutexGuard<()> {
        let hash = sub_hash(sub);
        let lock = {
            let mut builds = match self.builds.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            builds
                .entry(hash)
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    /// Starts one generation at `generation` for `sub`.
    ///
    /// The call removes every old object under the generation prefix first, so
    /// a failed earlier attempt cannot leave a row behind.
    /// It writes no wrapper, so the old replica stays visible.
    /// The caller must hold the subject build lock.
    pub(crate) async fn begin_generation(
        &self,
        sub: &str,
        generation: u64,
        head: u64,
    ) -> Result<OxkvGeneration, EntityError> {
        let hash = sub_hash(sub);
        if let Some((manifest, _version)) = self.read_wrapper(&hash).await?
            && manifest.generation == generation
        {
            return Err(EntityError::Internal(
                "oxkv replica generation is already published".to_string(),
            ));
        }
        let path = format!("{hash}/{generation}");
        let storage = self.storage_at(&path);
        delete_all(&storage, &ObjectPath::default()).await?;
        let mut builder = OxKvStore::builder()
            .with_store(Arc::clone(&storage))
            .with_prefix(ObjectPath::default());
        if self.skip_probe {
            builder = builder.skip_probe(true);
        }
        let store = builder
            .build_with_cache(default_sst_cache())
            .await
            .map_err(EntityError::Store)?;
        let meta = serde_json::json!({ "generation": generation, "head": head });
        let bytes =
            serde_json::to_vec(&meta).map_err(|error| EntityError::Internal(error.to_string()))?;
        store.stage_set("replica:meta", &bytes).await;
        Ok(OxkvGeneration {
            store,
            storage,
            generation,
            head,
        })
    }

    /// Publishes the wrapper manifest for one prepared generation.
    ///
    /// The call rejects a head below the stored head and leaves the old
    /// wrapper unchanged.
    /// It retries when another writer changes the wrapper first.
    /// After a successful publish it removes old generations beyond the
    /// retention window.
    pub(crate) async fn publish(
        &self,
        sub: &str,
        prepared: &PreparedGeneration,
    ) -> Result<(), EntityError> {
        let hash = sub_hash(sub);
        let storage = self.storage_at(&hash);
        let manifest = ReplicaManifest {
            generation: prepared.generation,
            head: prepared.head,
            objects: prepared.objects.clone(),
        };
        let payload = serde_json::to_vec(&manifest)
            .map_err(|error| EntityError::Internal(error.to_string()))?;
        for _attempt in 0..WRAPPER_PUT_ATTEMPTS {
            let existing = self.read_wrapper(&hash).await?;
            if let Some((stored, _)) = &existing
                && prepared.head < stored.head
            {
                return Err(EntityError::StaleHead {
                    stored: stored.head,
                    incoming: prepared.head,
                });
            }
            let mode = match &existing {
                Some((_, Some(version))) => PutMode::Update(version.clone()),
                Some((_, None)) => PutMode::Create,
                None => PutMode::Create,
            };
            match storage
                .put_opts(&ObjectPath::from("manifest.json"), payload.clone(), mode)
                .await
            {
                Ok(_) => {
                    if let Err(error) = self.cleanup_generations(&hash, prepared.generation).await {
                        tracing::warn!(
                            %error,
                            subject = %sub,
                            "oxkv replica cleanup failed"
                        );
                    }
                    return Ok(());
                }
                Err(StoreError::CasConflict(_)) => continue,
                Err(error) => return Err(EntityError::Store(error)),
            }
        }
        Err(EntityError::Internal(
            "oxkv replica wrapper publish conflicted with another writer".to_string(),
        ))
    }

    /// Removes one unpublished generation.
    ///
    /// The call does nothing when the wrapper already names the generation, so
    /// a lost publish race cannot delete a live replica.
    pub(crate) async fn discard_generation(
        &self,
        sub: &str,
        generation: u64,
    ) -> Result<(), EntityError> {
        let hash = sub_hash(sub);
        if let Some((manifest, _)) = self.read_wrapper(&hash).await?
            && manifest.generation == generation
        {
            return Ok(());
        }
        let storage = self.storage_at(&format!("{hash}/{generation}"));
        delete_all(&storage, &ObjectPath::default()).await
    }

    /// Returns the wrapper manifest of `sub`, or `None` when no replica exists.
    pub(crate) async fn manifest(&self, sub: &str) -> Result<Option<ReplicaManifest>, EntityError> {
        let hash = sub_hash(sub);
        Ok(self
            .read_wrapper(&hash)
            .await?
            .map(|(manifest, _)| manifest))
    }

    /// Returns one raw object of the current replica of `sub`.
    ///
    /// The call returns `None` when the subject has no replica, when `key` is
    /// not in the wrapper, or when the object is gone.
    /// The key must match a wrapper entry exactly, so a caller cannot read
    /// another subject or a path outside the generation.
    pub(crate) async fn object(
        &self,
        sub: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>, EntityError> {
        let manifest = match self.manifest(sub).await? {
            Some(manifest) => manifest,
            None => return Ok(None),
        };
        if !manifest.objects.iter().any(|object| object.key == key) {
            return Ok(None);
        }
        let hash = sub_hash(sub);
        let storage = self.storage_at(&format!("{hash}/{}", manifest.generation));
        match storage.get(&ObjectPath::from(key)).await {
            Ok(output) => Ok(Some(output.bytes)),
            Err(error) if is_not_found(&error) => Ok(None),
            Err(error) => Err(EntityError::Store(error)),
        }
    }

    /// Removes the wrapper and every generation of `sub`.
    ///
    /// The call returns `true` when a wrapper existed.
    pub(crate) async fn clear(&self, sub: &str) -> Result<bool, EntityError> {
        let hash = sub_hash(sub);
        let existed = self.read_wrapper(&hash).await?.is_some();
        let storage = self.storage_at(&hash);
        delete_all(&storage, &ObjectPath::default()).await?;
        Ok(existed)
    }

    /// Returns the storage view rooted at `path` below the replica root.
    fn storage_at(&self, path: &str) -> Arc<dyn Storage> {
        let root = if self.root.is_empty() {
            path.trim_matches('/').to_string()
        } else if path.is_empty() {
            self.root.clone()
        } else {
            format!("{}/{}", self.root, path.trim_matches('/'))
        };
        Arc::new(PrefixedStorage {
            inner: Arc::clone(&self.inner),
            root: ObjectPath::from(root),
        })
    }

    /// Reads and parses the wrapper of one subject hash.
    ///
    /// The result carries the object version for a conditional replace.
    async fn read_wrapper(
        &self,
        hash: &str,
    ) -> Result<Option<(ReplicaManifest, Option<ObjectVersion>)>, EntityError> {
        let storage = self.storage_at(hash);
        let output = match storage.get(&ObjectPath::from("manifest.json")).await {
            Ok(output) => output,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(EntityError::Store(error)),
        };
        let manifest = serde_json::from_slice(&output.bytes)
            .map_err(|error| EntityError::Internal(error.to_string()))?;
        let version = match (output.e_tag, output.version) {
            (None, None) => None,
            (e_tag, version) => Some(ObjectVersion { e_tag, version }),
        };
        Ok(Some((manifest, version)))
    }

    /// Removes every generation outside the retention window.
    ///
    /// The current generation and the highest generation below it stay.
    /// A generation above the current one stays, because another writer may
    /// still be filling it.
    async fn cleanup_generations(&self, hash: &str, current: u64) -> Result<(), EntityError> {
        let storage = self.storage_at(hash);
        let keys = storage
            .list(&ObjectPath::default())
            .await
            .map_err(EntityError::Store)?;
        let mut generations = Vec::new();
        for key in keys {
            let Some(first) = key.as_str().split('/').next() else {
                continue;
            };
            if let Ok(value) = first.parse::<u64>()
                && !generations.contains(&value)
            {
                generations.push(value);
            }
        }
        generations.sort_unstable();
        let previous: Vec<u64> = generations
            .iter()
            .copied()
            .filter(|value| *value < current)
            .rev()
            .take(RETAINED_GENERATIONS.saturating_sub(1))
            .collect();
        for generation in generations {
            if generation == current || previous.contains(&generation) || generation > current {
                continue;
            }
            let old = self.storage_at(&format!("{hash}/{generation}"));
            delete_all(&old, &ObjectPath::default()).await?;
        }
        Ok(())
    }
}

/// Deletes every object under `prefix` in one storage view.
async fn delete_all(storage: &Arc<dyn Storage>, prefix: &ObjectPath) -> Result<(), EntityError> {
    let keys = storage.list(prefix).await.map_err(EntityError::Store)?;
    for key in keys {
        storage.delete(&key).await.map_err(EntityError::Store)?;
    }
    Ok(())
}

/// Returns true when `error` reports a missing object.
fn is_not_found(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Storage(error) if error.cause == StorageCause::NotFound
    )
}

/// Returns the lowercase SHA-256 hex of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
