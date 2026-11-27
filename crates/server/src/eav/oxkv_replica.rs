//! Per-user, generation-scoped OxKV replicas for the WASM client.
//!
//! Each build writes one filtered `OxKvStore` under a unique build prefix
//! `{root}/{sub_hash}/{generation}/{build_id}`.
//! The store holds only the `entity:{id}:meta` and `entity:{id}:attr:{name}`
//! rows that the caller can read.
//! The client scans that key family through a read-only `OxKvReader`.
//!
//! A `{root}/{sub_hash}/{generation}/build.json` pointer names the build
//! prefix that the wrapper uses.
//! The pointer makes two builds at one generation independent.
//! A build cannot delete the objects of another build.
//!
//! The store is built at an empty virtual prefix over a storage adapter that
//! maps every path into the build prefix.
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
//! A failed build removes only its own build prefix.
//!
//! The single-writer lease is the cross-process guarantee.
//! The build lock is only a process-local gate.
//!
//! The module adds no client query and no business rule.
//! It does not read the change feed.

use std::collections::HashMap;
use std::sync::{Arc, Weak};

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

/// The pointer that names the build prefix of one generation.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct BuildPointer {
    /// The unique build id.
    build: String,
}

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
    /// The unique build id.
    build_id: String,
    /// The raw OxKV objects relative to the replica root.
    objects: Vec<ReplicaObject>,
}

impl PreparedGeneration {
    /// Returns the unique build id.
    pub(crate) fn build_id(&self) -> &str {
        &self.build_id
    }
}

/// A generation that a build is still filling.
pub(crate) struct OxkvGeneration {
    /// The writer for the generation.
    store: OxKvStore,
    /// The build-rooted storage view.
    storage: Arc<dyn Storage>,
    /// The unique build id.
    build_id: String,
    /// The replica generation.
    generation: u64,
    /// The change-feed head of the build.
    head: u64,
}

impl OxkvGeneration {
    /// Returns the unique build id.
    pub(crate) fn build_id(&self) -> &str {
        &self.build_id
    }

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
            build_id: self.build_id,
            objects,
        })
    }

    /// Removes every object of this build.
    ///
    /// The call is best effort at the caller.
    /// It never touches the wrapper, the build pointer, or another build.
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
    /// One weak build lock for each subject hash.
    ///
    /// An entry whose build ended is pruned on the next lookup.
    builds: Arc<std::sync::Mutex<HashMap<String, Weak<AsyncMutex<()>>>>>,
    /// The number of test publishes that must fail before the wrapper write.
    #[cfg(test)]
    publish_failures: Arc<std::sync::atomic::AtomicUsize>,
    /// The number of test builds that must see a generation conflict.
    #[cfg(test)]
    generation_conflicts: Arc<std::sync::atomic::AtomicUsize>,
    /// True when a test hides the wrapper object version.
    #[cfg(test)]
    strip_wrapper_version: Arc<std::sync::atomic::AtomicBool>,
    /// The number of test versionless wrapper creates that must fail.
    #[cfg(test)]
    wrapper_create_failures: Arc<std::sync::atomic::AtomicUsize>,
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
            #[cfg(test)]
            publish_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            generation_conflicts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            strip_wrapper_version: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            wrapper_create_failures: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Makes the next wrapper publish fail in a test.
    #[cfg(test)]
    pub(crate) fn fail_next_publish(&self) {
        self.publish_failures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Makes the next build see a generation conflict in a test.
    #[cfg(test)]
    pub(crate) fn fail_next_generation(&self) {
        self.generation_conflicts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Hides the wrapper object version in a test.
    #[cfg(test)]
    pub(crate) fn strip_wrapper_version_for_test(&self, strip: bool) {
        self.strip_wrapper_version
            .store(strip, std::sync::atomic::Ordering::SeqCst);
    }

    /// Makes the next versionless wrapper create fail in a test.
    #[cfg(test)]
    pub(crate) fn fail_next_wrapper_create(&self) {
        self.wrapper_create_failures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Locks one subject for a build in this process.
    ///
    /// The caller holds the guard until the build commits or aborts.
    /// The call prunes an entry whose last build ended.
    pub(crate) async fn lock_subject(&self, sub: &str) -> OwnedMutexGuard<()> {
        let hash = sub_hash(sub);
        let lock = {
            let mut builds = match self.builds.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            builds.retain(|_, lock| lock.strong_count() > 0);
            match builds.get(&hash).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(AsyncMutex::new(()));
                    builds.insert(hash, Arc::downgrade(&lock));
                    lock
                }
            }
        };
        lock.lock_owned().await
    }

    /// Returns the number of build-lock entries in a test.
    #[cfg(test)]
    pub(crate) fn build_lock_count(&self) -> usize {
        match self.builds.lock() {
            Ok(builds) => builds.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    /// Returns the build pointer of one generation in a test.
    #[cfg(test)]
    pub(crate) async fn build_pointer_for_test(
        &self,
        sub: &str,
        generation: u64,
    ) -> Result<Option<String>, EntityError> {
        self.read_build_pointer(&sub_hash(sub), generation).await
    }

    /// Returns the raw objects of one generation in a test.
    #[cfg(test)]
    pub(crate) async fn generation_objects_for_test(
        &self,
        sub: &str,
        generation: u64,
    ) -> Result<Vec<ReplicaObject>, EntityError> {
        let hash = sub_hash(sub);
        let storage = match self.read_build_pointer(&hash, generation).await? {
            Some(build_id) => self.storage_at(&format!("{hash}/{generation}/{build_id}")),
            None => self.storage_at(&format!("{hash}/{generation}")),
        };
        let keys = storage
            .list(&ObjectPath::default())
            .await
            .map_err(EntityError::Store)?;
        let mut objects = Vec::with_capacity(keys.len());
        for key in keys {
            let output = storage.get(&key).await.map_err(EntityError::Store)?;
            objects.push(ReplicaObject {
                key: key.as_str().to_string(),
                size: output.bytes.len() as u64,
                sha256: sha256_hex(&output.bytes),
            });
        }
        objects.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(objects)
    }

    /// Starts one generation at `generation` for `sub`.
    ///
    /// The call writes a unique build prefix, so two builds at one generation
    /// do not share objects.
    /// It writes no wrapper, so the old replica stays visible.
    /// The caller must hold the subject build lock.
    /// A wrapper that already names `generation` returns
    /// [`EntityError::GenerationTaken`], and the caller can retry.
    pub(crate) async fn begin_generation(
        &self,
        sub: &str,
        generation: u64,
        head: u64,
    ) -> Result<OxkvGeneration, EntityError> {
        #[cfg(test)]
        if self
            .generation_conflicts
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
        {
            self.generation_conflicts
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return Err(EntityError::GenerationTaken);
        }
        let hash = sub_hash(sub);
        if let Some((manifest, _version)) = self.read_wrapper(&hash).await?
            && manifest.generation == generation
        {
            return Err(EntityError::GenerationTaken);
        }
        let build_id = new_build_id();
        let path = format!("{hash}/{generation}/{build_id}");
        let storage = self.storage_at(&path);
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
            build_id,
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
        #[cfg(test)]
        if self
            .publish_failures
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
        {
            self.publish_failures
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return Err(EntityError::PublishConflict);
        }
        let hash = sub_hash(sub);
        self.write_build_pointer(&hash, prepared).await?;
        let storage = self.storage_at(&hash);
        let manifest = ReplicaManifest {
            generation: prepared.generation,
            head: prepared.head,
            objects: prepared.objects.clone(),
        };
        let payload = serde_json::to_vec(&manifest)
            .map_err(|error| EntityError::Internal(error.to_string()))?;
        for _attempt in 0..WRAPPER_PUT_ATTEMPTS {
            let existing = match self.read_wrapper(&hash).await {
                Ok(existing) => existing,
                Err(EntityError::Store(error)) if error.is_retryable() => continue,
                Err(error) => return Err(error),
            };
            if let Some((stored, _)) = &existing
                && prepared.head < stored.head
            {
                return Err(EntityError::StaleHead {
                    stored: stored.head,
                    incoming: prepared.head,
                });
            }
            let wrapper_path = ObjectPath::from("manifest.json");
            let result = match &existing {
                Some((_, Some(version))) => {
                    storage
                        .put_opts(
                            &wrapper_path,
                            payload.clone(),
                            PutMode::Update(version.clone()),
                        )
                        .await
                }
                Some((_, None)) => {
                    // A versionless backend cannot compare the old row.
                    // Save the old bytes, then remove the row and create it.
                    // A failed create restores the old wrapper.
                    let previous = storage
                        .get(&wrapper_path)
                        .await
                        .map_err(EntityError::Store)?
                        .bytes;
                    storage
                        .delete(&wrapper_path)
                        .await
                        .map_err(EntityError::Store)?;
                    #[cfg(test)]
                    let created = if self
                        .wrapper_create_failures
                        .load(std::sync::atomic::Ordering::SeqCst)
                        > 0
                    {
                        self.wrapper_create_failures
                            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        Err(StoreError::Other(
                            "test versionless wrapper create failure".to_string(),
                        ))
                    } else {
                        storage
                            .put_opts(&wrapper_path, payload.clone(), PutMode::Create)
                            .await
                    };
                    #[cfg(not(test))]
                    let created = storage
                        .put_opts(&wrapper_path, payload.clone(), PutMode::Create)
                        .await;
                    match created {
                        Ok(outcome) => Ok(outcome),
                        Err(error) => {
                            let restored = storage
                                .put_opts(&wrapper_path, previous, PutMode::Create)
                                .await;
                            if let Err(restore_error) = restored {
                                tracing::warn!(
                                    %restore_error,
                                    subject = %sub,
                                    "versionless wrapper restore failed"
                                );
                            }
                            Err(error)
                        }
                    }
                }
                None => {
                    storage
                        .put_opts(&wrapper_path, payload.clone(), PutMode::Create)
                        .await
                }
            };
            match result {
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
                Err(error) if error.is_retryable() => continue,
                Err(error) => return Err(EntityError::Store(error)),
            }
        }
        Err(EntityError::PublishConflict)
    }

    /// Removes one unpublished build.
    ///
    /// The call removes only the build prefix of `build_id`.
    /// It also removes the build pointer when the pointer names this build.
    /// A failed build then cannot become the retained previous generation.
    /// It does nothing when the wrapper and the pointer name this build, so a
    /// lost publish race cannot delete a live replica.
    pub(crate) async fn discard_generation(
        &self,
        sub: &str,
        generation: u64,
        build_id: &str,
    ) -> Result<(), EntityError> {
        let hash = sub_hash(sub);
        let published = self.read_build_pointer(&hash, generation).await?;
        if let Some((manifest, _)) = self.read_wrapper(&hash).await?
            && manifest.generation == generation
            && published.as_deref() == Some(build_id)
        {
            return Ok(());
        }
        let storage = self.storage_at(&format!("{hash}/{generation}/{build_id}"));
        delete_all(&storage, &ObjectPath::default()).await?;
        if published.as_deref() == Some(build_id) {
            self.storage_at(&format!("{hash}/{generation}"))
                .delete(&ObjectPath::from("build.json"))
                .await
                .map_err(EntityError::Store)?;
        }
        Ok(())
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
        let storage = self.build_storage(&hash, manifest.generation).await?;
        match storage.get(&ObjectPath::from(key)).await {
            Ok(output) => Ok(Some(output.bytes)),
            Err(error) if is_not_found(&error) => Ok(None),
            Err(error) => Err(EntityError::Store(error)),
        }
    }

    /// Removes the wrapper and every generation of `sub`.
    ///
    /// The call returns `true` when the wrapper or any generation existed.
    /// A failed generation with no wrapper also counts as an existing replica.
    pub(crate) async fn clear(&self, sub: &str) -> Result<bool, EntityError> {
        let hash = sub_hash(sub);
        let storage = self.storage_at(&hash);
        let keys = storage
            .list(&ObjectPath::default())
            .await
            .map_err(EntityError::Store)?;
        let existed = !keys.is_empty();
        for key in keys {
            storage.delete(&key).await.map_err(EntityError::Store)?;
        }
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

    /// Returns the build storage of one published generation.
    ///
    /// A generation with no pointer uses the generation root.
    /// That fallback reads a replica from before build ids existed.
    async fn build_storage(
        &self,
        hash: &str,
        generation: u64,
    ) -> Result<Arc<dyn Storage>, EntityError> {
        let Some(build_id) = self.read_build_pointer(hash, generation).await? else {
            return Ok(self.storage_at(&format!("{hash}/{generation}")));
        };
        Ok(self.storage_at(&format!("{hash}/{generation}/{build_id}")))
    }

    /// Returns the build id of one generation, or `None` when no pointer exists.
    async fn read_build_pointer(
        &self,
        hash: &str,
        generation: u64,
    ) -> Result<Option<String>, EntityError> {
        let storage = self.storage_at(&format!("{hash}/{generation}"));
        let output = match storage.get(&ObjectPath::from("build.json")).await {
            Ok(output) => output,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(EntityError::Store(error)),
        };
        let pointer: BuildPointer = serde_json::from_slice(&output.bytes)
            .map_err(|error| EntityError::Internal(error.to_string()))?;
        Ok(Some(pointer.build))
    }

    /// Writes the build pointer of one generation.
    ///
    /// The first pointer wins.
    /// A pointer to another build returns [`EntityError::GenerationTaken`].
    /// The call is idempotent for the same build id.
    async fn write_build_pointer(
        &self,
        hash: &str,
        prepared: &PreparedGeneration,
    ) -> Result<(), EntityError> {
        let storage = self.storage_at(&format!("{hash}/{}", prepared.generation));
        let path = ObjectPath::from("build.json");
        let payload = serde_json::to_vec(&BuildPointer {
            build: prepared.build_id.clone(),
        })
        .map_err(|error| EntityError::Internal(error.to_string()))?;
        for _attempt in 0..WRAPPER_PUT_ATTEMPTS {
            match storage.get(&path).await {
                Ok(output) => {
                    let pointer: BuildPointer = serde_json::from_slice(&output.bytes)
                        .map_err(|error| EntityError::Internal(error.to_string()))?;
                    if pointer.build == prepared.build_id {
                        return Ok(());
                    }
                    return Err(EntityError::GenerationTaken);
                }
                Err(error) if is_not_found(&error) => {
                    match storage
                        .put_opts(&path, payload.clone(), PutMode::Create)
                        .await
                    {
                        Ok(_) => return Ok(()),
                        Err(error) if error.is_retryable() => continue,
                        Err(error) => return Err(EntityError::Store(error)),
                    }
                }
                Err(error) if error.is_retryable() => continue,
                Err(error) => return Err(EntityError::Store(error)),
            }
        }
        Err(EntityError::PublishConflict)
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
        #[cfg(test)]
        let version = if self
            .strip_wrapper_version
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            None
        } else {
            version
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

/// Returns a random build id.
///
/// The id keeps two builds at one generation in different prefixes.
fn new_build_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_prefix;
    use crate::fs::s3::S3Backend;

    fn memory_s3() -> S3ClientConfig {
        S3ClientConfig {
            bucket: "eav-oxkv-replica-test".to_string(),
            region: "us-east-1".to_string(),
            endpoint_url: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
            backend: S3Backend::Memory,
        }
    }

    fn store() -> OxkvReplicaStore {
        OxkvReplicaStore::new(&memory_s3(), &test_prefix("eav-oxkv-unit"))
            .expect("the test store must build")
    }

    #[tokio::test]
    async fn a_loser_cannot_delete_the_build_prefix_of_a_winner() -> anyhow::Result<()> {
        let store = store();
        let winner = store.begin_generation("alice", 1, 7).await?;
        let winner_id = winner.build_id().to_string();
        let loser = store.begin_generation("alice", 1, 7).await?;
        let loser_id = loser.build_id().to_string();
        let prepared = winner.finish().await?;
        let hash = sub_hash("alice");
        let winner_storage = store.storage_at(&format!("{hash}/1/{winner_id}"));
        let before = winner_storage.list(&ObjectPath::default()).await?;
        assert!(!before.is_empty(), "the winner wrote no object");
        store.publish("alice", &prepared).await?;

        store.discard_generation("alice", 1, &loser_id).await?;

        assert_eq!(
            winner_storage.list(&ObjectPath::default()).await?,
            before,
            "the loser deleted an object of the winner"
        );
        let loser_storage = store.storage_at(&format!("{hash}/1/{loser_id}"));
        assert!(
            loser_storage.list(&ObjectPath::default()).await?.is_empty(),
            "the loser build prefix remains"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_idle_build_lock_is_pruned_on_the_next_lookup() -> anyhow::Result<()> {
        let store = store();
        let guard = store.lock_subject("alice").await;
        assert_eq!(store.build_lock_count(), 1);
        drop(guard);

        let guard = store.lock_subject("bob").await;
        assert_eq!(
            store.build_lock_count(),
            1,
            "the idle alice entry must be pruned"
        );
        drop(guard);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_build_removes_its_pointer_and_retains_the_published_generation()
    -> anyhow::Result<()> {
        let store = store();
        let first = store.begin_generation("alice", 1, 7).await?;
        let published = first.finish().await?;
        store.publish("alice", &published).await?;

        let failed = store.begin_generation("alice", 2, 8).await?;
        let failed_id = failed.build_id().to_string();
        let prepared = failed.finish().await?;
        store
            .write_build_pointer(&sub_hash("alice"), &prepared)
            .await?;
        assert_eq!(
            store.build_pointer_for_test("alice", 2).await?,
            Some(failed_id.clone()),
            "the failed build must write its pointer first"
        );

        store.discard_generation("alice", 2, &failed_id).await?;

        assert!(
            store.build_pointer_for_test("alice", 2).await?.is_none(),
            "the failed build kept its pointer"
        );
        assert!(
            store
                .generation_objects_for_test("alice", 2)
                .await?
                .is_empty(),
            "the failed build kept its objects"
        );

        let third = store.begin_generation("alice", 3, 9).await?;
        let prepared = third.finish().await?;
        store.publish("alice", &prepared).await?;

        assert_eq!(
            store.generation_objects_for_test("alice", 1).await?,
            published.objects,
            "the next build deleted the previous published generation"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_published_generation_returns_a_typed_conflict() -> anyhow::Result<()> {
        let store = store();
        let generation = store.begin_generation("alice", 1, 7).await?;
        let prepared = generation.finish().await?;
        store.publish("alice", &prepared).await?;

        let error = match store.begin_generation("alice", 1, 7).await {
            Ok(_) => panic!("the published generation must conflict"),
            Err(error) => error,
        };

        assert!(
            matches!(error, EntityError::GenerationTaken),
            "unexpected error: {error}"
        );
        Ok(())
    }
}
