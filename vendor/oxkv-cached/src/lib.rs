#![allow(clippy::multiple_crate_versions)]

//! Write-through RAM mirror over [`OxKvStore`].
//!
//! [`CachedOxKvStore`] pairs a durable LSM core with a [`BTreeStore`]. The
//! [`BTreeStore`] holds every resolved key. Therefore point and range reads
//! serve from memory. Writes keep WAL durability. The code imports
//! [`BTreeStore`] for the mirror type only. The durable behavior stays LSM.
//!
//! The mirror is authoritative under a single writer. A standalone write
//! applies to storage first and to memory second. [`CachedTx`] applies its
//! staged overlay to memory only after a successful commit. A blind `put` path
//! stays blind from the start to the end. The previous value for `set` comes
//! from the mirror instead of from an LSM read.
//!
//! A mirror can fall behind when another owner takes the epoch. A mirror can
//! also fall behind when another owner writes through a different handle. The
//! code derives freshness from `manifest.json` (`version` + `epoch` + SST set)
//! through conditional polling. The code reads `ownership.json` only when the
//! manifest suggests a takeover. A read never reads that file. A plain
//! [`GetSet`] read is always zero-I/O. The `*_checked` variants revalidate
//! against a time-to-live first. A write that [`StoreError::Fenced`]
//! rejects poisons the mirror. Reads then fail with the same fencing error.
//! Reads fail that way until [`refresh`](CachedOxKvStore::refresh) rebuilds
//! the mirror from the new owner.
//!
//! # Example
//!
//! ```rust
//! # #[tokio::main(flavor = "current_thread")] async fn main() {
//! use std::sync::Arc;
//! use oxkv::{GetSet, MemStorage, ObjectPath, OxKvStore};
//! use oxkv_cached::BuildCachedExt;
//!
//! let cached = OxKvStore::builder()
//!     .with_store(Arc::new(MemStorage::new()))
//!     .with_prefix(ObjectPath::from("mirror-doc"))
//!     .skip_probe(true)
//!     .build_cached()
//!     .await
//!     .unwrap();
//! cached.put_bytes("hello", b"world").await.unwrap();
//! assert_eq!(
//!     cached.get_bytes("hello").await.unwrap().as_deref(),
//!     Some(b"world".as_slice())
//! );
//! # }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use futures::channel::mpsc;
use oxkv::internals::{Manifest, ManifestCache, decode_wal_records, load_manifest, read_ownership};
use oxkv::{
    BTreeStore, Cache, ChangeEvent, Direction, GetSet, Hooks, KeyValue, LruCache, ObjectPath,
    Observer, OxKvStore, OxKvStoreBuilder, OxKvTx, Result, Scope, SstFile, Store, StoreError,
    Transaction, TxCas, Validator,
};

/// Locks a mutex, continuing through poisoning.
fn lock_ignore_poison<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Portable millisecond clock for TTLs.
fn now_millis() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Builder helpers for a write-through RAM mirror.
#[async_trait]
pub trait BuildCachedExt {
    /// Builds a write-through RAM mirror with the default SST cache.
    ///
    /// Acquires ownership like [`OxKvStoreBuilder::build`]. Then the method
    /// warms every key into memory via [`CachedOxKvStore::open`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the probe fails. It also returns
    /// [`StoreError::Fenced`] if the ownership CAS loses the race. It also
    /// returns a [`StoreError`] when the warming scan fails.
    async fn build_cached(self) -> Result<CachedOxKvStore>;

    /// Builds a write-through RAM mirror with a caller-supplied SST cache.
    ///
    /// See [`build_cached`](Self::build_cached) for the ownership and warming
    /// semantics. See [`OxKvStoreBuilder::build_with_cache`] for the cache
    /// choices.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the probe fails. It also returns
    /// [`StoreError::Fenced`] if the ownership CAS loses the race. It also
    /// returns a [`StoreError`] when the warming scan fails.
    async fn build_cached_with_cache<C>(self, cache: C) -> Result<CachedOxKvStore<C>>
    where
        C: Cache<String, Arc<SstFile>>;
}

#[async_trait]
impl BuildCachedExt for OxKvStoreBuilder {
    async fn build_cached(self) -> Result<CachedOxKvStore> {
        let inner = self.build().await?;
        CachedOxKvStore::open(inner).await
    }

    async fn build_cached_with_cache<C>(self, cache: C) -> Result<CachedOxKvStore<C>>
    where
        C: Cache<String, Arc<SstFile>>,
    {
        let inner = self.build_with_cache(cache).await?;
        CachedOxKvStore::open(inner).await
    }
}

/// Batch size for the paged scans behind [`CachedOxKvStore::rebuild`].
const SCAN_BATCH: usize = 256;

/// Staleness bound for [`CachedOxKvStore`] when none is configured.
///
/// This value matches the manifest poll TTL. A default mirror therefore
/// converges on the same envelope as an [`OxKvReader`](oxkv::OxKvReader).
const DEFAULT_STALE_TTL: Duration = Duration::from_secs(1);

/// Long cache peek for post-write syncs. The entry was just published by our
/// own write. Therefore any bound above zero hits without I/O.
const CACHE_PEEK_TTL: Duration = Duration::from_secs(3600);

/// How the mirror fills with the durable key set.
///
/// The default is [`WarmMode::Eager`]. In that mode, `open` returns only after
/// the mirror holds every key. The other modes return immediately. They
/// converge later. Choose them when startup latency matters more than instant
/// full speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WarmMode {
    /// Scan the whole store during `open` before serving reads.
    ///
    /// This mode has the slowest start and the fastest steady state. Every
    /// read after `open` is zero-I/O. Use this mode when RAM holds the dataset
    /// with room to spare.
    #[default]
    Eager,
    /// Return immediately and converge through an explicitly driven scan.
    ///
    /// Reads fall through to the durable core until the scan completes. Drive
    /// the scan with [`warm`](CachedOxKvStore::warm) or
    /// [`warm_step`](CachedOxKvStore::warm_step). Run that driver from any
    /// task or timer. Use this mode when startup must stay instant and the
    /// full set fits in RAM.
    Background,
    /// Return immediately and converge key by key on read misses.
    ///
    /// No scan ever runs unless [`warm`](CachedOxKvStore::warm) is called.
    /// Each miss fetches from the core and fills the mirror. Therefore hot
    /// keys arrive first. Untouched keys cost no RAM. Use this mode when the
    /// dataset exceeds RAM or the access is sparse.
    Lazy,
}

/// Durability-first view of one mirror generation.
#[derive(Debug)]
struct CachedState {
    /// Manifest epoch the mirror was built from.
    epoch: u64,
    /// Manifest version the mirror reflects.
    version: u64,
    /// SST ids visible when the mirror was synced.
    sst_ids: BTreeSet<String>,
    /// WAL ids already applied to the mirror.
    replayed: BTreeSet<String>,
    /// Last freshness poll in millis.
    last_check_ms: u64,
    /// Fencing message while the owning writer is superseded.
    poisoned: Option<String>,
    /// The mirror holds the full dataset. Reads then serve from memory alone.
    warmed: bool,
    /// Resume cursor for an explicitly driven scan.
    warm_cursor: Option<String>,
    /// Keys already scanned by the driven scan. The deletion difference uses
    /// them.
    scanned_keys: BTreeSet<String>,
}

/// Records one manifest generation into `state`.
///
/// The code tracks the ownership epoch separately. `manifest.epoch` records
/// the creation lineage. That value never moves on takeover. Therefore it
/// cannot detect a takeover.
fn observe_manifest(state: &mut CachedState, manifest: &Manifest) {
    state.version = manifest.version;
    state.sst_ids = manifest.sst.iter().map(|meta| meta.id.clone()).collect();
    state.replayed.extend(manifest.wal.iter().cloned());
    state.last_check_ms = now_millis();
    state.poisoned = None;
}

/// Returns the SST id set of one manifest generation.
fn sst_ids(manifest: &Manifest) -> BTreeSet<String> {
    manifest.sst.iter().map(|meta| meta.id.clone()).collect()
}

/// Returns `true` when `ttl_ms` millis elapsed since `last_check_ms`.
fn ttl_expired(last_check_ms: u64, ttl_ms: u64) -> bool {
    now_millis().wrapping_sub(last_check_ms) >= ttl_ms
}

/// Returns `true` when `key` falls inside the `direction`/`cursor` window.
fn in_window(key: &str, direction: Direction, cursor: &(Option<String>, Option<String>)) -> bool {
    if direction == Direction::Prev && cursor.0.is_none() {
        return false;
    }
    let (lower, upper) = match direction {
        Direction::Next => (cursor.0.as_deref(), cursor.1.as_deref()),
        Direction::Prev => (cursor.1.as_deref(), cursor.0.as_deref()),
    };
    if let Some(lo) = lower
        && key < lo
    {
        return false;
    }
    if let Some(hi) = upper
        && key > hi
    {
        return false;
    }
    true
}

/// Write-through RAM mirror over an [`OxKvStore`].
///
/// Share the value with `Arc`. The code reference-counts the mirror and the
/// sync state through clones of the inner handles. Therefore one
/// `Arc<CachedOxKvStore>` serves every thread.
pub struct CachedOxKvStore<C = LruCache<String, Arc<SstFile>>> {
    inner: OxKvStore<C>,
    mirror: BTreeStore,
    state: Arc<async_lock::Mutex<CachedState>>,
    /// Staleness bound for the `*_checked` reads, in millis.
    ttl_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Serializes explicitly driven scans against refresh rebuilds.
    scan_gate: Arc<async_lock::Mutex<()>>,
    /// Fill policy chosen at open.
    mode: WarmMode,
}

impl<C> std::fmt::Debug for CachedOxKvStore<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedOxKvStore").finish_non_exhaustive()
    }
}

/// Clones share the mirror and the sync state. The code reference-counts the
/// `BTreeStore` handle and the generation tracker. Therefore the clones
/// observe the same keys. Decorator composition (`Hooks`, `OtelStore`)
/// requires this behavior.
impl<C> Clone for CachedOxKvStore<C>
where
    C: Cache<String, Arc<SstFile>>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            mirror: self.mirror.clone(),
            state: Arc::clone(&self.state),
            ttl_ms: Arc::clone(&self.ttl_ms),
            scan_gate: Arc::clone(&self.scan_gate),
            mode: self.mode,
        }
    }
}

impl<C> Hooks for CachedOxKvStore<C>
where
    C: Cache<String, Arc<SstFile>>,
{
    fn add_validator<V>(&self, validator: V)
    where
        V: Validator + 'static,
    {
        self.inner.add_validator(validator);
    }

    fn add_observer<O>(&self, observer: O)
    where
        O: Observer + 'static,
    {
        self.inner.add_observer(observer);
    }

    fn watch_scope(&self, scope: Scope) -> mpsc::Receiver<ChangeEvent> {
        self.inner.watch_scope(scope)
    }

    fn current_seq(&self) -> u64 {
        self.inner.current_seq()
    }

    fn events_since(&self, seq: u64) -> Option<Vec<ChangeEvent>> {
        self.inner.events_since(seq)
    }
}

impl<C> CachedOxKvStore<C>
where
    C: Cache<String, Arc<SstFile>>,
{
    /// Opens a mirror over `inner`, warming every key into memory.
    ///
    /// Shorthand for [`open_with_mode`](Self::open_with_mode) with
    /// [`WarmMode::Eager`].
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the bulk scan or the manifest load fails.
    pub async fn open(inner: OxKvStore<C>) -> Result<Self> {
        Self::open_with_mode(inner, WarmMode::Eager).await
    }

    /// Opens a mirror over `inner` with the given fill policy.
    ///
    /// Only [`WarmMode::Eager`] warms before returning. The other modes set
    /// the ownership epoch and return immediately. In every mode, the mirror
    /// observes every write that this handle makes from the start.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the bulk scan or the manifest load fails.
    pub async fn open_with_mode(inner: OxKvStore<C>, mode: WarmMode) -> Result<Self> {
        let epoch = inner.epoch();
        let store = Self {
            inner,
            mirror: BTreeStore::default(),
            state: Arc::new(async_lock::Mutex::new(CachedState {
                epoch,
                version: 0,
                sst_ids: BTreeSet::new(),
                replayed: BTreeSet::new(),
                last_check_ms: 0,
                poisoned: None,
                warmed: false,

                warm_cursor: None,
                scanned_keys: BTreeSet::new(),
            })),
            ttl_ms: Arc::new(std::sync::atomic::AtomicU64::new(
                u64::try_from(DEFAULT_STALE_TTL.as_millis()).unwrap_or(u64::MAX),
            )),
            scan_gate: Arc::new(async_lock::Mutex::new(())),
            mode,
        };
        if mode == WarmMode::Eager {
            store.warm().await?;
        }
        Ok(store)
    }

    /// Sets the staleness bound for the `*_checked` reads.
    ///
    /// `Duration::ZERO` revalidates on every checked read. A large bound
    /// serves from memory until the caller calls
    /// [`refresh`](Self::refresh) or [`check_stale`](Self::check_stale)
    /// explicitly.
    #[must_use]
    pub fn with_stale_ttl(self, ttl: Duration) -> Self {
        self.ttl_ms.store(
            u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self
    }

    /// Returns the fill policy chosen at open.
    #[must_use]
    pub fn warm_mode(&self) -> WarmMode {
        self.mode
    }

    /// Returns the durable core for `flush`, `compact`, and `gc_wal`.
    ///
    /// Mirror reads never touch these paths. The maintenance that a caller
    /// issues here does not invalidate the mirror. Compactions and collections
    /// preserve the logical key set.
    #[must_use]
    pub fn inner(&self) -> &OxKvStore<C> {
        &self.inner
    }

    /// Returns the ownership epoch the mirror was built from.
    pub async fn cached_epoch(&self) -> u64 {
        self.state.lock().await.epoch
    }

    /// Returns the manifest version the mirror reflects.
    pub async fn cached_version(&self) -> u64 {
        self.state.lock().await.version
    }

    /// Reports whether the mirror is poisoned by a fencing rejection.
    ///
    /// A poisoned mirror fails reads with [`StoreError::Fenced`]. The mirror
    /// stays poisoned until [`refresh`](Self::refresh) adopts the new owner.
    pub async fn is_poisoned(&self) -> bool {
        self.state.lock().await.poisoned.is_some()
    }

    /// Fails with the fencing message while the mirror is poisoned.
    async fn reject_if_poisoned(&self) -> Result<()> {
        if let Some(reason) = self.state.lock().await.poisoned.clone() {
            return Err(StoreError::Fenced(reason));
        }
        Ok(())
    }

    /// Records a fencing rejection for subsequent reads.
    async fn poison(&self, reason: String) {
        self.state.lock().await.poisoned = Some(reason);
    }

    /// Poisons the mirror when `err` is a fencing rejection.
    async fn note_fenced(&self, err: &StoreError) {
        if let StoreError::Fenced(reason) = err {
            self.poison(reason.clone()).await;
        }
    }

    /// Pulls the just-published manifest generation into the sync state.
    ///
    /// Our own writes publish before returning. Therefore a cache peek
    /// observes them without I/O. Later refreshes skip re-applying our own
    /// WALs.
    async fn sync_after_write(&self) {
        let snapshot = {
            let guard = self.inner.manifest_cache().lock().await;
            guard
                .get_cached(CACHE_PEEK_TTL)
                .map(|(manifest, _)| manifest)
        };
        if let Some(manifest) = snapshot {
            let mut state = self.state.lock().await;
            observe_manifest(&mut state, &manifest);
        }
    }

    /// Revalidates when the staleness bound elapsed.
    async fn maybe_refresh(&self) -> Result<()> {
        let ttl_ms = self.ttl_ms.load(std::sync::atomic::Ordering::Relaxed);
        let expired = {
            let state = self.state.lock().await;
            state.poisoned.is_some() || ttl_expired(state.last_check_ms, ttl_ms)
        };
        if expired {
            self.refresh().await?;
        }
        Ok(())
    }

    /// Returns `true` when the mirror lags the durable core.
    ///
    /// The method polls `manifest.json` conditionally. It compares `version`
    /// and the SST set. The method does not read `ownership.json`. A poisoned
    /// mirror always reports stale.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the manifest poll fails.
    pub async fn check_stale(&self) -> Result<bool> {
        if self.is_poisoned().await {
            return Ok(true);
        }
        let (manifest, _) = load_manifest(
            self.inner.inner_store(),
            self.inner.prefix(),
            self.inner.epoch(),
            self.inner.manifest_cache(),
            Duration::from_secs(0),
        )
        .await?;
        let stale = {
            let state = self.state.lock().await;
            manifest.version != state.version || sst_ids(&manifest) != state.sst_ids
        };
        if !stale {
            self.state.lock().await.last_check_ms = now_millis();
        }
        Ok(stale)
    }

    /// Applies every missing generation to the mirror.
    ///
    /// WAL appends from the same owner replay incrementally. A new ownership
    /// epoch rebuilds from a full scan instead. An SST set change rebuilds
    /// from a full scan instead. An SST set change means a flush or a
    /// collection window that this mirror missed. The method returns the
    /// number of key records that it applied.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the manifest, a WAL file, the ownership
    /// record, or the rebuild scan fails.
    pub async fn refresh(&self) -> Result<usize> {
        let known = {
            let state = self.state.lock().await;
            (
                state.epoch,
                state.version,
                state.sst_ids.clone(),
                state.replayed.clone(),
            )
        };
        let (manifest, _) = load_manifest(
            self.inner.inner_store(),
            self.inner.prefix(),
            self.inner.epoch(),
            self.inner.manifest_cache(),
            Duration::from_secs(0),
        )
        .await?;
        if manifest.version == known.1 && sst_ids(&manifest) == known.2 {
            self.state.lock().await.last_check_ms = now_millis();
            return Ok(0);
        }
        let owner = read_ownership(self.inner.inner_store(), self.inner.prefix()).await?;
        let owner_epoch = owner.map_or(known.0, |record| record.epoch);
        if owner_epoch != known.0 || sst_ids(&manifest) != known.2 {
            let applied = self.warm().await?;
            let mut state = self.state.lock().await;
            state.epoch = owner_epoch;
            state.version = manifest.version;
            state.sst_ids = sst_ids(&manifest);
            state.replayed.extend(manifest.wal.iter().cloned());
            state.last_check_ms = now_millis();
            state.poisoned = None;
            return Ok(applied);
        }
        let missing: Vec<String> = manifest
            .wal
            .iter()
            .filter(|id| !known.3.contains(*id))
            .cloned()
            .collect();
        let applied = self.apply_wal_ids(&missing).await?;
        let mut state = self.state.lock().await;
        state.version = manifest.version;
        state.replayed.extend(manifest.wal.iter().cloned());
        state.last_check_ms = now_millis();
        state.poisoned = None;
        Ok(applied)
    }

    /// Applies listed WAL files to the mirror, skipping collected ones.
    async fn apply_wal_ids(&self, wal_ids: &[String]) -> Result<usize> {
        let mut applied = 0usize;
        for id in wal_ids {
            let path = ObjectPath::from(id.as_str());
            let bytes = match self.inner.inner_store().get(&path).await {
                Ok(out) => out.bytes,
                Err(e) if e.to_string().contains("not found") => continue,
                Err(e) => return Err(e),
            };
            for (key, value) in decode_wal_records(&bytes) {
                match value {
                    Some(raw) => self.mirror.put_bytes(&key, &raw).await?,
                    None => {
                        self.mirror.delete(&key).await?;
                    }
                }
                applied += 1;
            }
        }
        Ok(applied)
    }

    /// Rebuilds the mirror from a full scan of the durable core.
    ///
    /// The listed WAL files overlay the scan with a newest-wins rule. The
    /// scan only sees the SSTs and the local `MemTable`. Without the overlay,
    /// the scan would miss the unflushed generations from another owner.
    /// Reports whether the full dataset is mirrored.
    ///
    /// The result is `true` in these cases:
    ///
    /// - The mode is [`WarmMode::Eager`] and `open` has returned.
    /// - [`warm`](Self::warm) completed the scan.
    /// - Enough [`warm_step`](Self::warm_step) calls completed the scan.
    /// - A [`refresh`](Self::refresh) rebuilt the mirror.
    ///
    /// Until the result turns `true`, reads fall through to the durable core
    /// on mirror misses.
    pub async fn is_warmed(&self) -> bool {
        self.state.lock().await.warmed
    }

    /// Scans the whole store into the mirror, however many pages it takes.
    ///
    /// The method converges [`WarmMode::Background`] and [`WarmMode::Lazy`]
    /// handles to the eager steady state. The method also converges any
    /// handle again after a missed generation. The method returns the number
    /// of key records that it applied.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the manifest, a WAL file, or the scan
    /// fails.
    pub async fn warm(&self) -> Result<usize> {
        let _gate = self.scan_gate.lock().await;
        {
            let mut state = self.state.lock().await;
            state.warmed = false;
            state.warm_cursor = None;
            state.scanned_keys.clear();
        }
        let mut applied = 0usize;
        loop {
            let (done, step_applied) = self.warm_pages(u32::MAX).await?;
            applied += step_applied;
            if done {
                break;
            }
        }
        Ok(applied)
    }

    /// Advances an explicitly driven scan by up to `pages` SST pages.
    ///
    /// A caller drives this method from any task or timer. The method
    /// converges a [`WarmMode::Background`] handle without blocking `open`.
    /// Each call resumes where the previous call stopped. The final call
    /// overlays the listed WAL files. The final call also computes the
    /// deletion difference. The final call also marks the mirror warmed. The
    /// method returns `true` once the full dataset is mirrored. Concurrent
    /// drivers serialize on an internal gate. Therefore double-driving only
    /// wastes work.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when the manifest, a WAL file, or the scan
    /// fails.
    pub async fn warm_step(&self, pages: u32) -> Result<bool> {
        let _gate = self.scan_gate.lock().await;
        let (done, _) = self.warm_pages(pages.max(1)).await?;
        Ok(done)
    }

    /// Scans up to `max_pages` SST pages into the mirror.
    ///
    /// The method returns whether the scan exhausted the store. The method
    /// also returns the number of records that this call applied. The final
    /// call finishes the generation. The final call applies the WAL overlay.
    /// The final call also computes the deletion difference. The final call
    /// also publishes the sync state.
    async fn warm_pages(&self, max_pages: u32) -> Result<(bool, usize)> {
        if self.state.lock().await.warmed {
            return Ok((true, 0));
        }
        let (manifest, _) = load_manifest(
            self.inner.inner_store(),
            self.inner.prefix(),
            self.inner.epoch(),
            self.inner.manifest_cache(),
            Duration::from_secs(0),
        )
        .await?;
        let mut applied = 0usize;
        let mut pages = 0u32;
        loop {
            if pages >= max_pages {
                return Ok((false, applied));
            }
            let cursor = self.state.lock().await.warm_cursor.clone();
            let batch = self
                .inner
                .gets_bytes(Some(SCAN_BATCH), Direction::Next, (cursor.clone(), None))
                .await?;
            if batch.is_empty() {
                self.finish_warm(&manifest).await?;
                return Ok((true, applied));
            }
            let last = batch.last().map(|kv| kv.key.clone());
            let short = batch.len() < SCAN_BATCH;
            let mut state = self.state.lock().await;
            for kv in batch {
                if cursor.as_deref() == Some(kv.key.as_str()) {
                    continue;
                }
                state.scanned_keys.insert(kv.key.clone());
                drop(state);
                self.mirror.put_bytes(&kv.key, &kv.value).await?;
                applied += 1;
                state = self.state.lock().await;
            }
            state.warm_cursor = last;

            drop(state);
            pages += 1;
            if short {
                self.finish_warm(&manifest).await?;
                return Ok((true, applied));
            }
        }
    }

    /// Overlays the listed WAL files. Computes the deletion difference.
    /// Publishes the sync state. These steps complete one warming generation.
    async fn finish_warm(&self, manifest: &Manifest) -> Result<()> {
        for id in &manifest.wal {
            let path = ObjectPath::from(id.as_str());
            let bytes = match self.inner.inner_store().get(&path).await {
                Ok(out) => out.bytes,
                Err(e) if e.to_string().contains("not found") => continue,
                Err(e) => return Err(e),
            };
            for (key, value) in decode_wal_records(&bytes) {
                if let Some(raw) = value {
                    self.mirror.put_bytes(&key, &raw).await?;
                    self.state.lock().await.scanned_keys.insert(key);
                } else {
                    self.mirror.delete(&key).await?;
                    self.state.lock().await.scanned_keys.remove(&key);
                }
            }
        }
        let scanned = {
            let mut state = self.state.lock().await;
            std::mem::take(&mut state.scanned_keys)
        };
        let current = self
            .mirror
            .gets_bytes(None, Direction::Next, (None, None))
            .await?;
        for kv in &current {
            if !scanned.contains(&kv.key) {
                self.mirror.delete(&kv.key).await?;
            }
        }
        let mut state = self.state.lock().await;
        observe_manifest(&mut state, manifest);
        state.warm_cursor = None;

        state.warmed = true;
        Ok(())
    }

    /// Reads `key` from memory. Revalidates first when the bound elapsed.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when revalidation fails or the mirror is poisoned.
    pub async fn get_bytes_checked(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.maybe_refresh().await?;
        self.get_bytes(key).await
    }

    /// Checks `key` in memory. Revalidates first when the bound elapsed.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when revalidation fails or the mirror is poisoned.
    pub async fn has_checked(&self, key: &str) -> Result<bool> {
        self.maybe_refresh().await?;
        self.has(key).await
    }

    /// Scans memory in `direction`. Revalidates first when the bound
    /// elapsed.
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] when revalidation fails or the mirror is poisoned.
    pub async fn gets_bytes_checked(
        &self,
        limit: Option<usize>,
        direction: Direction,
        cursor: (Option<String>, Option<String>),
    ) -> Result<Vec<KeyValue>> {
        self.maybe_refresh().await?;
        self.gets_bytes(limit, direction, cursor).await
    }
}

#[async_trait]
impl<C> GetSet for CachedOxKvStore<C>
where
    C: Cache<String, Arc<SstFile>>,
{
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.reject_if_poisoned().await?;
        if let Some(value) = self.mirror.get_bytes(key).await? {
            return Ok(Some(value));
        }
        if self.state.lock().await.warmed {
            return Ok(None);
        }
        let value = self.inner.get_bytes(key).await?;
        if let Some(raw) = &value {
            self.mirror.put_bytes(key, raw).await?;
        }
        Ok(value)
    }

    async fn has(&self, key: &str) -> Result<bool> {
        self.reject_if_poisoned().await?;
        if self.mirror.has(key).await? {
            return Ok(true);
        }
        if self.state.lock().await.warmed {
            return Ok(false);
        }
        self.inner.has(key).await
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        self.reject_if_poisoned().await?;
        match self.inner.delete(key).await {
            Err(e) => {
                self.note_fenced(&e).await;
                Err(e)
            }
            Ok(existed) => {
                if existed {
                    self.mirror.delete(key).await?;
                }
                self.sync_after_write().await;
                Ok(existed)
            }
        }
    }

    async fn set_bytes(&self, key: &str, value: &[u8]) -> Result<Option<Vec<u8>>> {
        self.reject_if_poisoned().await?;
        let prev = self.mirror.get_bytes(key).await?;
        if let Err(e) = self.inner.set_bytes(key, value).await {
            self.note_fenced(&e).await;
            return Err(e);
        }
        self.mirror.put_bytes(key, value).await?;
        self.sync_after_write().await;
        Ok(prev)
    }

    async fn put_bytes(&self, key: &str, value: &[u8]) -> Result<()> {
        self.reject_if_poisoned().await?;
        if let Err(e) = self.inner.put_bytes(key, value).await {
            self.note_fenced(&e).await;
            return Err(e);
        }
        self.mirror.put_bytes(key, value).await?;
        self.sync_after_write().await;
        Ok(())
    }

    async fn gets_bytes(
        &self,
        limit: Option<usize>,
        direction: Direction,
        cursor: (Option<String>, Option<String>),
    ) -> Result<Vec<KeyValue>> {
        self.reject_if_poisoned().await?;
        if self.state.lock().await.warmed {
            return self.mirror.gets_bytes(limit, direction, cursor).await;
        }
        self.inner.gets_bytes(limit, direction, cursor).await
    }
}

#[async_trait]
impl<C> Store for CachedOxKvStore<C>
where
    C: Cache<String, Arc<SstFile>>,
{
    type Transaction = CachedTx<C>;

    fn begin_tx(&self) -> Result<Self::Transaction> {
        Ok(CachedTx {
            tx: self.inner.begin_tx()?,
            mirror: self.mirror.clone(),
            staged: std::sync::Mutex::new(BTreeMap::new()),
            state: Arc::clone(&self.state),
            manifest_cache: Arc::clone(self.inner.manifest_cache()),
        })
    }
}

/// Merges staged transaction records over base rows in `direction` order.
///
/// Staged deletes suppress their keys. Staged sets replace or extend them.
/// The function truncates the result to `limit` after it sorts the result.
/// Therefore the callers pass unbounded base scans. Therefore the callers pay
/// only for the merge.
fn merge_staged(
    mut rows: Vec<KeyValue>,
    staged: &BTreeMap<String, Option<Vec<u8>>>,
    direction: Direction,
    cursor: &(Option<String>, Option<String>),
    limit: Option<usize>,
) -> Vec<KeyValue> {
    for (key, value) in staged {
        if !in_window(key, direction, cursor) {
            continue;
        }
        rows.retain(|kv| kv.key != *key);
        if let Some(raw) = value {
            rows.push(KeyValue {
                key: key.clone(),
                value: raw.clone(),
            });
        }
    }
    match direction {
        Direction::Next => rows.sort_by(|a, b| a.key.cmp(&b.key)),
        Direction::Prev => rows.sort_by(|a, b| b.key.cmp(&a.key)),
    }
    if let Some(bound) = limit {
        rows.truncate(bound);
    }
    rows
}

/// Transaction over a [`CachedOxKvStore`].
///
/// The reads merge the staged overlay with the mirror. Therefore no storage
/// I/O happens before the commit once the mirror is warmed. Before that, the
/// reads fall through to the durable transaction. Those reads do not fill the
/// shared mirror. The overlay reaches memory only after the durable commit
/// succeeds.
pub struct CachedTx<C = LruCache<String, Arc<SstFile>>> {
    tx: OxKvTx<C>,
    mirror: BTreeStore,
    staged: std::sync::Mutex<BTreeMap<String, Option<Vec<u8>>>>,
    state: Arc<async_lock::Mutex<CachedState>>,
    manifest_cache: Arc<async_lock::Mutex<ManifestCache>>,
}

impl<C> std::fmt::Debug for CachedTx<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedTx").finish_non_exhaustive()
    }
}

#[async_trait]
impl<C> GetSet for CachedTx<C>
where
    C: Cache<String, Arc<SstFile>>,
{
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if let Some(staged) = lock_ignore_poison(&self.staged).get(key) {
            return Ok(staged.clone());
        }
        if let Some(value) = self.mirror.get_bytes(key).await? {
            return Ok(Some(value));
        }
        if self.state.lock().await.warmed {
            return Ok(None);
        }
        self.tx.get_bytes(key).await
    }

    async fn has(&self, key: &str) -> Result<bool> {
        if let Some(staged) = lock_ignore_poison(&self.staged).get(key) {
            return Ok(staged.is_some());
        }
        if self.mirror.has(key).await? {
            return Ok(true);
        }
        if self.state.lock().await.warmed {
            return Ok(false);
        }
        self.tx.has(key).await
    }

    async fn delete(&self, key: &str) -> Result<bool> {
        if let Some(None) = lock_ignore_poison(&self.staged).get(key) {
            return Ok(false);
        }
        let existed = self.tx.delete(key).await?;
        if existed {
            lock_ignore_poison(&self.staged).insert(key.to_string(), None);
        }
        Ok(existed)
    }

    async fn set_bytes(&self, key: &str, value: &[u8]) -> Result<Option<Vec<u8>>> {
        let prev = self.get_bytes(key).await?;
        self.tx.put_bytes(key, value).await?;
        lock_ignore_poison(&self.staged).insert(key.to_string(), Some(value.to_vec()));
        Ok(prev)
    }

    async fn put_bytes(&self, key: &str, value: &[u8]) -> Result<()> {
        self.tx.put_bytes(key, value).await?;
        lock_ignore_poison(&self.staged).insert(key.to_string(), Some(value.to_vec()));
        Ok(())
    }

    async fn gets_bytes(
        &self,
        limit: Option<usize>,
        direction: Direction,
        cursor: (Option<String>, Option<String>),
    ) -> Result<Vec<KeyValue>> {
        let staged = lock_ignore_poison(&self.staged).clone();
        let warmed = self.state.lock().await.warmed;
        let rows = if warmed {
            self.mirror
                .gets_bytes(None, direction, cursor.clone())
                .await?
        } else {
            self.tx.gets_bytes(None, direction, cursor.clone()).await?
        };
        Ok(merge_staged(rows, &staged, direction, &cursor, limit))
    }
}

#[async_trait]
impl<C> TxCas for CachedTx<C>
where
    C: Cache<String, Arc<SstFile>>,
{
    /// Stages a set-if-absent in the inner transaction and in the mirror
    /// overlay. The inner commit checks the precondition. A failed inner
    /// commit does not touch the mirror.
    async fn set_if_absent(&self, key: &str, value: &[u8]) -> Result<()> {
        self.tx.set_if_absent(key, value).await?;
        lock_ignore_poison(&self.staged).insert(key.to_string(), Some(value.to_vec()));
        Ok(())
    }

    /// Stages a compare-and-set in the inner transaction and in the mirror
    /// overlay. The inner commit checks the precondition. A failed inner
    /// commit does not touch the mirror.
    async fn compare_and_set(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<()> {
        self.tx.compare_and_set(key, expected, new).await?;
        lock_ignore_poison(&self.staged).insert(key.to_string(), Some(new.to_vec()));
        Ok(())
    }

    /// Stages a conditional delete in the inner transaction and in the mirror
    /// overlay. The inner commit checks the precondition. A failed inner
    /// commit does not touch the mirror.
    async fn delete_if(&self, key: &str, expected: &[u8]) -> Result<()> {
        self.tx.delete_if(key, expected).await?;
        lock_ignore_poison(&self.staged).insert(key.to_string(), None);
        Ok(())
    }
}

#[async_trait]
impl<C> Transaction for CachedTx<C>
where
    C: Cache<String, Arc<SstFile>>,
{
    async fn commit(self) -> Result<()> {
        let Self {
            tx,
            mirror,
            staged,
            state,
            manifest_cache,
        } = self;
        let staged = lock_ignore_poison(&staged).clone();
        if let Err(e) = tx.commit().await {
            if let StoreError::Fenced(reason) = &e {
                state.lock().await.poisoned = Some(reason.clone());
            }
            return Err(e);
        }
        for (key, value) in &staged {
            match value {
                Some(raw) => mirror.put_bytes(key, raw).await?,
                None => {
                    mirror.delete(key).await?;
                }
            }
        }
        let snapshot = {
            let guard = manifest_cache.lock().await;
            guard
                .get_cached(CACHE_PEEK_TTL)
                .map(|(manifest, _)| manifest)
        };
        if let Some(manifest) = snapshot {
            let mut guard = state.lock().await;
            observe_manifest(&mut guard, &manifest);
        }
        Ok(())
    }

    async fn rollback(self) -> Result<()> {
        self.tx.rollback().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxkv::{MemStorage, Storage};

    async fn writer(prefix: &str) -> (OxKvStore, Arc<dyn Storage>) {
        let backend: Arc<dyn Storage> = Arc::new(MemStorage::new());
        let store = OxKvStore::builder()
            .with_store(Arc::clone(&backend))
            .with_prefix(ObjectPath::from(prefix))
            .skip_probe(true)
            .build()
            .await
            .expect("build");
        (store, backend)
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn open_warms_existing_keys() {
        let (writer, _) = writer("cached-warm").await;
        writer.put_bytes("a", b"1").await.expect("put");
        writer.put_bytes("b", b"2").await.expect("put");
        let cached = CachedOxKvStore::open(writer).await.expect("open");
        assert_eq!(
            cached.get_bytes("a").await.expect("get"),
            Some(b"1".to_vec())
        );
        assert!(cached.has("b").await.expect("has"));
        assert!(!cached.check_stale().await.expect("fresh"));
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn range_reads_serve_both_directions() {
        let (writer, _) = writer("cached-range").await;
        for key in ["a", "b", "c"] {
            writer.put_bytes(key, b"v").await.expect("put");
        }
        let cached = CachedOxKvStore::open(writer).await.expect("open");
        let next = cached
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .expect("scan");
        assert_eq!(next.len(), 3);
        let prev = cached
            .gets_bytes(None, Direction::Prev, (Some("c".to_string()), None))
            .await
            .expect("scan");
        let keys: Vec<&str> = prev.iter().map(|kv| kv.key.as_str()).collect();
        assert_eq!(keys, ["c", "b", "a"]);
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn direct_writes_flow_through_to_storage() {
        let (writer, _) = writer("cached-write").await;
        let cached = CachedOxKvStore::open(writer).await.expect("open");
        assert_eq!(cached.set_bytes("k", b"v1").await.expect("set"), None);
        assert_eq!(
            cached.set_bytes("k", b"v2").await.expect("set"),
            Some(b"v1".to_vec())
        );
        cached.put_bytes("blind", b"b").await.expect("put");
        assert!(cached.delete("blind").await.expect("delete"));
        assert!(!cached.delete("blind").await.expect("delete"));
        let inner = cached.inner();
        assert_eq!(
            inner.get_bytes("k").await.expect("get"),
            Some(b"v2".to_vec())
        );
        assert_eq!(inner.get_bytes("blind").await.expect("get"), None);
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn checked_reads_follow_takeover() {
        let (writer, backend) = writer("cached-takeover").await;
        writer.put_bytes("a", b"1").await.expect("put");
        let cached = CachedOxKvStore::open(writer).await.expect("open");
        let before = cached.cached_epoch().await;
        let rival = OxKvStore::builder()
            .with_store(Arc::clone(&backend))
            .with_prefix(ObjectPath::from("cached-takeover"))
            .skip_probe(true)
            .build()
            .await
            .expect("takeover");
        rival.put_bytes("b", b"2").await.expect("put");
        assert!(cached.check_stale().await.expect("stale"));
        let applied = cached.refresh().await.expect("refresh");
        assert!(applied >= 1);
        assert!(cached.cached_epoch().await > before);
        assert_eq!(
            cached.get_bytes_checked("b").await.expect("get"),
            Some(b"2".to_vec())
        );
        assert_eq!(
            cached.get_bytes("a").await.expect("get"),
            Some(b"1".to_vec())
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn fenced_write_poisons_until_refresh() {
        let (writer, backend) = writer("cached-fence").await;
        writer.put_bytes("a", b"1").await.expect("put");
        let cached = CachedOxKvStore::open(writer).await.expect("open");
        let rival = OxKvStore::builder()
            .with_store(Arc::clone(&backend))
            .with_prefix(ObjectPath::from("cached-fence"))
            .skip_probe(true)
            .build()
            .await
            .expect("takeover");
        rival.put_bytes("b", b"2").await.expect("put");
        assert!(matches!(
            cached.put_bytes("x", b"y").await,
            Err(StoreError::Fenced(_))
        ));
        assert!(cached.is_poisoned().await);
        assert!(matches!(
            cached.get_bytes("a").await,
            Err(StoreError::Fenced(_))
        ));
        cached.refresh().await.expect("refresh");
        assert!(!cached.is_poisoned().await);
        assert_eq!(
            cached.get_bytes("b").await.expect("get"),
            Some(b"2".to_vec())
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn tx_commit_applies_and_rollback_discards() {
        let (writer, _) = writer("cached-tx").await;
        writer.put_bytes("keep", b"0").await.expect("put");
        let cached = CachedOxKvStore::open(writer).await.expect("open");
        let tx = cached.begin_tx().expect("tx");
        tx.set_bytes(" staged", b"1").await.expect("stage");
        tx.put_bytes("keep", b"9").await.expect("stage");
        tx.delete("missing").await.expect("delete");
        assert_eq!(cached.get_bytes(" staged").await.expect("get"), None);
        tx.commit().await.expect("commit");
        assert_eq!(
            cached.get_bytes(" staged").await.expect("get"),
            Some(b"1".to_vec())
        );
        assert_eq!(
            cached.inner().get_bytes("keep").await.expect("get"),
            Some(b"9".to_vec())
        );
        let tx = cached.begin_tx().expect("tx");
        tx.set_bytes("ghost", b"g").await.expect("stage");
        tx.delete("keep").await.expect("stage");
        tx.rollback().await.expect("rollback");
        assert_eq!(cached.get_bytes("ghost").await.expect("get"), None);
        assert_eq!(
            cached.get_bytes("keep").await.expect("get"),
            Some(b"9".to_vec())
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn tx_cas_applies_to_the_mirror_only_after_a_successful_commit() {
        let (writer, _) = writer("cached-tx-cas").await;
        writer.put_bytes("claim", b"owner").await.expect("put");
        let cached = CachedOxKvStore::open(writer).await.expect("open");

        let tx = cached.begin_tx().expect("tx");
        tx.compare_and_set("claim", Some(b"owner"), b"next")
            .await
            .expect("stage");
        assert_eq!(
            tx.get_bytes("claim").await.expect("staged read"),
            Some(b"next".to_vec()),
            "the transaction must read its own staged write"
        );
        tx.commit().await.expect("commit");
        assert_eq!(
            cached.get_bytes("claim").await.expect("mirror"),
            Some(b"next".to_vec())
        );
        assert_eq!(
            cached.inner().get_bytes("claim").await.expect("core"),
            Some(b"next".to_vec())
        );

        let tx = cached.begin_tx().expect("tx");
        tx.set_if_absent("claim", b"other").await.expect("stage");
        let error = tx.commit().await.expect_err("conflict");
        assert_eq!(
            error,
            StoreError::TxConflict {
                key: "claim".to_string(),
                current: Some(b"next".to_vec()),
            }
        );
        assert_eq!(
            cached.get_bytes("claim").await.expect("mirror"),
            Some(b"next".to_vec()),
            "a failed commit must not change the mirror"
        );
        assert_eq!(
            cached.inner().get_bytes("claim").await.expect("core"),
            Some(b"next".to_vec()),
            "a failed commit must not change the core"
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn build_cached_warms_and_serves() {
        let backend: Arc<dyn Storage> = Arc::new(MemStorage::new());
        let seed = OxKvStore::builder()
            .with_store(Arc::clone(&backend))
            .with_prefix(ObjectPath::from("cached-builder"))
            .skip_probe(true)
            .build()
            .await
            .expect("seed");
        seed.put_bytes("k", b"v").await.expect("put");
        drop(seed);
        let cached = OxKvStore::builder()
            .with_store(Arc::clone(&backend))
            .with_prefix(ObjectPath::from("cached-builder"))
            .skip_probe(true)
            .build_cached()
            .await
            .expect("build_cached");
        assert_eq!(
            cached.get_bytes("k").await.expect("get"),
            Some(b"v".to_vec())
        );
        let small = LruCache::new(1024, |_: &String, v: &Arc<SstFile>| {
            u32::try_from(v.size()).unwrap_or(u32::MAX)
        });
        let custom = OxKvStore::builder()
            .with_store(backend)
            .with_prefix(ObjectPath::from("cached-builder-custom"))
            .skip_probe(true)
            .build_cached_with_cache(small)
            .await
            .expect("build_cached_with_cache");
        custom.put_bytes("j", b"w").await.expect("put");
        assert_eq!(
            custom.get_bytes("j").await.expect("get"),
            Some(b"w".to_vec())
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn composes_with_hook_decorator() {
        struct RequireJson;

        #[async_trait::async_trait]
        impl Validator for RequireJson {
            async fn validate(
                &self,
                _ctx: &dyn oxkv::StoreView,
                key: &str,
                value: &[u8],
            ) -> Result<()> {
                serde_json::from_slice::<serde_json::Value>(value)
                    .map(|_| ())
                    .map_err(|e| StoreError::Rejected {
                        key: key.to_string(),
                        reason: e.to_string(),
                    })
            }
        }

        let (writer, _) = writer("cached-hooks").await;
        let cached = CachedOxKvStore::open(writer).await.expect("open");
        let hooked = cached.clone().with_validator(RequireJson);
        assert!(hooked.set_bytes("raw", b"nope").await.is_err());
        hooked
            .set_bytes("doc", br#"{"ok":true}"#)
            .await
            .expect("valid");
        assert_eq!(
            cached.get_bytes("doc").await.expect("get"),
            Some(br#"{"ok":true}"#.to_vec())
        );
        let scoped = cached.with_validator(RequireJson);
        let _ = scoped.watch_all();
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn eager_opens_fully_warmed() {
        let (writer, _) = writer("cached-eager").await;
        writer.put_bytes("a", b"1").await.expect("put");
        let cached = CachedOxKvStore::open_with_mode(writer, WarmMode::Eager)
            .await
            .expect("open");
        assert!(cached.is_warmed().await);
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn lazy_falls_through_and_fills_on_miss() {
        let (writer, _) = writer("cached-lazy").await;
        let cached = CachedOxKvStore::open_with_mode(writer, WarmMode::Lazy)
            .await
            .expect("open");
        assert!(!cached.is_warmed().await);
        cached.put_bytes("hot", b"1").await.expect("put");
        assert_eq!(
            cached.get_bytes("hot").await.expect("get"),
            Some(b"1".to_vec())
        );
        cached
            .inner()
            .put_bytes("cold", b"2")
            .await
            .expect("direct put");
        assert_eq!(
            cached.get_bytes("cold").await.expect("fall through"),
            Some(b"2".to_vec())
        );
        assert_eq!(
            cached.inner().get_bytes("cold").await.expect("oracle"),
            cached.get_bytes("cold").await.expect("filled"),
        );
        let rows = cached
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .expect("scan falls through");
        assert_eq!(rows.len(), 2);
        assert!(!cached.is_warmed().await);
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn background_steps_converge_to_warmed() {
        let (writer, _) = writer("cached-background").await;
        for i in 0..10 {
            writer
                .put_bytes(&format!("k{i:02}"), b"v")
                .await
                .expect("put");
        }
        let cached = CachedOxKvStore::open_with_mode(writer, WarmMode::Background)
            .await
            .expect("open");
        assert!(!cached.is_warmed().await);
        assert!(cached.warm_step(1).await.expect("step"));
        assert!(cached.is_warmed().await);
        let rows = cached
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .expect("scan");
        assert_eq!(rows.len(), 10);
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn warm_converges_lazy_handle() {
        let (writer, _) = writer("cached-lazy-warm").await;
        writer.put_bytes("a", b"1").await.expect("put");
        let cached = CachedOxKvStore::open_with_mode(writer, WarmMode::Lazy)
            .await
            .expect("open");
        let applied = cached.warm().await.expect("warm");
        assert!(applied >= 1);
        assert!(cached.is_warmed().await);
        assert!(!cached.check_stale().await.expect("fresh"));
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn tx_reads_fall_through_before_warmed() {
        let (writer, _) = writer("cached-tx-cold").await;
        let cached = CachedOxKvStore::open_with_mode(writer, WarmMode::Lazy)
            .await
            .expect("open");
        cached.put_bytes("a", b"1").await.expect("put");
        cached
            .inner()
            .put_bytes("b", b"2")
            .await
            .expect("direct put");
        let tx = cached.begin_tx().expect("tx");
        assert_eq!(
            tx.get_bytes("b").await.expect("fall through"),
            Some(b"2".to_vec())
        );
        let rows = tx
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .expect("scan");
        assert_eq!(rows.len(), 2);
        tx.rollback().await.expect("rollback");
    }

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    async fn tx_reads_merge_staged_with_mirror() {
        let (writer, _) = writer("cached-tx-read").await;
        for key in ["a", "b", "c"] {
            writer.put_bytes(key, b"v").await.expect("put");
        }
        let cached = CachedOxKvStore::open(writer).await.expect("open");
        let tx = cached.begin_tx().expect("tx");
        tx.delete("b").await.expect("stage");
        tx.set_bytes("d", b"new").await.expect("stage");
        assert_eq!(tx.get_bytes("b").await.expect("get"), None);
        assert_eq!(tx.get_bytes("d").await.expect("get"), Some(b"new".to_vec()));
        let rows = tx
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .expect("scan");
        let keys: Vec<&str> = rows.iter().map(|kv| kv.key.as_str()).collect();
        assert_eq!(keys, ["a", "c", "d"]);
        tx.rollback().await.expect("rollback");
    }
}
