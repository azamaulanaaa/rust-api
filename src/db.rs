//! Storage plumbing: the OxKV store factory and the single-writer lease.
//!
//! The module turns an S3 configuration and a prefix into an `object_store`
//! and an `oxkv::OxKvStore`. It uses the same bucket, region, and endpoint
//! settings as the store for the file bytes. It uses a separate prefix for
//! the transactional keys, which are `p:`, `g:`, `fs:`, and `wal:`. So one
//! bucket holds both sets of data.
//!
//! [`WriterLease`](crate::lease::WriterLease) lives in another module.
//! `oxkv` takes ownership with a CAS bump on `ownership.json`. So the last
//! writer wins. A second process on the same prefix cannot be *detected*
//! through `oxkv`. It can only fence the first one at write time. The lease
//! is the half that `oxkv` does not provide. The lease is a record of the
//! heartbeat in the same bucket. It makes a predecessor that is still alive
//! visible at startup.

use std::sync::Arc;

use object_store::ObjectStore;
use oxkv::{LruCache, ObjectPath, OxKvStore, SstFile, StoreError};

use crate::fs::s3::{S3Backend, S3ClientConfig};

/// Builds an `Arc<dyn ObjectStore>` from [`S3ClientConfig`].
///
/// The function calls [`s3_builder`](crate::fs::object_store::s3_builder), so
/// the client for the file bytes and the OxKV stores share one
/// `AmazonS3Builder` setup. It returns the raw store, so that
/// `OxKvStoreBuilder` can wrap it.
pub fn build_object_store(
    cfg: &S3ClientConfig,
) -> Result<Arc<dyn ObjectStore>, object_store::Error> {
    if cfg.backend == S3Backend::Memory {
        let store = crate::fs::object_store::shared_memory_store();
        return Ok(store as Arc<dyn ObjectStore>);
    }
    let store = crate::fs::object_store::s3_builder(cfg).build()?;
    Ok(Arc::new(store))
}

/// Builds a fenced [`OxKvStore`] at `prefix` inside the bucket of `cfg`.
///
/// `prefix` is the object prefix. An example is `"oxkv"`, where the keys live
/// under `oxkv/ownership.json` and `oxkv/e000000/wal/...`.
///
/// Contract: keep exactly one live handle per prefix. Each store that the
/// function builds owns a new session. A session has a memtable and a WAL
/// buffer. Two live handles on one prefix can fence each other. They can also
/// diverge on a real S3. Share the handle with `Arc` instead of building a
/// second one. A clone of the handle shares the state of the writer.
pub async fn build_s3_store(cfg: &S3ClientConfig, prefix: &str) -> Result<OxKvStore, StoreError> {
    let inner = build_object_store(cfg).map_err(|e| StoreError::Other(e.to_string()))?;
    let object_prefix = ObjectPath::from(prefix.trim_matches('/'));
    let mut builder = OxKvStore::builder()
        .with_object_store(inner)
        .with_prefix(object_prefix);
    if cfg.backend == S3Backend::Memory {
        builder = builder.skip_probe(true);
    }
    builder.build().await
}

/// Default cache of SST blocks for the calls that open a replica.
///
/// This is the same 256 MB S3-FIFO size that oxkv sets for each handle in
/// `build()`. One instance that every call shares is better than a cold cache
/// that every handle drops. Sharing means that a rebuild does not receive hot
/// SSTs again. The clones coordinate through the shared state.
pub fn default_sst_cache() -> LruCache<String, Arc<SstFile>> {
    LruCache::new(256 * 1024 * 1024, |_: &String, v: &Arc<SstFile>| {
        u32::try_from(v.size()).unwrap_or(u32::MAX)
    })
}

/// Builds an OxKV prefix for one test that cannot collide with another.
///
/// `name` identifies the test or the test data, for example `"fs-store"`. The
/// function appends the process ID and a random suffix. So two tests never
/// share a prefix. That is true within one binary, because the tests run at
/// the same time. It is also true across two calls of `cargo test` that run
/// at the same time. It is also true when a stray object is left in a real
/// bucket. Use this function with the `build_test_store*` family, not with a
/// fixed string. A shared prefix silently fences the session of another test
/// through the oxkv epoch. That failure appears only at random, and only
/// under load.
#[cfg(test)]
pub fn test_prefix(name: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    format!(
        "{name}-{}-{}",
        std::process::id(),
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>())
    )
}

/// Builds an [`OxKvStore`] in memory for a test. The function uses
/// `skip_probe(true)`, because `InMemory` has no probe for a
/// conditional write. Each prefix gets a new `InMemory`, so the tests
/// stay separate. To open the same prefix again inside one test, use
/// [`build_test_store_new_session`].
#[cfg(test)]
#[allow(clippy::expect_used)]
pub async fn build_test_store(prefix: &str) -> OxKvStore {
    let inner = Arc::new(object_store::memory::InMemory::new()) as Arc<dyn ObjectStore>;
    OxKvStore::builder()
        .with_object_store(inner)
        .with_prefix(ObjectPath::from(prefix))
        .skip_probe(true)
        .build()
        .await
        .expect("test OxKvStore must build")
}

/// Builds an [`OxKvStore`] in memory over the backend `inner` at `prefix`.
///
/// The function creates a NEW fencing session over the same prefix. The new
/// session has a separate memtable and WAL buffer. The new session replaces
/// the earlier session. So the handle is not shared. That is enough for a
/// single-threaded test that opens the prefix again after it drops the old
/// handle. It is not a model for sharing in production.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub async fn build_test_store_new_session(inner: Arc<dyn ObjectStore>, prefix: &str) -> OxKvStore {
    OxKvStore::builder()
        .with_object_store(inner)
        .with_prefix(ObjectPath::from(prefix))
        .skip_probe(true)
        .build()
        .await
        .expect("test OxKvStore must build")
}

/// Builds an [`OxKvStore`] that is not durable, over a new in-memory object
/// store.
///
/// Production uses this buffer for work such as the assembly of a snapshot
/// before the server uploads it as one S3 object. Nothing here survives
/// the process. The caller owns the persistence. The function uses
/// `skip_probe(true)`, because `InMemory` has no probe for a
/// conditional write. The caller must use a different `prefix` for each
/// buffer. Using one prefix for two buffers is a bug.
#[allow(clippy::expect_used)]
pub async fn build_scratch_store(prefix: &str) -> OxKvStore {
    let inner = Arc::new(object_store::memory::InMemory::new()) as Arc<dyn ObjectStore>;
    OxKvStore::builder()
        .with_object_store(inner)
        .with_prefix(ObjectPath::from(prefix))
        .skip_probe(true)
        .build()
        .await
        .expect("scratch OxKvStore must build")
}

// `build_scratch_store` needs an `#[allow(clippy::expect_used)]` of its
// own. The builders for tests only do not need one. `build_scratch_store` is
// unconditional public API. `sync` uses it to build a snapshot in RAM. So it
// compiles in builds that are not tests. The crate-root
// `cfg_attr(test, allow(..))` does not cover it.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The builders for tests only are not part of the public API.
    ///
    /// They return `InMemory` stores that use `skip_probe(true)`. That is
    /// the safe choice for a test backend with no probe for a conditional
    /// write. It is the *wrong* choice for anything else. Without the probe,
    /// there is no `manifest.json` CAS check and no detection of fencing.
    /// Publishing them as default public API offered exactly that as a
    /// supported way to build a store. The crate has a single-writer design
    /// as its main feature. Every test in this crate can still reach
    /// them. A host application that wants one can build it from
    /// `object_store::memory::InMemory` in three lines. The note about
    /// `skip_probe` in [`build_scratch_store`](Self::build_scratch_store)
    /// already shows that.
    ///
    /// The test leaves out `build_scratch_store` on purpose. `sync` uses it
    /// to build a snapshot in RAM before it uploads the snapshot. So that
    /// function is real API.
    #[test]
    fn test_only_store_builders_are_not_public() {
        for name in [
            "test_prefix",
            "build_test_store",
            "build_test_store_new_session",
        ] {
            let src = std::fs::read_to_string("src/db.rs").expect("readable");
            let needle = format!("pub fn {name}");
            let needle = if src.contains(&needle) {
                needle
            } else {
                // The store builders are async.
                format!("pub async fn {name}")
            };
            let at = src
                .find(&needle)
                .unwrap_or_else(|| panic!("{name} should still exist"));
            // A `#[cfg(test)]` between the doc comment of the item and its
            // signature. rustdoc keeps the attributes in that place.
            let above = &src[..at];
            let gated = above
                .rfind("#[cfg(test)]")
                .is_some_and(|i| !above[i..].contains("///"));
            assert!(gated, "{name} is public API but only used by tests");
        }
    }

    #[tokio::test]
    async fn test_store_roundtrip() -> anyhow::Result<()> {
        let store = build_test_store(&test_prefix("db-test")).await;
        use oxkv::{GetSet, Store as OxStore, Transaction as _};
        let s = store;
        s.set_bytes("hello", b"world").await?;
        assert_eq!(s.get_bytes("hello").await?, Some(b"world".to_vec()));
        let tx = s.begin_tx()?;
        tx.set_bytes("a", b"1").await?;
        tx.commit().await?;
        assert_eq!(s.get_bytes("a").await?, Some(b"1".to_vec()));
        Ok(())
    }
}
