//! OxKV S3Store factory.
//!
//! Centralizes conversion from S3 configuration + prefix into an
//! `object_store` + `oxkv::S3Store`. Reuses the same bucket/region/endpoint
//! settings that the file-byte store uses, but with a distinct prefix for
//! transactional keys (`p:`, `g:`, `fs:`, `wal:`) so one bucket hosts both.

use std::sync::Arc;

use object_store::{ObjectStore, path::Path as ObjectPath};
use oxkv::{S3Store, StoreError};

use crate::fs::s3::S3ClientConfig;

/// Builds an `Arc<dyn ObjectStore>` from [`S3ClientConfig`].
///
/// Delegates to [`s3_builder`](crate::fs::object_store::s3_builder) so the
/// file-byte client and the OxKV stores share one `AmazonS3Builder` setup;
/// returns the raw store so `S3StoreBuilder` can wrap it.
pub fn build_object_store(
    cfg: &S3ClientConfig,
) -> Result<Arc<dyn ObjectStore>, object_store::Error> {
    let store = crate::fs::object_store::s3_builder(cfg).build()?;
    Ok(Arc::new(store))
}

/// Builds a fenced [`S3Store`] at `prefix` inside `cfg`'s bucket.
///
/// `prefix` is the object prefix (e.g. `"oxkv"` -> keys live under
/// `oxkv/ownership.json`, `oxkv/e000000/wal/...`).
///
/// Contract: keep exactly one live handle per prefix. Each built store owns
/// a fresh session (memtable/WAL buffer); two live handles on the same
/// prefix can fence each other or diverge on real S3. Share the handle with
/// `Arc` instead of building a second one.
pub async fn build_s3_store(cfg: &S3ClientConfig, prefix: &str) -> Result<S3Store, StoreError> {
    let inner = build_object_store(cfg).map_err(|e| StoreError::Other(e.to_string()))?;
    let object_prefix = ObjectPath::from(prefix.trim_matches('/'));
    S3Store::builder()
        .with_store(inner)
        .with_prefix(object_prefix)
        .build()
        .await
}

/// Builds an in-memory [`S3Store`] for tests (uses `skip_probe(true)` so
/// `InMemory`'s missing conditional-write probe does not fail). Each prefix gets a
/// fresh `InMemory` so tests are isolated; for sharing across clones within one test
/// use `build_test_store_with_inner`.
#[allow(clippy::expect_used)]
pub async fn build_test_store(prefix: &str) -> S3Store {
    let inner = Arc::new(object_store::memory::InMemory::new()) as Arc<dyn ObjectStore>;
    S3Store::builder()
        .with_store(inner)
        .with_prefix(ObjectPath::from(prefix))
        .skip_probe(true)
        .build()
        .await
        .expect("test S3Store must build")
}

/// Builds an in-memory [`S3Store`] sharing `inner` (for tests that need `clone`-like sharing).
///
/// Note: this creates a NEW session over the same prefix (separate
/// memtable/WAL buffer), not a shared handle — adequate for single-threaded
/// test reopen flows, not a model for production sharing.
#[allow(clippy::expect_used)]
pub async fn build_test_store_with_inner(inner: Arc<dyn ObjectStore>, prefix: &str) -> S3Store {
    S3Store::builder()
        .with_store(inner)
        .with_prefix(ObjectPath::from(prefix))
        .skip_probe(true)
        .build()
        .await
        .expect("test S3Store must build")
}

/// Builds an ephemeral [`S3Store`] over a fresh in-memory object store.
///
/// Production serialization buffer (e.g. assembling a snapshot before
/// uploading it as one S3 object): nothing is durable here, the caller owns
/// persistence. Uses `skip_probe(true)` since `InMemory` has no
/// conditional-write probe. Callers must pass a unique `prefix` per buffer;
/// sharing one prefix across buffers is a bug.
#[allow(clippy::expect_used)]
pub async fn build_scratch_store(prefix: &str) -> S3Store {
    let inner = Arc::new(object_store::memory::InMemory::new()) as Arc<dyn ObjectStore>;
    S3Store::builder()
        .with_store(inner)
        .with_prefix(ObjectPath::from(prefix))
        .skip_probe(true)
        .build()
        .await
        .expect("scratch S3Store must build")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_roundtrip() -> anyhow::Result<()> {
        let store = build_test_store("test-oxkv").await;
        use oxkv::{GetSet, Store as OxStore, Transaction as _};
        let mut s = store;
        s.set_bytes("hello", b"world").await?;
        assert_eq!(s.get_bytes("hello").await?, Some(b"world".to_vec()));
        let mut tx = s.begin_tx()?;
        tx.set_bytes("a", b"1").await?;
        tx.commit().await?;
        assert_eq!(s.get_bytes("a").await?, Some(b"1".to_vec()));
        Ok(())
    }
}
