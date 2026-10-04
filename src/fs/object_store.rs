//! Object-store backend for [`crate::fs::s3::S3Client`].
//!
//! Provides an [`object_store::ObjectStore`] implementation of the S3 abstraction
//! so all file bytes live in a generic object store. Production uses
//! `AmazonS3` (S3, MinIO, R2 via `endpoint_url`) while tests use
//! `InMemory` — no external service required.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::Bytes;

use object_store::ObjectStore;
#[cfg(test)]
use object_store::memory::InMemory;
use object_store::multipart::{MultipartStore, PartId};
use object_store::path::Path as ObjectPath;
use object_store::{Attribute, Attributes, MultipartId, PutOptions, PutPayload};
use tokio::sync::Mutex;

use crate::fs::error::FsError;
use crate::fs::s3::{S3Client, S3ClientConfig};

/// Native multipart state streamed via [`MultipartStore`].
#[derive(Debug)]
struct MultipartState {
    bucket: String,
    key: String,
    path: ObjectPath,
    id: MultipartId,
    /// Part index (0-based) -> `PartId` returned by `put_part`.
    parts: BTreeMap<usize, PartId>,
}

/// Object-store backed [`S3Client`] with true streaming multipart.
///
/// For `AmazonS3` the store is bucket-scoped so `key` alone is the path;
/// for `InMemory` the bucket is prefixed to simulate isolation. Multipart
/// uploads are streamed via [`MultipartStore::put_part`] per part and
/// completed via [`MultipartStore::complete_multipart`], avoiding
/// buffering the entire object in memory.
pub struct ObjectStoreClient {
    store: Arc<dyn ObjectStore>,
    multipart: Arc<dyn MultipartStore>,
    states: Mutex<HashMap<String, MultipartState>>,
    is_memory: bool,
}

impl ObjectStoreClient {
    /// Creates a client from a single `Arc` that implements both traits.
    pub fn new_combined<T>(inner: Arc<T>) -> Self
    where
        T: ObjectStore + MultipartStore + 'static,
    {
        Self {
            store: inner.clone() as Arc<dyn ObjectStore>,
            multipart: inner as Arc<dyn MultipartStore>,
            states: Mutex::new(HashMap::new()),
            is_memory: false,
        }
    }

    /// Creates an in-memory client for unit tests.
    ///
    /// Test-only, and deliberately so. `is_memory` is the only thing that
    /// sets the `InMemory` key layout, where [`Self::path`] prefixes the
    /// bucket onto every key and [`S3Client::list_keys`] strips it back off
    /// the listing. That pairing is a simulation of bucket isolation, not
    /// S3's actual addressing, and the hazard `src/db.rs` documents for the
    /// store builders -- a client whose key layout disagrees with the
    /// backend's -- applies to it exactly as much. Gating it here keeps the
    /// simulation out of production builds, where nothing may obtain one.
    #[cfg(test)]
    pub fn in_memory() -> Arc<dyn S3Client> {
        let inner = Arc::new(InMemory::new());
        Arc::new(Self {
            store: inner.clone() as Arc<dyn ObjectStore>,
            multipart: inner as Arc<dyn MultipartStore>,
            states: Mutex::new(HashMap::new()),
            is_memory: true,
        })
    }

    fn path(&self, bucket: &str, key: &str) -> ObjectPath {
        if self.is_memory {
            ObjectPath::from(format!("{bucket}/{key}"))
        } else {
            ObjectPath::from(key)
        }
    }

    fn map_err(e: object_store::Error) -> FsError {
        match &e {
            object_store::Error::NotFound { .. } => FsError::NotFound(e.to_string()),
            _ => FsError::Internal(e.to_string()),
        }
    }

    fn put_attrs(content_type: Option<&str>, checksum_sha256: Option<&str>) -> Attributes {
        let mut attrs = Attributes::new();
        if let Some(ct) = content_type {
            attrs.insert(Attribute::ContentType, ct.to_string().into());
        }
        if let Some(cs) = checksum_sha256 {
            attrs.insert(
                Attribute::Metadata(Cow::Borrowed("checksum_sha256")),
                cs.to_string().into(),
            );
        }
        attrs
    }
}

#[async_trait]
impl S3Client for ObjectStoreClient {
    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        _content_type: Option<String>,
    ) -> Result<String, FsError> {
        let path = self.path(bucket, key);
        let id = self
            .multipart
            .create_multipart(&path)
            .await
            .map_err(Self::map_err)?;
        let upload_id = format!("ostore-{}", uuid::Uuid::now_v7());
        let mut states = self.states.lock().await;
        states.insert(
            upload_id.clone(),
            MultipartState {
                bucket: bucket.to_string(),
                key: key.to_string(),
                path,
                id,
                parts: BTreeMap::new(),
            },
        );
        Ok(upload_id)
    }

    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
        _checksum_sha256: Option<String>,
    ) -> Result<String, FsError> {
        if part_number < 1 {
            return Err(FsError::BadRequest("part_number must be >= 1".into()));
        }
        let part_idx = (part_number - 1) as usize;
        // Only the two fields the backend call needs are taken under the
        // lock, and the guard dies with this block. It used to live across
        // `put_part` itself -- and had to, because `state.parts.insert`
        // needed the same borrow -- so one slow PUT, or one hung
        // connection with no client-side timeout at this layer, blocked
        // every other multipart part upload in the PROCESS, including
        // unrelated users' uploads, for the full round trip. The map needs
        // microseconds of exclusion.
        let (path, id) = {
            let states = self.states.lock().await;
            let state = states
                .get(upload_id)
                .ok_or_else(|| FsError::Internal(format!("unknown upload_id {upload_id}")))?;
            if state.bucket != bucket || state.key != key {
                return Err(FsError::Internal("bucket/key mismatch".into()));
            }
            (state.path.clone(), state.id.clone())
        };
        let payload = PutPayload::from_bytes(body);
        let part_id = self
            .multipart
            .put_part(&path, &id, part_idx, payload)
            .await
            .map_err(Self::map_err)?;
        let etag = part_id.content_id.clone();
        // Re-locked only to record the id. The entry can legitimately be
        // GONE by now: `complete_multipart_upload` removes it before its
        // own backend call, and a backend that has already assembled the
        // object rejects this part too, so there is nothing to attach the
        // id to and dropping it is the outcome the backend already chose.
        //
        // That is the whole lost-update surface this creates, and it is
        // closed upstream rather than here: every engine entry point takes
        // the session lock across "are all parts present?" and the
        // complete, so a part whose id has not been recorded yet cannot
        // reach this function's `complete` at all. What remains is a
        // client re-uploading a part it already has WHILE completing it,
        // whose interleaving was equally arbitrary when the guard was held
        // across the call.
        let mut states = self.states.lock().await;
        match states.get_mut(upload_id) {
            Some(state) => {
                state.parts.insert(part_idx, part_id);
            }
            None => {
                tracing::debug!(
                    upload_id,
                    part_idx,
                    "multipart state gone while a part was in flight"
                );
            }
        }
        Ok(etag)
    }

    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        etags: Vec<String>,
    ) -> Result<(), FsError> {
        // `remove` hands ownership out, so nothing below needs the guard --
        // it only stayed alive to the end of the function, across the
        // backend call, for the same reason `upload_part` held it.
        let state = {
            let mut states = self.states.lock().await;
            states
                .remove(upload_id)
                .ok_or_else(|| FsError::Internal(format!("unknown upload_id {upload_id}")))?
        };
        if state.bucket != bucket || state.key != key {
            return Err(FsError::Internal("bucket/key mismatch".into()));
        }
        if etags.len() != state.parts.len() {
            return Err(FsError::Internal(format!(
                "etag count {} != part count {}",
                etags.len(),
                state.parts.len()
            )));
        }
        // Verify etags match stored PartIds in order and collect ordered PartIds.
        let mut ordered = Vec::with_capacity(etags.len());
        for (i, etag) in etags.iter().enumerate() {
            let part = state
                .parts
                .get(&i)
                .ok_or_else(|| FsError::Internal(format!("missing part {}", i + 1)))?;
            if &part.content_id != etag {
                return Err(FsError::Internal(format!(
                    "etag mismatch for part {}: expected {}, got {etag}",
                    i + 1,
                    part.content_id
                )));
            }
            ordered.push(part.clone());
        }
        self.multipart
            .complete_multipart(&state.path, &state.id, ordered)
            .await
            .map_err(Self::map_err)?;
        Ok(())
    }

    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), FsError> {
        // Checked under the lock, applied outside it. `remove` already made
        // the state unreachable, so a concurrent caller cannot see a
        // half-aborted upload either way, and the abort is no longer able
        // to hold the map against every other multipart call while it
        // waits on the backend.
        let state = {
            let mut states = self.states.lock().await;
            if let Some(state) = states.get(upload_id)
                && (state.bucket != bucket || state.key != key)
            {
                return Err(FsError::Internal("bucket/key mismatch".into()));
            }
            states.remove(upload_id)
        };
        if let Some(state) = state {
            // Propagate: the engine retries (restored from the persisted
            // record), and GC retains the session until S3 confirms.
            self.multipart
                .abort_multipart(&state.path, &state.id)
                .await
                .map_err(Self::map_err)?;
        }
        Ok(())
    }

    async fn backend_upload_id(&self, upload_id: &str) -> Option<String> {
        let states = self.states.lock().await;
        states.get(upload_id).map(|s| s.id.clone())
    }

    async fn restore_multipart(
        &self,
        record: &crate::fs::store::PersistedMultipart,
    ) -> Result<(), FsError> {
        use object_store::multipart::PartId;

        if record.bucket.is_empty() || record.key.is_empty() {
            return Err(FsError::Internal(
                "multipart record missing bucket/key".into(),
            ));
        }
        let path = self.path(&record.bucket, &record.key);
        let parts = record
            .parts
            .iter()
            .map(|(idx, content_id)| {
                (
                    *idx,
                    PartId {
                        content_id: content_id.clone(),
                    },
                )
            })
            .collect();
        let mut states = self.states.lock().await;
        states.insert(
            record.upload_id.clone(),
            MultipartState {
                bucket: record.bucket.clone(),
                key: record.key.clone(),
                path,
                id: record.s3_upload_id.clone(),
                parts,
            },
        );
        Ok(())
    }

    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: Bytes,
        content_type: Option<String>,
        checksum_sha256: Option<String>,
    ) -> Result<(), FsError> {
        let path = self.path(bucket, key);
        let payload = PutPayload::from_bytes(body);
        let attrs = Self::put_attrs(content_type.as_deref(), checksum_sha256.as_deref());
        if attrs.is_empty() {
            self.store
                .put(&path, payload)
                .await
                .map_err(Self::map_err)?;
        } else {
            self.store
                .put_opts(
                    &path,
                    payload,
                    PutOptions {
                        attributes: attrs,
                        ..Default::default()
                    },
                )
                .await
                .map_err(Self::map_err)?;
        }
        Ok(())
    }

    async fn get_object(&self, bucket: &str, key: &str) -> Result<Bytes, FsError> {
        let path = self.path(bucket, key);
        let res = self.store.get(&path).await.map_err(Self::map_err)?;
        let bytes = res
            .bytes()
            .await
            .map_err(|e| FsError::Internal(e.to_string()))?;
        Ok(bytes)
    }

    async fn get_object_stream(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<crate::fs::s3::ObjectStream, FsError> {
        use futures_util::TryStreamExt as _;

        let path = self.path(bucket, key);
        let res = self.store.get(&path).await.map_err(Self::map_err)?;
        let size = res.meta.size;
        let stream = res.into_stream().map_err(Self::map_err);
        Ok(crate::fs::s3::ObjectStream {
            size,
            stream: Box::pin(stream),
        })
    }

    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<crate::fs::s3::ObjectStream, FsError> {
        use futures_util::TryStreamExt as _;

        let path = self.path(bucket, key);
        let opts = object_store::GetOptions {
            range: Some(object_store::GetRange::Bounded(range)),
            ..Default::default()
        };
        let res = self
            .store
            .get_opts(&path, opts)
            .await
            .map_err(Self::map_err)?;
        let size = res.range.end.saturating_sub(res.range.start);
        let stream = res.into_stream().map_err(Self::map_err);
        Ok(crate::fs::s3::ObjectStream {
            size,
            stream: Box::pin(stream),
        })
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), FsError> {
        let path = self.path(bucket, key);
        match self.store.delete(&path).await {
            Ok(()) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(Self::map_err(e)),
        }
    }

    async fn list_keys(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<crate::fs::s3::ListedKey>, FsError> {
        use futures_util::TryStreamExt as _;

        let root = self.path(bucket, prefix);
        let mut out = Vec::new();
        let mut stream = self.store.list(Some(&root));
        while let Some(meta) = stream.try_next().await.map_err(Self::map_err)? {
            let full = meta.location.to_string();
            // InMemory nests keys under the bucket; strip it back to the
            // relative form the rest of the trait speaks.
            let key = if self.is_memory {
                full.strip_prefix(&format!("{bucket}/"))
                    .unwrap_or(&full)
                    .to_string()
            } else {
                full
            };
            out.push(crate::fs::s3::ListedKey {
                key,
                last_modified: meta.last_modified.timestamp(),
            });
        }
        Ok(out)
    }
}

/// Builds the configured `AmazonS3Builder` from [`S3ClientConfig`].
///
/// Single construction site for the endpoint/region/credential setup:
/// [`db`](crate::db) reuses this for OxKV `OxKvStore`s so the file-byte
/// client and the transactional stores cannot drift apart. Each caller
/// finishes the build itself because the `S3Client` wrapper needs the
/// concrete `AmazonS3` type (`MultipartStore` is not object-safe).
///
/// Supports S3-compatible endpoints (MinIO, R2) via `endpoint_url` and
/// `force_path_style`. For `http` endpoints `allow_http` is enabled.
pub fn s3_builder(config: &S3ClientConfig) -> object_store::aws::AmazonS3Builder {
    use object_store::aws::AmazonS3Builder;

    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(config.bucket.clone())
        .with_region(config.region.clone());

    if let Some(endpoint) = config.endpoint_url.clone() {
        builder = builder.with_endpoint(endpoint.clone());
        if endpoint.starts_with("http://") {
            builder = builder.with_allow_http(true);
        }
    }

    if let (Some(ak), Some(sk)) = (
        config.access_key_id.clone(),
        config.secret_access_key.clone(),
    ) {
        builder = builder.with_access_key_id(ak).with_secret_access_key(sk);
    }

    if config.force_path_style {
        builder = builder.with_virtual_hosted_style_request(false);
    }

    builder
}

/// Builds an [`ObjectStore`] from [`S3ClientConfig`] and wraps it as [`S3Client`].
///
/// Shares the [`s3_builder`] setup; only the `S3Client` adapter
/// wrapping lives here.
pub fn build_object_store(
    config: &S3ClientConfig,
) -> Result<Arc<dyn S3Client>, object_store::Error> {
    let store = s3_builder(config).build()?;
    Ok(Arc::new(ObjectStoreClient::new_combined(Arc::new(store))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    /// [`MultipartStore`] that parks the FIRST `put_part` until released.
    ///
    /// Everything else delegates to a real in-memory backend, so the
    /// upload still genuinely completes; only WHEN one backend call is
    /// outstanding is controlled, which is what turns "the state map is
    /// held across a network call" from an argument into an observation.
    #[derive(Debug)]
    struct GateMultipart {
        inner: Arc<InMemory>,
        parked: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Arc<tokio::sync::Notify>,
    }

    impl std::fmt::Display for GateMultipart {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "GateMultipart")
        }
    }

    #[async_trait]
    impl MultipartStore for GateMultipart {
        async fn create_multipart(&self, path: &ObjectPath) -> object_store::Result<MultipartId> {
            self.inner.create_multipart(path).await
        }
        async fn put_part(
            &self,
            path: &ObjectPath,
            id: &MultipartId,
            part_idx: usize,
            data: PutPayload,
        ) -> object_store::Result<PartId> {
            let gate = self.parked.lock().expect("gate").take();
            if let Some(tx) = gate {
                let _ = tx.send(());
                self.release.notified().await;
            }
            self.inner.put_part(path, id, part_idx, data).await
        }

        async fn complete_multipart(
            &self,
            path: &ObjectPath,
            id: &MultipartId,
            parts: Vec<PartId>,
        ) -> object_store::Result<object_store::PutResult> {
            self.inner.complete_multipart(path, id, parts).await
        }

        async fn abort_multipart(
            &self,
            path: &ObjectPath,
            id: &MultipartId,
        ) -> object_store::Result<()> {
            self.inner.abort_multipart(path, id).await
        }
    }

    /// The gate also has to be an [`ObjectStore`], because
    /// `ObjectStoreClient::new_combined` takes one `Arc` that is both halves
    /// of the client. Everything except `put_part` delegates straight to the
    /// real in-memory backend, so the upload this test parks still genuinely
    /// completes once released.
    #[async_trait]
    impl ObjectStore for GateMultipart {
        async fn put_opts(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            opts: object_store::PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            self.inner.put_opts(location, payload, opts).await
        }

        async fn put_multipart_opts(
            &self,
            location: &ObjectPath,
            opts: object_store::PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            self.inner.put_multipart_opts(location, opts).await
        }

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: object_store::GetOptions,
        ) -> object_store::Result<object_store::GetResult> {
            self.inner.get_opts(location, options).await
        }

        async fn delete(&self, location: &ObjectPath) -> object_store::Result<()> {
            self.inner.delete(location).await
        }

        fn list(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
        {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> object_store::Result<object_store::ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy(&self, from: &ObjectPath, to: &ObjectPath) -> object_store::Result<()> {
            self.inner.copy(from, to).await
        }

        async fn copy_if_not_exists(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
        ) -> object_store::Result<()> {
            self.inner.copy_if_not_exists(from, to).await
        }

        fn list_with_offset(
            &self,
            prefix: Option<&ObjectPath>,
            offset: &ObjectPath,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
        {
            self.inner.list_with_offset(prefix, offset)
        }
    }

    /// One slow backend call must not block the whole process.
    ///
    /// `upload_part` took `states.lock()` and held the guard across
    /// `MultipartStore::put_part` -- it needed the same borrow for the
    /// `state.parts.insert` on the next line -- so the process-global map
    /// was pinned for the full round trip. A single slow PUT, or a hung
    /// connection with no client-side timeout at this layer, stalled every
    /// other concurrent part upload in the process: unrelated users,
    /// unrelated buckets, uploads that share nothing with the slow one.
    ///
    /// Asserted two ways. `states.try_lock()` is the direct structural
    /// claim -- the map is free while a backend call is outstanding -- and
    /// the second upload completing is the same thing as the client would
    /// experience. The first fails on the old code with
    /// "the mutex is held across a backend call".
    #[tokio::test]
    async fn the_multipart_state_map_is_not_held_across_a_backend_call() -> anyhow::Result<()> {
        let inner = Arc::new(InMemory::new());
        let (tx, parked) = tokio::sync::oneshot::channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let client = Arc::new(ObjectStoreClient::new_combined(Arc::new(GateMultipart {
            inner: inner.clone(),
            parked: std::sync::Mutex::new(Some(tx)),
            release: Arc::clone(&release),
        })));

        let up_slow = client
            .create_multipart_upload("b", "files/slow", None)
            .await?;
        let up_other = client
            .create_multipart_upload("b", "files/other", None)
            .await?;

        let slow = tokio::spawn({
            let client = client.clone();
            let upload_id = up_slow.clone();
            async move {
                client
                    .upload_part(
                        "b",
                        "files/slow",
                        &upload_id,
                        1,
                        Bytes::from_static(b"slow"),
                        None,
                    )
                    .await
            }
        });
        parked
            .await
            .expect("the first put_part parked, or the gate never fired");

        assert!(
            client.states.try_lock().is_ok(),
            "the multipart state mutex is held across a backend call"
        );

        // A different upload, sharing nothing with the parked one, runs to
        // completion while it is still in flight.
        let etag = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.upload_part(
                "b",
                "files/other",
                &up_other,
                1,
                Bytes::from_static(b"other"),
                None,
            ),
        )
        .await
        .expect("a second upload was blocked by the first one's backend call")?;
        client
            .complete_multipart_upload("b", "files/other", &up_other, vec![etag])
            .await?;
        assert_eq!(
            client.get_object("b", "files/other").await?,
            Bytes::from_static(b"other")
        );

        release.notify_one();
        // The parked part still lands in the state a complete will read:
        // it was copied out under the lock, not carried by it.
        let slow_etag = slow.await.expect("slow task")?;
        client
            .complete_multipart_upload("b", "files/slow", &up_slow, vec![slow_etag])
            .await?;
        assert_eq!(
            client.get_object("b", "files/slow").await?,
            Bytes::from_static(b"slow")
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_keys_returns_relative_form() -> anyhow::Result<()> {
        let client = ObjectStoreClient::in_memory();
        client
            .put_object("b", "files/a", Bytes::from_static(b"1"), None, None)
            .await?;
        client
            .put_object("b", "files/b", Bytes::from_static(b"2"), None, None)
            .await?;
        client
            .put_object("b", "other/c", Bytes::from_static(b"3"), None, None)
            .await?;
        let mut keys = client.list_keys("b", "files/").await?;
        keys.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key, "files/a");
        assert_eq!(keys[1].key, "files/b");
        assert!(keys.iter().all(|k| k.last_modified > 0));
        Ok(())
    }

    #[tokio::test]
    async fn stream_roundtrip_matches_buffered() -> anyhow::Result<()> {
        use futures_util::TryStreamExt as _;

        let client = ObjectStoreClient::in_memory();
        let body: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
        client
            .put_object("b", "files/big", Bytes::from(body.clone()), None, None)
            .await?;
        let obj = client.get_object_stream("b", "files/big").await?;
        assert_eq!(obj.size, body.len() as u64);
        let chunks: Vec<Bytes> = obj.stream.try_collect().await?;
        let streamed: Vec<u8> = chunks.concat();
        assert_eq!(streamed, body);
        Ok(())
    }

    #[tokio::test]
    async fn put_get_roundtrip() -> anyhow::Result<()> {
        let client = ObjectStoreClient::in_memory();
        client
            .put_object("b", "k1", Bytes::from_static(b"hello"), None, None)
            .await?;
        let got = client.get_object("b", "k1").await?;
        assert_eq!(got, Bytes::from_static(b"hello"));
        Ok(())
    }

    #[tokio::test]
    async fn multipart_complete_assembles_in_order() -> anyhow::Result<()> {
        let client = ObjectStoreClient::in_memory();
        let upload_id = client
            .create_multipart_upload("b", "files/abc", None)
            .await?;
        let e1 = client
            .upload_part(
                "b",
                "files/abc",
                &upload_id,
                1,
                Bytes::from_static(b"hello "),
                None,
            )
            .await?;
        let e2 = client
            .upload_part(
                "b",
                "files/abc",
                &upload_id,
                2,
                Bytes::from_static(b"world"),
                None,
            )
            .await?;
        client
            .complete_multipart_upload("b", "files/abc", &upload_id, vec![e1, e2])
            .await?;
        assert_eq!(
            client.get_object("b", "files/abc").await?,
            Bytes::from_static(b"hello world")
        );
        Ok(())
    }

    #[tokio::test]
    async fn put_overwrites_and_delete_idempotent() -> anyhow::Result<()> {
        let client = ObjectStoreClient::in_memory();
        client
            .put_object("b", "k", Bytes::from_static(b"v1"), None, None)
            .await?;
        client
            .put_object("b", "k", Bytes::from_static(b"v2"), None, None)
            .await?;
        assert_eq!(
            client.get_object("b", "k").await?,
            Bytes::from_static(b"v2")
        );
        client.delete_object("b", "k").await?;
        assert!(matches!(
            client.get_object("b", "k").await.unwrap_err(),
            FsError::NotFound(_)
        ));
        client.delete_object("b", "k").await?;
        Ok(())
    }

    #[tokio::test]
    async fn put_with_content_type_and_checksum_forwarded() -> anyhow::Result<()> {
        let inner = Arc::new(InMemory::new());
        let client = Arc::new(ObjectStoreClient {
            store: inner.clone() as Arc<dyn ObjectStore>,
            multipart: inner.clone() as Arc<dyn MultipartStore>,
            states: Mutex::new(HashMap::new()),
            is_memory: true,
        });
        client
            .put_object(
                "b",
                "k-ct",
                Bytes::from_static(b"data"),
                Some("text/plain".into()),
                Some("abc123".into()),
            )
            .await?;
        // Verify attributes are persisted in the underlying store.
        let path = ObjectPath::from("b/k-ct");
        let res = inner.get(&path).await?;
        assert_eq!(
            res.attributes
                .get(&Attribute::ContentType)
                .map(|v| v.as_ref()),
            Some("text/plain")
        );
        assert_eq!(
            res.attributes
                .get(&Attribute::Metadata(Cow::Borrowed("checksum_sha256")))
                .map(|v| v.as_ref()),
            Some("abc123")
        );
        // Multipart creation on object_store 0.12 does not support attrs via
        // MultipartStore, so we only verify the upload succeeds.
        let up = client
            .create_multipart_upload("b", "k-mp", Some("application/octet-stream".into()))
            .await?;
        let e = client
            .upload_part("b", "k-mp", &up, 1, Bytes::from_static(b"hello"), None)
            .await?;
        client
            .complete_multipart_upload("b", "k-mp", &up, vec![e])
            .await?;
        let _mp_res = inner.get(&ObjectPath::from("b/k-mp")).await?;
        Ok(())
    }
}
