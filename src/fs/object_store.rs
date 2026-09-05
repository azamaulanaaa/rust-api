//! Object-store backend for [`crate::fs::s3::S3Client`].
//!
//! Provides an [`object_store::ObjectStore`] implementation of the S3 abstraction
//! so all file bytes live in a generic object store. Production uses
//! `AmazonS3` (S3, MinIO, R2 via `endpoint_url`) while tests use
//! `InMemory` — no external service required.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use object_store::ObjectStore;
use object_store::ObjectStoreExt;
use object_store::memory::InMemory;
use object_store::multipart::{MultipartStore, PartId};
use object_store::path::Path as ObjectPath;
use object_store::{MultipartId, PutPayload};
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
    /// Creates a client wrapping an arbitrary [`ObjectStore`] that also
    /// implements [`MultipartStore`].
    pub fn new(store: Arc<dyn ObjectStore>, multipart: Arc<dyn MultipartStore>) -> Self {
        Self {
            store,
            multipart,
            states: Mutex::new(HashMap::new()),
            is_memory: false,
        }
    }

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
        let mut states = self.states.lock().await;
        let state = states
            .get_mut(upload_id)
            .ok_or_else(|| FsError::Internal(format!("unknown upload_id {upload_id}")))?;
        if state.bucket != bucket || state.key != key {
            return Err(FsError::Internal("bucket/key mismatch".into()));
        }
        let payload = PutPayload::from_bytes(body);
        let part_id = self
            .multipart
            .put_part(&state.path, &state.id, part_idx, payload)
            .await
            .map_err(Self::map_err)?;
        let etag = part_id.content_id.clone();
        state.parts.insert(part_idx, part_id);
        Ok(etag)
    }

    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        etags: Vec<String>,
    ) -> Result<(), FsError> {
        let mut states = self.states.lock().await;
        let state = states
            .remove(upload_id)
            .ok_or_else(|| FsError::Internal(format!("unknown upload_id {upload_id}")))?;
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
        let mut states = self.states.lock().await;
        if let Some(state) = states.get(upload_id) {
            if state.bucket != bucket || state.key != key {
                return Err(FsError::Internal("bucket/key mismatch".into()));
            }
            let state = states.remove(upload_id).unwrap();
            let _ = self
                .multipart
                .abort_multipart(&state.path, &state.id)
                .await;
        }
        Ok(())
    }

    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: Bytes,
        _content_type: Option<String>,
        _checksum_sha256: Option<String>,
    ) -> Result<(), FsError> {
        let path = self.path(bucket, key);
        let payload = PutPayload::from_bytes(body);
        self.store
            .put(&path, payload)
            .await
            .map_err(Self::map_err)?;
        Ok(())
    }

    async fn get_object(&self, bucket: &str, key: &str) -> Result<Bytes, FsError> {
        let path = self.path(bucket, key);
        let res = self.store.get(&path).await.map_err(Self::map_err)?;
        let bytes = res.bytes().await.map_err(|e| FsError::Internal(e.to_string()))?;
        Ok(bytes)
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), FsError> {
        let path = self.path(bucket, key);
        match self.store.delete(&path).await {
            Ok(()) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(Self::map_err(e)),
        }
    }
}

/// Builds an [`ObjectStore`] from [`S3ClientConfig`] and wraps it as [`S3Client`].
///
/// Supports S3-compatible endpoints (MinIO, R2) via `endpoint_url` and
/// `force_path_style`. For `http` endpoints `allow_http` is enabled.
pub fn build_object_store(config: &S3ClientConfig) -> Arc<dyn S3Client> {
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

    if let (Some(ak), Some(sk)) = (config.access_key_id.clone(), config.secret_access_key.clone())
    {
        builder = builder
            .with_access_key_id(ak)
            .with_secret_access_key(sk);
    }

    if config.force_path_style {
        builder = builder.with_virtual_hosted_style_request(false);
    }

    let store = match builder.build() {
        Ok(s) => s,
        Err(e) => panic!("failed to build object_store AmazonS3: {e}"),
    };
    let inner = Arc::new(store);
    Arc::new(ObjectStoreClient::new_combined(inner))
}

/// Builds an [`S3Client`] using the object-store stack.
///
/// This is the object-store replacement for [`crate::fs::s3::build_s3_client`].
pub async fn build_s3_client(config: &S3ClientConfig) -> Arc<dyn S3Client> {
    build_object_store(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

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
            .upload_part("b", "files/abc", &upload_id, 1, Bytes::from_static(b"hello "), None)
            .await?;
        let e2 = client
            .upload_part("b", "files/abc", &upload_id, 2, Bytes::from_static(b"world"), None)
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
        assert_eq!(client.get_object("b", "k").await?, Bytes::from_static(b"v2"));
        client.delete_object("b", "k").await?;
        assert!(matches!(
            client.get_object("b", "k").await.unwrap_err(),
            FsError::NotFound(_)
        ));
        client.delete_object("b", "k").await?;
        Ok(())
    }
}
