//! S3 client abstraction for s3-compatible backends (AWS, MinIO, R2).
//!
//! Production implementation is backed by `object_store::aws::AmazonS3` via
//! [`crate::fs::object_store`]. The trait remains the seam so `FsEngine`
//! stays storage-agnostic and tests can inject `InMemory`.

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::fs::error::FsError;

/// Streaming download body: object chunks that never materialize the whole
/// file in memory at once.
pub type ByteStream = Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, FsError>> + Send>>;

/// A streaming object body with its lengths.
pub struct ObjectStream {
    /// Bytes carried by [`ObjectStream::stream`] (range length, or full
    /// size for whole-object downloads), for `Content-Length`.
    pub size: u64,
    /// Total object length in bytes, for `Content-Range`.
    pub total: u64,
    /// Byte chunks in order; a mid-stream failure ends the download.
    pub stream: ByteStream,
}

/// Abstraction over S3 operations used by [`crate::fs::FsEngine`].
#[async_trait]
pub trait S3Client: Send + Sync {
    /// Starts a multipart upload and returns the upload id.
    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: Option<String>,
    ) -> Result<String, FsError>;

    /// Uploads a single part (1-indexed `part_number`) and returns its ETag.
    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
        checksum_sha256: Option<String>,
    ) -> Result<String, FsError>;

    /// Completes a multipart upload given ordered ETags.
    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        etags: Vec<String>,
    ) -> Result<(), FsError>;

    /// Aborts a multipart upload.
    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), FsError>;

    /// Returns the backend (S3-side) upload id for an engine-side alias,
    /// when the client tracks one (used to persist resumable state).
    /// Defaults to `None` for stateless test doubles.
    async fn backend_upload_id(&self, upload_id: &str) -> Option<String> {
        let _ = upload_id;
        None
    }

    /// Rehydrates in-RAM multipart state from a persisted record after a
    /// restart. Defaults to a no-op for stateless test doubles.
    async fn restore_multipart(
        &self,
        record: &crate::fs::store::PersistedMultipart,
    ) -> Result<(), FsError> {
        let _ = record;
        Ok(())
    }

    /// Single-part put (used when `total_parts == 1`).
    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        body: Bytes,
        content_type: Option<String>,
        checksum_sha256: Option<String>,
    ) -> Result<(), FsError>;

    /// Fetches an object body.
    async fn get_object(&self, bucket: &str, key: &str) -> Result<Bytes, FsError>;

    /// Streams an object body with its total length.
    ///
    /// Downloads must not buffer whole files: the default impl collects
    /// through [`S3Client::get_object`] (keeps test doubles working),
    /// production overrides with true streaming from the object store.
    async fn get_object_stream(&self, bucket: &str, key: &str) -> Result<ObjectStream, FsError> {
        let body = self.get_object(bucket, key).await?;
        let size = body.len() as u64;
        let stream = futures_util::stream::once(async move { Ok(body) });
        Ok(ObjectStream {
            size,
            total: size,
            stream: Box::pin(stream),
        })
    }

    /// Streams one absolute byte range (`end` exclusive) with the total
    /// object length.
    ///
    /// Callers validate against metadata size first (unsatisfiable ranges
    /// are a 416 decided without touching S3); backends clamp defensively.
    /// The default impl slices through [`S3Client::get_object`] for test
    /// doubles, production streams the range from the object store.
    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<ObjectStream, FsError> {
        let body = self.get_object(bucket, key).await?;
        let total = body.len() as u64;
        let start = range.start.min(total) as usize;
        let end = range.end.min(total).max(start as u64) as usize;
        let slice = body.slice(start..end);
        Ok(ObjectStream {
            size: slice.len() as u64,
            total,
            stream: Box::pin(futures_util::stream::once(async move { Ok(slice) })),
        })
    }

    /// Deletes an object.
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), FsError>;

    /// Lists keys under `prefix` with last-modified times.
    ///
    /// Backs the GC orphan-byte pass: keys the metadata no longer
    /// references are unreachable and safe to reap once aged.
    async fn list_keys(&self, bucket: &str, prefix: &str) -> Result<Vec<ListedKey>, FsError>;
}

/// A listed object key with its last-modified time (unix seconds).
///
/// Keys use the same relative form as `put/get/delete_object` (e.g.
/// `"files/{id}"`), so listings compare directly against record keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedKey {
    /// Object key in relative form.
    pub key: String,
    /// Last-modified time as unix seconds.
    pub last_modified: i64,
}

/// Configuration for the object-store client, mirroring `config::S3Config`
/// but decoupled from the binary config crate.
#[derive(Debug, Clone)]
pub struct S3ClientConfig {
    /// Bucket name — used as `AmazonS3` bucket, prefixed to the path for `InMemory`.
    pub bucket: String,
    /// AWS region.
    pub region: String,
    /// Custom endpoint for S3-compatible providers.
    pub endpoint_url: Option<String>,
    /// Force path-style addressing (MinIO).
    pub force_path_style: bool,
    /// Static access key (optional).
    pub access_key_id: Option<String>,
    /// Static secret key (optional).
    pub secret_access_key: Option<String>,
}

/// Builds an `Arc<dyn S3Client>` from [`S3ClientConfig`] via `object_store`.
pub async fn build_s3_client(
    config: &S3ClientConfig,
) -> Result<Arc<dyn S3Client>, object_store::Error> {
    crate::fs::object_store::build_object_store(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_s3_client_variants_do_not_panic() -> anyhow::Result<()> {
        let base = S3ClientConfig {
            bucket: "test-bucket".into(),
            region: "us-east-1".into(),
            endpoint_url: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
        };
        let _ = build_s3_client(&base).await?;

        let with_endpoint = S3ClientConfig {
            endpoint_url: Some("http://localhost:9000".into()),
            force_path_style: true,
            ..base.clone()
        };
        let _ = build_s3_client(&with_endpoint).await?;

        let with_creds = S3ClientConfig {
            access_key_id: Some("minioadmin".into()),
            secret_access_key: Some("minioadmin".into()),
            force_path_style: true,
            ..base.clone()
        };
        let _ = build_s3_client(&with_creds).await?;

        let with_all = S3ClientConfig {
            endpoint_url: Some("http://localhost:9000".into()),
            force_path_style: true,
            access_key_id: Some("ak".into()),
            secret_access_key: Some("sk".into()),
            ..base
        };
        let client = build_s3_client(&with_all).await?;
        assert!(std::sync::Arc::strong_count(&client) >= 1);
        Ok(())
    }

    #[tokio::test]
    async fn build_s3_client_force_path_style_without_creds() -> anyhow::Result<()> {
        let cfg = S3ClientConfig {
            bucket: "b".into(),
            region: "us-west-2".into(),
            endpoint_url: None,
            force_path_style: true,
            access_key_id: None,
            secret_access_key: None,
        };
        let _ = build_s3_client(&cfg).await?;
        Ok(())
    }
}
