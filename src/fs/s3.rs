//! An S3 client for S3-compatible backends such as AWS, MinIO, and R2.
//!
//! The production implementation uses `object_store::aws::AmazonS3` through
//! [`crate::fs::object_store`].
//! The trait keeps `FsEngine` independent of the storage type.
//! A test can inject `InMemory`.

use std::{pin::Pin, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;

use crate::fs::error::FsError;

/// A download body stream. The stream yields object chunks and never holds
/// the whole file in memory at once.
pub type ByteStream = Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, FsError>> + Send>>;

/// A streaming object body with its length.
pub struct ObjectStream {
    /// The number of bytes in [`ObjectStream::stream`].
    /// The value is the range length, or the full size for a whole-object
    /// download.
    /// A route uses the value for `Content-Length`.
    pub size: u64,
    /// The byte chunks in order. A failure in the middle of the stream ends
    /// the download.
    pub stream: ByteStream,
}

/// An abstraction over the S3 operations that [`crate::fs::FsEngine`] uses.
#[async_trait]
pub trait S3Client: Send + Sync {
    /// Starts a multipart upload and returns the upload id.
    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: Option<String>,
    ) -> Result<String, FsError>;

    /// Uploads one part and returns its ETag. The count `part_number`
    /// starts at 1.
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

    /// Returns the upload id that the backend, which is S3, uses for an
    /// engine-side alias.
    /// The method returns a value only when the client tracks that id.
    /// The engine then uses the value to persist resumable state.
    /// A stateless test double returns `None`.
    async fn backend_upload_id(&self, upload_id: &str) -> Option<String> {
        let _ = upload_id;
        None
    }

    /// Loads the multipart state in RAM from a persisted record after a
    /// restart.
    /// A stateless test double does nothing.
    async fn restore_multipart(
        &self,
        record: &crate::fs::store::PersistedMultipart,
    ) -> Result<(), FsError> {
        let _ = record;
        Ok(())
    }

    /// Uploads the object in one part. The engine calls this method when
    /// `total_parts == 1`.
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

    /// Streams an object body with its length.
    ///
    /// A download must not buffer the whole file.
    /// The default implementation collects the body through
    /// [`S3Client::get_object`], so that test doubles keep working.
    /// The production implementation streams from the object store.
    async fn get_object_stream(&self, bucket: &str, key: &str) -> Result<ObjectStream, FsError> {
        let body = self.get_object(bucket, key).await?;
        let size = body.len() as u64;
        let stream = futures_util::stream::once(async move { Ok(body) });
        Ok(ObjectStream {
            size,
            stream: Box::pin(stream),
        })
    }

    /// Streams one absolute byte range (`end` exclusive).
    ///
    /// The caller validates the range against the metadata size first.
    /// An unsatisfiable range returns a 416 without touching S3.
    /// The backend clamps the range again as a safety measure.
    /// The default implementation slices the body through
    /// [`S3Client::get_object`] for test doubles.
    /// The production implementation streams the range from the object
    /// store.
    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<ObjectStream, FsError> {
        let body = self.get_object(bucket, key).await?;
        let object_len = body.len() as u64;
        let start = range.start.min(object_len) as usize;
        let end = range.end.min(object_len).max(start as u64) as usize;
        let slice = body.slice(start..end);
        Ok(ObjectStream {
            size: slice.len() as u64,
            stream: Box::pin(futures_util::stream::once(async move { Ok(slice) })),
        })
    }

    /// Deletes an object.
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), FsError>;

    /// Lists keys under `prefix` with last-modified times.
    ///
    /// The GC orphan-byte pass uses this method.
    /// A key that the metadata no longer references is unreachable.
    /// GC can delete the key after it reaches the age limit.
    async fn list_keys(&self, bucket: &str, prefix: &str) -> Result<Vec<ListedKey>, FsError>;
}

/// A listed object key with its last-modified time (unix seconds).
///
/// A key uses the same relative form as `put/get/delete_object`, for
/// example `"files/{id}"`.
/// A caller can then compare a listed key directly with a record key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedKey {
    /// Object key in relative form.
    pub key: String,
    /// Last-modified time as unix seconds.
    pub last_modified: i64,
}

/// Configuration for the object-store client.
/// It mirrors `config::S3Config`.
/// It is independent of the binary config crate.
#[derive(Debug, Clone)]
pub struct S3ClientConfig {
    /// The bucket name. `AmazonS3` uses it as the bucket.
    /// `InMemory` uses it as a path prefix.
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

/// Builds an `Arc<dyn S3Client>` from [`S3ClientConfig`] through
/// `object_store`.
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
