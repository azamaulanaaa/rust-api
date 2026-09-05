//! S3 client abstraction for s3-compatible backends (AWS, MinIO, R2).
//!
//! Production implementation is backed by `object_store::aws::AmazonS3` via
//! [`crate::fs::object_store`]. The trait remains the seam so `FsEngine`
//! stays storage-agnostic and tests can inject `InMemory`.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::fs::error::FsError;

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

    /// Deletes an object.
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), FsError>;
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
pub async fn build_s3_client(config: &S3ClientConfig) -> Arc<dyn S3Client> {
    crate::fs::object_store::build_object_store(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_s3_client_variants_do_not_panic() {
        let base = S3ClientConfig {
            bucket: "test-bucket".into(),
            region: "us-east-1".into(),
            endpoint_url: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
        };
        let _ = build_s3_client(&base).await;

        let with_endpoint = S3ClientConfig {
            endpoint_url: Some("http://localhost:9000".into()),
            force_path_style: true,
            ..base.clone()
        };
        let _ = build_s3_client(&with_endpoint).await;

        let with_creds = S3ClientConfig {
            access_key_id: Some("minioadmin".into()),
            secret_access_key: Some("minioadmin".into()),
            force_path_style: true,
            ..base.clone()
        };
        let _ = build_s3_client(&with_creds).await;

        let with_all = S3ClientConfig {
            endpoint_url: Some("http://localhost:9000".into()),
            force_path_style: true,
            access_key_id: Some("ak".into()),
            secret_access_key: Some("sk".into()),
            ..base
        };
        let client = build_s3_client(&with_all).await;
        assert!(std::sync::Arc::strong_count(&client) >= 1);
    }

    #[tokio::test]
    async fn build_s3_client_force_path_style_without_creds() {
        let cfg = S3ClientConfig {
            bucket: "b".into(),
            region: "us-west-2".into(),
            endpoint_url: None,
            force_path_style: true,
            access_key_id: None,
            secret_access_key: None,
        };
        let _ = build_s3_client(&cfg).await;
    }
}
