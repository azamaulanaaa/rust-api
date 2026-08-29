//! S3 client abstraction for s3-compatible backends (AWS, MinIO, R2).

use std::sync::Arc;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;

use crate::fs::error::FsError;

/// Abstraction over S3 operations used by [`crate::fs::FsEngine`].
/// Implemented by the real AWS SDK client and by an in-memory mock for tests.
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
    /// `checksum_sha256` is base64-encoded SHA256, forwarded to S3 for validation.
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
    /// `checksum_sha256` is base64-encoded SHA256, forwarded to S3.
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

/// Real S3 implementation backed by `aws-sdk-s3`.
pub struct RealS3Client {
    client: aws_sdk_s3::Client,
}

#[async_trait]
impl S3Client for RealS3Client {
    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: Option<String>,
    ) -> Result<String, FsError> {
        let mut req = self
            .client
            .create_multipart_upload()
            .bucket(bucket)
            .key(key);
        if let Some(ct) = content_type {
            req = req.content_type(ct);
        }
        let out = req
            .send()
            .await
            .map_err(|e| FsError::Internal(format!("create_multipart_upload: {e}")))?;
        out.upload_id()
            .map(|s| s.to_string())
            .ok_or_else(|| FsError::Internal("missing upload_id".into()))
    }

    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
        checksum_sha256: Option<String>,
    ) -> Result<String, FsError> {
        let mut req = self
            .client
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(body.to_vec()));
        if let Some(cs) = checksum_sha256 {
            req = req.checksum_sha256(cs);
        }
        let out = req
            .send()
            .await
            .map_err(|e| FsError::Internal(format!("upload_part {part_number}: {e}")))?;
        out.e_tag()
            .map(|s| s.to_string())
            .ok_or_else(|| FsError::Internal("missing ETag".into()))
    }

    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        etags: Vec<String>,
    ) -> Result<(), FsError> {
        let parts = etags
            .into_iter()
            .enumerate()
            .map(|(i, etag)| {
                aws_sdk_s3::types::CompletedPart::builder()
                    .e_tag(etag)
                    .part_number((i + 1) as i32)
                    .build()
            })
            .collect::<Vec<_>>();
        let completed = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|e| FsError::Internal(format!("complete_multipart_upload: {e}")))?;
        Ok(())
    }

    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), FsError> {
        self.client
            .abort_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|e| FsError::Internal(format!("abort_multipart_upload: {e}")))?;
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
        let mut req = self
            .client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(body.to_vec()));
        if let Some(ct) = content_type {
            req = req.content_type(ct);
        }
        if let Some(cs) = checksum_sha256 {
            req = req.checksum_sha256(cs);
        }
        req.send()
            .await
            .map_err(|e| FsError::Internal(format!("put_object: {e}")))?;
        Ok(())
    }

    async fn get_object(&self, bucket: &str, key: &str) -> Result<Bytes, FsError> {
        let out = self
            .client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| FsError::Internal(format!("get_object: {e}")))?;
        let data = out
            .body
            .collect()
            .await
            .map_err(|e| FsError::Internal(format!("collect get_object body: {e}")))?;
        Ok(data.into_bytes())
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), FsError> {
        self.client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| FsError::Internal(format!("delete_object: {e}")))?;
        Ok(())
    }
}

/// Configuration for the S3 client, mirroring `config::S3Config` but
/// defined in the library crate so `fs` does not depend on the binary config.
#[derive(Debug, Clone)]
pub struct S3ClientConfig {
    /// S3 bucket name (unused for client construction but kept for symmetry).
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

/// Builds an `Arc<dyn S3Client>` from [`S3ClientConfig`], honoring
/// `endpoint_url` and `force_path_style` for S3-compatible providers.
pub async fn build_s3_client(config: &S3ClientConfig) -> Arc<dyn S3Client> {
    let mut loader = aws_config::defaults(BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()));
    if let Some(endpoint) = config.endpoint_url.clone() {
        loader = loader.endpoint_url(endpoint);
    }
    let sdk_config = loader.load().await;
    // inject static credentials when provided (otherwise use env/instance chain)
    if let (Some(ak), Some(sk)) = (
        config.access_key_id.clone(),
        config.secret_access_key.clone(),
    ) {
        let creds = aws_sdk_s3::config::Credentials::new(ak, sk, None, None, "static");
        let mut s3_conf =
            aws_sdk_s3::config::Builder::from(&sdk_config).credentials_provider(creds);
        if config.force_path_style {
            s3_conf = s3_conf.force_path_style(true);
        }
        let s3_config = s3_conf.build();
        let client = aws_sdk_s3::Client::from_conf(s3_config);
        return Arc::new(RealS3Client { client });
    }
    // path-style without static creds
    if config.force_path_style {
        let s3_conf = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(true)
            .build();
        let client = aws_sdk_s3::Client::from_conf(s3_conf);
        return Arc::new(RealS3Client { client });
    }
    let client = aws_sdk_s3::Client::new(&sdk_config);
    Arc::new(RealS3Client { client })
}
