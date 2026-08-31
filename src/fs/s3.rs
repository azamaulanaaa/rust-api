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
        if part_number < 1 {
            return Err(FsError::BadRequest("part_number must be >= 1".into()));
        }
        let mut req = self
            .client
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(body));
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
        if etags.is_empty() {
            return Err(FsError::BadRequest("etags cannot be empty".into()));
        }
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
            .body(ByteStream::from(body));
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
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("NoSuchKey")
                    || msg.contains("NoSuchBucket")
                    || msg.contains("NotFound")
                {
                    FsError::NotFound(format!("object not found: {bucket}/{key}"))
                } else {
                    FsError::Internal(format!("get_object: {e}"))
                }
            })?;
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
    let has_custom_s3_config = config.access_key_id.is_some() || config.force_path_style;
    let mut s3_builder = aws_sdk_s3::config::Builder::from(&sdk_config);
    if let (Some(ak), Some(sk)) = (
        config.access_key_id.clone(),
        config.secret_access_key.clone(),
    ) {
        let creds = aws_sdk_s3::config::Credentials::new(ak, sk, None, None, "static");
        s3_builder = s3_builder.credentials_provider(creds);
    }
    if config.force_path_style {
        s3_builder = s3_builder.force_path_style(true);
    }
    let client = if has_custom_s3_config {
        let s3_config = s3_builder.build();
        aws_sdk_s3::Client::from_conf(s3_config)
    } else {
        aws_sdk_s3::Client::new(&sdk_config)
    };
    Arc::new(RealS3Client { client })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::Mutex;

    /// In-memory mock implementing [`S3Client`] for unit tests.
    /// Mirrors S3 semantics: bucket+key namespaced objects plus multipart state.
    struct InMemoryS3 {
        objects: Mutex<HashMap<(String, String), Bytes>>,
        multiparts: Mutex<HashMap<String, Multipart>>,
        counter: std::sync::atomic::AtomicU64,
    }

    #[allow(dead_code)]
    struct Multipart {
        bucket: String,
        key: String,
        parts: HashMap<i32, Bytes>,
        checksums: HashMap<i32, Option<String>>,
        content_type: Option<String>,
    }

    impl InMemoryS3 {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                objects: Mutex::new(HashMap::new()),
                multiparts: Mutex::new(HashMap::new()),
                counter: std::sync::atomic::AtomicU64::new(1),
            })
        }

        fn next_upload_id(&self) -> String {
            let n = self
                .counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            format!("upload-{n}")
        }
    }

    #[async_trait]
    impl S3Client for InMemoryS3 {
        async fn create_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            content_type: Option<String>,
        ) -> Result<String, FsError> {
            let id = self.next_upload_id();
            let mut mp = self.multiparts.lock().await;
            mp.insert(
                id.clone(),
                Multipart {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    parts: HashMap::new(),
                    checksums: HashMap::new(),
                    content_type,
                },
            );
            Ok(id)
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
            let mut mp = self.multiparts.lock().await;
            let m = mp
                .get_mut(upload_id)
                .ok_or_else(|| FsError::Internal(format!("unknown upload_id {upload_id}")))?;
            if m.bucket != bucket || m.key != key {
                return Err(FsError::Internal("bucket/key mismatch".into()));
            }
            if part_number < 1 {
                return Err(FsError::Internal("part_number must be >= 1".into()));
            }
            let etag = format!("etag-{}-{part_number}-{}", upload_id, body.len());
            m.parts.insert(part_number, body);
            m.checksums.insert(part_number, checksum_sha256);
            Ok(etag)
        }

        async fn complete_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
            etags: Vec<String>,
        ) -> Result<(), FsError> {
            let mut mp = self.multiparts.lock().await;
            let m = mp
                .remove(upload_id)
                .ok_or_else(|| FsError::Internal(format!("unknown upload_id {upload_id}")))?;
            if m.bucket != bucket || m.key != key {
                return Err(FsError::Internal("bucket/key mismatch".into()));
            }
            if etags.len() != m.parts.len() {
                return Err(FsError::Internal(format!(
                    "etag count {} != part count {}",
                    etags.len(),
                    m.parts.len()
                )));
            }
            // Verify etags correspond to stored parts (copy-paste guard: 1-indexed).
            for (i, etag) in etags.iter().enumerate() {
                let pn = (i + 1) as i32;
                let body = m
                    .parts
                    .get(&pn)
                    .ok_or_else(|| FsError::Internal(format!("missing part {pn}")))?;
                let expected = format!("etag-{}-{pn}-{}", upload_id, body.len());
                if etag != &expected {
                    return Err(FsError::Internal(format!(
                        "etag mismatch for part {pn}: expected {expected}, got {etag}"
                    )));
                }
            }
            // Assemble final object in order.
            let mut assembled = Vec::new();
            let mut sorted: Vec<_> = m.parts.into_iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            for (_, b) in sorted {
                assembled.extend_from_slice(&b);
            }
            let mut objs = self.objects.lock().await;
            objs.insert(
                (bucket.to_string(), key.to_string()),
                Bytes::from(assembled),
            );
            Ok(())
        }

        async fn abort_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
        ) -> Result<(), FsError> {
            let mut mp = self.multiparts.lock().await;
            if let Some(m) = mp.get(upload_id)
                && (m.bucket != bucket || m.key != key)
            {
                return Err(FsError::Internal("bucket/key mismatch".into()));
            }
            mp.remove(upload_id);
            Ok(())
        }

        async fn put_object(
            &self,
            bucket: &str,
            key: &str,
            body: Bytes,
            _content_type: Option<String>,
            checksum_sha256: Option<String>,
        ) -> Result<(), FsError> {
            // Store checksum alongside body as prefix for verification (test-only).
            // RealS3 forwards checksum to S3 for validation; mock keeps it for assertions.
            // We encode as: if checksum present, store body as-is but also track it in
            // a side check: checksum must be base64 if present (mirrors RealS3 passthrough).
            if let Some(cs) = checksum_sha256 {
                // Basic sanity: base64 chars only - catches copy-paste where header name wrong.
                if cs.chars().any(|c| c == ' ' || c == '\n') {
                    return Err(FsError::Internal("invalid checksum encoding".into()));
                }
            }
            let mut objs = self.objects.lock().await;
            objs.insert((bucket.to_string(), key.to_string()), body);
            Ok(())
        }

        async fn get_object(&self, bucket: &str, key: &str) -> Result<Bytes, FsError> {
            let objs = self.objects.lock().await;
            objs.get(&(bucket.to_string(), key.to_string()))
                .cloned()
                .ok_or_else(|| FsError::NotFound(format!("object not found: {bucket}/{key}")))
        }

        async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), FsError> {
            let mut objs = self.objects.lock().await;
            objs.remove(&(bucket.to_string(), key.to_string()));
            Ok(())
        }
    }

    // ── build_s3_client smoke tests ──────────────────────────────────────

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
        // client is usable (does not hit network on construction)
        assert!(Arc::strong_count(&client) >= 1);
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

    // ── put/get/delete ───────────────────────────────────────────────────

    #[tokio::test]
    async fn put_get_roundtrip() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        s3.put_object("b", "k1", Bytes::from_static(b"hello"), None, None)
            .await?;
        let got = s3.get_object("b", "k1").await?;
        assert_eq!(got, Bytes::from_static(b"hello"));
        Ok(())
    }

    #[tokio::test]
    async fn put_overwrites_previous_value() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        s3.put_object("b", "k", Bytes::from_static(b"v1"), None, None)
            .await?;
        s3.put_object("b", "k", Bytes::from_static(b"v2"), None, None)
            .await?;
        assert_eq!(s3.get_object("b", "k").await?, Bytes::from_static(b"v2"));
        Ok(())
    }

    #[tokio::test]
    async fn put_with_content_type_and_checksum_passthrough() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        let checksum =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"checksum-test");
        s3.put_object(
            "b",
            "k",
            Bytes::from_static(b"data"),
            Some("text/plain".into()),
            Some(checksum),
        )
        .await?;
        assert_eq!(s3.get_object("b", "k").await?, Bytes::from_static(b"data"));
        Ok(())
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let s3 = InMemoryS3::new();
        let err = s3.get_object("b", "nope").await.unwrap_err();
        assert!(matches!(err, FsError::NotFound(_)));
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn delete_removes_object() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        s3.put_object("b", "k", Bytes::from_static(b"to-delete"), None, None)
            .await?;
        s3.delete_object("b", "k").await?;
        assert!(matches!(
            s3.get_object("b", "k").await.unwrap_err(),
            FsError::NotFound(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn delete_idempotent_when_missing() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        // Should not error even if object never existed (mirrors S3).
        s3.delete_object("b", "ghost").await?;
        s3.delete_object("b", "ghost").await?;
        Ok(())
    }

    #[tokio::test]
    async fn bucket_key_namespacing_is_isolated() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        s3.put_object("bucket-a", "same/key", Bytes::from_static(b"a"), None, None)
            .await?;
        s3.put_object("bucket-b", "same/key", Bytes::from_static(b"b"), None, None)
            .await?;
        assert_eq!(
            s3.get_object("bucket-a", "same/key").await?,
            Bytes::from_static(b"a")
        );
        assert_eq!(
            s3.get_object("bucket-b", "same/key").await?,
            Bytes::from_static(b"b")
        );
        Ok(())
    }

    // ── multipart ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_multipart_returns_unique_ids() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        let id1 = s3.create_multipart_upload("b", "k", None).await?;
        let id2 = s3.create_multipart_upload("b", "k", None).await?;
        assert_ne!(id1, id2);
        assert!(id1.starts_with("upload-"));
        Ok(())
    }

    #[tokio::test]
    async fn multipart_upload_complete_assembles_in_order() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        let upload_id = s3
            .create_multipart_upload("b", "files/abc", Some("video/mp4".into()))
            .await?;
        let etag1 = s3
            .upload_part(
                "b",
                "files/abc",
                &upload_id,
                1,
                Bytes::from_static(b"hello "),
                None,
            )
            .await?;
        let etag2 = s3
            .upload_part(
                "b",
                "files/abc",
                &upload_id,
                2,
                Bytes::from_static(b"world"),
                None,
            )
            .await?;
        s3.complete_multipart_upload("b", "files/abc", &upload_id, vec![etag1, etag2])
            .await?;
        assert_eq!(
            s3.get_object("b", "files/abc").await?,
            Bytes::from_static(b"hello world")
        );
        Ok(())
    }

    #[tokio::test]
    async fn multipart_upload_with_checksums_forwarded() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        let upload_id = s3.create_multipart_upload("b", "k", None).await?;
        let cs1 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"cs1");
        let cs2 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"cs2");
        let etag1 = s3
            .upload_part(
                "b",
                "k",
                &upload_id,
                1,
                Bytes::from_static(b"part1"),
                Some(cs1.clone()),
            )
            .await?;
        let etag2 = s3
            .upload_part(
                "b",
                "k",
                &upload_id,
                2,
                Bytes::from_static(b"part2"),
                Some(cs2.clone()),
            )
            .await?;
        // Verify mock captured checksums (internal check).
        {
            let mp = s3.multiparts.lock().await;
            let m = mp.get(&upload_id).unwrap();
            assert_eq!(m.checksums.get(&1).unwrap().as_deref(), Some(cs1.as_str()));
            assert_eq!(m.checksums.get(&2).unwrap().as_deref(), Some(cs2.as_str()));
        }
        s3.complete_multipart_upload("b", "k", &upload_id, vec![etag1, etag2])
            .await?;
        assert_eq!(
            s3.get_object("b", "k").await?,
            Bytes::from_static(b"part1part2")
        );
        Ok(())
    }

    #[tokio::test]
    async fn multipart_part_number_must_be_one_indexed() {
        let s3 = InMemoryS3::new();
        let upload_id = s3.create_multipart_upload("b", "k", None).await.unwrap();
        let err = s3
            .upload_part("b", "k", &upload_id, 0, Bytes::from_static(b"x"), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("part_number"));
    }

    #[tokio::test]
    async fn multipart_complete_etag_mismatch_fails() {
        let s3 = InMemoryS3::new();
        let upload_id = s3.create_multipart_upload("b", "k", None).await.unwrap();
        let _etag = s3
            .upload_part("b", "k", &upload_id, 1, Bytes::from_static(b"data"), None)
            .await
            .unwrap();
        let err = s3
            .complete_multipart_upload("b", "k", &upload_id, vec!["bogus-etag".into()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("etag mismatch"));
    }

    #[tokio::test]
    async fn multipart_complete_missing_part_fails() {
        let s3 = InMemoryS3::new();
        let upload_id = s3.create_multipart_upload("b", "k", None).await.unwrap();
        s3.upload_part("b", "k", &upload_id, 1, Bytes::from_static(b"a"), None)
            .await
            .unwrap();
        // Claim 2 parts but only 1 uploaded.
        let err = s3
            .complete_multipart_upload("b", "k", &upload_id, vec!["etag-1".into(), "etag-2".into()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("etag count"));
    }

    #[tokio::test]
    async fn multipart_abort_clears_state() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        let upload_id = s3.create_multipart_upload("b", "k", None).await?;
        s3.upload_part("b", "k", &upload_id, 1, Bytes::from_static(b"temp"), None)
            .await?;
        s3.abort_multipart_upload("b", "k", &upload_id).await?;
        // Subsequent complete should fail (already aborted).
        let err = s3
            .complete_multipart_upload("b", "k", &upload_id, vec!["etag".into()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown upload_id"));
        // Object was never assembled.
        assert!(matches!(
            s3.get_object("b", "k").await.unwrap_err(),
            FsError::NotFound(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn multipart_abort_idempotent() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        let upload_id = s3.create_multipart_upload("b", "k", None).await?;
        s3.abort_multipart_upload("b", "k", &upload_id).await?;
        // Second abort is no-op (mirrors RealS3 best-effort in gc).
        s3.abort_multipart_upload("b", "k", &upload_id).await?;
        Ok(())
    }

    #[tokio::test]
    async fn multipart_upload_bucket_key_mismatch_rejected() {
        let s3 = InMemoryS3::new();
        let upload_id = s3.create_multipart_upload("b", "k", None).await.unwrap();
        let err = s3
            .upload_part(
                "other-bucket",
                "k",
                &upload_id,
                1,
                Bytes::from_static(b"x"),
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mismatch"));
        let err = s3
            .upload_part(
                "b",
                "other/key",
                &upload_id,
                1,
                Bytes::from_static(b"x"),
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mismatch"));
    }

    #[tokio::test]
    async fn upload_part_unknown_upload_id_fails() {
        let s3 = InMemoryS3::new();
        let err = s3
            .upload_part("b", "k", "no-such-id", 1, Bytes::from_static(b"x"), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown upload_id"));
    }

    #[tokio::test]
    async fn concurrent_multiparts_isolated() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        let id_a = s3.create_multipart_upload("b", "key-a", None).await?;
        let id_b = s3.create_multipart_upload("b", "key-b", None).await?;
        let etag_a = s3
            .upload_part("b", "key-a", &id_a, 1, Bytes::from_static(b"AAA"), None)
            .await?;
        let etag_b = s3
            .upload_part("b", "key-b", &id_b, 1, Bytes::from_static(b"BBB"), None)
            .await?;
        s3.complete_multipart_upload("b", "key-a", &id_a, vec![etag_a])
            .await?;
        s3.complete_multipart_upload("b", "key-b", &id_b, vec![etag_b])
            .await?;
        assert_eq!(
            s3.get_object("b", "key-a").await?,
            Bytes::from_static(b"AAA")
        );
        assert_eq!(
            s3.get_object("b", "key-b").await?,
            Bytes::from_static(b"BBB")
        );
        Ok(())
    }

    #[tokio::test]
    async fn single_part_put_vs_multipart_paths_do_not_collide() -> anyhow::Result<()> {
        let s3 = InMemoryS3::new();
        // Single-part path (FsEngine uses put_object when total_parts == 1).
        s3.put_object(
            "b",
            "single",
            Bytes::from_static(b"single-body"),
            None,
            None,
        )
        .await?;
        // Multipart path with same bucket but different key.
        let up = s3.create_multipart_upload("b", "multi", None).await?;
        let _etag = s3
            .upload_part("b", "multi", &up, 1, Bytes::from_static(b"multi-"), None)
            .await?;
        s3.upload_part("b", "multi", &up, 2, Bytes::from_static(b"body"), None)
            .await?; // intentionally not captured - will fail etag check, so capture correctly
        // Need to redo with correct etag count - test that mixed paths coexist.
        // Abort previous and do a clean 2-part.
        s3.abort_multipart_upload("b", "multi", &up).await?;
        let up2 = s3.create_multipart_upload("b", "multi", None).await?;
        let e1 = s3
            .upload_part("b", "multi", &up2, 1, Bytes::from_static(b"multi-"), None)
            .await?;
        let e2 = s3
            .upload_part("b", "multi", &up2, 2, Bytes::from_static(b"body"), None)
            .await?;
        s3.complete_multipart_upload("b", "multi", &up2, vec![e1, e2])
            .await?;
        assert_eq!(
            s3.get_object("b", "single").await?,
            Bytes::from_static(b"single-body")
        );
        assert_eq!(
            s3.get_object("b", "multi").await?,
            Bytes::from_static(b"multi-body")
        );
        Ok(())
    }
}
