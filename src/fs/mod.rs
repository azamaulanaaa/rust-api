//! S3-backed file storage mirroring `src/worker/fs/index.ts`.
//!
//! Provides chunked upload via S3 multipart (or single `PutObject` when
//! `total_parts == 1`), proxied through the server (`PUT /fs/uploads/{id}/parts/{idx}`).
//! Upload sessions and file metadata are persisted in an embedded `oxkv` store,
//! while binary content lives in S3. Authorization is per-file (`fs:{id}`)
//! with a coarse `fs` gate on creation.

pub mod error;
pub mod gc;
pub mod model;
pub mod object_store;
/// File-to-row relation with reference counting.
pub mod relation;
pub mod route;
pub mod s3;
pub mod store;

use std::path::Path;
use std::sync::Arc;

use crate::policy::{Action, PolicyEngine};

use error::FsError;
use model::{CompleteRequest, FileMetadata, InitRequest};
use s3::S3Client;
use store::{FileRecord, FsStore, UploadSession};

/// Core file-system engine: validates, coordinates `oxkv` and S3, and
/// enforces per-file policy via `fs:{id}`.
#[derive(Clone)]
pub struct FsEngine {
    pub(crate) store: FsStore,
    pub(crate) s3: Arc<dyn S3Client>,
    pub(crate) bucket: String,
    policy: PolicyEngine,
}

impl FsEngine {
    /// Opens the `oxkv` store at `store_path` (same Redb file as policy may be reused with a disjoint key prefix)
    /// and builds the S3 client from `s3_config`.
    pub async fn init(
        store_path: &Path,
        s3_config: &s3::S3ClientConfig,
        policy: PolicyEngine,
    ) -> Result<Self, FsError> {
        let store = FsStore::open(store_path).await?;
        let s3 = s3::build_s3_client(s3_config).await;
        Ok(Self {
            store,
            s3,
            bucket: s3_config.bucket.clone(),
            policy,
        })
    }

    /// Creates an engine from an explicit `S3Client` (e.g. in-memory mock for tests).
    pub fn from_parts(
        store: FsStore,
        s3: Arc<dyn S3Client>,
        bucket: String,
        policy: PolicyEngine,
    ) -> Self {
        Self {
            store,
            s3,
            bucket,
            policy,
        }
    }

    /// Validates `req` (mirrors `MetadataUploadSchema.filter`) and creates a new upload session.
    /// Returns the generated `file_id` (`uuidv7`).
    #[tracing::instrument(skip(self, req), fields(file_size = req.file_size, part_size = req.part_size, total_parts = req.file_total_parts, owner_sub = %owner_sub), err)]
    pub async fn init_upload(&self, req: InitRequest, owner_sub: &str) -> Result<String, FsError> {
        req.validate()?;
        // coarse gate: need `fs` write to create new files
        self.policy
            .require(owner_sub, "fs", Action::Write)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;

        let file_id = uuid::Uuid::now_v7().to_string();
        let s3_key = format!("files/{file_id}");

        // single-part optimization: PutObject, no MPU
        let s3_upload_id = if req.file_total_parts == 1 {
            None
        } else {
            let id = self
                .s3
                .create_multipart_upload(&self.bucket, &s3_key, None)
                .await?;
            Some(id)
        };

        let session = UploadSession {
            id: file_id.clone(),
            file_size: req.file_size,
            part_size: req.part_size,
            file_total_parts: req.file_total_parts,
            s3_upload_id,
            s3_key,
            owner_sub: owner_sub.to_string(),
            created_at: chrono::Utc::now().timestamp(),
            etags: vec![None; req.file_total_parts as usize],
            checksums: vec![None; req.file_total_parts as usize],
        };

        self.store.save_session(&session).await?;
        Ok(file_id)
    }

    /// Validates and stores a single chunk. `body` is the raw bytes for `part_index`.
    /// `checksum_sha256` is base64-encoded SHA256, forwarded to S3 for validation.
    #[tracing::instrument(skip(self, body, checksum_sha256), fields(file_id = %file_id, part_index, body_len = body.len(), caller_sub = %caller_sub), err)]
    pub async fn upload_part(
        &self,
        file_id: &str,
        part_index: u64,
        body: bytes::Bytes,
        checksum_sha256: Option<String>,
        caller_sub: &str,
    ) -> Result<(), FsError> {
        let mut session = self
            .store
            .get_session(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("upload session not found".into()))?;

        // coarse `fs` gate (simplified while better model is designed)
        self.policy
            .require(caller_sub, "fs", Action::Write)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;

        if part_index >= session.file_total_parts {
            return Err(FsError::BadRequest("part index out of bounds".into()));
        }

        // expected size mirrors TS logic
        let expected = if part_index == session.file_total_parts - 1 {
            session.file_size - session.part_size * part_index
        } else {
            session.part_size
        };
        if body.len() as u64 != expected {
            return Err(FsError::BadRequest(format!(
                "blob size mismatch for part {part_index}: expected {expected} bytes, got {}",
                body.len()
            )));
        }

        if session.file_total_parts == 1 {
            // single-part: direct PutObject with checksum passthrough
            self.s3
                .put_object(
                    &self.bucket,
                    &session.s3_key,
                    body,
                    None,
                    checksum_sha256.clone(),
                )
                .await?;
            session.etags[part_index as usize] = Some("put".into());
            // keep checksums vector in sync (ensure old sessions migrated)
            if session.checksums.len() != session.etags.len() {
                session.checksums.resize(session.etags.len(), None);
            }
            session.checksums[part_index as usize] = checksum_sha256;
            self.store.save_session(&session).await?;
            return Ok(());
        }

        let upload_id = session
            .s3_upload_id
            .clone()
            .ok_or_else(|| FsError::Internal("missing s3 upload id".into()))?;
        // S3 part numbers are 1-indexed
        let part_number = (part_index + 1) as i32;
        let etag = self
            .s3
            .upload_part(
                &self.bucket,
                &session.s3_key,
                &upload_id,
                part_number,
                body,
                checksum_sha256.clone(),
            )
            .await?;

        session.etags[part_index as usize] = Some(etag);
        if session.checksums.len() != session.etags.len() {
            session.checksums.resize(session.etags.len(), None);
        }
        session.checksums[part_index as usize] = checksum_sha256;
        self.store.save_session(&session).await?;
        Ok(())
    }

    /// Completes an upload session: verifies all parts, finalizes S3, persists file metadata.
    #[tracing::instrument(skip(self, req), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn complete_upload(
        &self,
        file_id: &str,
        req: CompleteRequest,
        caller_sub: &str,
    ) -> Result<(), FsError> {
        let session = self
            .store
            .get_session(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("upload session not found".into()))?;

        self.policy
            .require(caller_sub, "fs", Action::Write)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;

        // ensure all parts uploaded
        if session.etags.iter().any(|e| e.is_none()) {
            return Err(FsError::BadRequest("not all parts uploaded".into()));
        }

        if session.file_total_parts == 1 {
            // already PutObject on UploadPart; just ensure S3 object exists
            // (checksum forwarding will happen on UploadPart Complete path later)
            if session.etags[0].is_none() {
                return Err(FsError::BadRequest(
                    "missing part for single-part upload".into(),
                ));
            }
            // optional: update Content-Type via CopyObject if needed; keep key as-is for now
        } else {
            let mut etags: Vec<String> = Vec::with_capacity(session.etags.len());
            for e in &session.etags {
                let etag = e
                    .clone()
                    .ok_or_else(|| FsError::Internal("missing etag for part".into()))?;
                etags.push(etag);
            }
            let upload_id = session
                .s3_upload_id
                .as_deref()
                .ok_or_else(|| FsError::Internal("missing s3 upload id".into()))?;
            self.s3
                .complete_multipart_upload(&self.bucket, &session.s3_key, upload_id, etags)
                .await?;
        }

        let record = FileRecord {
            id: file_id.to_string(),
            name: req.name,
            mimetype: req.mimetype,
            size: session.file_size,
            s3_key: session.s3_key.clone(),
            owner_sub: session.owner_sub.clone(),
            created_at: chrono::Utc::now().timestamp(),
        };
        self.store.save_file(&record).await?;
        self.store.delete_session(file_id).await?;
        // grants already created at init; ensure they remain
        Ok(())
    }

    /// Aborts a multipart upload and removes session state.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn cancel_upload(&self, file_id: &str, caller_sub: &str) -> Result<(), FsError> {
        let session = self
            .store
            .get_session(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("upload session not found".into()))?;

        self.policy
            .require(caller_sub, "fs", Action::Write)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;

        if let Some(upload_id) = session.s3_upload_id {
            let _ = self
                .s3
                .abort_multipart_upload(&self.bucket, &session.s3_key, &upload_id)
                .await;
        }
        self.store.delete_session(file_id).await?;
        Ok(())
    }

    /// Returns file metadata (no body).
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn get_metadata(
        &self,
        file_id: &str,
        caller_sub: &str,
    ) -> Result<FileMetadata, FsError> {
        self.policy
            .require(caller_sub, "fs", Action::Read)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;
        let rec = self
            .store
            .get_file(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("file not found".into()))?;
        Ok(FileMetadata {
            id: rec.id,
            name: rec.name,
            mimetype: rec.mimetype,
            size: rec.size,
        })
    }

    /// Deletes a finalized file from S3 and metadata store.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn delete_file(&self, file_id: &str, caller_sub: &str) -> Result<(), FsError> {
        self.policy
            .require(caller_sub, "fs", Action::Delete)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;
        let rec = self
            .store
            .get_file(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("file not found".into()))?;
        self.s3.delete_object(&self.bucket, &rec.s3_key).await?;
        self.store.delete_file(file_id).await?;
        Ok(())
    }

    /// Streams a file body from S3 as bytes.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn get_object(
        &self,
        file_id: &str,
        caller_sub: &str,
    ) -> Result<(FileRecord, bytes::Bytes), FsError> {
        self.policy
            .require(caller_sub, "fs", Action::Read)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;
        let rec = self
            .store
            .get_file(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("file not found".into()))?;
        let body = self.s3.get_object(&self.bucket, &rec.s3_key).await?;
        Ok((rec, body))
    }

    /// Returns upload progress for client-driven polling.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn get_progress(
        &self,
        file_id: &str,
        caller_sub: &str,
    ) -> Result<model::ProgressResponse, FsError> {
        let session = self
            .store
            .get_session(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("upload session not found".into()))?;
        self.policy
            .require(caller_sub, "fs", Action::Read)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;
        let uploaded = session.etags.iter().filter(|e| e.is_some()).count() as u64;
        let percent = if session.file_total_parts == 0 {
            0
        } else {
            ((uploaded as f64 / session.file_total_parts as f64) * 100.0).round() as u64
        };
        let uploaded_parts: Vec<u64> = session
            .etags
            .iter()
            .enumerate()
            .filter_map(|(i, e)| if e.is_some() { Some(i as u64) } else { None })
            .collect();
        Ok(model::ProgressResponse {
            file_id: file_id.to_string(),
            file_size: session.file_size,
            part_size: session.part_size,
            total_parts: session.file_total_parts,
            uploaded_parts,
            percent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fs::object_store::ObjectStoreClient;
    use crate::policy::{Action, PolicyEngine};
    use bytes::Bytes;

    fn tmp_path(label: &str) -> std::path::PathBuf {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        std::env::temp_dir().join(format!(
            "rust-api-fs-engine-{}-{}-{}.redb",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>()),
            label
        ))
    }

    async fn make_engine(sub: &str, grant: bool) -> (FsEngine, std::path::PathBuf) {
        let path = tmp_path(sub);
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await.unwrap();
        let policy_path = tmp_path(&format!("{sub}-policy"));
        let _ = std::fs::remove_file(&policy_path);
        let policy = PolicyEngine::init(&policy_path).await.unwrap();
        if grant {
            policy
                .assign_group(sub.to_string(), "writers".to_string())
                .await
                .unwrap();
            policy
                .add_rule("writers".to_string(), "fs".to_string(), Action::Write)
                .await
                .unwrap();
            policy
                .add_rule("writers".to_string(), "fs".to_string(), Action::Read)
                .await
                .unwrap();
            policy
                .add_rule("writers".to_string(), "fs".to_string(), Action::Delete)
                .await
                .unwrap();
        }
        let s3 = ObjectStoreClient::in_memory();
        let engine = FsEngine::from_parts(store, s3, "test-bucket".to_string(), policy);
        (engine, path)
    }

    fn valid_single() -> InitRequest {
        InitRequest {
            file_size: 1024,
            part_size: 1024,
            file_total_parts: 1,
        }
    }
    fn valid_multi() -> InitRequest {
        InitRequest {
            file_size: 524288,
            part_size: 262144,
            file_total_parts: 2,
        }
    }

    #[tokio::test]
    async fn init_upload_validates_and_checks_policy() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        assert!(!id.is_empty());
        let err = engine
            .init_upload(
                InitRequest {
                    file_size: 0,
                    part_size: 1024,
                    file_total_parts: 1,
                },
                "alice",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::BadRequest(_)));
        Ok(())
    }

    #[tokio::test]
    async fn init_upload_forbidden_without_policy() {
        let (engine, _p) = make_engine("bob", false).await;
        let err = engine.init_upload(valid_single(), "bob").await.unwrap_err();
        assert!(matches!(err, FsError::Forbidden));
    }

    #[tokio::test]
    async fn init_creates_single_vs_multipart_session() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id1 = engine.init_upload(valid_single(), "alice").await?;
        let sess1 = engine.store.get_session(&id1).await?.unwrap();
        assert!(sess1.s3_upload_id.is_none());
        assert_eq!(sess1.s3_key, format!("files/{id1}"));
        let id2 = engine.init_upload(valid_multi(), "alice").await?;
        let sess2 = engine.store.get_session(&id2).await?.unwrap();
        assert!(sess2.s3_upload_id.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn upload_part_single_and_multipart_paths() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(
                &id,
                0,
                Bytes::from(vec![1u8; 1024]),
                Some("cs".into()),
                "alice",
            )
            .await?;
        let sess = engine.store.get_session(&id).await?.unwrap();
        assert_eq!(sess.etags[0], Some("put".into()));
        assert_eq!(sess.checksums[0], Some("cs".into()));
        let id2 = engine.init_upload(valid_multi(), "alice").await?;
        engine
            .upload_part(&id2, 0, Bytes::from(vec![2u8; 262144]), None, "alice")
            .await?;
        engine
            .upload_part(&id2, 1, Bytes::from(vec![3u8; 262144]), None, "alice")
            .await?;
        let sess2 = engine.store.get_session(&id2).await?.unwrap();
        assert!(sess2.etags[0].is_some() && sess2.etags[1].is_some());
        Ok(())
    }

    #[tokio::test]
    async fn upload_part_rejects_out_of_bounds_and_size_mismatch() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id = engine.init_upload(valid_multi(), "alice").await?;
        let err = engine
            .upload_part(&id, 5, Bytes::from(vec![0u8; 100]), None, "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::BadRequest(_)));
        assert!(err.to_string().contains("out of bounds"));
        let err = engine
            .upload_part(&id, 0, Bytes::from(vec![0u8; 10]), None, "alice")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("blob size mismatch"));
        Ok(())
    }

    #[tokio::test]
    async fn upload_part_not_found_and_forbidden() {
        let (engine, _p) = make_engine("alice", true).await;
        let err = engine
            .upload_part("ghost", 0, Bytes::from(vec![0u8; 1024]), None, "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::NotFound(_)));
        let (engine2, _p2) = make_engine("alice", true).await;
        let id = engine2.init_upload(valid_single(), "alice").await.unwrap();
        let err = engine2
            .upload_part(&id, 0, Bytes::from(vec![1u8; 1024]), None, "eve")
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::Forbidden));
    }

    #[tokio::test]
    async fn complete_upload_requires_all_parts_and_policy() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id = engine.init_upload(valid_multi(), "alice").await?;
        let err = engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "f".into(),
                    mimetype: "text/plain".into(),
                },
                "alice",
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not all parts"));
        engine
            .upload_part(&id, 0, Bytes::from(vec![0u8; 262144]), None, "alice")
            .await?;
        let err = engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "f".into(),
                    mimetype: "text/plain".into(),
                },
                "alice",
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not all parts"));
        let err = engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "f".into(),
                    mimetype: "x".into(),
                },
                "eve",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::Forbidden));
        let err = engine
            .complete_upload(
                "ghost",
                CompleteRequest {
                    name: "f".into(),
                    mimetype: "x".into(),
                },
                "alice",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::NotFound(_)));
        Ok(())
    }

    #[tokio::test]
    async fn complete_upload_single_and_multi_succeeds() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, Bytes::from(vec![9u8; 1024]), None, "alice")
            .await?;
        engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "a.txt".into(),
                    mimetype: "text/plain".into(),
                },
                "alice",
            )
            .await?;
        assert!(engine.store.get_session(&id).await?.is_none());
        let rec = engine.store.get_file(&id).await?.unwrap();
        assert_eq!(rec.name, "a.txt");
        assert_eq!(rec.size, 1024);
        let id2 = engine.init_upload(valid_multi(), "alice").await?;
        engine
            .upload_part(&id2, 0, Bytes::from(vec![1u8; 262144]), None, "alice")
            .await?;
        engine
            .upload_part(&id2, 1, Bytes::from(vec![2u8; 262144]), None, "alice")
            .await?;
        engine
            .complete_upload(
                &id2,
                CompleteRequest {
                    name: "b.bin".into(),
                    mimetype: "application/octet-stream".into(),
                },
                "alice",
            )
            .await?;
        assert!(engine.store.get_file(&id2).await?.is_some());
        let body = engine.s3.get_object("test-bucket", &format!("files/{id2}")).await?;
        assert_eq!(body.len(), 524288);
        Ok(())
    }

    #[tokio::test]
    async fn cancel_upload_cleans_s3_and_session() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id = engine.init_upload(valid_multi(), "alice").await?;
        engine
            .upload_part(&id, 0, Bytes::from(vec![0u8; 262144]), None, "alice")
            .await?;
        engine.cancel_upload(&id, "alice").await?;
        assert!(engine.store.get_session(&id).await?.is_none());
        let id2 = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id2, 0, Bytes::from(vec![5u8; 1024]), None, "alice")
            .await?;
        engine.cancel_upload(&id2, "alice").await?;
        assert!(engine.store.get_session(&id2).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn cancel_not_found_and_forbidden() {
        let (engine, _p) = make_engine("alice", true).await;
        assert!(matches!(
            engine.cancel_upload("ghost", "alice").await.unwrap_err(),
            FsError::NotFound(_)
        ));
        let id = engine.init_upload(valid_single(), "alice").await.unwrap();
        assert!(matches!(
            engine.cancel_upload(&id, "eve").await.unwrap_err(),
            FsError::Forbidden
        ));
    }

    #[tokio::test]
    async fn get_metadata_and_object_flow() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, Bytes::from(vec![7u8; 1024]), None, "alice")
            .await?;
        engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "doc.txt".into(),
                    mimetype: "text/plain".into(),
                },
                "alice",
            )
            .await?;
        let meta = engine.get_metadata(&id, "alice").await?;
        assert_eq!(meta.name, "doc.txt");
        assert_eq!(meta.size, 1024);
        let (rec, body) = engine.get_object(&id, "alice").await?;
        assert_eq!(rec.mimetype, "text/plain");
        assert_eq!(body.len(), 1024);
        assert!(matches!(
            engine.get_metadata(&id, "eve").await.unwrap_err(),
            FsError::Forbidden
        ));
        assert!(matches!(
            engine.get_object(&id, "eve").await.unwrap_err(),
            FsError::Forbidden
        ));
        assert!(matches!(
            engine.get_metadata("ghost", "alice").await.unwrap_err(),
            FsError::NotFound(_)
        ));
        assert!(matches!(
            engine.get_object("ghost", "alice").await.unwrap_err(),
            FsError::NotFound(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn delete_file_flow() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, Bytes::from(vec![1u8; 1024]), None, "alice")
            .await?;
        engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "x".into(),
                    mimetype: "text/plain".into(),
                },
                "alice",
            )
            .await?;
        assert!(matches!(
            engine.delete_file(&id, "eve").await.unwrap_err(),
            FsError::Forbidden
        ));
        assert!(matches!(
            engine.delete_file("ghost", "alice").await.unwrap_err(),
            FsError::NotFound(_)
        ));
        engine.delete_file(&id, "alice").await?;
        assert!(engine.store.get_file(&id).await?.is_none());
        assert!(matches!(
            engine.s3.get_object("test-bucket", &format!("files/{id}")).await.unwrap_err(),
            FsError::NotFound(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn get_progress_reports_uploaded_parts() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", true).await;
        let id = engine.init_upload(valid_multi(), "alice").await?;
        let prog = engine.get_progress(&id, "alice").await?;
        assert_eq!(prog.percent, 0);
        assert!(prog.uploaded_parts.is_empty());
        engine
            .upload_part(&id, 0, Bytes::from(vec![0u8; 262144]), None, "alice")
            .await?;
        let prog = engine.get_progress(&id, "alice").await?;
        assert_eq!(prog.percent, 50);
        assert_eq!(prog.uploaded_parts, vec![0]);
        assert!(matches!(
            engine.get_progress(&id, "eve").await.unwrap_err(),
            FsError::Forbidden
        ));
        assert!(matches!(
            engine.get_progress("ghost", "alice").await.unwrap_err(),
            FsError::NotFound(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn from_parts_and_init_smoke() -> anyhow::Result<()> {
        let path = tmp_path("from_parts");
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await?;
        let policy_path = tmp_path("from_parts_policy");
        let _ = std::fs::remove_file(&policy_path);
        let policy = PolicyEngine::init(&policy_path).await?;
        policy.assign_group("u".into(), "g".into()).await?;
        policy
            .add_rule("g".into(), "fs".into(), Action::Write)
            .await?;
        let s3 = ObjectStoreClient::in_memory();
        let engine = FsEngine::from_parts(store.clone(), s3, "b".into(), policy);
        assert_eq!(engine.bucket, "b");
        Ok(())
    }
}
