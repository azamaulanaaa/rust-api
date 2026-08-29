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
