//! S3-backed file storage with row-level relations.
//!
//! Temp files are owned by `owner_sub` with `refs==0`. Attaching to a row
//! increments refcount; detaching decrements and marks orphan for GC.

pub mod error;
pub mod gc;
pub mod model;
pub mod object_store;
/// File-to-row relation with reference counting.
pub mod relation;
/// Capability token for scoped file access.
pub mod token;
pub mod route;
pub mod s3;
pub mod store;

use std::path::Path;
use std::sync::Arc;

use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, PolicyEngine};

use error::FsError;
use model::{CompleteRequest, FileMetadata, InitRequest};
use s3::S3Client;
use store::{FileRecord, FsStore, UploadSession};

/// Core file-system engine with temp per-user scope and row delegation.
#[derive(Clone)]
pub struct FsEngine {
    pub(crate) store: FsStore,
    pub(crate) s3: Arc<dyn S3Client>,
    pub(crate) bucket: String,
    policy: PolicyEngine,
    token_secret: Arc<Vec<u8>>,
}

impl FsEngine {
    /// Opens the `oxkv` store and builds the S3 client.
    pub async fn init(
        store_path: &Path,
        s3_config: &s3::S3ClientConfig,
        policy: PolicyEngine,
    ) -> Result<Self, FsError> {
        let store = FsStore::open(store_path).await?;
        let s3 = s3::build_s3_client(s3_config).await;
        let secret = Self::gen_secret();
        Ok(Self {
            store,
            s3,
            bucket: s3_config.bucket.clone(),
            policy,
            token_secret: Arc::new(secret),
        })
    }

    /// Creates an engine from an explicit `S3Client` (tests).
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
            token_secret: Arc::new(Self::gen_secret()),
        }
    }

    fn gen_secret() -> Vec<u8> {
        let a = uuid::Uuid::now_v7();
        let b = uuid::Uuid::now_v7();
        let mut v = Vec::with_capacity(32);
        v.extend_from_slice(a.as_bytes());
        v.extend_from_slice(b.as_bytes());
        v
    }

    /// Mint a capability token for `file_id` and `act`.
    pub fn mint_token(&self, sub: &str, file_id: &str, act: Action) -> Result<String, FsError> {
        token::mint(sub, file_id, act, &self.token_secret, None)
    }

    /// Verify a capability token.
    pub fn verify_token(&self, token: &str, file_id: &str, act: Action) -> Result<(), FsError> {
        token::verify(token, file_id, act, &self.token_secret)?;
        Ok(())
    }

    /// Attach a file to a row; caller must have `Write` on the row.
    pub async fn attach(
        &self,
        row_type: &str,
        row_id: &str,
        file_id: &str,
        caller_sub: &str,
    ) -> Result<u32, FsError> {
        self.policy
            .require_row(caller_sub, row_type, row_id, Action::Write)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;
        // ensure file exists
        if self.store.get_file(file_id).await?.is_none() {
            return Err(FsError::NotFound("file not found".into()));
        }
        self.store.attach(row_type, row_id, file_id).await
    }

    /// Detach a file from a row; caller must have `Write` on the row.
    pub async fn detach(
        &self,
        row_type: &str,
        row_id: &str,
        file_id: &str,
        caller_sub: &str,
    ) -> Result<u32, FsError> {
        self.policy
            .require_row(caller_sub, row_type, row_id, Action::Write)
            .await
            .map_err(|e| match e {
                crate::policy::PolicyError::AccessDenied => FsError::Forbidden,
                other => FsError::Internal(other.to_string()),
            })?;
        self.store.detach(row_type, row_id, file_id).await
    }

    async fn can_access(&self, caller_sub: &str, file_id: &str, act: Action) -> Result<bool, FsError> {
        let Some(rec) = self.store.get_file(file_id).await? else {
            return Err(FsError::NotFound("file not found".into()));
        };
        if rec.owner_sub == caller_sub {
            return Ok(true);
        }
        let rows = self.store.rows_for_file(file_id).await?;
        if rows.is_empty() {
            return Ok(false);
        }
        for (ty, rid) in rows {
            if self
                .policy
                .authorize_row(caller_sub, &ty, &rid, act)
                .await
                .unwrap_or(false)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Validates `req` and creates a new upload session owned by `owner_sub`.
    #[tracing::instrument(skip(self, req), fields(file_size = req.file_size, part_size = req.part_size, total_parts = req.file_total_parts, owner_sub = %owner_sub), err)]
    pub async fn init_upload(&self, req: InitRequest, owner_sub: &str) -> Result<String, FsError> {
        req.validate()?;
        let file_id = uuid::Uuid::now_v7().to_string();
        let s3_key = format!("files/{file_id}");
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

    /// Stores a single chunk; only the session owner may write.
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
        if session.owner_sub != caller_sub {
            return Err(FsError::Forbidden);
        }
        if part_index >= session.file_total_parts {
            return Err(FsError::BadRequest("part index out of bounds".into()));
        }
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

    /// Finalizes an upload session; only the owner may complete.
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
        if session.owner_sub != caller_sub {
            return Err(FsError::Forbidden);
        }
        if session.etags.iter().any(|e| e.is_none()) {
            return Err(FsError::BadRequest("not all parts uploaded".into()));
        }
        if session.file_total_parts == 1 {
            if session.etags[0].is_none() {
                return Err(FsError::BadRequest(
                    "missing part for single-part upload".into(),
                ));
            }
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
        Ok(())
    }

    /// Aborts a multipart upload; only the owner may cancel.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn cancel_upload(&self, file_id: &str, caller_sub: &str) -> Result<(), FsError> {
        let session = self
            .store
            .get_session(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("upload session not found".into()))?;
        if session.owner_sub != caller_sub {
            return Err(FsError::Forbidden);
        }
        if let Some(upload_id) = session.s3_upload_id {
            let _ = self
                .s3
                .abort_multipart_upload(&self.bucket, &session.s3_key, &upload_id)
                .await;
        }
        self.store.delete_session(file_id).await?;
        Ok(())
    }

    /// Returns file metadata if caller owns temp file or has row access.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn get_metadata(
        &self,
        file_id: &str,
        caller_sub: &str,
    ) -> Result<FileMetadata, FsError> {
        if !self.can_access(caller_sub, file_id, Action::Read).await? {
            return Err(FsError::Forbidden);
        }
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

    /// Deletes a finalized file; allowed when caller has row `Delete` or owns temp unreferenced file.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn delete_file(&self, file_id: &str, caller_sub: &str) -> Result<(), FsError> {
        let rec = self
            .store
            .get_file(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("file not found".into()))?;
        // temp unreferenced file owned by caller can be deleted directly
        let info = self.store.get_ref_info(file_id).await?;
        if info.count == 0 {
            if rec.owner_sub != caller_sub {
                return Err(FsError::Forbidden);
            }
        } else if !self.can_access(caller_sub, file_id, Action::Delete).await? {
            return Err(FsError::Forbidden);
        }
        self.s3.delete_object(&self.bucket, &rec.s3_key).await?;
        self.store.delete_file(file_id).await?;
        // clean refs key if orphan
        Ok(())
    }

    /// Streams a file body if caller has row `Read` or owns temp.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn get_object(
        &self,
        file_id: &str,
        caller_sub: &str,
    ) -> Result<(FileRecord, bytes::Bytes), FsError> {
        if !self.can_access(caller_sub, file_id, Action::Read).await? {
            return Err(FsError::Forbidden);
        }
        let rec = self
            .store
            .get_file(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("file not found".into()))?;
        let body = self.s3.get_object(&self.bucket, &rec.s3_key).await?;
        Ok((rec, body))
    }

    /// Returns upload progress; only owner may poll.
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
        if session.owner_sub != caller_sub {
            return Err(FsError::Forbidden);
        }
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

    async fn make_engine(sub: &str, _grant: bool) -> (FsEngine, std::path::PathBuf) {
        let path = tmp_path(sub);
        let _ = std::fs::remove_file(&path);
        let store = FsStore::open(&path).await.unwrap();
        let policy_path = tmp_path(&format!("{sub}-policy"));
        let _ = std::fs::remove_file(&policy_path);
        let policy = PolicyEngine::init(&policy_path).await.unwrap();
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
    #[allow(dead_code)]
    fn valid_multi() -> InitRequest {
        InitRequest {
            file_size: 524288,
            part_size: 262144,
            file_total_parts: 2,
        }
    }

    #[tokio::test]
    async fn init_upload_validates() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", false).await;
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
    async fn temp_upload_owned_by_caller() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", false).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        // bob cannot write alice's session
        let err = engine
            .upload_part(&id, 0, Bytes::from(vec![1u8; 1024]), None, "bob")
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::Forbidden));
        Ok(())
    }

    #[tokio::test]
    async fn attach_requires_row_write() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", false).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, Bytes::from(vec![1u8; 1024]), None, "alice")
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
        // no row permission -> forbidden
        assert!(engine
            .attach("invoice", "123", &id, "alice")
            .await
            .is_err());
        // grant alice write on invoice:123
        engine
            .policy
            .add_rule("alice".into(), "invoice:123".into(), Action::Write)
            .await
            .unwrap();
        assert_eq!(engine.attach("invoice", "123", &id, "alice").await?, 1);
        // idempotent
        assert_eq!(engine.attach("invoice", "123", &id, "alice").await?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn row_access_grants_file_read() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", false).await;
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
        // bob cannot read temp file owned by alice
        assert!(engine.get_metadata(&id, "bob").await.is_err());
        // grant bob read via row
        engine
            .policy
            .add_rule("alice".into(), "invoice:123".into(), Action::Write)
            .await
            .unwrap();
        engine.attach("invoice", "123", &id, "alice").await?;
        engine
            .policy
            .add_rule("bob".into(), "invoice:123".into(), Action::Read)
            .await
            .unwrap();
        let meta = engine.get_metadata(&id, "bob").await?;
        assert_eq!(meta.name, "doc.txt");
        Ok(())
    }

    #[tokio::test]
    async fn token_mint_verify() -> anyhow::Result<()> {
        let (engine, _p) = make_engine("alice", false).await;
        let tok = engine.mint_token("alice", "file1", Action::Read)?;
        engine.verify_token(&tok, "file1", Action::Read)?;
        assert!(engine.verify_token(&tok, "file1", Action::Write).is_err());
        Ok(())
    }
}
