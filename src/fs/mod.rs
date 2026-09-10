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
pub mod route;
pub mod s3;
pub mod store;
/// Capability token for scoped file access.
pub mod token;

use std::sync::Arc;

use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, PolicyEngine};

use error::FsError;
use model::{CompleteRequest, FileMetadata, InitRequest};
use s3::S3Client;
use store::{FileRecord, FsStore, UploadSession};

use crate::sync::wal::{Wal, WalOp};

/// Core file-system engine with temp per-user scope and row delegation.
#[derive(Clone)]
pub struct FsEngine {
    pub(crate) store: FsStore,
    pub(crate) s3: Arc<dyn S3Client>,
    pub(crate) bucket: String,
    policy: PolicyEngine,
    token_keys: Arc<TokenKeys>,
    /// WAL for replica sync; `None` disables logging (tests).
    /// Production must wire it: without appends the WAL head never
    /// advances and replicas freeze at their last snapshot.
    wal: Option<Wal>,
}

/// One capability-token signing key: `kid` goes in the JWT header.
#[derive(Clone)]
struct TokenKey {
    kid: String,
    secret: Vec<u8>,
}

/// Capability-token signing keys: current mints, previous verifies only.
///
/// Token IDs stay UUIDv7 (oxkv sorts by creation time); only the HMAC
/// material needs real entropy, so IDs and secrets evolve independently.
#[derive(Clone)]
pub struct TokenKeys {
    current: TokenKey,
    previous: Option<TokenKey>,
}

impl TokenKeys {
    /// Ephemeral 256-bit key from the OS RNG: for tests and unconfigured
    /// runs. Tokens die with the process — production must configure a
    /// stable secret (see `CapabilityConfig`).
    pub fn ephemeral() -> Self {
        use rand::RngCore as _;

        let mut secret = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self {
            current: TokenKey {
                kid: token::kid_for(&secret),
                secret,
            },
            previous: None,
        }
    }

    /// Configured keys from hex: current mints, previous (if any)
    /// verifies during rotation. Rejects weak/truncated material.
    pub fn from_hex(current: &str, previous: Option<&str>) -> Result<Self, FsError> {
        let current_bytes = token::parse_secret_hex(current).map_err(FsError::BadRequest)?;
        let current = TokenKey {
            kid: token::kid_for(&current_bytes),
            secret: current_bytes,
        };
        let previous = previous
            .map(|s| {
                token::parse_secret_hex(s)
                    .map(|secret| TokenKey {
                        kid: token::kid_for(&secret),
                        secret,
                    })
                    .map_err(FsError::BadRequest)
            })
            .transpose()?;
        Ok(Self { current, previous })
    }
}

impl FsEngine {
    /// Creates the engine from an `OxKvStore` (per-user S3, scalable).
    pub async fn init(
        s3_store: oxkv::OxKvStore,
        s3_config: &s3::S3ClientConfig,
        policy: PolicyEngine,
    ) -> Result<Self, FsError> {
        let store = FsStore::new(s3_store);
        let s3 = s3::build_s3_client(s3_config)
            .await
            .map_err(|e| FsError::Internal(format!("failed to build S3 client: {e}")))?;
        Ok(Self {
            store,
            s3,
            bucket: s3_config.bucket.clone(),
            policy,
            token_keys: Arc::new(TokenKeys::ephemeral()),
            wal: None,
        })
    }

    /// Attaches a [`Wal`] for replica sync; ops are logged after each
    /// mutation (fail-closed: a logging failure fails the whole operation
    /// so the WAL never silently misses a committed write).
    pub fn with_wal(mut self, wal: Wal) -> Self {
        self.wal = Some(wal);
        self
    }

    /// Appends `op` when logging is wired; no-op otherwise.
    async fn append_wal(&self, op: WalOp) -> Result<(), FsError> {
        if let Some(wal) = &self.wal {
            wal.append(op).await?;
        }
        Ok(())
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
            token_keys: Arc::new(TokenKeys::ephemeral()),
            wal: None,
        }
    }

    /// Overrides the capability-token signing keys (production wires
    /// the configured secret; tests keep the ephemeral default).
    pub fn with_token_keys(mut self, keys: TokenKeys) -> Self {
        self.token_keys = Arc::new(keys);
        self
    }

    /// Mint a capability token for `file_id` and `act`.
    pub fn mint_token(&self, sub: &str, file_id: &str, act: Action) -> Result<String, FsError> {
        let keys = &self.token_keys;
        token::mint(
            sub,
            file_id,
            act,
            &keys.current.kid,
            &keys.current.secret,
            None,
        )
    }

    /// Verify a capability token.
    pub fn verify_token(&self, token: &str, file_id: &str, act: Action) -> Result<(), FsError> {
        let keys = &self.token_keys;
        let mut secrets = vec![keys.current.secret.as_slice()];
        if let Some(prev) = &keys.previous {
            secrets.push(prev.secret.as_slice());
        }
        token::verify(token, file_id, act, &secrets)?;
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
        let count = self.store.attach(row_type, row_id, file_id).await?;
        self
            .append_wal(WalOp::Attach {
                row_type: row_type.to_string(),
                row_id: row_id.to_string(),
                file_id: file_id.to_string(),
            })
            .await?;
        Ok(count)
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
        let count = self.store.detach(row_type, row_id, file_id).await?;
        self
            .append_wal(WalOp::Detach {
                row_type: row_type.to_string(),
                row_id: row_id.to_string(),
                file_id: file_id.to_string(),
            })
            .await?;
        Ok(count)
    }

    async fn can_access(
        &self,
        caller_sub: &str,
        file_id: &str,
        act: Action,
    ) -> Result<bool, FsError> {
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
    ///
    /// The body arrives as a chunk stream capped at the session's
    /// expected part size: oversize bodies are cut mid-stream (413)
    /// instead of buffered to completion, and a declared
    /// `Content-Length` that already mismatches is rejected before a
    /// single chunk is read. The part itself is still buffered once —
    /// S3 SigV4 must hash the full part before sending, so zero-buffer
    /// uploads are protocol-blocked; the bound is now the part size
    /// (≤10 MiB by init validation), not the 16 MiB blanket cap.
    #[tracing::instrument(skip(self, body, checksum_sha256), fields(file_id = %file_id, part_index, declared_len = declared_len, caller_sub = %caller_sub), err)]
    pub async fn upload_part<S>(
        &self,
        file_id: &str,
        part_index: u64,
        body: S,
        declared_len: Option<u64>,
        checksum_sha256: Option<String>,
        caller_sub: &str,
    ) -> Result<(), FsError>
    where
        // No `Send` bound: actix `Payload` is `!Send` (thread-local h1
        // body) and handlers run on the worker arbiter, so the intake
        // future stays thread-local like the `Bytes` extractor was.
        S: futures_util::Stream<Item = Result<bytes::Bytes, FsError>>,
    {
        use futures_util::StreamExt as _;

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
        match declared_len {
            Some(n) if n > expected => return Err(FsError::PayloadTooLarge),
            Some(n) if n != expected => {
                return Err(FsError::BadRequest(format!(
                    "declared part size {n} does not match expected {expected} bytes"
                )));
            }
            _ => {}
        }
        // Absolute ceiling mirrors the HTTP payload cap: the old `Bytes`
        // extractor rejected anything past it, and part sizes above it
        // were never uploadable.
        let ceiling =
            expected.min(crate::http::MAX_PAYLOAD_BYTES as u64) + 1;
        let mut buf = Vec::with_capacity(expected.min(crate::http::MAX_PAYLOAD_BYTES as u64) as usize);
        let mut total = 0u64;
        let mut stream = std::pin::pin!(body);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            total += chunk.len() as u64;
            if total >= ceiling {
                return Err(FsError::PayloadTooLarge);
            }
            buf.extend_from_slice(&chunk);
        }
        if total != expected {
            return Err(FsError::BadRequest(format!(
                "blob size mismatch for part {part_index}: expected {expected} bytes, got {total}"
            )));
        }
        let body = bytes::Bytes::from(buf);
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
        self
            .append_wal(WalOp::FileCreate { rec: record })
            .await?;
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
    ///
    /// Metadata goes first, then S3 bytes: a crash between the two leaks
    /// an unreachable object (converges on retry, S3 delete is idempotent)
    /// instead of a dangling record that serves errors.
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
        self.store.delete_file(file_id).await?;
        self.s3.delete_object(&self.bucket, &rec.s3_key).await?;
        self
            .append_wal(WalOp::FileDelete {
                file_id: file_id.to_string(),
            })
            .await?;
        // clean refs key if orphan
        Ok(())
    }

    /// Streams a file body if caller has row `Read` or owns temp.
    ///
    /// Chunks flow straight from the object store to the response: the
    /// full body is never buffered, so arbitrarily large files download
    /// in constant memory.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn get_object(
        &self,
        file_id: &str,
        caller_sub: &str,
    ) -> Result<(FileRecord, crate::fs::s3::ObjectStream), FsError> {
        if !self.can_access(caller_sub, file_id, Action::Read).await? {
            return Err(FsError::Forbidden);
        }
        let rec = self
            .store
            .get_file(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("file not found".into()))?;
        let body = self
            .s3
            .get_object_stream(&self.bucket, &rec.s3_key)
            .await?;
        Ok((rec, body))
    }

    /// Streams one absolute byte range (`end` exclusive) of a file the
    /// caller may read.
    ///
    /// Auth and metadata size come from the same checks as
    /// [`FsEngine::get_object`]; sizes are immutable after completion,
    /// so the range is clamped defensively and routes decide 416
    /// against metadata they already hold.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub, start = range.start, end = range.end), err)]
    pub async fn get_object_range(
        &self,
        file_id: &str,
        caller_sub: &str,
        range: std::ops::Range<u64>,
    ) -> Result<(FileRecord, crate::fs::s3::ObjectStream), FsError> {
        if !self.can_access(caller_sub, file_id, Action::Read).await? {
            return Err(FsError::Forbidden);
        }
        let rec = self
            .store
            .get_file(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("file not found".into()))?;
        let start = range.start.min(rec.size);
        let end = range.end.min(rec.size).max(start);
        let body = self
            .s3
            .get_object_range(&self.bucket, &rec.s3_key, start..end)
            .await?;
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use crate::fs::object_store::ObjectStoreClient;
    use crate::policy::{Action, PolicyEngine};
    use bytes::Bytes;

    async fn make_engine(sub: &str, _grant: bool) -> FsEngine {
        use crate::db::build_test_store;
        let prefix = format!("test-fs-engine-{}-{sub}", {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
        });
        let s3_store = build_test_store(&prefix).await;
        let store = FsStore::new(s3_store);
        let policy_prefix = format!("{prefix}-policy");
        let policy_store = build_test_store(&policy_prefix).await;
        let policy = PolicyEngine::init_s3(policy_store).await.unwrap();
        let s3 = ObjectStoreClient::in_memory();
        FsEngine::from_parts(store, s3, "test-bucket".to_string(), policy)
    }

    fn valid_single() -> InitRequest {
        InitRequest {
            file_size: 1024,
            part_size: 1024,
            file_total_parts: 1,
        }
    }

    /// Wraps one buffered part as the chunk stream the engine now takes.
    fn once_body(body: Vec<u8>) -> impl futures_util::Stream<Item = Result<Bytes, FsError>> {
        futures_util::stream::once(async move { Ok(Bytes::from(body)) })
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
        let engine = make_engine("alice", false).await;
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
        let engine = make_engine("alice", false).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        // bob cannot write alice's session
        let err = engine
            .upload_part(&id, 0, once_body(vec![1u8; 1024]), None, None, "bob")
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::Forbidden));
        Ok(())
    }

    #[tokio::test]
    async fn attach_requires_row_write() -> anyhow::Result<()> {
        let engine = make_engine("alice", false).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, once_body(vec![1u8; 1024]), None, None, "alice")
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
        assert!(engine.attach("invoice", "123", &id, "alice").await.is_err());
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
        let engine = make_engine("alice", false).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, once_body(vec![7u8; 1024]), None, None, "alice")
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
    async fn upload_part_cuts_oversize_streams_early() -> anyhow::Result<()> {
        use actix_web::ResponseError as _;

        let engine = make_engine("alice", false).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        // Unbounded 1 KiB chunks against a 1 KiB part: the intake must
        // 413 after the second chunk, not buffer forever.
        let flood = futures_util::stream::repeat_with(|| {
            Ok::<_, FsError>(Bytes::from(vec![0u8; 1024]))
        });
        let err = engine
            .upload_part(&id, 0, flood, None, None, "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::PayloadTooLarge));
        assert_eq!(
            err.status_code(),
            actix_web::http::StatusCode::PAYLOAD_TOO_LARGE
        );
        Ok(())
    }

    #[tokio::test]
    async fn upload_part_checks_declared_length_before_reading() -> anyhow::Result<()> {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let engine = make_engine("alice", false).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        // Records whether the stream is polled at all: a declared length
        // that already mismatches must fail before the first poll.
        let polled = Arc::new(AtomicBool::new(false));
        let flag = polled.clone();
        let untouched = futures_util::stream::poll_fn(move |_| {
            flag.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(None::<Result<Bytes, FsError>>)
        });
        let err = engine
            .upload_part(&id, 0, untouched, Some(999), None, "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::BadRequest(_)));
        assert!(!polled.load(Ordering::SeqCst));
        // Declared larger than expected is 413, not 400.
        let err = engine
            .upload_part(&id, 0, once_body(vec![1u8; 1024]), Some(2048), None, "alice")
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::PayloadTooLarge));
        Ok(())
    }

    #[tokio::test]
    async fn streamed_download_matches_upload() -> anyhow::Result<()> {
        use futures_util::TryStreamExt as _;

        let engine = make_engine("alice", false).await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        let body: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        engine
            .upload_part(&id, 0, once_body(body.clone()), None, None, "alice")
            .await?;
        engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "big.bin".into(),
                    mimetype: "application/octet-stream".into(),
                },
                "alice",
            )
            .await?;
        let (rec, obj) = engine.get_object(&id, "alice").await?;
        assert_eq!(obj.size, 1024);
        let chunks: Vec<Bytes> = obj.stream.try_collect().await?;
        assert_eq!(chunks.concat(), body);
        assert_eq!(rec.size, 1024);
        Ok(())
    }

    #[tokio::test]
    async fn token_mint_verify() -> anyhow::Result<()> {
        let engine = make_engine("alice", false).await;
        let tok = engine.mint_token("alice", "file1", Action::Read)?;
        engine.verify_token(&tok, "file1", Action::Read)?;
        assert!(engine.verify_token(&tok, "file1", Action::Write).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn mutations_append_to_wal() -> anyhow::Result<()> {
        use crate::sync::wal::{Wal, WalOp};

        let wal_prefix = format!("test-fs-wal-{}-{}", std::process::id(), {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
        });
        let wal = Wal::new(crate::db::build_test_store(&wal_prefix).await);
        let engine = make_engine("alice", false).await.with_wal(wal.clone());
        engine
            .policy
            .add_rule("alice".into(), "invoice:123".into(), Action::Write)
            .await
            .unwrap();

        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, once_body(vec![1u8; 1024]), None, None, "alice")
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
        engine.attach("invoice", "123", &id, "alice").await?;
        engine.detach("invoice", "123", &id, "alice").await?;
        engine.delete_file(&id, "alice").await?;

        let entries = wal.range(1, wal.head().await?).await?;
        let ops: Vec<&WalOp> = entries.iter().map(|e| &e.op).collect();
        assert_eq!(ops.len(), 4);
        assert!(matches!(&ops[0], WalOp::FileCreate { rec } if rec.id == id));
        assert!(matches!(&ops[1], WalOp::Attach { file_id, .. } if file_id == &id));
        assert!(matches!(&ops[2], WalOp::Detach { file_id, .. } if file_id == &id));
        assert!(matches!(&ops[3], WalOp::FileDelete { file_id } if file_id == &id));
        Ok(())
    }
}
