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

use std::collections::HashMap;
use std::sync::Arc;

use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, Authorizer};
use crate::records::{ChangeSink, WalOp};

use error::FsError;
use model::{CompleteRequest, FileMetadata, InitRequest};
use s3::S3Client;
use store::{FileRecord, FsStore, UploadSession};

/// Allocates `len` empty per-part slots without risking a process abort.
///
/// `vec![None; len]` *aborts* the process when the allocation fails, and
/// `len` is a field straight off the wire. Before this existed, a 70-byte
/// `POST /fs/uploads` declaring `2^54` parts allocated 383 TiB and killed
/// the server — a hard abort, not a catchable panic, so no handler could
/// have contained it.
///
/// [`InitRequest::validate`] caps the count at
/// [`MAX_MULTIPART_PARTS`](model::MAX_MULTIPART_PARTS), so this should not
/// fire. It exists because the failure mode of getting that cap wrong is
/// an uncatchable process death, which is worth a second layer: a bad
/// count has to degrade to a 4xx either way.
fn part_slots(len: u64) -> Result<Vec<Option<String>>, FsError> {
    let len = usize::try_from(len)
        .map_err(|_| FsError::BadRequest("file_total_parts does not fit in memory".into()))?;
    let mut slots: Vec<Option<String>> = Vec::new();
    // `try_reserve_exact` then `resize`: after the reservation succeeds,
    // `resize` only fills the reserved capacity and cannot reallocate.
    slots.try_reserve_exact(len).map_err(|_| {
        FsError::BadRequest("file_total_parts is too large to track upload state".into())
    })?;
    slots.resize(len, None);
    Ok(slots)
}

/// Maps a rejected feed append back onto an [`FsError`].
///
/// The feed reports failures opaquely (it may not be a store at all), and
/// the producer only has two things to say about it: it is not the client's
/// fault, and the reason belongs in the server log. Both hold for every
/// sink.
fn feed_error(e: anyhow::Error) -> FsError {
    FsError::Internal(e.to_string())
}

/// Core file-system engine with temp per-user scope and row delegation.
#[derive(Clone)]
pub struct FsEngine {
    pub(crate) store: FsStore,
    pub(crate) s3: Arc<dyn S3Client>,
    pub(crate) bucket: String,
    /// Row-level checks only, so this is the read-only
    /// [`Authorizer`](crate::policy::Authorizer) and not the whole engine.
    ///
    /// Every use of `self.policy` in production is `require_row` or
    /// `authorize_row`, so handing the engine over granted `fs` a write
    /// capability nothing here should have: `fs` has no change feed for
    /// policy mutations, so a rule added through this field would reach
    /// replicas' policy state with no WAL op and no way to replay it.
    /// `sync::SnapshotManager` already holds the same handle for the same
    /// reason.
    policy: Authorizer,
    token_keys: Arc<TokenKeys>,
    /// Change feed for replica sync; `None` disables logging (tests).
    /// Production must wire it: without appends the feed head never
    /// advances and replicas freeze at their last snapshot.
    ///
    /// Typed as [`ChangeSink`] rather than a concrete WAL so this module
    /// has no compile-time path to `sync` — see [`crate::records`].
    feed: Option<Arc<dyn ChangeSink>>,
    /// Serializes the read-modify-write of one upload's rows.
    session_locks: SessionLocks,
}

/// Per-upload serialization for the rows one upload owns.
///
/// An `UploadSession` and the `PersistedMultipart` record behind it are two
/// separate KV keys holding the same fact — how many parts have landed —
/// and every part upload read BOTH, merged its own index into its own copy
/// and wrote both back. `FsStore` takes `inner.write()` per call and never
/// across the pair, `FsEngine` is shared across workers as `web::Data`,
/// and the handler adds no serialization, so parallel part uploads — the
/// normal multipart client pattern — each wrote back a whole session built
/// from a snapshot taken before the other part's write.
///
/// The entry is keyed by file id, which is also the session id: uploads of
/// different files never contend, and the key is dropped when the last
/// holder goes so the map cannot grow with abandoned sessions.
#[derive(Clone, Default)]
struct SessionLocks {
    inner: Arc<std::sync::Mutex<HashMap<String, Arc<SessionEntry>>>>,
}

/// One session's lock, and how many claims are outstanding on it.
struct SessionEntry {
    /// Held across the read-modify-write of this upload's rows.
    lock: tokio::sync::Mutex<()>,
    /// Claims taken on `lock`, including one still waiting for it.
    ///
    /// The map entry may only be dropped when this reaches zero. A claim
    /// that has registered but has not run yet still owns the mutex, and if
    /// the entry vanished under it the NEXT caller would mint a second
    /// mutex for the same session -- two claims, two critical sections, and
    /// exactly the lost update this type exists to prevent.
    claims: std::sync::atomic::AtomicUsize,
}

/// A held-or-pending claim on one session's lock.
///
/// Owning one is what keeps the map entry alive; dropping it gives the claim
/// back, so two sequential parts of one upload do not leave a mutex behind
/// forever.
struct SessionLock<'a> {
    map: &'a std::sync::Mutex<HashMap<String, Arc<SessionEntry>>>,
    key: String,
    entry: Arc<SessionEntry>,
}

impl SessionLock<'_> {
    /// Waits for exclusive access to the session's rows.
    async fn acquire(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.entry.lock.lock().await
    }
}

impl Drop for SessionLock<'_> {
    fn drop(&mut self) {
        // A poisoned map means a holder panicked mid-registration; leave
        // the entry rather than drop somebody else's lock on the way out.
        let Ok(mut map) = self.map.lock() else {
            return;
        };
        if !map
            .get(&self.key)
            .is_some_and(|held| Arc::ptr_eq(held, &self.entry))
        {
            return;
        }
        // Under the map lock, so a claim registering right now cannot slip
        // between the last claim leaving and the entry disappearing.
        if self
            .entry
            .claims
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            map.remove(&self.key);
        }
    }
}

impl SessionLocks {
    /// Claims `key`, waiting for any other holder of the same session.
    ///
    /// The map is a `std::sync::Mutex` and is never held across an await:
    /// registering is microseconds, and the per-key async mutex below is
    /// what actually waits, so a slow part upload cannot stall registration
    /// for every other session.
    async fn acquire(&self, key: &str) -> SessionLock<'_> {
        let entry = {
            let mut map = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = Arc::clone(map.entry(key.to_string()).or_insert_with(|| {
                Arc::new(SessionEntry {
                    lock: tokio::sync::Mutex::new(()),
                    claims: std::sync::atomic::AtomicUsize::new(0),
                })
            }));
            entry
                .claims
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            entry
        };
        SessionLock {
            map: &self.inner,
            key: key.to_string(),
            entry,
        }
    }
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
        policy: Authorizer,
    ) -> Result<Self, FsError> {
        let store = FsStore::primary(s3_store);
        let s3 = s3::build_s3_client(s3_config)
            .await
            .map_err(|e| FsError::Internal(format!("failed to build S3 client: {e}")))?;
        Ok(Self {
            store,
            s3,
            bucket: s3_config.bucket.clone(),
            policy,
            token_keys: Arc::new(TokenKeys::ephemeral()),
            feed: None,
            session_locks: SessionLocks::default(),
        })
    }

    /// Attaches a [`ChangeSink`] for replica sync.
    ///
    /// Ops are announced so the feed does not silently miss a mutation, but
    /// NOT fail-closed. This comment used to claim the opposite --
    /// "a logging failure fails the whole operation so the feed never
    /// silently misses a committed write" -- and it was false in both
    /// directions: `complete_upload` and `delete_file` committed first and
    /// announced last, and nothing was rolled back, so a WAL failure lost
    /// the mutation *and* the session or row the retry needed.
    ///
    /// What actually holds now, and is what each mutation is written to
    /// keep:
    ///
    /// * An announce happens before the step that makes a mutation
    ///   unretryable ([`delete_file`](Self::delete_file) announces before
    ///   the row goes, like [`gc`](crate::fs::gc)), or immediately after
    ///   it with the handle for the retry deliberately left in place
    ///   ([`complete_upload`](Self::complete_upload) commits the record,
    ///   announces, and only then drops the session).
    /// * Every announce failure therefore leaves something a *later
    ///   request* can replay it from, and every entry point is idempotent
    ///   on that retry -- so the retry converges instead of 404ing.
    /// * A failed append is re-announced at most once per failure, because
    ///   the retry's own cleanup removes the handle. A client looping
    ///   `complete` cannot grow the feed.
    ///
    /// What this does NOT give: a client that never retries loses the
    /// announce for good. The committed record is on master, so a replica
    /// running a full rebuild picks the file up from the KV regardless, but
    /// incremental replay does not learn of it. That window is logged, not
    /// closed -- closing it needs a replayable outbox, which this crate has
    /// no storage for.
    ///
    /// Takes a trait object so this module never names `sync`. The
    /// concrete implementation is [`sync::wal::Wal`](crate::sync::wal::Wal).
    pub fn with_change_sink(mut self, feed: Arc<dyn ChangeSink>) -> Self {
        self.feed = Some(feed);
        self
    }

    /// Announces `op` when a feed is wired; no-op otherwise.
    async fn announce(&self, op: WalOp) -> Result<(), FsError> {
        if let Some(feed) = &self.feed {
            feed.append(op).await.map_err(feed_error)?;
        }
        Ok(())
    }

    /// Creates an engine from an explicit [`FsStore`] and [`S3Client`].
    ///
    /// The injection point behind the `S3Client` "seam so `FsEngine` stays
    /// storage-agnostic" contract: production goes through
    /// [`init`](Self::init), while this lets a host app (or a test) supply
    /// a different byte backend or metadata store. Callers own
    /// [`with_change_sink`](Self::with_change_sink) and
    /// [`with_token_keys`](Self::with_token_keys) separately, exactly as
    /// `init` leaves them.
    pub fn from_parts(
        store: FsStore,
        s3: Arc<dyn S3Client>,
        bucket: String,
        policy: Authorizer,
    ) -> Self {
        Self {
            store,
            s3,
            bucket,
            policy,
            token_keys: Arc::new(TokenKeys::ephemeral()),
            feed: None,
            session_locks: SessionLocks::default(),
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
        self.announce(WalOp::Attach {
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
        self.announce(WalOp::Detach {
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
        // Allocate before touching S3 is not possible (the multipart upload
        // is created first), so the slot vectors are built fallibly: a
        // failure here has to surface as a 4xx rather than take the process
        // down with it.
        let etags = part_slots(req.file_total_parts)?;
        let checksums = part_slots(req.file_total_parts)?;
        let session = UploadSession {
            id: file_id.clone(),
            file_size: req.file_size,
            part_size: req.part_size,
            file_total_parts: req.file_total_parts,
            s3_upload_id,
            s3_key,
            owner_sub: owner_sub.to_string(),
            created_at: chrono::Utc::now().timestamp(),
            etags,
            checksums,
        };
        self.store.save_session(&session).await?;
        // Persist S3-side state with the session: after a restart the
        // client RAM map is empty and only this record can rehydrate
        // (or abort) the backend upload.
        if let Some(upload_id) = session.s3_upload_id.as_deref() {
            let s3_upload_id = self.s3.backend_upload_id(upload_id).await.ok_or_else(|| {
                FsError::Internal("multipart created but backend id missing".into())
            })?;
            self.store
                .save_multipart(&crate::fs::store::PersistedMultipart {
                    upload_id: upload_id.to_string(),
                    bucket: self.bucket.clone(),
                    key: session.s3_key.clone(),
                    s3_upload_id,
                    parts: std::collections::BTreeMap::new(),
                    created_at: session.created_at,
                })
                .await?;
        }
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
    ///
    /// The session's two rows are merged under its lock *after* the bytes
    /// are staged, never before: the body stream and the S3 round trip are
    /// the slow part and are per-part, so holding the lock across them
    /// would serialize a client's own parallel part uploads — the pattern
    /// this exists to support. Everything that can lose an entry is in the
    /// merge ([`merge_part`](Self::merge_part)), which re-reads under the
    /// lock instead of trusting the copy read here.
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

        let session = self
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
        let ceiling = expected.min(crate::http::MAX_PAYLOAD_BYTES as u64) + 1;
        let mut buf =
            Vec::with_capacity(expected.min(crate::http::MAX_PAYLOAD_BYTES as u64) as usize);
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
            return self
                .merge_part(
                    file_id,
                    part_index,
                    None,
                    "put".into(),
                    checksum_sha256,
                    caller_sub,
                )
                .await;
        }
        let upload_id = session
            .s3_upload_id
            .clone()
            .ok_or_else(|| FsError::Internal("missing s3 upload id".into()))?;
        self.ensure_multipart(&upload_id).await?;
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
        self.merge_part(
            file_id,
            part_index,
            Some(&upload_id),
            etag,
            checksum_sha256,
            caller_sub,
        )
        .await
    }

    /// Folds one uploaded part into the session row and its durable
    /// multipart record, under the session's lock.
    ///
    /// Everything that can lose a concurrent part's entry is here: the
    /// session and the record are separate KV keys, so a merge that
    /// wrote only one of them — or read them at different instants than
    /// the sibling that was interleaved with — dropped a part that the
    /// client had already been told was uploaded.
    ///
    /// The session is re-read under the lock rather than reused from the
    /// caller's copy, which was taken before the body was streamed and
    /// before the S3 round trip. That copy is still what the size and
    /// bounds checks ran against, which is sound because `file_size`,
    /// `part_size` and `file_total_parts` are fixed at init and the id is
    /// a fresh uuid, so no other request can resize the session; the
    /// re-read still re-checks the index and the owner.
    ///
    /// The record is written FIRST. A crash between the two keys must
    /// leave the session short an etag, never the record short a part:
    /// the first is a 400 "not all parts uploaded" that the client repairs
    /// by re-uploading the part `GET /fs/uploads/{id}` shows missing, while
    /// the second is the unwedgeable "etag count N != part count N-1" that
    /// looks complete in every response the client can see. It is the same
    /// ordering `FsStore::delete_session` uses, cascade rows before the
    /// row that makes them reachable.
    async fn merge_part(
        &self,
        file_id: &str,
        part_index: u64,
        upload_id: Option<&str>,
        etag: String,
        checksum_sha256: Option<String>,
        caller_sub: &str,
    ) -> Result<(), FsError> {
        let session_lock = self.session_locks.acquire(file_id).await;
        let _held = session_lock.acquire().await;
        let mut session = self
            .store
            .get_session(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("upload session not found".into()))?;
        if session.owner_sub != caller_sub {
            return Err(FsError::Forbidden);
        }
        let slot = part_index as usize;
        if slot >= session.etags.len() {
            return Err(FsError::BadRequest("part index out of bounds".into()));
        }
        // Mirror staged content ids into the durable record so a
        // restarted client can still complete this upload.
        if let Some(upload_id) = upload_id
            && let Some(mut record) = self.store.load_multipart(upload_id).await?
        {
            record.parts.insert(slot, etag.clone());
            self.store.save_multipart(&record).await?;
        }
        session.etags[slot] = Some(etag);
        if session.checksums.len() != session.etags.len() {
            session.checksums.resize(session.etags.len(), None);
        }
        session.checksums[slot] = checksum_sha256;
        self.store.save_session(&session).await?;
        Ok(())
    }

    /// Rehydrates client-side multipart state from the durable record.
    ///
    /// Sessions predating persistence (or a crashed init between the
    /// session write and the record write) have no record: their
    /// backend upload is unaddressable, so callers get a clear restart
    /// signal instead of an opaque `unknown upload_id`.
    async fn ensure_multipart(&self, upload_id: &str) -> Result<(), FsError> {
        let Some(record) = self.store.load_multipart(upload_id).await? else {
            return Err(FsError::BadRequest(
                "multipart state unavailable (restarted server or expired session); start a new upload"
                    .into(),
            ));
        };
        self.s3.restore_multipart(&record).await
    }

    /// Aborts the S3 side of an expired/abandoned session.
    ///
    /// `NotFound` from S3 means already gone (aborted, completed, or a
    /// fresh InMemory backend after restart): success for GC purposes.
    /// Any other failure propagates so the session is retained for
    /// retry instead of leaking staged bytes no record points at.
    pub(crate) async fn abort_session_upload(
        &self,
        session: &UploadSession,
    ) -> Result<(), FsError> {
        let Some(upload_id) = session.s3_upload_id.as_deref() else {
            return self
                .s3
                .delete_object(&self.bucket, &session.s3_key)
                .await
                .map_err(|e| {
                    tracing::warn!("gc delete {} failed: {e}", session.id);
                    e
                });
        };
        if self.store.load_multipart(upload_id).await?.is_none() {
            // Predates persistence: backend unaddressable, staged parts
            // unreachable. Warn loudly, let the session go (a future
            // sweeper with S3 multipart listing could reclaim these).
            tracing::warn!(
                "gc expiring {} has no multipart record; staged S3 parts may leak",
                session.id
            );
            return Ok(());
        }
        self.ensure_multipart(upload_id).await.map_err(|e| {
            tracing::warn!("gc restore {} failed: {e}", session.id);
            e
        })?;
        match self
            .s3
            .abort_multipart_upload(&self.bucket, &session.s3_key, upload_id)
            .await
        {
            Ok(()) => Ok(()),
            Err(FsError::NotFound(_)) => {
                tracing::debug!("gc abort {} already gone", session.id);
                Ok(())
            }
            Err(e) => {
                tracing::warn!("gc abort {} failed: {e}", session.id);
                Err(e)
            }
        }
    }

    /// Finalizes an upload session; only the owner may complete.
    ///
    /// Idempotent from the client's side: a retry after a failed announce
    /// finds the committed record *and* the session the failure left
    /// behind, re-announces, and converges. See
    /// [`with_change_sink`](Self::with_change_sink) for what that does and
    /// does not guarantee.
    #[tracing::instrument(skip(self, req), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn complete_upload(
        &self,
        file_id: &str,
        req: CompleteRequest,
        caller_sub: &str,
    ) -> Result<(), FsError> {
        // Held across the whole completion, S3 round trip included: a
        // complete that interleaved with a part upload is the same lost
        // write as two parts interleaving with each other, and unlike two
        // parts it is not the client's normal pattern. This is per session,
        // so it costs nothing to a client uploading several files at once.
        let session_lock = self.session_locks.acquire(file_id).await;
        let _held = session_lock.acquire().await;
        // The record is read first because it is the committed half: a
        // session that outlived its own commit is the retry handle, and a
        // record with no session is an upload that already converged.
        let committed = self.store.get_file(file_id).await?;
        let session = self.store.get_session(file_id).await?;
        if let Some(rec) = &committed {
            if rec.owner_sub != caller_sub {
                return Err(FsError::Forbidden);
            }
            let Some(_session) = session else {
                // Announced and cleaned up by an earlier attempt: only this
                // module drops the session, and only after the append
                // returned, so there is nothing left to announce. Success
                // WITHOUT an append, which is what stops a client looping
                // `complete` on a file id from growing the feed.
                return Ok(());
            };
            // Committed, session still here: the announce (or the cleanup
            // after it) failed. Re-announce from the committed record --
            // the exact op that was lost -- then drop the handle so the
            // bound holds for the next retry too.
            self.announce(WalOp::FileCreate { rec: rec.clone() })
                .await?;
            self.store.delete_session(file_id).await?;
            return Ok(());
        }
        let session =
            session.ok_or_else(|| FsError::NotFound("upload session not found".into()))?;
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
            self.ensure_multipart(upload_id).await?;
            self.s3
                .complete_multipart_upload(&self.bucket, &session.s3_key, upload_id, etags)
                .await?;
            // Drop the durable record with the completed upload (the
            // session delete below cascades as a backstop).
            self.store.delete_multipart(upload_id).await?;
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
        // Commit, announce, and only then release the retry handle. The
        // old order deleted the session before the append, so an append
        // that failed left a committed file with no session and no op --
        // the client's retry 404'd on `get_session` and every replica
        // applying the feed incrementally never learned the file existed.
        self.store.save_file(&record).await?;
        self.announce(WalOp::FileCreate { rec: record }).await?;
        self.store.delete_session(file_id).await?;
        Ok(())
    }

    /// Aborts a multipart upload; only the owner may cancel.
    ///
    /// S3 abort runs before the session is deleted, and a failed abort
    /// (other than already-gone) fails the cancel: the session stays
    /// so GC retries instead of leaking staged parts no record
    /// points at.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn cancel_upload(&self, file_id: &str, caller_sub: &str) -> Result<(), FsError> {
        // Same lock as completion: a cancel that interleaved with a part
        // upload's merge would let that merge write the session back
        // underneath it, resurrecting an upload whose S3 side is gone.
        let session_lock = self.session_locks.acquire(file_id).await;
        let _held = session_lock.acquire().await;
        let session = self
            .store
            .get_session(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("upload session not found".into()))?;
        if session.owner_sub != caller_sub {
            return Err(FsError::Forbidden);
        }
        if session.s3_upload_id.is_some() {
            self.abort_session_upload(&session).await?;
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
    /// The announce comes FIRST, for the same reason [`gc`](crate::fs::gc)
    /// puts it before the row delete: the row is the only thing left that
    /// knows this deletion still has to be announced, so an append that
    /// fails has to retain it. The old order deleted the row and the bytes
    /// and announced last, which turned a WAL blip into a 500 whose retry
    /// 404'd (`get_file` -> `None`) -- every replica kept serving a record
    /// for bytes that were already gone, and nothing re-announced it.
    ///
    /// Metadata still goes before S3 bytes: a failure between them leaks an
    /// unreachable object, which gc's orphan pass provably reaps after the
    /// TTL, rather than leaving a record that 404s every download. A retry
    /// of THAT case finds no row and 404s, which is why the bytes are last.
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
        // Announced before the row goes, not after: an append that fails
        // here leaves the row, and the client's retry re-runs this whole
        // authorized path and converges. Re-announcing is free -- replaying
        // `FileDelete` is a `delete_file` on the replica, idempotent on a
        // file that is already gone.
        //
        // Deliberately NOT extended to "no record means already deleted,
        // announce anyway": that would turn every 404 into a permanent feed
        // entry, and the feed is append-only with nothing to authorize
        // against once the record is gone.
        self.announce(WalOp::FileDelete {
            file_id: file_id.to_string(),
        })
        .await?;
        self.store.delete_file(file_id).await?;
        self.s3.delete_object(&self.bucket, &rec.s3_key).await?;
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
        let body = self.s3.get_object_stream(&self.bucket, &rec.s3_key).await?;
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
mod tests {
    use super::*;

    use crate::fs::object_store::ObjectStoreClient;
    use crate::policy::PolicyEngine;
    use bytes::Bytes;

    async fn make_engine(sub: &str) -> FsEngine {
        make_engine_and_policy(sub).await.0
    }

    /// The engine plus the write-capable policy handle.
    ///
    /// `FsEngine` only holds an `Authorizer`, so a test that needs to grant a
    /// rule has to keep the engine that seeded it -- which is the point of
    /// the narrower field, not a workaround for it.
    async fn make_engine_and_policy(sub: &str) -> (FsEngine, PolicyEngine) {
        use crate::db::build_test_store;
        let prefix = format!("{}-{sub}", crate::db::test_prefix("fs-engine"));
        let s3_store = build_test_store(&prefix).await;
        let store = FsStore::primary(s3_store);
        let policy_prefix = format!("{prefix}-policy");
        let policy_store = build_test_store(&policy_prefix).await;
        let policy = PolicyEngine::init_s3(policy_store).await.unwrap();
        let s3 = ObjectStoreClient::in_memory();
        let engine =
            FsEngine::from_parts(store, s3, "test-bucket".to_string(), policy.authorizer());
        (engine, policy)
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

    /// Engine over an explicit byte backend, for the tests that need to
    /// control when the backend answers.
    async fn engine_with_s3(sub: &str, s3: Arc<dyn S3Client>) -> FsEngine {
        let prefix = format!("{}-{sub}", crate::db::test_prefix("fs-engine"));
        let store = FsStore::primary(crate::db::build_test_store(&prefix).await);
        let policy_prefix = format!("{prefix}-policy");
        let policy = PolicyEngine::init_s3(crate::db::build_test_store(&policy_prefix).await)
            .await
            .unwrap();
        FsEngine::from_parts(store, s3, "test-bucket".to_string(), policy.authorizer())
    }

    /// [`S3Client`] that parks ONE chosen `upload_part` until released.
    ///
    /// Everything else delegates to a real in-memory backend, so
    /// `complete_upload` genuinely assembles the object; only WHEN one part
    /// upload reaches the backend is controlled. That is what makes the
    /// interleaving a regression test rather than a race the scheduler has
    /// to lose: the parked part is inside the backend call while the other
    /// parts run their whole read-merge-write.
    struct GateS3 {
        inner: Arc<dyn S3Client>,
        /// The 1-indexed part number to park. It has to be the LAST one:
        /// the in-memory backend only accepts parts in ascending order.
        gate_part: i32,
        parked: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Arc<tokio::sync::Notify>,
    }

    impl GateS3 {
        /// The client, a "parked" signal fired from inside the `gate_part`
        /// upload, and the handle that lets it go.
        fn new(
            inner: Arc<dyn S3Client>,
            gate_part: i32,
        ) -> (
            Self,
            tokio::sync::oneshot::Receiver<()>,
            Arc<tokio::sync::Notify>,
        ) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let release = Arc::new(tokio::sync::Notify::new());
            (
                Self {
                    inner,
                    gate_part,
                    parked: std::sync::Mutex::new(Some(tx)),
                    release: Arc::clone(&release),
                },
                rx,
                release,
            )
        }
    }

    #[async_trait::async_trait]
    impl S3Client for GateS3 {
        async fn create_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            content_type: Option<String>,
        ) -> Result<String, FsError> {
            self.inner
                .create_multipart_upload(bucket, key, content_type)
                .await
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
            if part_number == self.gate_part {
                if let Some(tx) = self.parked.lock().expect("gate").take() {
                    let _ = tx.send(());
                }
                self.release.notified().await;
            }
            self.inner
                .upload_part(bucket, key, upload_id, part_number, body, checksum_sha256)
                .await
        }

        async fn complete_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
            etags: Vec<String>,
        ) -> Result<(), FsError> {
            self.inner
                .complete_multipart_upload(bucket, key, upload_id, etags)
                .await
        }

        async fn abort_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
        ) -> Result<(), FsError> {
            self.inner
                .abort_multipart_upload(bucket, key, upload_id)
                .await
        }

        async fn backend_upload_id(&self, upload_id: &str) -> Option<String> {
            self.inner.backend_upload_id(upload_id).await
        }

        async fn restore_multipart(
            &self,
            record: &crate::fs::store::PersistedMultipart,
        ) -> Result<(), FsError> {
            self.inner.restore_multipart(record).await
        }

        async fn put_object(
            &self,
            bucket: &str,
            key: &str,
            body: Bytes,
            content_type: Option<String>,
            checksum_sha256: Option<String>,
        ) -> Result<(), FsError> {
            self.inner
                .put_object(bucket, key, body, content_type, checksum_sha256)
                .await
        }

        async fn get_object(&self, bucket: &str, key: &str) -> Result<Bytes, FsError> {
            self.inner.get_object(bucket, key).await
        }

        async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), FsError> {
            self.inner.delete_object(bucket, key).await
        }

        async fn list_keys(
            &self,
            bucket: &str,
            prefix: &str,
        ) -> Result<Vec<crate::fs::s3::ListedKey>, FsError> {
            self.inner.list_keys(bucket, prefix).await
        }
    }

    /// Two parts of one upload, uploaded in parallel, must both survive.
    ///
    /// `upload_part` read the session, streamed the body, called the
    /// backend, and then wrote the ENTIRE session back:
    ///
    ///     session.etags[part_index as usize] = Some(etag.clone());
    ///     self.store.save_session(&session).await?;
    ///     if let Some(mut record) = self.store.load_multipart(&upload_id).await? {
    ///         record.parts.insert(part_index as usize, etag);
    ///         self.store.save_multipart(&record).await?;
    ///     }
    ///
    /// Nothing held the read-modify-write: `FsStore` takes `inner.write()`
    /// per call, and `FsEngine` is shared across workers as `web::Data`.
    /// Parallel part upload is the normal multipart client pattern, so part
    /// 1 writing back the session it read before part 0's save dropped part
    /// 0's etag, and `GET /fs/uploads/{id}` reported it as never uploaded
    /// even though the bytes were staged.
    ///
    /// The worse interleaving dropped only the RECORD: both session etags
    /// present, record short a part, `complete_upload` passing its
    /// `any(is_none)` gate and failing in the backend with "etag count 2
    /// != part count 1" -- a failure no client response hints at and no
    /// retry can clear.
    ///
    /// Deterministic by construction: part 0 is parked inside the backend
    /// call while part 1 runs start to finish, so the sibling that must
    /// interleave is guaranteed to interleave. Before the fix part 1's
    /// stale copy is written back over part 0's etag and the session is
    /// left `[Some, None]`.
    #[tokio::test]
    async fn concurrent_part_uploads_keep_every_etag_and_record_part() -> anyhow::Result<()> {
        const PARTS: u64 = 3;
        // The LAST part parks: parts must reach the backend in ascending
        // order, so the parked one has to be the one whose siblings ran
        // first.
        let (gate, parked, release) = GateS3::new(ObjectStoreClient::in_memory(), PARTS as i32);
        let engine = engine_with_s3("alice-parallel", Arc::new(gate)).await;
        let id = engine
            .init_upload(
                InitRequest {
                    file_size: PARTS * 1024,
                    part_size: 1024,
                    file_total_parts: PARTS,
                },
                "alice",
            )
            .await?;

        // The last part parks inside the backend; the earlier two then run
        // their whole read-merge-write while it waits.
        let last = tokio::spawn({
            let engine = engine.clone();
            let id = id.clone();
            async move {
                engine
                    .upload_part(
                        &id,
                        PARTS - 1,
                        once_body(vec![9u8; 1024]),
                        None,
                        None,
                        "alice",
                    )
                    .await
            }
        });
        parked
            .await
            .expect("the last part parked in the backend, or the gate never fired");
        for part in 0..PARTS - 1 {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                engine.upload_part(&id, part, once_body(vec![part as u8; 1024]), None, None, "alice"),
            )
            .await
            .expect("a part was blocked behind a SIBLING's backend call: the session lock is held too wide")?;
        }
        release.notify_one();
        last.await.expect("last part task")?;

        let session = engine
            .store
            .get_session(&id)
            .await?
            .expect("session survives an incomplete upload");
        assert_eq!(session.etags.len(), PARTS as usize);
        assert!(
            session.etags.iter().all(|e| e.is_some()),
            "a concurrent part's etag was dropped: {:?}",
            session.etags
        );
        let upload_id = session.s3_upload_id.clone().expect("multipart session");
        let record = engine
            .store
            .load_multipart(&upload_id)
            .await?
            .expect("multipart record");
        assert_eq!(
            record.parts.len(),
            PARTS as usize,
            "a concurrent part's record entry was dropped: {:?}",
            record.parts
        );

        // The whole point: an upload whose client has been told every part
        // is present must actually complete.
        engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "parallel.bin".into(),
                    mimetype: "application/octet-stream".into(),
                },
                "alice",
            )
            .await?;
        let (rec, obj) = engine.get_object(&id, "alice").await?;
        assert_eq!(rec.size, PARTS * 1024);
        assert_eq!(obj.size, PARTS * 1024);
        Ok(())
    }

    #[tokio::test]
    async fn init_upload_validates() -> anyhow::Result<()> {
        let engine = make_engine("alice").await;
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

    /// End-to-end version of the allocation-abort regression: the abusive
    /// body must come back as a 4xx, not take the process with it. Running
    /// this against the unfixed engine would abort the test binary, which
    /// is exactly the failure being guarded.
    #[tokio::test]
    async fn init_upload_rejects_an_allocation_bomb_without_dying() -> anyhow::Result<()> {
        let engine = make_engine("alice").await;
        let err = engine
            .init_upload(
                InitRequest {
                    file_size: u64::MAX - 1023,
                    part_size: 1024,
                    file_total_parts: (1u64 << 54) - 1,
                },
                "alice",
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, FsError::BadRequest(_)),
            "expected a 4xx, got {err:?}"
        );
        Ok(())
    }

    /// The slot vectors are built fallibly, so an absurd count is a 4xx even
    /// if validation is bypassed or the cap is later raised by mistake.
    #[test]
    fn part_slots_never_aborts() {
        // Legal: exactly the S3 limit.
        assert_eq!(
            part_slots(model::MAX_MULTIPART_PARTS).unwrap().len(),
            10_000
        );
        // Illegal by the cap, but reachable only if validation is skipped;
        // must return an error rather than attempt the allocation.
        let err = part_slots(u64::MAX).expect_err("u64::MAX must not allocate");
        assert!(matches!(err, FsError::BadRequest(_)), "got {err:?}");
        // The failure message must not leak memory state to the client.
        assert!(!err.to_string().contains("memory"), "leaks: {err}");
    }

    #[tokio::test]
    async fn temp_upload_owned_by_caller() -> anyhow::Result<()> {
        let engine = make_engine("alice").await;
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
        let (engine, policy) = make_engine_and_policy("alice").await;
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
        policy
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
        let (engine, policy) = make_engine_and_policy("alice").await;
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
        policy
            .add_rule("alice".into(), "invoice:123".into(), Action::Write)
            .await
            .unwrap();
        engine.attach("invoice", "123", &id, "alice").await?;
        policy
            .add_rule("bob".into(), "invoice:123".into(), Action::Read)
            .await
            .unwrap();
        let meta = engine.get_metadata(&id, "bob").await?;
        assert_eq!(meta.name, "doc.txt");
        Ok(())
    }

    /// `can_access` is the one FS call site that goes through
    /// `authorize_row` rather than `require_row`, so it is the one path the
    /// narrowed field could have broken silently: the trait impl it resolves
    /// against moved when `policy` became an `Authorizer`.
    ///
    /// Denial is asserted as carefully as the grant. A delegation mistake
    /// that resolved to a permissive default would still return `true` for
    /// the granted subject, so only the granted assertion would notice
    /// nothing.
    #[tokio::test]
    async fn authorize_row_decides_access_through_the_narrowed_policy_field() -> anyhow::Result<()>
    {
        let (engine, policy) = make_engine_and_policy("alice").await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, once_body(vec![9u8; 1024]), None, None, "alice")
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
        policy
            .add_rule("alice".into(), "invoice:123".into(), Action::Write)
            .await
            .unwrap();
        engine.attach("invoice", "123", &id, "alice").await?;

        // A linked row with no rule for bob is a deny, not an error.
        assert!(!engine.can_access("bob", &id, Action::Read).await?);

        policy
            .add_rule("bob".into(), "invoice:123".into(), Action::Read)
            .await
            .unwrap();
        assert!(engine.can_access("bob", &id, Action::Read).await?);
        // Read on the row is not write on it: the action is part of the key.
        assert!(!engine.can_access("bob", &id, Action::Delete).await?);

        // The owner always reaches their own file, whatever policy says.
        assert!(engine.can_access("alice", &id, Action::Delete).await?);
        // And a policy change made after the fact is seen, which is only
        // true because the handle shares the engine rather than copying it.
        policy
            .remove_rule("bob".into(), "invoice:123".into(), Action::Read)
            .await
            .unwrap();
        assert!(!engine.can_access("bob", &id, Action::Read).await?);
        Ok(())
    }

    /// `FsEngine` holds the read-only handle, not the write-capable engine.
    ///
    /// Every production use of the field is `require_row`/`authorize_row`, so
    /// the engine was a grant `fs` did not need and should not have had: it
    /// has no change feed for policy mutations, so a rule added through it
    /// would reach replicas with no WAL op to replay. Asserting the field's
    /// type is the only way to keep that true -- every behavioural test here
    /// passes either way, because the handle and the engine agree.
    #[test]
    fn the_policy_field_is_the_read_only_handle() {
        let src = std::fs::read_to_string("src/fs/mod.rs").expect("read src/fs/mod.rs");
        let field = src
            .lines()
            .find(|line| line.trim_start().starts_with("policy: "))
            .expect("FsEngine declares a policy field");
        assert_eq!(
            field.trim(),
            "policy: Authorizer,",
            "FsEngine's policy field must be the read-only Authorizer"
        );

        // And there is exactly one `RowAuthorizer` impl in the crate, for
        // that handle.
        let row = std::fs::read_to_string("src/policy/row.rs").expect("read src/policy/row.rs");
        let impls: Vec<&str> = row
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("impl RowAuthorizer for"))
            .collect();
        assert_eq!(
            impls,
            vec!["impl RowAuthorizer for Authorizer {"],
            "RowAuthorizer must be implemented once, for the handle whose \
             capability matches the trait"
        );
    }

    #[tokio::test]
    async fn upload_part_cuts_oversize_streams_early() -> anyhow::Result<()> {
        use actix_web::ResponseError as _;

        let engine = make_engine("alice").await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        // Unbounded 1 KiB chunks against a 1 KiB part: the intake must
        // 413 after the second chunk, not buffer forever.
        let flood =
            futures_util::stream::repeat_with(|| Ok::<_, FsError>(Bytes::from(vec![0u8; 1024])));
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

        let engine = make_engine("alice").await;
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
            .upload_part(
                &id,
                0,
                once_body(vec![1u8; 1024]),
                Some(2048),
                None,
                "alice",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::PayloadTooLarge));
        Ok(())
    }

    #[tokio::test]
    async fn streamed_download_matches_upload() -> anyhow::Result<()> {
        use futures_util::TryStreamExt as _;

        let engine = make_engine("alice").await;
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
        let engine = make_engine("alice").await;
        let tok = engine.mint_token("alice", "file1", Action::Read)?;
        engine.verify_token(&tok, "file1", Action::Read)?;
        assert!(engine.verify_token(&tok, "file1", Action::Write).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn mutations_are_announced_to_the_feed() -> anyhow::Result<()> {
        use crate::records::WalOp;
        use crate::sync::wal::Wal;

        let wal = Wal::new(crate::db::build_test_store(&crate::db::test_prefix("fs-wal")).await);
        let (engine, policy) = make_engine_and_policy("alice").await;
        let engine = engine.with_change_sink(Arc::new(wal.clone()));
        policy
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

    /// [`ChangeSink`] double that refuses every append.
    ///
    /// Stands in for the one failure both fixes here exist for: the
    /// mutation commits and the feed does not take it.
    struct DeadFeed;

    #[async_trait::async_trait]
    impl crate::records::ChangeSink for DeadFeed {
        async fn append(&self, _: crate::records::WalOp) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("feed down"))
        }
    }

    /// A complete that committed but could not announce must be repairable
    /// by the client's retry, and only by one.
    ///
    /// The old order was `save_file`, `delete_session`, `announce`. A WAL
    /// failure at the announce returned 500 with the record COMMITTED on
    /// master, and the client's retry then read `get_session` as `None`
    /// and 404'd "upload session not found" -- for good. The file was
    /// downloadable on master while every replica applying the feed
    /// incrementally never learned it existed, and no other code path
    /// re-announces a `FileCreate`.
    ///
    /// Asserting the first call returning 500 proves none of that, so the
    /// test drives the retry, which is where the loss happened: it must
    /// converge and the lost op must reach the feed.
    #[tokio::test]
    async fn a_complete_whose_announce_failed_is_repaired_by_the_retry() -> anyhow::Result<()> {
        use crate::records::WalOp;
        use crate::sync::wal::Wal;

        let (engine, _policy) = make_engine_and_policy("alice").await;
        let dead = engine.clone().with_change_sink(Arc::new(DeadFeed));

        let id = dead.init_upload(valid_single(), "alice").await?;
        dead.upload_part(&id, 0, once_body(vec![3u8; 1024]), None, None, "alice")
            .await?;
        dead.complete_upload(
            &id,
            CompleteRequest {
                name: "retry.txt".into(),
                mimetype: "text/plain".into(),
            },
            "alice",
        )
        .await
        .expect_err("a feed that refuses every append must fail the complete");

        // Committed, and the session is deliberately still there: that is
        // the handle the retry replays the announce from.
        assert!(
            engine.store.get_file(&id).await?.is_some(),
            "the record did not commit, so this test is not exercising the window"
        );
        assert!(
            engine.store.get_session(&id).await?.is_some(),
            "the session must survive a failed announce, or the retry has nothing to converge on"
        );

        // Feed repaired: the client retries, and this time it converges.
        let wal = Wal::new(
            crate::db::build_test_store(&crate::db::test_prefix("fs-complete-retry")).await,
        );
        let engine = engine.with_change_sink(Arc::new(wal.clone()));
        engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "retry.txt".into(),
                    mimetype: "text/plain".into(),
                },
                "alice",
            )
            .await?;
        let entries = wal.range(1, wal.head().await?).await?;
        assert_eq!(
            entries.len(),
            1,
            "the lost FileCreate never reached the feed"
        );
        assert!(
            matches!(&entries[0].op, WalOp::FileCreate { rec } if rec.id == id),
            "the retry announced something else: {:?}",
            entries[0].op
        );
        assert!(engine.store.get_session(&id).await?.is_none());

        // Bounded: the retry consumed the handle, so a client looping
        // `complete` cannot append forever against a converged upload.
        engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "retry.txt".into(),
                    mimetype: "text/plain".into(),
                },
                "alice",
            )
            .await?;
        assert_eq!(
            wal.head().await?,
            1,
            "a repeat complete appended to the feed again"
        );

        // And the file is the committed one, not a re-upload.
        assert_eq!(engine.get_metadata(&id, "alice").await?.name, "retry.txt");
        Ok(())
    }

    /// A delete that could not announce must leave the row for the retry.
    ///
    /// The old order was `delete_file`, `s3.delete_object`, `announce`. A
    /// WAL failure at the announce returned 500 with the row GONE, so the
    /// retry took `get_file` -> `None` and 404'd, while replicas kept
    /// serving a record for bytes that were already deleted -- the same
    /// stranding gc fixed in a4e40f9, one layer up.
    ///
    /// The row surviving the failed announce is the assertion that
    /// distinguishes the two orders; the retry converging is the one that
    /// matters to the client.
    #[tokio::test]
    async fn a_delete_whose_announce_failed_is_retried_rather_than_stranded() -> anyhow::Result<()>
    {
        use crate::records::WalOp;
        use crate::sync::wal::Wal;

        let (engine, _policy) = make_engine_and_policy("alice").await;
        let wal =
            Wal::new(crate::db::build_test_store(&crate::db::test_prefix("fs-delete-retry")).await);
        let engine = engine.with_change_sink(Arc::new(wal.clone()));

        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, once_body(vec![4u8; 1024]), None, None, "alice")
            .await?;
        engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "gone.txt".into(),
                    mimetype: "text/plain".into(),
                },
                "alice",
            )
            .await?;

        let dead = engine.clone().with_change_sink(Arc::new(DeadFeed));
        dead.delete_file(&id, "alice")
            .await
            .expect_err("a feed that refuses every append must fail the delete");
        assert!(
            engine.store.get_file(&id).await?.is_some(),
            "the row was deleted while its delete could not be announced"
        );

        // Feed repaired: the client's retry re-runs the authorized path.
        engine.delete_file(&id, "alice").await?;
        assert!(engine.store.get_file(&id).await?.is_none());
        let entries = wal.range(1, wal.head().await?).await?;
        assert_eq!(entries.len(), 2, "expected the create and one delete");
        assert!(
            matches!(&entries[1].op, WalOp::FileDelete { file_id } if file_id == &id),
            "the retry announced something else: {:?}",
            entries[1].op
        );

        // An id that never existed stays a 404 and appends nothing: the
        // feed is append-only, so turning every 404 into a `FileDelete`
        // would be permanent growth any authenticated caller could force.
        let err = engine
            .delete_file("never-existed", "alice")
            .await
            .expect_err("an unknown file id must stay a 404");
        assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
        assert_eq!(wal.head().await?, 2, "a 404 appended to the feed");
        Ok(())
    }
}
