//! File storage on S3, with relations to rows.
//!
//! A temp file has `refs==0` and belongs to `owner_sub`.
//! An attach to a row increases the ref-count.
//! A detach decreases it and marks the file for GC.

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

/// Allocates `len` empty part slots without any risk of a process abort.
///
/// `vec![None; len]` *aborts* the process when the allocation fails.
/// `len` is a field that comes straight from the wire.
/// Before this function existed, a 70-byte `POST /fs/uploads` request with
/// `2^54` parts allocated 383 TiB and stopped the server.
/// That failure was a hard abort, and not a catchable panic, so no handler
/// could contain it.
///
/// [`InitRequest::validate`] caps the count at
/// [`MAX_MULTIPART_PARTS`](model::MAX_MULTIPART_PARTS), so this function
/// should not run.
/// The function stays because a wrong cap ends the process with no catch,
/// and that failure deserves a second layer.
/// A bad count must always become a 4xx.
fn part_slots(len: u64) -> Result<Vec<Option<String>>, FsError> {
    let len = usize::try_from(len)
        .map_err(|_| FsError::BadRequest("file_total_parts does not fit in memory".into()))?;
    let mut slots: Vec<Option<String>> = Vec::new();
    // The code calls `try_reserve_exact` and then `resize`.
    // After the reservation succeeds, `resize` only fills the reserved
    // capacity, and it cannot allocate again.
    slots.try_reserve_exact(len).map_err(|_| {
        FsError::BadRequest("file_total_parts is too large to track upload state".into())
    })?;
    slots.resize(len, None);
    Ok(slots)
}

/// Maps a rejected feed append onto an [`FsError`].
///
/// The feed reports each failure in an unclear way, because the feed may
/// not be a store at all.
/// The producer can then say only two things.
/// The failure is not the fault of the client.
/// The reason belongs in the server log.
/// Both statements are true for every sink.
fn feed_error(e: anyhow::Error) -> FsError {
    FsError::Internal(e.to_string())
}

/// The core file system engine.
/// It uses a temp scope per user, and a row check for each row.
#[derive(Clone)]
pub struct FsEngine {
    pub(crate) store: FsStore,
    pub(crate) s3: Arc<dyn S3Client>,
    pub(crate) bucket: String,
    /// The engine runs row-level checks only.
    /// The field is therefore the read-only
    /// [`Authorizer`](crate::policy::Authorizer), and not the whole engine.
    ///
    /// Every use of `self.policy` in production is `require_row` or
    /// `authorize_row`.
    /// A whole engine would grant `fs` a write capability that nothing here
    /// should have.
    /// `fs` has no change feed for policy mutations.
    /// A rule added through this field would then reach the policy state
    /// of the replicas with no WAL op, and with no way to replay it.
    /// `sync::SnapshotManager` holds the same handle for the same reason.
    policy: Authorizer,
    token_keys: Arc<TokenKeys>,
    /// The change feed for the replica sync.
    /// `None` disables logging. A test uses `None`.
    /// Production must set the feed.
    /// Without appends, the feed head never advances, and the replicas stay
    /// at their last snapshot.
    ///
    /// The type is [`ChangeSink`] and not a concrete WAL, so that this
    /// module has no compile-time path to `sync`.
    /// See [`crate::records`].
    feed: Option<Arc<dyn ChangeSink>>,
    /// Serializes the read-modify-write of one upload's rows.
    session_locks: SessionLocks,
}

/// Serialization for the rows that one upload owns.
///
/// An `UploadSession` and the `PersistedMultipart` record behind it are two
/// separate KV keys.
/// Both keys store the same fact, which is how many parts have landed.
/// Every part upload read both keys. Then it merged its own index into its
/// own copy, and it wrote both keys back.
/// `FsStore` takes `inner.write()` for each call, and never for the pair
/// of keys.
/// `FsEngine` is shared across the workers as `web::Data`, and the handler
/// adds no serialization.
/// Parallel part uploads, which are the normal multipart client pattern,
/// therefore each wrote back a whole session.
/// Each of those sessions came from a snapshot that the other part write
/// took before it.
///
/// The map key is the file id, which is also the session id.
/// Uploads of different files never wait for each other.
/// The code removes the key when the last holder leaves, so that the map
/// cannot grow with abandoned sessions.
#[derive(Clone, Default)]
struct SessionLocks {
    inner: Arc<std::sync::Mutex<HashMap<String, Arc<SessionEntry>>>>,
}

/// One session's lock, and the number of claims on it.
struct SessionEntry {
    /// Held across the read-modify-write of this upload's rows.
    lock: tokio::sync::Mutex<()>,
    /// The number of claims on `lock`, including a claim that still waits for
    /// it.
    ///
    /// The code may drop the map entry only when this count reaches zero.
    /// A claim that registered but has not run yet still owns the mutex.
    /// If the entry then vanished, the NEXT caller would create a second
    /// mutex for the same session.
    /// Two claims and two critical sections give exactly the lost update
    /// that this type prevents.
    claims: std::sync::atomic::AtomicUsize,
}

/// A claim on the lock of one session. The claim is held or pending.
///
/// Owning the claim keeps the map entry alive.
/// Dropping the claim returns it, so that two parts of one upload that run
/// one after the other do not leave a mutex behind for ever.
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
        // A poisoned map means that a holder panicked during registration.
        // The code leaves the entry in place, and does not remove the lock
        // of another holder.
        let Ok(mut map) = self.map.lock() else {
            return;
        };
        if !map
            .get(&self.key)
            .is_some_and(|held| Arc::ptr_eq(held, &self.entry))
        {
            return;
        }
        // The code runs this under the map lock.
        // A claim that registers now cannot then slip between the last
        // claim that leaves and the entry that disappears.
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
    /// Claims `key` and waits for any other holder of the same session.
    ///
    /// The map is a `std::sync::Mutex`, and the code never holds it across
    /// an await.
    /// Registering takes microseconds.
    /// The async mutex for each key below is the part that waits, so a
    /// slow part upload cannot stop the registration of every other
    /// session.
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

/// One capability-token signing key.
/// The `kid` goes in the JWT header.
#[derive(Clone)]
struct TokenKey {
    kid: String,
    secret: Vec<u8>,
}

/// The signing keys for the capability tokens.
/// The current key signs new tokens.
/// The previous key verifies old tokens only.
///
/// The token IDs stay UUIDv7, because oxkv sorts by creation time.
/// Only the HMAC material needs real entropy, so the IDs and the secrets
/// change independently.
#[derive(Clone)]
pub struct TokenKeys {
    current: TokenKey,
    previous: Option<TokenKey>,
}

impl TokenKeys {
    /// Creates an ephemeral 256-bit key from the OS RNG.
    /// A test and an unconfigured run use this call.
    /// The tokens end with the process.
    /// Production must set a stable secret (see `CapabilityConfig`).
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

    /// Creates the configured keys from hex.
    /// The current key signs new tokens.
    /// The previous key, if the caller sets one, verifies tokens during a
    /// rotation.
    /// The function rejects weak or truncated material.
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

    /// Mints a capability token for `file_id` and `act`.
    /// The current key signs the token.
    ///
    /// The method lives here, and not only on [`FsEngine`].
    /// A caller that holds the keys can then create a token without an
    /// engine.
    /// The method is also the only way to see WHICH secret a resolved
    /// [`TokenKeys`] carries.
    /// `TokenKeys` on purpose exposes nothing about its material.
    /// It has no accessor for `secret` or `kid`.
    /// That is the correct default.
    /// The keys are a signing capability, and no legitimate caller needs to
    /// read the secret back.
    /// Verification by round trip answers the same question without an
    /// accessor.
    pub fn mint(&self, sub: &str, file_id: &str, act: Action) -> Result<String, FsError> {
        token::mint(
            sub,
            file_id,
            act,
            &self.current.kid,
            &self.current.secret,
            None,
        )
    }

    /// Verifies a capability token with the current key, and then with the
    /// previous key if a rotation is in progress.
    ///
    /// The method uses the same shape as [`FsEngine::verify_token`].
    /// It is public here, so that both sides of a mint and verify round trip
    /// are reachable from the keys alone.
    pub fn verify(&self, token: &str, file_id: &str, act: Action) -> Result<(), FsError> {
        let mut secrets = vec![self.current.secret.as_slice()];
        if let Some(prev) = &self.previous {
            secrets.push(prev.secret.as_slice());
        }
        token::verify(token, file_id, act, &secrets).map(|_| ())
    }
}

impl FsEngine {
    /// Creates the engine from an `OxKvStore`.
    /// The store uses a per-user S3 LSM store, and it scales per user.
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

    /// Attaches a [`ChangeSink`] for the replica sync.
    ///
    /// The engine announces each op, so that the feed does not miss a
    /// mutation without saying so.
    /// The code does not fail closed.
    /// This doc used to claim the opposite, that "a logging failure fails
    /// the whole operation so the feed never silently misses a committed
    /// write".
    /// That claim was false in both directions.
    /// `complete_upload` and `delete_file` committed first and announced
    /// last, and nothing rolled back.
    /// A WAL failure therefore lost the mutation and the session or row
    /// that the retry needed.
    ///
    /// These points hold now, and each mutation is written to keep them:
    ///
    /// * The engine announces before the step that makes a mutation
    ///   impossible to retry. [`delete_file`](Self::delete_file) announces
    ///   before the row goes, as [`gc`] does. The engine also announces
    ///   immediately after the step, and it leaves the handle for the retry
    ///   on purpose.
    ///   [`complete_upload`](Self::complete_upload) commits the record,
    ///   announces, and only then drops the session.
    /// * Every announce failure therefore leaves something that a *later
    ///   request* can replay it from. Every entry point is idempotent on
    ///   that retry, so the retry converges instead of returning 404.
    /// * The code announces a failed append again at most once per
    ///   failure, because the cleanup of the retry removes the handle. A
    ///   client that repeats `complete` cannot grow the feed.
    ///
    /// This contract does NOT give one thing.
    /// A client that never retries loses the announce for good.
    /// The committed record is on the master, so a replica that runs a full
    /// rebuild finds the file in the KV.
    /// Incremental replay does not find the file.
    /// The engine logs that window, and does not close it.
    /// Closing the window needs a replayable outbox, and this crate has no
    /// storage for one.
    ///
    /// The method takes a trait object, so this module never names `sync`.
    /// The concrete implementation is
    /// [`sync::wal::Wal`](crate::sync::wal::Wal).
    pub fn with_change_sink(mut self, feed: Arc<dyn ChangeSink>) -> Self {
        self.feed = Some(feed);
        self
    }

    /// Announces `op` when a feed is wired. The call does nothing otherwise.
    async fn announce(&self, op: WalOp) -> Result<(), FsError> {
        if let Some(feed) = &self.feed {
            feed.append(op).await.map_err(feed_error)?;
        }
        Ok(())
    }

    /// Creates an engine from an explicit [`FsStore`] and [`S3Client`].
    ///
    /// The method is the injection point for the `S3Client` contract,
    /// which keeps `FsEngine` independent of the storage type.
    /// Production goes through [`init`](Self::init).
    /// A host app or a test uses this method to supply another byte backend
    /// or another metadata store.
    /// The caller sets [`with_change_sink`](Self::with_change_sink) and
    /// [`with_token_keys`](Self::with_token_keys) separately, as `init`
    /// also does.
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

    /// Sets the signing keys for the capability tokens.
    /// Production sets the configured secret.
    /// A test keeps the ephemeral default.
    pub fn with_token_keys(mut self, keys: TokenKeys) -> Self {
        self.token_keys = Arc::new(keys);
        self
    }

    /// Mints a capability token for `file_id` and `act`.
    pub fn mint_token(&self, sub: &str, file_id: &str, act: Action) -> Result<String, FsError> {
        self.token_keys.mint(sub, file_id, act)
    }

    /// Verifies a capability token.
    pub fn verify_token(&self, token: &str, file_id: &str, act: Action) -> Result<(), FsError> {
        self.token_keys.verify(token, file_id, act)
    }

    /// Attach a file to a row. The caller must have `Write` on the row.
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
        // The file must exist.
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

    /// Detach a file from a row. The caller must have `Write` on the row.
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
        let rows = self.store.rows_for_file(file_id).await?;
        if rows.is_empty() {
            // A file with no reference is a temp upload.
            // The temp model gives the file to its owner.
            // The doc of `delete_file` and its `info.count == 0` check both
            // say so.
            // Ownership is therefore the WHOLE answer in this branch, as it
            // has always been.
            return Ok(rec.owner_sub == caller_sub);
        }
        // The ROW policy governs a file that is attached to rows.
        // The policy governs the user who uploaded the file as well.
        // If the code returned early on ownership before this loop, an
        // uploader could Read or Delete a file on a row with no grant.
        // An owner who attached a file to a shared row would then lose the
        // ability to remove the file.
        // A user who received no grant would lose the ability to read the
        // file.
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
        // The engine cannot allocate before it touches S3, because it
        // creates the multipart upload first.
        // The code therefore builds the slot vectors in a way that can fail.
        // A failure here must become a 4xx, and must not take the process
        // down.
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
        // The engine stores the S3 state with the session.
        // After a restart, the client RAM map is empty.
        // Only this record can load the backend upload, or abort it.
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

    /// Stores one chunk. Only the owner of the session may write.
    ///
    /// The body arrives as a chunk stream.
    /// The stream stops at the expected part size of the session.
    /// A body that is too large ends with 413 in the middle of the stream,
    /// and the code does not buffer it to the end.
    /// A declared `Content-Length` that does not match is rejected before
    /// the code reads the first chunk.
    /// The code buffers the part once, because S3 SigV4 must hash the whole
    /// part before it sends it.
    /// The S3 protocol therefore blocks uploads with no buffer.
    /// The bound is now the part size, which is at most 10 MiB by init
    /// validation, and not the 16 MiB cap for all bodies.
    ///
    /// The engine merges the two rows of the session under the lock *after*
    /// it stages the bytes, and never before.
    /// The body stream and the S3 round trip are the slow parts, and both
    /// are per part.
    /// Holding the lock across them would make the parallel part uploads of
    /// one client wait for each other.
    /// That pattern is the reason for this lock.
    /// Everything that can lose an entry is in the merge
    /// (`merge_part`).
    /// The merge reads the rows again under the lock, and does not trust
    /// the copy that the caller read.
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
        // The code sets no `Send` bound.
        // The actix `Payload` is `!Send`, because the h1 body is
        // thread-local, and the handlers run on the worker arbiter.
        // The intake future therefore stays thread-local, as the `Bytes`
        // extractor did.
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
        // The ceiling matches the HTTP payload cap.
        // The old `Bytes` extractor rejected anything above the cap, and a
        // part size above it was never uploadable.
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

    /// Adds one uploaded part to the session row and to the durable multipart
    /// record. The engine holds the lock of the session.
    ///
    /// Everything that can lose the entry of a concurrent part is here.
    /// The session and the record are separate KV keys.
    /// A merge that wrote only one of them dropped a part that the client
    /// already knew was uploaded.
    /// A merge that read them at a different moment from the sibling that
    /// ran at the same time dropped a part too.
    ///
    /// The engine reads the session again under the lock.
    /// The engine does not use the copy from the caller.
    /// The caller took that copy before it read the body and before the S3
    /// round trip.
    /// The size and bounds checks still ran against that copy.
    /// Those checks are sound because `file_size`, `part_size`, and
    /// `file_total_parts` are fixed at init, and the id is a new uuid.
    /// No other request can then resize the session.
    /// The read under the lock checks the index and the owner again.
    ///
    /// The engine writes the record FIRST.
    /// A crash between the two keys must then leave the session short of
    /// one etag, and never the record short of one part.
    /// A session that is short of an etag returns a 400 "not all parts
    /// uploaded".
    /// The client repairs that by uploading again the part that
    /// `GET /fs/uploads/{id}` shows as missing.
    /// A record that is short of one part gives "etag count N != part count
    /// N-1", which no client can clear.
    /// Every response that the client can see shows the upload as complete.
    /// The engine uses the same order as `FsStore::delete_session`, which
    /// deletes the cascade rows before the row that reaches them.
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
        // The engine copies the staged content ids into the durable
        // record, so that a restarted client can complete the upload.
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

    /// Loads the multipart state of the client from the durable record.
    ///
    /// A session from before the store added persistence has no record.
    /// A session whose init crashed between the session write and the
    /// record write also has no record.
    /// The backend upload of such a session cannot be addressed.
    /// The caller then gets a clear restart signal, and not an unclear
    /// `unknown upload_id`.
    async fn ensure_multipart(&self, upload_id: &str) -> Result<(), FsError> {
        let Some(record) = self.store.load_multipart(upload_id).await? else {
            return Err(FsError::BadRequest(
                "multipart state unavailable (restarted server or expired session); start a new upload"
                    .into(),
            ));
        };
        self.s3.restore_multipart(&record).await
    }

    /// Aborts the S3 side of an expired session or of an abandoned session.
    ///
    /// `NotFound` from S3 means that the upload is already gone.
    /// It was aborted, completed, or a restart gave a new InMemory backend.
    /// For GC that is a success.
    /// Any other failure passes to the caller, so that the session stays
    /// for a retry.
    /// This also stops the leak of staged bytes that no record points at.
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
            // The session is from before the store added persistence.
            // The backend upload cannot be addressed, and the staged parts
            // cannot be reached.
            // The engine warns, and then lets the session go.
            // A later sweeper that lists the S3 multipart uploads can
            // reclaim these parts.
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

    /// Finalizes an upload session. Only the owner may complete it.
    ///
    /// The method is idempotent for the client.
    /// A retry after a failed announce finds the committed record and the
    /// session that the failure left behind.
    /// The method announces again, and the retry converges.
    /// See [`with_change_sink`](Self::with_change_sink) for what this
    /// guarantees.
    #[tracing::instrument(skip(self, req), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn complete_upload(
        &self,
        file_id: &str,
        req: CompleteRequest,
        caller_sub: &str,
    ) -> Result<(), FsError> {
        // The engine holds the lock across the whole completion, and
        // the S3 round trip too.
        // A complete that runs at the same time as a part upload loses a
        // write in the same way as two parts that run at the same time.
        // Unlike two parts, a complete and a part upload are not the normal
        // pattern of a client.
        // The lock is per session, so it costs nothing to a client that
        // uploads several files at once.
        let session_lock = self.session_locks.acquire(file_id).await;
        let _held = session_lock.acquire().await;
        // The engine reads the record first, because the record is the
        // committed half.
        // A session that outlived its own commit is the handle for the
        // retry.
        // A record with no session is an upload that already converged.
        let committed = self.store.get_file(file_id).await?;
        let session = self.store.get_session(file_id).await?;
        if let Some(rec) = &committed {
            if rec.owner_sub != caller_sub {
                return Err(FsError::Forbidden);
            }
            let Some(_session) = session else {
                // An earlier attempt announced the op and cleaned up.
                // Only this module drops the session.
                // It drops the session only after the append returns.
                // There is then nothing left to announce.
                // The method returns success WITHOUT an append.
                // That is what stops a client that repeats `complete` on one
                // file id from growing the feed.
                return Ok(());
            };
            // The record is committed and the session is still there, so the
            // announce, or the cleanup after it, failed.
            // The method announces again from the committed record, which is
            // the exact op that was lost.
            // The method then drops the handle, so that the bound also holds
            // for the next retry.
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
            // The engine deletes the durable record with the
            // completed upload.
            // The session delete below is then a backup for that delete.
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
        // The engine commits, then announces, and only then releases
        // the retry handle.
        // The old order deleted the session before the append.
        // An append that then failed left a committed file with no session
        // and no op.
        // The retry of the client returned 404 on `get_session`.
        // Each replica that applies the feed incrementally never learned
        // that the file exists.
        self.store.save_file(&record).await?;
        self.announce(WalOp::FileCreate { rec: record }).await?;
        self.store.delete_session(file_id).await?;
        Ok(())
    }

    /// Aborts a multipart upload. Only the owner may cancel it.
    ///
    /// The engine aborts in S3 before it deletes the session.
    /// A failed abort, other than an upload that is already gone, fails the
    /// cancel.
    /// The session then stays, and GC retries it.
    /// This stops the leak of staged parts that no record points at.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn cancel_upload(&self, file_id: &str, caller_sub: &str) -> Result<(), FsError> {
        // The engine takes the same lock as for the completion.
        // A cancel that runs at the same time as the merge of a part upload
        // would let the merge write the session back.
        // That would bring back an upload whose S3 side is gone.
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

    /// Returns the file metadata. The caller must own the temp file, or the
    /// caller must have access to the row.
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

    /// Deletes a finalized file.
    /// The caller must have `Delete` on the row, or the caller must own the
    /// unreferenced temp file.
    ///
    /// The engine announces FIRST, for the same reason as [`gc`].
    /// `gc` announces before it deletes the row.
    /// The row is the only thing left that knows that this deletion still
    /// needs an announce.
    /// A failed append must therefore keep it.
    /// The old order deleted the row and the bytes, and announced last.
    /// A WAL failure then turned into a 500.
    /// The retry of that 500 returned 404, because `get_file` gave `None`.
    /// Each replica kept serving a record for bytes that were already gone,
    /// and nothing announced the delete again.
    ///
    /// The engine deletes the metadata before the S3 bytes.
    /// A failure between the two deletes leaks an object that no row
    /// reaches, and the orphan pass of gc deletes it after the TTL.
    /// The other order would leave a record that returns 404 for every
    /// download.
    /// A retry of that case finds no row and returns 404.
    /// That is why the bytes are last.
    #[tracing::instrument(skip(self), fields(file_id = %file_id, caller_sub = %caller_sub), err)]
    pub async fn delete_file(&self, file_id: &str, caller_sub: &str) -> Result<(), FsError> {
        let rec = self
            .store
            .get_file(file_id)
            .await?
            .ok_or_else(|| FsError::NotFound("file not found".into()))?;
        // The caller can delete an unreferenced temp file that the
        // caller owns.
        let info = self.store.get_ref_info(file_id).await?;
        if info.count == 0 {
            if rec.owner_sub != caller_sub {
                return Err(FsError::Forbidden);
            }
        } else if !self.can_access(caller_sub, file_id, Action::Delete).await? {
            return Err(FsError::Forbidden);
        }
        // The engine announces before the row goes, and not after.
        // A failed append then leaves the row.
        // The retry of the client runs this whole authorized path again and
        // converges.
        // An announce again costs nothing.
        // On the replica, replaying `FileDelete` is a `delete_file`, and it
        // is idempotent for a file that is already gone.
        //
        // The code deliberately does NOT extend this to "no record means
        // already deleted, announce anyway".
        // That change would turn every 404 into a permanent feed entry.
        // The feed is append-only, and it has nothing to check the request
        // against once the record is gone.
        self.announce(WalOp::FileDelete {
            file_id: file_id.to_string(),
        })
        .await?;
        self.store.delete_file(file_id).await?;
        self.s3.delete_object(&self.bucket, &rec.s3_key).await?;
        Ok(())
    }

    /// Streams a file body. The caller must have `Read` on the row, or own
    /// the temp file.
    ///
    /// The chunks go straight from the object store to the response.
    /// The engine never buffers the whole body, so a file of any size
    /// downloads with the same memory use.
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

    /// Streams one absolute byte range of a file that the caller may read.
    /// The `end` value is not part of the range.
    ///
    /// The auth check and the metadata size come from the same checks as
    /// [`FsEngine::get_object`].
    /// A size never changes after the completion, so the engine clamps the
    /// range as a safety measure.
    /// The routes then return 416 from metadata that they already hold.
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

    /// Returns upload progress. Only the owner may poll.
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

    /// The engine and the policy handle that can write rules.
    ///
    /// `FsEngine` only holds an `Authorizer`.
    /// A test that must grant a rule therefore has to keep the engine that
    /// created the rule.
    /// That is the point of the narrower field, and not a workaround.
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

    /// Wraps one buffered part as the chunk stream that the engine now takes.
    fn once_body(body: Vec<u8>) -> impl futures_util::Stream<Item = Result<Bytes, FsError>> {
        futures_util::stream::once(async move { Ok(Bytes::from(body)) })
    }

    /// Creates an engine over an explicit byte backend.
    /// A test that must control when the backend answers uses this
    /// helper.
    async fn engine_with_s3(sub: &str, s3: Arc<dyn S3Client>) -> FsEngine {
        let prefix = format!("{}-{sub}", crate::db::test_prefix("fs-engine"));
        let store = FsStore::primary(crate::db::build_test_store(&prefix).await);
        let policy_prefix = format!("{prefix}-policy");
        let policy = PolicyEngine::init_s3(crate::db::build_test_store(&policy_prefix).await)
            .await
            .unwrap();
        FsEngine::from_parts(store, s3, "test-bucket".to_string(), policy.authorizer())
    }

    /// An [`S3Client`] that parks ONE chosen `upload_part` until the test
    /// releases it.
    ///
    /// Every other call goes to a real in-memory backend, so
    /// `complete_upload` really assembles the object.
    /// The code controls only WHEN one part upload reaches the backend.
    /// That control makes the interleaving a regression test, and not a
    /// race that the scheduler must lose.
    /// The parked part is inside the backend call, while the other parts run
    /// their whole read, merge, and write.
    struct GateS3 {
        inner: Arc<dyn S3Client>,
        /// The part number to park, counted from 1.
        /// It must be the LAST part, because the in-memory backend accepts
        /// only parts in ascending order.
        gate_part: i32,
        parked: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Arc<tokio::sync::Notify>,
    }

    impl GateS3 {
        /// Returns the client, the signal that fires inside the `gate_part`
        /// upload to show that it is parked, and the handle that releases
        /// it.
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
    /// Nothing held the read-modify-write.
    /// `FsStore` takes `inner.write()` for each call, and `FsEngine` is
    /// shared across the workers as `web::Data`.
    /// Parallel part upload is the normal pattern of a multipart client.
    /// Part 1 then wrote back the session that it read before the save of
    /// part 0, and that dropped the etag of part 0.
    /// `GET /fs/uploads/{id}` reported the part as never uploaded, although
    /// the bytes were staged.
    ///
    /// A worse interleaving dropped only the RECORD.
    /// Both session etags were then present, and the record was short of one
    /// part.
    /// `complete_upload` passed its `any(is_none)` check, and then failed in
    /// the backend with "etag count 2 != part count 1".
    /// No client response reports that failure, and no retry can clear it.
    ///
    /// The test is deterministic by construction.
    /// Part 0 is parked inside the backend call, and part 1 runs from start
    /// to finish.
    /// The sibling that must interleave therefore always interleaves.
    /// Before the fix, the stale copy of part 1 was written back over the
    /// etag of part 0, and the session was left `[Some, None]`.
    #[tokio::test]
    async fn concurrent_part_uploads_keep_every_etag_and_record_part() -> anyhow::Result<()> {
        const PARTS: u64 = 3;
        // The LAST part is parked.
        // The parts must reach the backend in ascending order.
        // The parked part must therefore be the one whose siblings ran
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

        // The last part is parked inside the backend, and the earlier
        // two parts run their whole read, merge, and write while it waits.
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

        // The whole point of the test: an upload whose client was told
        // that every part is present must really complete.
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

    /// The end-to-end version of the test for the allocation abort.
    /// The abusive body must return a 4xx, and must not take the process
    /// with it.
    /// Running this test against the engine before the fix stopped the test
    /// binary, and that failure is the one that the test guards.
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

    /// The engine builds the slot vectors in a way that can fail, so an
    /// absurd count returns a 4xx.
    /// That is true even if a caller skips the validation or raises the
    /// cap by mistake.
    #[test]
    fn part_slots_never_aborts() {
        // This value is valid. It is exactly the S3 limit.
        assert_eq!(
            part_slots(model::MAX_MULTIPART_PARTS).unwrap().len(),
            10_000
        );
        // This value breaks the cap, and it is reachable only if a caller
        // skips the validation.
        // The function must return an error, and must not try the
        // allocation.
        let err = part_slots(u64::MAX).expect_err("u64::MAX must not allocate");
        assert!(matches!(err, FsError::BadRequest(_)), "got {err:?}");
        // The failure message must not tell the client about the memory
        // state.
        assert!(!err.to_string().contains("memory"), "leaks: {err}");
    }

    #[tokio::test]
    async fn temp_upload_owned_by_caller() -> anyhow::Result<()> {
        let engine = make_engine("alice").await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        // The subject bob cannot write the session of alice.
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
        // No row permission gives a forbidden error.
        assert!(engine.attach("invoice", "123", &id, "alice").await.is_err());
        // The test grants write on invoice:123 to alice.
        policy
            .add_rule("alice".into(), "invoice:123".into(), Action::Write)
            .await
            .unwrap();
        assert_eq!(engine.attach("invoice", "123", &id, "alice").await?, 1);
        // The second attach is idempotent.
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
        // The subject bob cannot read the temp file of alice.
        assert!(engine.get_metadata(&id, "bob").await.is_err());
        // The test grants read on the row to bob.
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

    /// `can_access` is the only FS call site that uses `authorize_row` and
    /// not `require_row`.
    /// It is therefore the one path that the narrower field could break
    /// without an error.
    /// The trait impl that it resolves against moved when `policy` became
    /// an `Authorizer`.
    ///
    /// The test checks a denial as carefully as it checks a grant.
    /// A delegation error that resolved to a default that allows access
    /// would still return `true` for the granted subject.
    /// Only the granted check would then find nothing wrong.
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

        // A linked row with no rule for bob denies the access. It does not
        // return an error.
        assert!(!engine.can_access("bob", &id, Action::Read).await?);

        policy
            .add_rule("bob".into(), "invoice:123".into(), Action::Read)
            .await
            .unwrap();
        assert!(engine.can_access("bob", &id, Action::Read).await?);
        // Read on the row is not write on the row. The action is part of the
        // key.
        assert!(!engine.can_access("bob", &id, Action::Delete).await?);

        // The OWNER is subject to the row policy now, like every other
        // subject.
        // Alice holds Write on invoice:123, and not Delete.
        // Alice therefore cannot remove a file attached to that row.
        // This assertion used to read "the owner always reaches their own
        // file, whatever policy says".
        // That reading was the bug, because it let an uploader delete a
        // file that another user used through a row that the uploader
        // controls.
        assert!(!engine.can_access("alice", &id, Action::Delete).await?);
        assert!(engine.can_access("alice", &id, Action::Write).await?);
        // The test also sees a policy change that comes later.
        // This is true only because the handle shares the engine, and does
        // not copy it.
        policy
            .remove_rule("bob".into(), "invoice:123".into(), Action::Read)
            .await
            .unwrap();
        assert!(!engine.can_access("bob", &id, Action::Read).await?);
        Ok(())
    }

    /// Ownership still answers for an UNREFERENCED file.
    /// That is the temp upload model, and it is the only place where
    /// ownership grants access.
    ///
    /// The narrower check in `can_access` must not remove that.
    /// `init_upload`, `upload_part`, and `complete_upload` together produce
    /// a file that is attached to no row.
    /// Its owner must then read and delete the file with no policy grant.
    #[tokio::test]
    async fn the_owner_reaches_their_own_unreferenced_temp_file() -> anyhow::Result<()> {
        let (engine, _policy) = make_engine_and_policy("alice").await;
        let id = engine.init_upload(valid_single(), "alice").await?;
        engine
            .upload_part(&id, 0, once_body(vec![9u8; 1024]), None, None, "alice")
            .await?;
        engine
            .complete_upload(
                &id,
                CompleteRequest {
                    name: "scratch.txt".into(),
                    mimetype: "text/plain".into(),
                },
                "alice",
            )
            .await?;

        // The file has no rows, so ownership is the whole answer.
        assert!(engine.can_access("alice", &id, Action::Read).await?);
        assert!(engine.can_access("alice", &id, Action::Delete).await?);
        // The file is still available to its owner only, and not to every
        // subject.
        assert!(!engine.can_access("bob", &id, Action::Read).await?);
        assert!(!engine.can_access("bob", &id, Action::Delete).await?);
        Ok(())
    }

    /// `FsEngine` holds the read-only handle, and not the engine that can
    /// write rules.
    ///
    /// Every production use of the field is `require_row` or
    /// `authorize_row`.
    /// A whole engine gives `fs` a grant that `fs` does not need and
    /// should not have.
    /// `fs` has no change feed for policy mutations.
    /// A rule added through it would reach the replicas with no WAL op to
    /// replay.
    /// The test checks the type of the field, because that is the only way
    /// to keep this true.
    /// Every test of behaviour in this file passes either way, because the
    /// handle and the engine agree.
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

        // The crate also has exactly one `RowAuthorizer` impl, and that
        // impl is for this handle.
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
        // The test sends 1 KiB chunks with no end, against a part of
        // 1 KiB.
        // The intake must then return 413 after the second chunk.
        // The intake must not buffer for ever.
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
        // The flag records whether the stream was polled at all.
        // A declared length that does not match must fail before the first
        // poll.
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
        // A declared length that is larger than expected returns 413, and not
        // 400.
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
    async fn mint_token_then_verify_token() -> anyhow::Result<()> {
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

    /// A [`ChangeSink`] test double that refuses every append.
    ///
    /// It stands for the one failure that both fixes here guard against.
    /// The mutation commits, and the feed does not take it.
    struct DeadFeed;

    #[async_trait::async_trait]
    impl crate::records::ChangeSink for DeadFeed {
        async fn append(&self, _: crate::records::WalOp) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("feed down"))
        }
    }

    /// A complete that committed but could not announce must be repairable
    /// by the retry of the client.
    /// Only the retry can repair it.
    ///
    /// The old order was `save_file`, `delete_session`, `announce`.
    /// A WAL failure at the announce returned 500, and the record was
    /// COMMITTED on the master.
    /// The retry of the client then read `get_session` as `None`.
    /// It returned 404 "upload session not found" for good.
    /// The file was then available on the master.
    /// Each replica that applies the feed incrementally never learned that
    /// the file exists.
    /// No other code path announces a `FileCreate` again.
    ///
    /// An assertion that the first call returns 500 proves none of this.
    /// The test therefore drives the retry, which is where the loss
    /// happened.
    /// The retry must converge, and the lost op must reach the feed.
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

        // The record is committed, and the session is still there on
        // purpose.
        // That session is the handle from which the retry announces again.
        assert!(
            engine.store.get_file(&id).await?.is_some(),
            "the record did not commit, so this test is not exercising the window"
        );
        assert!(
            engine.store.get_session(&id).await?.is_some(),
            "the session must survive a failed announce, or the retry has nothing to converge on"
        );

        // The feed is then repaired. The client retries, and this time the
        // retry converges.
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

        // The number of announces is bounded. The retry used the handle.
        // A client that repeats `complete` cannot append for ever against an
        // upload that converged.
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

        // The file is the one that was committed, and not a new upload.
        assert_eq!(engine.get_metadata(&id, "alice").await?.name, "retry.txt");
        Ok(())
    }

    /// A delete that could not announce must leave the row for the retry.
    ///
    /// The old order was `delete_file`, `s3.delete_object`, `announce`.
    /// A WAL failure at the announce returned 500, and the row was GONE.
    /// The retry then read `get_file` as `None` and returned 404.
    /// Each replica kept serving a record for bytes that were already
    /// deleted.
    /// That is the same stranding that gc fixed in a4e40f9, one layer up.
    ///
    /// The assertion that the row survives the failed announce is what
    /// tells the two orders apart.
    /// The assertion that the retry converges is the part that matters to
    /// the client.
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

        // The feed is then repaired. The retry of the client runs the
        // authorized path again.
        engine.delete_file(&id, "alice").await?;
        assert!(engine.store.get_file(&id).await?.is_none());
        let entries = wal.range(1, wal.head().await?).await?;
        assert_eq!(entries.len(), 2, "expected the create and one delete");
        assert!(
            matches!(&entries[1].op, WalOp::FileDelete { file_id } if file_id == &id),
            "the retry announced something else: {:?}",
            entries[1].op
        );

        // An id that never existed still returns 404 and appends nothing.
        // The feed is append-only.
        // Every 404 that became a `FileDelete` would grow the feed for
        // ever, and any caller with a token could force that growth.
        let err = engine
            .delete_file("never-existed", "alice")
            .await
            .expect_err("an unknown file id must stay a 404");
        assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
        assert_eq!(wal.head().await?, 2, "a 404 appended to the feed");
        Ok(())
    }
}
