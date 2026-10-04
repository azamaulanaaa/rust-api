//! GC for abandoned uploads and orphaned files.
//!
//! Sessions and temp/orphaned files older than 24h are removed.
//! Expired files are announced to the change feed (when the engine has a
//! sink wired) so replicas replay the deletion instead of keeping stale
//! copies.

use std::{collections::HashSet, sync::Arc, time::Duration};

use tokio::time::interval;

use crate::fs::FsEngine;
use crate::fs::store::RecordScan;

/// Object prefix holding file bytes (`UploadSession`/`FileRecord` keys
/// are `files/{id}`); the orphan-byte pass lists exactly this scope so
/// oxkv prefixes sharing the bucket are never touched.
const FILE_BYTES_PREFIX: &str = "files/";

/// TTL for abandoned sessions and orphaned files.
pub const TTL_SECS: i64 = 24 * 3600;

/// Spawn sweeper that runs every hour.
pub fn spawn(engine: Arc<FsEngine>) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            if let Err(e) = sweep_once(&engine).await {
                tracing::warn!("fs gc sweep failed: {e}");
            }
        }
    });
}

/// Single sweep: sessions, orphaned files, and orphan S3 bytes.
///
/// The session pass runs under the SAME per-session lock that
/// `merge_part` and `complete_upload` take, and re-reads each row under it.
/// The listing is a snapshot taken before the loop starts, so on its own it
/// says nothing about what the row holds by the time the sweeper reaches it
/// -- see the note inside the loop.
#[tracing::instrument(skip(engine), err)]
pub async fn sweep_once(engine: &FsEngine) -> Result<usize, crate::fs::error::FsError> {
    let now = chrono::Utc::now().timestamp();
    let mut cleaned = 0;

    let RecordScan {
        records: sessions,
        undecodable: unread_sessions,
    } = engine.store.list_sessions().await?;
    let RecordScan {
        records: files,
        undecodable: unread_files,
    } = engine.store.list_files().await?;

    // sessions
    for listed in &sessions {
        // The lock the upload path already uses for this session's rows.
        // Taking it here is what makes the sweeper a fourth serialized
        // writer rather than a fifth racy one: `merge_part` re-reads the
        // session under this lock and writes the copy back, so a sweep that
        // does not take it can land between that read and that write.
        //
        // The failure that produced is not a lost update, it is a destroyed
        // file. A client opens a session and stalls; nothing refreshes
        // `created_at`, so after the TTL the sweep considers it expired.
        // The client resumes and `upload_part` PUTs the bytes, then folds
        // them into the row. If the sweep's `delete_object` and
        // `delete_session` land inside that fold, the write resurrects the
        // row with the etag set -- and `complete_upload` then takes the
        // single-part branch, skips the multipart block (there is no S3
        // upload to complete, the object was already deleted), and commits
        // `save_file` -> `announce` -> `delete_session` and returns `Ok`.
        // The file is in the feed and answers `GET /fs/{id}`; every
        // download 404s forever, because the bytes went in the sweep and
        // nothing anywhere looks for a record whose object is missing.
        //
        // Under this lock the two orderings are the only ones left. Sweep
        // first: the row goes, so the fold re-reads `None` and the client
        // gets a 404 -- the bytes it wrote are unreferenced and the
        // orphan-byte pass reaps them. Fold first: the row is written, and
        // this pass deletes it moments later, so there is still no record
        // for `complete_upload` to commit. Neither ends with a file whose
        // bytes are gone.
        //
        // Declaration order matters and matches the call sites: the guard
        // is dropped before the claim is released, so a new claim can never
        // mint a second mutex while this guard is still live.
        let session_lock = engine.session_locks.acquire(&listed.id).await;
        let _held = session_lock.acquire().await;
        // Re-read under the lock rather than trusting the listing. A
        // session listed here may since have been completed -- which saves
        // the file record pointing at exactly these bytes -- or cancelled,
        // in which case deleting on the stale copy would reap a live
        // file's bytes and leave the same permanently-404 record this lock
        // exists to prevent.
        let Some(s) = engine.store.get_session(&listed.id).await? else {
            tracing::debug!("fs gc skipping upload {}: no longer a session", listed.id);
            continue;
        };
        if !s.is_expired(now, TTL_SECS) {
            continue;
        }
        tracing::info!(
            "fs gc expiring upload {} (age {}s)",
            s.id,
            now - s.created_at
        );
        // S3 first via the engine (restores post-restart state, tolerates
        // already-gone): on failure the session is kept so the next
        // sweep retries instead of leaking bytes no record points at.
        if engine.abort_session_upload(&s).await.is_err() {
            tracing::warn!("fs gc keeping upload {} for retry", s.id);
            continue;
        }
        engine.store.delete_session(&s.id).await?;
        cleaned += 1;
    }

    // orphaned / temp files
    for f in &files {
        // One unreadable row costs one file, not the sweep. The order is
        // sessions, then files, then orphan bytes, so propagating here
        // would strand every file listed after this one and skip the
        // orphan pass entirely -- on every subsequent sweep, because
        // nothing in the sweeper repairs the key. The result is an
        // unbounded leak of expired sessions, orphaned rows and orphan
        // bytes, with one `warn!` an hour as the only sign.
        //
        // This is the same call the sibling branch below already declines
        // to propagate, for the same reason: one bad item is retained and
        // the sweep continues. Retaining is also the safe direction here.
        // The orphan-byte pass keys off `f.s3_key`, which this row does
        // not affect, so skipping the file leaks it rather than losing it.
        let info = match engine.store.get_ref_info(&f.id).await {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("fs gc skipping file {}: ref-count unreadable: {e}", f.id);
                continue;
            }
        };
        if info.count != 0 {
            continue;
        }
        let age = info.orphan_since.unwrap_or(f.created_at);
        if now - age <= TTL_SECS {
            continue;
        }
        tracing::info!("fs gc expiring file {} (age {}s)", f.id, now - age);
        // Same retain-on-failure contract as sessions above. Age is measured
        // from `orphan_since` when the file was attached and later detached,
        // falling back to `created_at` for a file that was never referenced;
        // unlike a session there is no record method to delegate to, since
        // the timestamp lives on `RefInfo`, not on `FileRecord`.
        if engine
            .s3
            .delete_object(&engine.bucket, &f.s3_key)
            .await
            .map_err(|e| {
                tracing::warn!("gc delete {} failed: {e}", f.id);
                e
            })
            .is_err()
        {
            tracing::warn!("fs gc keeping file {} for retry", f.id);
            continue;
        }
        // Announce *before* the row goes, not after. The row is the only
        // record that this deletion still has to happen: once it is gone
        // no future sweep can find the file to re-announce, so a failed
        // append here strands every replica's copy for good -- the master
        // has no row, the replica has the record and the bytes, and no
        // later replay repairs either. Announced first, the same transient
        // failure leaves the row in place and the next sweep announces
        // again. Re-announcing is free of consequence: replaying
        // `FileDelete` is a `delete_file` on the replica, which is
        // idempotent on a file that is already gone.
        //
        // A failed announce retains the file rather than propagating. The
        // bytes are already gone at this point, so propagating would leave
        // exactly the unretryable state described above, and would abort
        // the rest of the sweep over one file.
        if let Err(e) = engine
            .announce(crate::records::WalOp::FileDelete {
                file_id: f.id.clone(),
            })
            .await
        {
            tracing::warn!(
                "fs gc keeping file {} for retry: announce failed: {e}",
                f.id
            );
            continue;
        }
        engine.store.delete_file(&f.id).await?;
        cleaned += 1;
    }

    // orphan S3 bytes: listed keys no session or file record references.
    // Crash windows between byte and metadata writes strand such keys;
    // only reap them past the TTL so in-flight uploads always survive.
    //
    // The liveness set below is built from the two scans above, so a row
    // either of them could not decode is a key whose bytes *look*
    // unreferenced when they are not -- the delete is irreversible and the
    // metadata row stays put, so every later download of that file 404s
    // forever. Proving a key unreferenced needs a complete scan, so an
    // incomplete one skips the whole pass: leaking the bytes costs
    // storage, taking them costs the file.
    let unread = unread_sessions.len() + unread_files.len();
    if unread > 0 {
        tracing::warn!(
            "fs gc skipping orphan-byte pass: {unread} metadata rows did not decode, so an \
             unreferenced key cannot be proven unreferenced"
        );
    } else {
        let mut live: HashSet<&str> = HashSet::new();
        for s in &sessions {
            live.insert(s.s3_key.as_str());
        }
        for f in &files {
            live.insert(f.s3_key.as_str());
        }
        // A listing failure skips just this pass (metadata work above stands).
        let listed = match engine.s3.list_keys(&engine.bucket, FILE_BYTES_PREFIX).await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::warn!("fs gc orphan-byte listing failed: {e}; skipping pass");
                Vec::new()
            }
        };
        for entry in listed {
            if live.contains(entry.key.as_str()) || now - entry.last_modified <= TTL_SECS {
                continue;
            }
            tracing::info!("fs gc expiring orphan bytes {}", entry.key);
            if engine
                .s3
                .delete_object(&engine.bucket, &entry.key)
                .await
                .map_err(|e| {
                    tracing::warn!("gc delete {} failed: {e}", entry.key);
                    e
                })
                .is_err()
            {
                tracing::warn!("fs gc keeping orphan bytes {} for retry", entry.key);
                continue;
            }
            cleaned += 1;
        }
    }

    if cleaned > 0 {
        tracing::info!("fs gc cleaned {cleaned} items");
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::db::build_test_store;
    use crate::fs::FsEngine;
    use crate::fs::error::FsError;
    use crate::fs::object_store::ObjectStoreClient;
    use crate::fs::s3::ListedKey;
    use crate::fs::s3::S3Client;
    use crate::fs::store::{FileRecord, FsStore, PersistedMultipart, UploadSession};
    use crate::policy::PolicyEngine;
    use bytes::Bytes;
    use tracing_subscriber::layer::SubscriberExt as _;

    async fn make_engine() -> FsEngine {
        let prefix = crate::db::test_prefix("gc");
        let store = FsStore::new(build_test_store(&prefix).await);
        let policy_store = build_test_store(&format!("{prefix}-policy")).await;
        let policy = PolicyEngine::init_s3(policy_store).await.unwrap();
        let s3 = ObjectStoreClient::in_memory();
        FsEngine::from_parts(store, s3, "test-bucket".into(), policy.authorizer())
    }

    fn session_with_age(id: &str, age_secs: i64, multipart: bool) -> UploadSession {
        UploadSession {
            id: id.to_string(),
            file_size: 1024,
            part_size: 1024,
            file_total_parts: 1,
            s3_upload_id: if multipart {
                Some(format!("upload-{id}"))
            } else {
                None
            },
            s3_key: format!("files/{id}"),
            owner_sub: "alice".into(),
            created_at: chrono::Utc::now().timestamp() - age_secs,
            etags: vec![None],
            checksums: vec![None],
        }
    }

    /// Wraps one buffered part as the chunk stream the engine now takes.
    fn once_body(body: Vec<u8>) -> impl futures_util::Stream<Item = Result<Bytes, FsError>> {
        futures_util::stream::once(async move { Ok(Bytes::from(body)) })
    }

    #[test]
    fn is_expired_boundary() {
        let now = 1_000_000;
        let s = UploadSession {
            id: "x".into(),
            file_size: 1,
            part_size: 1,
            file_total_parts: 1,
            s3_upload_id: None,
            s3_key: "k".into(),
            owner_sub: "o".into(),
            created_at: now - TTL_SECS,
            etags: vec![None],
            checksums: vec![None],
        };
        assert!(!s.is_expired(now, TTL_SECS));
        assert!(s.is_expired(now + 1, TTL_SECS));
    }

    #[tokio::test]
    async fn sweep_cleans_only_expired() -> anyhow::Result<()> {
        let engine = make_engine().await;
        engine
            .store
            .save_session(&session_with_age("fresh", 3600, true))
            .await?;
        engine
            .store
            .save_session(&session_with_age("old-mp", TTL_SECS + 3600, true))
            .await?;
        engine
            .store
            .save_session(&session_with_age("old-single", TTL_SECS + 3600, false))
            .await?;
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 2);
        assert!(engine.store.get_session("fresh").await?.is_some());
        assert!(engine.store.get_session("old-mp").await?.is_none());
        assert!(engine.store.get_session("old-single").await?.is_none());
        assert_eq!(sweep_once(&engine).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn sweep_cleans_orphaned_files() -> anyhow::Result<()> {
        let engine = make_engine().await;
        // fresh temp file stays
        let fresh = FileRecord {
            id: "fresh-file".into(),
            name: "a.txt".into(),
            mimetype: "text/plain".into(),
            size: 10,
            s3_key: "files/fresh-file".into(),
            owner_sub: "alice".into(),
            created_at: chrono::Utc::now().timestamp() - 3600,
        };
        engine.store.save_file(&fresh).await?;
        // old temp (never attached, refs 0, age > TTL)
        let old = FileRecord {
            id: "old-file".into(),
            name: "b.txt".into(),
            mimetype: "text/plain".into(),
            size: 10,
            s3_key: "files/old-file".into(),
            owner_sub: "alice".into(),
            created_at: chrono::Utc::now().timestamp() - TTL_SECS - 3600,
        };
        engine.store.save_file(&old).await?;
        engine
            .s3
            .put_object(
                "test-bucket",
                &old.s3_key,
                Bytes::from_static(b"data"),
                None,
                None,
            )
            .await?;
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 1);
        assert!(engine.store.get_file("fresh-file").await?.is_some());
        assert!(engine.store.get_file("old-file").await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn sweep_logs_orphan_deletes_to_wal() -> anyhow::Result<()> {
        use crate::records::WalOp;
        use crate::sync::wal::Wal;

        let wal = Wal::new(build_test_store(&crate::db::test_prefix("gc-wal")).await);
        let engine = make_engine().await.with_change_sink(Arc::new(wal.clone()));
        let old = FileRecord {
            id: "gc-wal-file".into(),
            name: "b.txt".into(),
            mimetype: "text/plain".into(),
            size: 10,
            s3_key: "files/gc-wal-file".into(),
            owner_sub: "alice".into(),
            created_at: chrono::Utc::now().timestamp() - TTL_SECS - 3600,
        };
        engine.store.save_file(&old).await?;
        assert_eq!(sweep_once(&engine).await?, 1);
        assert_eq!(wal.head().await?, 1);
        let entries = wal.range(1, 1).await?;
        assert!(
            matches!(&entries[0].op, WalOp::FileDelete { file_id } if file_id == "gc-wal-file")
        );
        // Second sweep finds nothing and logs nothing.
        assert_eq!(sweep_once(&engine).await?, 0);
        assert_eq!(wal.head().await?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn sweep_keeps_live_and_fresh_s3_keys() -> anyhow::Result<()> {
        let engine = make_engine().await;
        // Live single-part session: bytes exist, session still open.
        let file_id = engine
            .init_upload(
                crate::fs::model::InitRequest {
                    file_size: 1024,
                    part_size: 1024,
                    file_total_parts: 1,
                },
                "alice",
            )
            .await?;
        engine
            .upload_part(&file_id, 0, once_body(vec![9u8; 1024]), None, None, "alice")
            .await?;
        // Fresh stray bytes (e.g. crash between put and metadata write).
        engine
            .s3
            .put_object(
                "test-bucket",
                "files/stray",
                Bytes::from_static(b"x"),
                None,
                None,
            )
            .await?;

        assert_eq!(sweep_once(&engine).await?, 0);
        assert!(engine.store.get_session(&file_id).await?.is_some());
        assert!(
            engine
                .s3
                .get_object("test-bucket", "files/stray")
                .await
                .is_ok()
        );
        Ok(())
    }

    /// Scriptable [`S3Client`] double: records deletions and returns a
    /// canned listing, so the sweeper's orphan-byte and
    /// retain-on-failure paths can be driven without a real backend.
    ///
    /// One double covers both, because the two tests that need it differ
    /// only in what `list_keys` reports and whether the byte operations
    /// succeed -- and a per-test struct meant re-listing all nine trait
    /// methods every time a method was added to `S3Client`.
    struct FakeS3 {
        listed: Vec<ListedKey>,
        deleted: std::sync::Mutex<Vec<String>>,
        /// When false, `delete_object`/`abort_multipart_upload` fail.
        writes_succeed: bool,
    }

    impl FakeS3 {
        fn new(listed: Vec<ListedKey>, writes_succeed: bool) -> Self {
            Self {
                listed,
                deleted: std::sync::Mutex::new(Vec::new()),
                writes_succeed,
            }
        }

        fn deleted(&self) -> Vec<String> {
            self.deleted.lock().expect("delete log").clone()
        }

        /// Error every byte-mutating call when the double is in failure mode.
        fn write_guard(&self, op: &str) -> Result<(), FsError> {
            if self.writes_succeed {
                Ok(())
            } else {
                Err(FsError::Internal(format!("{op} failed")))
            }
        }
    }

    #[async_trait::async_trait]
    impl S3Client for FakeS3 {
        async fn create_multipart_upload(
            &self,
            _: &str,
            _: &str,
            _: Option<String>,
        ) -> Result<String, FsError> {
            Ok("u".into())
        }
        async fn upload_part(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: i32,
            _: Bytes,
            _: Option<String>,
        ) -> Result<String, FsError> {
            Ok("e".into())
        }
        async fn complete_multipart_upload(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: Vec<String>,
        ) -> Result<(), FsError> {
            Ok(())
        }
        async fn abort_multipart_upload(&self, _: &str, _: &str, _: &str) -> Result<(), FsError> {
            self.write_guard("abort")
        }
        async fn put_object(
            &self,
            _: &str,
            _: &str,
            _: Bytes,
            _: Option<String>,
            _: Option<String>,
        ) -> Result<(), FsError> {
            self.write_guard("put")
        }
        async fn get_object(&self, _: &str, _: &str) -> Result<Bytes, FsError> {
            Err(FsError::NotFound("no".into()))
        }
        async fn delete_object(&self, _: &str, key: &str) -> Result<(), FsError> {
            self.write_guard("delete")?;
            self.deleted
                .lock()
                .expect("delete log")
                .push(key.to_string());
            Ok(())
        }
        async fn list_keys(&self, _: &str, _: &str) -> Result<Vec<ListedKey>, FsError> {
            Ok(self.listed.clone())
        }
    }

    #[tokio::test]
    async fn sweep_reaps_aged_orphan_bytes() -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        let s3 = Arc::new(FakeS3::new(
            vec![
                ListedKey {
                    key: "files/old-stray".into(),
                    last_modified: now - TTL_SECS - 3600,
                },
                ListedKey {
                    key: "files/fresh-stray".into(),
                    last_modified: now - 60,
                },
                ListedKey {
                    key: "files/live-key".into(),
                    last_modified: now - TTL_SECS - 3600,
                },
            ],
            true,
        ));
        let orphan_prefix = crate::db::test_prefix("gc-orphan");
        let store = FsStore::new(build_test_store(&orphan_prefix).await);
        let policy =
            PolicyEngine::init_s3(build_test_store(&format!("{orphan_prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, s3.clone(), "b".into(), policy.authorizer());
        // Fresh session referencing live-key: aged but live, must survive.
        let mut sess = session_with_age("sess-live", 60, false);
        sess.s3_key = "files/live-key".into();
        engine.store.save_session(&sess).await?;

        assert_eq!(sweep_once(&engine).await?, 1);
        assert_eq!(s3.deleted(), vec!["files/old-stray".to_string()]);
        Ok(())
    }

    #[tokio::test]
    async fn sweep_reaps_restarted_multipart_session() -> anyhow::Result<()> {
        use object_store::memory::InMemory;

        // One backend surviving the "restart"; client RAM does not (S3
        // buckets outlive process restarts, so the backend upload id
        // stays addressable while the pre-restart RAM map is gone).
        let inner = std::sync::Arc::new(InMemory::new());
        let prefix = crate::db::test_prefix("gc-restart");
        let store = FsStore::new(build_test_store(&prefix).await);
        let policy =
            PolicyEngine::init_s3(build_test_store(&format!("{prefix}-policy")).await).await?;
        let pre: std::sync::Arc<dyn S3Client> =
            std::sync::Arc::new(ObjectStoreClient::new_combined(inner.clone()));
        let engine_pre = FsEngine::from_parts(
            store.clone(),
            pre,
            "test-bucket".into(),
            policy.authorizer(),
        );
        // Real multipart upload: backend id + durable record exist.
        let file_id = engine_pre
            .init_upload(
                crate::fs::model::InitRequest {
                    file_size: 2048,
                    part_size: 1024,
                    file_total_parts: 2,
                },
                "alice",
            )
            .await?;
        // Age it past the TTL.
        let mut sess = engine_pre
            .store
            .get_session(&file_id)
            .await?
            .expect("session exists");
        let upload_id = sess.s3_upload_id.clone().expect("multipart session");
        sess.created_at -= TTL_SECS + 100;
        engine_pre.store.save_session(&sess).await?;
        drop(engine_pre); // restart: RAM multipart states gone.
        let post: std::sync::Arc<dyn S3Client> =
            std::sync::Arc::new(ObjectStoreClient::new_combined(inner));
        let engine_post =
            FsEngine::from_parts(store, post, "test-bucket".into(), policy.authorizer());
        // GC restores the backend upload from the record, aborts it for
        // real, and converges the session plus its record.
        assert_eq!(sweep_once(&engine_post).await?, 1);
        assert!(engine_post.store.get_session(&file_id).await?.is_none());
        assert!(
            engine_post
                .store
                .load_multipart(&upload_id)
                .await?
                .is_none()
        );
        Ok(())
    }

    /// Writes a raw value under `key`, bypassing every typed setter, so a
    /// test can plant a row no writer in this crate would produce.
    async fn put_raw(store: &FsStore, key: &str, value: &[u8]) {
        use oxkv::GetSet as _;
        store
            .kv_handle()
            .write()
            .await
            .set_bytes(key, value)
            .await
            .expect("raw write");
    }

    /// [`std::io::Write`] sink sharing one buffer with the subscriber.
    #[derive(Clone)]
    struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Captures `tracing` output for the body, at `WARN` and above.
    ///
    /// Returns the buffer the subscriber writes into and the guard that
    /// keeps it installed. `set_default` is thread-local, and a
    /// `#[tokio::test]` runs the sweep on the calling thread, so this sees
    /// the sweeper's own events.
    fn capture_warnings() -> (
        Arc<std::sync::Mutex<Vec<u8>>>,
        tracing::subscriber::DefaultGuard,
    ) {
        let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&buf);
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || SharedBuf(Arc::clone(&sink)));
        let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        (buf, guard)
    }

    /// A row that will not decode must not cost the file whose bytes it
    /// describes.
    ///
    /// The sweep builds its liveness set from `list_files`/`list_sessions`,
    /// and an undecodable row is absent from both. Before the fix that made
    /// its object indistinguishable from a crash-stranded one: aged past the
    /// TTL, unreferenced by the *scan*, so the orphan-byte pass deleted the
    /// real S3 object while the metadata row it belongs to stayed put. The
    /// file was then permanently 404, out of a metadata problem that had a
    /// one-line fix.
    ///
    /// Reachable without corruption too -- any field added to `FileRecord`
    /// without a `#[serde(default)]` undecodes every row the previous
    /// version wrote, so this is one ordinary schema change away.
    ///
    /// The assertion is that *no* object is deleted. The `files/good` row
    /// decodes and is fresh, so it is legitimately not collectable either;
    /// only `files/bad` distinguishes the two behaviours.
    #[tokio::test]
    async fn sweep_never_deletes_bytes_of_an_undecodable_metadata_row() -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        let s3 = Arc::new(FakeS3::new(
            vec![
                ListedKey {
                    key: "files/good".into(),
                    last_modified: now - TTL_SECS - 3600,
                },
                ListedKey {
                    key: "files/bad".into(),
                    last_modified: now - TTL_SECS - 3600,
                },
            ],
            true,
        ));
        let prefix = crate::db::test_prefix("gc-undecodable");
        let store = FsStore::new(build_test_store(&prefix).await);
        let policy = PolicyEngine::init_s3(build_test_store(&format!("{prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, s3.clone(), "b".into(), policy.authorizer());

        // Fresh, unreferenced, unexpired: the sweep has no cause to delete
        // the bytes this record points at.
        engine
            .store
            .save_file(&FileRecord {
                id: "good".into(),
                name: "g.txt".into(),
                mimetype: "text/plain".into(),
                size: 4,
                s3_key: "files/good".into(),
                owner_sub: "alice".into(),
                created_at: now,
            })
            .await?;
        // The row whose bytes must survive, with a value nothing decodes.
        put_raw(
            &engine.store,
            "fs:files:bad:meta",
            br#"{"id":"bad","size":4,"s3_key":"files/bad","created_at":1"#,
        )
        .await;

        let (log, _guard) = capture_warnings();
        assert_eq!(sweep_once(&engine).await?, 0);
        assert_eq!(
            s3.deleted(),
            Vec::<String>::new(),
            "the sweep deleted an object whose metadata row it could not read"
        );

        // ...and the skip is visible, so this is diagnosable rather than a
        // silent leak: both the key and the refused pass are named.
        let logs = String::from_utf8(log.lock().expect("log buffer").clone()).expect("utf8");
        assert!(
            logs.contains("fs:files:bad:meta"),
            "the undecodable key was never logged:\n{logs}"
        );
        assert!(
            logs.contains("skipping orphan-byte pass"),
            "the refused pass was not logged:\n{logs}"
        );
        Ok(())
    }

    /// Once every row decodes, the pass resumes -- the fix defers, it does
    /// not disable the orphan-byte sweep.
    #[tokio::test]
    async fn orphan_byte_resumes_after_the_undecodable_row_decodes() -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        let s3 = Arc::new(FakeS3::new(
            vec![ListedKey {
                key: "files/stray".into(),
                last_modified: now - TTL_SECS - 3600,
            }],
            true,
        ));
        let prefix = crate::db::test_prefix("gc-undecodable-fixed");
        let store = FsStore::new(build_test_store(&prefix).await);
        let policy = PolicyEngine::init_s3(build_test_store(&format!("{prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, s3.clone(), "b".into(), policy.authorizer());

        put_raw(&engine.store, "fs:files:bad:meta", b"not json").await;
        assert_eq!(sweep_once(&engine).await?, 0);
        assert!(s3.deleted().is_empty());

        put_raw(&engine.store, "fs:files:bad:meta", b"not json").await;
        // Repaired: the row decodes again, so the sweep can prove
        // `files/stray` is unreferenced and reap it on this same pass.
        let repaired = FileRecord {
            id: "bad".into(),
            name: "b.txt".into(),
            mimetype: "text/plain".into(),
            size: 1,
            s3_key: "files/other".into(),
            owner_sub: "alice".into(),
            created_at: now,
        };
        put_raw(
            &engine.store,
            "fs:files:bad:meta",
            &serde_json::to_vec(&repaired)?,
        )
        .await;
        assert_eq!(sweep_once(&engine).await?, 1);
        assert_eq!(s3.deleted(), vec!["files/stray".to_string()]);
        Ok(())
    }

    /// [`ChangeSink`] double that refuses every append.
    ///
    /// Stands in for the one failure mode this ordering exists for: the
    /// mutation commits locally and the feed does not take it.
    struct DeadFeed;

    #[async_trait::async_trait]
    impl crate::records::ChangeSink for DeadFeed {
        async fn append(&self, _: crate::records::WalOp) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("feed down"))
        }
    }

    /// A file whose bytes are gone and whose deletion could not be
    /// announced must still be findable, or the deletion is lost for good.
    ///
    /// The old order was delete the object, delete the row, then announce:
    ///
    ///     engine.store.delete_file(&f.id).await?;
    ///     engine.announce(WalOp::FileDelete { .. }).await?;
    ///     cleaned += 1;
    ///
    /// A transient WAL failure at the announce returns `Err` with the row
    /// already deleted, so the retry cannot happen -- nothing scans for a
    /// file that has no record -- and every replica keeps the record *and*
    /// its bytes permanently. Nothing repairs it either, because the
    /// master's row is the only thing a later replay could have compared
    /// against.
    ///
    /// This drives the real order against a feed that refuses everything,
    /// then repairs the feed and sweeps again: the second sweep must find
    /// the file, announce it, and remove the row. Under the old order the
    /// first sweep already deleted the row and the second finds nothing,
    /// so the file is simply never announced.
    #[tokio::test]
    async fn a_failed_delete_announce_is_retried_rather_than_stranded() -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        let prefix = crate::db::test_prefix("gc-announce");
        let store = FsStore::new(build_test_store(&prefix).await);
        let policy = PolicyEngine::init_s3(build_test_store(&format!("{prefix}-p")).await).await?;
        let dead: Arc<dyn crate::records::ChangeSink> = Arc::new(DeadFeed);
        let bytes: Arc<dyn S3Client> = ObjectStoreClient::in_memory();
        let engine = FsEngine::from_parts(store, bytes, "b".into(), policy.authorizer())
            .with_change_sink(dead);
        engine
            .store
            .save_file(&FileRecord {
                id: "strand-me".into(),
                name: "f.txt".into(),
                mimetype: "text/plain".into(),
                size: 1,
                s3_key: "files/strand-me".into(),
                owner_sub: "alice".into(),
                created_at: now - TTL_SECS - 10,
            })
            .await?;
        engine
            .s3
            .put_object("b", "files/strand-me", Bytes::from_static(b"x"), None, None)
            .await?;

        // Feed down: the sweep may delete the bytes, but the row has to
        // survive or the deletion has nowhere to be retried from.
        assert_eq!(sweep_once(&engine).await?, 0);
        assert!(
            engine.store.get_file("strand-me").await?.is_some(),
            "the row was deleted while its delete could not be announced"
        );

        // Feed repaired. The row is still there, so the sweep finds the
        // file and this time the op lands.
        let wal = crate::sync::wal::Wal::new(
            build_test_store(&crate::db::test_prefix("gc-announce-wal")).await,
        );
        let engine = engine.with_change_sink(Arc::new(wal.clone()));
        assert_eq!(sweep_once(&engine).await?, 1);
        assert!(engine.store.get_file("strand-me").await?.is_none());
        let entries = wal.range(1, wal.head().await?).await?;
        assert_eq!(entries.len(), 1);
        assert!(
            matches!(&entries[0].op, crate::records::WalOp::FileDelete { file_id } if file_id == "strand-me"),
            "the delete was never announced: {:?}",
            entries[0].op
        );
        Ok(())
    }

    /// One undecodable ref-count row must not stall every sweep.
    ///
    /// `get_ref_info` maps a decode failure to `Err`, and the `?` that
    /// consumed it aborted `sweep_once` inside the file loop. Because the
    /// sweep runs sessions, then files, then orphan bytes, every file
    /// listed *after* the bad row stopped being cleaned and the orphan
    /// pass stopped running -- on every subsequent hourly sweep, because
    /// nothing in the sweeper repairs that key. One undecodable
    /// `fs:refs:{id}` value was therefore an unbounded leak of expired
    /// sessions, orphaned rows and orphan bytes, reported as a single
    /// `warn!` an hour.
    ///
    /// The ids are chosen so the bad row sorts first, because the scan is
    /// key-ordered: under the old behaviour nothing after it was reached
    /// at all.
    ///
    /// `RefInfo` has no `#[serde(default)]` either, so any field added to
    /// it turns this into a whole-store stall rather than a one-row one.
    /// That is deliberately left alone -- a default for `count` is `0`, and
    /// `0` is what makes a file eligible for collection, so the default
    /// would fail toward deleting live bytes instead of toward a leak.
    /// Confining the damage to one row is the fix for it.
    #[tokio::test]
    async fn one_unreadable_ref_count_row_costs_one_file_not_the_sweep() -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        let s3 = Arc::new(FakeS3::new(Vec::new(), true));
        let prefix = crate::db::test_prefix("gc-refs");
        let store = FsStore::new(build_test_store(&prefix).await);
        let policy = PolicyEngine::init_s3(build_test_store(&format!("{prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, s3.clone(), "b".into(), policy.authorizer());

        // `aaa-` sorts before `zzz-`, so the bad row is reached first.
        for id in ["aaa-bad-refs", "zzz-good"] {
            engine
                .store
                .save_file(&FileRecord {
                    id: id.into(),
                    name: "f.txt".into(),
                    mimetype: "text/plain".into(),
                    size: 1,
                    s3_key: format!("files/{id}"),
                    owner_sub: "alice".into(),
                    created_at: now - TTL_SECS - 10,
                })
                .await?;
        }
        put_raw(&engine.store, "fs:files:aaa-bad-refs:refs", b"{\"count\":").await;

        // The file behind the bad row is still cleaned...
        assert_eq!(sweep_once(&engine).await?, 1);
        assert_eq!(s3.deleted(), vec!["files/zzz-good".to_string()]);
        assert!(engine.store.get_file("zzz-good").await?.is_none());
        // ...and the one whose ref-count could not be read is retained,
        // rather than deleted on a guess or allowed to stall the rest.
        assert!(engine.store.get_file("aaa-bad-refs").await?.is_some());
        Ok(())
    }

    /// An in-flight part fold must not be deleted out from under by the
    /// sweeper, and the file that follows it must not commit with no bytes.
    ///
    /// This is the interleaving the session lock exists for. A client opens
    /// an upload and stalls; `created_at` never refreshes, so after the TTL
    /// the hourly sweep calls the session expired. The client resumes and
    /// PUTs the bytes, and `merge_part` -- which re-reads the session under
    /// the lock and writes that copy back -- is mid read-modify-write when
    /// the sweep runs. A sweep that does not take the same lock can land
    /// between the read and the write: it deletes the object, deletes the
    /// row, and the fold's write puts the row back with `etags[0]` set.
    /// `complete_upload` then sees a complete single-part session, skips the
    /// multipart block entirely -- there is no S3 upload left to complete,
    /// the object was already deleted -- and commits, returning `Ok`. The
    /// file is announced and answers `GET /fs/{id}`, and every download 404s
    /// forever.
    ///
    /// No adversary is needed: stalling past a 24-hour TTL and resuming
    /// during a sweep tick is an ordinary thing for a resumable upload
    /// client to do.
    ///
    /// The window is between two store calls inside `merge_part` with
    /// nothing to hang a double on, so the fold is stood in for: the test
    /// holds the engine's own session lock and performs the same
    /// read-then-write `merge_part` performs. What is asserted is the
    /// property that matters, from the outside: while the fold holds the
    /// lock the sweep cannot complete, and afterwards there is no record
    /// whose object is missing.
    #[tokio::test]
    async fn a_sweep_cannot_expire_a_session_under_an_in_flight_part_fold() -> anyhow::Result<()> {
        let engine = make_engine().await;
        let file_id = engine
            .init_upload(
                crate::fs::model::InitRequest {
                    file_size: 1024,
                    part_size: 1024,
                    file_total_parts: 1,
                },
                "alice",
            )
            .await?;
        // The client's part has landed: bytes on the object store, etag in
        // the row. What is left is the fold, held open below.
        engine
            .upload_part(&file_id, 0, once_body(vec![9u8; 1024]), None, None, "alice")
            .await?;
        // Age it past the TTL, which is the whole of "stalled": nothing
        // refreshes `created_at`, so an in-progress upload is indistinguishable
        // from an abandoned one to the sweeper.
        let mut session = engine
            .store
            .get_session(&file_id)
            .await?
            .expect("session exists");
        session.created_at -= TTL_SECS + 100;
        engine.store.save_session(&session).await?;

        // `merge_part`'s critical section: the session lock is held, and the
        // row has been read. The write is the next statement.
        let claim = engine.session_locks.acquire(&file_id).await;
        let _guard = claim.acquire().await;
        let mut folded = engine
            .store
            .get_session(&file_id)
            .await?
            .expect("session still exists");

        let swept = engine.clone();
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(sweep_once(&swept).await);
        });

        // The sweep cannot be allowed to finish here. Its abort deletes the
        // object and its row delete removes the row `merge_part` is about to
        // write back; under the old lock-free sweep this window is where the
        // file is lost. The bound is only here so the test cannot hang if the
        // property regresses -- on the old code the sweep finishes in
        // microseconds, well inside it.
        assert!(
            tokio::time::timeout(Duration::from_millis(250), &mut rx)
                .await
                .is_err(),
            "the sweep completed while a part fold held the session lock"
        );
        assert!(
            engine.store.get_session(&file_id).await?.is_some(),
            "the sweep deleted a session whose rows were being merged"
        );

        // Finish the fold, then let go in the order the production sites do:
        // the guard drops before the claim is released.
        folded.checksums[0] = Some("sha256:x".into());
        engine.store.save_session(&folded).await?;
        drop(_guard);
        drop(claim);

        assert_eq!(rx.await.expect("sweep reported")?, 1);
        assert!(engine.store.get_session(&file_id).await?.is_none());
        assert!(
            engine
                .s3
                .get_object("test-bucket", &format!("files/{file_id}"))
                .await
                .is_err(),
            "the sweep did not reap the bytes of the session it expired"
        );

        // The client's completion. Whether the sweep went first (404) or the
        // fold did (the sweep then expired the session), there must be no
        // `Ok` here: the old behaviour was a committed record for an object
        // that no longer existed.
        let committed = engine
            .complete_upload(
                &file_id,
                crate::fs::model::CompleteRequest {
                    name: "report.pdf".into(),
                    mimetype: "application/pdf".into(),
                },
                "alice",
            )
            .await;
        assert!(
            committed.is_err(),
            "complete_upload reported success for a session the sweeper had already expired"
        );
        assert!(
            engine.store.get_file(&file_id).await?.is_none(),
            "a file record was committed with no bytes behind it"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sweep_empty_store_returns_zero() -> anyhow::Result<()> {
        let engine = make_engine().await;
        assert_eq!(sweep_once(&engine).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn sweep_retains_session_when_abort_fails() -> anyhow::Result<()> {
        let fail_prefix = crate::db::test_prefix("gc-fail");
        let store = FsStore::new(build_test_store(&fail_prefix).await);
        let policy =
            PolicyEngine::init_s3(build_test_store(&format!("{fail_prefix}-p")).await).await?;
        // Every byte-mutating call fails, so both the session abort and the
        // orphaned-file delete are retained for the next sweep.
        let engine = FsEngine::from_parts(
            store,
            Arc::new(FakeS3::new(Vec::new(), false)),
            "b".into(),
            policy.authorizer(),
        );
        engine
            .store
            .save_session(&session_with_age("old-fail", TTL_SECS + 10, true))
            .await?;
        // Durable record present so expiry reaches the S3 abort (which
        // fails) instead of taking the no-record early return.
        engine
            .store
            .save_multipart(&PersistedMultipart {
                upload_id: "upload-old-fail".into(),
                bucket: "b".into(),
                key: "files/old-fail".into(),
                s3_upload_id: "real-fail".into(),
                parts: Default::default(),
                created_at: chrono::Utc::now().timestamp() - TTL_SECS - 10,
            })
            .await?;
        engine
            .store
            .save_file(&FileRecord {
                id: "old-fail-file".into(),
                name: "f.txt".into(),
                mimetype: "text/plain".into(),
                size: 1,
                s3_key: "files/old-fail-file".into(),
                owner_sub: "alice".into(),
                created_at: chrono::Utc::now().timestamp() - TTL_SECS - 10,
            })
            .await?;
        // S3 failure keeps sessions and files for the next sweep instead
        // of leaking bytes no record points at.
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 0);
        assert!(engine.store.get_session("old-fail").await?.is_some());
        assert!(engine.store.get_file("old-fail-file").await?.is_some());
        Ok(())
    }
}
