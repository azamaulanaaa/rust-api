//! Garbage collection for abandoned uploads and orphaned files.
//!
//! The sweeper removes sessions and temp or orphaned files that are older
//! than 24 hours. The engine announces expired files to the change feed
//! when a sink is set. Each replica then replays the deletion instead of
//! keeping a stale copy.
//!
//! # The two scopes
//!
//! The sweeper reclaims objects in two scopes. The scopes are separate.
//! Each pass names one scope and ignores the other.
//!
//! 1. The application byte scope. The keys have the shape `files/{id}`.
//!    The orphan byte pass lists this scope and deletes an object that no
//!    session row and no file row references. A crash between the byte
//!    write and the metadata write strands such an object.
//! 2. The store internal scope. The keys have the shape
//!    `e{6 digits}/wal/{8 digits}.log` under the oxkv prefix of this
//!    store. The store level pass deletes a WAL object that the manifest
//!    does not list. A failed manifest compare-and-swap strands such an
//!    object.
//!
//! The two scopes hold different objects. Therefore the store level pass
//! complements the orphan byte pass. The store level pass does not replace
//! it. The orphan byte pass also decides a question that the store level
//! pass cannot answer. The orphan byte pass needs a complete scan of the
//! metadata rows before it can call an application key unreferenced. The
//! store level pass has no such requirement. It reads no metadata row of
//! this crate.

use std::{collections::HashSet, sync::Arc, time::Duration};

use tokio::time::interval;

use crate::fs::FsEngine;
use crate::fs::store::RecordScan;

/// The object prefix that holds the file bytes.
///
/// The `UploadSession` and `FileRecord` keys are `files/{id}`. The orphan
/// byte pass lists only this scope. Therefore no other application key
/// family is in reach of that pass. The oxkv prefix of this store is
/// outside this scope. The store level pass reaches that prefix. The pass
/// above and the store level pass therefore never inspect the same object.
const FILE_BYTES_PREFIX: &str = "files/";

/// TTL for abandoned sessions and orphaned files.
pub const TTL_SECS: i64 = 24 * 3600;

/// Starts the sweeper task. The task runs once every hour.
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

/// Runs one sweep for sessions, orphaned files, orphan S3 bytes, and
/// orphaned store WAL objects.
///
/// The function returns the number of application items that the sweep
/// deleted. The store level pass does not add to that number. The two
/// scopes are separate, and the log of each pass reports its own count.
///
/// The session pass runs under the same per-session lock that `merge_part`
/// and `complete_upload` take. The pass reads each row again under the lock.
/// The listing is a snapshot. The code takes it before the loop starts.
/// Therefore the listing alone says nothing about what a row holds when the
/// sweeper reaches it. See the note inside the loop.
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
        // This is the lock that the upload path already uses for the rows of
        // this session. Taking the lock here makes the sweeper the fourth
        // serialized writer. Without the lock the sweeper would be a fifth
        // writer that races with the others. `merge_part` reads the session
        // again under this lock and writes the copy back. A sweep that does
        // not take the lock can land between that read and that write.
        //
        // The failure that this lock prevents is not a lost update. The
        // failure is a destroyed file. A client opens a session and then
        // stalls. Nothing refreshes `created_at`. Therefore the sweep
        // considers the session expired after the TTL. The client resumes
        // and `upload_part` PUTs the bytes. Then `merge_part` folds the
        // bytes into the row. If the sweep runs `delete_object` and
        // `delete_session` during that fold, the write restores the row with
        // the etag set. Then `complete_upload` takes the single part branch.
        // It skips the multipart block because there is no S3 upload to
        // complete. The object was already deleted. Then `complete_upload`
        // commits `save_file` -> `announce` -> `delete_session` and returns
        // `Ok`. The file is in the feed and answers `GET /fs/{id}`. Every
        // download then returns 404 forever. The bytes went in the sweep and
        // nothing looks for a record whose object is missing.
        //
        // Under this lock only two orderings remain:
        //
        // 1. Sweep first. The row goes. The fold reads `None`, so the client
        //    gets a 404. The bytes that it wrote are unreferenced, and the
        //    orphan byte pass removes them.
        // 2. Fold first. The row is written. This pass deletes the row
        //    moments later, so there is still no record for
        //    `complete_upload` to commit.
        //
        // Neither ordering ends with a file whose bytes are gone.
        //
        // The declaration order matters and matches the order at the call
        // sites. The code drops the guard before it releases the claim.
        // Therefore a new claim can never create a second mutex while this
        // guard is still live.
        let session_lock = engine.session_locks.acquire(&listed.id).await;
        let _held = session_lock.acquire().await;
        // The code reads the row again under the lock. The code does not
        // trust the listing. A session in the listing may have completed
        // since the listing was taken. A completed session saves the file
        // record that points at exactly these bytes. A session may also have
        // been cancelled. Deleting on the stale copy of a cancelled session
        // removes the bytes of a live file. That would leave the same
        // permanently 404 record that this lock prevents.
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
        // The engine deletes the S3 object first. The engine restores the
        // state after a restart and tolerates an object that is already
        // gone. On failure the code keeps the session, so the next sweep
        // retries. The code does not leak bytes that no record points at.
        if engine.abort_session_upload(&s).await.is_err() {
            tracing::warn!("fs gc keeping upload {} for retry", s.id);
            continue;
        }
        engine.store.delete_session(&s.id).await?;
        cleaned += 1;
    }

    // Orphaned and temp files.
    for f in &files {
        // One unreadable row costs one file. It does not cost the sweep. The
        // sweep runs sessions first, then files, then orphan bytes.
        // Therefore an error here would strand every file that the listing
        // returns after this one. The error would also skip the orphan byte
        // pass on every later sweep, because nothing in the sweeper repairs
        // the key. The result is an unbounded leak of expired sessions,
        // orphaned rows, and orphan bytes. One `warn!` per hour is the only
        // sign.
        //
        // This is the same call that the sibling branch below already
        // refuses to propagate, and for the same reason. The sweep retains
        // one bad item and then continues. Retaining the item is also the
        // safe direction here. The orphan byte pass uses `f.s3_key`. This
        // row does not affect that key, so skipping the file leaks the file
        // instead of losing it.
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
        // The code retains the item on failure, as it does for sessions
        // above. The code measures the age from `orphan_since` when the file
        // was attached and later detached. The code uses `created_at` for a
        // file that was never referenced. Unlike a session, there is no
        // record method that the code can call, because the timestamp is on
        // `RefInfo`, not on `FileRecord`.
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
        // The code announces before the row goes, and not after. The row is
        // the only record that says that this deletion still has to happen.
        // After the row is gone, no future sweep can find the file to
        // announce again. A failed append here therefore strands the copy on
        // every replica for good. The master has no row. The replica has the
        // record and the bytes. No later replay repairs either side.
        // When the code announces first, the same transient failure leaves
        // the row in place. The next sweep announces the deletion again.
        // Announcing again has no bad effect. Replaying `FileDelete` runs a
        // `delete_file` on the replica. That call is idempotent on a file
        // that is already gone.
        //
        // A failed announce retains the file. The code does not propagate the
        // error. The bytes are already gone at this point. Therefore
        // propagating would leave the exact state that cannot be retried, as
        // described above. It would also abort the rest of the sweep for one
        // file.
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

    // Store-internal WAL orphans. A failed manifest compare-and-swap
    // leaves a WAL object in storage that the manifest does not list. No
    // read path can reach that object. The object then costs storage for
    // the life of the prefix.
    //
    // The code runs this pass before the orphan-byte pass. The two passes
    // cover different scopes. The order between them decides no shared
    // outcome. The store pass goes first because the byte pass below is
    // the pass that the module already treats as the last one. A failure
    // here then leaves the byte pass, and the returns above, untouched.
    //
    // The code calls the store on the handle that the engine already
    // holds. The code must not open a second handle on the same prefix. A
    // second handle can fence this one on real S3.
    //
    // An error here does not stop the sweep. The code logs the error and
    // does not propagate it. The pass deletes only unreachable objects. A
    // failure therefore costs storage and not data.
    // The next hourly sweep tries again.
    match engine.store.gc_wal_orphans().await {
        Ok(0) => {}
        Ok(reclaimed) => {
            tracing::info!("fs gc reclaimed {reclaimed} orphaned store WAL objects");
        }
        Err(e) => {
            tracing::warn!("fs gc skipping store WAL orphan pass: {e}");
        }
    }

    // Orphan S3 bytes: listed keys that no session record or file record
    // references. A crash between the byte write and the metadata write can
    // strand such a key. The pass removes them only after the TTL, so
    // uploads that are in flight always survive.
    //
    // The code builds the liveness set below from the two scans above. A row
    // that either scan cannot decode makes its key look unreferenced when the
    // key is in fact referenced. The delete is irreversible and the metadata
    // row stays. Therefore every later download of that file returns 404
    // forever. The code needs a complete scan to prove that a key is
    // unreferenced. An incomplete scan therefore skips the whole pass.
    // Leaking the bytes costs storage. Removing the bytes costs the file.
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
        // A listing failure skips only this pass. The metadata work above
        // still stands.
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
        // The fresh temp file stays.
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
        // The old temp file was never attached. It has 0 references and an
        // age above the TTL.
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
        // A live single part session. The bytes exist and the session is
        // still open.
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
        // Fresh stray bytes, for example after a crash between the put and
        // the metadata write.
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

    /// A scriptable [`S3Client`] double. It records deletions and returns a
    /// prepared listing. The tests therefore drive the orphan byte path and
    /// the retain on failure path without a real backend.
    ///
    /// One double covers both paths. The two tests that use it differ only
    /// in what `list_keys` reports and in whether the byte operations
    /// succeed. A separate struct for each test would require listing all
    /// nine trait methods every time the code adds a method to `S3Client`.
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

        /// Returns an error from every call that writes bytes when the
        /// double is in failure mode.
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
        // A fresh session references live-key. The key is old but live, so
        // it must survive.
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

        // One backend survives the restart. The RAM of the client does
        // not. S3 buckets outlive process restarts, so the backend upload id
        // stays addressable. The RAM map from before the restart is gone.
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
        // A real multipart upload. The backend id and the durable record
        // both exist.
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
        drop(engine_pre); // The restart removes the multipart states from RAM.
        let post: std::sync::Arc<dyn S3Client> =
            std::sync::Arc::new(ObjectStoreClient::new_combined(inner));
        let engine_post =
            FsEngine::from_parts(store, post, "test-bucket".into(), policy.authorizer());
        // Garbage collection restores the backend upload from the record.
        // It aborts the upload for real and removes the session and its
        // record.
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

    /// Writes a raw value under `key`. The call bypasses every typed setter,
    /// so a test can plant a row that no writer in this crate would produce.
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

    /// A [`std::io::Write`] sink. It shares one buffer with the subscriber.
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

    /// Captures `tracing` output for the body at level `WARN` and above.
    ///
    /// The function returns the buffer that the subscriber writes into. It
    /// also returns the guard that keeps the subscriber installed.
    /// `set_default` is thread local. A `#[tokio::test]` runs the sweep on
    /// the calling thread. Therefore this function sees the events of the
    /// sweeper.
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
    /// The sweep builds its liveness set from `list_files` and
    /// `list_sessions`. An undecodable row is absent from both. Before the
    /// fix, such a row made its object the same as an object stranded by a
    /// crash. The row was older than the TTL. The scan did not reference
    /// the key. The orphan byte pass therefore deleted the real S3 object.
    /// The metadata row of that object stayed. The file then returned 404
    /// forever, because of a metadata problem that had a one line fix.
    ///
    /// Corruption is not necessary to reach this state. Any field that the
    /// code adds to `FileRecord` without a `#[serde(default)]` makes every
    /// row from the previous version fail to decode. One ordinary schema
    /// change is therefore enough.
    ///
    /// The assertion is that the sweep deletes no object. The `files/good`
    /// row decodes and is fresh, so it also must not be removed. Only
    /// `files/bad` distinguishes the two behaviours.
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

        // The row is fresh, unreferenced, and unexpired. The sweep
        // therefore has no cause to delete the bytes that this record
        // points at.
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
        // This row must keep its bytes. No value decodes it.
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

        // The log also shows the skip, so the state is not a silent
        // leak. The log names the key and the refused pass.
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

    /// Once every row decodes, the pass resumes. The fix defers the pass.
    /// It does not disable the orphan byte sweep.
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
        // The row decodes again. Therefore the sweep can prove that
        // `files/stray` is unreferenced and removes it in this same pass.
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

    /// A [`ChangeSink`] double that refuses every append.
    ///
    /// The double stands in for the one failure mode that this order
    /// supports. In that mode the mutation commits locally and the feed does
    /// not take it.
    struct DeadFeed;

    #[async_trait::async_trait]
    impl crate::records::ChangeSink for DeadFeed {
        async fn append(&self, _: crate::records::WalOp) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("feed down"))
        }
    }

    /// A file whose bytes are gone and whose deletion could not be
    /// announced must still be findable. Otherwise the deletion is lost for
    /// good.
    ///
    /// The old order deletes the object, deletes the row, and then announces:
    ///
    ///     engine.store.delete_file(&f.id).await?;
    ///     engine.announce(WalOp::FileDelete { .. }).await?;
    ///     cleaned += 1;
    ///
    /// A transient WAL failure at the announce returns `Err` after the code
    /// deleted the row. The retry therefore cannot happen, because nothing
    /// scans for a file that has no record. Every replica then keeps the
    /// record and its bytes permanently. Nothing repairs the state, because
    /// the row on the master is the only value that a later replay could
    /// compare against.
    ///
    /// The test drives the current order against a feed that refuses
    /// everything. The test then repairs the feed and sweeps again. The second
    /// sweep must find the file, announce it, and remove the row. Under the
    /// old order the first sweep already deleted the row. The second sweep
    /// then finds nothing, so the code never announces the file.
    #[tokio::test]
    async fn failed_announce_is_retried_and_the_row_is_not_stranded() -> anyhow::Result<()> {
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

        // The feed is down. The sweep may delete the bytes, but the row must
        // survive. Otherwise no later sweep can retry the deletion.
        assert_eq!(sweep_once(&engine).await?, 0);
        assert!(
            engine.store.get_file("strand-me").await?.is_some(),
            "the row was deleted while its delete could not be announced"
        );

        // The feed is repaired. The row is still there, so the sweep finds
        // the file and the operation now lands.
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

    /// One undecodable ref count row must not stall every sweep.
    ///
    /// `get_ref_info` maps a decode failure to `Err`. The `?` operator then
    /// aborted `sweep_once` inside the file loop. The sweep runs sessions,
    /// then files, then orphan bytes. Therefore every file after the bad row
    /// stopped being cleaned. The orphan byte pass also stopped running on
    /// every later hourly sweep, because nothing in the sweeper repairs the
    /// key. One undecodable `fs:refs:{id}` value therefore caused an
    /// unbounded leak of expired sessions, orphaned rows, and orphan bytes.
    /// A single `warn!` per hour reported the leak.
    ///
    /// The test chooses the ids so that the bad row comes first. The scan is
    /// ordered by key. Under the old behaviour, the code did not reach any
    /// row after the bad row.
    ///
    /// `RefInfo` has no `#[serde(default)]` either. Any field that the code
    /// adds to it turns this problem into a stall of the whole store. The
    /// field does not turn it into a stall of one row. The code deliberately leaves
    /// this alone. The default for `count` is `0`. The value `0` is what
    /// makes a file eligible for collection. The default would therefore
    /// fail toward the deletion of live bytes, and not toward a leak.
    /// Confining the damage to one row is the fix for this problem.
    #[tokio::test]
    async fn one_unreadable_ref_count_row_costs_one_file_not_the_sweep() -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        let s3 = Arc::new(FakeS3::new(Vec::new(), true));
        let prefix = crate::db::test_prefix("gc-refs");
        let store = FsStore::new(build_test_store(&prefix).await);
        let policy = PolicyEngine::init_s3(build_test_store(&format!("{prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, s3.clone(), "b".into(), policy.authorizer());

        // The key `aaa-` sorts before `zzz-`. The code therefore reaches the
        // bad row first.
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

        // The sweep still cleans the file after the bad row.
        assert_eq!(sweep_once(&engine).await?, 1);
        assert_eq!(s3.deleted(), vec!["files/zzz-good".to_string()]);
        assert!(engine.store.get_file("zzz-good").await?.is_none());
        // The sweep retains the file whose ref count it cannot read. The
        // code does not delete the file on a guess. The code does not let
        // the file stall the rest of the sweep.
        assert!(engine.store.get_file("aaa-bad-refs").await?.is_some());
        Ok(())
    }

    /// The sweeper must not delete an in-flight part fold, and the file
    /// that follows the fold must not commit without bytes.
    ///
    /// The session lock exists for this interleaving. A client opens an
    /// upload and then stalls. The value `created_at` never refreshes.
    /// Therefore the hourly sweep calls the session expired after the TTL.
    /// The client resumes and PUTs the bytes. Then `merge_part` runs a read
    /// modify write operation. The operation reads the session under the
    /// lock and writes that copy back. The sweep runs during the operation.
    /// A sweep that does not take the same lock can land between the read
    /// and the write. The sweep deletes the object and deletes the row. Then
    /// the write of the fold puts the row back with `etags[0]` set.
    /// `complete_upload` then sees a complete single part session and skips
    /// the multipart block. There is no S3 upload left to complete, because
    /// the object was already deleted. `complete_upload` then commits and
    /// returns `Ok`. The code announces the file, and the file answers
    /// `GET /fs/{id}`. Every download then returns 404 forever.
    ///
    /// The test needs no adversary. A client that can resume an upload can
    /// stall for more than 24 hours and resume during a sweep tick.
    ///
    /// The window is between two store calls inside `merge_part`. The code
    /// has nothing to attach a double to in the window, so the test stands
    /// in for the fold. The test holds the session lock of the engine and
    /// performs the same read then write that `merge_part` performs. The
    /// test asserts the property that matters, from the outside. While the
    /// fold holds the lock, the sweep cannot complete. After the fold
    /// releases the lock, no record points at a missing object.
    #[tokio::test]
    async fn sweep_cannot_expire_a_session_during_a_part_fold() -> anyhow::Result<()> {
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
        // The part of the client has landed. The bytes are on the object
        // store and the etag is in the row. The fold is the only step that
        // is left. The test holds the fold open below.
        engine
            .upload_part(&file_id, 0, once_body(vec![9u8; 1024]), None, None, "alice")
            .await?;
        // The test ages the session past the TTL. This age is the whole of a
        // stalled upload. Nothing refreshes `created_at`, so the sweeper
        // cannot tell an upload in progress from an abandoned upload.
        let mut session = engine
            .store
            .get_session(&file_id)
            .await?
            .expect("session exists");
        session.created_at -= TTL_SECS + 100;
        engine.store.save_session(&session).await?;

        // This is the critical section of `merge_part`. The code holds the
        // session lock and has read the row. The next statement is the
        // write.
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

        // The sweep must not finish here. The abort of the sweep deletes
        // the object. The row delete of the sweep removes the row that
        // `merge_part` will write back. Under the old sweep without a lock,
        // the sweep loses the file in this window. The bound is only here
        // so that the test cannot hang if the property fails again. Under
        // the old code the sweep finishes in microseconds, well inside the
        // bound.
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

        // The test finishes the fold and then releases the values in the
        // order that the production sites use. The code drops the guard
        // before it releases the claim.
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

        // This is the completion of the client. The code must not return
        // `Ok` here. That holds whether the sweep went first with a 404 or
        // the fold went first and the sweep then expired the session. The
        // old behaviour committed a record for an object that no longer
        // existed.
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
        // Every call that writes bytes fails. Therefore the sweep retains
        // both the session abort and the orphaned file delete for the next
        // sweep.
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
        // The durable record is present. Therefore the expiry reaches the
        // S3 abort, which fails, instead of taking the early return for a
        // missing record.
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
        // An S3 failure keeps the sessions and the files for the next sweep.
        // The code does not leak bytes that no record points at.
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 0);
        assert!(engine.store.get_session("old-fail").await?.is_some());
        assert!(engine.store.get_file("old-fail-file").await?.is_some());
        Ok(())
    }

    /// Writes one raw object into the backend of a test store.
    ///
    /// The call bypasses `oxkv`. A test can therefore plant an object that
    /// no writer in this crate would produce. That is the only way to
    /// reproduce the object that a failed manifest compare-and-swap leaves
    /// behind.
    async fn put_object(inner: &Arc<dyn object_store::ObjectStore>, path: &str) {
        use object_store::{ObjectStore as _, PutPayload, path::Path as ObjectPath};
        inner
            .put(&ObjectPath::from(path), PutPayload::from("raw".as_bytes()))
            .await
            .expect("raw put");
    }

    /// The store level pass and the orphan byte pass are two scopes. Each
    /// one runs in the same sweep.
    ///
    /// The orphan byte pass lists the `files/` scope of the application. The
    /// store level pass lists the oxkv prefix of this store. A key in one
    /// scope is never a candidate for the pass of the other scope. The store
    /// level pass therefore complements the orphan byte pass. The test fails
    /// if either pass replaces the other, or if either pass reaches into the
    /// scope of the other.
    ///
    /// The test plants one unlisted WAL object. That object is the whole
    /// target of the store level pass. A failed manifest compare-and-swap
    /// creates exactly that object. Nothing can read it afterwards.
    ///
    /// The test also plants an `sst/` object and a `manifest.json` value.
    /// Both have a path that the shape check must reject. The pass would
    /// destroy live data if it accepted either of them.
    ///
    /// `cleaned` stays at 1. The application pass counts its own deletion.
    /// The store level pass reports its own count in the log. The return
    /// value of `sweep_once` therefore keeps its old meaning.
    #[tokio::test]
    async fn the_sweep_reclaims_wal_orphans_in_their_own_scope() -> anyhow::Result<()> {
        use object_store::ObjectStore as _;
        use object_store::memory::InMemory;

        let now = chrono::Utc::now().timestamp();
        // The application scope. One aged byte that no row references.
        let s3 = Arc::new(FakeS3::new(
            vec![ListedKey {
                key: "files/stray".into(),
                last_modified: now - TTL_SECS - 3600,
            }],
            true,
        ));
        let prefix = crate::db::test_prefix("gc-wal-orphan");
        let inner = Arc::new(InMemory::new()) as Arc<dyn object_store::ObjectStore>;
        let handle = crate::db::build_test_store_new_session(Arc::clone(&inner), &prefix).await;
        let store = FsStore::new(handle);
        let policy = PolicyEngine::init_s3(build_test_store(&format!("{prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, s3.clone(), "b".into(), policy.authorizer());
        // A live row. The pass must not touch it.
        engine
            .store
            .save_file(&FileRecord {
                id: "live".into(),
                name: "l.txt".into(),
                mimetype: "text/plain".into(),
                size: 1,
                s3_key: "files/live".into(),
                owner_sub: "alice".into(),
                created_at: now,
            })
            .await?;

        // The store scope. One unlisted WAL object, plus two objects that
        // the shape check must reject.
        let orphan = format!("{prefix}/e000001/wal/00009999.log");
        let sst = format!("{prefix}/e000001/sst/L0/000000009.sst");
        for path in [&orphan, &sst] {
            put_object(&inner, path).await;
        }

        let cleaned = sweep_once(&engine).await?;
        assert_eq!(cleaned, 1, "the store pass must not count into cleaned");
        assert!(
            inner
                .get(&object_store::path::Path::from(orphan.as_str()))
                .await
                .is_err(),
            "the sweep kept an unlisted store WAL object"
        );
        assert!(
            inner
                .get(&object_store::path::Path::from(sst.as_str()))
                .await
                .is_ok(),
            "the sweep deleted an SST object"
        );
        assert!(
            inner
                .get(&object_store::path::Path::from(
                    format!("{prefix}/manifest.json").as_str()
                ))
                .await
                .is_ok(),
            "the sweep deleted the manifest"
        );
        // The application pass ran in the same sweep.
        assert_eq!(s3.deleted(), vec!["files/stray".to_string()]);
        assert!(engine.store.get_file("live").await?.is_some());
        Ok(())
    }

    /// A failed store level pass must not abort the passes that follow it.
    ///
    /// The store level pass runs before the orphan byte pass. An error in
    /// that pass must therefore stay inside it. The module already requires
    /// this for the other passes. One failure may not strand the work of a
    /// whole sweep, because nothing in the sweeper repairs a skipped pass.
    ///
    /// The test makes the pass fail for real. `gc_orphans` reads
    /// `ownership.json` before it deletes anything. A corrupt ownership
    /// record makes that read fail. A corrupt file is a state that a real
    /// bucket can hold after an interrupted write. The test needs no double.
    ///
    /// The test then asserts two facts. The orphan byte pass still deleted
    /// its aged object. The sweep returned the count of that pass, and not an
    /// error.
    #[tokio::test]
    async fn the_sweep_continues_after_the_store_wal_pass_fails() -> anyhow::Result<()> {
        use object_store::memory::InMemory;

        let now = chrono::Utc::now().timestamp();
        let s3 = Arc::new(FakeS3::new(
            vec![ListedKey {
                key: "files/stray".into(),
                last_modified: now - TTL_SECS - 3600,
            }],
            true,
        ));
        let prefix = crate::db::test_prefix("gc-wal-fail");
        let inner = Arc::new(InMemory::new()) as Arc<dyn object_store::ObjectStore>;
        let handle = crate::db::build_test_store_new_session(Arc::clone(&inner), &prefix).await;
        let store = FsStore::new(handle);
        let policy = PolicyEngine::init_s3(build_test_store(&format!("{prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, s3.clone(), "b".into(), policy.authorizer());
        // A fresh row. The file pass skips it, so the file pass writes
        // nothing. The test then isolates the store pass.
        engine
            .store
            .save_file(&FileRecord {
                id: "live".into(),
                name: "l.txt".into(),
                mimetype: "text/plain".into(),
                size: 1,
                s3_key: "files/live".into(),
                owner_sub: "alice".into(),
                created_at: now,
            })
            .await?;
        // The ownership record now fails to parse. The pass above must fail
        // on it.
        put_object(&inner, &format!("{prefix}/ownership.json")).await;
        let orphan = format!("{prefix}/e000001/wal/00009999.log");
        put_object(&inner, &orphan).await;

        let (log, _guard) = capture_warnings();
        let cleaned = sweep_once(&engine).await?;
        assert_eq!(
            cleaned, 1,
            "a failed store pass took the orphan byte pass with it"
        );
        assert_eq!(s3.deleted(), vec!["files/stray".to_string()]);
        assert!(
            engine.store.get_file("live").await?.is_some(),
            "the sweep deleted the row of a file that is not expired"
        );
        // The failed pass deleted nothing. The object stays for the next
        // sweep.
        assert!(
            inner
                .get(&object_store::path::Path::from(orphan.as_str()))
                .await
                .is_ok(),
            "a failed pass still deleted an object"
        );
        let logs = String::from_utf8(log.lock().expect("log buffer").clone()).expect("utf8");
        assert!(
            logs.contains("skipping store WAL orphan pass"),
            "the failed pass was not logged:\n{logs}"
        );
        Ok(())
    }

    /// Reads the `wal` list of the manifest that the store wrote.
    ///
    /// The function reads `manifest.json` from the backend. It does not
    /// read through the store, because the store read path does not
    /// expose the `wal` list. Every entry is a full prefixed id, so a
    /// caller can read the object of each entry in the backend.
    async fn listed_wal_ids(
        inner: &Arc<dyn object_store::ObjectStore>,
        prefix: &str,
    ) -> Vec<String> {
        use object_store::ObjectStore as _;
        let raw = inner
            .get(&object_store::path::Path::from(
                format!("{prefix}/manifest.json").as_str(),
            ))
            .await
            .expect("the manifest must exist in the backend of a written store");
        let manifest: serde_json::Value =
            serde_json::from_slice(&raw.bytes().await.expect("manifest bytes"))
                .expect("the manifest must be JSON");
        manifest["wal"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| id.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A listed `WAL` object is live data. The pass must keep it.
    ///
    /// The sibling test above proves that the pass reclaims an unlisted
    /// object. That sibling test cannot prove that the pass spares a
    /// listed object. It reads the row of a live file through the store.
    /// The read goes to the memtable. The read therefore succeeds
    /// even if the pass deleted the `WAL` object that holds the
    /// acknowledged write. The bytes stay in RAM after such a deletion, so
    /// the read cannot see the loss.
    ///
    /// This test makes a real write through the store. Then it reads the
    /// backend. The backend is the only place where a deleted object is
    /// visible. The test fails when the write listed no `WAL` id, because a
    /// test with no listed object proves nothing.
    ///
    /// The test plants one unlisted object as well. The sweep must delete
    /// that object and must keep every listed object.
    #[tokio::test]
    async fn the_sweep_spares_the_listed_wal_object() -> anyhow::Result<()> {
        use object_store::ObjectStore as _;
        use object_store::memory::InMemory;

        // The application scope is empty. So the count of `sweep_once`
        // covers the store pass alone.
        let s3 = Arc::new(FakeS3::new(Vec::new(), true));
        let prefix = crate::db::test_prefix("gc-wal-listed");
        let inner = Arc::new(InMemory::new()) as Arc<dyn object_store::ObjectStore>;
        let handle = crate::db::build_test_store_new_session(Arc::clone(&inner), &prefix).await;
        let store = FsStore::new(handle);
        let policy = PolicyEngine::init_s3(build_test_store(&format!("{prefix}-p")).await).await?;
        let engine = FsEngine::from_parts(store, s3, "b".into(), policy.authorizer());

        // A real write through the store. The write announces a `WAL`
        // object, and the manifest lists the full prefixed id of that
        // object.
        engine
            .store
            .save_file(&FileRecord {
                id: "live".into(),
                name: "l.txt".into(),
                mimetype: "text/plain".into(),
                size: 1,
                s3_key: "files/live".into(),
                owner_sub: "alice".into(),
                created_at: chrono::Utc::now().timestamp(),
            })
            .await?;

        // The ids come from the manifest in the backend. Each id must name
        // an object that the backend holds now.
        let listed = listed_wal_ids(&inner, &prefix).await;
        assert!(
            !listed.is_empty(),
            "the write through the store listed no WAL object, so the test proves nothing"
        );
        for id in &listed {
            assert!(
                inner
                    .get(&object_store::path::Path::from(id.as_str()))
                    .await
                    .is_ok(),
                "the listed WAL object {id} is not in the backend, so the test proves nothing"
            );
        }

        // The unlisted object of this scope. Only this object is a target
        // of the pass.
        let orphan = format!("{prefix}/e000001/wal/00009999.log");
        put_object(&inner, &orphan).await;

        assert_eq!(sweep_once(&engine).await?, 0, "the sweep deleted an item");
        assert!(
            inner
                .get(&object_store::path::Path::from(orphan.as_str()))
                .await
                .is_err(),
            "the sweep kept an unlisted store WAL object"
        );
        // Every listed object holds an acknowledged write. The backend is
        // the check, and not the memtable of the store.
        for id in &listed {
            assert!(
                inner
                    .get(&object_store::path::Path::from(id.as_str()))
                    .await
                    .is_ok(),
                "the sweep deleted the listed WAL object {id} and lost an acknowledged write"
            );
        }
        Ok(())
    }

    /// A fenced store must reclaim nothing. The pass must keep every
    /// object.
    ///
    /// `gc_orphans` returns 0 when the ownership record of the prefix
    /// names another session. The current owner can hold a `WAL` object in
    /// flight. The owner puts the object, then the owner lists the object.
    /// No manifest lists the object during that window. A stale session and a
    /// stale manifest would then delete a live write. The pass treats its
    /// fenced branch as a safety condition, not an optimization.
    ///
    /// The test fences the store for real. A second session over the same
    /// prefix and the same backend runs the epoch CAS. That is what a
    /// second writer does. The test then proves that a second writer fences
    /// the store. The assertions below would otherwise succeed for a store that
    /// no second writer ever reached.
    #[tokio::test]
    async fn the_pass_reclaims_no_object_from_a_fenced_store() -> anyhow::Result<()> {
        use object_store::ObjectStore as _;
        use object_store::memory::InMemory;

        let prefix = crate::db::test_prefix("gc-wal-fenced");
        let inner = Arc::new(InMemory::new()) as Arc<dyn object_store::ObjectStore>;
        let handle = crate::db::build_test_store_new_session(Arc::clone(&inner), &prefix).await;
        // A latch of this test. The write below records a fencing loss,
        // so the process wide latch must stay out of this test.
        let latch: &'static crate::fencing::Latch =
            Box::leak(Box::new(crate::fencing::Latch::new()));
        let store = FsStore::primary_with_latch(handle, latch);
        let policy = PolicyEngine::init_s3(build_test_store(&format!("{prefix}-p")).await).await?;
        let s3 = Arc::new(FakeS3::new(Vec::new(), true));
        let engine = FsEngine::from_parts(store, s3, "b".into(), policy.authorizer());

        // A real write before the takeover. The manifest lists the `WAL`
        // object of that write.
        engine
            .store
            .save_file(&FileRecord {
                id: "live".into(),
                name: "l.txt".into(),
                mimetype: "text/plain".into(),
                size: 1,
                s3_key: "files/live".into(),
                owner_sub: "alice".into(),
                created_at: chrono::Utc::now().timestamp(),
            })
            .await?;
        let listed = listed_wal_ids(&inner, &prefix).await;
        assert!(
            !listed.is_empty(),
            "the write through the store listed no WAL object, so the test proves nothing"
        );
        let orphan = format!("{prefix}/e000001/wal/00009999.log");
        put_object(&inner, &orphan).await;

        // A second session takes the epoch of the prefix. The holder must
        // outlive the call below.
        let _holder = crate::db::build_test_store_new_session(Arc::clone(&inner), &prefix).await;

        // The store lost the epoch. A write on it fails now, so the test
        // knows that the pass below runs on a fenced store.
        let err = engine
            .store
            .save_file(&FileRecord {
                id: "after-takeover".into(),
                name: "a.txt".into(),
                mimetype: "text/plain".into(),
                size: 1,
                s3_key: "files/after-takeover".into(),
                owner_sub: "alice".into(),
                created_at: chrono::Utc::now().timestamp(),
            })
            .await
            .expect_err("a write on a fenced store must fail");
        assert!(
            err.is_fencing_loss(),
            "the store was not fenced, so the test proves nothing: {err:?}"
        );

        assert_eq!(
            engine.store.gc_wal_orphans().await?,
            0,
            "a fenced store must report no reclaimed object"
        );
        // The unlisted object stays as well. A fenced pass reaches no
        // object, listed or unlisted.
        assert!(
            inner
                .get(&object_store::path::Path::from(orphan.as_str()))
                .await
                .is_ok(),
            "a fenced pass deleted an unlisted object"
        );
        for id in &listed {
            assert!(
                inner
                    .get(&object_store::path::Path::from(id.as_str()))
                    .await
                    .is_ok(),
                "a fenced pass deleted the listed WAL object {id}"
            );
        }
        Ok(())
    }
}
