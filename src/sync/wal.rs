//! Durable change feed on S3. This module provides the [`ChangeSink`]
//! implementation behind every replica.
//!
//! The op vocabulary ([`WalOp`], [`WalEntry`],
//! [`FileRecord`](crate::records::FileRecord)) lives in
//! [`crate::records`]. That way `fs` and `policy` announce changes without
//! depending on this module. Only the storage lives here.

use std::sync::Arc;

use async_trait::async_trait;
use oxkv::{GetSet, OxKvStore, Store as _, Transaction as _};
use tokio::sync::RwLock;

use crate::fencing::Latch;
use crate::fs::error::FsError;
use crate::records::{ChangeSink, WalEntry, WalOp};

/// The master change-feed prefix. The store writes to this prefix. The
/// fencing-loss log line names it so that an operator can tell which prefix
/// died.
const WAL_PREFIX: &str = "{db}/wal";

/// WAL stored in an [`OxKvStore`]. The store is per-user on S3 and scales.
///
/// Clones share the append mutex. Appends from any handle run one at a
/// time. Sequence numbers stay gap-free, and no entry is lost.
#[derive(Clone)]
pub struct Wal {
    store: Arc<RwLock<OxKvStore>>,
    append_lock: Arc<tokio::sync::Mutex<()>>,
    /// Where a lost epoch on the master change-feed prefix is recorded.
    ///
    /// In production the WAL uses the process-wide latch (see
    /// [`process_latch`](crate::fencing::process_latch)). A test can point
    /// its own WAL at a private [`Latch`](crate::fencing::Latch) through
    /// [`with_latch`](Self::with_latch).
    ///
    /// This field holds the latch instead of calling the free
    /// [`note_primary_loss`](crate::fencing::note_primary_loss), so the latch
    /// travels with the feed that owns the prefix. The `FsStore` field uses
    /// the same reasoning. `PRIMARY_LOSS` is one-way and has no reset. The
    /// first test to trip it then satisfies any assertion against it. Every
    /// test binary this crate runs trips it.
    latch: &'static Latch,
}

impl Wal {
    /// Creates a WAL from an [`OxKvStore`].
    pub fn new(s3_store: OxKvStore) -> Self {
        Self {
            store: Arc::new(RwLock::new(s3_store)),
            append_lock: Arc::new(tokio::sync::Mutex::new(())),
            latch: crate::fencing::process_latch(),
        }
    }

    /// Records fencing losses on `latch` instead of the process-wide one.
    ///
    /// This method mirrors `FsStore::primary_with_latch` and
    /// `PolicyEngine::with_latch`. The process latch is one-way and global.
    /// An assertion against it passes even if the code under test never
    /// latched.
    #[cfg(test)]
    pub(crate) fn with_latch(mut self, latch: &'static Latch) -> Self {
        self.latch = latch;
        self
    }

    fn seq_key() -> &'static str {
        "wal:seq"
    }

    fn entry_key(seq: u64) -> String {
        format!("wal:{seq:020}")
    }

    /// Appends an operation and returns the new sequence.
    ///
    /// Appends from any clone that shares this handle mutex run one at a
    /// time. The entry and the head pointer commit in one transaction. A
    /// crash cannot leave an entry without its head, and it cannot leave a
    /// head without its entry. The next append then reuses the same
    /// sequence instead of skipping it.
    async fn append_entry(&self, op: WalOp) -> Result<u64, FsError> {
        let result = self.append_entry_locked(op).await;
        if let Err(e) = &result
            && e.is_fencing_loss()
        {
            // The WAL lives on the master change-feed prefix, so losing it
            // stops this process. The `fs` and `policy` modules report the
            // same condition. Replica build races land on a per-user prefix
            // and are not fenced here.
            self.latch.trip(WAL_PREFIX, e.detail());
        }
        result
    }

    async fn append_entry_locked(&self, op: WalOp) -> Result<u64, FsError> {
        let _guard = self.append_lock.lock().await;
        let g = self.store.write().await;
        // An absent head means an empty feed, and only absence means that. A
        // present value that will not decode means a damaged head pointer.
        // Treating it as "empty" is not a recovery. The next sequence becomes
        // 1. Then `set_bytes` overwrites `wal:{...001}`, the first entry of
        // the feed. Every replica that applied 1..N reads `range(1, 1)` and
        // gets one op. It then applies the wrong op. Only `head()` reads this
        // key, and it complains after the damage.
        let cur = match g.get_bytes(Self::seq_key()).await.map_err(FsError::from)? {
            None => 0,
            Some(b) => serde_json::from_slice::<u64>(&b)
                .map_err(|e| FsError::Internal(format!("wal head pointer is undecodable: {e}")))?,
        };
        let seq = cur + 1;
        let entry = WalEntry {
            seq,
            op,
            ts: chrono::Utc::now().timestamp(),
        };
        let val = serde_json::to_vec(&entry).map_err(|e| FsError::Internal(e.to_string()))?;
        let seq_val = serde_json::to_vec(&seq).map_err(|e| FsError::Internal(e.to_string()))?;
        let tx = g.begin_tx().map_err(FsError::from)?;
        tx.set_bytes(&Self::entry_key(seq), &val)
            .await
            .map_err(FsError::from)?;
        tx.set_bytes(Self::seq_key(), &seq_val)
            .await
            .map_err(FsError::from)?;
        tx.commit().await.map_err(FsError::from)?;
        Ok(seq)
    }

    /// Current head seq.
    pub async fn head(&self) -> Result<u64, FsError> {
        let g = self.store.read().await;
        let Some(b) = g.get_bytes(Self::seq_key()).await.map_err(FsError::from)? else {
            return Ok(0);
        };
        serde_json::from_slice(&b).map_err(|e| FsError::Internal(e.to_string()))
    }

    /// Returns the entries from `from` to `to`. The range includes both ends.
    ///
    /// A missing or undecodable entry means corruption. Atomic appends keep
    /// `1..=head` complete, so a gap means that the store lost entries. A
    /// delay cannot make a gap. A gap returns an error instead of a skip,
    /// because a replay past it drops mutations without a trace. The caller
    /// then falls back to a full rebuild.
    ///
    /// `from > to` returns an error for the same reason. That range is empty
    /// for exactly one condition. The head sits behind the position that the
    /// reader already applied. `Ok(vec![])` would report "no new mutations"
    /// for a feed that lost the mutations this reader needs. The reader then
    /// stays stale for the life of the process. Nothing logs the fault, and
    /// no rebuild starts. Every other inconsistency in this function returns
    /// an error loudly. This one used to be the exception. A caller with
    /// nothing to read uses `from == to + 1`. That value means the feed is
    /// empty. The caller must read nothing and must not guess.
    pub async fn range(&self, from: u64, to: u64) -> Result<Vec<WalEntry>, FsError> {
        if from > to {
            return Err(FsError::Store(format!(
                "wal range {from}..={to} runs backwards: the head cannot be behind a reader \
                 that has applied {from}"
            )));
        }
        let g = self.store.read().await;
        let mut out = Vec::new();
        for seq in from..=to {
            let Some(b) = g
                .get_bytes(&Self::entry_key(seq))
                .await
                .map_err(FsError::from)?
            else {
                return Err(FsError::Store(format!("wal entry {seq} missing")));
            };
            let entry: WalEntry = serde_json::from_slice(&b)
                .map_err(|e| FsError::Internal(format!("wal entry {seq} undecodable: {e}")))?;
            if entry.seq != seq {
                return Err(FsError::Internal(format!(
                    "wal entry {seq} holds sequence {}",
                    entry.seq
                )));
            }
            out.push(entry);
        }
        Ok(out)
    }
}

/// The only reason `fs` and `policy` know about replicas.
///
/// `ChangeSink` declares one method, so a producer receives this trait
/// object without a compile-time path to `sync::wal`, `sync::snapshot`,
/// or anything else in `sync`.
///
/// The sequence number is dropped here. No caller used it. Handing the
/// number to a producer would let the producer treat its own append as a
/// replication guarantee. A caller that needs the head can ask
/// [`Wal::head`]. Replicas compare their coverage against that value.
#[async_trait]
impl ChangeSink for Wal {
    async fn append(&self, op: WalOp) -> anyhow::Result<()> {
        // `FsError` uses `Display` to produce sanitized text. A fencing loss
        // reaches the producer as an opaque cause. The producer has no way to
        // act on that cause.
        self.append_entry(op)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::build_test_store;

    async fn test_wal() -> Wal {
        let s3 = build_test_store(&crate::db::test_prefix("wal")).await;
        Wal::new(s3)
    }

    #[tokio::test]
    async fn append_and_range() -> anyhow::Result<()> {
        let wal = test_wal().await;
        assert_eq!(wal.head().await?, 0);
        wal.append(WalOp::Attach {
            row_type: "invoice".into(),
            row_id: "1".into(),
            file_id: "f1".into(),
        })
        .await?;
        wal.append(WalOp::Detach {
            row_type: "invoice".into(),
            row_id: "1".into(),
            file_id: "f1".into(),
        })
        .await?;
        assert_eq!(wal.head().await?, 2);
        let r = wal.range(1, 2).await?;
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].seq, 1);
        Ok(())
    }

    #[tokio::test]
    async fn range_fails_loudly_on_gaps_and_garbage() -> anyhow::Result<()> {
        let wal = test_wal().await;
        let op = || WalOp::Attach {
            row_type: "t".into(),
            row_id: "1".into(),
            file_id: "f".into(),
        };
        wal.append(op()).await?;
        wal.append(op()).await?;
        assert_eq!(wal.range(1, 2).await?.len(), 2);

        // A deleted entry makes the range return an error. The range does
        // not skip past it.
        let key1 = format!("wal:{:020}", 1);
        wal.store.write().await.delete(&key1).await?;
        assert!(wal.range(1, 2).await.is_err());
        // The untouched suffix still reads.
        assert_eq!(wal.range(2, 2).await?.len(), 1);

        // A corrupt payload also returns an error.
        let key2 = format!("wal:{:020}", 2);
        wal.store
            .write()
            .await
            .set_bytes(&key2, b"not json")
            .await?;
        assert!(wal.range(2, 2).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn rich_policy_ops_roundtrip_and_classify() -> anyhow::Result<()> {
        let wal = test_wal().await;
        wal.append(WalOp::PolicyRuleAdd {
            sub: "editors".into(),
            obj: "invoice:1".into(),
            act: "read".into(),
        })
        .await?;
        wal.append(WalOp::GroupAdd {
            user: "alice".into(),
            group: "editors".into(),
        })
        .await?;
        wal.append(WalOp::PolicyAdd { obj: "doc".into() }).await?;
        let entries = wal.range(1, 3).await?;
        assert!(matches!(
            &entries[0].op,
            WalOp::PolicyRuleAdd { sub, obj, act }
            if sub == "editors" && obj == "invoice:1" && act == "read"
        ));
        assert!(!entries[0].op.is_legacy_policy_mark());
        assert!(entries[2].op.is_legacy_policy_mark());

        // A legacy payload names only an object. It still deserializes.
        let legacy = serde_json::to_vec(&WalOp::PolicyAdd { obj: "x".into() })?;
        let back: WalOp = serde_json::from_slice(&legacy)?;
        assert!(back.is_legacy_policy_mark());
        Ok(())
    }

    /// A damaged head pointer must fail the append and not rewind the feed.
    ///
    /// The old code read the head with
    /// `.and_then(|b| from_slice(&b).ok()).unwrap_or(0)`. That expression maps
    /// "no head pointer" and "head pointer is garbage" to one value. The
    /// second case is not an empty feed. The next append takes `seq = 1`, and
    /// `set_bytes` overwrites `wal:{...001}`. A replica that applied 1..N then
    /// reads `range(1, 1)`, applies one op, and moves on. The replica then
    /// believes that it is current.
    ///
    /// Every other reader of this key treats a decode failure as an error.
    /// `head()` returns `Err(FsError::Internal)` for exactly this value. After
    /// a rewind, `head()` and the entries on disk disagree, and only `head()`
    /// complains. The append path was the only place that could not tell them
    /// apart.
    ///
    /// The test checks both halves. The append is refused. Entry 1 still holds
    /// the op that the code wrote first.
    #[tokio::test]
    async fn a_corrupt_head_pointer_refuses_the_append() -> anyhow::Result<()> {
        let wal = test_wal().await;
        let op = |tag: &str| WalOp::Attach {
            row_type: "t".into(),
            row_id: tag.into(),
            file_id: "f".into(),
        };
        wal.append(op("first")).await?;
        wal.append(op("second")).await?;
        assert_eq!(wal.head().await?, 2);

        wal.store
            .write()
            .await
            .set_bytes("wal:seq", b"{\"head\":2}")
            .await?;
        // `head()` was always loud about this value.
        assert!(wal.head().await.is_err());

        // The append must refuse rather than allocate sequence 1 again.
        assert!(
            wal.append(op("third")).await.is_err(),
            "a damaged head pointer was read as an empty feed"
        );
        // Entry 1 is untouched: still the first op, still sequence 1.
        let first = wal.range(1, 1).await?;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].seq, 1);
        assert!(
            matches!(&first[0].op, WalOp::Attach { row_id, .. } if row_id == "first"),
            "the feed's first entry was overwritten: {:?}",
            first[0].op
        );

        // Once the code repairs the pointer, the feed resumes where it
        // stopped. It did not lose entries 1..=2.
        wal.store.write().await.set_bytes("wal:seq", b"2").await?;
        wal.append(op("third"))
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        assert_eq!(wal.head().await?, 3);
        let all = wal.range(1, 3).await?;
        assert_eq!(all.len(), 3);
        Ok(())
    }

    /// `range(from, to)` with `from > to` is corruption, not an empty feed.
    ///
    /// This is the range that a replica asks for after the head moves
    /// backwards. The replica applied entries up to N. Then `range(N+1, head)`
    /// returns an empty result. The replica then concludes that nothing
    /// changed. The module doc states that gaps "error instead of being
    /// skipped", so that the caller falls back to a full rebuild. This path
    /// returned `Ok(vec![])` instead. It reported corruption as success, with
    /// no log line.
    #[tokio::test]
    async fn a_backwards_range_is_an_error() -> anyhow::Result<()> {
        let wal = test_wal().await;
        wal.append(WalOp::GroupDelete { group: "g".into() }).await?;
        wal.append(WalOp::GroupDelete { group: "h".into() }).await?;
        assert_eq!(wal.head().await?, 2);

        // A replica that applied 1..=2 asks for the rest of the feed. The
        // head has rewound to 1.
        let err = wal
            .range(3, 1)
            .await
            .expect_err("a backwards head was reported as no new mutations");
        assert!(
            err.to_string().contains("internal"),
            "unhelpful error: {err}"
        );

        // The refusal does not touch the feed. A repaired head still reads
        // the whole feed.
        assert_eq!(wal.range(1, 2).await?.len(), 2);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_appends_keep_unique_seqs() -> anyhow::Result<()> {
        let wal = test_wal().await;
        let mut handles = Vec::new();
        for t in 0..8u32 {
            let w = wal.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..25u32 {
                    w.append(WalOp::Attach {
                        row_type: "t".into(),
                        row_id: t.to_string(),
                        file_id: "f".into(),
                    })
                    .await
                    .unwrap();
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(wal.head().await?, 200);
        let entries = wal.range(1, 200).await?;
        let mut seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
        seqs.sort_unstable();
        seqs.dedup();
        assert_eq!(seqs.len(), 200);
        Ok(())
    }

    /// A change-feed write that loses the epoch must latch. It must not
    /// only fail.
    ///
    /// This module holds the third of the three primary fencing trip
    /// points. The other two are `fs` at `FsStore` and `policy` at
    /// `PolicyEngine`. This trip point had no test at all. Only
    /// `note_primary_loss` reached the trip, and nothing here called it.
    ///
    /// The failure that this test guards is the one the `fencing` module
    /// docs describe. A fenced change-feed write keeps failing as a 500
    /// while `/ready` stays 200. The lease cannot see an uncooperative
    /// second writer. Replicas then stop receiving mutations on a server
    /// that reports itself healthy.
    ///
    /// The test drives a real `OxKvStore` into `StoreError::Fenced`. It
    /// opens a second session over the same prefix. That session CAS-bumps
    /// `ownership.json` and fences the first session. The `fs::store::tests::fenced_store`
    /// test uses the same technique. It is the only technique available
    /// here. `Wal::new` takes a concrete `OxKvStore`, so the code cannot
    /// take `policy::adapter::tests::FencedStore`, which wraps a
    /// `BTreeStore`. Using a real handle instead of a hand-built error is
    /// the point. The test proves that the real commit path classifies the
    /// error as a fencing loss.
    ///
    /// The seeding write comes first, and it matters. In some paths
    /// `oxkv` treats a write to a store with no keys as a no-op. The
    /// fencing check fires only after the code has something to commit.
    ///
    /// The latch is a private latch. `PRIMARY_LOSS` is one-way and has no
    /// reset. `fencing::tests` trips it without a condition. An assertion
    /// against the global latch would then pass even if this code never
    /// latched.
    #[tokio::test]
    async fn a_fenced_change_feed_write_latches() {
        let prefix = crate::db::test_prefix("wal-fenced");
        let inner = std::sync::Arc::new(object_store::memory::InMemory::new())
            as std::sync::Arc<dyn object_store::ObjectStore>;
        let handle =
            crate::db::build_test_store_new_session(std::sync::Arc::clone(&inner), &prefix).await;
        let latch: &'static Latch = Box::leak(Box::new(Latch::new()));
        let wal = Wal::new(handle).with_latch(latch);

        // Write through the handle under test first. The fenced commit
        // below needs a real entry to lose.
        wal.append(WalOp::Attach {
            row_type: "invoice".into(),
            row_id: "1".into(),
            file_id: "f1".into(),
        })
        .await
        .expect("the unfenced feed accepts an append");
        assert!(!latch.is_tripped(), "a live feed must not latch");

        // A second session over the same prefix takes the epoch. This is
        // what an uncooperative second writer does. The holder must outlive
        // the assertion. `oxkv` fences another handle only while the holder
        // is alive.
        let _holder =
            crate::db::build_test_store_new_session(std::sync::Arc::clone(&inner), &prefix).await;

        // Drive `append_entry` instead of the `ChangeSink` impl. That impl
        // flattens `FsError` into an opaque `anyhow` message for the
        // producer. The message carries no classification by design. The
        // sanitized text cannot show whether this was a fencing loss or a
        // flaky store. `append_entry` is the layer that decides, and the
        // latch check below reads it.
        let err = wal
            .append_entry(WalOp::Attach {
                row_type: "invoice".into(),
                row_id: "2".into(),
                file_id: "f2".into(),
            })
            .await
            .expect_err("a fenced commit cannot succeed");

        // The classification comes first. The producer turns it into a 500.
        assert!(
            err.is_fencing_loss(),
            "a fenced change-feed write must be typed as a fencing loss, got: {err:?}"
        );
        // The 500 carries the store reason. `detail()` keeps that reason.
        // `Display` sanitizes it to "internal server error". The producer
        // acts on the classification. The log line keeps the detail.
        assert!(
            err.detail().contains("fenced") || err.detail().contains("epoch"),
            "the store's fencing reason must survive to the log: {:?}",
            err.detail()
        );
        // The latch comes last. The latch takes the instance out of
        // rotation. Without the latch, the write fails forever. Meanwhile,
        // `/ready` keeps reporting 200.
        assert!(
            latch.is_tripped(),
            "a fenced change-feed write must latch the fencing signal; \
             otherwise the lease keeps reporting a healthy master while \
             every replica stops receiving mutations"
        );
    }
}
