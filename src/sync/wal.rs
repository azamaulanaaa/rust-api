//! Durable change feed on S3: the [`ChangeSink`] implementation behind
//! every replica.
//!
//! The op vocabulary ([`WalOp`], [`WalEntry`],
//! [`FileRecord`](crate::records::FileRecord)) lives in
//! [`crate::records`] so that `fs` and `policy` can announce changes
//! without depending on this module. Only the storage lives here.

use std::sync::Arc;

use async_trait::async_trait;
use oxkv::{GetSet, OxKvStore, Store as _, Transaction as _};
use tokio::sync::RwLock;

use crate::fs::error::FsError;
use crate::records::{ChangeSink, WalEntry, WalOp};

/// The master change-feed prefix this store writes to, named in the
/// fencing-loss log line so an operator can tell which prefix died.
const WAL_PREFIX: &str = "{db}/wal";

/// WAL stored in an [`OxKvStore`] (per-user S3, scalable).
///
/// Clones share the append mutex: concurrent appends from any handle
/// serialize, so sequence numbers stay gap-free and no entry is lost.
#[derive(Clone)]
pub struct Wal {
    store: Arc<RwLock<OxKvStore>>,
    append_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Wal {
    /// Creates a WAL from an [`OxKvStore`].
    pub fn new(s3_store: OxKvStore) -> Self {
        Self {
            store: Arc::new(RwLock::new(s3_store)),
            append_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn seq_key() -> &'static str {
        "wal:seq"
    }

    fn entry_key(seq: u64) -> String {
        format!("wal:{seq:020}")
    }

    /// Append an operation, returns the new sequence.
    ///
    /// Serialized against concurrent appends on any clone sharing this
    /// handle's mutex. The entry and the head pointer commit in one
    /// transaction, so a crash can never leave an entry without its head
    /// (or a head without its entry): the next append reuses the same
    /// sequence instead of skipping it.
    async fn append_entry(&self, op: WalOp) -> Result<u64, FsError> {
        let result = self.append_entry_locked(op).await;
        if let Err(e) = &result
            && e.is_fencing_loss()
        {
            // The WAL lives on the master change-feed prefix, so losing it is
            // terminal for this process -- the same condition `fs` and
            // `policy` report. Replica build races land on a per-user prefix
            // and are not fenced through here.
            crate::fencing::note_primary_loss(WAL_PREFIX, e.detail());
        }
        result
    }

    async fn append_entry_locked(&self, op: WalOp) -> Result<u64, FsError> {
        let _guard = self.append_lock.lock().await;
        let g = self.store.write().await;
        // Absent means the feed is empty, and only absent means that. A
        // value that is present and will not decode is a damaged head
        // pointer, and treating it as "empty" is not a recovery: the next
        // sequence becomes 1 and `set_bytes` OVERWRITES `wal:{...001}`,
        // the first entry the feed has. Every replica that had applied
        // 1..N then reads `range(1, 1)`, gets one op, and mis-applies it,
        // while `head()` -- the only other reader of this key -- is the
        // one that complains, and only after the damage.
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

    /// Range `from..=to` inclusive.
    ///
    /// Missing or undecodable entries are corruption: atomic appends keep
    /// `1..=head` fully populated, so a gap means entries were lost, not
    /// merely delayed. Gaps error instead of being skipped — replaying
    /// past them would silently drop mutations — and callers fall back to
    /// a full rebuild.
    ///
    /// So does `from > to`. That range is empty for exactly one reason --
    /// the head is behind where the reader already is -- and reporting it
    /// as `Ok(vec![])` reports "no new mutations" for a feed that has lost
    /// the ones this reader depends on, leaving it permanently stale with
    /// nothing logged and no rebuild triggered. Every other inconsistency
    /// in this function is loud; this one used to be the exception. A
    /// caller that has nothing to read has `from == to + 1` only when the
    /// feed is empty, and should read nothing rather than guess.
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

/// The only reason `fs` and `policy` know anything about replicas.
///
/// `ChangeSink` is one method, so a producer can be handed this trait
/// object without a compile-time path to `sync::wal`, `sync::snapshot`,
/// or anything else in `sync`.
///
/// The sequence number is dropped here. No caller used it, and handing
/// one out would invite a producer to treat its own append as a
/// replication guarantee. A caller that needs the head can ask
/// [`Wal::head`] — that is the value replicas compare coverage against.
#[async_trait]
impl ChangeSink for Wal {
    async fn append(&self, op: WalOp) -> anyhow::Result<()> {
        // `FsError`'s `Display` is already the sanitized text, so a fencing
        // loss reaches the producer as an opaque cause it has no way to act
        // on.
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

        // Deleted entry: gap errors instead of silently replaying past it.
        let key1 = format!("wal:{:020}", 1);
        wal.store.write().await.delete(&key1).await?;
        assert!(wal.range(1, 2).await.is_err());
        // Untouched suffix still reads.
        assert_eq!(wal.range(2, 2).await?.len(), 1);

        // Corrupt payload errors as well.
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

        // Legacy payload (object only) still deserializes.
        let legacy = serde_json::to_vec(&WalOp::PolicyAdd { obj: "x".into() })?;
        let back: WalOp = serde_json::from_slice(&legacy)?;
        assert!(back.is_legacy_policy_mark());
        Ok(())
    }

    /// A damaged head pointer must fail the append, not rewind the feed.
    ///
    /// The head was read with `.and_then(|b| from_slice(&b).ok()).unwrap_or(0)`,
    /// which folds "no head pointer" and "head pointer is garbage" into the
    /// same value. The second is not an empty feed: the next append takes
    /// `seq = 1` and `set_bytes` overwrites `wal:{...001}`. A replica that
    /// had applied 1..N then reads `range(1, 1)`, applies one op, and moves
    /// on believing it is current.
    ///
    /// Every other reader of this key treats a decode failure as an error --
    /// `head()` returns `Err(FsError::Internal)` for exactly this value --
    /// so after the rewind `head()` and the entries on disk disagree and
    /// only `head()` complains. The append path was the one place that
    /// could not tell them apart.
    ///
    /// Asserts both halves: the append is refused, and entry 1 is still the
    /// op that was written first.
    #[tokio::test]
    async fn a_corrupt_head_pointer_fails_the_append_instead_of_rewinding() -> anyhow::Result<()> {
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

        // Once the pointer is repaired the feed resumes where it left off,
        // rather than having lost entries 1..=2.
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
    /// This is the shape a replica asks for once the head has gone
    /// backwards: it has applied up to N, `range(N+1, head)` comes back
    /// empty, and it concludes nothing happened. The module doc promises
    /// gaps "error instead of being skipped" precisely so the caller
    /// falls back to a full rebuild; this path returned `Ok(vec![])` and
    /// reported corruption as success, silently and with no log.
    #[tokio::test]
    async fn a_range_past_the_head_is_an_error_not_an_empty_feed() -> anyhow::Result<()> {
        let wal = test_wal().await;
        wal.append(WalOp::GroupDelete { group: "g".into() }).await?;
        wal.append(WalOp::GroupDelete { group: "h".into() }).await?;
        assert_eq!(wal.head().await?, 2);

        // A replica that applied 1..=2 asking for what is left of the feed
        // after the head rewound to 1.
        let err = wal
            .range(3, 1)
            .await
            .expect_err("a backwards head was reported as no new mutations");
        assert!(
            err.to_string().contains("internal"),
            "unhelpful error: {err}"
        );

        // The feed itself is untouched by the refusal, so a repaired head
        // still reads back the whole thing.
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
}
