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
use crate::records::{ChangeError, ChangeSink, WalEntry, WalOp};

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
        let cur = g
            .get_bytes(Self::seq_key())
            .await
            .map_err(FsError::from)?
            .and_then(|b| serde_json::from_slice::<u64>(&b).ok())
            .unwrap_or(0);
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
    pub async fn range(&self, from: u64, to: u64) -> Result<Vec<WalEntry>, FsError> {
        if from > to {
            return Ok(Vec::new());
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
    async fn append(&self, op: WalOp) -> Result<(), ChangeError> {
        // `ChangeError` is a string, so a fencing loss survives the trip
        // back to the producer intact -- which is the only thing that
        // matters, since the producer has no way to classify the cause.
        self.append_entry(op)
            .await
            .map(|_| ())
            .map_err(ChangeError::new)
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
