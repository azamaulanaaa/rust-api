//! WAL for master changes on S3.

use std::sync::Arc;

use oxkv::{GetSet, S3Store};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::fs::error::FsError;

/// Operation recorded in WAL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalOp {
    /// Policy rule added.
    PolicyAdd {
        /// Object affected.
        obj: String,
    },
    /// Policy rule removed.
    PolicyRemove {
        /// Object affected.
        obj: String,
    },
    /// File attached to row.
    Attach {
        /// Row type.
        row_type: String,
        /// Row identifier.
        row_id: String,
        /// File identifier.
        file_id: String,
    },
    /// File detached from row.
    Detach {
        /// Row type.
        row_type: String,
        /// Row identifier.
        row_id: String,
        /// File identifier.
        file_id: String,
    },
}

/// Entry in WAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    /// Monotonic sequence.
    pub seq: u64,
    /// Operation.
    pub op: WalOp,
    /// Timestamp.
    pub ts: i64,
}

/// WAL stored in an [`S3Store`] (per-user S3, scalable).
#[derive(Clone)]
pub struct Wal {
    store: Arc<RwLock<S3Store>>,
}

impl Wal {
    /// Creates a WAL from an [`S3Store`].
    pub fn new(s3_store: S3Store) -> Self {
        Self {
            store: Arc::new(RwLock::new(s3_store)),
        }
    }

    fn seq_key() -> &'static str {
        "wal:seq"
    }

    fn entry_key(seq: u64) -> String {
        format!("wal:{seq:020}")
    }

    /// Append an operation, returns new seq.
    pub async fn append(&self, op: WalOp) -> Result<u64, FsError> {
        let mut g = self.store.write().await;
        let cur = g
            .get_bytes(Self::seq_key())
            .await
            .map_err(|e| FsError::Store(e.to_string()))?
            .and_then(|b| serde_json::from_slice::<u64>(&b).ok())
            .unwrap_or(0);
        let seq = cur + 1;
        let entry = WalEntry {
            seq,
            op,
            ts: chrono::Utc::now().timestamp(),
        };
        let val = serde_json::to_vec(&entry).map_err(|e| FsError::Internal(e.to_string()))?;
        g.set_bytes(&Self::entry_key(seq), &val)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        let seq_val = serde_json::to_vec(&seq).map_err(|e| FsError::Internal(e.to_string()))?;
        g.set_bytes(Self::seq_key(), &seq_val)
            .await
            .map_err(|e| FsError::Store(e.to_string()))?;
        Ok(seq)
    }

    /// Current head seq.
    pub async fn head(&self) -> Result<u64, FsError> {
        let g = self.store.read().await;
        let Some(b) = g
            .get_bytes(Self::seq_key())
            .await
            .map_err(|e| FsError::Store(e.to_string()))?
        else {
            return Ok(0);
        };
        serde_json::from_slice(&b).map_err(|e| FsError::Internal(e.to_string()))
    }

    /// Range `from..=to` inclusive.
    pub async fn range(&self, from: u64, to: u64) -> Result<Vec<WalEntry>, FsError> {
        if from > to {
            return Ok(Vec::new());
        }
        let g = self.store.read().await;
        let mut out = Vec::new();
        for seq in from..=to {
            if let Some(b) = g
                .get_bytes(&Self::entry_key(seq))
                .await
                .map_err(|e| FsError::Store(e.to_string()))?
                && let Ok(e) = serde_json::from_slice::<WalEntry>(&b)
            {
                out.push(e);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::build_test_store;

    async fn test_wal() -> Wal {
        let prefix = {
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            format!(
                "test-wal-{}-{}",
                std::process::id(),
                URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
            )
        };
        let s3 = build_test_store(&prefix).await;
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
}
