//! File-based WAL for master changes.
//!
//! Stored in same `Redb` file under `wal:{seq}` with `wal:seq` head.
//! Migratable to `S3` backend when `oxkv` ships it.

use oxkv::GetSet;
use serde::{Deserialize, Serialize};

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

/// File-based WAL stored in a `Redb` file.
#[derive(Clone)]
pub struct Wal {
    store: std::sync::Arc<tokio::sync::RwLock<oxkv::RedbStore>>,
}

impl Wal {
    /// Open or create WAL file at `path`.
    pub async fn open(path: &std::path::Path) -> Result<Self, FsError> {
        if let Some(p) = path.parent()
            && !p.as_os_str().is_empty()
        {
            std::fs::create_dir_all(p).map_err(|e| FsError::Internal(e.to_string()))?;
        }
        let store = oxkv::RedbStore::new_file(path).map_err(|e| FsError::Store(e.to_string()))?;
        Ok(Self {
            store: std::sync::Arc::new(tokio::sync::RwLock::new(store)),
        })
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tmp_path() -> std::path::PathBuf {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        std::env::temp_dir().join(format!(
            "wal-test-{}-{}.redb",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(rand::random::<[u8; 8]>()),
        ))
    }

    #[tokio::test]
    async fn append_and_range() -> anyhow::Result<()> {
        let path = tmp_path();
        let _ = std::fs::remove_file(&path);
        let wal = Wal::open(&path).await?;
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
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}
