//! Shared change-feed vocabulary.
//!
//! # Why this module exists
//!
//! `fs` and `policy` *emit* changes; `sync` *consumes* them. Both sides
//! need the same types, and there is no third domain that owns them — so
//! the two arrangements that avoid a new module are both worse:
//!
//! - `fs` importing `WalOp` from `sync::wal`, while `sync` imports
//!   `FileRecord` back from `fs::store`, is a dependency cycle. A cycle
//!   cannot be enforced by the compiler, so "sync is above fs" survives
//!   only as a comment, and every new cross-domain type has to be placed
//!   by whoever notices first.
//! - Putting the feed in `fs` would make "the file store happens to own
//!   the change log" look intentional, and `sync` would then depend on
//!   `fs` for two unrelated reasons.
//!
//! So the vocabulary sits here, in a module that depends on nothing inside
//! the crate. The graph becomes a DAG:
//!
//! ```text
//!        records
//!        /     \
//!   fs, policy   sync
//!        \     /
//!      (fs::store, the write path)
//! ```
//!
//! `fs` and `policy` see only [`ChangeSink`](crate::records::ChangeSink) —
//! they emit and forget.
//! `sync` owns the durable implementation ([`Wal`](crate::sync::wal::Wal))
//! and the replica machinery. Neither has to know the other exists.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Persisted file record after a completed upload.
///
/// Lives here rather than in [`fs::store`](crate::fs::store) because it is
/// part of the feed contract: [`WalOp::FileCreate`] carries a full record
/// so a replica can re-apply the op without reading the master.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    /// File identifier.
    pub id: String,
    /// Original filename.
    pub name: String,
    /// MIME type.
    pub mimetype: String,
    /// Size in bytes.
    pub size: u64,
    /// S3 key.
    pub s3_key: String,
    /// Owner subject.
    pub owner_sub: String,
    /// Creation timestamp.
    pub created_at: i64,
}

/// Operation recorded in the change feed.
///
/// File and relation ops carry enough payload to re-apply against a
/// replica (`FileCreate` embeds the full record). Rich policy ops carry
/// the full rule/link so replay can resync only the affected user/row;
/// legacy `PolicyAdd`/`PolicyRemove` (object only) always fall back to a
/// full rebuild.
///
/// **Wire format.** This is `serde`-encoded into a durable log, so variants
/// may be added but existing ones must not change shape: an older reader
/// fails to decode a newer entry, and [`Wal`](crate::sync::wal::Wal)
/// treats an undecodable entry as corruption rather than skipping it. Add
/// a variant with `#[serde(default)]` fields where that is safe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalOp {
    /// Legacy policy mark (object only, pre-rich WAL).
    ///
    /// Kept for reading WALs written before rich ops existed; new code
    /// never writes it. Replay treats it as needing a full recalc.
    PolicyAdd {
        /// Object affected.
        obj: String,
    },
    /// Legacy policy mark (object only, pre-rich WAL).
    ///
    /// Kept for reading WALs written before rich ops existed; new code
    /// never writes it. Replay treats it as needing a full recalc.
    PolicyRemove {
        /// Object affected.
        obj: String,
    },
    /// Permission rule added (`p = sub, obj, act`).
    PolicyRuleAdd {
        /// Rule subject (user or group).
        sub: String,
        /// Rule object (`{row_type}:{row_id}` for rows).
        obj: String,
        /// Rule action (`read`/`write`/`delete`/`execute`).
        act: String,
    },
    /// Permission rule removed (`p = sub, obj, act`).
    PolicyRuleRemove {
        /// Rule subject (user or group).
        sub: String,
        /// Rule object (`{row_type}:{row_id}` for rows).
        obj: String,
        /// Rule action (`read`/`write`/`delete`/`execute`).
        act: String,
    },
    /// Group membership added (`g = user, group`).
    GroupAdd {
        /// Member subject.
        user: String,
        /// Group joined.
        group: String,
    },
    /// Group membership removed (`g = user, group`).
    GroupRemove {
        /// Member subject.
        user: String,
        /// Group left.
        group: String,
    },
    /// Group deleted (every membership link to `group` removed).
    GroupDelete {
        /// Group removed.
        group: String,
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
    /// File metadata created (completed upload).
    FileCreate {
        /// Full record as persisted on master.
        rec: FileRecord,
    },
    /// File metadata deleted.
    FileDelete {
        /// File identifier.
        file_id: String,
    },
}

impl WalOp {
    /// True for any policy-shape op (legacy or rich).
    pub fn is_policy_op(&self) -> bool {
        matches!(
            self,
            Self::PolicyAdd { .. }
                | Self::PolicyRemove { .. }
                | Self::PolicyRuleAdd { .. }
                | Self::PolicyRuleRemove { .. }
                | Self::GroupAdd { .. }
                | Self::GroupRemove { .. }
                | Self::GroupDelete { .. }
        )
    }

    /// True for legacy object-only marks that cannot replay incrementally.
    pub fn is_legacy_policy_mark(&self) -> bool {
        matches!(self, Self::PolicyAdd { .. } | Self::PolicyRemove { .. })
    }
}

/// One entry in the durable feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    /// Monotonic sequence.
    pub seq: u64,
    /// Operation.
    pub op: WalOp,
    /// Timestamp.
    pub ts: i64,
}

/// A change feed rejected an append.
///
/// Deliberately opaque: the producer is `fs` or `policy`, which has no
/// business knowing whether the failure was a store error, a fencing loss,
/// or a serialization problem. [`Wal`](crate::sync::wal::Wal) maps its own
/// [`FsError`](crate::fs::error::FsError) into this, and `fs`/`policy` map
/// it back on the way out. The detail is carried as a string for logs.
#[derive(Debug, Clone, thiserror::Error)]
#[error("change feed append failed: {0}")]
pub struct ChangeError(String);

impl ChangeError {
    /// Wraps a store-layer error for the producer.
    pub fn new(detail: impl std::fmt::Display) -> Self {
        Self(detail.to_string())
    }

    /// The underlying detail, for server-side logs.
    pub fn detail(&self) -> &str {
        &self.0
    }
}

/// Where committed mutations are announced.
///
/// The seam that keeps `fs` and `policy` out of `sync`. Producers append
/// after a mutation commits and treat a failure as fatal to the mutation
/// (fail-closed): if the feed misses a write, replicas silently diverge
/// from the master with nothing to replay.
///
/// Implementations must serialize concurrent appends so sequence numbers
/// stay gap-free. The durable implementation is
/// [`Wal`](crate::sync::wal::Wal).
#[async_trait]
pub trait ChangeSink: Send + Sync {
    /// Appends one operation, returning only once it is durable.
    async fn append(&self, op: WalOp) -> Result<(), ChangeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The feed is a wire format. A round trip has to preserve the op
    /// exactly, because `Wal::range` treats any mismatch as corruption
    /// rather than skipping the entry.
    #[test]
    fn ops_round_trip_through_the_wire_format() {
        let ops = [
            WalOp::FileCreate {
                rec: FileRecord {
                    id: "f1".into(),
                    name: "a.txt".into(),
                    mimetype: "text/plain".into(),
                    size: 7,
                    s3_key: "files/f1".into(),
                    owner_sub: "alice".into(),
                    created_at: 42,
                },
            },
            WalOp::PolicyRuleAdd {
                sub: "editors".into(),
                obj: "invoice:1".into(),
                act: "read".into(),
            },
            WalOp::GroupDelete {
                group: "editors".into(),
            },
            WalOp::PolicyAdd {
                obj: "legacy".into(),
            },
        ];
        for op in ops {
            let bytes = serde_json::to_vec(&op).expect("serializes");
            let back: WalOp = serde_json::from_slice(&bytes).expect("deserializes");
            assert_eq!(back, op);
        }
    }

    #[test]
    fn op_classification_is_exhaustive() {
        assert!(WalOp::PolicyAdd { obj: "x".into() }.is_policy_op());
        assert!(WalOp::PolicyAdd { obj: "x".into() }.is_legacy_policy_mark());
        assert!(WalOp::GroupDelete { group: "g".into() }.is_policy_op());
        assert!(!WalOp::GroupDelete { group: "g".into() }.is_legacy_policy_mark());
        assert!(
            !WalOp::FileDelete {
                file_id: "f".into()
            }
            .is_policy_op()
        );
    }

    #[test]
    fn change_error_keeps_detail_for_logs() {
        let err = ChangeError::new("epoch 7 superseded");
        assert!(err.to_string().contains("epoch 7 superseded"));
        assert_eq!(err.detail(), "epoch 7 superseded");
    }

    /// Reads a source file's *production* code: everything before the
    /// top-level `#[cfg(test)]` module, with comment lines dropped.
    fn production_source(path: &str) -> String {
        let src = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let mut out = String::new();
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            // A column-0 `#[cfg(test)]` opens the test module; everything
            // from there on is test-only, and tests legitimately reach
            // across the boundary to build fixtures.
            if trimmed == "#[cfg(test)]" {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// The whole point of this module: `fs` and `policy` must not depend on
    /// `sync`.
    ///
    /// They announce changes through [`ChangeSink`] precisely so the
    /// dependency does not exist. Without this test the edge creeps back
    /// one `use` at a time, and once it is back the graph is a cycle again
    /// -- which no compiler will tell you about, because Rust permits
    /// cycles between modules freely. Only the layering is at stake, and
    /// layering is exactly what nothing else enforces.
    ///
    /// Test modules are excluded because they legitimately construct a
    /// `Wal` to check that announcements are durable.
    #[test]
    fn producers_do_not_depend_on_the_consumer() {
        for file in [
            "src/fs/mod.rs",
            "src/fs/store.rs",
            "src/fs/gc.rs",
            "src/fs/route.rs",
            "src/fs/model.rs",
            "src/fs/s3.rs",
            "src/fs/token.rs",
            "src/fs/relation.rs",
            "src/fs/error.rs",
            "src/fs/object_store.rs",
            "src/policy/mod.rs",
            "src/policy/route.rs",
            "src/policy/setup.rs",
            "src/policy/adapter.rs",
            "src/policy/admin.rs",
            "src/policy/row.rs",
        ] {
            let src = production_source(file);
            assert!(
                !src.contains("crate::sync"),
                "{file} imports `crate::sync` in production code, re-creating the \
                 fs/policy <-> sync cycle. Announce changes through \
                 `crate::records::ChangeSink` instead."
            );
        }
    }

    /// The pivot must stay a leaf. If `records` grew a dependency on
    /// `fs`, `policy`, or `sync`, the cycle would just move rather than
    /// disappear.
    #[test]
    fn this_module_depends_on_nothing_in_the_crate() {
        let src = production_source("src/records.rs");
        for forbidden in ["crate::fs", "crate::policy", "crate::sync", "crate::http"] {
            assert!(
                !src.contains(forbidden),
                "src/records.rs references {forbidden}; it must stay a leaf so the \
                 change-feed vocabulary can be depended on without cycles"
            );
        }
    }
}
