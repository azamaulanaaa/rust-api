//! Shared vocabulary of the change feed.
//!
//! # Why this module exists
//!
//! `fs` and `policy` *emit* changes. `sync` *consumes* them. Both sides need
//! the same types. No third domain owns them. So both ways to avoid a new
//! module are worse:
//!
//! - `fs` imports `WalOp` from `sync::wal`, and `sync` imports `FileRecord`
//!   back from `fs::store`. That is a cycle. A compiler cannot enforce a
//!   cycle, so "sync is above fs" survives only as a comment. Every new type
//!   that crosses a domain then depends on who notices first.
//! - The feed goes in `fs`. That would make "the file store happens to own
//!   the change log" look like a decision. `sync` would then depend on `fs`
//!   for two reasons that have nothing to do with each other.
//!
//! So the vocabulary sits in this module. The module depends on nothing
//! inside the crate. The result is a directed acyclic graph:
//!
//! ```text
//!        records
//!        /     \
//!   fs, policy   sync
//!        \     /
//!      (fs::store, the write path)
//! ```
//!
//! `fs` and `policy` see only [`ChangeSink`](crate::records::ChangeSink).
//! They emit a change and forget it.
//! `sync` owns the durable implementation
//! ([`Wal`](crate::sync::wal::Wal)) and the replica machinery. Neither side
//! has to know that the other side exists.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// File record after an upload ends, as it is stored.
///
/// The type lives here, not in [`fs::store`](crate::fs::store), because it
/// is part of the feed contract. [`WalOp::FileCreate`] carries a whole
/// record. So a replica can apply the operation again without reading the
/// master.
///
/// **Schema changes.** The server reads this type from rows that are already
/// on disk. So an added field makes every old row unreadable, unless the
/// field has a default. An unreadable row is not the same as a missing row,
/// as far as the sweeper is concerned. The row disappears from
/// `list_files`. The pass for orphan bytes then deletes the object that the
/// row still describes. So a field whose absence has an honest value carries
/// `#[serde(default)]`. A field whose absence means that the record points at
/// the wrong place, or has passed the age for collection on purpose, does
/// not carry a default:
///
/// - `id` and `s3_key` identify the row and the bytes that it owns. `id` is
///   already in the key, but a default of `""` would describe no object.
///   `s3_key` is the only pointer from the metadata to the data. A wrong
///   pointer is data loss in the making.
/// - `size` supplies `Content-Length`. A `0` would look like a valid wrong
///   answer. It would truncate a download instead of failing it.
/// - `created_at` is the clock for garbage collection. A `0` reads as "made
///   at the start of the Unix epoch", which makes the record collectable at
///   once.
///
/// So a row that cannot decode stays a condition that is loud and visible.
/// The name of `list_files` shows the key. The sweeper refuses its pass for
/// orphan bytes. A row is never covered up by a default that deletes the
/// file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    /// File identifier.
    pub id: String,
    /// Original file name. The value is empty when the field is missing from an
    /// older row. A name is only for display, so no value of it is wrong.
    #[serde(default)]
    pub name: String,
    /// MIME type. The value is empty when the field is missing, for the same
    /// reason as `name`.
    #[serde(default)]
    pub mimetype: String,
    /// Size in bytes.
    pub size: u64,
    /// S3 key.
    pub s3_key: String,
    /// Subject of the owner. The value is empty when the field is missing.
    /// An empty value then matches no caller. So a record with no owner is
    /// read by nobody, not by everyone.
    #[serde(default)]
    pub owner_sub: String,
    /// Creation timestamp.
    pub created_at: i64,
}

/// An operation that is stored in the change feed.
///
/// The operations on files and on relations carry enough data to apply them
/// again on a replica. `FileCreate` carries the whole record. A rich policy
/// operation carries the whole rule or link. So a replay can resync only the
/// user or the row that the operation affected. The old operations
/// `PolicyAdd` and `PolicyRemove` carry only an object. They always need a
/// full rebuild.
///
/// **Wire format.** The server encodes this type with `serde` into a durable
/// log. So a new variant is safe, but an existing variant must not change
/// its form. An older reader cannot decode a newer entry, and
/// [`Wal`](crate::sync::wal::Wal) treats an entry that it cannot decode as
/// corruption instead of skipping it. Add a variant with
/// `#[serde(default)]` fields where that is safe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalOp {
    /// An old policy mark that names only an object, from before the rich
    /// operations existed.
    ///
    /// The variant is kept so that the server can read old WALs. New code
    /// never writes it. A replay treats it as a need for a full rebuild.
    PolicyAdd {
        /// The object that is affected.
        obj: String,
    },
    /// An old policy mark that names only an object, from before the rich
    /// operations existed.
    ///
    /// The variant is kept so that the server can read old WALs. New code
    /// never writes it. A replay treats it as a need for a full rebuild.
    PolicyRemove {
        /// The object that is affected.
        obj: String,
    },
    /// A permission rule was added (`p = sub, obj, act`).
    PolicyRuleAdd {
        /// Subject of the rule, which is a user or a group.
        sub: String,
        /// Object of the rule. A row uses `{row_type}:{row_id}`.
        obj: String,
        /// Action of the rule, which is `read`, `write`, `delete`, or
        /// `execute`.
        act: String,
    },
    /// A permission rule was removed (`p = sub, obj, act`).
    PolicyRuleRemove {
        /// Subject of the rule, which is a user or a group.
        sub: String,
        /// Object of the rule. A row uses `{row_type}:{row_id}`.
        obj: String,
        /// Action of the rule, which is `read`, `write`, `delete`, or
        /// `execute`.
        act: String,
    },
    /// Group membership was added (`g = user, group`).
    GroupAdd {
        /// Subject of the member.
        user: String,
        /// The group that the member joined.
        group: String,
    },
    /// Group membership was removed (`g = user, group`).
    GroupRemove {
        /// Subject of the member.
        user: String,
        /// The group that the member left.
        group: String,
    },
    /// A group was deleted, which removed every membership link to `group`.
    GroupDelete {
        /// The group that was removed.
        group: String,
    },
    /// A file was attached to a row.
    Attach {
        /// The type of the row.
        row_type: String,
        /// The identifier of the row.
        row_id: String,
        /// The identifier of the file.
        file_id: String,
    },
    /// A file was detached from a row.
    Detach {
        /// The type of the row.
        row_type: String,
        /// The identifier of the row.
        row_id: String,
        /// The identifier of the file.
        file_id: String,
    },
    /// File metadata was created, which means that an upload ended.
    FileCreate {
        /// The whole record, as it is stored on the master.
        rec: FileRecord,
    },
    /// File metadata was deleted.
    FileDelete {
        /// The identifier of the file.
        file_id: String,
    },
}

impl WalOp {
    /// True for an old mark that names only an object, which cannot replay
    /// in steps.
    pub fn is_legacy_policy_mark(&self) -> bool {
        matches!(self, Self::PolicyAdd { .. } | Self::PolicyRemove { .. })
    }
}

/// One entry in the durable feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    /// Sequence number that only increases.
    pub seq: u64,
    /// The operation.
    pub op: WalOp,
    /// The time stamp.
    pub ts: i64,
}

/// The place where the server announces changes that it has committed.
///
/// This trait is the seam that keeps `fs` and `policy` out of `sync`. A
/// producer appends an operation after a mutation commits. It treats a
/// failure as fatal to the mutation, so the flow fails closed. If the
/// feed misses a write, the replicas diverge from the master in a way
/// that has nothing to replay.
///
/// An implementation must serialize the appends that run at the same
/// time. The sequence numbers must then have no gaps. The durable
/// implementation is [`Wal`](crate::sync::wal::Wal).
///
/// The failure is an opaque `anyhow::Error` on purpose. The producer is
/// `fs` or `policy`. Neither has any business knowing whether the failure
/// came from the store, from a fencing loss, or from serialization. The
/// [`Wal`](crate::sync::wal::Wal) has no business exposing
/// [`FsError`](crate::fs::error::FsError) either. Both flatten the error
/// at the boundary. Neither classifies the cause on the way back.
///
/// The trait uses a boxed error, not a new type that the crate defines.
/// The boxed error carries the same information. Nothing passes the
/// message, which is the sanitized `Display` of the sink. The only cost
/// is a wrapper that `fs` and `policy` would have to unwrap again on the
/// way out. `anyhow` is a leaf dependency, so this module keeps its
/// property of depending on nothing in the crate.
#[async_trait]
pub trait ChangeSink: Send + Sync {
    /// Appends one operation. The function returns only after the
    /// operation is durable.
    ///
    /// The message of a failure is for the server logs on the same
    /// machine. It is the `Display` of the sink, which is already the
    /// sanitized text. It is not the cause underneath.
    async fn append(&self, op: WalOp) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::production_source;

    /// The feed is a wire format. A round trip must keep the operation exactly.
    /// `Wal::range` treats any difference as corruption, not as an entry to
    /// skip.
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

    /// A replay classifies the operations, and the classification must list
    /// every operation. An operation that this does not name takes the wrong
    /// branch in `replay`.
    ///
    /// `is_legacy_policy_mark` is the only classifier left, and it decides
    /// the outcome. `SnapshotManager::replay` refuses a range that contains
    /// one of these operations before it opens a writer. An old mark names an
    /// object and no rule, so nothing in it can be applied in steps.
    #[test]
    fn op_classification_is_exhaustive() {
        assert!(WalOp::PolicyAdd { obj: "x".into() }.is_legacy_policy_mark());
        assert!(WalOp::PolicyRemove { obj: "x".into() }.is_legacy_policy_mark());
        assert!(!WalOp::GroupDelete { group: "g".into() }.is_legacy_policy_mark());
        assert!(
            !WalOp::PolicyRuleAdd {
                sub: "s".into(),
                obj: "o".into(),
                act: "read".into(),
            }
            .is_legacy_policy_mark()
        );
        assert!(
            !WalOp::FileDelete {
                file_id: "f".into()
            }
            .is_legacy_policy_mark()
        );
    }

    /// An added field must not make a row on disk unreadable.
    ///
    /// `FileRecord` has no version marker. So the only thing between "add a
    /// field" and "no stored record can be read" is a default on that field.
    /// An unreadable file row does nothing quietly. The row drops out of
    /// `list_files`. The sweeper then reads the object of that row as one
    /// that nothing uses, and it deletes the bytes of a file that the
    /// metadata still describes. So the set of fields with a default is
    /// deliberate, not a blanket. `id`, `s3_key`, `size`, and `created_at`
    /// stay required, because a default on one of them points at the wrong
    /// object, or reports the wrong length, or makes the record old enough
    /// for collection at once.
    #[test]
    fn an_added_field_does_not_orphan_an_existing_row() {
        // A row as an older version wrote it. The row has no `name`, no
        // `mimetype`, and no `owner_sub`.
        let old = br#"{"id":"f1","size":7,"s3_key":"files/f1","created_at":42}"#;
        let rec: FileRecord = serde_json::from_slice(old).expect("an old row still decodes");
        assert_eq!(rec.id, "f1");
        assert_eq!(rec.s3_key, "files/f1");
        assert_eq!(rec.size, 7);
        assert_eq!(rec.created_at, 42);
        // A record with no owner is read by nobody, not by everyone.
        assert_eq!(rec.owner_sub, "");
        assert_eq!(rec.name, "");
        assert_eq!(rec.mimetype, "");

        // The fields with no honest default stay required. So a row
        // that misses one stays a *visible* failure, instead of
        // becoming a plausible wrong answer.
        for field in [
            &br#"{"size":7,"s3_key":"files/f1","created_at":42}"#[..],
            &br#"{"id":"f1","size":7,"created_at":42}"#[..],
            &br#"{"id":"f1","s3_key":"files/f1","created_at":42}"#[..],
            &br#"{"id":"f1","size":7,"s3_key":"files/f1"}"#[..],
        ] {
            assert!(
                serde_json::from_slice::<FileRecord>(field).is_err(),
                "a row missing a load-bearing field decoded to a guess"
            );
        }
    }

    /// The purpose of this module: `fs` and `policy` must not depend on
    /// `sync`.
    ///
    /// They announce changes through [`ChangeSink`] so that the dependency
    /// does not exist. Without this test, the edge comes back one `use` at a
    /// time. Once it is back, the graph is a cycle again. No compiler reports
    /// that, because Rust allows a cycle between modules. Only the order of
    /// the layers is at stake here. Nothing else enforces that order.
    ///
    /// The test leaves out the test modules. Tests may reach across the
    /// boundary to build a `Wal` and check that the announcements are
    /// durable.
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

    /// This module must stay a leaf. If `records` gained a dependency on `fs`,
    /// `policy`, or `sync`, the cycle would move instead of disappearing.
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
