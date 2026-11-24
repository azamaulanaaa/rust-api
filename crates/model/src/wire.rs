//! Request and response types for the job and sync paths.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{CommandKind, JobState};

/// The status of one job, as the API shows it.
///
/// The server builds this view from the stored queue status. The stored
/// status is part of the durable queue format and never goes on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JobStatusView {
    /// The job identifier.
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub id: Uuid,
    /// The command kind of the job.
    pub kind: CommandKind,
    /// The current lifecycle state.
    pub state: JobState,
    /// The number of attempts that the queue started.
    pub attempt: u32,
    /// The maximum number of attempts.
    pub max_attempts: u32,
    /// The creation time in unix seconds.
    pub created_at: i64,
    /// The earliest run time in unix seconds.
    pub scheduled_at: i64,
    /// The lease expiry time in unix milliseconds.
    ///
    /// The field is present only while a worker holds the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<i64>,
    /// The finish time in unix seconds.
    ///
    /// The field is present only in a terminal state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
    /// The worker that holds or held the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<String>,
    /// The failure text for a failed or dead job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The result bytes in base64 form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_base64: Option<String>,
    /// The change feed sequence that the write advanced to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_seq: Option<u64>,
}

/// One write command from a client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CommandEnvelope {
    /// The command kind. The server rejects a kind without a handler.
    pub kind: CommandKind,
    /// The command data in JSON form.
    pub payload: serde_json::Value,
    /// The client key that makes the enqueue idempotent.
    pub idempotency_key: String,
    /// The entity version that the client read.
    ///
    /// The server rejects the command when the current version is not the
    /// same value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
}

/// The result of one applied job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CommitReceipt {
    /// The change feed sequence that the write advanced to.
    pub commit_seq: u64,
}

/// A position in the change feed.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SyncCursor {
    /// The number of change feed entries that the reader applied.
    pub seq: u64,
}

/// The description of one replica that the server built for a subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReplicaManifest {
    /// The build generation. Each build increments the value.
    pub generation: u64,
    /// The highest change feed sequence in the replica.
    pub head: u64,
    /// The objects in the replica, relative to the replica root.
    pub objects: Vec<ReplicaObject>,
}

/// One object in a replica manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReplicaObject {
    /// The object key relative to the replica root.
    pub key: String,
    /// The object size in bytes.
    pub size: u64,
    /// The SHA-256 of the object bytes as lowercase hex.
    pub sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds one job view with no optional field set.
    fn job_view() -> JobStatusView {
        JobStatusView {
            id: Uuid::nil(),
            kind: CommandKind::parse("entity.update").expect("valid kind"),
            state: JobState::Queued,
            attempt: 0,
            max_attempts: 5,
            created_at: 1_700_000_000,
            scheduled_at: 1_700_000_001,
            lease_expires_at: None,
            finished_at: None,
            worker: None,
            error: None,
            result_base64: None,
            commit_seq: None,
        }
    }

    /// A queued job omits every optional field.
    #[test]
    fn a_queued_job_omits_the_optional_fields() {
        let value = serde_json::to_value(job_view()).expect("job view serializes");
        for field in [
            "lease_expires_at",
            "finished_at",
            "worker",
            "error",
            "result_base64",
            "commit_seq",
        ] {
            assert!(value.get(field).is_none(), "{field} must be omitted");
        }
        let back: JobStatusView = serde_json::from_value(value).expect("job view parses");
        assert_eq!(back, job_view());
    }

    /// A terminal job carries its finish data and keeps it across serde.
    #[test]
    fn a_terminal_job_carries_its_finish_data() {
        let mut view = job_view();
        view.state = JobState::Succeeded;
        view.attempt = 1;
        view.finished_at = Some(1_700_000_010);
        view.worker = Some("worker-1".to_string());
        view.result_base64 = Some("aGVsbG8=".to_string());
        view.commit_seq = Some(42);
        let value = serde_json::to_value(&view).expect("job view serializes");
        assert_eq!(value["state"], serde_json::json!("succeeded"));
        assert_eq!(value["commit_seq"], serde_json::json!(42));
        let back: JobStatusView = serde_json::from_value(value).expect("job view parses");
        assert_eq!(back, view);
    }

    /// A command envelope keeps its optional expected version.
    #[test]
    fn a_command_envelope_keeps_its_expected_version() {
        let envelope = CommandEnvelope {
            kind: CommandKind::parse("entity.update").expect("valid kind"),
            payload: serde_json::json!({"name": "alice"}),
            idempotency_key: "client-1".to_string(),
            expected_version: Some(3),
        };
        let value = serde_json::to_value(&envelope).expect("envelope serializes");
        assert_eq!(value["expected_version"], serde_json::json!(3));
        let back: CommandEnvelope = serde_json::from_value(value).expect("envelope parses");
        assert_eq!(back, envelope);

        let without = serde_json::json!({
            "kind": "entity.update",
            "payload": {},
            "idempotency_key": "client-2",
        });
        let back: CommandEnvelope =
            serde_json::from_value(without).expect("the version is optional");
        assert_eq!(back.expected_version, None);
    }

    /// A commit receipt carries the sequence that the write advanced.
    #[test]
    fn a_commit_receipt_carries_its_sequence() {
        let receipt = CommitReceipt { commit_seq: 9 };
        let value = serde_json::to_value(receipt).expect("receipt serializes");
        assert_eq!(value, serde_json::json!({"commit_seq": 9}));
        let back: CommitReceipt = serde_json::from_value(value).expect("receipt parses");
        assert_eq!(back, receipt);
    }

    /// A sync cursor starts at zero and keeps its sequence.
    #[test]
    fn a_sync_cursor_keeps_its_sequence() {
        assert_eq!(SyncCursor::default().seq, 0);
        let cursor = SyncCursor { seq: 12 };
        let value = serde_json::to_value(cursor).expect("cursor serializes");
        assert_eq!(value, serde_json::json!({"seq": 12}));
        let back: SyncCursor = serde_json::from_value(value).expect("cursor parses");
        assert_eq!(back, cursor);
    }

    /// A replica manifest keeps its generation, head, and objects.
    #[test]
    fn a_replica_manifest_keeps_its_objects() {
        let manifest = ReplicaManifest {
            generation: 7,
            head: 42,
            objects: vec![ReplicaObject {
                key: "manifest.json".to_string(),
                size: 128,
                sha256: "00".repeat(32),
            }],
        };
        let value = serde_json::to_value(&manifest).expect("manifest serializes");
        assert_eq!(value["generation"], serde_json::json!(7));
        assert_eq!(
            value["objects"][0]["key"],
            serde_json::json!("manifest.json")
        );
        let back: ReplicaManifest = serde_json::from_value(value).expect("manifest parses");
        assert_eq!(back, manifest);
    }
}
