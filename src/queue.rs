//! Generic, business-logic-free job queue.
//!
//! This module defines the queue traits, value types, and status model.
//! Concrete backends live in the submodules of this module.
//!
//! Domain job types and handlers live in the application crate, not here.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identifier of a job. The value is the job's [`Job::id`].
pub type JobId = Uuid;

/// A unit of work that a worker processes.
///
/// The type carries bytes only. The application decodes the payload for its
/// own job kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    /// Unique identifier of the job.
    pub id: Uuid,
    /// Kind of the job. Workers dispatch on this value.
    pub kind: String,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
    /// Higher values run first.
    pub priority: i32,
    /// Number of attempts already made.
    pub attempt: u32,
    /// Maximum number of attempts before the job is dead-lettered.
    pub max_attempts: u32,
    /// Creation time, in unix seconds.
    pub created_at: i64,
    /// Earliest time the job may run, in unix seconds.
    pub scheduled_at: i64,
    /// Optional key for idempotent enqueue.
    pub idempotency_key: Option<String>,
    /// Transport metadata.
    pub headers: BTreeMap<String, String>,
}

/// A job that a worker has leased.
#[derive(Debug, Clone)]
pub struct LeasedJob {
    /// The leased job.
    pub job: Job,
    /// Time at which the lease expires, in unix seconds.
    pub lease_expires_at: i64,
}

/// Status of a job in the queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    /// The job is waiting to run.
    Queued,
    /// A worker holds the job.
    Leased {
        /// Worker that holds the lease.
        worker: String,
        /// Lease expiry time, in unix seconds.
        expires_at: i64,
    },
    /// The job finished well.
    Succeeded {
        /// Optional result bytes.
        result: Option<Vec<u8>>,
        /// Completion time, in unix seconds.
        finished_at: i64,
    },
    /// The job failed without retry.
    Failed {
        /// Error text.
        error: String,
        /// Completion time, in unix seconds.
        finished_at: i64,
    },
    /// The job exhausted its retries.
    Dead {
        /// Error text.
        error: String,
        /// Completion time, in unix seconds.
        finished_at: i64,
    },
}

/// Retry instruction passed to [`JobQueue::nack`].
#[derive(Debug, Clone)]
pub enum RetryPolicy {
    /// Do not retry the job.
    NoRetry,
    /// Retry the job after the given delay.
    Retry {
        /// Delay before the job may run again.
        delay: Duration,
    },
}

/// Error returned by queue operations.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// Underlying store failure.
    #[error("queue store error: {0}")]
    Store(String),
    /// The job does not exist.
    #[error("queue job not found: {0}")]
    NotFound(JobId),
    /// The job is already leased.
    #[error("queue job is already leased")]
    AlreadyLeased,
    /// The lease expired.
    #[error("queue lease expired")]
    LeaseExpired,
    /// A duplicate idempotency key was seen.
    #[error("queue duplicate idempotency key: {0}")]
    DuplicateIdempotency(String),
    /// The job is invalid.
    #[error("queue invalid job: {0}")]
    Invalid(String),
    /// The backend is not available.
    #[error("queue backend not available: {0}")]
    Unsupported(String),
    /// I/O failure.
    #[error("queue io error: {0}")]
    Io(String),
}

/// Contract for a job queue backend.
#[async_trait]
pub trait JobQueue: Send + Sync {
    /// Adds a job. Returns its id.
    async fn enqueue(&self, job: Job) -> Result<JobId, QueueError>;

    /// Reserves up to `limit` jobs for `worker`.
    async fn reserve(
        &self,
        worker: &str,
        limit: usize,
        lease: Duration,
    ) -> Result<Vec<LeasedJob>, QueueError>;

    /// Marks a job as done.
    async fn ack(&self, job_id: JobId, result: Option<Vec<u8>>) -> Result<(), QueueError>;

    /// Marks a job as failed.
    async fn nack(&self, job_id: JobId, error: &str, retry: RetryPolicy) -> Result<(), QueueError>;

    /// Extends the lease of a job.
    async fn extend_lease(&self, job_id: JobId, lease: Duration) -> Result<(), QueueError>;

    /// Returns the status of a job.
    async fn status(&self, job_id: JobId) -> Result<JobStatus, QueueError>;
}

/// Handler for one job kind.
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// Kind that this handler processes.
    fn kind(&self) -> &'static str;

    /// Processes the job. Returns an optional result.
    async fn handle(&self, job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error>;
}

pub mod memory;
pub mod metrics;

pub use memory::MemoryQueue;
pub use worker::QueueWorker;
pub mod durable;
pub mod worker;

pub use metrics::QueueMetrics;

#[cfg(feature = "queue-rabbitmq")]
pub mod rabbitmq;
