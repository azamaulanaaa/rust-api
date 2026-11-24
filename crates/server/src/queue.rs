//! Generic, business-logic-free job queue.
//!
//! This module defines the queue traits, value types, and status model.
//! Concrete backends live in the submodules of this module.
//!
//! Domain job types and handlers live in the application crate, not here.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use opentelemetry::global;
use opentelemetry::propagation::{Extractor, Injector};
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
    /// The authenticated subject that enqueued the job.
    ///
    /// An HTTP request that enqueues a job sets the owner. An internal job
    /// can leave the field empty. The serde default keeps old stored records
    /// readable.
    #[serde(default)]
    pub owner_sub: Option<String>,
    /// Transport metadata.
    pub headers: BTreeMap<String, String>,
}

/// Proof that a worker holds a lease on a job.
///
/// A queue operation that changes a leased job must carry the token that
/// [`JobQueue::reserve`] or [`JobQueue::extend_lease`] returned. The backend
/// rejects the call when the token does not match the current lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseToken {
    /// Worker that holds the lease.
    pub worker: String,
    /// Lease generation. The backend increments the value on each reserve
    /// and each extension. An old token has a lower value.
    pub generation: u64,
}

/// A job that a worker has leased.
#[derive(Debug, Clone)]
pub struct LeasedJob {
    /// The leased job.
    pub job: Job,
    /// Proof of the current lease.
    pub lease: LeaseToken,
}

/// Status of a job in the queue.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    /// The job is waiting to run.
    Queued,
    /// A worker holds the job.
    Leased {
        /// Worker that holds the lease.
        worker: String,
        /// Lease expiry time, in unix milliseconds.
        ///
        /// The value has millisecond precision, so a lease below one second
        /// keeps its full duration. All other times in this type use unix
        /// seconds.
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
#[non_exhaustive]
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

/// Retry decision that a [`JobError`] carries.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobRetry {
    /// Do not retry the job.
    NoRetry,
    /// Retry the job after the given delay.
    RetryAfter(Duration),
    /// Retry the job with the worker retry schedule.
    RetryDefault,
}

/// A job error that carries the retry decision.
///
/// A handler returns this error to control the next action of the worker.
/// The worker maps [`JobRetry::NoRetry`] to [`RetryPolicy::NoRetry`].
/// It maps [`JobRetry::RetryAfter`] to [`RetryPolicy::Retry`] with the same
/// delay.
/// It maps [`JobRetry::RetryDefault`] to the worker retry schedule.
/// An error without this type uses the worker retry schedule.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct JobError {
    /// The error text.
    message: String,
    /// The retry decision.
    retry: JobRetry,
}

impl From<anyhow::Error> for JobError {
    fn from(error: anyhow::Error) -> Self {
        Self::retryable(error.to_string())
    }
}

impl JobError {
    /// Creates an error for a permanent failure.
    ///
    /// The worker does not retry the job.
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retry: JobRetry::NoRetry,
        }
    }

    /// Creates an error for a temporary failure.
    ///
    /// The worker uses its own retry schedule.
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retry: JobRetry::RetryDefault,
        }
    }

    /// Creates an error for a temporary failure with a delay.
    ///
    /// The worker retries the job after `delay`.
    pub fn retry_after(message: impl Into<String>, delay: Duration) -> Self {
        Self {
            message: message.into(),
            retry: JobRetry::RetryAfter(delay),
        }
    }

    /// Returns the retry decision.
    pub fn retry(&self) -> JobRetry {
        self.retry
    }
}

/// Error returned by queue operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// Underlying store failure.
    #[error("queue store error: {0}")]
    Store(#[source] Box<dyn std::error::Error + Send + Sync>),
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

/// Error text that has no upstream cause.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct QueueMessage(String);

impl QueueError {
    /// Wraps a store error so callers can read its source.
    pub(crate) fn store(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Store(Box::new(error))
    }

    /// Wraps store error text that has no upstream cause.
    pub(crate) fn store_message(message: impl Into<String>) -> Self {
        Self::Store(Box::new(QueueMessage(message.into())))
    }
}

/// Contract for a job queue backend.
#[async_trait]
pub trait JobQueue: Send + Sync {
    /// Adds a job. Returns its id.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Invalid`] when `max_attempts` is zero.
    /// Returns [`QueueError::Store`] when the backend write fails.
    async fn enqueue(&self, job: Job) -> Result<JobId, QueueError>;

    /// Reserves up to `limit` jobs for `worker`.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::Store`] when a backend read or write fails.
    async fn reserve(
        &self,
        worker: &str,
        limit: usize,
        lease: Duration,
    ) -> Result<Vec<LeasedJob>, QueueError>;

    /// Marks a job as done.
    ///
    /// The call fails with [`QueueError::LeaseExpired`] or
    /// [`QueueError::AlreadyLeased`] when `lease` is not the current token.
    /// A failed call does not change the job.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::NotFound`] when the job does not exist.
    /// Returns [`QueueError::LeaseExpired`] or [`QueueError::AlreadyLeased`]
    /// when the lease is gone or belongs to another worker.
    /// Returns [`QueueError::Store`] when a backend write fails.
    async fn ack(
        &self,
        job_id: JobId,
        lease: &LeaseToken,
        result: Option<Vec<u8>>,
    ) -> Result<(), QueueError>;

    /// Marks a job as failed.
    ///
    /// The call fails with [`QueueError::LeaseExpired`] or
    /// [`QueueError::AlreadyLeased`] when `lease` is not the current token.
    /// A failed call does not change the job.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::NotFound`] when the job does not exist.
    /// Returns [`QueueError::LeaseExpired`] or [`QueueError::AlreadyLeased`]
    /// when the lease is gone or belongs to another worker.
    /// Returns [`QueueError::Store`] when a backend write fails.
    async fn nack(
        &self,
        job_id: JobId,
        lease: &LeaseToken,
        error: &str,
        retry: RetryPolicy,
    ) -> Result<(), QueueError>;

    /// Extends the lease of a job and returns the new token.
    ///
    /// The old token is not valid after this call. The call fails with
    /// [`QueueError::LeaseExpired`] or [`QueueError::AlreadyLeased`] when
    /// `lease` is not the current token. A failed call does not change the
    /// job.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::NotFound`] when the job does not exist.
    /// Returns [`QueueError::LeaseExpired`] or [`QueueError::AlreadyLeased`]
    /// when the lease is gone or belongs to another worker.
    /// Returns [`QueueError::Store`] when a backend write fails.
    async fn extend_lease(
        &self,
        job_id: JobId,
        lease: &LeaseToken,
        extend: Duration,
    ) -> Result<LeaseToken, QueueError>;

    /// Returns the status of a job.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::NotFound`] when the job does not exist.
    /// Returns [`QueueError::Store`] when a backend read or write fails.
    async fn status(&self, job_id: JobId) -> Result<JobStatus, QueueError>;
}

/// Handler for one job kind.
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// Kind that this handler processes.
    fn kind(&self) -> &'static str;

    /// Processes the job. Returns an optional result.
    ///
    /// # Errors
    ///
    /// Returns [`JobError`] with the retry decision for the job.
    async fn handle(&self, job: &Job) -> Result<Option<Vec<u8>>, JobError>;
}

pub mod memory;
pub mod metrics;

pub use memory::MemoryQueue;
pub use worker::QueueWorker;
pub mod durable;
pub mod worker;

pub use metrics::QueueMetrics;

/// Converts a lease duration to milliseconds for storage.
///
/// The call rounds a non-zero duration up to the next millisecond.
/// A zero duration stays zero, so the lease expires at once.
pub(crate) fn lease_millis(duration: Duration) -> i64 {
    let millis = duration.as_millis();
    let millis = if duration.subsec_nanos().is_multiple_of(1_000_000) {
        millis
    } else {
        millis.saturating_add(1)
    };
    i64::try_from(millis).unwrap_or(i64::MAX)
}

/// Converts a delay to whole seconds for [`Job::scheduled_at`].
///
/// The call rounds a non-zero fraction up to the next second.
/// The result saturates at `i64::MAX`.
pub(crate) fn delay_secs(delay: Duration) -> i64 {
    let secs = delay
        .as_secs()
        .saturating_add(u64::from(delay.subsec_nanos() != 0));
    i64::try_from(secs).unwrap_or(i64::MAX)
}

#[cfg(feature = "queue-rabbitmq")]
pub mod rabbitmq;

/// Injects the current OpenTelemetry trace context into job headers.
///
/// The function writes the W3C `traceparent` and `tracestate` entries. A
/// worker that reads the same job can then continue the trace.
pub fn inject_trace_context(headers: &mut BTreeMap<String, String>) {
    struct MapInjector<'a>(&'a mut BTreeMap<String, String>);
    impl Injector for MapInjector<'_> {
        fn set(&mut self, key: &str, value: String) {
            self.0.insert(key.to_string(), value);
        }
    }
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(
            &opentelemetry::Context::current(),
            &mut MapInjector(headers),
        );
    });
}

/// Extracts an OpenTelemetry trace context from job headers.
///
/// The function returns the context that [`inject_trace_context`] stored.
/// An empty context results when the job carries no trace header.
pub fn extract_trace_context(headers: &BTreeMap<String, String>) -> opentelemetry::Context {
    struct MapExtractor<'a>(&'a BTreeMap<String, String>);
    impl Extractor for MapExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v.as_str())
        }
        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(String::as_str).collect()
        }
    }
    global::get_text_map_propagator(|propagator| propagator.extract(&MapExtractor(headers)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sub_second_delay_rounds_up_to_one_second() {
        assert_eq!(delay_secs(Duration::from_millis(1)), 1);
    }

    #[test]
    fn a_whole_second_delay_keeps_its_value() {
        assert_eq!(delay_secs(Duration::from_secs(3)), 3);
    }

    #[test]
    fn a_delay_above_i64_max_saturates() {
        assert_eq!(delay_secs(Duration::from_secs(u64::MAX)), i64::MAX);
    }

    #[test]
    fn a_store_error_keeps_its_source() {
        let error = QueueError::store(std::io::Error::other("disk full"));
        assert!(std::error::Error::source(&error).is_some());
        assert!(error.to_string().contains("disk full"));
    }

    #[test]
    fn an_anyhow_error_becomes_a_retryable_job_error() {
        let error = JobError::from(anyhow::anyhow!("handler failed"));
        assert!(matches!(error.retry(), JobRetry::RetryDefault));
        assert_eq!(error.to_string(), "handler failed");
    }
}
