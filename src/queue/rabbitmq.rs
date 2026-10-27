//! RabbitMQ adapter for the job queue.
//!
//! The adapter is behind the `queue-rabbitmq` feature. It maps queue
//! operations to AMQP primitives. A concrete broker connection is supplied
//! by the application.

use std::time::Duration;

use async_trait::async_trait;

use super::{Job, JobId, JobStatus, LeasedJob, QueueError, RetryPolicy};

/// RabbitMQ-backed queue.
///
/// The type reserves the seam for an AMQP backend. The application wires a
/// connection factory. Until then, operations report that the backend is not
/// available.
pub struct RabbitMqQueue {
    /// Connection URL.
    pub url: String,
}

impl RabbitMqQueue {
    /// Builds a queue handle.
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

#[async_trait]
impl super::JobQueue for RabbitMqQueue {
    async fn enqueue(&self, _job: Job) -> Result<JobId, QueueError> {
        Err(QueueError::Unsupported(
            "rabbitmq backend is not wired".to_string(),
        ))
    }

    async fn reserve(
        &self,
        _worker: &str,
        _limit: usize,
        _lease: Duration,
    ) -> Result<Vec<LeasedJob>, QueueError> {
        Err(QueueError::Unsupported(
            "rabbitmq backend is not wired".to_string(),
        ))
    }

    async fn ack(&self, _job_id: JobId, _result: Option<Vec<u8>>) -> Result<(), QueueError> {
        Err(QueueError::Unsupported(
            "rabbitmq backend is not wired".to_string(),
        ))
    }

    async fn nack(
        &self,
        _job_id: JobId,
        _error: &str,
        _retry: RetryPolicy,
    ) -> Result<(), QueueError> {
        Err(QueueError::Unsupported(
            "rabbitmq backend is not wired".to_string(),
        ))
    }

    async fn extend_lease(&self, _job_id: JobId, _lease: Duration) -> Result<(), QueueError> {
        Err(QueueError::Unsupported(
            "rabbitmq backend is not wired".to_string(),
        ))
    }

    async fn status(&self, _job_id: JobId) -> Result<JobStatus, QueueError> {
        Err(QueueError::Unsupported(
            "rabbitmq backend is not wired".to_string(),
        ))
    }
}
