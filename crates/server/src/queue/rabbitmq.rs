//! RabbitMQ adapter for the job queue.
//!
//! The adapter is behind the `queue-rabbitmq` feature. It maps queue
//! operations to AMQP primitives. A concrete broker connection is supplied
//! by the application.

use std::time::Duration;

use async_trait::async_trait;

use super::{Job, JobId, JobStatus, LeaseToken, LeasedJob, QueueError, RetryPolicy};

/// RabbitMQ-backed queue.
///
/// The type reserves the seam for an AMQP backend. The application wires a
/// connection factory. Until then, operations report that the backend is not
/// available.
#[derive(Debug)]
pub struct RabbitMqQueue {
    /// Connection URL.
    url: String,
}

impl RabbitMqQueue {
    /// Builds a queue handle.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Returns the connection URL.
    pub fn url(&self) -> &str {
        &self.url
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

    async fn ack(
        &self,
        _job_id: JobId,
        _lease: &LeaseToken,
        _result: Option<Vec<u8>>,
    ) -> Result<(), QueueError> {
        Err(QueueError::Unsupported(
            "rabbitmq backend is not wired".to_string(),
        ))
    }

    async fn nack(
        &self,
        _job_id: JobId,
        _lease: &LeaseToken,
        _error: &str,
        _retry: RetryPolicy,
    ) -> Result<(), QueueError> {
        Err(QueueError::Unsupported(
            "rabbitmq backend is not wired".to_string(),
        ))
    }

    async fn extend_lease(
        &self,
        _job_id: JobId,
        _lease: &LeaseToken,
        _extend: Duration,
    ) -> Result<LeaseToken, QueueError> {
        Err(QueueError::Unsupported(
            "rabbitmq backend is not wired".to_string(),
        ))
    }

    async fn get(&self, _job_id: JobId) -> Result<Job, QueueError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_queue_handle_keeps_the_connection_url() {
        let queue = RabbitMqQueue::new("amqp://localhost");
        assert_eq!(queue.url(), "amqp://localhost");
    }
}
