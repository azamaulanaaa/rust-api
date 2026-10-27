//! Worker runtime for the job queue.

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::CancelToken;

use super::{JobHandler, JobQueue, LeasedJob, RetryPolicy};

/// A worker that reserves and processes jobs.
pub struct QueueWorker {
    /// Queue backend.
    queue: Arc<dyn JobQueue>,
    /// Handlers by kind.
    handlers: Vec<Arc<dyn JobHandler>>,
    /// Worker id.
    worker_id: String,
    /// Batch size.
    batch_size: usize,
    /// Lease duration.
    lease: Duration,
    /// Poll interval when idle.
    poll_interval: Duration,
}

impl QueueWorker {
    /// Builds a worker.
    pub fn new(
        queue: Arc<dyn JobQueue>,
        handlers: Vec<Arc<dyn JobHandler>>,
        worker_id: String,
    ) -> Self {
        Self {
            queue,
            handlers,
            worker_id,
            batch_size: 4,
            lease: Duration::from_secs(30),
            poll_interval: Duration::from_millis(200),
        }
    }

    /// Sets the batch size.
    pub fn with_batch_size(mut self, n: usize) -> Self {
        self.batch_size = n;
        self
    }

    /// Sets the lease duration.
    pub fn with_lease(mut self, lease: Duration) -> Self {
        self.lease = lease;
        self
    }

    /// Sets the poll interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Finds a handler for a kind.
    fn handler_for(&self, kind: &str) -> Option<Arc<dyn JobHandler>> {
        self.handlers.iter().find(|h| h.kind() == kind).cloned()
    }

    /// Runs until cancelled.
    pub async fn run<C: CancelToken>(&self, cancel: C) {
        while !cancel.is_cancelled() {
            let jobs = match self
                .queue
                .reserve(&self.worker_id, self.batch_size, self.lease)
                .await
            {
                Ok(j) => j,
                Err(e) => {
                    warn!(error = %e, "queue reserve failed");
                    tokio::time::sleep(self.poll_interval).await;
                    continue;
                }
            };
            if jobs.is_empty() {
                tokio::time::sleep(self.poll_interval).await;
                continue;
            }
            for leased in jobs {
                self.process(leased).await;
            }
        }
    }

    async fn process(&self, leased: LeasedJob) {
        let job = leased.job;
        let job_id = job.id;
        let start = std::time::Instant::now();
        let handler = self.handler_for(&job.kind);
        let Some(handler) = handler else {
            let _ = self
                .queue
                .nack(job_id, "no handler for kind", RetryPolicy::NoRetry)
                .await;
            return;
        };
        // Lease extender.
        let ext_cancel = tokio_util::sync::CancellationToken::new();
        let ext_handle = {
            let queue = Arc::clone(&self.queue);
            let cancel = ext_cancel.clone();
            let lease = self.lease;
            let id = job_id;
            tokio::spawn(async move {
                while !cancel.is_cancelled() {
                    tokio::time::sleep(lease / 3).await;
                    if cancel.is_cancelled() {
                        break;
                    }
                    let _ = queue.extend_lease(id, lease).await;
                }
            })
        };
        let result = handler.handle(&job).await;
        ext_cancel.cancel();
        let _ = ext_handle.await;
        let elapsed = start.elapsed().as_secs_f64();
        match result {
            Ok(res) => {
                if let Err(e) = self.queue.ack(job_id, res).await {
                    warn!(error = %e, "queue ack failed");
                }
            }
            Err(e) => {
                warn!(error = %e, "job failed");
                let _ = self
                    .queue
                    .nack(
                        job_id,
                        &e.to_string(),
                        RetryPolicy::Retry {
                            delay: Duration::from_secs(1),
                        },
                    )
                    .await;
            }
        }
        info!(job_id = %job_id, elapsed = elapsed, "job processed");
    }
}
