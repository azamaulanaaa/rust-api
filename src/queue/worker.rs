//! Worker runtime for the job queue.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{Instrument, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::CancelToken;

use super::{JobHandler, JobQueue, LeasedJob, QueueMetrics, RetryPolicy};

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
    /// Base delay for the first retry.
    retry_base: Duration,
    /// Maximum delay between retries.
    retry_max: Duration,
    /// Metrics for the worker.
    metrics: QueueMetrics,
}

/// Returns the retry delay for an attempt.
///
/// The first failure uses `base`. Each later failure doubles the delay.
/// The result is capped at `max`.
pub fn retry_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let multiplier = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
    base.saturating_mul(multiplier).min(max)
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
            retry_base: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
            metrics: QueueMetrics::new("worker"),
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

    /// Sets the base retry delay.
    pub fn with_retry_base(mut self, base: Duration) -> Self {
        self.retry_base = base;
        self
    }

    /// Sets the maximum retry delay.
    pub fn with_retry_max(mut self, max: Duration) -> Self {
        self.retry_max = max;
        self
    }

    /// Sets the metrics handle.
    pub fn with_metrics(mut self, metrics: QueueMetrics) -> Self {
        self.metrics = metrics;
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
        let job_kind = job.kind.clone();
        let start = Instant::now();
        let parent_cx = super::extract_trace_context(&job.headers);
        let span = tracing::info_span!(
            "queue.process",
            "otel.name" = format!("process {}", job_kind),
            "queue.backend" = "worker",
            "job.id" = %job_id,
            "job.kind" = %job_kind,
            "job.attempt" = job.attempt,
        );
        if let Err(e) = span.set_parent(parent_cx) {
            tracing::debug!("ignoring invalid inbound trace context: {e}");
        }

        let handler = self.handler_for(&job.kind);
        let Some(handler) = handler else {
            let _ = self
                .queue
                .nack(job_id, "no handler for kind", RetryPolicy::NoRetry)
                .await;
            self.metrics.record_failed();
            self.metrics
                .record_processing_duration(start.elapsed().as_secs_f64());
            span.in_scope(|| warn!(job_id = %job_id, "no handler for job kind"));
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
        let result = handler.handle(&job).instrument(span.clone()).await;
        ext_cancel.cancel();
        let _ = ext_handle.await;
        let elapsed = start.elapsed().as_secs_f64();
        match result {
            Ok(res) => {
                if let Err(e) = self.queue.ack(job_id, res).await {
                    warn!(error = %e, "queue ack failed");
                }
                self.metrics.record_completed();
            }
            Err(e) => {
                warn!(error = %e, "job failed");
                let delay = retry_delay(job.attempt, self.retry_base, self.retry_max);
                let _ = self
                    .queue
                    .nack(job_id, &e.to_string(), RetryPolicy::Retry { delay })
                    .await;
                self.metrics.record_failed();
            }
        }
        self.metrics.record_processing_duration(elapsed);
        span.in_scope(|| info!(job_id = %job_id, elapsed = elapsed, "job processed"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_uses_base_for_the_first_failure() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        assert_eq!(retry_delay(0, base, max), Duration::from_secs(1));
    }

    #[test]
    fn retry_delay_doubles_for_the_second_failure() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        assert_eq!(retry_delay(1, base, max), Duration::from_secs(2));
    }

    #[test]
    fn retry_delay_doubles_again_for_the_third_failure() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        assert_eq!(retry_delay(2, base, max), Duration::from_secs(4));
    }

    #[test]
    fn retry_delay_caps_the_delay_at_max() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        assert_eq!(retry_delay(10, base, max), Duration::from_secs(60));
    }

    #[test]
    fn retry_delay_handles_a_large_attempt_without_overflow() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        assert_eq!(retry_delay(u32::MAX, base, max), Duration::from_secs(60));
    }
}
