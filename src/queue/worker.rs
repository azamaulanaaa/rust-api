//! Worker runtime for the job queue.
//!
//! A panic in a job handler fails only that job. The worker loop continues and
//! processes later jobs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{Instrument, error, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::CancelToken;

use super::{Job, JobHandler, JobQueue, LeasedJob, QueueMetrics, RetryPolicy};

/// A worker that reserves and processes jobs.
///
/// The worker runs each job handler in its own task. A handler panic becomes a
/// job failure: the worker nacks the job and applies the retry policy. The
/// worker loop continues after the panic.
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

/// Runs one job handler in its own task.
///
/// The task owns an `Arc` handle to the handler. A panic in the handler thus
/// stays inside the task and arrives back as a `JoinError`.
async fn run_handler(
    handler: Arc<dyn JobHandler>,
    job: Job,
    span: tracing::Span,
) -> Result<Option<Vec<u8>>, anyhow::Error> {
    handler.handle(&job).instrument(span).await
}

/// Returns the error message for a panic in a job handler task.
fn panic_message(join: tokio::task::JoinError) -> String {
    let payload = join.into_panic();
    if let Some(message) = payload.downcast_ref::<&str>() {
        format!("job handler panicked: {message}")
    } else if let Some(message) = payload.downcast_ref::<String>() {
        format!("job handler panicked: {message}")
    } else {
        "job handler panicked".to_string()
    }
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
        let task = tokio::spawn(run_handler(Arc::clone(&handler), job.clone(), span.clone()));
        let result = match task.await {
            Ok(result) => result,
            Err(join) if join.is_panic() => {
                ext_cancel.cancel();
                let _ = ext_handle.await;
                let elapsed = start.elapsed().as_secs_f64();
                let message = panic_message(join);
                span.in_scope(|| {
                    error!(
                        job_id = %job_id,
                        job_kind = %job_kind,
                        panic = %message,
                        "job handler panicked"
                    )
                });
                let delay = retry_delay(job.attempt, self.retry_base, self.retry_max);
                if let Err(e) = self
                    .queue
                    .nack(job_id, &message, RetryPolicy::Retry { delay })
                    .await
                {
                    warn!(error = %e, "queue nack failed");
                }
                self.metrics.record_failed();
                self.metrics.record_processing_duration(elapsed);
                return;
            }
            Err(join) => Err(anyhow::anyhow!("job task failed: {join}")),
        };
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

    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::queue::{JobId, JobStatus, MemoryQueue};

    /// Handler that panics on the first call and succeeds on later calls.
    struct PanicOnceHandler {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl JobHandler for PanicOnceHandler {
        fn kind(&self) -> &'static str {
            "flaky"
        }

        async fn handle(&self, _job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                panic!("handler panic");
            }
            Ok(Some(vec![1]))
        }
    }

    /// Handler that always panics.
    struct PanicHandler;

    #[async_trait]
    impl JobHandler for PanicHandler {
        fn kind(&self) -> &'static str {
            "panic"
        }

        async fn handle(&self, _job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
            panic!("handler panic");
        }
    }

    /// Handler that always succeeds.
    struct OkHandler;

    #[async_trait]
    impl JobHandler for OkHandler {
        fn kind(&self) -> &'static str {
            "ok"
        }

        async fn handle(&self, _job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
            Ok(Some(vec![7]))
        }
    }

    /// Handler that always returns an error.
    struct ErrHandler;

    #[async_trait]
    impl JobHandler for ErrHandler {
        fn kind(&self) -> &'static str {
            "fail"
        }

        async fn handle(&self, _job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
            Err(anyhow::anyhow!("handler failed"))
        }
    }

    fn test_job(kind: &str, priority: i32, max_attempts: u32) -> Job {
        Job {
            id: Uuid::now_v7(),
            kind: kind.to_string(),
            payload: Vec::new(),
            priority,
            attempt: 0,
            max_attempts,
            created_at: 0,
            scheduled_at: 0,
            idempotency_key: None,
            headers: BTreeMap::new(),
        }
    }

    async fn wait_for_status<F>(queue: &MemoryQueue, id: JobId, ready: F) -> JobStatus
    where
        F: Fn(&JobStatus) -> bool,
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = queue.status(id).await.unwrap();
            if ready(&status) {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the job did not reach the expected status"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

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

    #[tokio::test]
    async fn a_handler_panic_does_not_stop_the_worker() {
        let queue = Arc::new(MemoryQueue::new());
        let handler = Arc::new(PanicOnceHandler {
            calls: AtomicUsize::new(0),
        });
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            vec![Arc::clone(&handler) as Arc<dyn JobHandler>],
            "worker-1".to_string(),
        )
        .with_lease(Duration::from_millis(30))
        .with_poll_interval(Duration::from_millis(1))
        .with_retry_base(Duration::ZERO)
        .with_retry_max(Duration::ZERO);
        let job = test_job("flaky", 0, 3);
        let id = job.id;
        queue.enqueue(job).await.unwrap();

        let cancel = CancellationToken::new();
        let run = tokio::spawn({
            let cancel = cancel.clone();
            async move { worker.run(cancel).await }
        });

        let status =
            wait_for_status(&queue, id, |s| matches!(s, JobStatus::Succeeded { .. })).await;
        cancel.cancel();
        run.await.unwrap();

        assert!(matches!(status, JobStatus::Succeeded { .. }));
        assert_eq!(handler.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_panicked_job_is_nacked_with_the_current_attempt() {
        let queue = Arc::new(MemoryQueue::new());
        let handler = Arc::new(PanicOnceHandler {
            calls: AtomicUsize::new(0),
        });
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            vec![Arc::clone(&handler) as Arc<dyn JobHandler>],
            "worker-1".to_string(),
        )
        .with_lease(Duration::from_millis(30))
        .with_retry_base(Duration::ZERO)
        .with_retry_max(Duration::ZERO);
        let job = test_job("flaky", 0, 3);
        let id = job.id;
        queue.enqueue(job).await.unwrap();

        let leased = queue
            .reserve("worker-1", 1, Duration::from_millis(30))
            .await
            .unwrap();
        worker.process(leased.into_iter().next().unwrap()).await;

        let status = queue.status(id).await.unwrap();
        assert!(matches!(status, JobStatus::Queued), "got {status:?}");
        let leased = queue
            .reserve("worker-1", 1, Duration::from_millis(30))
            .await
            .unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].job.attempt, 1);
        assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_panic_at_the_attempt_limit_dead_letters_the_job_and_the_worker_continues() {
        let queue = Arc::new(MemoryQueue::new());
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            vec![
                Arc::new(PanicHandler) as Arc<dyn JobHandler>,
                Arc::new(OkHandler) as Arc<dyn JobHandler>,
            ],
            "worker-1".to_string(),
        )
        .with_lease(Duration::from_millis(30))
        .with_poll_interval(Duration::from_millis(1))
        .with_retry_base(Duration::ZERO)
        .with_retry_max(Duration::ZERO);
        let cancel = CancellationToken::new();
        let run = tokio::spawn({
            let cancel = cancel.clone();
            async move { worker.run(cancel).await }
        });

        let panic_job = test_job("panic", 0, 1);
        let panic_id = panic_job.id;
        queue.enqueue(panic_job).await.unwrap();
        let status =
            wait_for_status(&queue, panic_id, |s| matches!(s, JobStatus::Dead { .. })).await;
        assert!(matches!(status, JobStatus::Dead { .. }));

        let ok_job = test_job("ok", 0, 1);
        let ok_id = ok_job.id;
        queue.enqueue(ok_job).await.unwrap();
        let status =
            wait_for_status(&queue, ok_id, |s| matches!(s, JobStatus::Succeeded { .. })).await;
        assert!(matches!(status, JobStatus::Succeeded { .. }));

        cancel.cancel();
        run.await.unwrap();
    }

    #[tokio::test]
    async fn a_successful_job_is_acked() {
        let queue = Arc::new(MemoryQueue::new());
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            vec![Arc::new(OkHandler) as Arc<dyn JobHandler>],
            "worker-1".to_string(),
        )
        .with_lease(Duration::from_millis(30));
        let job = test_job("ok", 0, 3);
        let id = job.id;
        queue.enqueue(job).await.unwrap();

        let leased = queue
            .reserve("worker-1", 1, Duration::from_millis(30))
            .await
            .unwrap();
        worker.process(leased.into_iter().next().unwrap()).await;

        match queue.status(id).await.unwrap() {
            JobStatus::Succeeded { result, .. } => assert_eq!(result, Some(vec![7])),
            other => panic!("expected succeeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_failed_job_is_nacked_and_retried() {
        let queue = Arc::new(MemoryQueue::new());
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            vec![Arc::new(ErrHandler) as Arc<dyn JobHandler>],
            "worker-1".to_string(),
        )
        .with_lease(Duration::from_millis(30))
        .with_retry_base(Duration::ZERO)
        .with_retry_max(Duration::ZERO);
        let job = test_job("fail", 0, 3);
        let id = job.id;
        queue.enqueue(job).await.unwrap();

        let leased = queue
            .reserve("worker-1", 1, Duration::from_millis(30))
            .await
            .unwrap();
        worker.process(leased.into_iter().next().unwrap()).await;

        let status = queue.status(id).await.unwrap();
        assert!(matches!(status, JobStatus::Queued), "got {status:?}");
        let leased = queue
            .reserve("worker-1", 1, Duration::from_millis(30))
            .await
            .unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].job.attempt, 1);
    }

    #[tokio::test]
    async fn cancellation_stops_the_worker() {
        let queue = Arc::new(MemoryQueue::new());
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            Vec::new(),
            "worker-1".to_string(),
        )
        .with_poll_interval(Duration::from_millis(5));
        let cancel = CancellationToken::new();
        let run = tokio::spawn({
            let cancel = cancel.clone();
            async move { worker.run(cancel).await }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("the worker did not stop after cancellation")
            .unwrap();
    }
}
