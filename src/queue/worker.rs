//! Worker runtime for the job queue.
//!
//! A panic in a job handler fails only that job. The worker loop continues and
//! processes later jobs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::{Instrument, error, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::CancelToken;

use super::{
    Job, JobHandler, JobId, JobQueue, LeaseToken, LeasedJob, QueueError, QueueMetrics, RetryPolicy,
};

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

/// Holds the lease token of one job while the job waits and runs.
///
/// A renewal task extends the lease at one third of the lease duration. Each
/// extension replaces the token with a new generation. The worker reads the
/// latest token for `ack` and `nack`.
struct LeaseGuard {
    /// Latest token that the renewal task wrote.
    token: Arc<Mutex<LeaseToken>>,
    /// Stops the renewal task.
    cancel: tokio_util::sync::CancellationToken,
    /// Task that renews the lease.
    handle: tokio::task::JoinHandle<()>,
}

impl LeaseGuard {
    /// Stops the renewal task and returns the latest token.
    ///
    /// The function waits for the task to exit. The token does not change
    /// after the call returns.
    async fn stop(mut self) -> LeaseToken {
        self.cancel.cancel();
        let _ = (&mut self.handle).await;
        self.token.lock().await.clone()
    }
}

impl Drop for LeaseGuard {
    /// Stops the renewal task when the guard goes out of scope.
    fn drop(&mut self) {
        self.cancel.cancel();
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

    /// Starts a task that renews the lease of one job.
    ///
    /// The task starts when the worker reserves the job. A job that waits in
    /// a reserved batch thus keeps a live lease before its handler starts.
    /// The task stops when the caller calls [`LeaseGuard::stop`].
    fn start_lease_extension(&self, job_id: JobId, initial: LeaseToken) -> LeaseGuard {
        let token = Arc::new(Mutex::new(initial));
        let cancel = tokio_util::sync::CancellationToken::new();
        let queue = Arc::clone(&self.queue);
        let lease = self.lease;
        // A zero lease must not make the task loop without a wait.
        let tick = (lease / 3).max(Duration::from_millis(1));
        let current = Arc::clone(&token);
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    _ = tokio::time::sleep(tick) => {}
                }
                let previous = current.lock().await.clone();
                match queue.extend_lease(job_id, &previous, lease).await {
                    Ok(next) => *current.lock().await = next,
                    Err(error @ (QueueError::AlreadyLeased | QueueError::LeaseExpired)) => {
                        warn!(job_id = %job_id, error = %error, "queue lease lost; stop the renewal");
                        break;
                    }
                    Err(error) => {
                        warn!(job_id = %job_id, error = %error, "queue lease renewal failed");
                    }
                }
            }
        });
        LeaseGuard {
            token,
            cancel,
            handle,
        }
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
            // Start one renewal task per reserved job before the first
            // handler runs. A later job in the batch must not lose its
            // lease while an earlier job runs.
            let mut batch = Vec::with_capacity(jobs.len());
            for leased in jobs {
                let guard = self.start_lease_extension(leased.job.id, leased.lease.clone());
                batch.push((leased, guard));
            }
            for (leased, guard) in batch {
                self.process(leased, guard).await;
            }
        }
    }

    /// Runs one leased job and records its result.
    ///
    /// The function uses the latest token from `guard` for `ack` and `nack`.
    /// It records a completion only when the ack succeeds.
    async fn process(&self, leased: LeasedJob, guard: LeaseGuard) {
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
            let lease = guard.stop().await;
            if let Err(e) = self
                .queue
                .nack(job_id, &lease, "no handler for kind", RetryPolicy::NoRetry)
                .await
            {
                warn!(error = %e, job_id = %job_id, "queue nack failed; the lease was lost");
            }
            self.metrics.record_failed();
            self.metrics
                .record_processing_duration(start.elapsed().as_secs_f64());
            span.in_scope(|| warn!(job_id = %job_id, "no handler for job kind"));
            return;
        };
        let task = tokio::spawn(run_handler(Arc::clone(&handler), job.clone(), span.clone()));
        let result = match task.await {
            Ok(result) => result,
            Err(join) if join.is_panic() => {
                let lease = guard.stop().await;
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
                    .nack(job_id, &lease, &message, RetryPolicy::Retry { delay })
                    .await
                {
                    warn!(error = %e, job_id = %job_id, "queue nack failed; the lease was lost");
                }
                self.metrics.record_failed();
                self.metrics.record_processing_duration(elapsed);
                return;
            }
            Err(join) => Err(anyhow::anyhow!("job task failed: {join}")),
        };
        let lease = guard.stop().await;
        let elapsed = start.elapsed().as_secs_f64();
        match result {
            Ok(res) => match self.queue.ack(job_id, &lease, res).await {
                Ok(()) => {
                    self.metrics.record_completed();
                    span.in_scope(|| info!(job_id = %job_id, elapsed = elapsed, "job processed"));
                }
                Err(e) => {
                    // The lease was lost. The job stays leased and the queue
                    // can run it again. Do not record a completion or a job
                    // failure. The backend records the lease loss.
                    span.in_scope(|| {
                        warn!(
                            job_id = %job_id,
                            error = %e,
                            elapsed = elapsed,
                            "queue ack failed; the lease was lost"
                        )
                    });
                }
            },
            Err(e) => {
                warn!(error = %e, job_id = %job_id, "job failed");
                let policy = match e.downcast_ref::<super::JobError>() {
                    Some(error) => match error.retry() {
                        super::JobRetry::NoRetry => RetryPolicy::NoRetry,
                        super::JobRetry::RetryAfter(delay) => RetryPolicy::Retry { delay },
                        super::JobRetry::RetryDefault => RetryPolicy::Retry {
                            delay: retry_delay(job.attempt, self.retry_base, self.retry_max),
                        },
                    },
                    None => RetryPolicy::Retry {
                        delay: retry_delay(job.attempt, self.retry_base, self.retry_max),
                    },
                };
                if let Err(nack_error) = self
                    .queue
                    .nack(job_id, &lease, &e.to_string(), policy)
                    .await
                {
                    warn!(error = %nack_error, job_id = %job_id, "queue nack failed; the lease was lost");
                }
                self.metrics.record_failed();
            }
        }
        self.metrics.record_processing_duration(elapsed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

    /// Counts the runs of each job and flags two runs at the same time.
    #[derive(Default)]
    struct RunTracker {
        runs: tokio::sync::Mutex<HashMap<JobId, usize>>,
        active: tokio::sync::Mutex<HashMap<JobId, usize>>,
        overlap: AtomicBool,
    }

    impl RunTracker {
        /// Returns the number of runs of a job.
        async fn runs_of(&self, id: JobId) -> usize {
            self.runs.lock().await.get(&id).copied().unwrap_or(0)
        }

        /// Records the start of a run.
        async fn enter(&self, id: JobId) {
            *self.runs.lock().await.entry(id).or_insert(0) += 1;
            let mut active = self.active.lock().await;
            let count = active.entry(id).or_insert(0);
            *count += 1;
            if *count > 1 {
                self.overlap.store(true, Ordering::SeqCst);
            }
        }

        /// Records the end of a run.
        async fn leave(&self, id: JobId) {
            if let Some(count) = self.active.lock().await.get_mut(&id) {
                *count = count.saturating_sub(1);
            }
        }
    }

    /// Handler that runs for a fixed time and records each run.
    struct TimedHandler {
        kind: &'static str,
        delay: Duration,
        tracker: Arc<RunTracker>,
    }

    #[async_trait]
    impl JobHandler for TimedHandler {
        fn kind(&self) -> &'static str {
            self.kind
        }

        async fn handle(&self, job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
            self.tracker.enter(job.id).await;
            tokio::time::sleep(self.delay).await;
            self.tracker.leave(job.id).await;
            Ok(Some(vec![1]))
        }
    }

    /// Queue that rejects every ack with [`QueueError::AlreadyLeased`].
    struct RejectAckQueue {
        inner: MemoryQueue,
        acks: AtomicUsize,
    }

    #[async_trait]
    impl JobQueue for RejectAckQueue {
        async fn enqueue(&self, job: Job) -> Result<JobId, QueueError> {
            self.inner.enqueue(job).await
        }

        async fn reserve(
            &self,
            worker: &str,
            limit: usize,
            lease: Duration,
        ) -> Result<Vec<LeasedJob>, QueueError> {
            self.inner.reserve(worker, limit, lease).await
        }

        async fn ack(
            &self,
            _job_id: JobId,
            _lease: &LeaseToken,
            _result: Option<Vec<u8>>,
        ) -> Result<(), QueueError> {
            self.acks.fetch_add(1, Ordering::SeqCst);
            Err(QueueError::AlreadyLeased)
        }

        async fn nack(
            &self,
            job_id: JobId,
            lease: &LeaseToken,
            error: &str,
            retry: RetryPolicy,
        ) -> Result<(), QueueError> {
            self.inner.nack(job_id, lease, error, retry).await
        }

        async fn extend_lease(
            &self,
            job_id: JobId,
            lease: &LeaseToken,
            extend: Duration,
        ) -> Result<LeaseToken, QueueError> {
            self.inner.extend_lease(job_id, lease, extend).await
        }

        async fn status(&self, job_id: JobId) -> Result<JobStatus, QueueError> {
            self.inner.status(job_id).await
        }
    }

    /// Handler that returns a permanent job error.
    struct PermanentErrHandler;

    #[async_trait]
    impl JobHandler for PermanentErrHandler {
        fn kind(&self) -> &'static str {
            "permanent"
        }

        async fn handle(&self, _job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
            Err(crate::queue::JobError::permanent("permanent failure").into())
        }
    }

    /// Handler that returns a retry job error with a delay.
    struct RetryAfterErrHandler;

    #[async_trait]
    impl JobHandler for RetryAfterErrHandler {
        fn kind(&self) -> &'static str {
            "retry-after"
        }

        async fn handle(&self, _job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
            Err(
                crate::queue::JobError::retry_after("temporary failure", Duration::from_secs(60))
                    .into(),
            )
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

    /// Runs the first job of a reserved batch through the worker.
    async fn process_one(worker: &QueueWorker, mut leased: Vec<LeasedJob>) {
        let job = leased.remove(0);
        let guard = worker.start_lease_extension(job.job.id, job.lease.clone());
        worker.process(job, guard).await;
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
        .with_lease(Duration::from_secs(30))
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
        .with_lease(Duration::from_secs(30))
        .with_retry_base(Duration::ZERO)
        .with_retry_max(Duration::ZERO);
        let job = test_job("flaky", 0, 3);
        let id = job.id;
        queue.enqueue(job).await.unwrap();

        let leased = queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap();
        process_one(&worker, leased).await;

        let status = queue.status(id).await.unwrap();
        assert!(matches!(status, JobStatus::Queued), "got {status:?}");
        let leased = queue
            .reserve("worker-1", 1, Duration::from_secs(30))
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
        .with_lease(Duration::from_secs(30))
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
        .with_lease(Duration::from_secs(30));
        let job = test_job("ok", 0, 3);
        let id = job.id;
        queue.enqueue(job).await.unwrap();

        let leased = queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap();
        process_one(&worker, leased).await;

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
        .with_lease(Duration::from_secs(30))
        .with_retry_base(Duration::ZERO)
        .with_retry_max(Duration::ZERO);
        let job = test_job("fail", 0, 3);
        let id = job.id;
        queue.enqueue(job).await.unwrap();

        let leased = queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap();
        process_one(&worker, leased).await;

        let status = queue.status(id).await.unwrap();
        assert!(matches!(status, JobStatus::Queued), "got {status:?}");
        let leased = queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].job.attempt, 1);
    }

    #[tokio::test]
    async fn a_long_handler_keeps_its_lease() {
        let queue = Arc::new(MemoryQueue::new());
        let tracker = Arc::new(RunTracker::default());
        let handler = Arc::new(TimedHandler {
            kind: "slow",
            delay: Duration::from_millis(2_300),
            tracker: Arc::clone(&tracker),
        });
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            vec![handler as Arc<dyn JobHandler>],
            "worker-1".to_string(),
        )
        .with_lease(Duration::from_secs(2))
        .with_poll_interval(Duration::from_millis(10));
        let job = test_job("slow", 0, 3);
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
        assert_eq!(
            tracker.runs_of(id).await,
            1,
            "the job must run once and keep its lease"
        );
    }

    #[tokio::test]
    async fn a_slow_batch_keeps_every_reserved_lease() {
        let queue = Arc::new(MemoryQueue::new());
        let tracker = Arc::new(RunTracker::default());
        let slow = Arc::new(TimedHandler {
            kind: "slow",
            delay: Duration::from_millis(2_200),
            tracker: Arc::clone(&tracker),
        });
        let later = Arc::new(TimedHandler {
            kind: "later",
            delay: Duration::from_millis(1_000),
            tracker: Arc::clone(&tracker),
        });
        let build = |id: &str| {
            QueueWorker::new(
                Arc::clone(&queue) as Arc<dyn JobQueue>,
                vec![
                    Arc::clone(&slow) as Arc<dyn JobHandler>,
                    Arc::clone(&later) as Arc<dyn JobHandler>,
                ],
                id.to_string(),
            )
            .with_lease(Duration::from_secs(2))
            .with_poll_interval(Duration::from_millis(10))
            .with_batch_size(2)
        };

        let first = test_job("slow", 1, 3);
        let second = test_job("later", 0, 3);
        let ids = [first.id, second.id];
        queue.enqueue(first).await.unwrap();
        queue.enqueue(second).await.unwrap();

        let cancel = CancellationToken::new();
        let worker_one = build("worker-1");
        let run_one = tokio::spawn({
            let cancel = cancel.clone();
            async move { worker_one.run(cancel).await }
        });
        // Let the first worker reserve both jobs before the second one polls.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let worker_two = build("worker-2");
        let run_two = tokio::spawn({
            let cancel = cancel.clone();
            async move { worker_two.run(cancel).await }
        });

        for id in ids {
            wait_for_status(&queue, id, |s| matches!(s, JobStatus::Succeeded { .. })).await;
        }
        cancel.cancel();
        run_one.await.unwrap();
        run_two.await.unwrap();

        assert!(
            !tracker.overlap.load(Ordering::SeqCst),
            "a job ran twice at the same time"
        );
        for id in ids {
            assert_eq!(
                tracker.runs_of(id).await,
                1,
                "the job must run once when a slow job delays the batch"
            );
        }
    }

    #[tokio::test]
    async fn a_rejected_ack_keeps_the_job_leased() {
        let queue = Arc::new(RejectAckQueue {
            inner: MemoryQueue::new(),
            acks: AtomicUsize::new(0),
        });
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            vec![Arc::new(OkHandler) as Arc<dyn JobHandler>],
            "worker-1".to_string(),
        )
        .with_lease(Duration::from_secs(30));
        let job = test_job("ok", 0, 3);
        let id = job.id;
        queue.inner.enqueue(job).await.unwrap();
        let leased = queue
            .inner
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap();

        process_one(&worker, leased).await;

        assert_eq!(
            queue.acks.load(Ordering::SeqCst),
            1,
            "the worker must attempt the ack"
        );
        assert_eq!(
            worker.metrics.failed_count(),
            0,
            "a lost lease is not a job failure"
        );
        assert_eq!(
            worker.metrics.lease_lost_count(),
            0,
            "the backend records a lease loss; the worker must not count it twice"
        );
        let status = queue.inner.status(id).await.unwrap();
        assert!(
            matches!(status, JobStatus::Leased { .. }),
            "a rejected ack must not mark the job done, got {status:?}"
        );
    }

    #[tokio::test]
    async fn a_permanent_job_error_is_not_retried() {
        let queue = Arc::new(MemoryQueue::new());
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            vec![Arc::new(PermanentErrHandler) as Arc<dyn JobHandler>],
            "worker-1".to_string(),
        )
        .with_lease(Duration::from_secs(30));
        let job = test_job("permanent", 0, 5);
        let id = job.id;
        queue.enqueue(job).await.unwrap();

        let leased = queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap();
        process_one(&worker, leased).await;

        let status = queue.status(id).await.unwrap();
        assert!(matches!(status, JobStatus::Failed { .. }), "got {status:?}");
        assert!(
            queue
                .reserve("probe", 1, Duration::from_secs(30))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_retry_after_job_error_uses_the_delay() {
        let queue = Arc::new(MemoryQueue::new());
        let worker = QueueWorker::new(
            Arc::clone(&queue) as Arc<dyn JobQueue>,
            vec![Arc::new(RetryAfterErrHandler) as Arc<dyn JobHandler>],
            "worker-1".to_string(),
        )
        .with_lease(Duration::from_secs(30))
        .with_retry_base(Duration::ZERO)
        .with_retry_max(Duration::ZERO);
        let job = test_job("retry-after", 0, 5);
        let id = job.id;
        queue.enqueue(job).await.unwrap();

        let leased = queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await
            .unwrap();
        process_one(&worker, leased).await;

        let status = queue.status(id).await.unwrap();
        assert!(matches!(status, JobStatus::Queued), "got {status:?}");
        assert!(
            queue
                .reserve("probe", 1, Duration::from_secs(30))
                .await
                .unwrap()
                .is_empty()
        );
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
