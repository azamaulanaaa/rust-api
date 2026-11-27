//! In-memory job queue backend.
//!
//! The backend is non-durable. Use it for tests and local development.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::instrument;

use super::{Job, JobId, JobStatus, LeaseToken, LeasedJob, QueueError, QueueMetrics, RetryPolicy};

/// Internal record held by the in-memory backend.
#[derive(Debug, Clone)]
struct Record {
    job: Job,
    status: JobStatus,
    /// Generation of the current or last lease. The backend increments the
    /// value on each reserve and each extension. An old token has a lower
    /// value.
    lease_generation: u64,
    result: Option<Vec<u8>>,
    error: Option<String>,
    finished_at: Option<i64>,
}

/// In-memory job queue.
#[derive(Debug)]
pub struct MemoryQueue {
    state: Arc<Mutex<State>>,
    metrics: QueueMetrics,
}

#[derive(Debug)]
struct State {
    records: BTreeMap<JobId, Record>,
    idempotency: BTreeMap<String, JobId>,
}

impl MemoryQueue {
    /// Builds an empty in-memory queue.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                records: BTreeMap::new(),
                idempotency: BTreeMap::new(),
            })),
            metrics: QueueMetrics::new("memory"),
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// Returns the current time in unix milliseconds.
    ///
    /// The lease expiry uses milliseconds, so a lease below one second keeps
    /// its full duration.
    fn now_millis() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    fn sweep_expired(state: &mut State) {
        let now = Self::now();
        let now_millis = Self::now_millis();
        for rec in state.records.values_mut() {
            if let JobStatus::Leased { expires_at, .. } = rec.status
                && expires_at <= now_millis
            {
                let attempt = rec.job.attempt.saturating_add(1);
                rec.job.attempt = attempt;
                rec.job.scheduled_at = now;
                if attempt >= rec.job.max_attempts {
                    rec.status = JobStatus::Dead {
                        error: "lease expired".to_string(),
                        finished_at: now,
                    };
                    rec.error = Some("lease expired".to_string());
                    rec.finished_at = Some(now);
                } else {
                    rec.status = JobStatus::Queued;
                }
            }
        }
    }

    /// Checks a lease token against the record status.
    ///
    /// The function returns [`QueueError::AlreadyLeased`] when another worker
    /// holds the job or the token has an old generation. It returns
    /// [`QueueError::LeaseExpired`] when the lease is gone or its time has
    /// passed.
    fn check_lease(rec: &Record, lease: &LeaseToken) -> Result<(), QueueError> {
        match &rec.status {
            JobStatus::Leased { worker, expires_at } => {
                if worker != &lease.worker || rec.lease_generation != lease.generation {
                    Err(QueueError::AlreadyLeased)
                } else if *expires_at <= Self::now_millis() {
                    Err(QueueError::LeaseExpired)
                } else {
                    Ok(())
                }
            }
            _ => Err(QueueError::LeaseExpired),
        }
    }

    /// Records the number of jobs that wait to run.
    async fn record_depth(&self) {
        let state = self.state.lock().await;
        let depth = state
            .records
            .values()
            .filter(|record| matches!(record.status, JobStatus::Queued))
            .count() as u64;
        drop(state);
        self.metrics.record_depth(depth);
    }
}

impl Default for MemoryQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::JobQueue for MemoryQueue {
    #[instrument(name = "queue.enqueue", skip(self, job), fields(queue.backend = "memory", job.id = %job.id, job.kind = %job.kind))]
    async fn enqueue(&self, job: Job) -> Result<JobId, QueueError> {
        if job.max_attempts == 0 {
            return Err(QueueError::Invalid(
                "max_attempts must be positive".to_string(),
            ));
        }
        let mut job = job;
        super::inject_trace_context(&mut job.headers);
        let mut state = self.state.lock().await;
        if let Some(key) = &job.idempotency_key
            && let Some(existing) = state.idempotency.get(key)
        {
            return Ok(*existing);
        }
        let id = job.id;
        let rec = Record {
            job: job.clone(),
            status: JobStatus::Queued,
            lease_generation: 0,
            result: None,
            error: None,
            finished_at: None,
        };
        if let Some(key) = &job.idempotency_key {
            state.idempotency.insert(key.clone(), id);
        }
        state.records.insert(id, rec);
        drop(state);
        self.metrics.record_enqueued();
        self.record_depth().await;
        Ok(id)
    }

    #[instrument(name = "queue.reserve", skip(self), fields(queue.backend = "memory", worker = %worker, limit = %limit))]
    async fn reserve(
        &self,
        worker: &str,
        limit: usize,
        lease: Duration,
    ) -> Result<Vec<LeasedJob>, QueueError> {
        let mut state = self.state.lock().await;
        Self::sweep_expired(&mut state);
        let now = Self::now();
        let now_millis = Self::now_millis();
        let lease_millis = super::lease_millis(lease);
        let mut candidates: Vec<JobId> = state
            .records
            .iter()
            .filter(|(_, r)| matches!(r.status, JobStatus::Queued) && r.job.scheduled_at <= now)
            .map(|(id, _)| *id)
            .collect();
        candidates.sort_by(|a, b| {
            let ra = &state.records[a];
            let rb = &state.records[b];
            rb.job
                .priority
                .cmp(&ra.job.priority)
                .then(ra.job.created_at.cmp(&rb.job.created_at))
        });
        candidates.truncate(limit);
        let mut out = Vec::new();
        for id in candidates {
            let Some(rec) = state.records.get_mut(&id) else {
                continue;
            };
            let expires_at = now_millis.saturating_add(lease_millis);
            rec.lease_generation = rec.lease_generation.saturating_add(1);
            let generation = rec.lease_generation;
            rec.status = JobStatus::Leased {
                worker: worker.to_string(),
                expires_at,
            };
            out.push(LeasedJob {
                job: rec.job.clone(),
                lease: LeaseToken {
                    worker: worker.to_string(),
                    generation,
                },
            });
        }
        drop(state);
        self.metrics.record_reserved(out.len() as u64);
        self.record_depth().await;
        Ok(out)
    }

    #[instrument(name = "queue.ack", skip(self, result), fields(queue.backend = "memory", job.id = %job_id))]
    async fn ack(
        &self,
        job_id: JobId,
        lease: &LeaseToken,
        result: Option<Vec<u8>>,
    ) -> Result<(), QueueError> {
        let mut state = self.state.lock().await;
        let rec = state
            .records
            .get_mut(&job_id)
            .ok_or(QueueError::NotFound(job_id))?;
        if let Err(error) = Self::check_lease(rec, lease) {
            self.metrics.record_lease_lost();
            return Err(error);
        }
        let finished = Self::now();
        rec.status = JobStatus::Succeeded {
            result: result.clone(),
            finished_at: finished,
        };
        rec.result = result;
        rec.finished_at = Some(finished);
        drop(state);
        self.metrics.record_completed();
        self.record_depth().await;
        Ok(())
    }

    #[instrument(name = "queue.nack", skip(self), fields(queue.backend = "memory", job.id = %job_id, error = %error))]
    async fn nack(
        &self,
        job_id: JobId,
        lease: &LeaseToken,
        error: &str,
        retry: RetryPolicy,
    ) -> Result<(), QueueError> {
        let mut state = self.state.lock().await;
        let rec = state
            .records
            .get_mut(&job_id)
            .ok_or(QueueError::NotFound(job_id))?;
        if let Err(error) = Self::check_lease(rec, lease) {
            self.metrics.record_lease_lost();
            return Err(error);
        }
        let finished = Self::now();
        match retry {
            RetryPolicy::NoRetry => {
                rec.status = JobStatus::Failed {
                    error: error.to_string(),
                    finished_at: finished,
                };
                rec.error = Some(error.to_string());
                rec.finished_at = Some(finished);
            }
            RetryPolicy::Retry { delay } => {
                let attempt = rec.job.attempt.saturating_add(1);
                rec.job.attempt = attempt;
                if attempt >= rec.job.max_attempts {
                    rec.status = JobStatus::Dead {
                        error: error.to_string(),
                        finished_at: finished,
                    };
                    rec.error = Some(error.to_string());
                    rec.finished_at = Some(finished);
                } else {
                    rec.job.scheduled_at = finished.saturating_add(super::delay_secs(delay));
                    rec.status = JobStatus::Queued;
                    rec.error = Some(error.to_string());
                }
            }
        }
        let dead_lettered = matches!(rec.status, JobStatus::Dead { .. });
        drop(state);
        self.metrics.record_failed();
        if dead_lettered {
            self.metrics.record_dead_lettered();
        }
        self.record_depth().await;
        Ok(())
    }

    #[instrument(name = "queue.extend_lease", skip(self), fields(queue.backend = "memory", job.id = %job_id))]
    async fn extend_lease(
        &self,
        job_id: JobId,
        lease: &LeaseToken,
        extend: Duration,
    ) -> Result<LeaseToken, QueueError> {
        let mut state = self.state.lock().await;
        Self::sweep_expired(&mut state);
        let rec = state
            .records
            .get_mut(&job_id)
            .ok_or(QueueError::NotFound(job_id))?;
        if let Err(error) = Self::check_lease(rec, lease) {
            drop(state);
            self.record_depth().await;
            self.metrics.record_lease_lost();
            return Err(error);
        }
        let new_expiry = Self::now_millis().saturating_add(super::lease_millis(extend));
        rec.lease_generation = rec.lease_generation.saturating_add(1);
        rec.status = JobStatus::Leased {
            worker: lease.worker.clone(),
            expires_at: new_expiry,
        };
        let token = LeaseToken {
            worker: lease.worker.clone(),
            generation: rec.lease_generation,
        };
        drop(state);
        self.record_depth().await;
        Ok(token)
    }

    #[instrument(name = "queue.status", skip(self), fields(queue.backend = "memory", job.id = %job_id))]
    async fn status(&self, job_id: JobId) -> Result<JobStatus, QueueError> {
        let mut state = self.state.lock().await;
        Self::sweep_expired(&mut state);
        let status = state
            .records
            .get(&job_id)
            .map(|rec| rec.status.clone())
            .ok_or(QueueError::NotFound(job_id));
        drop(state);
        self.record_depth().await;
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{Job, JobQueue, JobStatus, RetryPolicy};
    use std::time::Duration;
    use uuid::Uuid;

    fn job(kind: &str) -> Job {
        Job {
            id: Uuid::now_v7(),
            kind: kind.to_string(),
            payload: vec![1, 2, 3],
            priority: 0,
            attempt: 0,
            max_attempts: 3,
            created_at: 0,
            scheduled_at: 0,
            idempotency_key: None,
            owner_sub: None,
            headers: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn enqueue_returns_the_job_id() {
        let q = MemoryQueue::new();
        let j = job("work");
        let id = j.id;
        let got = q.enqueue(j).await.unwrap();
        assert_eq!(got, id);
    }

    #[tokio::test]
    async fn reserve_returns_leased_jobs() {
        let q = MemoryQueue::new();
        q.enqueue(job("work")).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
        match q.status(leased[0].job.id).await.unwrap() {
            JobStatus::Leased { worker, .. } => assert_eq!(worker, "w1"),
            other => panic!("expected leased, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn a_lease_below_one_second_keeps_its_duration() {
        let q = MemoryQueue::new();
        q.enqueue(job("work")).await.unwrap();

        let started = MemoryQueue::now_millis();
        let leased = q
            .reserve("w1", 10, Duration::from_millis(100))
            .await
            .unwrap();
        let id = leased[0].job.id;
        match q.status(id).await.unwrap() {
            JobStatus::Leased { expires_at, .. } => {
                assert!(
                    expires_at >= started + 90,
                    "a 100 ms lease must keep its millisecond duration"
                );
            }
            other => panic!("expected leased, got {:?}", other),
        }

        q.ack(id, &leased[0].lease, None).await.unwrap();
    }

    #[tokio::test]
    async fn a_rejected_ack_counts_as_a_lease_loss_and_not_a_failure() {
        let q = MemoryQueue::new();
        let (stale, _) = stale_and_current_lease(&q).await;

        let _ = q.ack(stale.job.id, &stale.lease, None).await.unwrap_err();

        assert_eq!(q.metrics.lease_lost_count(), 1);
        assert_eq!(q.metrics.failed_count(), 0);
    }

    #[tokio::test]
    async fn a_failed_job_counts_as_a_failure_and_not_a_lease_loss() {
        let q = MemoryQueue::new();
        q.enqueue(job("work")).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();

        q.nack(
            leased[0].job.id,
            &leased[0].lease,
            "boom",
            RetryPolicy::NoRetry,
        )
        .await
        .unwrap();

        assert_eq!(q.metrics.failed_count(), 1);
        assert_eq!(q.metrics.lease_lost_count(), 0);
    }

    /// Reserves one job with an expired lease, then reserves it again.
    async fn stale_and_current_lease(q: &MemoryQueue) -> (LeasedJob, LeasedJob) {
        q.enqueue(job("work")).await.unwrap();
        let mut first = q.reserve("w1", 10, Duration::from_secs(0)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut second = q.reserve("w2", 10, Duration::from_secs(30)).await.unwrap();
        (first.pop().unwrap(), second.pop().unwrap())
    }

    #[tokio::test]
    async fn a_stale_lease_cannot_ack_a_job() {
        let q = MemoryQueue::new();
        let (stale, current) = stale_and_current_lease(&q).await;
        let error = q
            .ack(stale.job.id, &stale.lease, Some(vec![1]))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            QueueError::AlreadyLeased | QueueError::LeaseExpired
        ));
        match q.status(current.job.id).await.unwrap() {
            JobStatus::Leased { worker, .. } => assert_eq!(worker, "w2"),
            other => panic!("expected leased, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn a_current_lease_can_ack_a_job() {
        let q = MemoryQueue::new();
        let (_, current) = stale_and_current_lease(&q).await;
        q.ack(current.job.id, &current.lease, Some(vec![9]))
            .await
            .unwrap();
        match q.status(current.job.id).await.unwrap() {
            JobStatus::Succeeded { result, .. } => assert_eq!(result, Some(vec![9])),
            other => panic!("expected succeeded, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn a_stale_lease_cannot_nack_a_job() {
        let q = MemoryQueue::new();
        let (stale, current) = stale_and_current_lease(&q).await;
        let error = q
            .nack(stale.job.id, &stale.lease, "boom", RetryPolicy::NoRetry)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            QueueError::AlreadyLeased | QueueError::LeaseExpired
        ));
        match q.status(current.job.id).await.unwrap() {
            JobStatus::Leased { worker, .. } => assert_eq!(worker, "w2"),
            other => panic!("expected leased, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn a_current_lease_can_nack_a_job() {
        let q = MemoryQueue::new();
        let (_, current) = stale_and_current_lease(&q).await;
        q.nack(
            current.job.id,
            &current.lease,
            "boom",
            RetryPolicy::Retry {
                delay: Duration::from_secs(0),
            },
        )
        .await
        .unwrap();
        match q.status(current.job.id).await.unwrap() {
            JobStatus::Queued => {}
            other => panic!("expected queued, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn a_stale_lease_cannot_extend_a_lease() {
        let q = MemoryQueue::new();
        let (stale, current) = stale_and_current_lease(&q).await;
        let error = q
            .extend_lease(stale.job.id, &stale.lease, Duration::from_secs(30))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            QueueError::AlreadyLeased | QueueError::LeaseExpired
        ));
        match q.status(current.job.id).await.unwrap() {
            JobStatus::Leased { worker, .. } => assert_eq!(worker, "w2"),
            other => panic!("expected leased, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn a_current_lease_can_extend_a_lease() {
        let q = MemoryQueue::new();
        let (_, current) = stale_and_current_lease(&q).await;
        let before = match q.status(current.job.id).await.unwrap() {
            JobStatus::Leased { expires_at, .. } => expires_at,
            other => panic!("expected leased, got {:?}", other),
        };
        let renewed = q
            .extend_lease(current.job.id, &current.lease, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(renewed.worker, current.lease.worker);
        assert!(renewed.generation > current.lease.generation);
        match q.status(current.job.id).await.unwrap() {
            JobStatus::Leased { worker, expires_at } => {
                assert_eq!(worker, "w2");
                assert!(expires_at > before);
            }
            other => panic!("expected leased, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn a_renewed_lease_can_ack_the_job() {
        let q = MemoryQueue::new();
        q.enqueue(job("work")).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        let id = leased[0].job.id;
        let renewed = q
            .extend_lease(id, &leased[0].lease, Duration::from_secs(30))
            .await
            .unwrap();

        q.ack(id, &renewed, Some(vec![5])).await.unwrap();

        match q.status(id).await.unwrap() {
            JobStatus::Succeeded { result, .. } => assert_eq!(result, Some(vec![5])),
            other => panic!("expected succeeded, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn two_extensions_then_nack_succeeds() {
        let q = MemoryQueue::new();
        q.enqueue(job("work")).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        let id = leased[0].job.id;
        let second = q
            .extend_lease(id, &leased[0].lease, Duration::from_secs(30))
            .await
            .unwrap();
        let third = q
            .extend_lease(id, &second, Duration::from_secs(30))
            .await
            .unwrap();

        q.nack(id, &third, "boom", RetryPolicy::NoRetry)
            .await
            .unwrap();

        match q.status(id).await.unwrap() {
            JobStatus::Failed { error, .. } => assert_eq!(error, "boom"),
            other => panic!("expected failed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn a_token_from_before_an_extension_is_rejected() {
        let q = MemoryQueue::new();
        q.enqueue(job("work")).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        let id = leased[0].job.id;
        let old = leased[0].lease.clone();
        let renewed = q
            .extend_lease(id, &old, Duration::from_secs(30))
            .await
            .unwrap();

        let error = q.ack(id, &old, Some(vec![1])).await.unwrap_err();
        assert!(matches!(
            error,
            QueueError::AlreadyLeased | QueueError::LeaseExpired
        ));
        match q.status(id).await.unwrap() {
            JobStatus::Leased { .. } => {}
            other => panic!("expected leased, got {:?}", other),
        }

        q.ack(id, &renewed, Some(vec![1])).await.unwrap();
    }

    #[tokio::test]
    async fn ack_marks_the_job_succeeded() {
        let q = MemoryQueue::new();
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        q.ack(leased[0].job.id, &leased[0].lease, Some(vec![9]))
            .await
            .unwrap();
        match q.status(id).await.unwrap() {
            JobStatus::Succeeded { result, .. } => assert_eq!(result, Some(vec![9])),
            other => panic!("expected succeeded, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn nack_with_retry_requeues_the_job() {
        let q = MemoryQueue::new();
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        q.nack(
            leased[0].job.id,
            &leased[0].lease,
            "boom",
            RetryPolicy::Retry {
                delay: Duration::from_secs(0),
            },
        )
        .await
        .unwrap();
        // attempt incremented
        let leased2 = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased2.len(), 1);
        assert_eq!(leased2[0].job.attempt, 1);
        let _ = id;
    }

    #[tokio::test]
    async fn nack_exhausts_to_dead_letter() {
        let q = MemoryQueue::new();
        let mut j = job("work");
        j.max_attempts = 1;
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        q.nack(
            leased[0].job.id,
            &leased[0].lease,
            "boom",
            RetryPolicy::Retry {
                delay: Duration::from_secs(0),
            },
        )
        .await
        .unwrap();
        match q.status(id).await.unwrap() {
            JobStatus::Dead { .. } => {}
            other => panic!("expected dead, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn expired_lease_is_requeued() {
        let q = MemoryQueue::new();
        q.enqueue(job("work")).await.unwrap();
        // reserve with zero lease
        let _ = q.reserve("w1", 10, Duration::from_secs(0)).await.unwrap();
        // force expiry by sleeping
        tokio::time::sleep(Duration::from_millis(10)).await;
        let leased = q.reserve("w2", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
    }

    #[tokio::test]
    async fn an_expired_lease_counts_as_an_attempt() {
        let q = MemoryQueue::new();
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let _ = q.reserve("w1", 10, Duration::from_secs(0)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let leased = q.reserve("w2", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].job.id, id);
        assert_eq!(leased[0].job.attempt, 1);
    }

    #[tokio::test]
    async fn an_expired_lease_dead_letters_at_the_attempt_limit() {
        let q = MemoryQueue::new();
        let mut j = job("work");
        j.max_attempts = 1;
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let _ = q.reserve("w1", 10, Duration::from_secs(0)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        match q.status(id).await.unwrap() {
            JobStatus::Dead { .. } => {}
            other => panic!("expected dead, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn idempotent_enqueue_returns_existing_id() {
        let q = MemoryQueue::new();
        let mut j1 = job("work");
        j1.idempotency_key = Some("key-1".to_string());
        let id1 = q.enqueue(j1).await.unwrap();
        let mut j2 = job("work");
        j2.id = Uuid::now_v7();
        j2.idempotency_key = Some("key-1".to_string());
        let id2 = q.enqueue(j2).await.unwrap();
        assert_eq!(id1, id2);
    }

    #[tokio::test]
    async fn a_dead_letter_records_the_final_attempt() {
        let q = MemoryQueue::new();
        let mut j = job("work");
        j.max_attempts = 1;
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        q.nack(
            leased[0].job.id,
            &leased[0].lease,
            "boom",
            RetryPolicy::Retry {
                delay: Duration::ZERO,
            },
        )
        .await
        .unwrap();

        let state = q.state.lock().await;
        assert_eq!(state.records[&id].job.attempt, 1);
    }

    #[tokio::test]
    async fn a_sub_second_retry_delay_rounds_up() {
        let q = MemoryQueue::new();
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        let before = MemoryQueue::now();
        q.nack(
            leased[0].job.id,
            &leased[0].lease,
            "boom",
            RetryPolicy::Retry {
                delay: Duration::from_millis(500),
            },
        )
        .await
        .unwrap();
        let after = MemoryQueue::now();

        let state = q.state.lock().await;
        let scheduled_at = state.records[&id].job.scheduled_at;
        assert!(scheduled_at > before, "the job must wait one second");
        assert!(scheduled_at <= after + 1, "the job must not wait too long");
    }

    #[tokio::test]
    async fn the_depth_gauge_tracks_only_queued_jobs() {
        let q = MemoryQueue::new();
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        assert_eq!(q.metrics.depth_value(), 1);

        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(q.metrics.depth_value(), 0);

        q.ack(id, &leased[0].lease, None).await.unwrap();
        assert_eq!(q.metrics.depth_value(), 0);
    }
}
