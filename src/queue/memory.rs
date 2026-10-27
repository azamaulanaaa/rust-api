//! In-memory job queue backend.
//!
//! The backend is non-durable. Use it for tests and local development.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::instrument;

use super::{Job, JobId, JobStatus, LeasedJob, QueueError, QueueMetrics, RetryPolicy};

/// Internal record held by the in-memory backend.
#[derive(Clone)]
struct Record {
    job: Job,
    status: JobStatus,
    worker: Option<String>,
    lease_expires_at: Option<i64>,
    result: Option<Vec<u8>>,
    error: Option<String>,
    finished_at: Option<i64>,
}

/// In-memory job queue.
pub struct MemoryQueue {
    state: Arc<Mutex<State>>,
    metrics: QueueMetrics,
}

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

    fn sweep_expired(state: &mut State) {
        let now = Self::now();
        for rec in state.records.values_mut() {
            if let JobStatus::Leased { expires_at, .. } = rec.status
                && expires_at <= now
            {
                rec.status = JobStatus::Queued;
                rec.worker = None;
                rec.lease_expires_at = None;
            }
        }
    }
}

impl Default for MemoryQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl super::JobQueue for MemoryQueue {
    #[instrument(skip(self, job))]
    async fn enqueue(&self, job: Job) -> Result<JobId, QueueError> {
        if job.max_attempts == 0 {
            return Err(QueueError::Invalid(
                "max_attempts must be positive".to_string(),
            ));
        }
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
            worker: None,
            lease_expires_at: None,
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
        self.metrics
            .record_depth(self.state.lock().await.records.len() as u64);
        Ok(id)
    }

    #[instrument(skip(self))]
    async fn reserve(
        &self,
        worker: &str,
        limit: usize,
        lease: Duration,
    ) -> Result<Vec<LeasedJob>, QueueError> {
        let mut state = self.state.lock().await;
        Self::sweep_expired(&mut state);
        let now = Self::now();
        let lease_secs = lease.as_secs() as i64;
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
            rec.status = JobStatus::Leased {
                worker: worker.to_string(),
                expires_at: now + lease_secs,
            };
            rec.worker = Some(worker.to_string());
            rec.lease_expires_at = Some(now + lease_secs);
            out.push(LeasedJob {
                job: rec.job.clone(),
                lease_expires_at: now + lease_secs,
            });
        }
        drop(state);
        self.metrics.record_reserved(out.len() as u64);
        Ok(out)
    }

    #[instrument(skip(self, result))]
    async fn ack(&self, job_id: JobId, result: Option<Vec<u8>>) -> Result<(), QueueError> {
        let mut state = self.state.lock().await;
        let rec = state
            .records
            .get_mut(&job_id)
            .ok_or(QueueError::NotFound(job_id))?;
        let finished = Self::now();
        rec.status = JobStatus::Succeeded {
            result: result.clone(),
            finished_at: finished,
        };
        rec.result = result;
        rec.finished_at = Some(finished);
        rec.worker = None;
        rec.lease_expires_at = None;
        drop(state);
        self.metrics.record_completed();
        Ok(())
    }

    #[instrument(skip(self))]
    async fn nack(&self, job_id: JobId, error: &str, retry: RetryPolicy) -> Result<(), QueueError> {
        let mut state = self.state.lock().await;
        let rec = state
            .records
            .get_mut(&job_id)
            .ok_or(QueueError::NotFound(job_id))?;
        let finished = Self::now();
        match retry {
            RetryPolicy::NoRetry => {
                rec.status = JobStatus::Failed {
                    error: error.to_string(),
                    finished_at: finished,
                };
                rec.error = Some(error.to_string());
                rec.finished_at = Some(finished);
                rec.worker = None;
                rec.lease_expires_at = None;
                drop(state);
                self.metrics.record_failed();
            }
            RetryPolicy::Retry { delay } => {
                let attempt = rec.job.attempt;
                if attempt.saturating_add(1) >= rec.job.max_attempts {
                    rec.status = JobStatus::Dead {
                        error: error.to_string(),
                        finished_at: finished,
                    };
                    rec.error = Some(error.to_string());
                    rec.finished_at = Some(finished);
                    rec.worker = None;
                    rec.lease_expires_at = None;
                    drop(state);
                    self.metrics.record_dead_lettered();
                    self.metrics.record_failed();
                } else {
                    rec.job.attempt = attempt.saturating_add(1);
                    rec.job.scheduled_at = finished + delay.as_secs() as i64;
                    rec.status = JobStatus::Queued;
                    rec.error = Some(error.to_string());
                    rec.worker = None;
                    rec.lease_expires_at = None;
                    drop(state);
                    self.metrics.record_failed();
                }
            }
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn extend_lease(&self, job_id: JobId, lease: Duration) -> Result<(), QueueError> {
        let mut state = self.state.lock().await;
        Self::sweep_expired(&mut state);
        let rec = state
            .records
            .get_mut(&job_id)
            .ok_or(QueueError::NotFound(job_id))?;
        match &rec.status {
            JobStatus::Leased { expires_at, .. } => {
                let now = Self::now();
                if *expires_at <= now {
                    return Err(QueueError::LeaseExpired);
                }
                let new_expiry = now + lease.as_secs() as i64;
                rec.status = JobStatus::Leased {
                    worker: rec.worker.clone().unwrap_or_default(),
                    expires_at: new_expiry,
                };
                rec.lease_expires_at = Some(new_expiry);
            }
            _ => return Err(QueueError::AlreadyLeased),
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn status(&self, job_id: JobId) -> Result<JobStatus, QueueError> {
        let mut state = self.state.lock().await;
        Self::sweep_expired(&mut state);
        let rec = state
            .records
            .get(&job_id)
            .ok_or(QueueError::NotFound(job_id))?;
        Ok(rec.status.clone())
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
    async fn ack_marks_the_job_succeeded() {
        let q = MemoryQueue::new();
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        q.ack(leased[0].job.id, Some(vec![9])).await.unwrap();
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
}
