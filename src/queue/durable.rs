//! Durable S3/OxKV job queue backend.
//!
//! The backend persists job records under an OxKV store. The caller must
//! pass a shared handle to a store that is already guarded by the
//! single-writer lease. This module does not open a second writer.

#[cfg(test)]
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use oxkv::{GetSet as _, Store as _, Transaction as _};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::instrument;
use uuid::Uuid;

use super::{Job, JobId, JobStatus, LeasedJob, QueueError, QueueMetrics, RetryPolicy};

/// Persisted envelope for one job.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredJob {
    /// The job.
    job: Job,
    /// Current status.
    status: JobStatus,
}

/// Durable job queue backed by OxKV.
pub struct DurableQueue {
    store: Arc<RwLock<oxkv::OxKvStore>>,
    metrics: QueueMetrics,
}

impl DurableQueue {
    /// Builds a queue over a shared OxKV handle.
    pub fn new(store: Arc<RwLock<oxkv::OxKvStore>>) -> Self {
        Self {
            store,
            metrics: QueueMetrics::new("durable"),
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn job_key(id: Uuid) -> String {
        format!("job:{}", id)
    }

    fn idempotency_key(key: &str) -> String {
        format!("idemp:{}", key)
    }

    async fn sweep_expired(&self) -> Result<(), QueueError> {
        let handle = Arc::clone(&self.store);
        let g = handle.read().await;
        let kvs = g
            .gets_bytes(None, oxkv::Direction::Next, (None, None))
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        drop(g);
        let now = Self::now();
        let mut expired: Vec<Uuid> = Vec::new();
        for kv in &kvs {
            if !kv.key.starts_with("job:") {
                continue;
            }
            if let Ok(sj) = serde_json::from_slice::<StoredJob>(&kv.value)
                && let JobStatus::Leased { expires_at, .. } = sj.status
                && expires_at <= now
                && let Some(id_str) = kv.key.strip_prefix("job:")
                && let Ok(id) = id_str.parse::<Uuid>()
            {
                expired.push(id);
            }
        }
        for id in expired {
            let key = Self::job_key(id);
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
            if let Some(bytes) = tx
                .get_bytes(&key)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?
            {
                if let Ok(mut sj) = serde_json::from_slice::<StoredJob>(&bytes) {
                    if let JobStatus::Leased { .. } = sj.status {
                        sj.status = JobStatus::Queued;
                        let val = serde_json::to_vec(&sj)
                            .map_err(|e| QueueError::Store(e.to_string()))?;
                        tx.set_bytes(&key, &val)
                            .await
                            .map_err(|e| QueueError::Store(e.to_string()))?;
                        tx.commit()
                            .await
                            .map_err(|e| QueueError::Store(e.to_string()))?;
                    } else {
                        let _ = tx.rollback().await;
                    }
                } else {
                    let _ = tx.rollback().await;
                }
            } else {
                let _ = tx.rollback().await;
            }
        }
        Ok(())
    }

    async fn load(&self, id: JobId) -> Result<StoredJob, QueueError> {
        let key = Self::job_key(id);
        let g = self.store.read().await;
        let bytes = g
            .get_bytes(&key)
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        drop(g);
        let bytes = bytes.ok_or(QueueError::NotFound(id))?;
        serde_json::from_slice(&bytes).map_err(|e| QueueError::Store(e.to_string()))
    }
}

#[async_trait]
impl super::JobQueue for DurableQueue {
    #[instrument(name = "queue.enqueue", skip(self, job), fields(queue.backend = "durable", job.id = %job.id, job.kind = %job.kind))]
    async fn enqueue(&self, job: Job) -> Result<JobId, QueueError> {
        if job.max_attempts == 0 {
            return Err(QueueError::Invalid(
                "max_attempts must be positive".to_string(),
            ));
        }
        let mut job = job;
        super::inject_trace_context(&mut job.headers);
        if let Some(key) = &job.idempotency_key {
            let ik = Self::idempotency_key(key);
            let g = self.store.read().await;
            if let Some(bytes) = g
                .get_bytes(&ik)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?
            {
                drop(g);
                let id_str =
                    String::from_utf8(bytes).map_err(|e| QueueError::Store(e.to_string()))?;
                if let Ok(id) = id_str.parse::<Uuid>() {
                    return Ok(id);
                }
            } else {
                drop(g);
            }
        }
        let id = job.id;
        let sj = StoredJob {
            job: job.clone(),
            status: JobStatus::Queued,
        };
        let val = serde_json::to_vec(&sj).map_err(|e| QueueError::Store(e.to_string()))?;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
        tx.set_bytes(&Self::job_key(id), &val)
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        if let Some(key) = &job.idempotency_key {
            tx.set_bytes(&Self::idempotency_key(key), id.to_string().as_bytes())
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
        }
        tx.commit()
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        drop(g);
        self.metrics.record_enqueued();
        // Best-effort depth for telemetry.
        let depth = {
            let guard = self.store.read().await;
            guard
                .gets_bytes(None, oxkv::Direction::Next, (None, None))
                .await
                .map(|kvs| kvs.iter().filter(|kv| kv.key.starts_with("job:")).count() as u64)
                .unwrap_or(0)
        };
        self.metrics.record_depth(depth);
        Ok(id)
    }

    #[instrument(name = "queue.reserve", skip(self), fields(queue.backend = "durable", worker = %worker, limit = %limit))]
    async fn reserve(
        &self,
        worker: &str,
        limit: usize,
        lease: Duration,
    ) -> Result<Vec<LeasedJob>, QueueError> {
        self.sweep_expired().await?;
        let g = self.store.read().await;
        let kvs = g
            .gets_bytes(None, oxkv::Direction::Next, (None, None))
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        drop(g);
        let now = Self::now();
        let mut candidates: Vec<StoredJob> = Vec::new();
        for kv in &kvs {
            if !kv.key.starts_with("job:") {
                continue;
            }
            if let Ok(sj) = serde_json::from_slice::<StoredJob>(&kv.value)
                && matches!(sj.status, JobStatus::Queued)
                && sj.job.scheduled_at <= now
            {
                candidates.push(sj);
            }
        }
        candidates.sort_by(|a, b| {
            b.job
                .priority
                .cmp(&a.job.priority)
                .then(a.job.created_at.cmp(&b.job.created_at))
        });
        candidates.truncate(limit);
        let lease_secs = lease.as_secs() as i64;
        let mut out = Vec::new();
        for sj in candidates {
            let id = sj.job.id;
            let expiry = now + lease_secs;
            let mut new_sj = sj.clone();
            new_sj.status = JobStatus::Leased {
                worker: worker.to_string(),
                expires_at: expiry,
            };
            let val = serde_json::to_vec(&new_sj).map_err(|e| QueueError::Store(e.to_string()))?;
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
            tx.set_bytes(&Self::job_key(id), &val)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            drop(g);
            out.push(LeasedJob {
                job: new_sj.job,
                lease_expires_at: expiry,
            });
        }
        self.metrics.record_reserved(out.len() as u64);
        Ok(out)
    }

    #[instrument(name = "queue.ack", skip(self, result), fields(queue.backend = "durable", job.id = %job_id))]
    async fn ack(&self, job_id: JobId, result: Option<Vec<u8>>) -> Result<(), QueueError> {
        let mut sj = self.load(job_id).await?;
        let finished = Self::now();
        sj.status = JobStatus::Succeeded {
            result: result.clone(),
            finished_at: finished,
        };
        let val = serde_json::to_vec(&sj).map_err(|e| QueueError::Store(e.to_string()))?;
        let g = self.store.write().await;
        let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
        tx.set_bytes(&Self::job_key(job_id), &val)
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        drop(g);
        self.metrics.record_completed();
        Ok(())
    }

    #[instrument(name = "queue.nack", skip(self), fields(queue.backend = "durable", job.id = %job_id, error = %error))]
    async fn nack(&self, job_id: JobId, error: &str, retry: RetryPolicy) -> Result<(), QueueError> {
        let mut sj = self.load(job_id).await?;
        let finished = Self::now();
        match retry {
            RetryPolicy::NoRetry => {
                sj.status = JobStatus::Failed {
                    error: error.to_string(),
                    finished_at: finished,
                };
                let val = serde_json::to_vec(&sj).map_err(|e| QueueError::Store(e.to_string()))?;
                let g = self.store.write().await;
                let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
                tx.set_bytes(&Self::job_key(job_id), &val)
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                drop(g);
                self.metrics.record_failed();
            }
            RetryPolicy::Retry { delay } => {
                if sj.job.attempt.saturating_add(1) >= sj.job.max_attempts {
                    sj.status = JobStatus::Dead {
                        error: error.to_string(),
                        finished_at: finished,
                    };
                    let val =
                        serde_json::to_vec(&sj).map_err(|e| QueueError::Store(e.to_string()))?;
                    let g = self.store.write().await;
                    let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.set_bytes(&Self::job_key(job_id), &val)
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.commit()
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    drop(g);
                    self.metrics.record_dead_lettered();
                    self.metrics.record_failed();
                } else {
                    sj.job.attempt = sj.job.attempt.saturating_add(1);
                    sj.job.scheduled_at = finished + delay.as_secs() as i64;
                    sj.status = JobStatus::Queued;
                    let val =
                        serde_json::to_vec(&sj).map_err(|e| QueueError::Store(e.to_string()))?;
                    let g = self.store.write().await;
                    let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.set_bytes(&Self::job_key(job_id), &val)
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.commit()
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    drop(g);
                    self.metrics.record_failed();
                }
            }
        }
        Ok(())
    }

    #[instrument(name = "queue.extend_lease", skip(self), fields(queue.backend = "durable", job.id = %job_id))]
    async fn extend_lease(&self, job_id: JobId, lease: Duration) -> Result<(), QueueError> {
        self.sweep_expired().await?;
        let mut sj = self.load(job_id).await?;
        let now = Self::now();
        match &sj.status {
            JobStatus::Leased { expires_at, worker } => {
                if *expires_at <= now {
                    return Err(QueueError::LeaseExpired);
                }
                let worker = worker.clone();
                let new_expiry = now + lease.as_secs() as i64;
                sj.status = JobStatus::Leased {
                    worker,
                    expires_at: new_expiry,
                };
                let val = serde_json::to_vec(&sj).map_err(|e| QueueError::Store(e.to_string()))?;
                let g = self.store.write().await;
                let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
                tx.set_bytes(&Self::job_key(job_id), &val)
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                drop(g);
            }
            _ => return Err(QueueError::AlreadyLeased),
        }
        Ok(())
    }

    #[instrument(name = "queue.status", skip(self), fields(queue.backend = "durable", job.id = %job_id))]
    async fn status(&self, job_id: JobId) -> Result<JobStatus, QueueError> {
        self.sweep_expired().await?;
        let sj = self.load(job_id).await?;
        Ok(sj.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::queue::{Job, JobQueue, JobStatus, RetryPolicy};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;
    use uuid::Uuid;

    async fn queue() -> DurableQueue {
        let prefix = db::test_prefix("queue-durable");
        let store = db::build_test_store(&prefix).await;
        DurableQueue::new(Arc::new(RwLock::new(store)))
    }

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
        let q = queue().await;
        let j = job("work");
        let id = j.id;
        let got = q.enqueue(j).await.unwrap();
        assert_eq!(got, id);
    }

    #[tokio::test]
    async fn reserve_returns_leased_jobs() {
        let q = queue().await;
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
        let q = queue().await;
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
        let q = queue().await;
        q.enqueue(job("work")).await.unwrap();
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
        let leased2 = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased2.len(), 1);
        assert_eq!(leased2[0].job.attempt, 1);
    }

    #[tokio::test]
    async fn nack_exhausts_to_dead_letter() {
        let q = queue().await;
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
        let q = queue().await;
        q.enqueue(job("work")).await.unwrap();
        let _ = q.reserve("w1", 10, Duration::from_secs(0)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let leased = q.reserve("w2", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
    }

    #[tokio::test]
    async fn idempotent_enqueue_returns_existing_id() {
        let q = queue().await;
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
