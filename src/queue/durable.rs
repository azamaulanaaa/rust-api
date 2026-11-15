//! Durable S3/OxKV job queue backend.
//!
//! The backend persists job records under an OxKV store. The caller must
//! pass a shared handle to a store that is already guarded by the
//! single-writer lease. This module does not open a second writer.
//!
//! # Key layout
//!
//! | Key | Value |
//! | --- | --- |
//! | `job:{id}` | Job row. The value is a JSON `StoredJob`. |
//! | `job-status:queued:{id}` | Empty status marker. The job waits to run. |
//! | `job-status:leased:{id}` | Empty status marker. A worker holds the job. |
//! | `job-status:dead:{id}` | Empty status marker. The job has no retries left. |
//! | `job-status:succeeded:{id}` | Empty status marker. The job finished well. |
//! | `job-status:failed:{id}` | Empty status marker. The job failed without retry. |
//! | `idemp:{key}` | Job id for an idempotency key. |
//! | `job-meta:backfilled` | Backfill marker. |
//!
//! A job row has one status marker. The row and the marker change in one
//! transaction. The queue lists one marker family. It does not scan the
//! `job:` family after the backfill.
//!
//! # Backfill
//!
//! An old store has job rows but no status markers. The first `reserve` or
//! `dead_jobs` call scans the `job:` family one time. It writes the marker
//! for each row, including a `Succeeded` or `Failed` row. It writes the
//! `job-meta:backfilled` marker last. Later calls skip the scan. The
//! backfill keeps every terminal row, because the `status` query reads it.
//!
//! # Terminal retention
//!
//! A dead, succeeded, or failed row stays in the store for 7 days. The
//! sweep deletes the row and its marker after that time. A fresh terminal
//! row stays, so `status` returns it.

#[cfg(test)]
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use oxkv::{
    GetSet as _, KeyPrefix, ScanExt as _, Store as _, StoreError, Transaction as _, TxCas as _,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, instrument};
use uuid::Uuid;

use super::{Job, JobId, JobStatus, LeasedJob, QueueError, QueueMetrics, RetryPolicy};

/// Prefix of a job row.
const JOB_PREFIX: &str = "job:";
/// Prefix of a queued status marker.
const QUEUED_PREFIX: &str = "job-status:queued:";
/// Prefix of a leased status marker.
const LEASED_PREFIX: &str = "job-status:leased:";
/// Prefix of a dead status marker.
const DEAD_PREFIX: &str = "job-status:dead:";
/// Prefix of a succeeded status marker.
const SUCCEEDED_PREFIX: &str = "job-status:succeeded:";
/// Prefix of a failed status marker.
const FAILED_PREFIX: &str = "job-status:failed:";
/// Key that marks a completed backfill.
const BACKFILL_KEY: &str = "job-meta:backfilled";
/// Time that a dead, succeeded, or failed row stays in the store: 7 days.
const TERMINAL_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
/// Number of marker keys that one queue scan reads.
const QUEUE_SCAN_PAGE: usize = 512;

/// Persisted envelope for one job.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredJob {
    /// The job.
    job: Job,
    /// Current status.
    status: JobStatus,
}

/// Durable job queue backed by OxKV.
///
/// # Transitions
///
/// | Operation | Job row | Status marker |
/// | --- | --- | --- |
/// | `enqueue` | Write | Write `queued` |
/// | `reserve` | Update | Delete `queued`, write `leased` |
/// | `ack` | Keep `Succeeded` | Delete the old marker, write `succeeded` |
/// | `nack` (retry) | Update | Delete the old marker, write `queued` |
/// | `nack` (dead) | Update | Delete the old marker, write `dead` |
/// | `nack` (failed) | Keep `Failed` | Delete the old marker, write `failed` |
/// | `sweep_expired` | Update | Delete `leased`, write `queued` |
/// | `sweep_expired` retention | Delete the row | Delete the terminal marker |
///
/// Each transition writes the row and the marker in one transaction. A
/// failed read or write returns [`QueueError::Store`].
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
        format!("{JOB_PREFIX}{id}")
    }

    fn queued_key(id: Uuid) -> String {
        format!("{QUEUED_PREFIX}{id}")
    }

    fn leased_key(id: Uuid) -> String {
        format!("{LEASED_PREFIX}{id}")
    }

    fn dead_key(id: Uuid) -> String {
        format!("{DEAD_PREFIX}{id}")
    }

    fn succeeded_key(id: Uuid) -> String {
        format!("{SUCCEEDED_PREFIX}{id}")
    }

    fn failed_key(id: Uuid) -> String {
        format!("{FAILED_PREFIX}{id}")
    }

    fn idempotency_key(key: &str) -> String {
        format!("idemp:{}", key)
    }

    /// Returns the exclusive upper bound of a `prefix:` range scan.
    fn prefix_scan_end(prefix: &str) -> String {
        debug_assert!(prefix.ends_with(':'));
        let mut end = prefix.to_string();
        end.pop();
        end.push(';');
        end
    }

    /// Returns the marker prefix for a status that has one.
    fn status_prefix(status: &JobStatus) -> Option<&'static str> {
        match status {
            JobStatus::Queued => Some(QUEUED_PREFIX),
            JobStatus::Leased { .. } => Some(LEASED_PREFIX),
            JobStatus::Dead { .. } => Some(DEAD_PREFIX),
            JobStatus::Succeeded { .. } => Some(SUCCEEDED_PREFIX),
            JobStatus::Failed { .. } => Some(FAILED_PREFIX),
        }
    }

    /// Returns the marker key for a status that has one.
    fn status_key(status: &JobStatus, id: JobId) -> Option<String> {
        Self::status_prefix(status).map(|prefix| format!("{prefix}{id}"))
    }

    /// Lists the job ids under one marker prefix.
    async fn ids_with_prefix(&self, prefix: &str) -> Result<Vec<JobId>, QueueError> {
        let g = self.store.read().await;
        let mut ids = Vec::new();
        let mut after = None;
        loop {
            let page = g
                .scan_keys(KeyPrefix::new(prefix), after, QUEUE_SCAN_PAGE)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            for key in &page.items {
                if let Some(id) = key.strip_prefix(prefix)
                    && let Ok(id) = id.parse::<Uuid>()
                {
                    ids.push(id);
                }
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Ok(ids)
    }

    /// Writes the status markers for an old store one time.
    ///
    /// The function scans the `job:` family when the backfill marker is
    /// absent. It writes one marker for each row, including a `Succeeded` or
    /// `Failed` row. It keeps every row, because `status` reads it. It
    /// writes the backfill marker last.
    async fn backfill(&self) -> Result<(), QueueError> {
        {
            let g = self.store.read().await;
            if g.has(BACKFILL_KEY)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?
            {
                return Ok(());
            }
        }

        let g = self.store.write().await;
        if g.has(BACKFILL_KEY)
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?
        {
            return Ok(());
        }
        let rows = g
            .gets_bytes(
                None,
                oxkv::Direction::Next,
                (
                    Some(JOB_PREFIX.to_string()),
                    Some(Self::prefix_scan_end(JOB_PREFIX)),
                ),
            )
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
        for kv in &rows {
            match serde_json::from_slice::<StoredJob>(&kv.value) {
                Ok(sj) => {
                    if let Some(marker) = Self::status_key(&sj.status, sj.job.id) {
                        tx.set_bytes(&marker, b"")
                            .await
                            .map_err(|e| QueueError::Store(e.to_string()))?;
                    }
                }
                Err(e) => {
                    debug!(key = %kv.key, error = %e, "skipping job row that does not decode");
                }
            }
        }
        tx.set_bytes(BACKFILL_KEY, b"1")
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        Ok(())
    }

    /// Returns an expired lease to the queue and removes old terminal rows.
    ///
    /// The function lists the `leased`, `dead`, `succeeded`, and `failed`
    /// markers. It does not scan the `job:` family.
    async fn sweep_expired(&self) -> Result<(), QueueError> {
        let now = Self::now();
        for id in self.ids_with_prefix(LEASED_PREFIX).await? {
            let key = Self::job_key(id);
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
            let bytes = tx
                .get_bytes(&key)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            let Some(bytes) = bytes else {
                tx.delete(&Self::leased_key(id))
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                continue;
            };
            let Ok(sj) = serde_json::from_slice::<StoredJob>(&bytes) else {
                let _ = tx.rollback().await;
                continue;
            };
            let expired =
                matches!(sj.status, JobStatus::Leased { expires_at, .. } if expires_at <= now);
            let is_leased = matches!(sj.status, JobStatus::Leased { .. });
            if expired {
                let mut new_sj = sj;
                new_sj.status = JobStatus::Queued;
                let val =
                    serde_json::to_vec(&new_sj).map_err(|e| QueueError::Store(e.to_string()))?;
                tx.set_bytes(&key, &val)
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.delete(&Self::leased_key(id))
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.set_bytes(&Self::queued_key(id), b"")
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
            } else if is_leased {
                let _ = tx.rollback().await;
            } else {
                tx.delete(&Self::leased_key(id))
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
            }
        }

        for prefix in [DEAD_PREFIX, SUCCEEDED_PREFIX, FAILED_PREFIX] {
            self.purge_terminal(prefix, now).await?;
        }
        Ok(())
    }

    /// Deletes the terminal rows under one marker prefix after the retention.
    ///
    /// The function deletes a row and its marker when the status matches the
    /// prefix and `finished_at` is older than the retention window. It
    /// deletes a stale marker when the row is missing or has another status.
    async fn purge_terminal(&self, prefix: &str, now: i64) -> Result<(), QueueError> {
        let cutoff = now - TERMINAL_RETENTION_SECS;
        for id in self.ids_with_prefix(prefix).await? {
            let key = Self::job_key(id);
            let marker = format!("{prefix}{id}");
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
            let bytes = tx
                .get_bytes(&key)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            let Some(bytes) = bytes else {
                tx.delete(&marker)
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                continue;
            };
            let Ok(sj) = serde_json::from_slice::<StoredJob>(&bytes) else {
                debug!(key = %key, "skipping job row that does not decode");
                let _ = tx.rollback().await;
                continue;
            };
            let matches_prefix = Self::status_prefix(&sj.status) == Some(prefix);
            let finished_at = match sj.status {
                JobStatus::Dead { finished_at, .. }
                | JobStatus::Succeeded { finished_at, .. }
                | JobStatus::Failed { finished_at, .. } => Some(finished_at),
                JobStatus::Queued | JobStatus::Leased { .. } => None,
            };
            let expired = matches_prefix && finished_at.is_some_and(|t| t < cutoff);
            if expired {
                tx.delete(&key)
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.delete(&marker)
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
            } else if matches_prefix {
                let _ = tx.rollback().await;
            } else {
                tx.delete(&marker)
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
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

    /// Returns all dead-lettered jobs.
    ///
    /// The function lists the `job-status:dead:` markers. It loads only
    /// those job rows. It returns only jobs with the `Dead` status. The
    /// result is sorted by completion time, newest first. The function skips
    /// rows that do not decode.
    pub async fn dead_jobs(&self) -> Result<Vec<Job>, QueueError> {
        self.backfill().await?;
        let ids = self.ids_with_prefix(DEAD_PREFIX).await?;
        let mut dead: Vec<(i64, Job)> = Vec::new();
        let g = self.store.read().await;
        for id in ids {
            let key = Self::job_key(id);
            let bytes = g
                .get_bytes(&key)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            let Some(bytes) = bytes else {
                continue;
            };
            match serde_json::from_slice::<StoredJob>(&bytes) {
                Ok(sj) => {
                    if let JobStatus::Dead { finished_at, .. } = sj.status {
                        dead.push((finished_at, sj.job));
                    }
                }
                Err(e) => {
                    debug!(key = %key, error = %e, "skipping job row that does not decode");
                }
            }
        }
        drop(g);
        dead.sort_by_key(|a| std::cmp::Reverse(a.0));
        Ok(dead.into_iter().map(|(_, job)| job).collect())
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
        let idempotency_key = job
            .idempotency_key
            .as_ref()
            .map(|key| Self::idempotency_key(key));
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
        tx.set_bytes(&Self::queued_key(id), b"")
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        if let Some(key) = &idempotency_key {
            tx.set_if_absent(key, id.to_string().as_bytes())
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
        }
        match tx.commit().await {
            Ok(()) => {}
            Err(StoreError::TxConflict {
                key,
                current: Some(current),
            }) if Some(&key) == idempotency_key.as_ref() => {
                drop(g);
                let id_str =
                    String::from_utf8(current).map_err(|e| QueueError::Store(e.to_string()))?;
                let existing = id_str
                    .parse::<Uuid>()
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                return Ok(existing);
            }
            Err(StoreError::TxConflict { key, current: None })
                if Some(&key) == idempotency_key.as_ref() =>
            {
                return Err(QueueError::Store(
                    "idempotency key conflict has no stored id".to_string(),
                ));
            }
            Err(error) => return Err(QueueError::Store(error.to_string())),
        }
        drop(g);
        self.metrics.record_enqueued();
        // Best-effort depth for telemetry. Count the queued markers only.
        let depth = self
            .ids_with_prefix(QUEUED_PREFIX)
            .await
            .map(|ids| ids.len() as u64)
            .unwrap_or(0);
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
        self.backfill().await?;
        self.sweep_expired().await?;
        let now = Self::now();
        let ids = self.ids_with_prefix(QUEUED_PREFIX).await?;
        let mut candidates: Vec<StoredJob> = Vec::new();
        {
            let g = self.store.read().await;
            for id in ids {
                let key = Self::job_key(id);
                let bytes = g
                    .get_bytes(&key)
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                let Some(bytes) = bytes else {
                    continue;
                };
                match serde_json::from_slice::<StoredJob>(&bytes) {
                    Ok(sj) => {
                        if matches!(sj.status, JobStatus::Queued) && sj.job.scheduled_at <= now {
                            candidates.push(sj);
                        }
                    }
                    Err(e) => {
                        debug!(key = %key, error = %e, "skipping job row that does not decode");
                    }
                }
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
        for candidate in candidates {
            let id = candidate.job.id;
            let expiry = now + lease_secs;
            let key = Self::job_key(id);
            let g = self.store.write().await;
            let tx = g.begin_tx().map_err(|e| QueueError::Store(e.to_string()))?;
            let bytes = tx
                .get_bytes(&key)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            let Some(bytes) = bytes else {
                tx.delete(&Self::queued_key(id))
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.commit()
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                continue;
            };
            let Ok(mut sj) = serde_json::from_slice::<StoredJob>(&bytes) else {
                let _ = tx.rollback().await;
                continue;
            };
            if !matches!(sj.status, JobStatus::Queued) {
                let _ = tx.rollback().await;
                continue;
            }
            sj.status = JobStatus::Leased {
                worker: worker.to_string(),
                expires_at: expiry,
            };
            let val = serde_json::to_vec(&sj).map_err(|e| QueueError::Store(e.to_string()))?;
            tx.set_bytes(&key, &val)
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            tx.delete(&Self::queued_key(id))
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            tx.set_bytes(&Self::leased_key(id), b"")
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| QueueError::Store(e.to_string()))?;
            drop(g);
            out.push(LeasedJob {
                job: sj.job,
                lease_expires_at: expiry,
            });
        }
        self.metrics.record_reserved(out.len() as u64);
        Ok(out)
    }

    #[instrument(name = "queue.ack", skip(self, result), fields(queue.backend = "durable", job.id = %job_id))]
    async fn ack(&self, job_id: JobId, result: Option<Vec<u8>>) -> Result<(), QueueError> {
        // Keep the `Succeeded` row. The `status` query reads it.
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
        tx.delete(&Self::queued_key(job_id))
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        tx.delete(&Self::leased_key(job_id))
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        tx.delete(&Self::dead_key(job_id))
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        tx.delete(&Self::failed_key(job_id))
            .await
            .map_err(|e| QueueError::Store(e.to_string()))?;
        tx.set_bytes(&Self::succeeded_key(job_id), b"")
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
                tx.delete(&Self::queued_key(job_id))
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.delete(&Self::leased_key(job_id))
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.delete(&Self::dead_key(job_id))
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.delete(&Self::succeeded_key(job_id))
                    .await
                    .map_err(|e| QueueError::Store(e.to_string()))?;
                tx.set_bytes(&Self::failed_key(job_id), b"")
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
                    tx.delete(&Self::queued_key(job_id))
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.delete(&Self::leased_key(job_id))
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.delete(&Self::succeeded_key(job_id))
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.delete(&Self::failed_key(job_id))
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.set_bytes(&Self::dead_key(job_id), b"")
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
                    tx.delete(&Self::leased_key(job_id))
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.delete(&Self::dead_key(job_id))
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.delete(&Self::succeeded_key(job_id))
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.delete(&Self::failed_key(job_id))
                        .await
                        .map_err(|e| QueueError::Store(e.to_string()))?;
                    tx.set_bytes(&Self::queued_key(job_id), b"")
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

    #[tokio::test]
    async fn a_duplicate_idempotent_enqueue_writes_one_job_and_one_marker() {
        let q = queue().await;
        let mut first = job("work");
        first.idempotency_key = Some("key-2".to_string());
        let first_id = first.id;
        let got_first = q.enqueue(first).await.unwrap();
        let mut second = job("work");
        second.id = Uuid::now_v7();
        second.idempotency_key = Some("key-2".to_string());
        let got_second = q.enqueue(second).await.unwrap();

        assert_eq!(got_first, first_id);
        assert_eq!(got_second, first_id, "the stored id must be returned");
        let g = q.store.read().await;
        let job_rows = g
            .count_prefix(KeyPrefix::new(JOB_PREFIX), usize::MAX)
            .await
            .unwrap();
        let queued_rows = g
            .count_prefix(KeyPrefix::new(QUEUED_PREFIX), usize::MAX)
            .await
            .unwrap();
        assert_eq!(job_rows, 1, "one job row must exist");
        assert_eq!(queued_rows, 1, "one queued marker must exist");
    }

    #[tokio::test]
    async fn ids_with_prefix_reads_every_page() {
        let q = queue().await;
        let mut expected = Vec::new();
        {
            let g = q.store.write().await;
            let tx = g.begin_tx().unwrap();
            for _ in 0..(QUEUE_SCAN_PAGE + 1) {
                let id = Uuid::now_v7();
                expected.push(id);
                tx.set_bytes(&DurableQueue::queued_key(id), b"")
                    .await
                    .unwrap();
            }
            tx.commit().await.unwrap();
        }

        let found = q.ids_with_prefix(QUEUED_PREFIX).await.unwrap();

        assert_eq!(found.len(), expected.len());
        expected.sort_unstable();
        let mut found = found;
        found.sort_unstable();
        assert_eq!(found, expected);
    }

    async fn put_job(q: &DurableQueue, job: Job, status: JobStatus) {
        use oxkv::{Store as _, Transaction as _};
        let id = job.id;
        let sj = StoredJob { job, status };
        let val = serde_json::to_vec(&sj).unwrap();
        let g = q.store.write().await;
        let tx = g.begin_tx().unwrap();
        tx.set_bytes(&DurableQueue::job_key(id), &val)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn dead_jobs_returns_empty_when_no_job_is_dead() {
        let q = queue().await;
        q.enqueue(job("work")).await.unwrap();
        let dead = q.dead_jobs().await.unwrap();
        assert!(dead.is_empty());
    }

    #[tokio::test]
    async fn dead_jobs_lists_a_dead_job() {
        let q = queue().await;
        let j = job("work");
        let id = j.id;
        put_job(
            &q,
            j,
            JobStatus::Dead {
                error: "boom".to_string(),
                finished_at: 10,
            },
        )
        .await;
        let dead = q.dead_jobs().await.unwrap();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].id, id);
    }

    #[tokio::test]
    async fn dead_jobs_ignores_a_succeeded_job() {
        let q = queue().await;
        put_job(
            &q,
            job("work"),
            JobStatus::Succeeded {
                result: None,
                finished_at: 10,
            },
        )
        .await;
        let dead = q.dead_jobs().await.unwrap();
        assert!(dead.is_empty());
    }

    #[tokio::test]
    async fn dead_jobs_sorts_newest_first() {
        let q = queue().await;
        let older = job("older");
        let older_id = older.id;
        let newer = job("newer");
        let newer_id = newer.id;
        put_job(
            &q,
            older,
            JobStatus::Dead {
                error: "old".to_string(),
                finished_at: 10,
            },
        )
        .await;
        put_job(
            &q,
            newer,
            JobStatus::Dead {
                error: "new".to_string(),
                finished_at: 20,
            },
        )
        .await;
        let dead = q.dead_jobs().await.unwrap();
        assert_eq!(dead.len(), 2);
        assert_eq!(dead[0].id, newer_id);
        assert_eq!(dead[1].id, older_id);
    }

    #[tokio::test]
    async fn dead_jobs_skips_rows_that_do_not_decode() {
        let q = queue().await;
        let j = job("work");
        let id = j.id;
        put_job(
            &q,
            j,
            JobStatus::Dead {
                error: "boom".to_string(),
                finished_at: 10,
            },
        )
        .await;
        let bad_id = Uuid::now_v7();
        let g = q.store.write().await;
        let tx = g.begin_tx().unwrap();
        tx.set_bytes(&DurableQueue::job_key(bad_id), b"not json")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        drop(g);
        let dead = q.dead_jobs().await.unwrap();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].id, id);
    }

    async fn has_key(q: &DurableQueue, key: &str) -> bool {
        let g = q.store.read().await;
        g.has(key).await.unwrap()
    }

    async fn put_indexed_job(q: &DurableQueue, job: Job, status: JobStatus) {
        use oxkv::{Store as _, Transaction as _};
        let id = job.id;
        let marker = DurableQueue::status_key(&status, id);
        let sj = StoredJob { job, status };
        let val = serde_json::to_vec(&sj).unwrap();
        let g = q.store.write().await;
        let tx = g.begin_tx().unwrap();
        tx.set_bytes(&DurableQueue::job_key(id), &val)
            .await
            .unwrap();
        if let Some(marker) = marker {
            tx.set_bytes(&marker, b"").await.unwrap();
        }
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn status_markers_follow_enqueue_reserve_and_ack() {
        let q = queue().await;
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        assert!(has_key(&q, &DurableQueue::queued_key(id)).await);
        assert!(!has_key(&q, &DurableQueue::leased_key(id)).await);

        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
        assert!(!has_key(&q, &DurableQueue::queued_key(id)).await);
        assert!(has_key(&q, &DurableQueue::leased_key(id)).await);

        q.ack(id, Some(vec![7])).await.unwrap();
        assert!(!has_key(&q, &DurableQueue::queued_key(id)).await);
        assert!(!has_key(&q, &DurableQueue::leased_key(id)).await);
        assert!(!has_key(&q, &DurableQueue::dead_key(id)).await);
        assert!(has_key(&q, &DurableQueue::succeeded_key(id)).await);
        assert!(has_key(&q, &DurableQueue::job_key(id)).await);
        match q.status(id).await.unwrap() {
            JobStatus::Succeeded { result, .. } => assert_eq!(result, Some(vec![7])),
            other => panic!("expected succeeded, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn nack_without_retry_keeps_the_failed_row() {
        let q = queue().await;
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
        q.nack(id, "boom", RetryPolicy::NoRetry).await.unwrap();
        assert!(!has_key(&q, &DurableQueue::queued_key(id)).await);
        assert!(!has_key(&q, &DurableQueue::leased_key(id)).await);
        assert!(!has_key(&q, &DurableQueue::dead_key(id)).await);
        assert!(has_key(&q, &DurableQueue::failed_key(id)).await);
        assert!(has_key(&q, &DurableQueue::job_key(id)).await);
        match q.status(id).await.unwrap() {
            JobStatus::Failed { error, .. } => assert_eq!(error, "boom"),
            other => panic!("expected failed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn nack_with_retry_moves_the_marker_to_queued() {
        let q = queue().await;
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
        q.nack(
            id,
            "boom",
            RetryPolicy::Retry {
                delay: Duration::from_secs(0),
            },
        )
        .await
        .unwrap();
        assert!(!has_key(&q, &DurableQueue::leased_key(id)).await);
        assert!(has_key(&q, &DurableQueue::queued_key(id)).await);
        assert!(!has_key(&q, &DurableQueue::dead_key(id)).await);
    }

    #[tokio::test]
    async fn nack_at_the_attempt_limit_moves_the_marker_to_dead() {
        let q = queue().await;
        let mut j = job("work");
        j.max_attempts = 1;
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
        q.nack(
            id,
            "boom",
            RetryPolicy::Retry {
                delay: Duration::from_secs(0),
            },
        )
        .await
        .unwrap();
        assert!(!has_key(&q, &DurableQueue::leased_key(id)).await);
        assert!(!has_key(&q, &DurableQueue::queued_key(id)).await);
        assert!(has_key(&q, &DurableQueue::dead_key(id)).await);
    }

    #[tokio::test]
    async fn an_expired_lease_sweep_moves_the_marker_to_queued() {
        let q = queue().await;
        let j = job("work");
        let id = j.id;
        q.enqueue(j).await.unwrap();
        let _ = q.reserve("w1", 10, Duration::from_secs(0)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let _ = q.status(id).await.unwrap();
        assert!(!has_key(&q, &DurableQueue::leased_key(id)).await);
        assert!(has_key(&q, &DurableQueue::queued_key(id)).await);
    }

    #[tokio::test]
    async fn reserve_skips_a_future_job_and_returns_a_due_job() {
        let q = queue().await;
        let now = DurableQueue::now();
        let mut future = job("future");
        future.priority = 10;
        future.scheduled_at = now + 3_600;
        let future_id = future.id;
        q.enqueue(future).await.unwrap();
        let mut due = job("due");
        due.priority = 0;
        due.scheduled_at = now - 1;
        let due_id = due.id;
        q.enqueue(due).await.unwrap();

        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].job.id, due_id);
        assert!(has_key(&q, &DurableQueue::queued_key(future_id)).await);
    }

    #[tokio::test]
    async fn reserve_keeps_priority_order_then_created_order() {
        let q = queue().await;
        let mut first_created = job("first");
        first_created.priority = 1;
        first_created.created_at = 10;
        let first_id = first_created.id;
        let mut high = job("high");
        high.priority = 2;
        high.created_at = 20;
        let high_id = high.id;
        let mut last_created = job("last");
        last_created.priority = 1;
        last_created.created_at = 30;
        let last_id = last_created.id;
        q.enqueue(last_created).await.unwrap();
        q.enqueue(high).await.unwrap();
        q.enqueue(first_created).await.unwrap();

        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        let ids: Vec<_> = leased.iter().map(|l| l.job.id).collect();
        assert_eq!(ids, vec![high_id, first_id, last_id]);
    }

    #[tokio::test]
    async fn dead_jobs_returns_newest_first_and_ignores_other_statuses() {
        let q = queue().await;
        let now = DurableQueue::now();
        let mut queued = job("queued");
        queued.created_at = 1;
        q.enqueue(queued).await.unwrap();
        put_indexed_job(
            &q,
            job("leased"),
            JobStatus::Leased {
                worker: "w1".to_string(),
                expires_at: now + 3_600,
            },
        )
        .await;
        let older = job("older");
        let older_id = older.id;
        let newer = job("newer");
        let newer_id = newer.id;
        put_indexed_job(
            &q,
            older,
            JobStatus::Dead {
                error: "old".to_string(),
                finished_at: 10,
            },
        )
        .await;
        put_indexed_job(
            &q,
            newer,
            JobStatus::Dead {
                error: "new".to_string(),
                finished_at: 20,
            },
        )
        .await;

        let dead = q.dead_jobs().await.unwrap();
        assert_eq!(dead.len(), 2);
        assert_eq!(dead[0].id, newer_id);
        assert_eq!(dead[1].id, older_id);
    }

    #[tokio::test]
    async fn reserve_backfills_an_old_store() {
        let q = queue().await;
        let now = DurableQueue::now();
        let succeeded = job("done");
        let succeeded_id = succeeded.id;
        put_job(
            &q,
            succeeded,
            JobStatus::Succeeded {
                result: None,
                finished_at: now,
            },
        )
        .await;
        let failed = job("broken");
        let failed_id = failed.id;
        put_job(
            &q,
            failed,
            JobStatus::Failed {
                error: "boom".to_string(),
                finished_at: now,
            },
        )
        .await;
        let queued = job("waiting");
        let queued_id = queued.id;
        put_job(&q, queued, JobStatus::Queued).await;

        assert!(!has_key(&q, BACKFILL_KEY).await);
        let leased = q.reserve("w1", 10, Duration::from_secs(30)).await.unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].job.id, queued_id);
        assert!(has_key(&q, BACKFILL_KEY).await);
        assert!(has_key(&q, &DurableQueue::leased_key(queued_id)).await);
        assert!(!has_key(&q, &DurableQueue::queued_key(queued_id)).await);
        // The backfill keeps a terminal row and writes its marker.
        assert!(has_key(&q, &DurableQueue::job_key(succeeded_id)).await);
        assert!(has_key(&q, &DurableQueue::succeeded_key(succeeded_id)).await);
        assert!(has_key(&q, &DurableQueue::job_key(failed_id)).await);
        assert!(has_key(&q, &DurableQueue::failed_key(failed_id)).await);
        assert!(!has_key(&q, &DurableQueue::dead_key(succeeded_id)).await);
        assert!(!has_key(&q, &DurableQueue::dead_key(failed_id)).await);
    }

    #[tokio::test]
    async fn sweep_removes_a_dead_row_past_the_retention_window() {
        let q = queue().await;
        let now = DurableQueue::now();
        let old = job("old");
        let old_id = old.id;
        put_indexed_job(
            &q,
            old,
            JobStatus::Dead {
                error: "old".to_string(),
                finished_at: now - TERMINAL_RETENTION_SECS - 1,
            },
        )
        .await;
        let new = job("new");
        let new_id = new.id;
        put_indexed_job(
            &q,
            new,
            JobStatus::Dead {
                error: "new".to_string(),
                finished_at: now,
            },
        )
        .await;

        let _ = q.status(new_id).await.unwrap();
        assert!(!has_key(&q, &DurableQueue::job_key(old_id)).await);
        assert!(!has_key(&q, &DurableQueue::dead_key(old_id)).await);
        assert!(has_key(&q, &DurableQueue::job_key(new_id)).await);
        assert!(has_key(&q, &DurableQueue::dead_key(new_id)).await);
    }

    #[tokio::test]
    async fn sweep_removes_a_succeeded_row_past_the_retention_window() {
        let q = queue().await;
        let now = DurableQueue::now();
        let old = job("old");
        let old_id = old.id;
        put_indexed_job(
            &q,
            old,
            JobStatus::Succeeded {
                result: Some(vec![1]),
                finished_at: now - TERMINAL_RETENTION_SECS - 1,
            },
        )
        .await;
        let new = job("new");
        let new_id = new.id;
        put_indexed_job(
            &q,
            new,
            JobStatus::Succeeded {
                result: Some(vec![2]),
                finished_at: now,
            },
        )
        .await;

        let _ = q.status(new_id).await.unwrap();
        assert!(!has_key(&q, &DurableQueue::job_key(old_id)).await);
        assert!(!has_key(&q, &DurableQueue::succeeded_key(old_id)).await);
        assert!(has_key(&q, &DurableQueue::job_key(new_id)).await);
        assert!(has_key(&q, &DurableQueue::succeeded_key(new_id)).await);
    }

    #[tokio::test]
    async fn sweep_removes_a_failed_row_past_the_retention_window() {
        let q = queue().await;
        let now = DurableQueue::now();
        let old = job("old");
        let old_id = old.id;
        put_indexed_job(
            &q,
            old,
            JobStatus::Failed {
                error: "old".to_string(),
                finished_at: now - TERMINAL_RETENTION_SECS - 1,
            },
        )
        .await;
        let new = job("new");
        let new_id = new.id;
        put_indexed_job(
            &q,
            new,
            JobStatus::Failed {
                error: "new".to_string(),
                finished_at: now,
            },
        )
        .await;

        let _ = q.status(new_id).await.unwrap();
        assert!(!has_key(&q, &DurableQueue::job_key(old_id)).await);
        assert!(!has_key(&q, &DurableQueue::failed_key(old_id)).await);
        assert!(has_key(&q, &DurableQueue::job_key(new_id)).await);
        assert!(has_key(&q, &DurableQueue::failed_key(new_id)).await);
    }

    #[tokio::test]
    async fn a_second_sweep_after_a_purge_does_not_fail() {
        let q = queue().await;
        let now = DurableQueue::now();
        let old = job("old");
        let old_id = old.id;
        put_indexed_job(
            &q,
            old,
            JobStatus::Succeeded {
                result: None,
                finished_at: now - TERMINAL_RETENTION_SECS - 1,
            },
        )
        .await;
        let new = job("new");
        let new_id = new.id;
        put_indexed_job(
            &q,
            new,
            JobStatus::Succeeded {
                result: None,
                finished_at: now,
            },
        )
        .await;

        let _ = q.status(new_id).await.unwrap();
        let _ = q.status(new_id).await.unwrap();
        assert!(!has_key(&q, &DurableQueue::job_key(old_id)).await);
        assert!(!has_key(&q, &DurableQueue::succeeded_key(old_id)).await);
        assert!(has_key(&q, &DurableQueue::job_key(new_id)).await);
        assert!(has_key(&q, &DurableQueue::succeeded_key(new_id)).await);
    }

    #[tokio::test]
    async fn an_idempotent_enqueue_writes_one_marker_and_one_row() {
        let q = queue().await;
        let mut first = job("work");
        first.idempotency_key = Some("key-1".to_string());
        let id = q.enqueue(first).await.unwrap();
        let mut second = job("work");
        second.idempotency_key = Some("key-1".to_string());
        let got = q.enqueue(second).await.unwrap();
        assert_eq!(got, id);
        assert_eq!(q.ids_with_prefix(QUEUED_PREFIX).await.unwrap(), vec![id]);
        assert_eq!(q.ids_with_prefix(JOB_PREFIX).await.unwrap().len(), 1);
    }
}
