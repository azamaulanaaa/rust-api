//! Example: in-memory job queue with a worker.
//!
//! Build with `cargo build --example job_queue`.

use std::sync::Arc;

use async_trait::async_trait;
use rust_api::queue::{Job, JobHandler, JobQueue, MemoryQueue, QueueWorker};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct EchoHandler;

#[async_trait]
impl JobHandler for EchoHandler {
    fn kind(&self) -> &'static str {
        "echo"
    }

    async fn handle(&self, job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
        Ok(Some(job.payload.clone()))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let queue = Arc::new(MemoryQueue::new());
    let job = Job {
        id: Uuid::now_v7(),
        kind: "echo".to_string(),
        payload: b"hello".to_vec(),
        priority: 0,
        attempt: 0,
        max_attempts: 3,
        created_at: 0,
        scheduled_at: 0,
        idempotency_key: None,
        headers: std::collections::BTreeMap::new(),
    };
    queue
        .enqueue(job)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let worker = QueueWorker::new(
        queue.clone() as Arc<dyn JobQueue>,
        vec![Arc::new(EchoHandler)],
        "worker-1".to_string(),
    );

    let cancel = CancellationToken::new();
    let handle = tokio::spawn({
        let cancel = cancel.clone();
        async move { worker.run(cancel).await }
    });

    // Let the worker process the job.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    cancel.cancel();
    let _ = handle.await;
    Ok(())
}
