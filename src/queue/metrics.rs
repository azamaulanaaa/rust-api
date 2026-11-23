//! Metrics helpers for the queue.

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};

/// Holds the OpenTelemetry instruments for one queue backend.
#[derive(Debug)]
pub struct QueueMetrics {
    backend: &'static str,
    enqueued: Counter<u64>,
    reserved: Counter<u64>,
    completed: Counter<u64>,
    failed: Counter<u64>,
    lease_lost: Counter<u64>,
    dead_lettered: Counter<u64>,
    depth: Gauge<u64>,
    processing_duration: Histogram<f64>,
    /// Number of calls to [`QueueMetrics::record_failed`] in this process.
    #[cfg(test)]
    failed_total: std::sync::atomic::AtomicU64,
    /// Number of calls to [`QueueMetrics::record_lease_lost`] in this process.
    #[cfg(test)]
    lease_lost_total: std::sync::atomic::AtomicU64,
    /// Last depth that this handle recorded. The field exists for tests.
    #[cfg(test)]
    depth_value: std::sync::atomic::AtomicU64,
}

impl QueueMetrics {
    /// Builds a new set of instruments.
    pub fn new(backend: &'static str) -> Self {
        let meter: Meter = global::meter("rust-api.queue");
        Self {
            backend,
            enqueued: meter.u64_counter("queue.enqueued").build(),
            reserved: meter.u64_counter("queue.reserved").build(),
            completed: meter.u64_counter("queue.completed").build(),
            failed: meter.u64_counter("queue.failed").build(),
            lease_lost: meter.u64_counter("queue.lease_lost").build(),
            dead_lettered: meter.u64_counter("queue.dead_lettered").build(),
            depth: meter.u64_gauge("queue.depth").build(),
            processing_duration: meter.f64_histogram("queue.processing_duration").build(),
            #[cfg(test)]
            failed_total: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            lease_lost_total: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            depth_value: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Records an enqueue.
    pub fn record_enqueued(&self) {
        let attrs = [KeyValue::new("queue.backend", self.backend)];
        self.enqueued.add(1, &attrs);
    }

    /// Records a reserve batch.
    pub fn record_reserved(&self, count: u64) {
        let attrs = [KeyValue::new("queue.backend", self.backend)];
        self.reserved.add(count, &attrs);
    }

    /// Records a completion.
    pub fn record_completed(&self) {
        let attrs = [KeyValue::new("queue.backend", self.backend)];
        self.completed.add(1, &attrs);
    }

    /// Records a failure.
    pub fn record_failed(&self) {
        let attrs = [KeyValue::new("queue.backend", self.backend)];
        self.failed.add(1, &attrs);
        #[cfg(test)]
        self.failed_total
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Records a rejected ack, nack, or lease extension.
    ///
    /// The lease is gone when the call returns `LeaseExpired` or
    /// `AlreadyLeased`. The job did not fail in that case, so the call does
    /// not change the `queue.failed` counter.
    pub fn record_lease_lost(&self) {
        let attrs = [KeyValue::new("queue.backend", self.backend)];
        self.lease_lost.add(1, &attrs);
        #[cfg(test)]
        self.lease_lost_total
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Returns the number of recorded failures. The method exists for tests.
    #[cfg(test)]
    pub(crate) fn failed_count(&self) -> u64 {
        self.failed_total.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns the number of recorded lease losses. The method exists for tests.
    #[cfg(test)]
    pub(crate) fn lease_lost_count(&self) -> u64 {
        self.lease_lost_total
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Records a dead-lettered job.
    pub fn record_dead_lettered(&self) {
        let attrs = [KeyValue::new("queue.backend", self.backend)];
        self.dead_lettered.add(1, &attrs);
    }

    /// Records the current depth.
    pub fn record_depth(&self, depth: u64) {
        let attrs = [KeyValue::new("queue.backend", self.backend)];
        self.depth.record(depth, &attrs);
        #[cfg(test)]
        self.depth_value
            .store(depth, std::sync::atomic::Ordering::SeqCst);
    }

    /// Returns the depth that this handle last recorded. The method exists for tests.
    #[cfg(test)]
    pub(crate) fn depth_value(&self) -> u64 {
        self.depth_value.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Records processing duration in seconds.
    pub fn record_processing_duration(&self, seconds: f64) {
        let attrs = [KeyValue::new("queue.backend", self.backend)];
        self.processing_duration.record(seconds, &attrs);
    }
}
