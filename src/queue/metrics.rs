//! Metrics helpers for the queue.

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};

/// Holds the OpenTelemetry instruments for one queue backend.
pub struct QueueMetrics {
    backend: &'static str,
    enqueued: Counter<u64>,
    reserved: Counter<u64>,
    completed: Counter<u64>,
    failed: Counter<u64>,
    dead_lettered: Counter<u64>,
    depth: Gauge<u64>,
    processing_duration: Histogram<f64>,
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
            dead_lettered: meter.u64_counter("queue.dead_lettered").build(),
            depth: meter.u64_gauge("queue.depth").build(),
            processing_duration: meter.f64_histogram("queue.processing_duration").build(),
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
    }

    /// Records processing duration in seconds.
    pub fn record_processing_duration(&self, seconds: f64) {
        let attrs = [KeyValue::new("queue.backend", self.backend)];
        self.processing_duration.record(seconds, &attrs);
    }
}
