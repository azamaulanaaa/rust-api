//! Metrics helpers for the EAV runtime.
//!
//! [`EavMetrics`] holds one instrument for each runtime event.
//! The instruments use the meter `rust-api.eav`.
//! The module adds no business logic.

use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};

/// The meter name for the EAV metrics.
const METER: &str = "rust-api.eav";

/// Holds the OpenTelemetry instruments for the EAV runtime.
#[derive(Clone)]
pub struct EavMetrics {
    outbox_flushed: Counter<u64>,
    outbox_failed: Counter<u64>,
    outbox_pending: Gauge<u64>,
    outbox_duration: Histogram<f64>,
    rules_executed: Counter<u64>,
    rules_failed: Counter<u64>,
    timers_fired: Counter<u64>,
    timers_failed: Counter<u64>,
    timers_due: Gauge<u64>,
    timer_duration: Histogram<f64>,
    webhook_delivered: Counter<u64>,
    webhook_failed: Counter<u64>,
    webhook_duration: Histogram<f64>,
}

impl EavMetrics {
    /// Builds the EAV instruments from the global meter.
    pub fn new() -> Self {
        let meter: Meter = global::meter(METER);
        Self {
            outbox_flushed: meter.u64_counter("eav.outbox.flushed").build(),
            outbox_failed: meter.u64_counter("eav.outbox.failed").build(),
            outbox_pending: meter.u64_gauge("eav.outbox.pending").build(),
            outbox_duration: meter.f64_histogram("eav.outbox.flush_duration").build(),
            rules_executed: meter.u64_counter("eav.rules.executed").build(),
            rules_failed: meter.u64_counter("eav.rules.failed").build(),
            timers_fired: meter.u64_counter("eav.timers.fired").build(),
            timers_failed: meter.u64_counter("eav.timers.failed").build(),
            timers_due: meter.u64_gauge("eav.timers.due").build(),
            timer_duration: meter.f64_histogram("eav.timer.pass_duration").build(),
            webhook_delivered: meter.u64_counter("eav.webhook.delivered").build(),
            webhook_failed: meter.u64_counter("eav.webhook.failed").build(),
            webhook_duration: meter.f64_histogram("eav.webhook.delivery_duration").build(),
        }
    }

    /// Returns the process-wide metrics.
    ///
    /// The first call builds the instruments.
    /// Every later call returns a clone.
    pub fn global() -> Self {
        static METRICS: OnceLock<EavMetrics> = OnceLock::new();
        METRICS.get_or_init(Self::new).clone()
    }

    /// Records one outbox flush.
    ///
    /// The call records the delivered count and the elapsed time in seconds.
    pub fn record_outbox_flush(&self, count: u64, duration: Duration) {
        let attrs = [KeyValue::new("component", "outbox")];
        self.outbox_flushed.add(count, &attrs);
        self.outbox_duration.record(duration.as_secs_f64(), &attrs);
    }

    /// Records one outbox failure.
    pub fn record_outbox_failure(&self) {
        let attrs = [KeyValue::new("component", "outbox")];
        self.outbox_failed.add(1, &attrs);
    }

    /// Records the current number of pending outbox rows.
    pub fn record_outbox_pending(&self, count: u64) {
        let attrs = [KeyValue::new("component", "outbox")];
        self.outbox_pending.record(count, &attrs);
    }

    /// Records one executed rule.
    pub fn record_rule_executed(&self) {
        let attrs = [KeyValue::new("component", "rules")];
        self.rules_executed.add(1, &attrs);
    }

    /// Records one failed rule action.
    pub fn record_rule_failed(&self) {
        let attrs = [KeyValue::new("component", "rules")];
        self.rules_failed.add(1, &attrs);
    }

    /// Records one timer pass.
    ///
    /// The call records the fired count and the elapsed time in seconds.
    pub fn record_timer_fired(&self, count: u64, duration: Duration) {
        let attrs = [KeyValue::new("component", "timers")];
        self.timers_fired.add(count, &attrs);
        self.timer_duration.record(duration.as_secs_f64(), &attrs);
    }

    /// Records one timer pass failure.
    pub fn record_timer_failure(&self) {
        let attrs = [KeyValue::new("component", "timers")];
        self.timers_failed.add(1, &attrs);
    }

    /// Records the current number of due timer entities.
    pub fn record_timer_due(&self, count: u64) {
        let attrs = [KeyValue::new("component", "timers")];
        self.timers_due.record(count, &attrs);
    }

    /// Records one successful webhook delivery.
    ///
    /// The call records the elapsed time in seconds.
    pub fn record_webhook_delivered(&self, duration: Duration) {
        let attrs = [KeyValue::new("component", "webhook")];
        self.webhook_delivered.add(1, &attrs);
        self.webhook_duration.record(duration.as_secs_f64(), &attrs);
    }

    /// Records one failed webhook delivery.
    pub fn record_webhook_failure(&self) {
        let attrs = [KeyValue::new("component", "webhook")];
        self.webhook_failed.add(1, &attrs);
    }
}

impl Default for EavMetrics {
    /// Returns a new set of EAV instruments.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_record_method_runs_without_panic() {
        let metrics = EavMetrics::new();

        metrics.record_outbox_flush(2, Duration::from_millis(5));
        metrics.record_outbox_failure();
        metrics.record_outbox_pending(3);
        metrics.record_rule_executed();
        metrics.record_rule_failed();
        metrics.record_timer_fired(4, Duration::from_millis(5));
        metrics.record_timer_failure();
        metrics.record_timer_due(5);
        metrics.record_webhook_delivered(Duration::from_millis(5));
        metrics.record_webhook_failure();
    }

    #[test]
    fn global_returns_a_usable_clone() {
        let first = EavMetrics::global();
        let second = first.clone();

        second.record_rule_executed();
    }
}
