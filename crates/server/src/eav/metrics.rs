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

use crate::rules::engine::{ExecutionOutcome, RuleObserver};

/// The meter name for the EAV metrics.
const METER: &str = "rust-api.eav";

/// Holds the OpenTelemetry instruments for the EAV runtime.
#[derive(Clone)]
pub struct EavMetrics {
    entity_writes: Counter<u64>,
    entity_deletes: Counter<u64>,
    entity_version_conflicts: Counter<u64>,
    entity_unique_conflicts: Counter<u64>,
    outbox_flushed: Counter<u64>,
    outbox_failed: Counter<u64>,
    outbox_pending: Gauge<u64>,
    outbox_pending_age: Gauge<f64>,
    outbox_duration: Histogram<f64>,
    rules_executed: Counter<u64>,
    rules_failed: Counter<u64>,
    rules_dead_lettered: Counter<u64>,
    feed_lag: Gauge<u64>,
    timers_fired: Counter<u64>,
    timers_failed: Counter<u64>,
    timers_due: Gauge<u64>,
    timer_duration: Histogram<f64>,
    webhook_delivered: Counter<u64>,
    webhook_failed: Counter<u64>,
    webhook_duration: Histogram<f64>,
    replica_builds: Counter<u64>,
    replica_build_failures: Counter<u64>,
    replica_build_duration: Histogram<f64>,
}

impl EavMetrics {
    /// Builds the EAV instruments from the global meter.
    pub fn new() -> Self {
        Self::from_meter(global::meter(METER))
    }

    /// Builds the EAV instruments from `meter`.
    fn from_meter(meter: Meter) -> Self {
        Self {
            entity_writes: meter.u64_counter("eav.entity.writes").build(),
            entity_deletes: meter.u64_counter("eav.entity.deletes").build(),
            entity_version_conflicts: meter.u64_counter("eav.entity.version_conflicts").build(),
            entity_unique_conflicts: meter.u64_counter("eav.entity.unique_conflicts").build(),
            outbox_flushed: meter.u64_counter("eav.outbox.flushed").build(),
            outbox_failed: meter.u64_counter("eav.outbox.failed").build(),
            outbox_pending: meter.u64_gauge("eav.outbox.pending").build(),
            outbox_pending_age: meter.f64_gauge("eav.outbox.pending_age").build(),
            outbox_duration: meter.f64_histogram("eav.outbox.flush_duration").build(),
            rules_executed: meter.u64_counter("eav.rules.executed").build(),
            rules_failed: meter.u64_counter("eav.rules.failed").build(),
            rules_dead_lettered: meter.u64_counter("eav.rules.dead_lettered").build(),
            feed_lag: meter.u64_gauge("eav.feed.lag").build(),
            timers_fired: meter.u64_counter("eav.timers.fired").build(),
            timers_failed: meter.u64_counter("eav.timers.failed").build(),
            timers_due: meter.u64_gauge("eav.timers.due").build(),
            timer_duration: meter.f64_histogram("eav.timer.pass_duration").build(),
            webhook_delivered: meter.u64_counter("eav.webhook.delivered").build(),
            webhook_failed: meter.u64_counter("eav.webhook.failed").build(),
            webhook_duration: meter.f64_histogram("eav.webhook.delivery_duration").build(),
            replica_builds: meter.u64_counter("eav.replica.builds").build(),
            replica_build_failures: meter.u64_counter("eav.replica.build_failures").build(),
            replica_build_duration: meter.f64_histogram("eav.replica.build_duration").build(),
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

    /// Records the age of the oldest pending outbox row, in seconds.
    ///
    /// A caller with no pending row records zero.
    pub fn record_outbox_pending_age(&self, age: Duration) {
        let attrs = [KeyValue::new("component", "outbox")];
        self.outbox_pending_age.record(age.as_secs_f64(), &attrs);
    }

    /// Records one or more committed entity writes.
    pub fn record_entity_writes(&self, count: u64) {
        let attrs = [KeyValue::new("component", "entity")];
        self.entity_writes.add(count, &attrs);
    }

    /// Records one or more committed entity deletes.
    pub fn record_entity_deletes(&self, count: u64) {
        let attrs = [KeyValue::new("component", "entity")];
        self.entity_deletes.add(count, &attrs);
    }

    /// Records one entity version conflict.
    pub fn record_entity_version_conflict(&self) {
        let attrs = [KeyValue::new("component", "entity")];
        self.entity_version_conflicts.add(1, &attrs);
    }

    /// Records one entity unique conflict.
    pub fn record_entity_unique_conflict(&self) {
        let attrs = [KeyValue::new("component", "entity")];
        self.entity_unique_conflicts.add(1, &attrs);
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

    /// Records one or more rule dead letters.
    pub fn record_rule_dead_letter(&self, count: u64) {
        let attrs = [KeyValue::new("component", "rules")];
        self.rules_dead_lettered.add(count, &attrs);
    }

    /// Records the distance from the rule cursor to the feed head.
    pub fn record_feed_lag(&self, entries: u64) {
        let attrs = [KeyValue::new("component", "rules")];
        self.feed_lag.record(entries, &attrs);
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

    /// Records one completed replica build and its duration.
    pub fn record_replica_build(&self, duration: Duration) {
        let attrs = [KeyValue::new("component", "replica")];
        self.replica_builds.add(1, &attrs);
        self.replica_build_duration
            .record(duration.as_secs_f64(), &attrs);
    }

    /// Records one failed replica build.
    pub fn record_replica_build_failure(&self) {
        let attrs = [KeyValue::new("component", "replica")];
        self.replica_build_failures.add(1, &attrs);
    }
}

impl Default for EavMetrics {
    /// Returns a new set of EAV instruments.
    fn default() -> Self {
        Self::new()
    }
}

/// Test helpers that read the recorded metric values.
#[cfg(test)]
pub(crate) mod test_support {
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};

    use super::EavMetrics;

    /// One meter provider and its in-memory exporter.
    pub(crate) struct MetricCapture {
        provider: SdkMeterProvider,
        exporter: InMemoryMetricExporter,
    }

    impl MetricCapture {
        /// Builds a private meter provider and a set of instruments.
        pub(crate) fn new() -> (EavMetrics, Self) {
            let exporter = InMemoryMetricExporter::default();
            let provider = SdkMeterProvider::builder()
                .with_periodic_exporter(exporter.clone())
                .build();
            let metrics = EavMetrics::from_meter(provider.meter("eav-test"));
            (metrics, Self { provider, exporter })
        }

        /// Exports the current values and returns the newest set.
        fn latest(&self) -> Vec<opentelemetry_sdk::metrics::data::ResourceMetrics> {
            self.provider
                .force_flush()
                .expect("the meter provider must flush");
            self.exporter
                .get_finished_metrics()
                .expect("the in-memory exporter must return its metrics")
        }

        /// Returns the value of one u64 counter by name.
        pub(crate) fn counter(&self, name: &str) -> u64 {
            let exports = self.latest();
            let metric = exports
                .last()
                .and_then(|resource| {
                    resource
                        .scope_metrics()
                        .flat_map(|scope| scope.metrics())
                        .find(|metric| metric.name() == name)
                })
                .unwrap_or_else(|| panic!("metric {name} was not exported"));
            let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
                panic!("metric {name} is not a u64 counter");
            };
            sum.data_points().map(|point| point.value()).sum()
        }

        /// Returns the value of one u64 gauge by name.
        pub(crate) fn gauge(&self, name: &str) -> u64 {
            let exports = self.latest();
            let metric = exports
                .last()
                .and_then(|resource| {
                    resource
                        .scope_metrics()
                        .flat_map(|scope| scope.metrics())
                        .find(|metric| metric.name() == name)
                })
                .unwrap_or_else(|| panic!("metric {name} was not exported"));
            let AggregatedMetrics::U64(MetricData::Gauge(gauge)) = metric.data() else {
                panic!("metric {name} is not a u64 gauge");
            };
            gauge
                .data_points()
                .map(|point| point.value())
                .max()
                .unwrap_or(0)
        }

        /// Returns the value of one f64 gauge by name.
        pub(crate) fn f64_gauge(&self, name: &str) -> f64 {
            let exports = self.latest();
            let metric = exports
                .last()
                .and_then(|resource| {
                    resource
                        .scope_metrics()
                        .flat_map(|scope| scope.metrics())
                        .find(|metric| metric.name() == name)
                })
                .unwrap_or_else(|| panic!("metric {name} was not exported"));
            let AggregatedMetrics::F64(MetricData::Gauge(gauge)) = metric.data() else {
                panic!("metric {name} is not an f64 gauge");
            };
            gauge
                .data_points()
                .map(|point| point.value())
                .next()
                .unwrap_or(0.0)
        }

        /// Returns the sample count of one f64 histogram by name.
        pub(crate) fn histogram_count(&self, name: &str) -> u64 {
            let exports = self.latest();
            let metric = exports
                .last()
                .and_then(|resource| {
                    resource
                        .scope_metrics()
                        .flat_map(|scope| scope.metrics())
                        .find(|metric| metric.name() == name)
                })
                .unwrap_or_else(|| panic!("metric {name} was not exported"));
            let AggregatedMetrics::F64(MetricData::Histogram(histogram)) = metric.data() else {
                panic!("metric {name} is not an f64 histogram");
            };
            histogram.data_points().map(|point| point.count()).sum()
        }
    }
}

impl RuleObserver for EavMetrics {
    /// Records a rule result.
    ///
    /// Only [`ExecutionOutcome::Executed`] increments the executed counter.
    /// No other outcome increments the failed counter.
    fn on_execution(&self, outcome: ExecutionOutcome) {
        if outcome == ExecutionOutcome::Executed {
            self.record_rule_executed();
        }
    }

    /// Records one failed rule action.
    fn on_action_failure(&self) {
        self.record_rule_failed();
    }

    /// Records dead-lettered rules.
    fn on_dead_letter(&self, count: u64) {
        self.record_rule_dead_letter(count);
    }

    /// Records the distance from the rule cursor to the feed head.
    fn on_feed_lag(&self, entries: u64) {
        self.record_feed_lag(entries);
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MetricCapture;
    use super::*;

    #[test]
    fn every_record_method_runs_without_panic() {
        let metrics = EavMetrics::new();

        metrics.record_outbox_flush(2, Duration::from_millis(5));
        metrics.record_outbox_failure();
        metrics.record_outbox_pending(3);
        metrics.record_outbox_pending_age(Duration::from_secs(4));
        metrics.record_entity_writes(1);
        metrics.record_entity_deletes(1);
        metrics.record_entity_version_conflict();
        metrics.record_entity_unique_conflict();
        metrics.record_rule_executed();
        metrics.record_rule_failed();
        metrics.record_rule_dead_letter(2);
        metrics.record_feed_lag(7);
        metrics.record_timer_fired(4, Duration::from_millis(5));
        metrics.record_timer_failure();
        metrics.record_timer_due(5);
        metrics.record_webhook_delivered(Duration::from_millis(5));
        metrics.record_webhook_failure();
        metrics.record_replica_build(Duration::from_millis(5));
        metrics.record_replica_build_failure();
    }

    #[test]
    fn counter_values_reflect_the_recorded_events() {
        let (metrics, capture) = MetricCapture::new();

        metrics.record_entity_writes(3);
        metrics.record_entity_writes(2);
        metrics.record_entity_deletes(4);
        metrics.record_entity_version_conflict();
        metrics.record_entity_version_conflict();
        metrics.record_entity_unique_conflict();
        metrics.record_rule_dead_letter(2);
        metrics.record_rule_dead_letter(1);
        metrics.record_replica_build(Duration::from_millis(20));
        metrics.record_replica_build_failure();
        metrics.record_outbox_failure();
        metrics.record_outbox_flush(6, Duration::from_millis(5));

        assert_eq!(capture.counter("eav.entity.writes"), 5);
        assert_eq!(capture.counter("eav.entity.deletes"), 4);
        assert_eq!(capture.counter("eav.entity.version_conflicts"), 2);
        assert_eq!(capture.counter("eav.entity.unique_conflicts"), 1);
        assert_eq!(capture.counter("eav.rules.dead_lettered"), 3);
        assert_eq!(capture.counter("eav.replica.builds"), 1);
        assert_eq!(capture.counter("eav.replica.build_failures"), 1);
        assert_eq!(capture.counter("eav.outbox.failed"), 1);
        assert_eq!(capture.counter("eav.outbox.flushed"), 6);
        assert_eq!(capture.histogram_count("eav.replica.build_duration"), 1);
    }

    #[test]
    fn gauges_reflect_pending_age_feed_lag_and_pending_count() {
        let (metrics, capture) = MetricCapture::new();

        metrics.record_outbox_pending(9);
        metrics.record_outbox_pending_age(Duration::from_millis(2500));
        metrics.record_feed_lag(17);

        assert_eq!(capture.gauge("eav.outbox.pending"), 9);
        assert_eq!(capture.f64_gauge("eav.outbox.pending_age"), 2.5);
        assert_eq!(capture.gauge("eav.feed.lag"), 17);
    }

    #[test]
    fn global_returns_a_usable_clone() {
        let first = EavMetrics::global();
        let second = first.clone();

        second.record_rule_executed();
    }

    #[test]
    fn the_observer_methods_run_for_each_outcome() {
        let metrics = EavMetrics::new();
        for outcome in [
            ExecutionOutcome::Executed,
            ExecutionOutcome::ConditionFalse,
            ExecutionOutcome::AlreadyExecuted,
            ExecutionOutcome::CausationLimit,
        ] {
            metrics.on_execution(outcome);
        }
        metrics.on_action_failure();
        metrics.on_dead_letter(2);
        metrics.on_feed_lag(3);
    }
}
