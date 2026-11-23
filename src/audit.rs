//! Audit logging for mutations.
//!
//! [`AuditEvent`](crate::audit::AuditEvent) describes one mutation.
//! [`AuditSink`](crate::audit::AuditSink) receives events.
//! [`TracingAuditSink`](crate::audit::TracingAuditSink) is the default sink:
//! it writes each event with `tracing::info!`.
//! A subscriber must keep the `audit` target at `info` or lower.

use tracing::info;

/// Failure while recording an audit event.
#[derive(Debug, thiserror::Error)]
#[error("audit sink failed: {0}")]
pub struct AuditError(String);

/// One auditable mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditEvent {
    /// Who performed the mutation.
    pub subject: String,
    /// What operation was performed.
    pub action: String,
    /// What the operation touched.
    pub target: String,
    /// Unix timestamp of the event, in seconds.
    pub timestamp: i64,
}

impl AuditEvent {
    /// Creates an event and stamps the current time in seconds.
    #[must_use]
    pub fn new(
        subject: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            action: action.into(),
            target: target.into(),
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    /// Creates an event with a given timestamp in seconds.
    ///
    /// Use this constructor to replay an event that happened earlier.
    #[must_use]
    pub fn with_timestamp(
        subject: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        timestamp: i64,
    ) -> Self {
        Self {
            subject: subject.into(),
            action: action.into(),
            target: target.into(),
            timestamp,
        }
    }
}

/// Sink for [`AuditEvent`]s.
pub trait AuditSink: Send + Sync {
    /// Records one audit event.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the sink cannot record the event.
    fn record(&self, event: AuditEvent) -> Result<(), AuditError>;
}

/// [`AuditSink`] that writes each event through `tracing::info!`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
        info!(
            target: "audit",
            subject = %event.subject,
            action = %event.action,
            target = %event.target,
            timestamp = event.timestamp,
            "audit event"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Capture(std::sync::Mutex<Vec<AuditEvent>>);

    impl AuditSink for Capture {
        fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

    #[test]
    fn new_stamps_the_current_time_and_accepts_owned_action_names() {
        let event = AuditEvent::new("alice", String::from("rule.add"), "rule:1");
        let now = chrono::Utc::now().timestamp();
        assert!(event.timestamp <= now && event.timestamp >= now - 2);
        assert_eq!(event.subject, "alice");
        assert_eq!(event.action, "rule.add");
        assert_eq!(event.target, "rule:1");
    }

    #[test]
    fn with_timestamp_keeps_the_given_time() {
        let event = AuditEvent::with_timestamp("alice", "rule.add", "rule:1", 42);
        assert_eq!(event.timestamp, 42);
    }

    #[test]
    fn record_passes_the_event_to_the_sink() {
        let sink = Capture::default();
        let event = AuditEvent::with_timestamp("alice", "rule.add", "rule:1", 42);
        sink.record(event.clone()).unwrap();
        assert_eq!(sink.0.lock().unwrap().as_slice(), &[event]);
    }
}
