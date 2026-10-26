//! Audit logging for mutations.
//!
//! [`AuditEvent`] describes one mutation. An [`AuditSink`] receives events.
//! [`TracingAuditSink`] is the default sink: it writes each event with
//! `tracing::info!`.

use tracing::info;

/// One auditable mutation.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Who performed the mutation.
    pub subject: String,
    /// What operation was performed.
    pub action: &'static str,
    /// What the operation touched.
    pub target: String,
    /// Unix timestamp of the event, in seconds.
    pub timestamp: i64,
}

/// Sink for [`AuditEvent`]s.
pub trait AuditSink: Send + Sync {
    /// Records one audit event.
    fn record(&self, event: AuditEvent);
}

/// [`AuditSink`] that writes each event through `tracing::info!`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: AuditEvent) {
        info!(
            subject = %event.subject,
            action = %event.action,
            target = %event.target,
            timestamp = event.timestamp,
            "audit event"
        );
    }
}
