//! The client server-sent event transport and the job watcher.
//!
//! `GET /jobs/{id}/events` sends one `status` event at connect time, a
//! `status` event on each change, a `: heartbeat` comment every 15 seconds,
//! and one `terminal` event. An `error` event carries only a stable code. A
//! terminal event ends the stream.
//!
//! The watcher applies each status view to the pending job. It stops at a
//! terminal state. When the stream fails, closes without a terminal event, or
//! sends an `error` event, the watcher falls back to `GET /jobs/{id}` at a
//! bounded interval for a bounded number of polls. Polling is the guaranteed
//! transport. The watcher never changes the replica or the query view.
//!
//! The route has no `Last-Event-ID` support. A reconnect receives the current
//! status. The server route answers `400`, `401`, `404`, or `429` before the
//! stream starts. The browser `EventSource` API does not show that status, so
//! a failed connection falls back to polling and the poll maps the status. A
//! native event source can report the status directly.

use core::fmt;
use std::time::Duration;

use rust_api_model::wire::JobStatusView;

use super::{JobClient, JobError, PendingJob, is_safe_job_id};
use crate::auth::{Transport, TransportError};

/// One event from a job status stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobEvent {
    /// A nonterminal status view.
    Status(JobStatusView),
    /// A terminal status view. The stream ends after this event.
    Terminal(JobStatusView),
    /// A stream failure with a stable code. The client must poll.
    Error(StreamErrorCode),
    /// A keepalive comment.
    ///
    /// The browser `EventSource` API hides a comment, so a browser source
    /// never yields this variant. A native source can yield it.
    Heartbeat,
}

/// The stable code of one `error` event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamErrorCode {
    /// The subject lost the read grant on the job.
    AccessRevoked,
    /// The queue or the status view failed.
    StreamUnavailable,
}

impl StreamErrorCode {
    /// Return the stable wire name of this code.
    ///
    /// A name, once added, stays part of the stable surface.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessRevoked => "access_revoked",
            Self::StreamUnavailable => "stream_unavailable",
        }
    }

    /// Parse one wire code. An unknown code returns `None`.
    #[cfg(target_arch = "wasm32")]
    fn parse(code: &str) -> Option<Self> {
        match code {
            "access_revoked" => Some(Self::AccessRevoked),
            "stream_unavailable" => Some(Self::StreamUnavailable),
            _ => None,
        }
    }
}

/// A failure to open or read one job status stream.
///
/// The HTTP status is present only when the source learned it before the
/// stream started. The browser `EventSource` API does not expose the status,
/// so a browser failure has no status and falls back to polling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFailure {
    /// The HTTP status of a route answer, if the source learned it.
    status: Option<u16>,
    /// A detail message from the source.
    detail: String,
}

impl StreamFailure {
    /// Build a failure with one detail message and no HTTP status.
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            status: None,
            detail: detail.into(),
        }
    }

    /// Build a failure from one route answer.
    pub fn from_status(status: u16) -> Self {
        Self {
            status: Some(status),
            detail: format!("the stream route answered HTTP {status}"),
        }
    }

    /// Return the HTTP status, when the source learned it.
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    /// Return the detail message.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for StreamFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for StreamFailure {}

/// Yields one event at a time from a job status stream.
///
/// A browser source wraps `EventSource`. A native test uses a scripted
/// source. The call returns `None` when the stream closes without a terminal
/// event.
// The native async-in-trait form is enough here. The client runs on one
// browser thread, and no caller needs a `Send` bound on the future.
#[allow(async_fn_in_trait)]
pub trait JobEventSource {
    /// Read the next event from the stream.
    ///
    /// The call returns `None` when the stream ends. The watcher then falls
    /// back to polling.
    async fn next_event(&mut self) -> Option<Result<JobEvent, StreamFailure>>;
}

/// Waits between two fallback polls.
///
/// The watcher takes one delay value. A native test uses an immediate delay.
/// The browser uses a timer.
#[allow(async_fn_in_trait)]
pub trait PollDelay {
    /// Wait for one interval.
    async fn wait(&self, duration: Duration);
}

/// The limits of the poll fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchOptions {
    /// The wait between two fallback polls.
    pub poll_interval: Duration,
    /// The maximum number of fallback polls.
    ///
    /// A value of `0` disables the fallback. The watch then returns a
    /// `request` error when the stream fails.
    pub max_polls: u32,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            max_polls: 60,
        }
    }
}

/// Watch one job over an event source and fall back to polling.
///
/// The function reads one event at a time. A `status` or `terminal` view is
/// stored in the [`JobClient`] pending state and passed to `on_event`. A
/// terminal state stops the watch and returns the final pending job. A
/// heartbeat is ignored.
///
/// An `error` event, a stream failure, or a stream that closes without a
/// terminal event starts the poll fallback. The fallback calls
/// [`JobClient::poll`] up to [`WatchOptions::max_polls`] times and waits
/// [`WatchOptions::poll_interval`] between two polls. A terminal poll stops
/// the fallback.
///
/// A `401`, `403`, or `404` that the source reports before the stream starts
/// maps to [`JobError::LoginRequired`], [`JobError::Forbidden`], or
/// [`JobError::NotFound`]. A `429` from the stream gate is a stream failure
/// and falls back to polling. An error from a fallback poll maps through
/// [`JobClient::poll`].
///
/// A view for another job ends the stream read and starts the fallback. The
/// function never changes the replica or the query view. An unsafe id returns
/// [`JobError::NotFound`] before the source is read.
///
/// # Errors
///
/// Returns a [`JobError`] when a stream status maps to one, a poll fails, or
/// the fallback reaches [`WatchOptions::max_polls`] before a terminal state.
/// The last case is a `request` error.
pub async fn watch<T, S, D, F>(
    jobs: &JobClient<T>,
    id: &str,
    mut source: S,
    delay: D,
    options: WatchOptions,
    mut on_event: F,
) -> Result<PendingJob, JobError>
where
    T: Transport,
    S: JobEventSource,
    D: PollDelay,
    F: FnMut(&PendingJob),
{
    if !is_safe_job_id(id) {
        return Err(JobError::NotFound);
    }

    let mut failure_status = None;
    loop {
        match source.next_event().await {
            Some(Ok(JobEvent::Status(view) | JobEvent::Terminal(view))) => {
                let Some(job) = jobs.apply_view(id, view) else {
                    break;
                };
                on_event(&job);
                if job.is_terminal() {
                    return Ok(job);
                }
            }
            Some(Ok(JobEvent::Heartbeat)) => {}
            Some(Ok(JobEvent::Error(_code))) => {
                // Both codes mean the stream cannot continue. Polling is the
                // guaranteed transport, so the watcher does not stop here.
                break;
            }
            Some(Err(failure)) => {
                failure_status = failure.status();
                break;
            }
            None => break,
        }
    }
    // Drop the stream before the fallback. A browser source must not
    // reconnect while the watcher polls.
    drop(source);

    match failure_status {
        Some(401) => return Err(JobError::LoginRequired),
        Some(403) => return Err(JobError::Forbidden),
        Some(404) => return Err(JobError::NotFound),
        _ => {}
    }

    fallback(jobs, id, delay, options, on_event).await
}

/// Poll one job until a terminal state or the poll bound.
async fn fallback<T, D, F>(
    jobs: &JobClient<T>,
    id: &str,
    delay: D,
    options: WatchOptions,
    mut on_event: F,
) -> Result<PendingJob, JobError>
where
    T: Transport,
    D: PollDelay,
    F: FnMut(&PendingJob),
{
    for poll in 0..options.max_polls {
        let job = jobs.poll(id).await?;
        on_event(&job);
        if job.is_terminal() {
            return Ok(job);
        }
        let more_polls = poll + 1 < options.max_polls;
        if more_polls && !options.poll_interval.is_zero() {
            delay.wait(options.poll_interval).await;
        }
    }
    Err(JobError::Transport(TransportError::new(
        "the job watch ended before the job reached a terminal state",
    )))
}

/// Parse one event name and data pair from a stream.
///
/// An unknown event name returns `None`, so a newer server event does not
/// break an older client. An invalid status body, an unknown error code, or a
/// malformed error body is a stream failure.
#[cfg(target_arch = "wasm32")]
fn parse_event(name: &str, data: &str) -> Result<Option<JobEvent>, StreamFailure> {
    match name {
        "status" => parse_view(data).map(|view| Some(JobEvent::Status(view))),
        "terminal" => parse_view(data).map(|view| Some(JobEvent::Terminal(view))),
        "error" => {
            let value: serde_json::Value = serde_json::from_str(data).map_err(|error| {
                StreamFailure::new(format!("the stream error event is not valid JSON: {error}"))
            })?;
            let code = value
                .get("code")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| StreamFailure::new("the stream error event has no code"))?;
            let code = StreamErrorCode::parse(code).ok_or_else(|| {
                StreamFailure::new(format!("the stream sent the unknown error code {code}"))
            })?;
            Ok(Some(JobEvent::Error(code)))
        }
        _ => Ok(None),
    }
}

/// Parse one status view body.
#[cfg(target_arch = "wasm32")]
fn parse_view(data: &str) -> Result<JobStatusView, StreamFailure> {
    serde_json::from_str(data).map_err(|error| {
        StreamFailure::new(format!(
            "the stream status event is not a job status view: {error}"
        ))
    })
}

/// The browser event source and fallback delay.
#[cfg(target_arch = "wasm32")]
pub mod browser {
    use std::time::Duration;

    use futures_util::stream::{SelectAll, StreamExt as _};
    use gloo_net::eventsource::futures::{EventSource, EventSourceBuilder, EventSourceSubscription};

    use super::{JobEvent, JobEventSource, PollDelay, StreamFailure, parse_event};

    /// The event names of the job status route.
    const EVENT_NAMES: [&str; 3] = ["status", "terminal", "error"];

    /// Reads a job status stream through the browser `EventSource` API.
    ///
    /// The source sends the `auth_token` cookie with the same-origin
    /// connection. It never reads the cookie value. Dropping the source
    /// closes the connection.
    pub struct BrowserEventSource {
        /// The connection. The subscriptions hold a clone, and the last drop
        /// closes it.
        _connection: EventSource,
        /// The three named event streams.
        events: SelectAll<EventSourceSubscription>,
    }

    impl BrowserEventSource {
        /// Open the event stream for one job.
        ///
        /// The path is `/jobs/{id}/events` on the page origin. An invalid URL
        /// or a failed listener setup returns a stream failure. The browser
        /// does not show the HTTP status of a refused connection.
        ///
        /// # Errors
        ///
        /// Returns a [`StreamFailure`] when the browser cannot create the
        /// connection or a listener.
        pub fn open(id: &str) -> Result<Self, StreamFailure> {
            let mut connection = EventSourceBuilder::new()
                .with_credentials(true)
                .build(&format!("/jobs/{id}/events"))
                .map_err(|error| StreamFailure::new(error.to_string()))?;
            let mut events = SelectAll::new();
            for name in EVENT_NAMES {
                let subscription = connection
                    .subscribe(name)
                    .map_err(|error| StreamFailure::new(error.to_string()))?;
                events.push(subscription);
            }
            Ok(Self {
                _connection: connection,
                events,
            })
        }
    }

    impl JobEventSource for BrowserEventSource {
        async fn next_event(&mut self) -> Option<Result<JobEvent, StreamFailure>> {
            loop {
                let (name, message) = match self.events.next().await? {
                    Ok(event) => event,
                    Err(error) => return Some(Err(StreamFailure::new(error.to_string()))),
                };
                let Some(data) = message.data().as_string() else {
                    return Some(Err(StreamFailure::new(
                        "the stream event data is not text",
                    )));
                };
                match parse_event(&name, &data) {
                    Ok(Some(event)) => return Some(Ok(event)),
                    Ok(None) => {}
                    Err(failure) => return Some(Err(failure)),
                }
            }
        }
    }

    /// Waits between two fallback polls with a browser timer.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct BrowserDelay;

    impl PollDelay for BrowserDelay {
        async fn wait(&self, duration: Duration) {
            let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
            let millis = u32::try_from(millis).unwrap_or(u32::MAX);
            gloo_timers::future::TimeoutFuture::new(millis).await;
        }
    }
}
