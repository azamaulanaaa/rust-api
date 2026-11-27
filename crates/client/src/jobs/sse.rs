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
    #[cfg(any(target_arch = "wasm32", test))]
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
/// [`WatchOptions::poll_interval`] between two polls. Each poll updates the
/// pending job. A terminal poll stops the fallback.
///
/// A `401`, `403`, or `404` that the source reports before the stream starts
/// maps to [`JobError::LoginRequired`], [`JobError::Forbidden`], or
/// [`JobError::NotFound`]. A `400` or `429` from the stream route is a stream
/// failure and falls back to polling. The fallback poll then reports
/// `request` for a `400`. An error from a fallback poll maps through
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
        // A poll does not store a job when the slot is empty. The watcher
        // stores the answer, so `pending_job()` reflects the fallback.
        let job = jobs.apply_pending(job);
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

/// Validate one job id and return its event stream path.
///
/// The browser `EventSource` call normalizes a relative URL. The check runs
/// before the path is built, so an unsafe id cannot reach another route.
#[cfg(any(target_arch = "wasm32", test))]
fn event_path(id: &str) -> Result<String, StreamFailure> {
    if !is_safe_job_id(id) {
        return Err(StreamFailure::new("the job id is not a safe request path"));
    }
    Ok(format!("/jobs/{id}/events"))
}

/// Parse one event name and data pair from a stream.
///
/// An unknown event name returns `None`, so a newer server event does not
/// break an older client. An invalid status body, an unknown error code, or a
/// malformed error body is a stream failure.
#[cfg(any(target_arch = "wasm32", test))]
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
#[cfg(any(target_arch = "wasm32", test))]
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
    use gloo_net::eventsource::futures::{
        EventSource, EventSourceBuilder, EventSourceSubscription,
    };

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
        /// The path is `/jobs/{id}/events` on the page origin. An unsafe id,
        /// an invalid URL, or a failed listener setup returns a stream
        /// failure. The browser does not show the HTTP status of a refused
        /// connection.
        ///
        /// # Errors
        ///
        /// Returns a [`StreamFailure`] when the id is not a safe request path,
        /// or when the browser cannot create the connection or a listener.
        pub fn open(id: &str) -> Result<Self, StreamFailure> {
            let path = super::event_path(id)?;
            let mut connection = EventSourceBuilder::new()
                .with_credentials(true)
                .build(&path)
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
                    return Some(Err(StreamFailure::new("the stream event data is not text")));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Credentials, Method, Request, Response};
    use crate::eav::ReplicaQuery;
    use crate::eav::test_support::{ScriptedTransport, build_objects, entity_rows, script_replica};
    use rust_api_model::domain::JobState;
    use serde_json::{Value, json};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::pin;
    use std::rc::Rc;
    use std::task::{Context, Poll, Waker};

    /// One job id that is a valid request path segment.
    const JOB_ID: &str = "0190a5c2-7f3a-7c2b-8e4d-0123456789ab";

    /// Another job id that is a valid request path segment.
    const OTHER_JOB_ID: &str = "0190a5c2-7f3a-7c2b-8e4d-0123456789ac";

    /// One scripted transport answer.
    #[derive(Clone, Debug)]
    struct Reply {
        /// The HTTP status code.
        status: u16,
        /// The response body.
        body: Vec<u8>,
    }

    impl Reply {
        /// Build an answer with one JSON body.
        fn json(status: u16, body: Vec<u8>) -> Self {
            Self { status, body }
        }

        /// Build an answer with one status and no body.
        fn status(status: u16) -> Self {
            Self {
                status,
                body: Vec::new(),
            }
        }
    }

    /// The recorded requests of the fake transport.
    type Requests = Rc<RefCell<Vec<Request>>>;

    /// A transport that records every request and returns scripted answers.
    struct FakeTransport {
        /// The recorded requests.
        requests: Requests,
        /// The scripted answers.
        replies: Rc<RefCell<VecDeque<Reply>>>,
    }

    impl FakeTransport {
        /// Build a transport with no scripted answers.
        fn new() -> (Requests, Rc<RefCell<VecDeque<Reply>>>, Self) {
            let requests = Rc::new(RefCell::new(Vec::new()));
            let replies = Rc::new(RefCell::new(VecDeque::new()));
            (
                Rc::clone(&requests),
                Rc::clone(&replies),
                Self { requests, replies },
            )
        }
    }

    impl Transport for FakeTransport {
        async fn send(&self, request: Request) -> Result<Response, TransportError> {
            self.requests.borrow_mut().push(request);
            let reply = self
                .replies
                .borrow_mut()
                .pop_front()
                .expect("a scripted reply");
            Ok(Response {
                status: reply.status,
                body: reply.body,
            })
        }
    }

    /// A scripted event source that counts its reads.
    struct ScriptedSource {
        /// The events that the source yields.
        events: RefCell<VecDeque<Result<JobEvent, StreamFailure>>>,
        /// The number of reads.
        reads: Rc<Cell<usize>>,
    }

    impl ScriptedSource {
        /// Build a source from one event list.
        fn new(events: Vec<Result<JobEvent, StreamFailure>>) -> (Self, Rc<Cell<usize>>) {
            let reads = Rc::new(Cell::new(0));
            (
                Self {
                    events: RefCell::new(events.into()),
                    reads: Rc::clone(&reads),
                },
                reads,
            )
        }
    }

    impl JobEventSource for ScriptedSource {
        async fn next_event(&mut self) -> Option<Result<JobEvent, StreamFailure>> {
            self.reads.set(self.reads.get() + 1);
            self.events.borrow_mut().pop_front()
        }
    }

    /// A fallback delay that records each wait and returns at once.
    #[derive(Clone, Default)]
    struct RecordingDelay {
        /// The recorded waits.
        waits: Rc<RefCell<Vec<Duration>>>,
    }

    impl RecordingDelay {
        /// Build a delay with no recorded waits.
        fn new() -> Self {
            Self::default()
        }
    }

    impl PollDelay for RecordingDelay {
        async fn wait(&self, duration: Duration) {
            self.waits.borrow_mut().push(duration);
        }
    }

    /// Poll one future to completion. The fakes are always ready.
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// Build one job status body for one id.
    fn job_body_for(
        id: &str,
        state: &str,
        attempt: u32,
        error: Option<&str>,
        commit_seq: Option<u64>,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": id,
            "kind": "entity.create",
            "state": state,
            "attempt": attempt,
            "max_attempts": 5,
            "created_at": 1_700_000_000,
            "scheduled_at": 1_700_000_000,
            "error": error,
            "commit_seq": commit_seq,
        }))
        .expect("the job body serializes")
    }

    /// Build one job status body for the watched job.
    fn job_body(
        state: &str,
        attempt: u32,
        error: Option<&str>,
        commit_seq: Option<u64>,
    ) -> Vec<u8> {
        job_body_for(JOB_ID, state, attempt, error, commit_seq)
    }

    /// Build one job status view for one id.
    fn view_for(id: &str, state: &str, attempt: u32, commit_seq: Option<u64>) -> JobStatusView {
        serde_json::from_slice(&job_body_for(id, state, attempt, None, commit_seq))
            .expect("the view parses")
    }

    /// Build one job status view for the watched job.
    fn view(state: &str, attempt: u32, commit_seq: Option<u64>) -> JobStatusView {
        view_for(JOB_ID, state, attempt, commit_seq)
    }

    /// Script one `200` poll answer for one id.
    fn script_poll_for(
        replies: &Rc<RefCell<VecDeque<Reply>>>,
        id: &str,
        state: &str,
        attempt: u32,
        commit_seq: Option<u64>,
    ) {
        replies
            .borrow_mut()
            .push_back(Reply::json(200, job_body_for(id, state, attempt, None, commit_seq)));
    }

    /// Script one `200` poll answer for the watched job.
    fn script_poll(
        replies: &Rc<RefCell<VecDeque<Reply>>>,
        state: &str,
        attempt: u32,
        commit_seq: Option<u64>,
    ) {
        script_poll_for(replies, JOB_ID, state, attempt, commit_seq);
    }

    /// Build one event recorder.
    fn recorder() -> (Rc<RefCell<Vec<PendingJob>>>, impl FnMut(&PendingJob)) {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let record = {
            let seen = Rc::clone(&seen);
            move |job: &PendingJob| seen.borrow_mut().push(job.clone())
        };
        (seen, record)
    }

    /// Return the states of the recorded jobs.
    fn states(seen: &Rc<RefCell<Vec<PendingJob>>>) -> Vec<JobState> {
        seen.borrow().iter().map(|job| job.state).collect()
    }

    /// The watcher applies the initial status, a heartbeat, a status change,
    /// and the terminal event. It stops before a poll.
    #[test]
    fn the_watcher_applies_the_initial_status_and_stops_at_the_terminal_event() {
        let (source, reads) = ScriptedSource::new(vec![
            Ok(JobEvent::Status(view("queued", 0, None))),
            Ok(JobEvent::Heartbeat),
            Ok(JobEvent::Status(view("leased", 1, None))),
            Ok(JobEvent::Terminal(view("succeeded", 1, Some(5)))),
        ]);
        let (requests, _, transport) = FakeTransport::new();
        let jobs = JobClient::new(transport);
        let delay = RecordingDelay::new();
        let (seen, record) = recorder();

        let job = block_on(watch(
            &jobs,
            JOB_ID,
            source,
            delay.clone(),
            WatchOptions::default(),
            record,
        ))
        .expect("the watch resolves");

        assert_eq!(
            states(&seen),
            [JobState::Queued, JobState::Leased, JobState::Succeeded]
        );
        assert_eq!(job.state, JobState::Succeeded);
        assert_eq!(job.commit_seq, Some(5));
        assert!(job.is_terminal());
        assert_eq!(jobs.pending(), Some(job));
        assert!(
            requests.borrow().is_empty(),
            "no poll after a terminal event"
        );
        assert!(delay.waits.borrow().is_empty(), "no fallback wait");
        assert_eq!(reads.get(), 4);
    }

    /// A stream failure falls back to polling and resolves at terminal.
    #[test]
    fn a_stream_failure_falls_back_to_polling() {
        let (source, _) = ScriptedSource::new(vec![Err(StreamFailure::new("the stream closed"))]);
        let (requests, replies, transport) = FakeTransport::new();
        script_poll(&replies, "queued", 0, None);
        script_poll(&replies, "succeeded", 1, Some(5));
        let jobs = JobClient::new(transport);
        let delay = RecordingDelay::new();
        let (seen, record) = recorder();

        let job = block_on(watch(
            &jobs,
            JOB_ID,
            source,
            delay.clone(),
            WatchOptions::default(),
            record,
        ))
        .expect("the fallback resolves");

        assert_eq!(states(&seen), [JobState::Queued, JobState::Succeeded]);
        assert_eq!(job.state, JobState::Succeeded);
        assert_eq!(job.commit_seq, Some(5));
        assert_eq!(jobs.pending(), Some(job));

        let requests = requests.borrow();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| {
            request.method == Method::Get
                && request.path == format!("/jobs/{JOB_ID}")
                && request.credentials == Credentials::Include
        }));
        assert_eq!(delay.waits.borrow().len(), 1);
        assert_eq!(delay.waits.borrow()[0], Duration::from_secs(1));
    }

    /// Both `error` codes fall back to polling.
    #[test]
    fn an_error_event_falls_back_to_polling() {
        for code in [
            StreamErrorCode::AccessRevoked,
            StreamErrorCode::StreamUnavailable,
        ] {
            let (source, _) = ScriptedSource::new(vec![
                Ok(JobEvent::Status(view("queued", 0, None))),
                Ok(JobEvent::Error(code)),
            ]);
            let (requests, replies, transport) = FakeTransport::new();
            script_poll(&replies, "succeeded", 1, Some(5));
            let jobs = JobClient::new(transport);
            let (seen, record) = recorder();

            let job = block_on(watch(
                &jobs,
                JOB_ID,
                source,
                RecordingDelay::new(),
                WatchOptions::default(),
                record,
            ))
            .expect("the fallback resolves");

            assert_eq!(job.state, JobState::Succeeded);
            assert_eq!(states(&seen), [JobState::Queued, JobState::Succeeded]);
            assert_eq!(requests.borrow().len(), 1, "{code:?}");
        }
    }

    /// A stream that closes without a terminal event falls back to polling.
    #[test]
    fn a_closed_stream_falls_back_to_polling() {
        let (source, _) = ScriptedSource::new(Vec::new());
        let (requests, replies, transport) = FakeTransport::new();
        script_poll(&replies, "succeeded", 1, Some(5));
        let jobs = JobClient::new(transport);
        let (seen, record) = recorder();

        let job = block_on(watch(
            &jobs,
            JOB_ID,
            source,
            RecordingDelay::new(),
            WatchOptions::default(),
            record,
        ))
        .expect("the fallback resolves");

        assert_eq!(job.state, JobState::Succeeded);
        assert_eq!(states(&seen), [JobState::Succeeded]);
        assert_eq!(requests.borrow().len(), 1);
    }

    /// A stream view and a fallback poll for another job are rejected and do
    /// not replace the pending job or reach the callback.
    #[test]
    fn a_mismatched_stream_and_poll_do_not_replace_the_pending_job() {
        let other = view_for(OTHER_JOB_ID, "queued", 0, None);
        let (source, _) = ScriptedSource::new(vec![Ok(JobEvent::Status(other))]);
        let (requests, replies, transport) = FakeTransport::new();
        script_poll_for(&replies, OTHER_JOB_ID, "succeeded", 1, Some(5));
        let jobs = JobClient::new(transport);
        let stored = PendingJob {
            id: OTHER_JOB_ID.to_owned(),
            state: JobState::Queued,
            attempt: 0,
            error: None,
            commit_seq: None,
        };
        jobs.apply_pending(stored.clone());
        let (seen, record) = recorder();

        let error = block_on(watch(
            &jobs,
            JOB_ID,
            source,
            RecordingDelay::new(),
            WatchOptions::default(),
            record,
        ))
        .expect_err("both events name another job");

        assert!(matches!(error, JobError::MismatchedJob));
        assert_eq!(error.status_name(), "request");
        assert_eq!(jobs.pending(), Some(stored));
        assert!(
            seen.borrow().is_empty(),
            "the mismatched view must not reach the callback"
        );
        assert_eq!(requests.borrow().len(), 1, "the fallback polls once");
    }

    /// A fallback poll for another job is rejected and does not fill the
    /// pending slot.
    #[test]
    fn a_mismatched_fallback_poll_is_not_applied() {
        let (source, _) = ScriptedSource::new(vec![Err(StreamFailure::new("the stream ended"))]);
        let (requests, replies, transport) = FakeTransport::new();
        script_poll_for(&replies, OTHER_JOB_ID, "succeeded", 1, Some(5));
        let jobs = JobClient::new(transport);
        let (seen, record) = recorder();

        let error = block_on(watch(
            &jobs,
            JOB_ID,
            source,
            RecordingDelay::new(),
            WatchOptions::default(),
            record,
        ))
        .expect_err("the poll names another job");

        assert!(matches!(error, JobError::MismatchedJob));
        assert_eq!(error.status_name(), "request");
        assert_eq!(jobs.pending(), None);
        assert!(seen.borrow().is_empty());
        assert_eq!(requests.borrow().len(), 1);
    }

    /// A terminal first event stops without polling.
    #[test]
    fn a_terminal_first_event_stops_without_polling() {
        let (source, reads) =
            ScriptedSource::new(vec![Ok(JobEvent::Terminal(view("dead", 5, None)))]);
        let (requests, _, transport) = FakeTransport::new();
        let jobs = JobClient::new(transport);
        let delay = RecordingDelay::new();
        let (seen, record) = recorder();

        let job = block_on(watch(
            &jobs,
            JOB_ID,
            source,
            delay.clone(),
            WatchOptions::default(),
            record,
        ))
        .expect("the watch resolves");

        assert_eq!(job.state, JobState::Dead);
        assert_eq!(states(&seen), [JobState::Dead]);
        assert!(requests.borrow().is_empty());
        assert!(delay.waits.borrow().is_empty());
        assert_eq!(reads.get(), 1);
    }

    /// A pre-stream `401`, `403`, or `404` maps to the stable error.
    #[test]
    fn a_pre_stream_status_maps_to_the_stable_error() {
        for (status, name) in [
            (401, "login_required"),
            (403, "forbidden"),
            (404, "not_found"),
        ] {
            let (source, _) = ScriptedSource::new(vec![Err(StreamFailure::from_status(status))]);
            let (requests, _, transport) = FakeTransport::new();
            let jobs = JobClient::new(transport);

            let error = block_on(watch(
                &jobs,
                JOB_ID,
                source,
                RecordingDelay::new(),
                WatchOptions::default(),
                |_job| panic!("the watch must not apply a job"),
            ))
            .expect_err("the watch fails");

            assert_eq!(error.status_name(), name, "HTTP {status}");
            assert!(requests.borrow().is_empty(), "no poll after HTTP {status}");
        }
    }

    /// A `429` stream gate answer is a stream failure and falls back.
    #[test]
    fn a_pre_stream_429_falls_back_to_polling() {
        let (source, _) = ScriptedSource::new(vec![Err(StreamFailure::from_status(429))]);
        let (requests, replies, transport) = FakeTransport::new();
        script_poll(&replies, "succeeded", 1, Some(5));
        let jobs = JobClient::new(transport);
        let (seen, record) = recorder();

        let job = block_on(watch(
            &jobs,
            JOB_ID,
            source,
            RecordingDelay::new(),
            WatchOptions::default(),
            record,
        ))
        .expect("the fallback resolves");

        assert_eq!(job.state, JobState::Succeeded);
        assert_eq!(states(&seen), [JobState::Succeeded]);
        assert_eq!(requests.borrow().len(), 1);
    }

    /// A `401`, `403`, `404`, or `429` from a fallback poll maps to a stable
    /// error.
    #[test]
    fn a_fallback_poll_status_maps_to_the_stable_error() {
        for (status, name) in [
            (401, "login_required"),
            (403, "forbidden"),
            (404, "not_found"),
            (429, "request"),
        ] {
            let (source, _) =
                ScriptedSource::new(vec![Err(StreamFailure::new("the stream ended"))]);
            let (requests, replies, transport) = FakeTransport::new();
            replies.borrow_mut().push_back(Reply::status(status));
            let jobs = JobClient::new(transport);

            let error = block_on(watch(
                &jobs,
                JOB_ID,
                source,
                RecordingDelay::new(),
                WatchOptions::default(),
                |_job| panic!("the poll must not apply a job"),
            ))
            .expect_err("the watch fails");

            assert_eq!(error.status_name(), name, "HTTP {status}");
            assert_eq!(requests.borrow().len(), 1);
        }
    }

    /// The fallback stops at its poll bound and returns `request`.
    #[test]
    fn the_fallback_stops_at_its_poll_bound() {
        let (source, _) = ScriptedSource::new(vec![Err(StreamFailure::new("the stream ended"))]);
        let (requests, replies, transport) = FakeTransport::new();
        script_poll(&replies, "queued", 0, None);
        script_poll(&replies, "queued", 1, None);
        let jobs = JobClient::new(transport);
        let delay = RecordingDelay::new();
        let options = WatchOptions {
            poll_interval: Duration::from_millis(50),
            max_polls: 2,
        };

        let error = block_on(watch(
            &jobs,
            JOB_ID,
            source,
            delay.clone(),
            options,
            |_job| {},
        ))
        .expect_err("the watch is bounded");

        assert_eq!(error.status_name(), "request");
        assert_eq!(requests.borrow().len(), 2);
        assert_eq!(*delay.waits.borrow(), vec![Duration::from_millis(50)]);
    }

    /// An unsafe id is rejected before the source is read.
    #[test]
    fn an_unsafe_id_is_rejected_before_the_source_is_read() {
        let (source, reads) =
            ScriptedSource::new(vec![Ok(JobEvent::Terminal(view("succeeded", 1, Some(5))))]);
        let (requests, _, transport) = FakeTransport::new();
        let jobs = JobClient::new(transport);

        let error = block_on(watch(
            &jobs,
            "../auth/me",
            source,
            RecordingDelay::new(),
            WatchOptions::default(),
            |_job| panic!("the watch must not apply a job"),
        ))
        .expect_err("the id is not safe");

        assert!(matches!(error, JobError::NotFound));
        assert_eq!(reads.get(), 0);
        assert!(requests.borrow().is_empty());
    }

    /// The watcher does not change the loaded replica or query view.
    #[test]
    fn the_watcher_does_not_change_the_replica_view() {
        let objects = build_objects(entity_rows("e1", false));
        let (eav_replies, eav_transport) = ScriptedTransport::new();
        script_replica(&eav_replies, &objects, 1, 7);
        let query = ReplicaQuery::new(eav_transport);
        let state = block_on(query.load()).expect("the replica loads");
        let object_count = query.replica().object_count();

        let (source, _) =
            ScriptedSource::new(vec![Ok(JobEvent::Terminal(view("succeeded", 1, Some(5))))]);
        let (_, _, transport) = FakeTransport::new();
        let jobs = JobClient::new(transport);

        block_on(watch(
            &jobs,
            JOB_ID,
            source,
            RecordingDelay::new(),
            WatchOptions::default(),
            |_job| {},
        ))
        .expect("the watch resolves");

        assert_eq!(query.replica().state(), Some(state));
        assert_eq!(query.replica().object_count(), object_count);
        let page =
            block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
                .expect("the query still succeeds");
        assert_eq!(page.items, ["e1"]);
    }

    /// The browser event path accepts a safe id and rejects an unsafe id.
    #[test]
    fn the_browser_event_path_rejects_an_unsafe_id() {
        assert_eq!(
            event_path(JOB_ID).expect("the id is safe"),
            format!("/jobs/{JOB_ID}/events")
        );
        let long_id = "a".repeat(65);
        for id in ["../auth/me", "a/b", "a?b", "a#b", "", long_id.as_str()] {
            let error = event_path(id).expect_err("the id is not safe");
            assert_eq!(error.detail(), "the job id is not a safe request path");
            assert_eq!(error.status(), None);
        }
    }

    /// The event parser reads the server event names and bodies.
    #[test]
    fn the_event_parser_reads_the_server_frames() {
        let body = String::from_utf8(job_body("queued", 0, None, None)).expect("the body is text");

        assert_eq!(
            parse_event("status", &body).expect("the status parses"),
            Some(JobEvent::Status(view("queued", 0, None)))
        );
        assert_eq!(
            parse_event("terminal", &body).expect("the terminal parses"),
            Some(JobEvent::Terminal(view("queued", 0, None)))
        );
        assert_eq!(
            parse_event("error", "{\"code\":\"access_revoked\"}").expect("the error parses"),
            Some(JobEvent::Error(StreamErrorCode::AccessRevoked))
        );
        assert_eq!(
            parse_event("error", "{\"code\":\"stream_unavailable\"}").expect("the error parses"),
            Some(JobEvent::Error(StreamErrorCode::StreamUnavailable))
        );
        assert_eq!(
            parse_event("message", "{}").expect("an unknown name is ignored"),
            None
        );

        assert!(parse_event("status", "{").is_err());
        assert!(parse_event("error", "{}").is_err());
        assert!(parse_event("error", "{\"code\":\"other\"}").is_err());
        assert!(parse_event("error", "{").is_err());
    }

    /// The stream error names are stable.
    #[test]
    fn the_stream_error_names_are_stable() {
        assert_eq!(StreamErrorCode::AccessRevoked.as_str(), "access_revoked");
        assert_eq!(
            StreamErrorCode::StreamUnavailable.as_str(),
            "stream_unavailable"
        );
    }

    /// The default watch options use a bounded interval and poll count.
    #[test]
    fn the_default_watch_options_are_bounded() {
        let options = WatchOptions::default();
        assert_eq!(options.poll_interval, Duration::from_secs(1));
        assert_eq!(options.max_polls, 60);
    }
}
