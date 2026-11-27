//! The client job client: submit a command and follow its status.
//!
//! A write is a job. The client sends `POST /jobs` with a
//! [`CommandEnvelope`](rust_api_model::wire::CommandEnvelope) and then follows
//! `GET /jobs/{id}` or `GET /jobs/{id}/events`. The client never changes the
//! replica view on submit. It shows the committed replica data plus the
//! [`PendingJob`](crate::jobs::PendingJob) until the server
//! reports `succeeded` and the replica applied the commit sequence.
//!
//! The `poll` module names the guaranteed fallback transport. The `sse`
//! module holds the event-source seam and the watcher. The watcher uses the
//! stream and falls back to polling when the stream fails.

pub mod poll;
pub mod sse;

use core::fmt;
use std::cell::RefCell;

use rust_api_model::domain::{CommandKind, JobState};
use rust_api_model::wire::{CommandEnvelope, JobStatusView, MAX_IDEMPOTENCY_KEY_LEN};
use serde_json::Value;

use crate::auth::{Credentials, Request, Transport, TransportError};

/// The route that accepts one command.
const JOBS_PATH: &str = "/jobs";

/// The route prefix for one job status.
const JOB_PATH_PREFIX: &str = "/jobs/";

/// The maximum length of a job id in the request path.
const MAX_JOB_ID_LEN: usize = 64;

/// A failure to submit or poll one job.
///
/// The enum is non-exhaustive. A caller must treat a new variant as an error.
#[derive(Debug)]
#[non_exhaustive]
pub enum JobError {
    /// The server has no valid session for this browser.
    LoginRequired,
    /// The server denied access to the job.
    Forbidden,
    /// The job is absent, or the server does not show it to this subject.
    NotFound,
    /// The idempotency key already names a different command.
    Conflict,
    /// The kind, the payload, or the idempotency key is not valid.
    InvalidCommand,
    /// The transport failed before the client read an answer.
    Transport(TransportError),
    /// The status body is not a valid [`JobStatusView`].
    InvalidBody(serde_json::Error),
    /// The server answered with a status that the route does not define.
    UnexpectedStatus(u16),
}

impl JobError {
    /// Return the stable JavaScript error name.
    ///
    /// A name, once added, stays part of the stable surface. The transport,
    /// body, and unexpected-status errors all use `request`.
    pub const fn status_name(&self) -> &'static str {
        match self {
            Self::LoginRequired => "login_required",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::InvalidCommand => "invalid_command",
            Self::Transport(_) | Self::InvalidBody(_) | Self::UnexpectedStatus(_) => "request",
        }
    }

    /// Return `true` when the failure means the session ended.
    ///
    /// A caller sets the session state to login-required for this error.
    pub const fn requires_login(&self) -> bool {
        matches!(self, Self::LoginRequired)
    }
}

impl fmt::Display for JobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoginRequired => formatter.write_str("a login is required"),
            Self::Forbidden => formatter.write_str("the server denied access to the job"),
            Self::NotFound => formatter.write_str("the job is absent or not visible"),
            Self::Conflict => formatter.write_str("the idempotency key names a different command"),
            Self::InvalidCommand => formatter.write_str("the command is not valid"),
            Self::Transport(error) => write!(formatter, "the job request failed: {error}"),
            Self::InvalidBody(error) => {
                write!(formatter, "the job status body is not valid: {error}")
            }
            Self::UnexpectedStatus(status) => {
                write!(formatter, "the server answered HTTP {status}")
            }
        }
    }
}

impl std::error::Error for JobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::InvalidBody(error) => Some(error),
            _ => None,
        }
    }
}

/// One submitted job as the client tracks it.
///
/// The client shows this value next to the committed replica data. It never
/// applies the command to the replica view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingJob {
    /// The job identifier.
    pub id: String,
    /// The current lifecycle state.
    pub state: JobState,
    /// The number of attempts that the queue started.
    pub attempt: u32,
    /// The failure text for a failed or dead job.
    pub error: Option<String>,
    /// The change feed sequence that the write advanced to.
    pub commit_seq: Option<u64>,
}

impl PendingJob {
    /// Build one pending job from a server status view.
    fn from_view(view: JobStatusView) -> Self {
        Self {
            id: view.id.to_string(),
            state: view.state,
            attempt: view.attempt,
            error: view.error,
            commit_seq: view.commit_seq,
        }
    }

    /// Return `true` when the job has no further work.
    ///
    /// The terminal states are `succeeded`, `failed`, and `dead`. A caller
    /// stops its poll in a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Return `true` when this job committed and the replica applied it.
    ///
    /// The rule is true when the state is `succeeded`, [`Self::commit_seq`]
    /// holds a sequence, and `replica_head` is at least that sequence.
    ///
    /// A job without a commit sequence is not committed by this rule. That
    /// case means the write reported no change feed position, so the client
    /// cannot prove that the replica includes it. The caller must fall back
    /// to a replica reload and compare the replica head or generation. This
    /// helper stays `false` in that case.
    pub fn is_committed(&self, replica_head: u64) -> bool {
        if self.state != JobState::Succeeded {
            return false;
        }
        match self.commit_seq {
            Some(commit_seq) => replica_head >= commit_seq,
            None => false,
        }
    }
}

/// Submits one command and polls its status over one transport.
///
/// The client stores at most one pending job. The job client has no replica
/// or query state, so a submit or a poll cannot change the replica view.
#[derive(Debug)]
pub struct JobClient<T: Transport> {
    transport: T,
    pending: RefCell<Option<PendingJob>>,
}

impl<T: Transport> JobClient<T> {
    /// Build a job client over one transport.
    ///
    /// This constructor does no network work.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            pending: RefCell::new(None),
        }
    }

    /// Return the stored pending job.
    ///
    /// The value is `None` until a submit succeeds or after
    /// [`clear_pending`](Self::clear_pending).
    pub fn pending(&self) -> Option<PendingJob> {
        self.pending.borrow().clone()
    }

    /// Remove the stored pending job.
    pub fn clear_pending(&self) {
        self.pending.replace(None);
    }

    /// Submit one command and store the accepted job.
    ///
    /// The call parses the kind and checks the idempotency key before the
    /// request. The key must hold 1 to [`MAX_IDEMPOTENCY_KEY_LEN`] bytes. The
    /// body is a [`CommandEnvelope`] with no `expected_version`. The request
    /// is `POST /jobs` with cookie credentials and
    /// `Content-Type: application/json`.
    ///
    /// A `202` answer stores and returns the pending job. A `401` answer
    /// returns [`JobError::LoginRequired`]. A `409` answer returns
    /// [`JobError::Conflict`]. A `400` answer returns
    /// [`JobError::InvalidCommand`]. Any other answer returns
    /// [`JobError::UnexpectedStatus`]. A transport failure returns
    /// [`JobError::Transport`]. A body that is not a [`JobStatusView`]
    /// returns [`JobError::InvalidBody`].
    pub async fn submit(
        &self,
        kind: &str,
        payload: Value,
        idempotency_key: &str,
    ) -> Result<PendingJob, JobError> {
        let kind = CommandKind::parse(kind).map_err(|_| JobError::InvalidCommand)?;
        if !valid_idempotency_key(idempotency_key) {
            return Err(JobError::InvalidCommand);
        }
        let envelope = CommandEnvelope {
            kind,
            payload,
            idempotency_key: idempotency_key.to_owned(),
            expected_version: None,
        };
        let body = serde_json::to_string(&envelope).map_err(|_| JobError::InvalidCommand)?;
        let request = Request::json_post(JOBS_PATH, Credentials::Include, body);
        let response = self
            .transport
            .send(request)
            .await
            .map_err(JobError::Transport)?;
        match response.status {
            202 => {
                let view: JobStatusView =
                    serde_json::from_slice(&response.body).map_err(JobError::InvalidBody)?;
                let job = PendingJob::from_view(view);
                self.pending.replace(Some(job.clone()));
                Ok(job)
            }
            status => Err(JobError::from_submit_status(status)),
        }
    }

    /// Apply one event view to the stored pending job.
    ///
    /// The view is stored when its id matches `expected_id`. A terminal stored
    /// job with the same id does not change. The method returns `None` when
    /// the view names another job. The watcher uses this method for the
    /// initial, status, and terminal events.
    pub(crate) fn apply_view(&self, expected_id: &str, view: JobStatusView) -> Option<PendingJob> {
        let job = PendingJob::from_view(view);
        if job.id != expected_id {
            return None;
        }
        let current = self.pending.borrow().clone();
        if let Some(current) = current
            && current.id == job.id
            && current.is_terminal()
        {
            return Some(current);
        }
        self.pending.replace(Some(job.clone()));
        Some(job)
    }

    /// Read the status of one job and update the stored pending job.
    ///
    /// The request is `GET /jobs/{id}` with cookie credentials. A `200`
    /// answer returns the job. The call updates the stored pending job when
    /// the id matches. A job in a terminal state does not change again. A
    /// `404` answer returns [`JobError::NotFound`]. A `401` answer returns
    /// [`JobError::LoginRequired`]. Any other answer returns
    /// [`JobError::UnexpectedStatus`]. A transport failure returns
    /// [`JobError::Transport`]. A body that is not a [`JobStatusView`]
    /// returns [`JobError::InvalidBody`].
    ///
    /// The call does not change the replica or query view.
    pub async fn poll(&self, id: &str) -> Result<PendingJob, JobError> {
        if !is_safe_job_id(id) {
            return Err(JobError::NotFound);
        }
        let request = Request::get(format!("{JOB_PATH_PREFIX}{id}"), Credentials::Include);
        let response = self
            .transport
            .send(request)
            .await
            .map_err(JobError::Transport)?;
        match response.status {
            200 => {
                let view: JobStatusView =
                    serde_json::from_slice(&response.body).map_err(JobError::InvalidBody)?;
                let job = PendingJob::from_view(view);
                let current = self.pending.borrow().clone();
                if let Some(current) = current
                    && current.id == job.id
                {
                    if current.is_terminal() {
                        return Ok(current);
                    }
                    self.pending.replace(Some(job.clone()));
                }
                Ok(job)
            }
            status => Err(JobError::from_poll_status(status)),
        }
    }
}

impl JobError {
    /// Map one unexpected submit status to a stable error.
    const fn from_submit_status(status: u16) -> Self {
        match status {
            400 => Self::InvalidCommand,
            401 => Self::LoginRequired,
            403 => Self::Forbidden,
            409 => Self::Conflict,
            _ => Self::UnexpectedStatus(status),
        }
    }

    /// Map one unexpected poll status to a stable error.
    const fn from_poll_status(status: u16) -> Self {
        match status {
            401 => Self::LoginRequired,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            _ => Self::UnexpectedStatus(status),
        }
    }
}

/// Return `true` when one idempotency key has a valid byte length.
fn valid_idempotency_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_IDEMPOTENCY_KEY_LEN
}

/// Return `true` when one job id is a safe request path segment.
///
/// The allowlist keeps URL syntax out of the request path. A client can call
/// [`JobClient::poll`] with any string, so the check runs before the request.
pub(crate) fn is_safe_job_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_JOB_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthClient, AuthState, JSON_CONTENT_TYPE, Method, Response};
    use crate::eav::ReplicaQuery;
    use crate::eav::test_support::{ScriptedTransport, build_objects, entity_rows, script_replica};
    use serde_json::json;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::pin;
    use std::rc::Rc;
    use std::task::{Context, Poll, Waker};

    /// One job id that is a valid request path segment.
    const JOB_ID: &str = "0190a5c2-7f3a-7c2b-8e4d-0123456789ab";

    /// One scripted transport answer.
    #[derive(Clone, Debug)]
    struct Reply {
        /// The HTTP status code.
        status: u16,
        /// The response body.
        body: Vec<u8>,
    }

    impl Reply {
        /// Build an answer with one status and one JSON body.
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

    /// The scripted answers of the fake transport.
    type Replies = Rc<RefCell<VecDeque<Reply>>>;

    /// A transport that records every request and returns scripted answers.
    struct FakeTransport {
        /// The recorded requests.
        requests: Requests,
        /// The scripted answers.
        replies: Replies,
    }

    impl FakeTransport {
        /// Build a transport with no scripted answers.
        fn new() -> (Requests, Replies, Self) {
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

    /// A transport that returns one fixed status.
    struct FixedTransport(u16);

    impl Transport for FixedTransport {
        async fn send(&self, _request: Request) -> Result<Response, TransportError> {
            Ok(Response {
                status: self.0,
                body: Vec::new(),
            })
        }
    }

    /// Poll one future to completion. The fake transport is always ready.
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

    /// Build one job status body.
    fn job_body(
        state: &str,
        attempt: u32,
        error: Option<&str>,
        commit_seq: Option<u64>,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": JOB_ID,
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

    /// Script one `202` queued answer.
    fn script_queued(replies: &Replies) {
        replies
            .borrow_mut()
            .push_back(Reply::json(202, job_body("queued", 0, None, None)));
    }

    /// Build one pending job with one state and commit sequence.
    fn pending(state: JobState, commit_seq: Option<u64>) -> PendingJob {
        PendingJob {
            id: JOB_ID.to_owned(),
            state,
            attempt: 1,
            error: None,
            commit_seq,
        }
    }

    /// Submit sends a credentialed JSON POST with a command envelope.
    #[test]
    fn submit_sends_a_json_command_envelope() {
        let (requests, replies, transport) = FakeTransport::new();
        script_queued(&replies);
        let client = JobClient::new(transport);

        let job = block_on(client.submit("entity.create", json!({"name": "alice"}), "key-1"))
            .expect("the submit succeeds");

        assert_eq!(job.state, JobState::Queued);
        assert_eq!(job.id, JOB_ID);
        assert_eq!(job.attempt, 0);
        assert_eq!(job.error, None);
        assert_eq!(job.commit_seq, None);
        assert_eq!(client.pending(), Some(job));

        let requests = requests.borrow();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, Method::Post);
        assert_eq!(request.path, "/jobs");
        assert_eq!(request.credentials, Credentials::Include);
        assert_eq!(request.content_type.as_deref(), Some(JSON_CONTENT_TYPE));

        let body = request.body.as_deref().expect("the request has a body");
        let envelope: CommandEnvelope = serde_json::from_str(body).expect("the envelope parses");
        assert_eq!(envelope.kind.as_str(), "entity.create");
        assert_eq!(envelope.payload, json!({"name": "alice"}));
        assert_eq!(envelope.idempotency_key, "key-1");
        assert_eq!(envelope.expected_version, None);

        let value: Value = serde_json::from_str(body).expect("the body is JSON");
        assert!(
            value.get("expected_version").is_none(),
            "the envelope must omit expected_version"
        );
    }

    /// Poll reads the job route before and after the job finishes.
    #[test]
    fn poll_reads_the_job_status_and_updates_the_pending_job() {
        let (requests, replies, transport) = FakeTransport::new();
        script_queued(&replies);
        replies
            .borrow_mut()
            .push_back(Reply::json(200, job_body("queued", 0, None, None)));
        replies
            .borrow_mut()
            .push_back(Reply::json(200, job_body("leased", 1, None, None)));
        replies
            .borrow_mut()
            .push_back(Reply::json(200, job_body("succeeded", 1, None, Some(5))));
        let client = JobClient::new(transport);

        block_on(client.submit("entity.create", json!({"name": "alice"}), "key-1"))
            .expect("the submit succeeds");

        let job = block_on(client.poll(JOB_ID)).expect("the poll succeeds");
        assert_eq!(job.state, JobState::Queued);
        assert!(!job.is_terminal());

        let job = block_on(client.poll(JOB_ID)).expect("the poll succeeds");
        assert_eq!(job.state, JobState::Leased);
        assert_eq!(job.attempt, 1);
        assert!(!job.is_terminal());

        let job = block_on(client.poll(JOB_ID)).expect("the poll succeeds");
        assert_eq!(job.state, JobState::Succeeded);
        assert_eq!(job.commit_seq, Some(5));
        assert!(job.is_terminal());
        assert_eq!(client.pending(), Some(job));

        let requests = requests.borrow();
        let paths: Vec<&str> = requests
            .iter()
            .map(|request| request.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "/jobs",
                "/jobs/0190a5c2-7f3a-7c2b-8e4d-0123456789ab",
                "/jobs/0190a5c2-7f3a-7c2b-8e4d-0123456789ab",
                "/jobs/0190a5c2-7f3a-7c2b-8e4d-0123456789ab",
            ]
        );
        assert!(requests.iter().skip(1).all(|request| {
            request.method == Method::Get
                && request.credentials == Credentials::Include
                && request.body.is_none()
        }));
    }

    /// A terminal job does not change after a later poll.
    #[test]
    fn a_terminal_job_does_not_change() {
        let (_, replies, transport) = FakeTransport::new();
        script_queued(&replies);
        replies
            .borrow_mut()
            .push_back(Reply::json(200, job_body("succeeded", 1, None, Some(5))));
        replies
            .borrow_mut()
            .push_back(Reply::json(200, job_body("leased", 2, None, None)));
        let client = JobClient::new(transport);

        block_on(client.submit("entity.create", json!({}), "key-1")).expect("the submit succeeds");
        let done = block_on(client.poll(JOB_ID)).expect("the poll succeeds");
        assert_eq!(done.state, JobState::Succeeded);

        let job = block_on(client.poll(JOB_ID)).expect("the poll succeeds");
        assert_eq!(job, done);
        assert_eq!(client.pending(), Some(done));
    }

    /// Submit maps a conflict, an invalid command, and other statuses.
    #[test]
    fn submit_maps_conflict_and_invalid_statuses() {
        for (status, expected_name) in [
            (409, "conflict"),
            (400, "invalid_command"),
            (403, "forbidden"),
            (404, "request"),
        ] {
            let (requests, replies, transport) = FakeTransport::new();
            replies.borrow_mut().push_back(Reply::status(status));
            let client = JobClient::new(transport);

            let error = block_on(client.submit("entity.create", json!({}), "key-1"))
                .expect_err("the submit fails");

            assert_eq!(error.status_name(), expected_name);
            let matched = match &error {
                JobError::Conflict => status == 409,
                JobError::InvalidCommand => status == 400,
                JobError::Forbidden => status == 403,
                JobError::UnexpectedStatus(code) => *code == status,
                _ => false,
            };
            assert!(matched, "unexpected error for status {status}: {error}");
            assert_eq!(requests.borrow().len(), 1);
            assert_eq!(client.pending(), None);
        }
    }

    /// A `401` and a `404` map to stable errors.
    #[test]
    fn submit_and_poll_map_auth_and_missing_errors() {
        let (_, replies, transport) = FakeTransport::new();
        replies.borrow_mut().push_back(Reply::status(401));
        let client = JobClient::new(transport);

        let error = block_on(client.submit("entity.create", json!({}), "key-1"))
            .expect_err("the submit fails");
        assert_eq!(error.status_name(), "login_required");
        assert!(error.requires_login());
        assert!(matches!(error, JobError::LoginRequired));

        let (_, replies, transport) = FakeTransport::new();
        replies.borrow_mut().push_back(Reply::status(404));
        let client = JobClient::new(transport);

        let error = block_on(client.poll(JOB_ID)).expect_err("the poll fails");
        assert_eq!(error.status_name(), "not_found");
        assert!(!error.requires_login());
        assert!(matches!(error, JobError::NotFound));
    }

    /// A `403` and an unexpected status map to stable errors.
    #[test]
    fn poll_maps_forbidden_and_unexpected_statuses() {
        for status in [403, 500, 202, 409] {
            let (_, replies, transport) = FakeTransport::new();
            replies.borrow_mut().push_back(Reply::status(status));
            let client = JobClient::new(transport);

            let error = block_on(client.poll(JOB_ID)).expect_err("the poll fails");

            let expected_name = if status == 403 {
                "forbidden"
            } else {
                "request"
            };
            assert_eq!(error.status_name(), expected_name);
            let matched = match &error {
                JobError::Forbidden => status == 403,
                JobError::UnexpectedStatus(code) => *code == status,
                _ => false,
            };
            assert!(matched, "unexpected error for status {status}: {error}");
        }
    }

    /// A bad kind or key is rejected before the request.
    #[test]
    fn an_invalid_command_is_rejected_before_the_request() {
        let (requests, _, transport) = FakeTransport::new();
        let client = JobClient::new(transport);

        for key in [String::new(), "k".repeat(MAX_IDEMPOTENCY_KEY_LEN + 1)] {
            let error = block_on(client.submit("entity.create", json!({}), &key))
                .expect_err("the key is not valid");
            assert!(matches!(error, JobError::InvalidCommand));
        }
        let error = block_on(client.submit("Bad Kind", json!({}), "key-1"))
            .expect_err("the kind is not valid");
        assert!(matches!(error, JobError::InvalidCommand));

        assert_eq!(requests.borrow().len(), 0);
    }

    /// A job id that can change the request path is rejected.
    #[test]
    fn an_unsafe_job_id_is_rejected_before_the_request() {
        let (requests, _, transport) = FakeTransport::new();
        let client = JobClient::new(transport);
        let long_id = "a".repeat(MAX_JOB_ID_LEN + 1);

        for id in ["../auth/me", "a/b", "a?b", "", long_id.as_str()] {
            let error = block_on(client.poll(id)).expect_err("the id is not safe");
            assert!(matches!(error, JobError::NotFound));
        }

        assert_eq!(requests.borrow().len(), 0);
    }

    /// The commit rule needs success, a sequence, and an applied head.
    #[test]
    fn a_job_is_committed_only_after_the_replica_applies_it() {
        assert!(!pending(JobState::Queued, Some(5)).is_committed(10));
        assert!(!pending(JobState::Leased, Some(5)).is_committed(10));
        assert!(!pending(JobState::Failed, Some(5)).is_committed(10));
        assert!(!pending(JobState::Dead, Some(5)).is_committed(10));
        assert!(!pending(JobState::Succeeded, Some(5)).is_committed(4));
        assert!(pending(JobState::Succeeded, Some(5)).is_committed(5));
        assert!(pending(JobState::Succeeded, Some(5)).is_committed(6));
        assert!(!pending(JobState::Succeeded, None).is_committed(u64::MAX));
    }

    /// The pending slot clears on request.
    #[test]
    fn a_clear_removes_the_pending_job() {
        let (_, replies, transport) = FakeTransport::new();
        script_queued(&replies);
        let client = JobClient::new(transport);

        block_on(client.submit("entity.create", json!({}), "key-1")).expect("the submit succeeds");
        assert!(client.pending().is_some());

        client.clear_pending();

        assert_eq!(client.pending(), None);
    }

    /// A `401` from a job call can set the session to login-required.
    #[test]
    fn a_job_401_sets_the_session_login_required() {
        let (_, replies, transport) = FakeTransport::new();
        replies.borrow_mut().push_back(Reply::status(401));
        let client = JobClient::new(transport);
        let auth = AuthClient::new(FixedTransport(200));
        assert_eq!(auth.state(), AuthState::Unknown);

        let error = block_on(client.submit("entity.create", json!({}), "key-1"))
            .expect_err("the submit fails");
        if error.requires_login() {
            auth.set_login_required();
        }

        assert_eq!(auth.state(), AuthState::LoginRequired);
    }

    /// A submit and a poll do not change the loaded replica or query view.
    #[test]
    fn job_calls_do_not_change_the_replica_view() {
        let objects = build_objects(entity_rows("e1", false));
        let (eav_replies, eav_transport) = ScriptedTransport::new();
        script_replica(&eav_replies, &objects, 1, 7);
        let query = ReplicaQuery::new(eav_transport);
        let state = block_on(query.load()).expect("the replica loads");
        let object_count = query.replica().object_count();

        let (_, replies, transport) = FakeTransport::new();
        script_queued(&replies);
        replies
            .borrow_mut()
            .push_back(Reply::json(200, job_body("succeeded", 1, None, Some(5))));
        let client = JobClient::new(transport);

        block_on(client.submit("entity.create", json!({"name": "alice"}), "key-1"))
            .expect("the submit succeeds");
        block_on(client.poll(JOB_ID)).expect("the poll succeeds");

        assert_eq!(query.replica().state(), Some(state));
        assert_eq!(query.replica().object_count(), object_count);
        let page =
            block_on(query.query_attribute("tag", &Value::String("alpha".into()), None, None))
                .expect("the query still succeeds");
        assert_eq!(page.items, ["e1"]);
    }

    /// The job error names are stable.
    #[test]
    fn the_job_error_names_are_stable() {
        assert_eq!(JobError::LoginRequired.status_name(), "login_required");
        assert_eq!(JobError::Forbidden.status_name(), "forbidden");
        assert_eq!(JobError::NotFound.status_name(), "not_found");
        assert_eq!(JobError::Conflict.status_name(), "conflict");
        assert_eq!(JobError::InvalidCommand.status_name(), "invalid_command");
        assert_eq!(
            JobError::Transport(TransportError::new("the browser failed")).status_name(),
            "request"
        );
        let body = serde_json::from_str::<Value>("{").expect_err("the body is not valid");
        assert_eq!(JobError::InvalidBody(body).status_name(), "request");
        assert_eq!(JobError::UnexpectedStatus(404).status_name(), "request");
    }

    /// A request error keeps its transport or body cause.
    #[test]
    fn a_request_error_keeps_its_cause() {
        let error = JobError::Transport(TransportError::new("the browser rejected the request"));
        assert_eq!(error.status_name(), "request");
        let source = std::error::Error::source(&error).expect("the transport error has a source");
        assert_eq!(source.to_string(), "the browser rejected the request");
        assert_eq!(
            error.to_string(),
            "the job request failed: the browser rejected the request"
        );

        let body = serde_json::from_str::<Value>("{").expect_err("the body is not valid");
        let error = JobError::InvalidBody(body);
        assert_eq!(error.status_name(), "request");
        assert!(std::error::Error::source(&error).is_some());
        assert!(
            error
                .to_string()
                .starts_with("the job status body is not valid:"),
            "{error}"
        );

        let error = JobError::UnexpectedStatus(409);
        assert_eq!(error.status_name(), "request");
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(error.to_string(), "the server answered HTTP 409");
    }
}
