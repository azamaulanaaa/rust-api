//! The JavaScript-facing client surface.
//!
//! This module builds only for `wasm32`. The surface is small on purpose.
//! This version sends the session probe, downloads the per-user file replica,
//! downloads the per-user EAV oxkv replica, answers one local entity query,
//! and submits, polls, and watches jobs. It has no persistent storage. The
//! client never applies a pending command to the replica view.
//!
//! The string shapes and the status names are stable. A name, once added,
//! stays part of the stable surface.

use rust_api_model::domain::JobState;
use serde::Serialize;
use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::auth::AuthClient;
use crate::auth::TransportError;
use crate::auth::browser::BrowserTransport;
use crate::eav::{QueryError, ReplicaQuery};
use crate::jobs::sse::browser::{BrowserDelay, BrowserEventSource};
use crate::jobs::sse::{WatchOptions, watch};
use crate::jobs::{JobClient, JobError, PendingJob};
use crate::replica::ReplicaClient;

/// The JavaScript-facing client for the rust-api server.
///
/// Create one instance in JavaScript with `new Client()`. The constructor
/// does no network or storage work. A method, once added, stays part of the
/// stable surface.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Client {
    auth: AuthClient<BrowserTransport>,
    replica: ReplicaClient<BrowserTransport>,
    query: ReplicaQuery<BrowserTransport>,
    jobs: JobClient<BrowserTransport>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl Client {
    /// Create a client.
    ///
    /// The constructor does not contact the server, read browser storage,
    /// or read a cookie. It only builds the client value.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            auth: AuthClient::new(BrowserTransport),
            replica: ReplicaClient::new(BrowserTransport),
            query: ReplicaQuery::new(BrowserTransport),
            jobs: JobClient::new(BrowserTransport),
        }
    }

    /// Check the session and return its stable name.
    ///
    /// The promise resolves to `"authenticated"`, `"login_required"`,
    /// `"error"`, or `"unknown"`. The browser sends the `auth_token` cookie
    /// with the request. The client does not read the cookie value.
    /// A method once added stays part of the stable surface.
    pub async fn check_session(&self) -> String {
        self.auth.check_session().await.as_str().to_owned()
    }

    /// Download the per-user file replica and return its state or an error name.
    ///
    /// The method downloads `GET /sync/db/manifest.json` and then every
    /// object that the manifest names, with the `auth_token` cookie. It
    /// verifies the byte length and the SHA-256 of each object. The new
    /// replica replaces the stored replica only after every check passes.
    ///
    /// A successful load returns a JSON string:
    ///
    /// ```text
    /// {"generation":7,"head":42,"applied_seq":42,"objects":3}
    /// ```
    ///
    /// A failed load returns one stable status string:
    ///
    /// - `"login_required"`: the server answered `401` and cleared the cache.
    /// - `"forbidden"`: the server answered `403` and cleared the cache.
    /// - `"stale_generation"`: the manifest is older than the stored replica.
    /// - `"superseded"`: a newer load or a clear replaced this load.
    /// - `"integrity"`: an object does not match its size or SHA-256.
    /// - `"request"`: a transport failure, a manifest parse error, an unsafe
    ///   object key, or an unexpected status.
    ///
    /// The cache stays unchanged on every error except `login_required` and
    /// `forbidden`. The JSON field names and the status strings are stable.
    /// A method once added stays part of the stable surface.
    pub async fn load_replica(&self) -> String {
        match self.replica.load().await {
            Ok(state) => format!(
                "{{\"generation\":{},\"head\":{},\"applied_seq\":{},\"objects\":{}}}",
                state.generation,
                state.head,
                state.applied_seq,
                self.replica.object_count()
            ),
            Err(error) => error.status_name().to_owned(),
        }
    }

    /// Download the per-user EAV oxkv replica and return its state or an error name.
    ///
    /// The method downloads `GET /eav/sync/oxkv/manifest.json` and then
    /// every object that the manifest names. It uses the same cookie
    /// credentials, size check, SHA-256 check, and generation rule as
    /// [`load_replica`](Self::load_replica).
    ///
    /// A successful load returns a JSON string:
    ///
    /// ```text
    /// {"generation":7,"head":42,"applied_seq":42,"objects":3}
    /// ```
    ///
    /// A failed load returns one stable status string:
    /// `"login_required"`, `"forbidden"`, `"stale_generation"`,
    /// `"superseded"`, `"integrity"`, or `"request"`.
    ///
    /// The file replica and the EAV replica have separate caches. A
    /// successful EAV load makes [`query_replica`](Self::query_replica)
    /// ready. A method once added stays part of the stable surface.
    pub async fn load_eav_replica(&self) -> String {
        match self.query.load().await {
            Ok(state) => format!(
                "{{\"generation\":{},\"head\":{},\"applied_seq\":{},\"objects\":{}}}",
                state.generation,
                state.head,
                state.applied_seq,
                self.query.replica().object_count()
            ),
            Err(error) => error.status_name().to_owned(),
        }
    }

    /// Run one local query for an exact EAV attribute value.
    ///
    /// `value_json` is a JSON string. A scalar keeps its JSON type. A tagged
    /// value keeps the server attribute type, for example
    /// `{"type":"timestamp","value":1700}`. A JSON `null`, array, untagged
    /// object, or tagged `json` value is not a valid query value.
    /// `limit` is the page size. The default is 50 and the maximum is 200.
    /// `after` is the last id of the previous page.
    ///
    /// A successful query returns a JSON string:
    ///
    /// ```text
    /// {"items":["e1"],"next":"e2"}
    /// ```
    ///
    /// The `next` field is `null` when no match remains. A failed query
    /// returns one stable error name:
    ///
    /// ```text
    /// {"error":"not_loaded"}
    /// ```
    ///
    /// The error names are `not_loaded`, `corrupt_replica`,
    /// `unsupported_value`, `invalid_query`, and `replica`.
    ///
    /// The query reads only the replica that the server built for this
    /// subject. It makes no authorization decision. A JSON attribute row is
    /// not part of the view. A method once added stays part of the stable
    /// surface.
    pub async fn query_replica(
        &self,
        attribute: &str,
        value_json: &str,
        limit: Option<u32>,
        after: Option<String>,
    ) -> String {
        let value: serde_json::Value = match serde_json::from_str(value_json) {
            Ok(value) => value,
            Err(_) => return error_json(QueryError::InvalidQuery),
        };
        match self
            .query
            .query_attribute(
                attribute,
                &value,
                limit.map(|value| value as usize),
                after.as_deref(),
            )
            .await
        {
            Ok(page) => json!({"items": page.items, "next": page.next}).to_string(),
            Err(error) => error_json(error),
        }
    }

    /// Submit one command and return the pending job or an error name.
    ///
    /// `kind` is the command kind. Only `entity.create` is submittable today;
    /// the server rejects any other kind with `400`. `payload_json` is the
    /// command payload as a JSON string. The client does not decode the
    /// `entity.create` payload; it forwards the parsed JSON value.
    /// `idempotency_key` makes the enqueue idempotent. It must hold 1 to 128
    /// bytes.
    ///
    /// The request is `POST /jobs` with the `auth_token` cookie and
    /// `Content-Type: application/json`. A `202` answer stores the pending
    /// job. The client does not change the replica or the query view.
    ///
    /// A successful submit returns a JSON string:
    ///
    /// ```text
    /// {"id":"...","state":"queued","attempt":0,"error":null,
    ///  "commit_seq":null,"terminal":false,"committed":false}
    /// ```
    ///
    /// The `committed` field is true only when the EAV replica is loaded and
    /// its applied sequence covers the job commit sequence. The method does
    /// not load a replica.
    ///
    /// A failed submit returns one stable error name:
    ///
    /// ```text
    /// {"error":"invalid_command"}
    /// ```
    ///
    /// The error names are `login_required`, `forbidden`, `not_found`,
    /// `conflict`, `invalid_command`, and `request`. A `401` answer also sets
    /// the session state to login-required. A method once added stays part of
    /// the stable surface.
    pub async fn submit_job(
        &self,
        kind: &str,
        payload_json: &str,
        idempotency_key: &str,
    ) -> String {
        let payload = match serde_json::from_str(payload_json) {
            Ok(payload) => payload,
            Err(_) => return job_error_json(JobError::InvalidCommand),
        };
        match self.jobs.submit(kind, payload, idempotency_key).await {
            Ok(job) => self.pending_json(&job),
            Err(error) => self.job_failure(error),
        }
    }

    /// Read the status of one job and return the pending job or an error name.
    ///
    /// The request is `GET /jobs/{id}` with the `auth_token` cookie. The call
    /// updates the stored pending job when the id matches. A terminal job
    /// does not change again. The method does not change the replica or the
    /// query view.
    ///
    /// A successful poll returns the same JSON shape as
    /// [`submit_job`](Self::submit_job). A failed poll returns one stable
    /// error name: `login_required`, `forbidden`, `not_found`, `conflict`,
    /// `invalid_command`, or `request`. A `401` answer also sets the session
    /// state to login-required. A method once added stays part of the stable
    /// surface.
    pub async fn poll_job(&self, id: &str) -> String {
        match self.jobs.poll(id).await {
            Ok(job) => self.pending_json(&job),
            Err(error) => self.job_failure(error),
        }
    }

    /// Watch one job over server-sent events and fall back to polling.
    ///
    /// The method opens `GET /jobs/{id}/events` with the `auth_token` cookie
    /// and same-origin credentials. `on_event` is a JavaScript function. The
    /// client calls it with one JSON string on each initial, status, and
    /// terminal event. The string is the same pending-job shape as
    /// [`submit_job`](Self::submit_job). The fallback poll calls the function
    /// on each poll. The function never changes the replica or the query
    /// view.
    ///
    /// The server sends `event: status` and `event: terminal` with a
    /// `JobStatusView` JSON body. It sends `event: error` with only
    /// `{"code":"access_revoked"}` or `{"code":"stream_unavailable"}`. A
    /// `: heartbeat` comment arrives every 15 seconds. A terminal event ends
    /// the stream. The client does not support `Last-Event-ID`; a reconnect
    /// receives the current status.
    ///
    /// The server route answers `400`, `401`, `404`, or `429` before the
    /// stream starts. The browser `EventSource` API does not show that
    /// status, so a refused connection falls back to polling and the poll
    /// maps the status.
    ///
    /// The promise resolves with the final pending-job JSON:
    ///
    /// ```text
    /// {"id":"...","state":"succeeded","attempt":1,"error":null,
    ///  "commit_seq":5,"terminal":true,"committed":false}
    /// ```
    ///
    /// A stream `error` event, a closed stream, or a connection failure falls
    /// back to `GET /jobs/{id}` at a bounded interval for a bounded number of
    /// polls. A terminal poll ends the watch. No poll runs after a terminal
    /// event.
    ///
    /// A failed watch returns one stable error name, the same shape and names
    /// as [`poll_job`](Self::poll_job):
    ///
    /// ```text
    /// {"error":"login_required"}
    /// ```
    ///
    /// The error names are `login_required`, `forbidden`, `not_found`,
    /// `conflict`, `invalid_command`, and `request`. A fallback that reaches
    /// its poll bound returns `request`. A `401` during the fallback also sets
    /// the session state to login-required. A callback that throws does not
    /// stop the watch. A method once added stays part of the stable surface.
    pub async fn watch_job(&self, id: &str, on_event: js_sys::Function) -> String {
        if !crate::jobs::is_safe_job_id(id) {
            return self.job_failure(JobError::NotFound);
        }
        let source = match BrowserEventSource::open(id) {
            Ok(source) => source,
            Err(error) => {
                return self.job_failure(JobError::Transport(TransportError::new(
                    error.to_string(),
                )));
            }
        };
        let result = watch(
            &self.jobs,
            id,
            source,
            BrowserDelay,
            WatchOptions::default(),
            |job| {
                let json = self.pending_json(job);
                let _ = on_event.call1(&JsValue::NULL, &JsValue::from_str(&json));
            },
        )
        .await;
        match result {
            Ok(job) => self.pending_json(&job),
            Err(error) => self.job_failure(error),
        }
    }

    /// Return the stored pending job, or `null` when there is none.
    ///
    /// The method does no network work. It returns the JSON shape of
    /// [`submit_job`](Self::submit_job). The `committed` field uses the EAV
    /// replica applied sequence when the EAV replica is loaded. Otherwise it
    /// is false. The method does not load a replica. A method once added stays
    /// part of the stable surface.
    pub fn pending_job(&self) -> String {
        match self.jobs.pending() {
            Some(job) => self.pending_json(&job),
            None => "null".to_owned(),
        }
    }

    /// Return the stable JSON body of one pending job.
    fn pending_json(&self, job: &PendingJob) -> String {
        let applied_seq = self.query.replica().state().map(|state| state.applied_seq);
        let committed = applied_seq.is_some_and(|head| job.is_committed(head));
        let body = PendingJobJson {
            id: &job.id,
            state: state_name(job.state),
            attempt: job.attempt,
            error: job.error.as_deref(),
            commit_seq: job.commit_seq,
            terminal: job.is_terminal(),
            committed,
        };
        serde_json::to_string(&body).unwrap_or_else(|_| "{\"error\":\"request\"}".to_owned())
    }

    /// Return the stable JSON body of one job error.
    ///
    /// A `401` answer also sets the session state to login-required.
    fn job_failure(&self, error: JobError) -> String {
        if error.requires_login() {
            self.auth.set_login_required();
        }
        job_error_json(error)
    }
}

/// The stable JSON body of one pending job.
///
/// The field order is part of the stable shape.
#[derive(Serialize)]
struct PendingJobJson<'a> {
    /// The job identifier.
    id: &'a str,
    /// The lifecycle state name.
    state: &'static str,
    /// The number of attempts that the queue started.
    attempt: u32,
    /// The failure text, or `null`.
    error: Option<&'a str>,
    /// The commit sequence, or `null`.
    commit_seq: Option<u64>,
    /// Whether the job is terminal.
    terminal: bool,
    /// Whether the replica applied the commit.
    committed: bool,
}

/// Return the stable JavaScript name of one job state.
fn state_name(state: JobState) -> &'static str {
    match state {
        JobState::Queued => "queued",
        JobState::Leased => "leased",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::Dead => "dead",
        _ => "unknown",
    }
}

/// Return the stable JSON body of one query error.
fn error_json(error: QueryError) -> String {
    json!({"error": error.status_name()}).to_string()
}

/// Return the stable JSON body of one job error.
fn job_error_json(error: JobError) -> String {
    json!({"error": error.status_name()}).to_string()
}
