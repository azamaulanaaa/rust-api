//! The server-sent event route for one job status.
//!
//! The route sends one initial `status` event. It then reads the queue at a
//! bounded interval and sends a `status` event only when the view changes. A
//! comment heartbeat keeps the connection alive. A terminal state sends one
//! `terminal` event and closes the stream.
//!
//! The route has a fixed time cap and a concurrency gate. It keeps no event
//! history. It ignores the `Last-Event-ID` header and sends the current status
//! on every reconnect.
//!
//! The poll interval comes from `[limits].job_event_stream_poll_ms`. A shorter
//! interval sends a change sooner and reads the full job row more often. A
//! lighter status API is a later change.

use std::{io, sync::Arc, time::Duration};

use actix_web::{HttpResponse, get, web};
use bytes::Bytes;
use futures_util::stream::{self, Stream};
use rust_api_model::wire::JobStatusView;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use uuid::Uuid;

use super::{
    JobStreamTiming, SubjectGates,
    poll::{may_read, not_found},
    status_view,
};
use crate::http::{
    error::ApiError,
    middleware::jwt::{Claims, Validated},
};
use crate::limits::{ConcurrencyGate, GatedStream, too_many};
use crate::policy::Authorizer;
use crate::queue::{JobQueue, QueueError};

/// The interval between two heartbeat comments.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// The event name for a nonterminal status view.
const STATUS_EVENT: &str = "status";

/// The event name for a terminal status view.
const TERMINAL_EVENT: &str = "terminal";

/// The event name for a stream failure.
const ERROR_EVENT: &str = "error";

/// The error code for a stream that lost its read grant.
const ACCESS_REVOKED_CODE: &str = "access_revoked";

/// The error code for a stream that cannot read its job.
const STREAM_UNAVAILABLE_CODE: &str = "stream_unavailable";

/// The comment line that keeps the connection alive.
const HEARTBEAT_FRAME: &[u8] = b": heartbeat\n\n";

/// Streams the status of one job as server-sent events.
///
/// The owner reads the job. A holder of the `superadmin` role reads every
/// job. A policy rule on the object `job:<uuid>` with the `read` action also
/// allows that job. Any other subject gets `404`, the same answer as for a
/// missing job.
///
/// # Per-job grants
///
/// The grant rule has no TTL and no automatic cleanup. Remove the rule through
/// the existing policy route `DELETE /policy/rules` when access must end.
///
/// Each `status` or `terminal` event carries the full [`JobStatusView`],
/// including `worker`, `attempt`, the timestamps, and the stored handler
/// error text in `error`. The server does not sanitize that error text.
///
/// An `error` event carries only a stable code. It never carries the stored
/// view or internal error text. The client must fall back to polling after an
/// `error` event.
///
/// An event goes only to the job owner, a holder of the `superadmin` role, or
/// a subject that holds a `job:<uuid>` / `read` grant.
///
/// The initial `status` event carries the current view. A `terminal` event
/// for `succeeded`, `failed`, or `dead` closes the stream.
///
/// A mid-stream failure sends one `error` event with a stable code.
/// `access_revoked` means the subject lost the read grant.
/// `stream_unavailable` means the queue or the status view failed.
///
/// The route keeps no event history. It ignores `Last-Event-ID` and sends the
/// current status on every reconnect.
///
/// The stream closes when the token expires or at the configured stream time
/// limit. A queue or view error sends `stream_unavailable` before the close.
/// The internal error stays in the log.
///
/// # Errors
///
/// Returns `400` when the id is not a UUID.
/// Returns `401` when the request has no valid token.
/// Returns `429` when no stream slot is free.
/// Returns `500` when the queue or the status view fails.
#[utoipa::path(
    get,
    path = "/jobs/{id}/events",
    tag = "jobs",
    params(("id" = String, Path, description = "job identifier")),
    responses(
        (status = 200, description = "the job status events", content_type = "text/event-stream"),
        (status = 400, description = "the id is not a UUID", body = crate::http::error::ErrorBody),
        (status = 401, description = "authentication required", body = crate::http::error::ErrorBody),
        (status = 404, description = "the job is absent or not visible", body = crate::http::error::ErrorBody),
        (status = 429, description = "no stream slot is free", body = crate::http::error::ErrorBody),
        (status = 500, description = "the queue or the status view failed", body = crate::http::error::ErrorBody)
    )
)]
#[get("/{id}/events")]
pub async fn job_events(
    id: web::Path<String>,
    claims: Validated<Claims>,
    queue: web::Data<Arc<dyn JobQueue>>,
    policy: web::Data<Authorizer>,
    gate: web::Data<ConcurrencyGate>,
    subject_gates: web::Data<SubjectGates>,
    timing: web::Data<JobStreamTiming>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::parse_str(&id.into_inner()).map_err(|_| ApiError::BadRequest)?;
    // Read the status first: an expired lease updates the stored attempt, so
    // the job read that follows carries the same attempt as the view.
    let status = match queue.status(id).await {
        Ok(status) => status,
        Err(QueueError::NotFound(_)) => return Ok(not_found()),
        Err(error) => return Err(ApiError::Internal(Box::new(error))),
    };
    let job = match queue.get(id).await {
        Ok(job) => job,
        Err(QueueError::NotFound(_)) => return Ok(not_found()),
        Err(error) => return Err(ApiError::Internal(Box::new(error))),
    };
    if !may_read(&job, &claims.sub, &policy).await {
        return Ok(not_found());
    }
    let view = status_view(&job, &status).map_err(|error| ApiError::Internal(Box::new(error)))?;

    let permit = gate.acquire();
    if permit.is_none() && !gate.is_disabled() {
        return Ok(too_many("job status stream"));
    }
    let Some(subject_permit) = subject_gates.acquire(&claims.sub) else {
        return Ok(too_many("job status streams for one subject"));
    };

    let duration = stream_duration(
        claims.exp,
        chrono::Utc::now().timestamp(),
        timing.max_duration,
    );
    let events = event_stream(
        queue.get_ref().clone(),
        id,
        claims.sub.clone(),
        policy.get_ref().clone(),
        view,
        duration,
        timing.poll_interval,
    );

    Ok(HttpResponse::Ok()
        .content_type("text/event-stream")
        .streaming(GatedStream::with_permits(
            events,
            permit.into_iter().chain(std::iter::once(subject_permit)),
        )))
}

/// Returns the time that a stream may stay open.
///
/// The value is the smaller of the time left on the token and `max_duration`.
/// A token that already expired gives a zero duration.
fn stream_duration(exp: u64, now: i64, max_duration: Duration) -> Duration {
    let now = u64::try_from(now).unwrap_or(0);
    Duration::from_secs(exp.saturating_sub(now)).min(max_duration)
}

/// Why the stream can no longer read its job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollError {
    /// The subject lost the read grant.
    AccessRevoked,
    /// The queue or the status view failed.
    Unavailable,
}

/// Reads the current view of one job for one subject.
///
/// The function reads the status first, because an expired lease updates the
/// stored attempt. It then reads the stored job, so the view carries the same
/// attempt and run time as the status. It checks the shared read predicate
/// after the job read. A missing job, a queue error, or a view error is
/// unavailable. A lost grant is [`PollError::AccessRevoked`].
async fn current_view(
    queue: &Arc<dyn JobQueue>,
    job_id: Uuid,
    sub: &str,
    policy: &Authorizer,
) -> Result<JobStatusView, PollError> {
    let status = match queue.status(job_id).await {
        Ok(status) => status,
        Err(QueueError::NotFound(_)) => return Err(PollError::Unavailable),
        Err(error) => {
            tracing::warn!(%error, "the job status read failed; the status stream ends");
            return Err(PollError::Unavailable);
        }
    };
    let job = match queue.get(job_id).await {
        Ok(job) => job,
        Err(QueueError::NotFound(_)) => return Err(PollError::Unavailable),
        Err(error) => {
            tracing::warn!(%error, "the job read failed; the status stream ends");
            return Err(PollError::Unavailable);
        }
    };
    if !may_read(&job, sub, policy).await {
        return Err(PollError::AccessRevoked);
    }
    match status_view(&job, &status) {
        Ok(view) => Ok(view),
        Err(error) => {
            tracing::warn!(
                %error,
                "the job status view could not be built; the status stream ends"
            );
            Err(PollError::Unavailable)
        }
    }
}

/// State of one event stream.
struct StreamState {
    /// The queue that the stream reads.
    queue: Arc<dyn JobQueue>,
    /// The identifier of the job that the stream follows.
    job_id: Uuid,
    /// The subject that opened the stream.
    sub: String,
    /// The policy that decides whether the subject may still read the job.
    policy: Authorizer,
    /// The first view. The stream sends it before it reads the queue.
    initial: Option<JobStatusView>,
    /// A terminal view that the stream sends after the initial status.
    pending_terminal: Option<JobStatusView>,
    /// The view that the stream sent last.
    last: Option<JobStatusView>,
    /// True after the stream sent its terminal or error event.
    done: bool,
    /// The timer that bounds the queue read rate.
    ticker: Interval,
    /// The timer that sends a heartbeat comment.
    heartbeat: Interval,
    /// The instant at which the stream must close.
    deadline: Instant,
}

/// One timer event of the stream loop.
enum TimerEvent {
    /// The poll timer fired.
    Poll,
    /// The heartbeat timer fired.
    Heartbeat,
}

/// Builds the stream of events for one job.
///
/// The stream sends the initial view at once. A terminal initial view sends
/// its terminal event at once. Otherwise the stream reads the queue on each
/// poll tick and sends a status event only when the view changes. A heartbeat
/// comment goes out every [`HEARTBEAT_INTERVAL`], independent of the poll
/// interval. A lost grant sends `access_revoked`. A queue or view error sends
/// `stream_unavailable`. Both end the stream.
fn event_stream(
    queue: Arc<dyn JobQueue>,
    job_id: Uuid,
    sub: String,
    policy: Authorizer,
    initial: JobStatusView,
    duration: Duration,
    poll_interval: Duration,
) -> impl Stream<Item = Result<Bytes, io::Error>> + 'static {
    let now = Instant::now();
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut heartbeat = tokio::time::interval_at(now + HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let deadline = now.checked_add(duration).unwrap_or(now);
    let state = StreamState {
        queue,
        job_id,
        sub,
        policy,
        initial: Some(initial),
        pending_terminal: None,
        last: None,
        done: false,
        ticker,
        heartbeat,
        deadline,
    };

    stream::unfold(state, |mut state| async move {
        if let Some(view) = state.initial.take() {
            state.last = Some(view.clone());
            if view.state.is_terminal() {
                state.pending_terminal = Some(view.clone());
            }
            return Some((status_frame(&view), state));
        }
        if let Some(view) = state.pending_terminal.take() {
            state.done = true;
            return Some((terminal_frame(&view), state));
        }
        if state.done {
            return None;
        }

        loop {
            let event = tokio::select! {
                () = tokio::time::sleep_until(state.deadline) => return None,
                _ = state.ticker.tick() => TimerEvent::Poll,
                _ = state.heartbeat.tick() => TimerEvent::Heartbeat,
            };
            if matches!(event, TimerEvent::Heartbeat) {
                return Some((Ok(Bytes::from_static(HEARTBEAT_FRAME)), state));
            }
            let view =
                match current_view(&state.queue, state.job_id, &state.sub, &state.policy).await {
                    Ok(view) => view,
                    Err(PollError::AccessRevoked) => {
                        state.done = true;
                        return Some((Ok(error_frame(ACCESS_REVOKED_CODE)), state));
                    }
                    Err(PollError::Unavailable) => {
                        state.done = true;
                        return Some((Ok(error_frame(STREAM_UNAVAILABLE_CODE)), state));
                    }
                };
            if view.state.is_terminal() {
                state.done = true;
                return Some((terminal_frame(&view), state));
            }
            if state.last.as_ref() != Some(&view) {
                state.last = Some(view.clone());
                return Some((status_frame(&view), state));
            }
        }
    })
}

/// Builds one `status` event.
fn status_frame(view: &JobStatusView) -> Result<Bytes, io::Error> {
    view_frame(STATUS_EVENT, view)
}

/// Builds one `terminal` event.
fn terminal_frame(view: &JobStatusView) -> Result<Bytes, io::Error> {
    view_frame(TERMINAL_EVENT, view)
}

/// Builds one `error` event with a stable code.
///
/// The frame has no internal text. The code tells the client why the stream
/// ended and that it must fall back to polling.
fn error_frame(code: &str) -> Bytes {
    Bytes::from(format!(
        "event: {ERROR_EVENT}\ndata: {{\"code\":\"{code}\"}}\n\n"
    ))
}

/// Builds one event frame with a JSON data line.
///
/// The JSON encoder writes one line, so the frame has no line continuation.
fn view_frame(event: &str, view: &JobStatusView) -> Result<Bytes, io::Error> {
    let data = serde_json::to_string(view).map_err(io::Error::other)?;
    Ok(Bytes::from(format!("event: {event}\ndata: {data}\n\n")))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use actix_web::{App, http::StatusCode, test as actix_test};
    use futures_util::StreamExt as _;
    use jsonwebtoken::EncodingKey;
    use serde_json::{Value, json};

    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::http::ApiModule as _;
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::http::middleware::jwt::JwtClaimsMiddleware;
    use crate::jobs::{JobsApiModule, SubmittableKinds, poll::job_object};
    use crate::policy::{Action, PolicyEngine};
    use crate::queue::{Job, JobStatus, MemoryQueue};
    use rust_api_model::wire::CommitReceipt;

    const KID: &str = "jobs-sse-test-kid";
    const AUD: &str = "test-aud";

    struct Fixture {
        server: wiremock::MockServer,
        encoding_key: EncodingKey,
        queue: Arc<MemoryQueue>,
        engine: PolicyEngine,
    }

    impl Fixture {
        fn token(&self, sub: &str) -> anyhow::Result<String> {
            sign_rs256(
                &json!({
                    "sub": sub,
                    "iss": self.server.uri(),
                    "aud": AUD,
                    "exp": 2000000000u64,
                }),
                KID,
                &self.encoding_key,
            )
        }

        async fn module(&self) -> anyhow::Result<JobsApiModule> {
            let middleware = JwtClaimsMiddleware::<Claims>::new_with_jwks(
                &format!("{}/jwks", self.server.uri()),
                AUD,
                &self.server.uri(),
            )
            .await?;
            Ok(JobsApiModule::new(
                self.queue.clone(),
                middleware,
                self.engine.authorizer(),
                SubmittableKinds::empty(),
            ))
        }
    }

    async fn fixture() -> anyhow::Result<Fixture> {
        let (key, encoding_key) = rsa_key(KID)?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;
        let engine =
            PolicyEngine::init_s3(build_test_store(&test_prefix("jobs-sse-policy")).await).await?;
        Ok(Fixture {
            server,
            encoding_key,
            queue: Arc::new(MemoryQueue::new()),
            engine,
        })
    }

    fn auth(req: actix_test::TestRequest, token: &str) -> actix_test::TestRequest {
        req.insert_header(("Cookie", format!("auth_token={token}")))
    }

    /// Builds a policy with no rules. The owner check needs no rule.
    async fn stream_policy() -> anyhow::Result<Authorizer> {
        let store = build_test_store(&test_prefix("jobs-sse-stream-policy")).await;
        Ok(PolicyEngine::init_s3(store).await?.authorizer())
    }

    /// Builds a stream for the owner of the test job.
    async fn test_stream(
        queue: Arc<MemoryQueue>,
        id: Uuid,
        view: JobStatusView,
        duration: Duration,
        poll_interval: Duration,
    ) -> anyhow::Result<impl Stream<Item = Result<Bytes, io::Error>> + 'static> {
        Ok(event_stream(
            queue,
            id,
            "alice".to_string(),
            stream_policy().await?,
            view,
            duration,
            poll_interval,
        ))
    }

    fn sample_job(owner: &str) -> Job {
        Job {
            id: Uuid::now_v7(),
            kind: "entity.create".to_string(),
            payload: b"{}".to_vec(),
            priority: 0,
            attempt: 0,
            max_attempts: 5,
            created_at: 1_700_000_000,
            scheduled_at: 1_700_000_000,
            idempotency_key: None,
            owner_sub: Some(owner.to_string()),
            headers: BTreeMap::new(),
        }
    }

    /// Enqueues one job and marks it succeeded with `result`.
    async fn finished_job(
        queue: &MemoryQueue,
        owner: &str,
        result: Option<Vec<u8>>,
    ) -> anyhow::Result<Uuid> {
        let job = sample_job(owner);
        let id = job.id;
        queue.enqueue(job).await?;
        let mut leased = queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await?;
        let leased = leased
            .pop()
            .ok_or_else(|| anyhow::anyhow!("the job was not leased"))?;
        queue.ack(id, &leased.lease, result).await?;
        Ok(id)
    }

    /// Reads the event name and data of each event in a body.
    fn parse_events(body: &str) -> Vec<(String, Value)> {
        body.split("\n\n")
            .filter(|block| !block.trim().is_empty())
            .map(|block| {
                let mut name = String::new();
                let mut data = String::new();
                for line in block.lines() {
                    if let Some(rest) = line.strip_prefix("event: ") {
                        name = rest.to_string();
                    }
                    if let Some(rest) = line.strip_prefix("data: ") {
                        data.push_str(rest);
                    }
                }
                let value = serde_json::from_str(&data).expect("the event data is JSON");
                (name, value)
            })
            .collect()
    }

    #[actix_web::test]
    async fn the_owner_receives_the_initial_status_and_the_terminal_event() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;
        let receipt = serde_json::to_vec(&CommitReceipt { commit_seq: 9 })?;
        let id = finished_job(&fixture.queue, "alice", Some(receipt)).await?;

        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}/events")),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );

        let body = String::from_utf8(actix_test::read_body(response).await.to_vec())?;
        let events = parse_events(&body);
        assert_eq!(events.len(), 2, "one status event and one terminal event");
        assert_eq!(events[0].0, "status");
        assert_eq!(events[0].1["id"], id.to_string());
        assert_eq!(events[0].1["state"], "succeeded");
        assert_eq!(events[0].1["commit_seq"], 9);
        assert!(
            events[0].1.get("result_base64").is_none(),
            "the receipt bytes must not repeat in the view"
        );
        assert_eq!(events[1].0, "terminal");
        assert_eq!(events[1].1["id"], id.to_string());
        assert_eq!(events[1].1["state"], "succeeded");
        assert_eq!(events[1].1["commit_seq"], 9);
        assert!(
            events[1].1.get("result_base64").is_none(),
            "the receipt bytes must not repeat in the view"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn a_second_subject_gets_404_for_the_stream() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let id = finished_job(&fixture.queue, "alice", None).await?;

        let token = fixture.token("bob")?;
        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}/events")),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["error"], "job not found");
        assert_eq!(body["code"], "not_found");
        Ok(())
    }

    #[actix_web::test]
    async fn a_per_job_grant_allows_a_second_subject_to_stream() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let id = finished_job(&fixture.queue, "alice", None).await?;
        let token = fixture.token("bob")?;

        let denied = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}/events")),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, denied).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["error"], "job not found");
        assert_eq!(body["code"], "not_found");

        fixture
            .engine
            .add_rule("bob".into(), job_object(id), Action::Read)
            .await?;

        let allowed = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}/events")),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, allowed).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(actix_test::read_body(response).await.to_vec())?;
        let events = parse_events(&body);
        assert_eq!(events[0].0, "status");
        assert_eq!(events[1].0, "terminal");
        Ok(())
    }

    #[actix_web::test]
    async fn an_invalid_id_is_400_for_the_stream() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let token = fixture.token("alice")?;
        let request = auth(
            actix_test::TestRequest::get().uri("/jobs/not-a-uuid/events"),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["code"], "invalid_request");
        Ok(())
    }

    #[actix_web::test]
    async fn an_anonymous_stream_request_is_401() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let id = Uuid::now_v7();

        let request = actix_test::TestRequest::get()
            .uri(&format!("/jobs/{id}/events"))
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[actix_web::test]
    async fn a_busy_stream_gate_returns_429() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let gate = ConcurrencyGate::new(1);
        let slot = gate.acquire().expect("the only stream slot");
        let module = fixture.module().await?.with_stream_gate(gate);
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;
        let id = finished_job(&fixture.queue, "alice", None).await?;

        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}/events")),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["error"], "too many requests");
        drop(slot);
        Ok(())
    }

    #[actix_web::test]
    async fn the_module_uses_the_configured_stream_duration() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture
            .module()
            .await?
            .with_stream_max_duration(Duration::from_millis(100));
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;
        let job = sample_job("alice");
        let id = job.id;
        fixture.queue.enqueue(job).await?;

        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}/events")),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = String::from_utf8(actix_test::read_body(response).await.to_vec())?;
        let events = parse_events(&body);
        assert_eq!(
            events.len(),
            1,
            "the configured duration closes the stream before a second tick"
        );
        assert_eq!(events[0].0, "status");
        assert_eq!(events[0].1["state"], "queued");
        Ok(())
    }

    #[actix_web::test]
    async fn a_subject_at_its_stream_cap_gets_429_while_another_subject_connects()
    -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let subject_gates = SubjectGates::new(1);
        let slot = subject_gates
            .acquire("alice")
            .expect("alice holds the only subject slot");
        let module = fixture.module().await?.with_subject_gate(subject_gates);
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let alice_token = fixture.token("alice")?;
        let alice_id = finished_job(&fixture.queue, "alice", None).await?;
        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{alice_id}/events")),
            &alice_token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["error"], "too many requests");

        let bob_token = fixture.token("bob")?;
        let bob_id = finished_job(&fixture.queue, "bob", None).await?;
        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{bob_id}/events")),
            &bob_token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "one subject at its cap must not refuse another subject"
        );
        let body = String::from_utf8(actix_test::read_body(response).await.to_vec())?;
        assert_eq!(parse_events(&body).len(), 2);

        drop(slot);
        Ok(())
    }

    #[test]
    fn the_stream_duration_uses_the_earlier_of_the_token_and_the_cap() {
        let now: u64 = 1_700_000_000;
        let now = i64::try_from(now).expect("the test time fits in i64");
        let cap = Duration::from_secs(120);
        assert_eq!(
            stream_duration(1_700_000_060, now, cap),
            Duration::from_secs(60)
        );
        assert_eq!(stream_duration(1_700_003_600, now, cap), cap);
        assert_eq!(stream_duration(1_699_999_990, now, cap), Duration::ZERO);
    }

    #[test]
    fn the_event_frames_carry_the_event_name_and_the_view() {
        let job = sample_job("alice");
        let view = status_view(&job, &JobStatus::Queued).expect("the queued view builds");

        let status =
            String::from_utf8_lossy(&status_frame(&view).expect("the status frame builds"))
                .to_string();
        assert!(status.starts_with("event: status\n"));
        assert!(status.ends_with("\n\n"));
        assert!(status.contains(&format!("\"id\":\"{}\"", job.id)));
        assert!(status.contains("\"state\":\"queued\""));

        let terminal =
            String::from_utf8_lossy(&terminal_frame(&view).expect("the terminal frame builds"))
                .to_string();
        assert!(terminal.starts_with("event: terminal\n"));
        assert!(terminal.contains(&format!("\"id\":\"{}\"", job.id)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_stream_sends_a_heartbeat_comment() -> anyhow::Result<()> {
        let queue = Arc::new(MemoryQueue::new());
        let job = sample_job("alice");
        let id = job.id;
        queue.enqueue(job.clone()).await?;
        let status = queue.status(id).await?;
        let view = status_view(&job, &status)?;
        let events = test_stream(
            queue,
            id,
            view,
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .await?;
        tokio::pin!(events);

        let first = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no initial event"))??;
        assert!(String::from_utf8_lossy(&first).contains("event: status"));

        let mut heartbeat = false;
        for _ in 0..200 {
            let Some(Ok(bytes)) = events.next().await else {
                break;
            };
            if bytes.as_ref() == HEARTBEAT_FRAME {
                heartbeat = true;
                break;
            }
        }
        assert!(heartbeat, "a quiet stream must send a heartbeat");
        Ok(())
    }

    /// A heartbeat arrives before a poll that is slower than the heartbeat.
    #[tokio::test(start_paused = true)]
    async fn a_heartbeat_arrives_before_a_slow_poll() -> anyhow::Result<()> {
        let queue = Arc::new(MemoryQueue::new());
        let job = sample_job("alice");
        let id = job.id;
        queue.enqueue(job.clone()).await?;
        let view = status_view(&job, &queue.status(id).await?)?;
        let events = test_stream(
            queue.clone(),
            id,
            view,
            Duration::from_secs(60),
            Duration::from_secs(20),
        )
        .await?;
        tokio::pin!(events);

        let first = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no initial event"))??;
        assert!(String::from_utf8_lossy(&first).contains("event: status"));

        let start = Instant::now();
        let heartbeat = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no heartbeat"))??;
        assert_eq!(heartbeat.as_ref(), HEARTBEAT_FRAME);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= HEARTBEAT_INTERVAL,
            "the heartbeat must wait for its own interval"
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "the heartbeat must arrive before the 20 s poll"
        );

        queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await?;
        let next = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no status change"))??;
        let next = parse_events(&String::from_utf8_lossy(&next));
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].0, "status");
        assert_eq!(next[0].1["state"], "leased");
        Ok(())
    }

    /// A zero poll interval from the builder gets a finite timer.
    ///
    /// The test fetches JWKS from a local server, so it uses real time.
    /// Paused time can fire the fetch timeout.
    #[tokio::test]
    async fn a_zero_stream_poll_interval_gets_a_finite_tick() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture
            .module()
            .await?
            .with_stream_poll_interval(Duration::ZERO);
        let poll_interval = module.stream_timing.poll_interval;
        assert!(
            !poll_interval.is_zero(),
            "a zero poll interval must not reach the timer"
        );
        let mut ticker = tokio::time::interval(poll_interval);
        ticker.tick().await;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn the_stream_sends_a_status_event_when_the_view_changes() -> anyhow::Result<()> {
        let queue = Arc::new(MemoryQueue::new());
        let job = sample_job("alice");
        let id = job.id;
        queue.enqueue(job.clone()).await?;
        let view = status_view(&job, &queue.status(id).await?)?;
        let events = test_stream(
            queue.clone(),
            id,
            view,
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .await?;
        tokio::pin!(events);

        let first = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no initial event"))??;
        assert!(String::from_utf8_lossy(&first).contains("\"state\":\"queued\""));

        queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await?;
        let next = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no status change"))??;
        assert!(String::from_utf8_lossy(&next).contains("\"state\":\"leased\""));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn the_stream_sends_a_terminal_event_when_the_job_finishes() -> anyhow::Result<()> {
        let queue = Arc::new(MemoryQueue::new());
        let job = sample_job("alice");
        let id = job.id;
        queue.enqueue(job.clone()).await?;
        let view = status_view(&job, &queue.status(id).await?)?;
        let events = test_stream(
            queue.clone(),
            id,
            view,
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .await?;
        tokio::pin!(events);

        let first = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no initial event"))??;
        assert!(String::from_utf8_lossy(&first).contains("\"state\":\"queued\""));

        let mut leased = queue
            .reserve("worker-1", 1, Duration::from_secs(30))
            .await?;
        let leased = leased
            .pop()
            .ok_or_else(|| anyhow::anyhow!("the job was not leased"))?;
        queue.ack(id, &leased.lease, None).await?;

        let terminal = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no terminal event"))??;
        let text = String::from_utf8_lossy(&terminal).to_string();
        assert!(text.starts_with("event: terminal\n"));
        assert!(text.contains("\"state\":\"succeeded\""));
        assert!(events.next().await.is_none(), "the stream must close");
        Ok(())
    }

    #[tokio::test]
    async fn the_stream_reads_a_fresh_job_after_a_lease_expires() -> anyhow::Result<()> {
        let queue = Arc::new(MemoryQueue::new());
        let job = sample_job("alice");
        let id = job.id;
        queue.enqueue(job.clone()).await?;
        let view = status_view(&job, &queue.status(id).await?)?;
        let events = test_stream(
            queue.clone(),
            id,
            view,
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .await?;
        tokio::pin!(events);

        let first = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no initial event"))??;
        let first = String::from_utf8_lossy(&first).to_string();
        assert!(first.contains("\"attempt\":0"));

        // A zero lease expires before the next tick. The status read then
        // moves the job back to queued with a new attempt and run time.
        queue
            .reserve("worker-1", 10, Duration::from_secs(0))
            .await?;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let next = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no refreshed event"))??;
        let next = parse_events(&String::from_utf8_lossy(&next));
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].0, "status");
        assert_eq!(next[0].1["state"], "queued");
        assert_eq!(next[0].1["attempt"], 1);
        let scheduled_at = next[0].1["scheduled_at"]
            .as_i64()
            .ok_or_else(|| anyhow::anyhow!("the view has no run time"))?;
        assert!(
            scheduled_at > job.scheduled_at,
            "the refreshed view must not reuse the connect-time run time"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_ends_at_the_configured_duration() -> anyhow::Result<()> {
        let queue = Arc::new(MemoryQueue::new());
        let job = sample_job("alice");
        let id = job.id;
        queue.enqueue(job.clone()).await?;
        let view = status_view(&job, &JobStatus::Queued)?;
        let events = test_stream(
            queue,
            id,
            view,
            Duration::from_millis(300),
            Duration::from_millis(100),
        )
        .await?;
        tokio::pin!(events);

        assert!(events.next().await.is_some(), "the initial event arrives");
        assert!(
            events.next().await.is_none(),
            "the configured duration ends the stream"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_overflowing_stream_duration_ends_after_the_initial_status() -> anyhow::Result<()> {
        let queue = Arc::new(MemoryQueue::new());
        let job = sample_job("alice");
        let id = job.id;
        queue.enqueue(job.clone()).await?;
        let view = status_view(&job, &JobStatus::Queued)?;
        let events =
            test_stream(queue, id, view, Duration::MAX, Duration::from_millis(100)).await?;
        tokio::pin!(events);

        assert!(events.next().await.is_some(), "the initial event arrives");
        assert!(
            events.next().await.is_none(),
            "an overflow falls back to an immediate deadline"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_queue_error_ends_the_stream_without_sending_text() -> anyhow::Result<()> {
        let queue = Arc::new(MemoryQueue::new());
        let job = sample_job("alice");
        let id = job.id;
        let view = status_view(&job, &JobStatus::Queued)?;
        let events = test_stream(
            queue,
            id,
            view,
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .await?;
        tokio::pin!(events);

        assert!(events.next().await.is_some(), "the initial event arrives");
        let error = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no error event"))??;
        let error = parse_events(&String::from_utf8_lossy(&error));
        assert_eq!(error.len(), 1);
        assert_eq!(error[0].0, "error");
        assert_eq!(error[0].1["code"], "stream_unavailable");
        assert!(
            events.next().await.is_none(),
            "the queue error ends the stream"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_view_error_ends_the_stream_without_sending_text() -> anyhow::Result<()> {
        let queue = Arc::new(MemoryQueue::new());
        let valid = sample_job("alice");
        let view = status_view(&valid, &JobStatus::Queued)?;
        let mut job = valid;
        job.kind = "not a kind".to_string();
        let id = job.id;
        queue.enqueue(job.clone()).await?;
        let events = test_stream(
            queue,
            id,
            view,
            Duration::from_secs(60),
            Duration::from_millis(100),
        )
        .await?;
        tokio::pin!(events);

        assert!(events.next().await.is_some(), "the initial event arrives");
        let error = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no error event"))??;
        let error = parse_events(&String::from_utf8_lossy(&error));
        assert_eq!(error.len(), 1);
        assert_eq!(error[0].0, "error");
        assert_eq!(error[0].1["code"], "stream_unavailable");
        assert!(
            events.next().await.is_none(),
            "the view error ends the stream"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_sends_access_revoked_when_the_grant_is_removed() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let job = sample_job("alice");
        let id = job.id;
        fixture.queue.enqueue(job.clone()).await?;
        let view = status_view(&job, &fixture.queue.status(id).await?)?;
        let object = job_object(id);
        fixture
            .engine
            .add_rule("bob".into(), object.clone(), Action::Read)
            .await?;
        let events = event_stream(
            fixture.queue.clone(),
            id,
            "bob".to_string(),
            fixture.engine.authorizer(),
            view,
            Duration::from_secs(60),
            Duration::from_millis(100),
        );
        tokio::pin!(events);

        let first = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no initial event"))??;
        assert!(String::from_utf8_lossy(&first).contains("event: status"));

        fixture
            .engine
            .remove_rule("bob".into(), object, Action::Read)
            .await?;
        let error = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream has no error event"))??;
        let error = parse_events(&String::from_utf8_lossy(&error));
        assert_eq!(error.len(), 1);
        assert_eq!(error[0].0, "error");
        assert_eq!(error[0].1["code"], "access_revoked");
        assert!(
            events.next().await.is_none(),
            "the revoked stream must close"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn a_job_with_an_unknown_kind_is_500() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;
        let mut job = sample_job("alice");
        job.kind = "not a kind".to_string();
        let id = job.id;
        fixture.queue.enqueue(job).await?;

        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}/events")),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }
}
