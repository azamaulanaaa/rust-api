//! The poll routes for job submission and one job status.
//!
//! The routes derive the owner from the validated JWT claims. A client
//! cannot set the owner.

use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{HttpResponse, get, http::StatusCode, web};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rust_api_model::wire::{CommandEnvelope, MAX_IDEMPOTENCY_KEY_LEN};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::http::error::ApiError;
use crate::http::middleware::jwt::{Claims, Validated};
use crate::policy::{Action, Authorizer, SUPERADMIN_ROLE};
use crate::queue::{Job, JobQueue, QueueError};

use super::{SubmittableKinds, redact_non_owner, status_view};

/// The queue priority of a job that an HTTP request enqueues.
const JOB_PRIORITY: i32 = 0;
/// The attempt budget of a job that an HTTP request enqueues.
const MAX_ATTEMPTS: u32 = 5;
/// The job header that holds the idempotency fingerprint.
///
/// The value is the base64 SHA-256 of the kind, a NUL byte, and the stored
/// payload bytes. The route reserves this header name.
const IDEMPOTENCY_FINGERPRINT_HEADER: &str = "x-idempotency-sha256";

/// Enqueues one command for the authenticated subject.
///
/// The server takes the owner from `Claims.sub`. A client cannot set the
/// owner. The payload is stored as JSON bytes.
///
/// A duplicate idempotency key returns the stored job only when the kind and
/// payload match. An edited retry gets `409`. The key is scoped to the owner,
/// so two subjects can use the same key without seeing each other's jobs.
///
/// The route stores a base64 SHA-256 fingerprint of the kind and the stored
/// payload bytes under the reserved `x-idempotency-sha256` job header.
///
/// # Errors
///
/// Returns `400` when the body is not a [`CommandEnvelope`], the kind is
/// not in the client-submittable set, `expected_version` is present, or the
/// idempotency key is empty or longer than [`MAX_IDEMPOTENCY_KEY_LEN`].
/// Returns `401` when the request has no valid token.
/// Returns `409` when the queue reports a duplicate key without the stored
/// job id, the stored job belongs to another subject, or the stored
/// fingerprint does not match this body.
/// Returns `500` when the queue fails.
#[utoipa::path(
    post,
    path = "/jobs",
    tag = "jobs",
    request_body = rust_api_model::wire::CommandEnvelope,
    responses(
        (status = 202, description = "the job was accepted", body = rust_api_model::wire::JobStatusView),
        (status = 400, description = "the body, kind, version, or key is invalid", body = crate::http::error::ErrorBody),
        (status = 401, description = "authentication required", body = crate::http::error::ErrorBody),
        (status = 409, description = "the idempotency key conflicts", body = crate::http::error::ErrorBody),
        (status = 500, description = "the queue or the job view failed", body = crate::http::error::ErrorBody)
    )
)]
pub async fn create_job(
    claims: Validated<Claims>,
    queue: web::Data<Arc<dyn JobQueue>>,
    submittable: web::Data<SubmittableKinds>,
    body: web::Json<CommandEnvelope>,
) -> Result<HttpResponse, ApiError> {
    let now = chrono::Utc::now().timestamp();
    let envelope = body.into_inner();
    if !submittable.contains(&envelope.kind) {
        return Err(ApiError::BadRequest);
    }
    if envelope.expected_version.is_some() {
        return Err(ApiError::BadRequest);
    }
    let key = &envelope.idempotency_key;
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(ApiError::BadRequest);
    }
    let owner = claims.sub.clone();
    let payload = serde_json::to_vec(&envelope.payload)
        .map_err(|error| ApiError::Internal(Box::new(error)))?;
    let fingerprint = idempotency_fingerprint(envelope.kind.as_str(), &payload);
    let mut headers = BTreeMap::new();
    headers.insert(IDEMPOTENCY_FINGERPRINT_HEADER.to_string(), fingerprint.clone());
    let job = Job {
        id: Uuid::now_v7(),
        kind: envelope.kind.as_str().to_string(),
        payload,
        priority: JOB_PRIORITY,
        attempt: 0,
        max_attempts: MAX_ATTEMPTS,
        created_at: now,
        scheduled_at: now,
        idempotency_key: Some(owner_idempotency_key(&owner, key)),
        owner_sub: Some(owner.clone()),
        headers,
    };

    let id = queue.enqueue(job).await.map_err(queue_error)?;
    // A duplicate key returns the id of the stored job. Read the status
    // first: an expired lease updates the stored attempt.
    let status = queue.status(id).await.map_err(queue_error)?;
    let stored = queue.get(id).await.map_err(queue_error)?;
    // The queue keys are owner-scoped above. This check is defensive: a
    // backend that returns another owner's id must not answer with that job.
    if stored.owner_sub.as_deref() != Some(owner.as_str()) {
        return Err(ApiError::Conflict);
    }
    // A duplicate key must come from the same command. The fingerprint
    // covers the kind and payload, so an edited retry conflicts.
    if stored.headers.get(IDEMPOTENCY_FINGERPRINT_HEADER) != Some(&fingerprint) {
        return Err(ApiError::Conflict);
    }
    let view =
        status_view(&stored, &status).map_err(|error| ApiError::Internal(Box::new(error)))?;

    Ok(HttpResponse::Accepted().json(view))
}

/// Returns the status of one job.
///
/// The owner reads the job. A holder of the `superadmin` role reads every
/// job. A policy rule on the object `job:<uuid>` with the `read` action also
/// allows that job. An administrator adds the rule through the existing
/// policy routes. Any other subject gets `404`, the same answer as for a
/// missing job, so the route does not show whether a job exists. The
/// response carries `Cache-Control: no-store`. The result bytes and the
/// error text are owner-only.
///
/// # Per-job grants
///
/// An administrator grants one subject access to one job with a policy rule
/// on the object `job:<uuid>` and the action `read`. The rule has no TTL and
/// no automatic cleanup. Remove the rule through the existing policy route
/// `DELETE /policy/rules` when access must end.
///
/// # Errors
///
/// Returns `400` when the id is not a UUID.
/// Returns `401` when the request has no valid token.
#[utoipa::path(
    get,
    path = "/jobs/{id}",
    tag = "jobs",
    params(("id" = String, Path, description = "job identifier")),
    responses(
        (status = 200, description = "the job status", body = rust_api_model::wire::JobStatusView),
        (status = 400, description = "the id is not a UUID", body = crate::http::error::ErrorBody),
        (status = 401, description = "authentication required", body = crate::http::error::ErrorBody),
        (status = 404, description = "the job is absent or not visible", body = crate::http::error::ErrorBody),
        (status = 500, description = "the queue or the job view failed", body = crate::http::error::ErrorBody)
    )
)]
#[get("/{id}")]
pub async fn get_job(
    id: web::Path<String>,
    claims: Validated<Claims>,
    queue: web::Data<Arc<dyn JobQueue>>,
    policy: web::Data<Authorizer>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::parse_str(&id.into_inner()).map_err(|_| ApiError::BadRequest)?;
    // Read the status first: an expired lease updates the stored attempt, so
    // the job read that follows carries the same attempt as the view.
    let status = match queue.status(id).await {
        Ok(status) => status,
        Err(QueueError::NotFound(_)) => return Ok(not_found()),
        Err(error) => return Err(queue_error(error)),
    };
    let job = match queue.get(id).await {
        Ok(job) => job,
        Err(QueueError::NotFound(_)) => return Ok(not_found()),
        Err(error) => return Err(queue_error(error)),
    };
    let is_owner = job.owner_sub.as_deref() == Some(claims.sub.as_str());
    if !may_read(&job, &claims.sub, &policy).await {
        return Ok(not_found());
    }
    let mut view =
        status_view(&job, &status).map_err(|error| ApiError::Internal(Box::new(error)))?;
    redact_non_owner(&mut view, is_owner);

    Ok(HttpResponse::Ok().json(view))
}

/// Reports whether `sub` may read `job`.
///
/// The owner reads the job. A holder of the [`SUPERADMIN_ROLE`] role reads
/// every job. A policy rule on the object `job:<uuid>` with the `read`
/// action also allows that job. An administrator adds the rule through the
/// existing policy routes. A policy error denies the read and stays in the
/// log, so a failure does not change the answer from `404` to `500`.
async fn may_read(job: &Job, sub: &str, policy: &Authorizer) -> bool {
    if job.owner_sub.as_deref() == Some(sub) {
        return true;
    }
    let roles = policy.groups_of_user(sub).await;
    if roles.iter().any(|role| role == SUPERADMIN_ROLE) {
        return true;
    }
    match policy
        .authorize(sub, job_object(job.id), Action::Read)
        .await
    {
        Ok(allowed) => allowed,
        Err(error) => {
            tracing::warn!(%error, "the job read policy check failed; the read is denied");
            false
        }
    }
}

/// Returns the policy object name for one job.
///
/// The form is `job:<uuid>` and the action is `read`. An administrator
/// grants one subject access to one job with these values.
fn job_object(id: Uuid) -> String {
    format!("job:{id}")
}

/// Builds the answer for an absent job and for a job that the caller may not
/// read.
///
/// Both cases return the same answer, so the route does not show whether a
/// job exists.
fn not_found() -> HttpResponse {
    ApiError::envelope(
        StatusCode::NOT_FOUND,
        "job not found",
        Some("not_found"),
        None,
    )
}

/// Maps a queue failure onto the shared API error type.
///
/// A duplicate key with no job id is a conflict, because a retry cannot
/// return a job that the queue did not name. Every other backend failure is
/// an internal error and stays out of the response body.
fn queue_error(error: QueueError) -> ApiError {
    match error {
        QueueError::Invalid(message) => {
            tracing::warn!(%message, "the queue rejected a job");
            ApiError::BadRequest
        }
        QueueError::DuplicateIdempotency(_) => ApiError::Conflict,
        other => ApiError::Internal(Box::new(other)),
    }
}

/// Returns the idempotency key that the queue stores for one owner.
///
/// The length prefix keeps two owner and key pairs distinct when either
/// value contains the separator. A global key would let one subject reach
/// another subject's job by reusing an idempotency key.
fn owner_idempotency_key(owner: &str, key: &str) -> String {
    format!("{}:{}:{}", owner.len(), owner, key)
}

/// Returns the fingerprint of one command body.
///
/// The input is the kind, a NUL byte, and the exact payload bytes that the
/// job stores. The owner is not part of the hash, because the queue key is
/// already owner-scoped.
fn idempotency_fingerprint(kind: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(payload);
    STANDARD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use actix_web::{App, http::StatusCode, test as actix_test};
    use jsonwebtoken::EncodingKey;
    use serde_json::{Value, json};

    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::http::ApiModule as _;
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::http::middleware::jwt::JwtClaimsMiddleware;
    use crate::jobs::{JobsApiModule, SubmittableKinds};
    use crate::policy::PolicyEngine;
    use crate::queue::{LeaseToken, MemoryQueue, RetryPolicy};

    const KID: &str = "jobs-poll-test-kid";
    const AUD: &str = "test-aud";

    struct Fixture {
        server: wiremock::MockServer,
        encoding_key: EncodingKey,
        queue: Arc<MemoryQueue>,
        engine: PolicyEngine,
        submittable: SubmittableKinds,
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
                self.submittable.clone(),
            ))
        }
    }

    async fn fixture() -> anyhow::Result<Fixture> {
        let (key, encoding_key) = rsa_key(KID)?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;
        let engine =
            PolicyEngine::init_s3(build_test_store(&test_prefix("jobs-poll-policy")).await).await?;
        let submittable = SubmittableKinds::from_names(["entity.create", "entity.delete"])?;
        Ok(Fixture {
            server,
            encoding_key,
            queue: Arc::new(MemoryQueue::new()),
            engine,
            submittable,
        })
    }

    fn auth(req: actix_test::TestRequest, token: &str) -> actix_test::TestRequest {
        req.insert_header(("Cookie", format!("auth_token={token}")))
    }

    /// Leases the one queued job and returns its lease token.
    async fn lease_one(fixture: &Fixture, id: Uuid) -> anyhow::Result<LeaseToken> {
        let leased = fixture.queue.reserve("worker-1", 1, Duration::from_secs(30)).await?;
        let job = leased.into_iter().next().expect("a job is queued");
        assert_eq!(job.job.id, id);
        Ok(job.lease)
    }

    /// Marks one job as succeeded with the given result bytes.
    async fn succeed_with(fixture: &Fixture, id: Uuid, result: Vec<u8>) -> anyhow::Result<()> {
        let lease = lease_one(fixture, id).await?;
        fixture.queue.ack(id, &lease, Some(result)).await?;
        Ok(())
    }

    /// Marks one job as failed with the given error text.
    async fn fail_with(fixture: &Fixture, id: Uuid, error: &str) -> anyhow::Result<()> {
        let lease = lease_one(fixture, id).await?;
        fixture.queue.nack(id, &lease, error, RetryPolicy::NoRetry).await?;
        Ok(())
    }

    fn command_body(key: &str) -> String {
        json!({
            "kind": "entity.create",
            "payload": {"name": "alice"},
            "idempotency_key": key,
        })
        .to_string()
    }

    /// Sends one command and returns the `202` view.
    ///
    /// The macro expands at the call site, because the Actix test service
    /// type is not nameable in a function signature.
    macro_rules! post_command {
        ($app:expr, $token:expr, $key:expr) => {{
            let request = auth(actix_test::TestRequest::post().uri("/jobs"), &$token)
                .insert_header(("Content-Type", "application/json"))
                .set_payload(command_body($key))
                .to_request();
            let response = actix_test::call_service(&$app, request).await;
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            actix_test::read_body_json::<Value, _>(response).await
        }};
    }

    /// Sends one status read and returns the response.
    macro_rules! read_job {
        ($app:expr, $token:expr, $id:expr) => {{
            let request = auth(
                actix_test::TestRequest::get().uri(&format!("/jobs/{}", $id)),
                &$token,
            )
            .to_request();
            actix_test::call_service(&$app, request).await
        }};
    }

    #[actix_web::test]
    async fn the_module_claims_the_jobs_prefix() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        assert_eq!(fixture.module().await?.prefix(), "/jobs");
        Ok(())
    }

    #[actix_web::test]
    async fn the_owner_enqueues_and_reads_the_job() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;

        let created = post_command!(app, token, "key-1");
        assert_eq!(created["kind"], "entity.create");
        assert_eq!(created["state"], "queued");
        assert_eq!(created["attempt"], 0);
        assert_eq!(created["max_attempts"], 5);
        let id = created["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();

        let stored = fixture.queue.get(Uuid::parse_str(&id)?).await?;
        assert_eq!(stored.owner_sub.as_deref(), Some("alice"));
        assert_eq!(stored.kind, "entity.create");
        assert_eq!(stored.priority, 0);
        assert_eq!(stored.max_attempts, 5);

        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}")),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let read: Value = actix_test::read_body_json(response).await;
        assert_eq!(read["id"], created["id"]);
        assert_eq!(read["kind"], "entity.create");
        assert_eq!(read["state"], "queued");
        Ok(())
    }

    #[actix_web::test]
    async fn an_unregistered_kind_is_400() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let token = fixture.token("alice")?;
        let body = json!({
            "kind": "entity.update",
            "payload": {"name": "alice"},
            "idempotency_key": "key-1",
        });
        let request = auth(actix_test::TestRequest::post().uri("/jobs"), &token)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(body.to_string())
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["error"], "bad request");
        assert_eq!(body["code"], "invalid_request");
        assert!(
            !body.to_string().contains("entity.update"),
            "the answer must not echo the kind"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn an_expected_version_is_400() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let token = fixture.token("alice")?;
        let body = json!({
            "kind": "entity.create",
            "payload": {"name": "alice"},
            "idempotency_key": "key-1",
            "expected_version": 3,
        });
        let request = auth(actix_test::TestRequest::post().uri("/jobs"), &token)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(body.to_string())
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["code"], "invalid_request");
        Ok(())
    }

    #[actix_web::test]
    async fn an_invalid_idempotency_key_is_400() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;

        for key in [String::new(), "k".repeat(MAX_IDEMPOTENCY_KEY_LEN + 1)] {
            let body = command_body(&key);
            let request = auth(actix_test::TestRequest::post().uri("/jobs"), &token)
                .insert_header(("Content-Type", "application/json"))
                .set_payload(body)
                .to_request();
            let response = actix_test::call_service(&app, request).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body: Value = actix_test::read_body_json(response).await;
            assert_eq!(body["code"], "invalid_request");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn a_maximum_length_idempotency_key_is_accepted() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;

        let key = "k".repeat(MAX_IDEMPOTENCY_KEY_LEN);
        let created = post_command!(app, token, &key);
        assert_eq!(created["state"], "queued");
        Ok(())
    }

    #[actix_web::test]
    async fn the_webhook_delivery_kind_is_not_submittable() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let token = fixture.token("alice")?;
        let body = json!({
            "kind": "webhook.deliver",
            "payload": {"url": "https://example.test/hook"},
            "idempotency_key": "key-1",
        });
        let request = auth(actix_test::TestRequest::post().uri("/jobs"), &token)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(body.to_string())
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["code"], "invalid_request");
        Ok(())
    }

    #[actix_web::test]
    async fn a_second_subject_gets_404_for_the_job() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice_token = fixture.token("alice")?;
        let created = post_command!(app, alice_token, "key-1");
        let id = created["id"].as_str().expect("the view has an id");

        let bob_token = fixture.token("bob")?;
        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}")),
            &bob_token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["error"], "job not found");
        assert_eq!(body["code"], "not_found");
        assert!(
            body.get("kind").is_none(),
            "the answer must not show the job"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn an_invalid_id_is_400() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let token = fixture.token("alice")?;
        let request = auth(
            actix_test::TestRequest::get().uri("/jobs/not-a-uuid"),
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
    async fn an_unknown_job_is_404() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let token = fixture.token("alice")?;
        let id = Uuid::now_v7();
        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}")),
            &token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["code"], "not_found");
        Ok(())
    }

    #[test]
    fn queue_errors_map_to_the_expected_api_errors() {
        assert!(matches!(
            queue_error(QueueError::Invalid("bad max_attempts".to_string())),
            ApiError::BadRequest
        ));
        assert!(matches!(
            queue_error(QueueError::DuplicateIdempotency("key-1".to_string())),
            ApiError::Conflict
        ));
        assert!(matches!(
            queue_error(QueueError::store(std::io::Error::other("disk full"))),
            ApiError::Internal(_)
        ));
    }

    #[actix_web::test]
    async fn a_per_job_grant_allows_a_second_subject() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice_token = fixture.token("alice")?;
        let created = post_command!(app, alice_token, "key-1");
        let id = created["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();
        let bob_token = fixture.token("bob")?;

        let denied = read_job!(app, bob_token, id);
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);

        let object = job_object(Uuid::parse_str(&id)?);
        fixture
            .engine
            .add_rule("bob".into(), object, Action::Read)
            .await?;

        let allowed = read_job!(app, bob_token, id);
        assert_eq!(allowed.status(), StatusCode::OK);
        let view: Value = actix_test::read_body_json(allowed).await;
        assert_eq!(view["id"], created["id"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_grant_for_another_job_does_not_allow_the_read() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice_token = fixture.token("alice")?;
        let first = post_command!(app, alice_token, "key-1");
        let second = post_command!(app, alice_token, "key-2");
        let first_id = first["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();
        let second_id = second["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();
        let bob_token = fixture.token("bob")?;

        let object = job_object(Uuid::parse_str(&second_id)?);
        fixture
            .engine
            .add_rule("bob".into(), object, Action::Read)
            .await?;

        let denied = read_job!(app, bob_token, first_id);
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
        let body: Value = actix_test::read_body_json(denied).await;
        assert_eq!(body["error"], "job not found");
        assert_eq!(body["code"], "not_found");

        let allowed = read_job!(app, bob_token, second_id);
        assert_eq!(allowed.status(), StatusCode::OK);
        Ok(())
    }

    #[actix_web::test]
    async fn the_view_keeps_the_attempt_of_an_expired_lease() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice_token = fixture.token("alice")?;
        let created = post_command!(app, alice_token, "key-1");
        let id = created["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();

        let _ = fixture
            .queue
            .reserve("worker-1", 10, Duration::from_secs(0))
            .await?;

        let response = read_job!(app, alice_token, id);
        assert_eq!(response.status(), StatusCode::OK);
        let view: Value = actix_test::read_body_json(response).await;
        assert_eq!(view["attempt"], 1);
        assert_eq!(view["state"], "queued");
        Ok(())
    }

    #[actix_web::test]
    async fn a_duplicate_idempotency_key_returns_the_stored_job() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;

        let first = post_command!(app, token, "key-1");
        let second = post_command!(app, token, "key-1");

        assert_eq!(first["id"], second["id"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_duplicate_key_with_a_different_body_is_409() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;

        let _ = post_command!(app, token, "key-1");
        let body = json!({
            "kind": "entity.create",
            "payload": {"name": "bob"},
            "idempotency_key": "key-1",
        });
        let request = auth(actix_test::TestRequest::post().uri("/jobs"), &token)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(body.to_string())
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["code"], "conflict");
        Ok(())
    }

    #[actix_web::test]
    async fn a_duplicate_key_with_a_different_kind_is_409() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;

        let _ = post_command!(app, token, "key-1");
        let body = json!({
            "kind": "entity.delete",
            "payload": {"name": "alice"},
            "idempotency_key": "key-1",
        });
        let request = auth(actix_test::TestRequest::post().uri("/jobs"), &token)
            .insert_header(("Content-Type", "application/json"))
            .set_payload(body.to_string())
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(body["code"], "conflict");
        Ok(())
    }

    #[actix_web::test]
    async fn two_subjects_keep_separate_idempotency_keys() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let alice_token = fixture.token("alice")?;
        let bob_token = fixture.token("bob")?;
        let alice = post_command!(app, alice_token, "shared-key");
        let bob = post_command!(app, bob_token, "shared-key");

        assert_ne!(alice["id"], bob["id"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_superadmin_reads_every_job() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        assert!(fixture.engine.claim_superadmin("root").await?);
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice_token = fixture.token("alice")?;
        let created = post_command!(app, alice_token, "key-1");
        let id = created["id"].as_str().expect("the view has an id");

        let root_token = fixture.token("root")?;
        let request = auth(
            actix_test::TestRequest::get().uri(&format!("/jobs/{id}")),
            &root_token,
        )
        .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let read: Value = actix_test::read_body_json(response).await;
        assert_eq!(read["id"], created["id"]);
        Ok(())
    }

    #[actix_web::test]
    async fn the_owner_sees_the_result_and_error() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice_token = fixture.token("alice")?;

        let succeeded = post_command!(app, alice_token, "key-1");
        let succeeded_id = succeeded["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();
        succeed_with(
            &fixture,
            Uuid::parse_str(&succeeded_id)?,
            b"secret".to_vec(),
        )
        .await?;

        let failed = post_command!(app, alice_token, "key-2");
        let failed_id = failed["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();
        fail_with(&fixture, Uuid::parse_str(&failed_id)?, "boom").await?;

        let response = read_job!(app, alice_token, succeeded_id);
        assert_eq!(response.status(), StatusCode::OK);
        let view: Value = actix_test::read_body_json(response).await;
        assert_eq!(view["result_base64"], "c2VjcmV0");
        assert!(view.get("error").is_none());

        let response = read_job!(app, alice_token, failed_id);
        assert_eq!(response.status(), StatusCode::OK);
        let view: Value = actix_test::read_body_json(response).await;
        assert_eq!(view["error"], "boom");
        assert!(view.get("result_base64").is_none());
        Ok(())
    }

    #[actix_web::test]
    async fn a_superadmin_does_not_see_the_result_or_error() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        assert!(fixture.engine.claim_superadmin("root").await?);
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice_token = fixture.token("alice")?;

        let succeeded = post_command!(app, alice_token, "key-1");
        let succeeded_id = succeeded["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();
        succeed_with(
            &fixture,
            Uuid::parse_str(&succeeded_id)?,
            b"secret".to_vec(),
        )
        .await?;

        let failed = post_command!(app, alice_token, "key-2");
        let failed_id = failed["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();
        fail_with(&fixture, Uuid::parse_str(&failed_id)?, "boom").await?;

        let root_token = fixture.token("root")?;
        let response = read_job!(app, root_token, succeeded_id);
        assert_eq!(response.status(), StatusCode::OK);
        let view: Value = actix_test::read_body_json(response).await;
        assert!(view.get("result_base64").is_none());
        assert!(view.get("error").is_none());

        let response = read_job!(app, root_token, failed_id);
        assert_eq!(response.status(), StatusCode::OK);
        let view: Value = actix_test::read_body_json(response).await;
        assert!(view.get("error").is_none());
        assert!(view.get("result_base64").is_none());
        Ok(())
    }

    #[actix_web::test]
    async fn a_grantee_does_not_see_the_result_or_error() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice_token = fixture.token("alice")?;

        let succeeded = post_command!(app, alice_token, "key-1");
        let succeeded_id = succeeded["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();
        succeed_with(
            &fixture,
            Uuid::parse_str(&succeeded_id)?,
            b"secret".to_vec(),
        )
        .await?;

        let failed = post_command!(app, alice_token, "key-2");
        let failed_id = failed["id"]
            .as_str()
            .expect("the view has an id")
            .to_string();
        fail_with(&fixture, Uuid::parse_str(&failed_id)?, "boom").await?;

        let succeeded_object = job_object(Uuid::parse_str(&succeeded_id)?);
        fixture
            .engine
            .add_rule("bob".into(), succeeded_object, Action::Read)
            .await?;
        let failed_object = job_object(Uuid::parse_str(&failed_id)?);
        fixture
            .engine
            .add_rule("bob".into(), failed_object, Action::Read)
            .await?;

        let bob_token = fixture.token("bob")?;
        let response = read_job!(app, bob_token, succeeded_id);
        assert_eq!(response.status(), StatusCode::OK);
        let view: Value = actix_test::read_body_json(response).await;
        assert!(view.get("result_base64").is_none());
        assert!(view.get("error").is_none());

        let response = read_job!(app, bob_token, failed_id);
        assert_eq!(response.status(), StatusCode::OK);
        let view: Value = actix_test::read_body_json(response).await;
        assert!(view.get("error").is_none());
        assert!(view.get("result_base64").is_none());
        Ok(())
    }

    #[actix_web::test]
    async fn an_anonymous_request_is_401() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        for request in [
            actix_test::TestRequest::post()
                .uri("/jobs")
                .insert_header(("Content-Type", "application/json"))
                .set_payload(command_body("key-1"))
                .to_request(),
            actix_test::TestRequest::get()
                .uri("/jobs/0190f6e0-0000-7000-8000-000000000000")
                .to_request(),
        ] {
            let response = actix_test::call_service(&app, request).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        Ok(())
    }
}
