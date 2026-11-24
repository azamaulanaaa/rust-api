//! The poll routes for job submission and one job status.
//!
//! The routes derive the owner from the validated JWT claims. A client
//! cannot set the owner.

use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{HttpResponse, get, web};
use rust_api_model::wire::CommandEnvelope;
use uuid::Uuid;

use crate::http::error::ApiError;
use crate::http::middleware::jwt::{Claims, Validated};
use crate::queue::{Job, JobQueue, QueueError};

use super::not_implemented;
use super::status_view;

/// The queue priority of a job that an HTTP request enqueues.
const JOB_PRIORITY: i32 = 0;
/// The attempt budget of a job that an HTTP request enqueues.
const MAX_ATTEMPTS: u32 = 5;

/// Enqueues one command for the authenticated subject.
///
/// The server takes the owner from `Claims.sub`. A client cannot set the
/// owner. The payload is stored as JSON bytes.
///
/// A duplicate idempotency key returns the stored job, so a retry returns
/// the same job id and the same view. The key is scoped to the owner, so two
/// subjects can use the same key without seeing each other's jobs.
///
/// # Errors
///
/// Returns `400` when the body is not a [`CommandEnvelope`].
/// Returns `401` when the request has no valid token.
/// Returns `409` when the queue reports a duplicate key without the stored
/// job id, because that error carries no id to read.
/// Returns `500` when the queue fails.
pub async fn create_job(
    claims: Validated<Claims>,
    queue: web::Data<Arc<dyn JobQueue>>,
    body: web::Json<CommandEnvelope>,
) -> Result<HttpResponse, ApiError> {
    let now = chrono::Utc::now().timestamp();
    let envelope = body.into_inner();
    let owner = claims.sub.clone();
    let payload = serde_json::to_vec(&envelope.payload)
        .map_err(|error| ApiError::Internal(Box::new(error)))?;
    let job = Job {
        id: Uuid::now_v7(),
        kind: envelope.kind.as_str().to_string(),
        payload,
        priority: JOB_PRIORITY,
        attempt: 0,
        max_attempts: MAX_ATTEMPTS,
        created_at: now,
        scheduled_at: now,
        idempotency_key: Some(owner_idempotency_key(&owner, &envelope.idempotency_key)),
        owner_sub: Some(owner.clone()),
        headers: BTreeMap::new(),
    };

    let id = queue.enqueue(job).await.map_err(queue_error)?;
    // A duplicate key returns the id of the stored job, so read it back.
    let stored = queue.get(id).await.map_err(queue_error)?;
    // The queue keys are owner-scoped above. This check is defensive: a
    // backend that returns another owner's id must not answer with that job.
    if stored.owner_sub.as_deref() != Some(owner.as_str()) {
        return Err(ApiError::Conflict);
    }
    let status = queue.status(id).await.map_err(queue_error)?;
    let view = status_view(&stored, &status).map_err(|error| ApiError::Internal(Box::new(error)))?;

    Ok(HttpResponse::Accepted().json(view))
}

/// Returns the status of one job.
///
/// The route answers 501 until the status feature lands. The finished route
/// returns `200` with a [`JobStatusView`](rust_api_model::wire::JobStatusView)
/// and `404` for an absent or invisible job.
#[utoipa::path(
    get,
    path = "/jobs/{id}",
    tag = "jobs",
    params(("id" = String, Path, description = "job identifier")),
    responses(
        (status = 501, description = "not implemented", body = crate::http::error::ErrorBody)
    )
)]
#[get("/{id}")]
pub async fn get_job(_id: web::Path<String>) -> HttpResponse {
    not_implemented("job status polling")
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{App, http::StatusCode, test as actix_test};
    use jsonwebtoken::EncodingKey;
    use serde_json::{Value, json};

    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::http::ApiModule as _;
    use crate::http::middleware::jwt::JwtClaimsMiddleware;
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::jobs::JobsApiModule;
    use crate::policy::PolicyEngine;
    use crate::queue::MemoryQueue;

    const KID: &str = "jobs-poll-test-kid";
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
            ))
        }
    }

    async fn fixture() -> anyhow::Result<Fixture> {
        let (key, encoding_key) = rsa_key(KID)?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;
        let engine =
            PolicyEngine::init_s3(build_test_store(&test_prefix("jobs-poll-policy")).await).await?;
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
            let view: Value = actix_test::read_body_json(response).await;
            view
        }};
    }

    #[actix_web::test]
    async fn the_module_claims_the_jobs_prefix() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        assert_eq!(fixture.module().await?.prefix(), "/jobs");
        Ok(())
    }

    #[actix_web::test]
    async fn the_owner_enqueues_the_job() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fixture.token("alice")?;

        let created = post_command!(app, token, "key-1");
        assert_eq!(created["kind"], "entity.create");
        assert_eq!(created["state"], "queued");
        assert_eq!(created["attempt"], 0);
        assert_eq!(created["max_attempts"], 5);
        let id = created["id"].as_str().expect("the view has an id").to_string();

        let stored = fixture.queue.get(Uuid::parse_str(&id)?).await?;
        assert_eq!(stored.owner_sub.as_deref(), Some("alice"));
        assert_eq!(stored.kind, "entity.create");
        assert_eq!(stored.priority, 0);
        assert_eq!(stored.max_attempts, 5);
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
    async fn an_anonymous_command_is_401() -> anyhow::Result<()> {
        let fixture = fixture().await?;
        let module = fixture.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let request = actix_test::TestRequest::post()
            .uri("/jobs")
            .insert_header(("Content-Type", "application/json"))
            .set_payload(command_body("key-1"))
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }
}
