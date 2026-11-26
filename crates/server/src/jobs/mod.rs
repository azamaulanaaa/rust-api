//! Job submission and status routes.
//!
//! This module owns the `/jobs` prefix. The poll route and the server-sent
//! event route live in the `poll` and `sse` submodules. The foundation
//! registers the prefix one time, so a feature branch changes only its
//! handler module.
//!
//! Polling is the guaranteed fallback. The SSE route is an optimization.
//! The poll route is live. The SSE route answers 501 until its feature
//! branch lands.

use std::collections::BTreeSet;
use std::sync::Arc;

use actix_web::{
    HttpResponse,
    http::StatusCode,
    web::{self, ServiceConfig},
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rust_api_model::{CommandKind, CommandKindError, JobState, JobStatusView, wire::CommitReceipt};

use crate::http::{
    ApiModule,
    error::ApiError,
    middleware::{
        jwt::{Claims, JwtClaimsMiddleware},
        no_cache::NoCache,
    },
};
use crate::policy::Authorizer;
use crate::queue::{Job, JobHandler, JobQueue, JobStatus};

/// The poll routes for job submission and one job status.
pub mod poll;

/// The server-sent event route for one job status.
pub mod sse;

/// The set of job kinds that have a registered handler.
///
/// The type is cheap to clone, because the set sits behind an [`Arc`]. Use
/// [`WorkerKinds`] for a worker handler set and [`SubmittableKinds`] for a
/// client-submittable set.
#[derive(Clone, Debug)]
struct JobKinds {
    kinds: Arc<BTreeSet<CommandKind>>,
}

impl JobKinds {
    /// Builds an empty set.
    pub fn empty() -> Self {
        Self {
            kinds: Arc::new(BTreeSet::new()),
        }
    }

    /// Builds the set from a handler list.
    ///
    /// The function reads [`JobHandler::kind`] from each handler. A caller
    /// must not keep a second worker kind list.
    ///
    /// # Errors
    ///
    /// Returns [`JobKindsError`] when a handler kind is invalid or two
    /// handlers declare the same kind.
    pub fn from_handlers(handlers: &[Arc<dyn JobHandler>]) -> Result<Self, JobKindsError> {
        Self::from_names(handlers.iter().map(|handler| handler.kind()))
    }

    /// Builds the set from explicit kind names.
    ///
    /// # Errors
    ///
    /// Returns [`JobKindsError::Invalid`] when a name is not a valid command
    /// kind. Returns [`JobKindsError::Duplicate`] when a name appears more
    /// than one time.
    pub fn from_names<I, S>(names: I) -> Result<Self, JobKindsError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut kinds = BTreeSet::new();
        for name in names {
            let name = name.as_ref();
            let kind = CommandKind::parse(name).map_err(|source| JobKindsError::Invalid {
                kind: name.to_string(),
                source,
            })?;
            if !kinds.insert(kind.clone()) {
                return Err(JobKindsError::Duplicate { kind });
            }
        }
        Ok(Self {
            kinds: Arc::new(kinds),
        })
    }

    /// Returns `true` when the set holds `kind`.
    pub fn contains(&self, kind: &CommandKind) -> bool {
        self.kinds.contains(kind)
    }

    /// Returns `true` when the set holds no kind.
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// Checks that every kind in this set has a worker handler.
    ///
    /// # Errors
    ///
    /// Returns [`JobKindsError::Unhandled`] for the first kind that no
    /// handler in `workers` declares.
    pub fn ensure_subset_of(&self, workers: &JobKinds) -> Result<(), JobKindsError> {
        if let Some(kind) = self.kinds.difference(&workers.kinds).next() {
            return Err(JobKindsError::Unhandled { kind: kind.clone() });
        }
        Ok(())
    }
}

/// The set of job kinds that a worker handler declares.
///
/// A [`WorkerKinds`] value cannot be passed where a [`SubmittableKinds`] is
/// required. The distinct types keep the worker capability and the client
/// capability apart at compile time.
#[derive(Clone, Debug)]
pub struct WorkerKinds(JobKinds);

impl WorkerKinds {
    /// Builds the set from a handler list.
    ///
    /// # Errors
    ///
    /// Returns [`JobKindsError`] when a handler kind is invalid or two
    /// handlers declare the same kind.
    pub fn from_handlers(handlers: &[Arc<dyn JobHandler>]) -> Result<Self, JobKindsError> {
        JobKinds::from_handlers(handlers).map(Self)
    }

    /// Returns `true` when the set holds `kind`.
    pub fn contains(&self, kind: &CommandKind) -> bool {
        self.0.contains(kind)
    }
}

/// The set of job kinds that a client may submit.
///
/// A [`SubmittableKinds`] value cannot be passed where a [`WorkerKinds`] is
/// required. Use [`SubmittableKinds::ensure_subset_of`] to prove that each
/// kind has a worker handler.
#[derive(Clone, Debug)]
pub struct SubmittableKinds(JobKinds);

impl SubmittableKinds {
    /// Builds an empty set.
    pub fn empty() -> Self {
        Self(JobKinds::empty())
    }

    /// Builds the set from explicit kind names.
    ///
    /// # Errors
    ///
    /// Returns [`JobKindsError::Invalid`] when a name is not a valid command
    /// kind. Returns [`JobKindsError::Duplicate`] when a name appears more
    /// than one time.
    pub fn from_names<I, S>(names: I) -> Result<Self, JobKindsError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        JobKinds::from_names(names).map(Self)
    }

    /// Checks that every kind in this set has a worker handler.
    ///
    /// # Errors
    ///
    /// Returns [`JobKindsError::Unhandled`] for the first kind that no
    /// handler in `workers` declares.
    pub fn ensure_subset_of(&self, workers: &WorkerKinds) -> Result<(), JobKindsError> {
        self.0.ensure_subset_of(&workers.0)
    }

    /// Returns `true` when the set holds `kind`.
    pub fn contains(&self, kind: &CommandKind) -> bool {
        self.0.contains(kind)
    }

    /// Returns `true` when the set holds no kind.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A handler kind is invalid, or more than one handler declares it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JobKindsError {
    /// A handler declares a kind outside the command kind allowlist.
    #[error("a job handler declares an invalid kind: {kind}")]
    Invalid {
        /// The kind that the handler declares.
        kind: String,
        /// The parser failure.
        #[source]
        source: CommandKindError,
    },
    /// More than one handler declares the same kind.
    #[error("two job handlers declare the same kind: {kind}")]
    Duplicate {
        /// The kind that more than one handler declares.
        kind: CommandKind,
    },
    /// A client-submittable kind has no worker handler.
    #[error("a client-submittable kind has no worker handler: {kind}")]
    Unhandled {
        /// The kind that no worker handler declares.
        kind: CommandKind,
    },
}

/// The module that owns the `/jobs` route prefix.
pub struct JobsApiModule {
    queue: Arc<dyn JobQueue>,
    policy: Authorizer,
    jwt: JwtClaimsMiddleware<Claims>,
    submittable: SubmittableKinds,
}

impl JobsApiModule {
    /// Creates the module from a queue, JWT middleware, authorizer, and the
    /// client-submittable kind registry.
    ///
    /// Share the authorizer with the policy engine, so the module sees the
    /// same policy state as every other module. The submittable set is
    /// separate from the worker handler set, so a worker-only kind stays
    /// private. The constructor takes [`SubmittableKinds`], so a
    /// [`WorkerKinds`] value cannot be passed here.
    pub fn new(
        queue: Arc<dyn JobQueue>,
        jwt: JwtClaimsMiddleware<Claims>,
        policy: Authorizer,
        submittable: SubmittableKinds,
    ) -> Self {
        Self {
            queue,
            jwt,
            policy,
            submittable,
        }
    }
}

impl ApiModule for JobsApiModule {
    fn prefix(&self) -> &str {
        "/jobs"
    }

    fn configure(&self, cfg: &mut ServiceConfig) {
        let queue = web::Data::new(self.queue.clone());
        let policy = web::Data::new(self.policy.clone());
        let submittable = web::Data::new(self.submittable.clone());
        let jwt = self.jwt.clone();
        cfg.service(
            web::scope("/jobs")
                .app_data(queue)
                .app_data(policy)
                .app_data(submittable)
                .wrap(jwt)
                .wrap(NoCache)
                .route("", web::post().to(poll::create_job))
                .service(poll::get_job)
                .service(sse::job_events),
        );
    }
}

/// Builds the not-implemented answer for one route.
///
/// The answer uses the shared error envelope and a message that names the
/// missing behavior. A caller therefore learns that the route exists and
/// that the server has no implementation yet.
pub(crate) fn not_implemented(route: &str) -> HttpResponse {
    ApiError::envelope(
        StatusCode::NOT_IMPLEMENTED,
        &format!("{route} is not implemented"),
        Some("not_implemented"),
        None,
    )
}

/// Builds the API view of one stored job status.
///
/// The function maps the stored status to [`JobStatusView`]. The stored
/// status never goes on the wire. A handler that advances the change feed
/// returns a [`CommitReceipt`] as JSON in its result bytes. The function
/// maps those bytes to `commit_seq` and does not repeat them in
/// `result_base64`. Other result bytes go in `result_base64` and leave
/// `commit_seq` empty.
///
/// The function returns [`CommandKindError`] when the stored kind is not a
/// valid command kind.
pub(crate) fn status_view(
    job: &Job,
    status: &JobStatus,
) -> Result<JobStatusView, CommandKindError> {
    let kind = CommandKind::parse(job.kind.clone())?;
    let mut view = JobStatusView {
        id: job.id,
        kind,
        state: JobState::Queued,
        attempt: job.attempt,
        max_attempts: job.max_attempts,
        created_at: job.created_at,
        scheduled_at: job.scheduled_at,
        lease_expires_at_ms: None,
        finished_at: None,
        worker: None,
        error: None,
        result_base64: None,
        commit_seq: None,
    };

    match status {
        JobStatus::Queued => {}
        JobStatus::Leased { worker, expires_at } => {
            view.state = JobState::Leased;
            view.worker = Some(worker.clone());
            view.lease_expires_at_ms = Some(*expires_at);
        }
        JobStatus::Succeeded {
            result,
            finished_at,
        } => {
            view.state = JobState::Succeeded;
            view.finished_at = Some(*finished_at);
            if let Some(bytes) = result {
                match serde_json::from_slice::<CommitReceipt>(bytes) {
                    Ok(receipt) => view.commit_seq = Some(receipt.commit_seq),
                    Err(_) => view.result_base64 = Some(STANDARD.encode(bytes)),
                }
            }
        }
        JobStatus::Failed { error, finished_at } => {
            view.state = JobState::Failed;
            view.finished_at = Some(*finished_at);
            view.error = Some(error.clone());
        }
        JobStatus::Dead { error, finished_at } => {
            view.state = JobState::Dead;
            view.finished_at = Some(*finished_at);
            view.error = Some(error.clone());
        }
    }

    Ok(view)
}

/// Hides the owner-only fields of a job view from a non-owner.
///
/// The function clears `result_base64` and `error` when `is_owner` is false.
/// The rest of the view stays. Call this after the access check and before
/// the response.
pub(crate) fn redact_non_owner(view: &mut JobStatusView, is_owner: bool) {
    if !is_owner {
        view.result_base64 = None;
        view.error = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    /// Builds one stored job for the status view tests.
    fn sample_job() -> Job {
        Job {
            id: Uuid::nil(),
            kind: "entity.create".to_string(),
            payload: b"input".to_vec(),
            priority: 0,
            attempt: 2,
            max_attempts: 5,
            created_at: 1_700_000_000,
            scheduled_at: 1_700_000_010,
            idempotency_key: Some("key-1".to_string()),
            owner_sub: None,
            headers: BTreeMap::new(),
        }
    }

    /// A stored job from before the owner field decodes without an owner.
    #[test]
    fn a_stored_job_without_the_owner_decodes_with_no_owner() {
        let mut value = serde_json::to_value(sample_job()).expect("the job serializes");
        let object = value.as_object_mut().expect("the job is an object");
        assert!(object.remove("owner_sub").is_some());
        let job: Job = serde_json::from_value(value).expect("the stored job parses");
        assert_eq!(job.owner_sub, None);
    }

    /// A handler with one kind, for the registry test.
    struct KindHandler(&'static str);

    #[async_trait::async_trait]
    impl JobHandler for KindHandler {
        fn kind(&self) -> &'static str {
            self.0
        }

        async fn handle(&self, _job: &Job) -> Result<Option<Vec<u8>>, crate::queue::JobError> {
            Ok(None)
        }
    }

    /// The worker set holds every kind of the handler list and no other kind.
    #[test]
    fn the_worker_kinds_keep_every_handler_kind() {
        let handlers: Vec<Arc<dyn JobHandler>> = vec![
            Arc::new(KindHandler("entity.create")),
            Arc::new(KindHandler("entity.delete")),
        ];
        let kinds = WorkerKinds::from_handlers(&handlers).expect("the handler kinds are unique");

        for handler in &handlers {
            let kind = CommandKind::parse(handler.kind()).expect("the handler kind is valid");
            assert!(
                kinds.contains(&kind),
                "the worker set is missing {}",
                handler.kind()
            );
        }
        let unregistered = CommandKind::parse("entity.update").expect("the test kind is valid");
        assert!(!kinds.contains(&unregistered));
    }

    /// The worker set rejects two handlers with the same kind.
    #[test]
    fn the_worker_kinds_reject_a_duplicate_kind() {
        let handlers: Vec<Arc<dyn JobHandler>> = vec![
            Arc::new(KindHandler("entity.create")),
            Arc::new(KindHandler("entity.create")),
        ];
        let error = WorkerKinds::from_handlers(&handlers).expect_err("the duplicate must fail");

        assert!(matches!(
            &error,
            JobKindsError::Duplicate { kind } if kind.as_str() == "entity.create"
        ));
        assert_eq!(
            error.to_string(),
            "two job handlers declare the same kind: entity.create"
        );
    }

    /// The worker set rejects a handler kind outside the allowlist.
    #[test]
    fn the_worker_kinds_reject_an_invalid_handler_kind() {
        let handlers: Vec<Arc<dyn JobHandler>> = vec![Arc::new(KindHandler("Webhook.Deliver"))];
        let error = WorkerKinds::from_handlers(&handlers).expect_err("the invalid kind must fail");

        assert!(matches!(error, JobKindsError::Invalid { .. }));
    }

    /// A submittable kind must have a worker handler.
    ///
    /// [`WorkerKinds`] and [`SubmittableKinds`] are different types, so a
    /// worker set does not compile where a submittable set is required.
    #[test]
    fn the_submittable_set_must_be_a_worker_subset() {
        let handlers: Vec<Arc<dyn JobHandler>> = vec![Arc::new(KindHandler("entity.create"))];
        let workers = WorkerKinds::from_handlers(&handlers).expect("the worker kinds are valid");
        let handled =
            SubmittableKinds::from_names(["entity.create"]).expect("the submittable kind is valid");

        assert!(handled.ensure_subset_of(&workers).is_ok());
        assert!(SubmittableKinds::empty().ensure_subset_of(&workers).is_ok());

        let missing =
            SubmittableKinds::from_names(["entity.delete"]).expect("the submittable kind is valid");
        let error = missing
            .ensure_subset_of(&workers)
            .expect_err("the missing handler must fail");
        assert!(matches!(
            error,
            JobKindsError::Unhandled { kind } if kind.as_str() == "entity.delete"
        ));
    }

    /// `status_view` maps the queued and leased states and their fields.
    #[test]
    fn status_view_maps_the_queued_and_leased_states() {
        let job = sample_job();

        let queued = status_view(&job, &JobStatus::Queued).expect("the queued status maps");
        assert_eq!(queued.id, job.id);
        assert_eq!(queued.kind.as_str(), "entity.create");
        assert_eq!(queued.state, JobState::Queued);
        assert_eq!(queued.attempt, job.attempt);
        assert_eq!(queued.max_attempts, job.max_attempts);
        assert_eq!(queued.created_at, job.created_at);
        assert_eq!(queued.scheduled_at, job.scheduled_at);
        assert_eq!(queued.lease_expires_at_ms, None);
        assert_eq!(queued.finished_at, None);
        assert_eq!(queued.worker, None);
        assert_eq!(queued.error, None);
        assert_eq!(queued.result_base64, None);
        assert_eq!(queued.commit_seq, None);

        let leased = status_view(
            &job,
            &JobStatus::Leased {
                worker: "worker-7".to_string(),
                expires_at: 1_700_000_000_123,
            },
        )
        .expect("the leased status maps");
        assert_eq!(leased.state, JobState::Leased);
        assert_eq!(leased.worker.as_deref(), Some("worker-7"));
        assert_eq!(leased.lease_expires_at_ms, Some(1_700_000_000_123));
        assert_eq!(leased.finished_at, None);
        assert_eq!(leased.commit_seq, None);
    }

    /// `status_view` maps the terminal states and encodes the result bytes.
    #[test]
    fn status_view_maps_the_terminal_states() {
        let job = sample_job();

        let succeeded = status_view(
            &job,
            &JobStatus::Succeeded {
                result: Some(b"done".to_vec()),
                finished_at: 1_700_000_020,
            },
        )
        .expect("the succeeded status maps");
        assert_eq!(succeeded.state, JobState::Succeeded);
        assert_eq!(succeeded.finished_at, Some(1_700_000_020));
        assert_eq!(succeeded.result_base64.as_deref(), Some("ZG9uZQ=="));
        assert_eq!(succeeded.error, None);
        assert_eq!(succeeded.commit_seq, None);

        let empty = status_view(
            &job,
            &JobStatus::Succeeded {
                result: None,
                finished_at: 1_700_000_021,
            },
        )
        .expect("the empty succeeded status maps");
        assert_eq!(empty.result_base64, None);
        assert_eq!(empty.commit_seq, None);

        for (status, state, error, finished_at) in [
            (
                JobStatus::Failed {
                    error: "the handler failed".to_string(),
                    finished_at: 1_700_000_030,
                },
                JobState::Failed,
                "the handler failed",
                1_700_000_030,
            ),
            (
                JobStatus::Dead {
                    error: "the attempts ran out".to_string(),
                    finished_at: 1_700_000_040,
                },
                JobState::Dead,
                "the attempts ran out",
                1_700_000_040,
            ),
        ] {
            let view = status_view(&job, &status).expect("the terminal status maps");
            assert_eq!(view.state, state);
            assert_eq!(view.error.as_deref(), Some(error));
            assert_eq!(view.finished_at, Some(finished_at));
            assert_eq!(view.worker, None);
            assert_eq!(view.result_base64, None);
            assert_eq!(view.commit_seq, None);
        }
    }

    /// A succeeded job reads `commit_seq` from a receipt result and omits the bytes.
    #[test]
    fn status_view_reads_the_commit_receipt() {
        let job = sample_job();
        let result =
            serde_json::to_vec(&CommitReceipt { commit_seq: 42 }).expect("receipt serializes");

        let view = status_view(
            &job,
            &JobStatus::Succeeded {
                result: Some(result),
                finished_at: 1_700_000_020,
            },
        )
        .expect("the succeeded status maps");

        assert_eq!(view.state, JobState::Succeeded);
        assert_eq!(view.commit_seq, Some(42));
        assert_eq!(view.result_base64, None);
    }

    /// A receipt with an unknown field stays in the result bytes.
    #[test]
    fn status_view_keeps_a_receipt_with_unknown_fields_as_result_bytes() {
        let job = sample_job();
        let result = br#"{"commit_seq": 9, "detail": "x"}"#.to_vec();

        let view = status_view(
            &job,
            &JobStatus::Succeeded {
                result: Some(result.clone()),
                finished_at: 1_700_000_020,
            },
        )
        .expect("the succeeded status maps");

        assert_eq!(view.commit_seq, None);
        assert_eq!(view.result_base64, Some(STANDARD.encode(result)));
    }
}
