//! Per-user entity change feed for clients.
//!
//! The feed reports the entity events in the shared change log.
//! A client caches the events and replays them.
//! The feed is not a materialized replica.
//! It adds no business logic.
//!
//! `GET /eav/sync/status` reports the current feed head.
//! It carries an `ETag`, so a repeat poll can return `304`.
//! `GET /eav/sync/events` returns the entity events after a cursor.
//! Each event carries its snapshot, so the client needs no extra read.
//! `GET /eav/sync/snapshot` returns one page of entity state for the first
//! load of an offline client.
//! The client then reads the events feed for each change.
//!
//! `POST /eav/sync/replica` stores a JSON snapshot for the caller.
//! `GET /eav/sync/replica` returns the stored snapshot.
//! `GET /eav/sync/replica/status` reports the log head and the stored head.
//! The client applies the events after the stored head.
//! The replica is a point-in-time snapshot, not an incremental store.
//!
//! The events route checks one collection grant.
//! Without the collection grant, it checks a row grant for each event.
//! A caller sees only the events that it can read.

use actix_web::{
    HttpRequest, HttpResponse, get,
    http::header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH},
    post, web,
};
use serde::Serialize;

use crate::eav::entity::Entity;
use crate::eav::entity_error::EntityError;
use crate::eav::route::{
    ENTITIES, ENTITY_ROW, EavApiError, PageQuery, can_read_entity, page_next_offset,
};
use crate::eav::runtime::EavRuntime;
use crate::fs::error::FsError;
use crate::http::middleware::jwt::{Claims, Validated};
use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, Authorizer};
use crate::records::{EntityEvent, WalEntry, WalOp};

/// The default number of events in one page.
const DEFAULT_LIMIT: usize = 100;
/// The largest number of events in one page.
const MAX_LIMIT: usize = 500;
/// The number of entities that a replica build reads in one page.
const REPLICA_PAGE: usize = 500;
/// The number of replica builds before a stale head is final.
const REPLICA_BUILD_ATTEMPTS: u32 = 2;

/// The current head of the entity change feed.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SyncStatusResponse {
    /// The sequence number of the last entry in the change log.
    pub head: u64,
}

/// One entity event with its position in the change log.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SyncEvent {
    /// The sequence number of the entry in the change log.
    pub seq: u64,
    /// The entity change.
    pub event: EntityEvent,
}

/// One page of the entity change feed.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SyncEventsResponse {
    /// The visible entity events in log order.
    pub events: Vec<SyncEvent>,
    /// The cursor for the next call.
    ///
    /// The value is the sequence of the last event when the page is full.
    /// Otherwise it is the current head.
    pub next: u64,
    /// The head of the change log at the time of the call.
    pub head: u64,
}

/// One page of entity state for the first load of an offline client.
///
/// The route filters the raw page with the grants of the caller.
/// A filtered page can then hold fewer items than the limit.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SnapshotPage {
    /// The entities on this page that the caller can read.
    pub items: Vec<Entity>,
    /// `Some` means the raw page was full and a following page may exist.
    ///
    /// The value comes from the raw page length, not from `items`.
    /// A filtered page can then hold fewer items than the limit.
    /// Continue while `next_offset` is `Some`.
    pub next_offset: Option<usize>,
    /// The head of the change log at the time of the call.
    ///
    /// The client passes this value as `since` to the events feed.
    pub head: u64,
}

/// The result of a replica build.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ReplicaBuildResponse {
    /// The change-log head at the time of the build.
    pub head: u64,
    /// The number of visible entities in the replica.
    pub count: usize,
}

/// The current change-log head and the stored replica head.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ReplicaStatusResponse {
    /// The current head of the change log.
    pub head: u64,
    /// The head of the stored replica, or `None` when no replica exists.
    pub built_head: Option<u64>,
}

/// The query of the events route.
#[derive(Debug, Clone, Copy, serde::Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
pub struct SyncEventsQuery {
    /// The last sequence that the client applied. The default is 0.
    #[serde(default)]
    pub since: Option<u64>,
    /// The largest number of events in the page. The default is 100.
    /// The maximum is 500.
    #[serde(default)]
    pub limit: Option<usize>,
}

impl SyncEventsQuery {
    /// Resolves the cursor and the page size.
    fn resolve(self) -> Result<(u64, usize), EavApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_LIMIT);
        if limit == 0 || limit > MAX_LIMIT {
            return Err(EavApiError::Invalid(Box::new(InvalidLimit)));
        }
        Ok((self.since.unwrap_or(0), limit))
    }
}

/// The source of a page size outside the allowed range.
#[derive(Debug)]
struct InvalidLimit;

impl std::fmt::Display for InvalidLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("limit must be between 1 and 500")
    }
}

impl std::error::Error for InvalidLimit {}

/// The source of a cursor that is ahead of the feed head.
#[derive(Debug)]
struct CursorAhead;

impl std::fmt::Display for CursorAhead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("since is ahead of the feed head")
    }
}

impl std::error::Error for CursorAhead {}

/// Converts a change-log failure to a sanitized server error.
fn internal(error: FsError) -> EavApiError {
    EavApiError::Internal(Box::new(error))
}

/// Returns the quoted `ETag` for one head value.
fn status_etag(head: u64) -> String {
    format!("\"{head}\"")
}

/// Returns true when `If-None-Match` matches the current tag.
///
/// The check accepts the weak form and a comma-separated list.
fn etag_matches(header: &str, etag: &str) -> bool {
    if header.trim() == "*" {
        return true;
    }
    let want = normalize_etag(etag);
    header.split(',').any(|tag| normalize_etag(tag) == want)
}

/// Removes the weak prefix and the quotes from one tag.
fn normalize_etag(tag: &str) -> &str {
    let tag = tag.trim();
    let tag = tag.strip_prefix("W/").unwrap_or(tag).trim();
    tag.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(tag)
}

/// Returns the current head of the entity change feed.
///
/// The caller needs a valid session.
/// The route needs no Casbin permission.
/// A matching `If-None-Match` returns `304` with no body.
#[utoipa::path(get, path = "/eav/sync/status", tag = "eav", responses((status = 200, body = SyncStatusResponse), (status = 304, description = "not modified"), (status = 401, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[get("/sync/status")]
pub(crate) async fn status(
    runtime: web::Data<EavRuntime>,
    _claims: Validated<Claims>,
    req: HttpRequest,
) -> Result<HttpResponse, EavApiError> {
    let head = runtime.wal().head().await.map_err(internal)?;
    let etag = status_etag(head);
    if let Some(header) = req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        && etag_matches(header, &etag)
    {
        return Ok(HttpResponse::NotModified()
            .insert_header((ETAG, etag))
            .finish());
    }
    Ok(HttpResponse::Ok()
        .insert_header((ETAG, etag))
        .json(SyncStatusResponse { head }))
}

/// Returns one page of entity events after the cursor.
///
/// The route reads the current head first.
/// A cursor ahead of the head returns `409`.
/// A cursor at the head returns an empty page.
/// The route checks the collection grant once.
/// Without that grant, it checks each event row.
/// The route ignores file and policy entries.
/// A full page returns the last included sequence as `next`.
/// A page that is not full returns the head as `next`.
/// This route does not use `ETag`.
#[utoipa::path(get, path = "/eav/sync/events", tag = "eav", params(SyncEventsQuery), responses((status = 200, body = SyncEventsResponse), (status = 400, body = crate::http::error::ErrorBody), (status = 401, body = crate::http::error::ErrorBody), (status = 409, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[get("/sync/events")]
pub(crate) async fn events(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    query: web::Query<SyncEventsQuery>,
) -> Result<HttpResponse, EavApiError> {
    let (since, limit) = query.into_inner().resolve()?;
    let head = runtime.wal().head().await.map_err(internal)?;
    if since > head {
        return Err(EavApiError::Conflict(Box::new(CursorAhead)));
    }
    if since == head {
        return Ok(HttpResponse::Ok().json(SyncEventsResponse {
            events: Vec::new(),
            next: head,
            head,
        }));
    }

    let entries = runtime
        .wal()
        .range(since + 1, head)
        .await
        .map_err(internal)?;
    let collection = policy
        .authorize(&claims.sub, ENTITIES, Action::Read)
        .await
        .map_err(EavApiError::from)?;

    let mut events = Vec::new();
    for entry in entries {
        if events.len() == limit {
            break;
        }
        let WalEntry { seq, op, .. } = entry;
        let WalOp::Entity { event } = op else {
            continue;
        };
        let visible = if collection {
            true
        } else {
            policy
                .authorize_row(&claims.sub, ENTITY_ROW, &event.entity_id, Action::Read)
                .await
                .map_err(EavApiError::from)?
        };
        if visible {
            events.push(SyncEvent { seq, event });
        }
    }

    let next = match events.last() {
        Some(last) if events.len() == limit => last.seq,
        _ => head,
    };
    Ok(HttpResponse::Ok().json(SyncEventsResponse { events, next, head }))
}

/// Returns one page of entity state.
///
/// The caller needs a valid session.
/// The route needs no collection Casbin permission.
/// A collection read exposes every entity.
/// A row grant exposes only that entity.
/// The route reads a raw page and filters each row.
/// `next_offset` comes from the raw page length.
/// A filtered page can then hold fewer items than the limit.
/// A matching `If-None-Match` returns `304` with no body.
#[utoipa::path(get, path = "/eav/sync/snapshot", tag = "eav", params(PageQuery), responses((status = 200, body = SnapshotPage), (status = 304, description = "not modified"), (status = 400, body = crate::http::error::ErrorBody), (status = 401, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[get("/sync/snapshot")]
pub(crate) async fn snapshot(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    query: web::Query<PageQuery>,
    req: HttpRequest,
) -> Result<HttpResponse, EavApiError> {
    let (limit, offset) = query.into_inner().resolve()?;
    let head = runtime.wal().head().await.map_err(internal)?;
    let etag = status_etag(head);
    if let Some(header) = req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        && etag_matches(header, &etag)
    {
        return Ok(HttpResponse::NotModified()
            .insert_header((ETAG, etag))
            .finish());
    }

    let raw = runtime.entities().list_page(limit, offset).await?;
    let raw_len = raw.len();
    let mut items = Vec::with_capacity(raw_len);
    for entity in raw {
        if can_read_entity(&policy, &claims.sub, &entity.id).await? {
            items.push(entity);
        }
    }
    let next_offset = page_next_offset(offset, raw_len, limit);
    Ok(HttpResponse::Ok()
        .insert_header((ETAG, etag))
        .json(SnapshotPage {
            items,
            next_offset,
            head,
        }))
}

/// The source of a missing replica.
#[derive(Debug)]
struct MissingReplica;

impl std::fmt::Display for MissingReplica {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("replica does not exist")
    }
}

impl std::error::Error for MissingReplica {}

/// Builds a stored replica for the caller.
///
/// The caller needs a valid session.
/// The route reads the current change-log head first.
/// It then reads every entity in pages of 500.
/// It keeps only the entities that the caller can read.
/// The build replaces the previous replica for the same subject.
/// The client applies the events after the returned `head`.
/// A newer build can commit first.
/// The route then reads a fresh feed head and builds one more time.
/// A second stale result returns `409`.
#[utoipa::path(post, path = "/eav/sync/replica", tag = "eav", responses((status = 200, body = ReplicaBuildResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 409, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[post("/sync/replica")]
pub(crate) async fn build_replica(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
) -> Result<HttpResponse, EavApiError> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let head = runtime.wal().head().await.map_err(internal)?;
        let mut items = Vec::new();
        let mut offset = 0;
        loop {
            let page = runtime.entities().list_page(REPLICA_PAGE, offset).await?;
            let len = page.len();
            for entity in page {
                if can_read_entity(&policy, &claims.sub, &entity.id).await? {
                    items.push(entity);
                }
            }
            if len < REPLICA_PAGE {
                break;
            }
            offset = offset.saturating_add(len);
        }
        let data = serde_json::to_vec(&items).map_err(|e| EavApiError::Internal(Box::new(e)))?;
        let count = items.len();
        match runtime.replicas().put(&claims.sub, head, data).await {
            Ok(()) => return Ok(HttpResponse::Ok().json(ReplicaBuildResponse { head, count })),
            Err(EntityError::StaleHead { .. }) if attempt < REPLICA_BUILD_ATTEMPTS => continue,
            Err(error) => return Err(EavApiError::from(error)),
        }
    }
}

/// Returns the stored replica of the caller.
///
/// The caller needs a valid session.
/// A missing replica returns `404`.
/// The route sets `ETag` and `X-Replica-Head` to the stored head.
/// A match on `If-None-Match` returns `304` with no body.
/// The client applies the events after the stored head.
#[utoipa::path(get, path = "/eav/sync/replica", tag = "eav", responses((status = 200, body = Vec<Entity>, content_type = "application/json"), (status = 304, description = "not modified"), (status = 401, body = crate::http::error::ErrorBody), (status = 404, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[get("/sync/replica")]
pub(crate) async fn replica(
    runtime: web::Data<EavRuntime>,
    claims: Validated<Claims>,
    req: HttpRequest,
) -> Result<HttpResponse, EavApiError> {
    let Some((head, data)) = runtime.replicas().get(&claims.sub).await? else {
        return Err(EavApiError::NotFound(Box::new(MissingReplica)));
    };
    let etag = status_etag(head);
    if let Some(header) = req
        .headers()
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        && etag_matches(header, &etag)
    {
        return Ok(HttpResponse::NotModified()
            .insert_header((ETAG, etag))
            .finish());
    }
    Ok(HttpResponse::Ok()
        .insert_header((ETAG, etag))
        .insert_header(("X-Replica-Head", head.to_string()))
        .insert_header((CONTENT_TYPE, "application/json"))
        .body(data))
}

/// Returns the change-log head and the stored replica head.
///
/// The caller needs a valid session.
/// The route sets no `ETag`.
/// The client applies the events after `built_head`.
/// A `built_head` of `None` means that no replica exists.
#[utoipa::path(get, path = "/eav/sync/replica/status", tag = "eav", responses((status = 200, body = ReplicaStatusResponse), (status = 401, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[get("/sync/replica/status")]
pub(crate) async fn replica_status(
    runtime: web::Data<EavRuntime>,
    claims: Validated<Claims>,
) -> Result<HttpResponse, EavApiError> {
    let head = runtime.wal().head().await.map_err(internal)?;
    let built_head = runtime.replicas().status(&claims.sub).await?;
    Ok(HttpResponse::Ok().json(ReplicaStatusResponse { head, built_head }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{App, http, test as actix_test};
    use jsonwebtoken::EncodingKey;
    use serde_json::{Value, json};
    use utoipa::OpenApi as _;

    use super::*;
    use crate::db::{build_s3_store, build_test_store, test_prefix};
    use crate::docs::ApiDoc;
    use crate::eav::entity::{AttributeValue, EntityDraft};
    use crate::eav::route::EavApiModule;
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft};
    use crate::fs::s3::{S3Backend, S3ClientConfig};
    use crate::http::ApiModule;
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::policy::PolicyEngine;
    use crate::records::{ChangeSink, EntityEventKind};
    use crate::rules::action::{ActionContext, RuleAction};
    use crate::sync::wal::Wal;

    const KID: &str = "eav-sync-test-kid";
    const AUD: &str = "test-aud";

    /// A no-op action for the runtime.
    struct NoopAction;

    #[async_trait::async_trait]
    impl RuleAction for NoopAction {
        fn kind(&self) -> &str {
            "record"
        }

        async fn execute(&self, _ctx: ActionContext) -> Result<(), anyhow::Error> {
            Ok(())
        }
    }

    struct Fixture {
        server: wiremock::MockServer,
        encoding_key: EncodingKey,
        runtime: EavRuntime,
        engine: PolicyEngine,
    }

    impl Fixture {
        fn issuer(&self) -> String {
            self.server.uri()
        }

        fn token(&self, sub: &str) -> anyhow::Result<String> {
            sign_rs256(
                &json!({
                    "sub": sub,
                    "iss": self.issuer(),
                    "aud": AUD,
                    "exp": 2000000000u64,
                }),
                KID,
                &self.encoding_key,
            )
        }

        async fn module(&self) -> anyhow::Result<EavApiModule> {
            let middleware =
                crate::http::middleware::jwt::JwtClaimsMiddleware::<Claims>::new_with_jks(
                    &format!("{}/jwks", self.server.uri()),
                    AUD,
                    &self.issuer(),
                )
                .await?;
            Ok(EavApiModule::new(
                self.runtime.clone(),
                self.engine.authorizer(),
                middleware,
            ))
        }
    }

    async fn fixture() -> anyhow::Result<Fixture> {
        let (key, encoding_key) = rsa_key(KID)?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;
        let s3 = S3ClientConfig {
            bucket: "eav-sync-test".to_string(),
            region: "us-east-1".to_string(),
            endpoint_url: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
            backend: S3Backend::Memory,
        };
        let prefix = test_prefix("eav-sync");
        let wal = Wal::new(build_s3_store(&s3, &format!("{prefix}/wal")).await?);
        let runtime = EavRuntime::build(&s3, &prefix, wal, vec![Arc::new(NoopAction)]).await?;
        let engine =
            PolicyEngine::init_s3(build_test_store(&test_prefix("eav-sync-policy")).await).await?;
        Ok(Fixture {
            server,
            encoding_key,
            runtime,
            engine,
        })
    }

    fn auth(req: actix_test::TestRequest, token: &str) -> actix_test::TestRequest {
        req.insert_header(("Cookie", format!("auth_token={token}")))
    }

    fn event(entity_id: &str) -> EntityEvent {
        EntityEvent {
            event_id: format!("evt-{entity_id}"),
            entity_id: entity_id.to_string(),
            entity_version: 1,
            kind: EntityEventKind::Created,
            schemas: vec!["invoice".to_string()],
            changed: Vec::new(),
            actor: "alice".to_string(),
            causation_id: None,
            causation_depth: 0,
            correlation_id: "req-1".to_string(),
            snapshot: Some(Default::default()),
            occurred_at: 1_760_000_000,
        }
    }

    async fn append_entity(fx: &Fixture, entity_id: &str) -> anyhow::Result<u64> {
        fx.runtime
            .wal()
            .append(WalOp::Entity {
                event: event(entity_id),
            })
            .await?;
        Ok(fx.runtime.wal().head().await?)
    }

    async fn append_file(fx: &Fixture) -> anyhow::Result<()> {
        fx.runtime
            .wal()
            .append(WalOp::FileDelete {
                file_id: "f1".to_string(),
            })
            .await?;
        Ok(())
    }

    async fn append_policy(fx: &Fixture) -> anyhow::Result<()> {
        fx.runtime
            .wal()
            .append(WalOp::PolicyRuleAdd {
                sub: "editors".to_string(),
                obj: "entity:e1".to_string(),
                act: "read".to_string(),
            })
            .await?;
        Ok(())
    }

    async fn publish_task_schema(fx: &Fixture) -> anyhow::Result<()> {
        fx.runtime
            .schemas()
            .publish(SchemaDraft {
                id: "task".to_string(),
                extends: Vec::new(),
                attributes: Default::default(),
            })
            .await?;
        Ok(())
    }

    async fn create_entity(fx: &Fixture, id: &str) -> anyhow::Result<()> {
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: id.to_string(),
                    schemas: vec!["task".to_string()],
                    attributes: Default::default(),
                },
                &crate::eav::entity::WriteContext::new("alice"),
            )
            .await?;
        Ok(())
    }

    async fn grant_collection_read(fx: &Fixture, sub: &str) -> anyhow::Result<()> {
        fx.engine
            .assign_group(sub.to_string(), "collection-readers".to_string())
            .await?;
        fx.engine
            .add_rule(
                "collection-readers".to_string(),
                ENTITIES.to_string(),
                Action::Read,
            )
            .await?;
        Ok(())
    }

    async fn grant_row_read(fx: &Fixture, sub: &str, entity_id: &str) -> anyhow::Result<()> {
        fx.engine
            .assign_group(sub.to_string(), "row-readers".to_string())
            .await?;
        fx.engine
            .add_rule(
                "row-readers".to_string(),
                format!("entity:{entity_id}"),
                Action::Read,
            )
            .await?;
        Ok(())
    }

    macro_rules! get_route {
        ($app:expr, $uri:expr, $token:expr) => {
            actix_test::call_service(
                $app,
                auth(actix_test::TestRequest::get().uri($uri), $token).to_request(),
            )
        };
    }

    #[actix_web::test]
    async fn status_returns_200_and_an_etag_and_supports_304() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_entity(&fx, "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = get_route!(&app, "/eav/sync/status", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let etag = res
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(etag, "\"1\"");
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["head"], 1);

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get()
                    .uri("/eav/sync/status")
                    .insert_header((IF_NONE_MATCH, etag)),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_MODIFIED);
        let body = actix_test::read_body(res).await;
        assert!(body.is_empty());
        Ok(())
    }

    #[actix_web::test]
    async fn events_return_only_entity_events_in_wal_order() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_file(&fx).await?;
        append_entity(&fx, "e1").await?;
        append_policy(&fx).await?;
        append_entity(&fx, "e2").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/events", &fx.token("alice")?).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        let listed = body["events"].as_array().expect("events");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["seq"], 2);
        assert_eq!(listed[0]["event"]["entity_id"], "e1");
        assert_eq!(listed[1]["seq"], 4);
        assert_eq!(listed[1]["event"]["entity_id"], "e2");
        assert_eq!(body["next"], 4);
        assert_eq!(body["head"], 4);
        Ok(())
    }

    #[actix_web::test]
    async fn a_collection_read_user_sees_every_entity_event() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_entity(&fx, "e1").await?;
        append_entity(&fx, "e2").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/events", &fx.token("alice")?).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["events"].as_array().map(Vec::len), Some(2));
        Ok(())
    }

    #[actix_web::test]
    async fn a_row_grant_user_sees_only_its_entity_event() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_entity(&fx, "e1").await?;
        append_entity(&fx, "e2").await?;
        grant_row_read(&fx, "carol", "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/events", &fx.token("carol")?).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        let listed = body["events"].as_array().expect("events");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["event"]["entity_id"], "e1");
        Ok(())
    }

    #[actix_web::test]
    async fn a_user_with_no_permission_gets_an_empty_list() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_entity(&fx, "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/events", &fx.token("bob")?).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["events"].as_array().map(Vec::len), Some(0));
        assert_eq!(body["next"], 1);
        assert_eq!(body["head"], 1);
        Ok(())
    }

    #[actix_web::test]
    async fn limit_and_next_continuation_work() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_entity(&fx, "e1").await?;
        append_entity(&fx, "e2").await?;
        append_entity(&fx, "e3").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = get_route!(&app, "/eav/sync/events?limit=2", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        let listed = body["events"].as_array().expect("events");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["event"]["entity_id"], "e1");
        assert_eq!(listed[1]["event"]["entity_id"], "e2");
        assert_eq!(body["next"], 2);

        let res = get_route!(&app, "/eav/sync/events?limit=2&since=2", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        let listed = body["events"].as_array().expect("events");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["event"]["entity_id"], "e3");
        assert_eq!(body["next"], 3);
        assert_eq!(body["head"], 3);

        let res = get_route!(&app, "/eav/sync/events?since=3", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["events"].as_array().map(Vec::len), Some(0));
        assert_eq!(body["next"], 3);
        Ok(())
    }

    #[actix_web::test]
    async fn an_invalid_limit_is_400() -> anyhow::Result<()> {
        let fx = fixture().await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for uri in ["/eav/sync/events?limit=0", "/eav/sync/events?limit=501"] {
            let res = get_route!(&app, uri, &token).await;
            assert_eq!(res.status(), http::StatusCode::BAD_REQUEST, "{uri}");
            let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
            assert_eq!(body.code.as_deref(), Some("invalid_request"), "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn since_ahead_of_head_is_409() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/events?since=99", &fx.token("alice")?).await;
        assert_eq!(res.status(), http::StatusCode::CONFLICT);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("conflict"));
        Ok(())
    }

    #[actix_web::test]
    async fn unauthenticated_sync_routes_are_401() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        for uri in ["/eav/sync/status", "/eav/sync/events", "/eav/sync/snapshot"] {
            let res = actix_test::call_service(
                &app,
                actix_test::TestRequest::get().uri(uri).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED, "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn events_ignore_if_none_match() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get()
                    .uri("/eav/sync/events")
                    .insert_header((IF_NONE_MATCH, "\"1\"")),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["events"].as_array().map(Vec::len), Some(1));
        Ok(())
    }

    #[actix_web::test]
    async fn snapshot_returns_the_page_envelope() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
        grant_collection_read(&fx, "alice").await?;
        let head = fx.runtime.wal().head().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/snapshot", &fx.token("alice")?).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let etag = res
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(etag, format!("\"{head}\""));
        let body: Value = actix_test::read_body_json(res).await;
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["id"], "e1");
        assert_eq!(items[1]["id"], "e2");
        assert!(body["next_offset"].is_null());
        assert_eq!(body["head"], head);
        Ok(())
    }

    #[actix_web::test]
    async fn a_second_snapshot_page_uses_the_next_offset() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
        create_entity(&fx, "e3").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = get_route!(&app, "/eav/sync/snapshot?limit=2", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["id"], "e1");
        assert_eq!(items[1]["id"], "e2");
        assert_eq!(body["next_offset"], 2);

        let res = get_route!(&app, "/eav/sync/snapshot?limit=2&offset=2", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "e3");
        assert!(body["next_offset"].is_null());
        Ok(())
    }

    #[actix_web::test]
    async fn a_row_grant_user_sees_only_its_snapshot_entity() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
        grant_row_read(&fx, "carol", "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/snapshot", &fx.token("carol")?).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "e1");
        Ok(())
    }

    #[actix_web::test]
    async fn a_user_with_no_permission_gets_an_empty_snapshot_page() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/snapshot", &fx.token("bob")?).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["items"].as_array().map(Vec::len), Some(0));
        assert_eq!(body["head"], 1);
        Ok(())
    }

    #[actix_web::test]
    async fn a_matching_snapshot_if_none_match_returns_304() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let head = fx.runtime.wal().head().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get()
                    .uri("/eav/sync/snapshot")
                    .insert_header((IF_NONE_MATCH, format!("\"{head}\""))),
                &fx.token("alice")?,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_MODIFIED);
        let body = actix_test::read_body(res).await;
        assert!(body.is_empty());
        Ok(())
    }

    #[actix_web::test]
    async fn an_invalid_snapshot_limit_is_400() -> anyhow::Result<()> {
        let fx = fixture().await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        for uri in ["/eav/sync/snapshot?limit=0", "/eav/sync/snapshot?limit=201"] {
            let res = get_route!(&app, uri, &token).await;
            assert_eq!(res.status(), http::StatusCode::BAD_REQUEST, "{uri}");
            let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
            assert_eq!(body.code.as_deref(), Some("invalid_request"), "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_build_stores_the_visible_entity_list() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
        grant_collection_read(&fx, "alice").await?;
        let head = fx.runtime.wal().head().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["head"], head);
        assert_eq!(body["count"], 2);

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let etag = format!("\"{head}\"");
        assert_eq!(
            res.headers().get(ETAG).and_then(|v| v.to_str().ok()),
            Some(etag.as_str())
        );
        let replica_head = head.to_string();
        assert_eq!(
            res.headers()
                .get("X-Replica-Head")
                .and_then(|v| v.to_str().ok()),
            Some(replica_head.as_str())
        );
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["id"], "e1");
        assert_eq!(items[1]["id"], "e2");
        Ok(())
    }

    #[actix_web::test]
    async fn a_row_grant_user_gets_only_its_entity_in_the_replica() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
        grant_row_read(&fx, "carol", "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("carol")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["count"], 1);

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "e1");
        Ok(())
    }

    #[actix_web::test]
    async fn a_user_with_no_permission_gets_an_empty_replica() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("bob")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["count"], 0);

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        assert!(items.is_empty());
        Ok(())
    }

    #[actix_web::test]
    async fn a_missing_replica_is_404() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/replica", &fx.token("alice")?).await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("not_found"));
        Ok(())
    }

    #[actix_web::test]
    async fn a_matching_replica_if_none_match_returns_304() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;
        let body: Value = actix_test::read_body_json(res).await;
        let head = body["head"].as_u64().expect("head");

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get()
                    .uri("/eav/sync/replica")
                    .insert_header((IF_NONE_MATCH, format!("\"{head}\""))),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::NOT_MODIFIED);
        let body = actix_test::read_body(res).await;
        assert!(body.is_empty());
        Ok(())
    }

    #[actix_web::test]
    async fn replica_status_reports_both_heads() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = get_route!(&app, "/eav/sync/replica/status", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        let head = body["head"].as_u64().expect("head");
        assert_eq!(head, fx.runtime.wal().head().await?);
        assert!(body["built_head"].is_null());

        actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;

        let res = get_route!(&app, "/eav/sync/replica/status", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["head"], head);
        assert_eq!(body["built_head"], head);
        Ok(())
    }

    #[actix_web::test]
    async fn a_rebuild_replaces_the_snapshot_and_raises_the_built_head() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let first: Value = actix_test::read_body_json(res).await;
        let first_head = first["head"].as_u64().expect("head");

        create_entity(&fx, "e2").await?;
        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let second: Value = actix_test::read_body_json(res).await;
        let second_head = second["head"].as_u64().expect("head");
        assert!(second_head > first_head);

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        let etag = format!("\"{second_head}\"");
        assert_eq!(
            res.headers().get(ETAG).and_then(|v| v.to_str().ok()),
            Some(etag.as_str())
        );
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        assert_eq!(items.len(), 2);

        let res = get_route!(&app, "/eav/sync/replica/status", &token).await;
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["built_head"], second_head);
        Ok(())
    }

    #[actix_web::test]
    async fn a_stale_replica_build_is_409_and_keeps_the_stored_snapshot() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let head = fx.runtime.wal().head().await?;
        let future = head + 100;
        fx.runtime
            .replicas()
            .put("alice", future, b"newer".to_vec())
            .await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;

        assert_eq!(res.status(), http::StatusCode::CONFLICT);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("conflict"));
        assert_eq!(
            fx.runtime.replicas().get("alice").await?,
            Some((future, b"newer".to_vec()))
        );
        Ok(())
    }

    #[test]
    fn openapi_includes_sync_paths_and_schemas() {
        let spec: Value =
            serde_json::from_str(&ApiDoc::openapi().to_json().expect("spec serializes"))
                .expect("spec is JSON");
        let paths = spec["paths"].as_object().expect("paths");
        assert!(paths.contains_key("/eav/sync/status"));
        assert!(paths.contains_key("/eav/sync/events"));
        assert!(paths.contains_key("/eav/sync/snapshot"));
        assert!(paths.contains_key("/eav/sync/replica"));
        assert!(paths.contains_key("/eav/sync/replica/status"));
        let schemas = spec["components"]["schemas"]
            .as_object()
            .expect("component schemas");
        for name in [
            "SyncStatusResponse",
            "SyncEvent",
            "SyncEventsResponse",
            "SyncEventsQuery",
            "SnapshotPage",
            "ReplicaBuildResponse",
            "ReplicaStatusResponse",
            "EntityEvent",
            "AttributeChange",
        ] {
            assert!(schemas.contains_key(name), "spec missing {name}");
        }
    }

    #[actix_web::test]
    async fn the_feed_carries_the_entity_snapshot() -> anyhow::Result<()> {
        let fx = fixture().await?;
        fx.runtime
            .schemas()
            .publish(SchemaDraft {
                id: "invoice".to_string(),
                extends: Vec::new(),
                attributes: [(
                    "total".to_string(),
                    AttributeDef {
                        name: "total".to_string(),
                        ty: AttributeType::Integer,
                        required: false,
                        indexed: false,
                        unique: false,
                        default: None,
                    },
                )]
                .into_iter()
                .collect(),
            })
            .await?;
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: "e1".to_string(),
                    schemas: vec!["invoice".to_string()],
                    attributes: [("total".to_string(), AttributeValue::Integer(10))]
                        .into_iter()
                        .collect(),
                },
                &crate::eav::entity::WriteContext::new("alice"),
            )
            .await?;
        fx.runtime.entities().flush_outbox().await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = get_route!(&app, "/eav/sync/events", &fx.token("alice")?).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        let listed = body["events"].as_array().expect("events");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["event"]["snapshot"]["total"], 10);
        Ok(())
    }
}
