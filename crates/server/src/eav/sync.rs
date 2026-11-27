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
//! The first snapshot page returns the current feed head.
//! Each later page sends that head and gets the same value back.
//! A head above the current feed head returns `409`.
//!
//! `POST /eav/sync/replica` stores a chunked JSON snapshot for the caller.
//! `GET /eav/sync/replica` returns the stored snapshot as one JSON array.
//! `GET /eav/sync/replica?chunk=N` returns one page of the stored snapshot.
//! `GET /eav/sync/replica/status` reports the log head and the stored head.
//! `DELETE /eav/sync/replica` removes the stored replica of the caller.
//! The same build also writes a per-user OxKV mirror for the WASM client.
//! `GET /eav/sync/oxkv/manifest.json` returns the mirror wrapper manifest.
//! `GET /eav/sync/oxkv/objects/{object}` returns one raw OxKV object.
//! The client applies the events after the stored head.
//! The replica is a head-anchored snapshot, not an incremental store.
//! The build reads the feed head first, then pages the entities.
//! A build holds at most `MAX_REPLICA_ENTITIES` visible entities.
//! The current limit is 100,000.
//! A build that exceeds the limit stops the entity scan and returns `400`.
//! The build scans at most `MAX_REPLICA_SCAN_ENTITIES` entities.
//! A build that exceeds the scan limit returns `400`.
//! The build writes no snapshot, so the stored replica stays unchanged.
//! A change that commits after the head can appear in the snapshot.
//! An apply must be idempotent and version-aware.
//! The full read is for compatibility.
//! Use the chunk read to page a large replica.
//!
//! The OxKV mirror holds only the `entity:{id}:meta` and
//! `entity:{id}:attr:{name}` rows that the caller can read.
//! It holds no index, outbox, timer, or reverse-reference row.
//! The wrapper names each raw OxKV object with its size and SHA-256.
//! The wrapper generation and head equal the JSON replica generation and head.
//! The build publishes the wrapper only after every object is written.
//! A lower head never replaces a higher head.
//! A rebuild keeps the current and the previous generation.
//! A failed build leaves the old wrapper and the old generation readable.
//!
//! A reset removes the snapshot, the chunks, the manifest, the generation, and
//! the head.
//! The caller needs a valid session and no management grant.
//! A caller owns its replica.
//! A reset returns `204` when a replica existed.
//! A reset returns `404` when the caller has no replica.
//! After a WAL reset, call the reset route, then build a new replica.
//!
//! Each build increments the stored generation, including an equal-head build.
//! The full read sets `X-Replica-Generation`.
//! The chunk read sets `X-Replica-Generation` and returns `generation` in the
//! body.
//! A client that pages chunks must compare the generation across the pages.
//! The client must restart at chunk 0 when the generation changes, because the
//! pages then come from two different builds.
//!
//! The build filters with the grants at build time.
//! Each replica read filters again with the current grants.
//! The snapshot gives no authorization cache.
//! A policy change takes effect on the next read.
//! The replica read sets no `ETag`, because the response depends on the
//! current grants and has no stable validator.
//!
//! The events route checks one collection grant.
//! Without the collection grant, it checks a row grant for each event.
//! A caller sees only the events that it can read.
//!
//! The events route reads the feed in fixed windows.
//! A window holds at most `EVENT_SCAN_BATCH` entries.
//! The route holds the read guard for one window only.
//! It releases the guard before it reads the next window.
//! A slow client therefore does not block appends for its whole backlog.
//! The route stops at `limit` visible events or at the feed head.
//! An invisible entry neither fills the page nor stops the scan.

use actix_web::{
    HttpRequest, HttpResponse, delete, get,
    http::header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH},
    post, web,
};
use serde::Serialize;
use std::time::Instant;

use crate::eav::entity::Entity;
use crate::eav::entity_error::EntityError;
use crate::eav::oxkv_replica::OxkvGeneration;
use crate::eav::route::{
    ENTITIES, ENTITY_ROW, EavApiError, PageMode, PageQuery, can_read_entity, page_next_offset,
    visible_cursor_page,
};
use crate::eav::runtime::EavRuntime;
use crate::fs::error::FsError;
use crate::http::middleware::jwt::{Claims, Validated};
use crate::policy::row::RowAuthorizer;
use crate::policy::{Action, Authorizer};
use crate::records::{EntityEvent, WalEntry, WalOp};
use rust_api_model::wire::ReplicaManifest;

/// The default number of events in one page.
const DEFAULT_LIMIT: usize = 100;
/// The largest number of events in one page.
const MAX_LIMIT: usize = 500;
/// The number of entities that a replica build reads in one page.
#[cfg(not(test))]
const REPLICA_PAGE: usize = 500;
/// A small page in tests, so a build spans more than one page.
#[cfg(test)]
const REPLICA_PAGE: usize = 2;
/// The number of change-log entries that the events route reads in one window.
#[cfg(not(test))]
const EVENT_SCAN_BATCH: usize = 256;
/// A small window in tests, so a scan spans more than one window.
#[cfg(test)]
const EVENT_SCAN_BATCH: usize = 2;
/// The number of entities in one stored replica chunk.
#[cfg(not(test))]
const REPLICA_CHUNK_ENTITIES: usize = 500;
/// A small chunk in tests, so a build stores more than one chunk.
#[cfg(test)]
const REPLICA_CHUNK_ENTITIES: usize = 2;
/// The number of replica builds before a stale head is final.
const REPLICA_BUILD_ATTEMPTS: u32 = 2;
/// The largest number of visible entities in one replica build.
#[cfg(not(test))]
const MAX_REPLICA_ENTITIES: usize = 100_000;
/// A small entity cap in tests, so a build can exceed it.
#[cfg(test)]
const MAX_REPLICA_ENTITIES: usize = 2;
/// The largest number of entities that one replica build scans.
///
/// The build checks the caller grant on each scanned entity.
/// The bound stops a caller with no grant from scanning the full store.
const MAX_REPLICA_SCAN_ENTITIES: usize = MAX_REPLICA_ENTITIES * 10;
/// The largest serialized byte size of one replica build.
#[cfg(not(test))]
const REPLICA_BUILD_MAX_BYTES: usize = 64 * 1024 * 1024;
/// A small byte cap in tests, so a build can exceed it.
#[cfg(test)]
const REPLICA_BUILD_MAX_BYTES: usize = 16 * 1024;

/// The current head of the entity change feed.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[schema(as = EavSyncStatusResponse)]
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
///
/// The route scans the feed in windows of `EVENT_SCAN_BATCH` entries.
/// It releases the change-log read guard between two windows.
/// An invisible entry neither fills the page nor stops the scan.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SyncEventsResponse {
    /// The visible entity events in log order.
    pub events: Vec<SyncEvent>,
    /// The cursor for the next call.
    ///
    /// The value is the sequence of the last returned event when the page is
    /// full.
    /// Otherwise it is the current head.
    /// The next request starts after this sequence, so no event repeats.
    /// An invisible entry after this sequence stays for a later page.
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
    /// The value is `None` when the next offset would pass the cap.
    /// Continue while `next_offset` is `Some`.
    pub next_offset: Option<usize>,
    /// The id to resume after for the next page.
    ///
    /// The value is `Some` only in cursor mode.
    /// The value is the id of the last visible entity.
    /// The value never names an entity that the caller cannot read.
    /// The value is `None` when the scan is exhausted.
    pub next: Option<String>,
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
    /// The build generation of the stored replica.
    pub generation: u64,
    /// The number of visible entities in the replica.
    pub count: usize,
    /// The number of stored chunks.
    pub chunks: usize,
}

/// The query of the replica read route.
#[derive(Debug, Clone, Copy, Default, serde::Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct ReplicaChunkQuery {
    /// The zero-based chunk index.
    ///
    /// Omit it to read the full snapshot as a JSON array of entities.
    /// Set it to read one `ReplicaChunkResponse`.
    #[serde(default)]
    pub chunk: Option<usize>,
}

/// One page of a stored replica.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ReplicaChunkResponse {
    /// The head of the stored replica.
    pub head: u64,
    /// The build generation of the stored replica.
    pub generation: u64,
    /// The zero-based index of this chunk.
    pub chunk: usize,
    /// The number of chunks in the stored replica.
    pub chunks: usize,
    /// The entities in this chunk.
    pub items: Vec<Entity>,
    /// The index of the next chunk, or `None` on the last chunk.
    pub next: Option<usize>,
}

/// The response body of the replica read route.
///
/// The route returns one of two shapes.
/// Without `chunk`, it returns every permitted entity as a JSON array.
/// With `chunk=N`, it returns one [`ReplicaChunkResponse`].
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum ReplicaReadResponse {
    /// Every permitted entity in the full replica.
    Full(Vec<Entity>),
    /// One stored chunk.
    Chunk(ReplicaChunkResponse),
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

/// The query of the snapshot route.
///
/// The first request of a paging sequence omits `head`.
/// The route then returns the current feed head.
/// Each later request sends that head.
/// The route then returns the same head on every page.
#[derive(Debug, Clone, Default, serde::Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
pub struct SnapshotQuery {
    /// The page size. The default is 50. The maximum is 200.
    #[serde(default)]
    pub limit: Option<usize>,
    /// The number of items to skip. The default is 0.
    ///
    /// The maximum is 1000. Use `after` for a deeper page.
    #[serde(default)]
    pub offset: Option<usize>,
    /// The id to resume after.
    ///
    /// A present value selects cursor mode.
    /// Omit the field to use offset paging.
    #[serde(default)]
    pub after: Option<String>,
    /// The head that pins this paging sequence.
    ///
    /// Omit it on the first request.
    /// A value above the current feed head returns `409`.
    #[serde(default)]
    pub head: Option<u64>,
}

impl SnapshotQuery {
    /// Resolves the page size, the paging mode, and the pinned head.
    fn resolve(self) -> Result<(usize, PageMode, Option<u64>), EavApiError> {
        let page = PageQuery {
            limit: self.limit,
            offset: self.offset,
            after: self.after,
        };
        let (limit, mode) = page.resolve()?;
        Ok((limit, mode, self.head))
    }
}

/// The source of a snapshot head that is ahead of the current feed head.
#[derive(Debug)]
struct SnapshotHeadAhead;

impl std::fmt::Display for SnapshotHeadAhead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("head is ahead of the feed head")
    }
}

impl std::error::Error for SnapshotHeadAhead {}

/// Converts a change-log failure to a sanitized server error.
fn internal(error: FsError) -> EavApiError {
    EavApiError::Internal(Box::new(error))
}

/// Decodes one stored replica chunk into entities.
fn decode_chunk(chunk: &[u8]) -> Result<Vec<Entity>, EavApiError> {
    serde_json::from_slice(chunk).map_err(|e| EavApiError::Internal(Box::new(e)))
}

/// Keeps only the entities that the caller can read.
///
/// The route calls this function on every read.
/// The function does not cache an authorization decision.
async fn filter_readable(
    policy: &Authorizer,
    sub: &str,
    items: Vec<Entity>,
) -> Result<Vec<Entity>, EavApiError> {
    let mut visible = Vec::with_capacity(items.len());
    for entity in items {
        if can_read_entity(policy, sub, &entity.id).await? {
            visible.push(entity);
        }
    }
    Ok(visible)
}

/// Returns the quoted `ETag` for one head value.
fn status_etag(head: u64) -> String {
    format!("\"{head}\"")
}

/// Returns the last sequence of a scan window.
///
/// The window starts at `start` and holds at most `batch` entries.
/// The result never passes `head`.
/// `batch` must be at least 1.
fn window_end(start: u64, head: u64, batch: usize) -> u64 {
    let width = u64::try_from(batch).unwrap_or(u64::MAX);
    start.saturating_add(width.saturating_sub(1)).min(head)
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
/// The route reads the feed in windows of `EVENT_SCAN_BATCH` entries.
/// It holds the read guard for one window only.
/// It releases the guard before it reads the next window.
/// The scan stops at `limit` visible events or at the head.
/// An invisible entry neither fills the page nor stops the scan.
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

    let collection = policy
        .authorize(&claims.sub, ENTITIES, Action::Read)
        .await
        .map_err(EavApiError::from)?;

    let mut events = Vec::with_capacity(limit.min(EVENT_SCAN_BATCH));
    let mut start = since + 1;
    loop {
        let end = window_end(start, head, EVENT_SCAN_BATCH);
        let entries = runtime.wal().range(start, end).await.map_err(internal)?;
        for entry in entries {
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
                if events.len() == limit {
                    break;
                }
            }
        }
        if events.len() == limit || end == head {
            break;
        }
        start = end + 1;
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
/// A cursor query uses the entity marker family and returns `next`.
/// The route reads raw pages until the page is full or the entity list ends.
/// A raw page can hold only rows that the caller cannot read, so a fixed raw
/// page count could miss a later visible row.
/// The `next` value is the id of the last visible entity.
/// The value never names an entity that the caller cannot read.
/// A scan that finds no visible entity returns `next: null`.
/// The first request of a paging sequence omits `head`.
/// The route then returns the current feed head.
/// Each later request sends that head and gets the same head.
/// A head above the current feed head returns `409`.
/// The route sets no `ETag` and ignores `If-None-Match`.
/// The response depends on the current grants and on the page, so it has no
/// stable validator.
#[utoipa::path(get, path = "/eav/sync/snapshot", tag = "eav", params(SnapshotQuery), responses((status = 200, body = SnapshotPage), (status = 400, body = crate::http::error::ErrorBody), (status = 401, body = crate::http::error::ErrorBody), (status = 409, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[get("/sync/snapshot")]
pub(crate) async fn snapshot(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    query: web::Query<SnapshotQuery>,
) -> Result<HttpResponse, EavApiError> {
    let (limit, mode, pinned) = query.into_inner().resolve()?;
    let current = runtime.wal().head().await.map_err(internal)?;
    let head = match pinned {
        Some(head) if head > current => {
            return Err(EavApiError::Conflict(Box::new(SnapshotHeadAhead)));
        }
        Some(head) => head,
        None => current,
    };

    match mode {
        PageMode::Cursor(after) => {
            let (items, next) = visible_cursor_page(&policy, &claims.sub, limit, after, |cursor| {
                let runtime = runtime.clone();
                async move {
                    runtime
                        .entities()
                        .list_after(limit, cursor.as_deref())
                        .await
                        .map_err(EavApiError::from)
                }
            })
            .await?;
            Ok(HttpResponse::Ok().json(SnapshotPage {
                items,
                next_offset: None,
                next,
                head,
            }))
        }
        PageMode::Offset(offset) => {
            let raw = runtime.entities().list_page(limit, offset).await?;
            let raw_len = raw.len();
            let mut items = Vec::with_capacity(raw_len);
            for entity in raw {
                if can_read_entity(&policy, &claims.sub, &entity.id).await? {
                    items.push(entity);
                }
            }
            let next_offset = page_next_offset(offset, raw_len, limit);
            Ok(HttpResponse::Ok().json(SnapshotPage {
                items,
                next_offset,
                next: None,
                head,
            }))
        }
    }
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

/// The source of a missing raw OxKV replica object.
#[derive(Debug)]
struct MissingOxkvObject;

impl std::fmt::Display for MissingOxkvObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("oxkv replica object does not exist")
    }
}

impl std::error::Error for MissingOxkvObject {}

/// The source of a build that lost a concurrent generation race.
#[derive(Debug)]
struct ReplicaBuildRestarted;

impl std::fmt::Display for ReplicaBuildRestarted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("replica build lost a generation race")
    }
}

impl std::error::Error for ReplicaBuildRestarted {}

/// The source of a replica build that exceeds a size limit.
#[derive(Debug)]
struct ReplicaBuildTooLarge(&'static str);

impl std::fmt::Display for ReplicaBuildTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ReplicaBuildTooLarge {}

/// Returns the entity limit for one replica build.
fn replica_entity_limit(runtime: &EavRuntime) -> usize {
    let _ = runtime;
    #[cfg(test)]
    {
        if let Some(limit) = runtime.replica_test().limit() {
            return limit;
        }
    }
    MAX_REPLICA_ENTITIES
}

/// Builds a stored replica for the caller.
///
/// The caller needs a valid session.
/// The route reads the current change-log head first.
/// It then reads every entity in id order with a cursor.
/// A change that commits after the head can appear in the snapshot.
/// It keeps only the entities that the caller can read.
/// It serializes the entities into ordered JSON chunks.
/// Each chunk holds at most `REPLICA_CHUNK_ENTITIES` entities.
/// The build holds at most `MAX_REPLICA_ENTITIES` visible entities.
/// The current limit is 100,000.
/// A build that exceeds the limit stops the entity scan and returns `400`.
/// The build scans at most `MAX_REPLICA_SCAN_ENTITIES` entities.
/// A build that exceeds the scan limit returns `400`.
/// The build serializes each chunk as it fills and holds the total serialized
/// size under `REPLICA_BUILD_MAX_BYTES`.
/// A build that exceeds the byte limit returns `400`.
/// The current byte limit is 64 MiB.
/// `ReplicaStore::put` takes every serialized chunk, so the build holds all
/// chunks in memory until the put returns.
/// The byte cap bounds that memory.
/// The build writes no snapshot, so the stored replica stays unchanged.
/// The build replaces the previous replica and its chunks for the same
/// subject.
/// The build increments the replica generation and returns it.
/// The client applies the events after the returned `head`.
/// An apply must be idempotent and version-aware.
/// A newer build can commit first.
/// The route then reads a fresh feed head and builds one more time.
/// A second stale result returns `409`.
#[utoipa::path(post, path = "/eav/sync/replica", tag = "eav", responses((status = 200, body = ReplicaBuildResponse), (status = 400, body = crate::http::error::ErrorBody), (status = 401, body = crate::http::error::ErrorBody), (status = 409, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[post("/sync/replica")]
pub(crate) async fn build_replica(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
) -> Result<HttpResponse, EavApiError> {
    let started = Instant::now();
    let metrics = runtime.metrics().clone();
    let result = build_replica_inner(runtime, policy, claims).await;
    match &result {
        Ok(_) => metrics.record_replica_build(started.elapsed()),
        Err(_) => metrics.record_replica_build_failure(),
    }
    result
}

/// Builds a stored replica for the caller.
///
/// The build holds the subject lock while it writes the OxKV mirror.
/// It reads the planned generation, writes the mirror, then commits the JSON
/// replica.
/// It publishes the wrapper only when the committed generation matches the
/// planned generation.
/// A failed mirror write and a rejected JSON commit leave the old wrapper and
/// the old generation readable.
async fn build_replica_inner(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
) -> Result<HttpResponse, EavApiError> {
    #[cfg(test)]
    runtime.replica_test().reset_read();
    let entity_limit = replica_entity_limit(&runtime);
    let mut attempt = 0;
    loop {
        attempt += 1;
        let _guard = runtime.oxkv().lock_subject(&claims.sub).await;
        let head = runtime.wal().head().await.map_err(internal)?;
        let planned = runtime.replicas().next_generation(&claims.sub).await?;
        let generation = runtime
            .oxkv()
            .begin_generation(&claims.sub, planned, head)
            .await?;
        let (count, chunks) =
            match scan_replica(&runtime, &policy, &claims.sub, &generation, entity_limit).await {
                Ok(result) => result,
                Err(error) => {
                    let _ = generation.abort().await;
                    return Err(error);
                }
            };
        let chunk_count = chunks.len();
        let prepared = match generation.finish().await {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = runtime
                    .oxkv()
                    .discard_generation(&claims.sub, planned)
                    .await;
                return Err(error.into());
            }
        };
        match runtime.replicas().put(&claims.sub, head, chunks).await {
            Ok(actual) if actual == planned => {
                if let Err(error) = runtime.oxkv().publish(&claims.sub, &prepared).await {
                    tracing::warn!(
                        %error,
                        subject = %claims.sub,
                        "oxkv replica wrapper publish failed after the JSON commit"
                    );
                    let _ = runtime
                        .oxkv()
                        .discard_generation(&claims.sub, planned)
                        .await;
                    return Err(EavApiError::Conflict(Box::new(ReplicaBuildRestarted)));
                }
                return Ok(HttpResponse::Ok().json(ReplicaBuildResponse {
                    head,
                    generation: actual,
                    count,
                    chunks: chunk_count,
                }));
            }
            Ok(_) => {
                let _ = runtime
                    .oxkv()
                    .discard_generation(&claims.sub, planned)
                    .await;
                if attempt < REPLICA_BUILD_ATTEMPTS {
                    continue;
                }
                return Err(EavApiError::Conflict(Box::new(ReplicaBuildRestarted)));
            }
            Err(EntityError::StaleHead { .. }) if attempt < REPLICA_BUILD_ATTEMPTS => {
                let _ = runtime
                    .oxkv()
                    .discard_generation(&claims.sub, planned)
                    .await;
                continue;
            }
            Err(error) => {
                let _ = runtime
                    .oxkv()
                    .discard_generation(&claims.sub, planned)
                    .await;
                return Err(EavApiError::from(error));
            }
        }
    }
}

/// Scans the visible entities and fills one OxKV generation.
///
/// The scan stops at `entity_limit` visible entities or at the scan cap.
/// It serializes the same ordered JSON chunks as the JSON replica.
/// A row is staged before its chunk can fail, so the caller must abort the
/// generation on an error.
async fn scan_replica(
    runtime: &EavRuntime,
    policy: &Authorizer,
    sub: &str,
    generation: &OxkvGeneration,
    entity_limit: usize,
) -> Result<(usize, Vec<Vec<u8>>), EavApiError> {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut chunk_bytes = 0usize;
    let mut pending: Vec<Entity> = Vec::new();
    let mut count = 0;
    let mut scanned: usize = 0;
    let mut after: Option<String> = None;
    loop {
        let (page, next) = runtime
            .entities()
            .list_after(REPLICA_PAGE, after.as_deref())
            .await?;
        for entity in page {
            scanned = scanned.saturating_add(1);
            #[cfg(test)]
            runtime.replica_test().count_read();
            if scanned > MAX_REPLICA_SCAN_ENTITIES {
                return Err(EavApiError::Invalid(Box::new(ReplicaBuildTooLarge(
                    "replica build exceeds the scan limit",
                ))));
            }
            if can_read_entity(policy, sub, &entity.id).await? {
                count += 1;
                if count > entity_limit {
                    return Err(EavApiError::Invalid(Box::new(ReplicaBuildTooLarge(
                        "replica build exceeds the entity limit",
                    ))));
                }
                generation.add_entity(&entity).await?;
                pending.push(entity);
                if pending.len() == REPLICA_CHUNK_ENTITIES {
                    let chunk = serde_json::to_vec(&pending)
                        .map_err(|e| EavApiError::Internal(Box::new(e)))?;
                    chunk_bytes = chunk_bytes.saturating_add(chunk.len());
                    if chunk_bytes > REPLICA_BUILD_MAX_BYTES {
                        return Err(EavApiError::Invalid(Box::new(ReplicaBuildTooLarge(
                            "replica build exceeds the byte limit",
                        ))));
                    }
                    chunks.push(chunk);
                    pending.clear();
                }
            }
        }
        match next {
            Some(cursor) => after = Some(cursor),
            None => break,
        }
    }
    if !pending.is_empty() {
        let chunk = serde_json::to_vec(&pending).map_err(|e| EavApiError::Internal(Box::new(e)))?;
        chunk_bytes = chunk_bytes.saturating_add(chunk.len());
        if chunk_bytes > REPLICA_BUILD_MAX_BYTES {
            return Err(EavApiError::Invalid(Box::new(ReplicaBuildTooLarge(
                "replica build exceeds the byte limit",
            ))));
        }
        chunks.push(chunk);
    }
    Ok((count, chunks))
}

/// Removes both stored replicas of the caller.
///
/// The caller needs a valid session.
/// The route needs no management grant, because a caller owns its replica.
/// The route removes only the replica of the caller.
/// The route takes the subject build lock before it clears either store.
/// A build that waits for the lock cannot repopulate the mirror after the
/// reset.
/// A reset removes the JSON snapshot, the chunks, the manifest, the
/// generation, the head, the OxKV wrapper, and every OxKV generation.
/// A reset returns `204` when the JSON replica or the OxKV replica existed.
/// A reset returns `404` only when neither replica existed.
/// After a WAL reset, call the reset route, then build a new replica.
/// The next build starts at generation 1.
#[utoipa::path(delete, path = "/eav/sync/replica", tag = "eav", responses((status = 204, description = "replica removed"), (status = 401, body = crate::http::error::ErrorBody), (status = 404, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[delete("/sync/replica")]
pub(crate) async fn reset_replica(
    runtime: web::Data<EavRuntime>,
    claims: Validated<Claims>,
) -> Result<HttpResponse, EavApiError> {
    let _guard = runtime.oxkv().lock_subject(&claims.sub).await;
    let json = runtime.replicas().clear(&claims.sub).await?;
    let oxkv = runtime.oxkv().clear(&claims.sub).await?;
    if json || oxkv {
        return Ok(HttpResponse::NoContent().finish());
    }
    Err(EavApiError::NotFound(Box::new(MissingReplica)))
}

/// The source of a replica chunk index outside the stored range.
#[derive(Debug)]
struct ReplicaChunkOutOfRange;

impl std::fmt::Display for ReplicaChunkOutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("replica chunk is out of range")
    }
}

impl std::error::Error for ReplicaChunkOutOfRange {}

/// Returns the stored replica of the caller.
///
/// The caller needs a valid session.
/// A missing replica returns `404`.
/// The route filters every entity with the current grants.
/// A caller with no read grant gets an empty list or an empty page.
/// The snapshot gives no authorization cache.
/// A policy change takes effect on the next read.
/// Without a `chunk` parameter, the route returns every permitted entity as
/// one JSON array and sets `X-Replica-Head` and `X-Replica-Generation`.
/// A full read above `[limits].max_full_replica_bytes` returns `400`.
/// The client must then use chunk mode.
/// The value `0` disables the gate.
/// With `chunk=N`, the route returns one stored chunk and sets
/// `X-Replica-Head`, `X-Replica-Generation`, `X-Replica-Chunk`, and
/// `X-Replica-Chunks`.
/// The chunk response also carries `generation` in its body.
/// A client that pages chunks must compare the generation across the pages.
/// The client must restart at chunk 0 when the generation changes, because the
/// pages then come from two different builds.
/// The route sets no `ETag` and ignores `If-None-Match`.
/// The response depends on the current grants, so it has no stable validator.
/// An out-of-range `chunk` returns `400`.
/// A replica with no entity returns chunk 0 with `chunks: 0`, an empty `items`,
/// and `next: null`.
/// The client applies the events after the stored head.
#[utoipa::path(get, path = "/eav/sync/replica", tag = "eav", params(ReplicaChunkQuery), responses((status = 200, body = ReplicaReadResponse), (status = 400, body = crate::http::error::ErrorBody), (status = 401, body = crate::http::error::ErrorBody), (status = 404, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[get("/sync/replica")]
pub(crate) async fn replica(
    runtime: web::Data<EavRuntime>,
    policy: web::Data<Authorizer>,
    claims: Validated<Claims>,
    query: web::Query<ReplicaChunkQuery>,
) -> Result<HttpResponse, EavApiError> {
    let Some(index) = query.into_inner().chunk else {
        let Some(stored) = runtime.replicas().get(&claims.sub).await? else {
            return Err(EavApiError::NotFound(Box::new(MissingReplica)));
        };
        let limit = runtime.full_replica_byte_limit();
        if limit > 0 {
            let bytes: usize = stored.chunks.iter().map(Vec::len).sum();
            if bytes > limit {
                return Err(EavApiError::ReplicaTooLarge);
            }
        }
        let mut items: Vec<Entity> = Vec::new();
        for chunk in stored.chunks {
            items.extend(decode_chunk(&chunk)?);
        }
        let items = filter_readable(&policy, &claims.sub, items).await?;
        let data = serde_json::to_vec(&items).map_err(|e| EavApiError::Internal(Box::new(e)))?;
        return Ok(HttpResponse::Ok()
            .insert_header(("X-Replica-Head", stored.head.to_string()))
            .insert_header(("X-Replica-Generation", stored.generation.to_string()))
            .insert_header((CONTENT_TYPE, "application/json"))
            .body(data));
    };

    let Some(chunk) = runtime.replicas().get_chunk(&claims.sub, index).await? else {
        if runtime.replicas().status(&claims.sub).await?.is_none() {
            return Err(EavApiError::NotFound(Box::new(MissingReplica)));
        }
        return Err(EavApiError::Invalid(Box::new(ReplicaChunkOutOfRange)));
    };
    let items = decode_chunk(&chunk.data)?;
    let items = filter_readable(&policy, &claims.sub, items).await?;
    let next = (index + 1 < chunk.chunks).then_some(index + 1);
    Ok(HttpResponse::Ok()
        .insert_header(("X-Replica-Head", chunk.head.to_string()))
        .insert_header(("X-Replica-Generation", chunk.generation.to_string()))
        .insert_header(("X-Replica-Chunk", index.to_string()))
        .insert_header(("X-Replica-Chunks", chunk.chunks.to_string()))
        .json(ReplicaChunkResponse {
            head: chunk.head,
            generation: chunk.generation,
            chunk: index,
            chunks: chunk.chunks,
            items,
            next,
        }))
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

/// Returns the OxKV replica wrapper manifest of the caller.
///
/// The caller needs a valid session and no management grant.
/// A missing replica returns `404`.
/// The body is a [`ReplicaManifest`] with the generation, the head, and every
/// raw object relative to the replica root.
/// The object keys are exactly the keys that the client stores in its
/// read-only `OxKvReader` map with an empty prefix.
/// The route sets `X-Replica-Generation` and `X-Replica-Head`.
/// The route sets no `ETag`, because the wrapper changes only on a rebuild.
#[utoipa::path(get, path = "/eav/sync/oxkv/manifest.json", tag = "eav", responses((status = 200, body = ReplicaManifest), (status = 401, body = crate::http::error::ErrorBody), (status = 404, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[get("/sync/oxkv/manifest.json")]
pub(crate) async fn oxkv_manifest(
    runtime: web::Data<EavRuntime>,
    claims: Validated<Claims>,
) -> Result<HttpResponse, EavApiError> {
    let Some(manifest) = runtime.oxkv().manifest(&claims.sub).await? else {
        return Err(EavApiError::NotFound(Box::new(MissingReplica)));
    };
    Ok(HttpResponse::Ok()
        .insert_header(("X-Replica-Generation", manifest.generation.to_string()))
        .insert_header(("X-Replica-Head", manifest.head.to_string()))
        .json(manifest))
}

/// Returns one raw OxKV object of the caller.
///
/// The caller needs a valid session and no management grant.
/// The route resolves the object only through the wrapper of the caller.
/// A key that the wrapper does not list returns `404`, so one subject cannot
/// read the object of another subject.
/// A missing replica returns `404`.
/// The body is `application/octet-stream`.
#[utoipa::path(get, path = "/eav/sync/oxkv/objects/{object}", tag = "eav", params(("object" = String, Path, description = "Object key relative to the replica root")), responses((status = 200, description = "raw OxKV object bytes"), (status = 401, body = crate::http::error::ErrorBody), (status = 404, body = crate::http::error::ErrorBody), (status = 500, body = crate::http::error::ErrorBody)))]
#[get("/sync/oxkv/objects/{object:.*}")]
pub(crate) async fn oxkv_object(
    runtime: web::Data<EavRuntime>,
    claims: Validated<Claims>,
    object: web::Path<String>,
) -> Result<HttpResponse, EavApiError> {
    let Some(bytes) = runtime.oxkv().object(&claims.sub, &object).await? else {
        return Err(EavApiError::NotFound(Box::new(MissingOxkvObject)));
    };
    Ok(HttpResponse::Ok()
        .insert_header((CONTENT_TYPE, "application/octet-stream"))
        .body(bytes))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use actix_web::{App, http, test as actix_test};
    use jsonwebtoken::EncodingKey;
    use oxkv::{Direction, KeyPrefix, MemStorage, ObjectPath, OxKvStore, PutMode, Storage as _};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use utoipa::OpenApi as _;

    use super::*;
    use crate::db::{build_s3_store, build_test_store, test_prefix};
    use crate::docs::ApiDoc;
    use crate::eav::entity::{AttributeValue, EntityDraft};
    use crate::eav::metrics::test_support::MetricCapture;
    use crate::eav::route::EavApiModule;
    use crate::eav::runtime::{RefCheck, Scripts};
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft};
    use crate::fs::s3::{S3Backend, S3ClientConfig};
    use crate::http::ApiModule;
    use crate::http::middleware::jwks::test_support::{rsa_key, sign_rs256, spawn_jwks};
    use crate::policy::PolicyEngine;
    use crate::records::{ChangeSink, EntityEventKind};
    use crate::rules::action::{ActionContext, ActionError, RuleAction};
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

        async fn execute(&self, _ctx: ActionContext) -> Result<(), ActionError> {
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
                crate::http::middleware::jwt::JwtClaimsMiddleware::<Claims>::new_with_jwks(
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
        let runtime = EavRuntime::build(
            &s3,
            &prefix,
            wal,
            vec![Arc::new(NoopAction)],
            RefCheck::On,
            8,
            Scripts::Disabled,
        )
        .await?;
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

    /// Grants one row read to one subject with a private group.
    ///
    /// Two subjects that share a group also share every row rule in it.
    async fn grant_private_row_read(
        fx: &Fixture,
        sub: &str,
        entity_id: &str,
    ) -> anyhow::Result<()> {
        let group = format!("row-readers-{sub}");
        fx.engine
            .assign_group(sub.to_string(), group.clone())
            .await?;
        fx.engine
            .add_rule(group, format!("entity:{entity_id}"), Action::Read)
            .await?;
        Ok(())
    }

    async fn revoke_collection_read(fx: &Fixture) -> anyhow::Result<()> {
        fx.engine
            .remove_rule(
                "collection-readers".to_string(),
                ENTITIES.to_string(),
                Action::Read,
            )
            .await?;
        Ok(())
    }

    async fn revoke_row_read(fx: &Fixture, entity_id: &str) -> anyhow::Result<()> {
        fx.engine
            .remove_rule(
                "row-readers".to_string(),
                format!("entity:{entity_id}"),
                Action::Read,
            )
            .await?;
        Ok(())
    }

    /// Raises the replica entity limit for a test with many entities.
    fn raise_replica_limit(fx: &Fixture) {
        fx.runtime.replica_test().set_limit(100);
    }

    macro_rules! get_route {
        ($app:expr, $uri:expr, $token:expr) => {
            actix_test::call_service(
                $app,
                auth(actix_test::TestRequest::get().uri($uri), $token).to_request(),
            )
        };
    }

    macro_rules! delete_route {
        ($app:expr, $uri:expr, $token:expr) => {
            actix_test::call_service(
                $app,
                auth(actix_test::TestRequest::delete().uri($uri), $token).to_request(),
            )
        };
    }

    macro_rules! post_replica {
        ($app:expr, $token:expr) => {
            actix_test::call_service(
                $app,
                auth(
                    actix_test::TestRequest::post().uri("/eav/sync/replica"),
                    $token,
                )
                .to_request(),
            )
        };
    }

    macro_rules! get_oxkv_manifest {
        ($app:expr, $token:expr) => {{
            let res = get_route!($app, "/eav/sync/oxkv/manifest.json", $token).await;
            assert_eq!(res.status(), http::StatusCode::OK);
            let body: ReplicaManifest = actix_test::read_body_json(res).await;
            body
        }};
    }

    macro_rules! get_oxkv_object {
        ($app:expr, $token:expr, $key:expr) => {{
            let uri = format!("/eav/sync/oxkv/objects/{}", $key);
            let res = get_route!($app, &uri, $token).await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            assert_eq!(
                res.headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/octet-stream"),
                "{uri}"
            );
            actix_test::read_body(res).await.to_vec()
        }};
    }

    /// Fetches every object of a wrapper and checks its size and SHA-256.
    macro_rules! fetch_oxkv_objects {
        ($app:expr, $token:expr, $manifest:expr) => {{
            let mut objects = Vec::with_capacity($manifest.objects.len());
            for object in &$manifest.objects {
                let bytes = get_oxkv_object!($app, $token, &object.key);
                assert_eq!(
                    bytes.len() as u64,
                    object.size,
                    "size mismatch for {}",
                    object.key
                );
                let hash: String = Sha256::digest(&bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(hash, object.sha256, "hash mismatch for {}", object.key);
                objects.push((object.key.clone(), bytes));
            }
            objects
        }};
    }

    /// Opens a replica the way the WASM client does.
    async fn open_oxkv_reader(objects: Vec<(String, Vec<u8>)>) -> anyhow::Result<oxkv::OxKvReader> {
        let storage = Arc::new(MemStorage::new());
        for (key, bytes) in objects {
            storage
                .put_opts(&ObjectPath::from(key.as_str()), bytes, PutMode::Create)
                .await?;
        }
        Ok(OxKvStore::builder()
            .with_store(storage)
            .with_prefix(ObjectPath::default())
            .build_reader()
            .await?)
    }

    /// Returns every key under `prefix` in a reader.
    async fn reader_keys(reader: &oxkv::OxKvReader, prefix: &str) -> anyhow::Result<Vec<String>> {
        let rows = reader
            .gets_bytes(
                Some(1000),
                Direction::Next,
                (
                    Some(prefix.to_string()),
                    KeyPrefix::new(prefix).upper_bound(),
                ),
            )
            .await?;
        Ok(rows.into_iter().map(|row| row.key).collect())
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

    #[test]
    fn a_scan_window_never_passes_the_head() {
        assert_eq!(window_end(1, 10, 2), 2);
        assert_eq!(window_end(9, 10, 2), 10);
        assert_eq!(window_end(10, 10, 2), 10);
        assert_eq!(window_end(1, 1, 256), 1);
        assert_eq!(window_end(u64::MAX - 1, u64::MAX, 256), u64::MAX);
    }

    #[test]
    fn a_full_scan_window_holds_exactly_the_batch() {
        let start = 3;
        let end = window_end(start, 100, 4);
        assert_eq!(end - start + 1, 4);
        assert_eq!(window_end(start, 100, 1), start);
    }

    /// Reads one page of the events feed and returns its body.
    macro_rules! read_page {
        ($app:expr, $token:expr, $since:expr, $limit:expr) => {{
            let uri = format!("/eav/sync/events?limit={}&since={}", $limit, $since);
            let res = get_route!($app, &uri, $token).await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let body: Value = actix_test::read_body_json(res).await;
            Ok::<Value, anyhow::Error>(body)
        }};
    }

    #[actix_web::test]
    async fn a_limit_pages_every_visible_event_once() -> anyhow::Result<()> {
        let fx = fixture().await?;
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            append_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let head = fx.runtime.wal().head().await?;

        let first = read_page!(&app, &token, 0, 2)?;
        let listed = first["events"].as_array().expect("events");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["event"]["entity_id"], "e1");
        assert_eq!(listed[1]["event"]["entity_id"], "e2");
        assert_eq!(first["next"], 2);
        assert_eq!(first["head"], head);

        let mut since = 2;
        let mut ids = vec!["e1".to_string(), "e2".to_string()];
        loop {
            let body = read_page!(&app, &token, since, 2)?;
            for event in body["events"].as_array().expect("events") {
                ids.push(
                    event["event"]["entity_id"]
                        .as_str()
                        .expect("id")
                        .to_string(),
                );
            }
            let next = body["next"].as_u64().expect("next");
            if next == since {
                break;
            }
            assert!(next > since, "since={since} next={next}");
            since = next;
        }

        assert_eq!(ids, ["e1", "e2", "e3", "e4", "e5"]);
        assert_eq!(since, head);
        Ok(())
    }

    #[actix_web::test]
    async fn a_feed_longer_than_one_window_pages_to_the_head() -> anyhow::Result<()> {
        let fx = fixture().await?;
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            append_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let head = fx.runtime.wal().head().await?;
        assert!(head > EVENT_SCAN_BATCH as u64);

        let mut since = 0;
        let mut seqs = Vec::new();
        loop {
            let body = read_page!(&app, &token, since, 1)?;
            let listed = body["events"].as_array().expect("events");
            assert!(listed.len() <= 1);
            for event in listed {
                seqs.push(event["seq"].as_u64().expect("seq"));
            }
            let next = body["next"].as_u64().expect("next");
            if next == since {
                break;
            }
            assert!(next > since, "since={since} next={next}");
            since = next;
        }

        assert_eq!(seqs, [1, 2, 3, 4, 5]);
        assert_eq!(since, head);
        Ok(())
    }

    #[actix_web::test]
    async fn a_row_grant_pages_across_a_window_boundary() -> anyhow::Result<()> {
        let fx = fixture().await?;
        for id in ["e1", "e2", "e3", "e4", "e5", "e6"] {
            append_entity(&fx, id).await?;
        }
        grant_row_read(&fx, "carol", "e3").await?;
        grant_row_read(&fx, "carol", "e5").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("carol")?;
        let head = fx.runtime.wal().head().await?;

        let first = read_page!(&app, &token, 0, 2)?;
        let listed = first["events"].as_array().expect("events");
        let ids: Vec<&str> = listed
            .iter()
            .map(|event| event["event"]["entity_id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["e3", "e5"]);
        assert_eq!(first["next"], 5);

        let second = read_page!(&app, &token, 5, 2)?;
        assert_eq!(second["events"].as_array().map(Vec::len), Some(0));
        assert_eq!(second["next"], head);
        assert_eq!(second["head"], head);
        Ok(())
    }

    #[actix_web::test]
    async fn a_cursor_at_the_head_returns_an_empty_page() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_entity(&fx, "e1").await?;
        append_entity(&fx, "e2").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let head = fx.runtime.wal().head().await?;

        let body = read_page!(&app, &token, head, 1)?;
        assert_eq!(body["events"].as_array().map(Vec::len), Some(0));
        assert_eq!(body["next"], head);
        assert_eq!(body["head"], head);
        Ok(())
    }

    #[actix_web::test]
    async fn a_cursor_one_past_the_head_is_409() -> anyhow::Result<()> {
        let fx = fixture().await?;
        append_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        let head = fx.runtime.wal().head().await?;

        let res = get_route!(
            &app,
            format!("/eav/sync/events?since={}", head + 1).as_str(),
            &token
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::CONFLICT);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("conflict"));
        Ok(())
    }

    #[actix_web::test]
    async fn a_repeat_request_at_next_does_not_repeat_an_event() -> anyhow::Result<()> {
        let fx = fixture().await?;
        for id in ["e1", "e2", "e3"] {
            append_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let first = read_page!(&app, &token, 0, 2)?;
        assert_eq!(first["next"], 2);
        let again = read_page!(&app, &token, 0, 2)?;
        assert_eq!(again, first);

        let rest = read_page!(&app, &token, 2, 2)?;
        let listed = rest["events"].as_array().expect("events");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["seq"], 3);
        assert_eq!(rest["next"], 3);
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
        assert!(res.headers().get(ETAG).is_none(), "snapshot sets no ETag");
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
    async fn a_snapshot_paging_sequence_keeps_one_head() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = get_route!(&app, "/eav/sync/snapshot?limit=1", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let first: Value = actix_test::read_body_json(res).await;
        let head = first["head"].as_u64().expect("head");
        assert_eq!(first["next_offset"], 1);

        create_entity(&fx, "e4").await?;
        assert!(fx.runtime.wal().head().await? > head);

        let uri = format!("/eav/sync/snapshot?limit=1&offset=1&head={head}");
        let res = get_route!(&app, &uri, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
        let second: Value = actix_test::read_body_json(res).await;
        assert_eq!(second["head"], head, "page 2 kept the pinned head");
        assert_eq!(second["next_offset"], 2);
        assert_eq!(second["items"][0]["id"], "e2");

        let uri = format!("/eav/sync/snapshot?limit=1&offset=2&head={head}");
        let res = get_route!(&app, &uri, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
        let third: Value = actix_test::read_body_json(res).await;
        assert_eq!(third["head"], head, "page 3 kept the pinned head");

        let current = fx.runtime.wal().head().await?;
        let uri = format!("/eav/sync/snapshot?head={}", current + 1);
        let res = get_route!(&app, &uri, &token).await;
        assert_eq!(res.status(), http::StatusCode::CONFLICT, "{uri}");
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("conflict"));
        Ok(())
    }

    #[actix_web::test]
    async fn a_snapshot_cursor_pages_through_every_visible_entity_once() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let mut ids = Vec::new();
        let mut after: Option<String> = Some(String::new());
        let mut head: Option<u64> = None;
        let mut first = true;
        loop {
            let mut uri = match &after {
                Some(cursor) => format!("/eav/sync/snapshot?limit=1&after={cursor}"),
                None => "/eav/sync/snapshot?limit=1".to_string(),
            };
            if let Some(head) = head {
                uri.push_str(&format!("&head={head}"));
            }
            let res = get_route!(&app, &uri, &token).await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let body: Value = actix_test::read_body_json(res).await;
            assert!(body["next_offset"].is_null(), "{uri}");
            let page_ids: Vec<&str> = body["items"]
                .as_array()
                .expect("items")
                .iter()
                .map(|item| item["id"].as_str().expect("id"))
                .collect();
            if first {
                assert_eq!(page_ids, vec!["e1"], "{uri}");
                assert_eq!(body["next"], "e1", "{uri}");
                head = Some(body["head"].as_u64().expect("head"));
                first = false;
            } else {
                assert_eq!(body["head"], head.expect("head"), "{uri}");
            }
            ids.extend(page_ids.iter().map(|id| id.to_string()));
            match body["next"].as_str() {
                Some(cursor) => after = Some(cursor.to_string()),
                None => break,
            }
        }

        assert_eq!(ids, vec!["e1", "e2", "e3"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_row_grant_snapshot_pages_every_visible_entity_once() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            create_entity(&fx, id).await?;
        }
        for id in ["e2", "e4"] {
            grant_row_read(&fx, "carol", id).await?;
        }
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("carol")?;

        let mut ids = Vec::new();
        let mut after: Option<String> = Some(String::new());
        loop {
            let uri = match &after {
                Some(cursor) => format!("/eav/sync/snapshot?limit=1&after={cursor}"),
                None => "/eav/sync/snapshot?limit=1".to_string(),
            };
            let res = get_route!(&app, &uri, &token).await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let body: Value = actix_test::read_body_json(res).await;
            for item in body["items"].as_array().expect("items") {
                ids.push(item["id"].as_str().expect("id").to_string());
            }
            let next = body["next"].as_str().map(str::to_string);
            if let Some(cursor) = &next {
                assert!(
                    cursor == "e2" || cursor == "e4",
                    "the cursor named an unreadable entity: {cursor}"
                );
            }
            match next {
                Some(cursor) => after = Some(cursor),
                None => break,
            }
        }

        assert_eq!(ids, ["e2", "e4"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_snapshot_scan_reaches_a_visible_row_after_many_invisible_rows() -> anyhow::Result<()>
    {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for index in 1..=8 {
            create_entity(&fx, &format!("n{index:02}")).await?;
        }
        create_entity(&fx, "v1").await?;
        grant_row_read(&fx, "carol", "v1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("carol")?;

        let mut ids = Vec::new();
        let mut after: Option<String> = Some(String::new());
        loop {
            let uri = match &after {
                Some(cursor) => format!("/eav/sync/snapshot?limit=1&after={cursor}"),
                None => "/eav/sync/snapshot?limit=1".to_string(),
            };
            let res = get_route!(&app, &uri, &token).await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let body: Value = actix_test::read_body_json(res).await;
            for item in body["items"].as_array().expect("items") {
                ids.push(item["id"].as_str().expect("id").to_string());
            }
            match body["next"].as_str() {
                Some(cursor) => {
                    assert_eq!(cursor, "v1", "the cursor named an unreadable entity");
                    after = Some(cursor.to_string());
                }
                None => break,
            }
        }

        assert_eq!(ids, ["v1"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_no_grant_snapshot_cursor_returns_no_entity_id() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_entity(&fx, id).await?;
        }
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("bob")?;

        for uri in [
            "/eav/sync/snapshot?limit=1&after=",
            "/eav/sync/snapshot?limit=1&after=e1",
        ] {
            let res = get_route!(&app, uri, &token).await;
            assert_eq!(res.status(), http::StatusCode::OK, "{uri}");
            let body: Value = actix_test::read_body_json(res).await;
            assert_eq!(body["items"].as_array().map(Vec::len), Some(0), "{uri}");
            assert!(body["next"].is_null(), "{uri} leaked a cursor");
        }
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
    async fn a_snapshot_ignores_if_none_match_and_a_revocation_is_fresh() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let head = fx.runtime.wal().head().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        revoke_collection_read(&fx).await?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get()
                    .uri("/eav/sync/snapshot")
                    .insert_header((IF_NONE_MATCH, format!("\"{head}\""))),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert!(res.headers().get(ETAG).is_none(), "snapshot sets no ETag");
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(
            body["items"].as_array().map(Vec::len),
            Some(0),
            "a revoked grant must not return stale data"
        );
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
    async fn an_eav_response_forbids_a_shared_cache() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        for res in [
            get_route!(&app, "/eav/sync/snapshot", &token).await,
            get_route!(&app, "/eav/sync/replica", &token).await,
        ] {
            assert_eq!(res.status(), http::StatusCode::OK);
            assert_eq!(
                res.headers()
                    .get("cache-control")
                    .and_then(|value| value.to_str().ok()),
                Some("no-store"),
                "a shared cache must not store an EAV response"
            );
            assert_eq!(
                res.headers()
                    .get("pragma")
                    .and_then(|value| value.to_str().ok()),
                Some("no-cache")
            );
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
        assert_eq!(body["generation"], 1);
        assert_eq!(body["count"], 2);
        let generation = body["generation"].as_u64().expect("generation");

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert!(
            res.headers().get(ETAG).is_none(),
            "replica read sets no ETag"
        );
        let replica_head = head.to_string();
        assert_eq!(
            res.headers()
                .get("X-Replica-Head")
                .and_then(|v| v.to_str().ok()),
            Some(replica_head.as_str())
        );
        let replica_generation = generation.to_string();
        assert_eq!(
            res.headers()
                .get("X-Replica-Generation")
                .and_then(|v| v.to_str().ok()),
            Some(replica_generation.as_str()),
            "the full read sets X-Replica-Generation"
        );
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["id"], "e1");
        assert_eq!(items[1]["id"], "e2");
        Ok(())
    }

    #[actix_web::test]
    async fn a_full_replica_read_at_the_size_gate_is_allowed_and_one_byte_over_is_400()
    -> anyhow::Result<()> {
        let mut fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
        grant_collection_read(&fx, "alice").await?;
        let (metrics, capture) = MetricCapture::new();
        fx.runtime = fx.runtime.with_metrics(metrics);
        let token = fx.token("alice")?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(capture.counter("eav.replica.builds"), 1);
        assert_eq!(capture.histogram_count("eav.replica.build_duration"), 1);
        let stored = fx
            .runtime
            .replicas()
            .get("alice")
            .await?
            .expect("stored replica");
        let bytes: usize = stored.chunks.iter().map(Vec::len).sum();
        assert!(bytes > 0);

        // A replica that is exactly at the gate is allowed.
        fx.runtime = fx.runtime.with_full_replica_limit(bytes);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);

        // One byte over the gate returns a clear 400 and names chunk mode.
        fx.runtime = fx.runtime.with_full_replica_limit(bytes - 1);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("replica_too_large"));
        assert!(
            body.error.contains("use chunk mode"),
            "the 400 must name chunk mode: {}",
            body.error
        );

        // Chunk mode stays available.
        let res = get_route!(&app, "/eav/sync/replica?chunk=0", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_build_over_the_entity_limit_is_400() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("invalid_request"));
        assert_eq!(body.error, "invalid request");
        assert_eq!(
            ReplicaBuildTooLarge("replica build exceeds the entity limit").to_string(),
            "replica build exceeds the entity limit"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_build_over_the_byte_limit_is_400() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let mut attributes = std::collections::BTreeMap::new();
        attributes.insert(
            "body".to_string(),
            AttributeDef {
                name: "body".to_string(),
                ty: AttributeType::String,
                required: false,
                indexed: false,
                unique: false,
                default: None,
            },
        );
        fx.runtime
            .schemas()
            .publish(SchemaDraft {
                id: "task".to_string(),
                extends: Vec::new(),
                attributes,
            })
            .await?;
        let mut body = std::collections::BTreeMap::new();
        body.insert(
            "body".to_string(),
            AttributeValue::String("x".repeat(REPLICA_BUILD_MAX_BYTES + 1024)),
        );
        fx.runtime
            .entities()
            .create(
                EntityDraft {
                    id: "e1".to_string(),
                    schemas: vec!["task".to_string()],
                    attributes: body,
                },
                &crate::eav::entity::WriteContext::new("alice"),
            )
            .await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;

        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("invalid_request"));
        assert_eq!(
            ReplicaBuildTooLarge("replica build exceeds the byte limit").to_string(),
            "replica build exceeds the byte limit"
        );
        assert_eq!(fx.runtime.replicas().get("alice").await?, None);
        Ok(())
    }

    #[actix_web::test]
    async fn a_rejected_replica_build_keeps_the_old_replica() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let built: Value = actix_test::read_body_json(res).await;
        let old_head = built["head"].as_u64().expect("head");
        let old_generation = built["generation"].as_u64().expect("generation");
        let before = fx
            .runtime
            .replicas()
            .get("alice")
            .await?
            .expect("stored replica");

        create_entity(&fx, "e2").await?;
        create_entity(&fx, "e3").await?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("invalid_request"));

        let after = fx
            .runtime
            .replicas()
            .get("alice")
            .await?
            .expect("stored replica");
        assert_eq!(after, before);
        assert_eq!(after.head, old_head);
        assert_eq!(after.generation, old_generation);

        let res = get_route!(&app, "/eav/sync/replica/status", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["built_head"], old_head);

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "e1");
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_build_at_the_entity_limit_succeeds() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["count"], 2);
        assert_eq!(body["chunks"], 1);
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_build_stops_reading_at_the_entity_limit() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            fx.runtime.replica_test().read(),
            3,
            "the scan must stop at the entity that passes the limit"
        );
        assert!(
            fx.runtime.replica_test().read() < 5,
            "the scan read every entity before it stopped"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_build_stops_reading_at_the_scan_limit_without_a_grant() -> anyhow::Result<()>
    {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for index in 0..=MAX_REPLICA_SCAN_ENTITIES {
            create_entity(&fx, &format!("e{index:02}")).await?;
        }
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;

        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("invalid_request"));
        assert_eq!(
            ReplicaBuildTooLarge("replica build exceeds the scan limit").to_string(),
            "replica build exceeds the scan limit"
        );
        assert_eq!(
            fx.runtime.replica_test().read(),
            MAX_REPLICA_SCAN_ENTITIES + 1,
            "the scan must stop at the entity that passes the scan limit"
        );
        assert_eq!(fx.runtime.replicas().get("alice").await?, None);
        Ok(())
    }

    #[actix_web::test]
    async fn a_row_grant_keeps_the_replica_build_under_the_entity_limit() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            create_entity(&fx, id).await?;
        }
        grant_row_read(&fx, "alice", "e1").await?;
        grant_row_read(&fx, "alice", "e2").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["count"], 2);

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["e1", "e2"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_build_reads_every_cursor_page() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        raise_replica_limit(&fx);
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
        assert_eq!(body["count"], 5);

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec!["e1", "e2", "e3", "e4", "e5"]);
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

        let res = get_route!(&app, "/eav/sync/replica?chunk=0", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert_eq!(
            res.headers()
                .get("X-Replica-Chunks")
                .and_then(|value| value.to_str().ok()),
            Some("0")
        );
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["chunk"], 0);
        assert_eq!(body["chunks"], 0);
        assert_eq!(body["items"].as_array().map(Vec::len), Some(0));
        assert!(body["next"].is_null());
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_read_drops_collection_read_after_revocation() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        raise_replica_limit(&fx);
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
        let built: Value = actix_test::read_body_json(res).await;
        assert_eq!(built["count"], 3);
        let head = built["head"].as_u64().expect("head");

        let res = get_route!(&app, "/eav/sync/replica/status", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["built_head"], head);

        revoke_collection_read(&fx).await?;
        grant_row_read(&fx, "alice", "e1").await?;

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["e1"]);

        let res = get_route!(&app, "/eav/sync/replica/status", &token).await;
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["built_head"], head);

        revoke_row_read(&fx, "e1").await?;
        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        assert!(items.is_empty());

        let stored = fx
            .runtime
            .replicas()
            .get("alice")
            .await?
            .expect("stored replica");
        assert_eq!(stored.head, head);
        let stored_count: usize = stored
            .chunks
            .iter()
            .map(|chunk| {
                serde_json::from_slice::<Vec<Value>>(chunk)
                    .expect("stored chunk")
                    .len()
            })
            .sum();
        assert_eq!(stored_count, 3);
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_chunk_read_drops_collection_read_after_revocation() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3", "e4"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        raise_replica_limit(&fx);
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
        let built: Value = actix_test::read_body_json(res).await;
        assert_eq!(built["chunks"], 2);
        let head = built["head"].as_u64().expect("head");

        revoke_collection_read(&fx).await?;
        grant_row_read(&fx, "alice", "e1").await?;
        grant_row_read(&fx, "alice", "e3").await?;

        let res = get_route!(&app, "/eav/sync/replica?chunk=0", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["head"], head);
        assert_eq!(body["chunk"], 0);
        assert_eq!(body["chunks"], 2);
        assert_eq!(body["next"], 1);
        let items = body["items"].as_array().expect("items");
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["e1"]);

        let res = get_route!(&app, "/eav/sync/replica?chunk=1", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["head"], head);
        assert_eq!(body["chunk"], 1);
        assert_eq!(body["chunks"], 2);
        assert!(body["next"].is_null());
        let items = body["items"].as_array().expect("items");
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["e3"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_read_omits_an_entity_after_a_row_grant_removal() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
        grant_row_read(&fx, "carol", "e1").await?;
        grant_row_read(&fx, "carol", "e2").await?;
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
        let built: Value = actix_test::read_body_json(res).await;
        assert_eq!(built["count"], 2);

        revoke_row_read(&fx, "e2").await?;

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["e1"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_collection_read_user_still_gets_every_replica_entity() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        raise_replica_limit(&fx);
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["e1", "e2", "e3"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_filtered_replica_pages_every_permitted_entity_once() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        raise_replica_limit(&fx);
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
        let built: Value = actix_test::read_body_json(res).await;
        assert_eq!(built["chunks"], 3);

        revoke_collection_read(&fx).await?;
        for id in ["e1", "e3", "e5"] {
            grant_row_read(&fx, "alice", id).await?;
        }

        let mut seen = Vec::new();
        let mut chunk = 0;
        loop {
            let res = get_route!(
                &app,
                format!("/eav/sync/replica?chunk={chunk}").as_str(),
                &token
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK);
            assert_eq!(
                res.headers()
                    .get("X-Replica-Chunk")
                    .and_then(|value| value.to_str().ok()),
                Some(chunk.to_string().as_str())
            );
            assert_eq!(
                res.headers()
                    .get("X-Replica-Chunks")
                    .and_then(|value| value.to_str().ok()),
                Some("3")
            );
            let body: Value = actix_test::read_body_json(res).await;
            for item in body["items"].as_array().expect("items") {
                seen.push(item["id"].as_str().expect("id").to_string());
            }
            match body["next"].as_u64() {
                Some(next) => chunk = next,
                None => break,
            }
        }
        assert_eq!(seen, ["e1", "e3", "e5"]);
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
    async fn a_replica_conditional_read_ignores_if_none_match_and_filters() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
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

        revoke_collection_read(&fx).await?;
        grant_row_read(&fx, "alice", "e1").await?;

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
        assert_eq!(res.status(), http::StatusCode::OK);
        assert!(
            res.headers().get(ETAG).is_none(),
            "replica read sets no ETag"
        );
        let body = actix_test::read_body(res).await;
        let items: Vec<Value> = serde_json::from_slice(&body)?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "e1");
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
        assert!(
            res.headers().get(ETAG).is_none(),
            "replica read sets no ETag"
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
            .put("alice", future, vec![b"newer".to_vec()])
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
            Some(crate::eav::replica::ReplicaSnapshot {
                head: future,
                generation: 1,
                chunks: vec![b"newer".to_vec()],
            })
        );
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_build_stores_chunks_that_page_every_entity_once() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3", "e4", "e5"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        raise_replica_limit(&fx);
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
        let built: Value = actix_test::read_body_json(res).await;
        assert_eq!(built["count"], 5);
        assert_eq!(built["chunks"], 3);
        let generation = built["generation"].as_u64().expect("generation");

        let res = get_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        let ids: Vec<&str> = items
            .iter()
            .map(|item| item["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, ["e1", "e2", "e3", "e4", "e5"]);

        let mut seen = Vec::new();
        let mut chunk = 0;
        loop {
            let res = get_route!(
                &app,
                format!("/eav/sync/replica?chunk={chunk}").as_str(),
                &token
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK);
            assert_eq!(
                res.headers()
                    .get("X-Replica-Chunk")
                    .and_then(|value| value.to_str().ok()),
                Some(chunk.to_string().as_str())
            );
            assert_eq!(
                res.headers()
                    .get("X-Replica-Chunks")
                    .and_then(|value| value.to_str().ok()),
                Some("3")
            );
            assert_eq!(
                res.headers()
                    .get("X-Replica-Generation")
                    .and_then(|value| value.to_str().ok()),
                Some(generation.to_string().as_str()),
                "every chunk of one build has the same generation header"
            );
            let body: Value = actix_test::read_body_json(res).await;
            assert_eq!(body["chunk"], chunk);
            assert_eq!(
                body["generation"], generation,
                "every chunk of one build has the same generation"
            );
            let items = body["items"].as_array().expect("items");
            for item in items {
                seen.push(item["id"].as_str().expect("id").to_string());
            }
            match body["next"].as_u64() {
                Some(next) => chunk = next,
                None => break,
            }
        }
        assert_eq!(seen, ["e1", "e2", "e3", "e4", "e5"]);
        Ok(())
    }

    #[actix_web::test]
    async fn a_rebuild_between_two_chunk_reads_changes_the_generation() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2", "e3"] {
            create_entity(&fx, id).await?;
        }
        grant_collection_read(&fx, "alice").await?;
        raise_replica_limit(&fx);
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
        let head = first["head"].as_u64().expect("head");
        let first_generation = first["generation"].as_u64().expect("generation");
        assert_eq!(first["chunks"], 2);

        let res = get_route!(&app, "/eav/sync/replica?chunk=0", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let first_header = res
            .headers()
            .get("X-Replica-Generation")
            .and_then(|value| value.to_str().ok())
            .expect("generation header")
            .to_string();
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["chunk"], 0);
        assert_eq!(body["generation"], first_generation);

        // A rebuild with no new entity keeps the head and replaces the
        // snapshot at that same head.
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
        let second_generation = second["generation"].as_u64().expect("generation");
        assert_eq!(second_head, head, "the rebuild kept the same head");
        assert!(
            second_generation > first_generation,
            "the rebuild must increment the generation"
        );

        let res = get_route!(&app, "/eav/sync/replica?chunk=1", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let second_header = res
            .headers()
            .get("X-Replica-Generation")
            .and_then(|value| value.to_str().ok())
            .expect("generation header")
            .to_string();
        let page_head = res
            .headers()
            .get("X-Replica-Head")
            .and_then(|value| value.to_str().ok())
            .expect("head header")
            .to_string();
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["chunk"], 1);
        assert_eq!(body["generation"], second_generation);
        assert_eq!(
            page_head,
            head.to_string(),
            "both pages came from the same head"
        );
        assert_ne!(
            first_header, second_header,
            "the two pages came from two builds"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_chunk_read_rejects_an_out_of_range_index() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;

        let res = get_route!(&app, "/eav/sync/replica?chunk=9", &token).await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.code.as_deref(), Some("invalid_request"));

        let res = get_route!(&app, "/eav/sync/replica?chunk=x", &token).await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_chunk_conditional_read_ignores_if_none_match_and_filters()
    -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;
        actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        )
        .await;

        let res = get_route!(&app, "/eav/sync/replica?chunk=0", &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let head = res
            .headers()
            .get("X-Replica-Head")
            .and_then(|value| value.to_str().ok())
            .expect("head header")
            .to_string();
        let generation = res
            .headers()
            .get("X-Replica-Generation")
            .and_then(|value| value.to_str().ok())
            .expect("generation header")
            .to_string();
        assert!(
            res.headers().get(ETAG).is_none(),
            "replica read sets no ETag"
        );

        revoke_collection_read(&fx).await?;
        grant_row_read(&fx, "alice", "e1").await?;

        let res = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::get()
                    .uri("/eav/sync/replica?chunk=0")
                    .insert_header((IF_NONE_MATCH, format!("\"{head}-0\""))),
                &token,
            )
            .to_request(),
        )
        .await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert!(
            res.headers().get(ETAG).is_none(),
            "replica read sets no ETag"
        );
        assert_eq!(
            res.headers()
                .get("X-Replica-Head")
                .and_then(|value| value.to_str().ok()),
            Some(head.as_str())
        );
        assert_eq!(
            res.headers()
                .get("X-Replica-Generation")
                .and_then(|value| value.to_str().ok()),
            Some(generation.as_str())
        );
        let body: Value = actix_test::read_body_json(res).await;
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "e1");
        assert_eq!(body["chunk"], 0);
        assert_eq!(body["chunks"], 1);
        assert_eq!(
            body["generation"].as_u64().expect("generation").to_string(),
            generation
        );
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_reset_allows_a_build_after_a_stored_higher_head() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let head = fx.runtime.wal().head().await?;
        let stored = serde_json::to_vec(&Vec::<Entity>::new())?;
        fx.runtime
            .replicas()
            .put("alice", head + 5, vec![stored])
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
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["code"], "conflict");

        let res = delete_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        let body = actix_test::read_body(res).await;
        assert!(body.is_empty(), "a reset returns no body");

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
        assert_eq!(body["generation"], 1);
        assert_eq!(body["count"], 1);
        Ok(())
    }

    #[actix_web::test]
    async fn delete_without_a_replica_returns_404() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = delete_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
        assert_eq!(body.error, "not found");
        assert_eq!(body.code.as_deref(), Some("not_found"));
        assert_eq!(fx.runtime.replicas().status("alice").await?, None);
        Ok(())
    }

    #[actix_web::test]
    async fn a_replica_reset_affects_only_the_caller() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        grant_collection_read(&fx, "bob").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice = fx.token("alice")?;
        let bob = fx.token("bob")?;

        for token in [&alice, &bob] {
            let res = actix_test::call_service(
                &app,
                auth(
                    actix_test::TestRequest::post().uri("/eav/sync/replica"),
                    token,
                )
                .to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::OK);
        }

        let res = delete_route!(&app, "/eav/sync/replica", &alice).await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);

        let res = get_route!(&app, "/eav/sync/replica/status", &alice).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert!(body["built_head"].is_null(), "the reset left a head");

        let res = get_route!(&app, "/eav/sync/replica/status", &bob).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["built_head"], body["head"]);

        let res = get_route!(&app, "/eav/sync/replica", &bob).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let items: Vec<Value> = actix_test::read_body_json(res).await;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "e1");
        Ok(())
    }

    #[actix_web::test]
    async fn the_read_and_chunk_routes_return_404_after_a_reset() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        for id in ["e1", "e2"] {
            create_entity(&fx, id).await?;
        }
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

        let res = delete_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);

        for uri in ["/eav/sync/replica", "/eav/sync/replica?chunk=0"] {
            let res = get_route!(&app, uri, &token).await;
            assert_eq!(res.status(), http::StatusCode::NOT_FOUND, "{uri}");
            let body: crate::http::error::ErrorBody = actix_test::read_body_json(res).await;
            assert_eq!(body.code.as_deref(), Some("not_found"), "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn the_oxkv_manifest_lists_only_the_objects_of_the_caller() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        create_entity(&fx, "e2").await?;
        grant_private_row_read(&fx, "alice", "e1").await?;
        grant_private_row_read(&fx, "bob", "e2").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let alice = fx.token("alice")?;
        let bob = fx.token("bob")?;

        for token in [&alice, &bob] {
            let res = post_replica!(&app, token).await;
            assert_eq!(res.status(), http::StatusCode::OK);
        }

        let alice_manifest = get_oxkv_manifest!(&app, &alice);
        let bob_manifest = get_oxkv_manifest!(&app, &bob);
        assert_eq!(alice_manifest.generation, 1);
        assert_eq!(bob_manifest.generation, 1);
        assert_eq!(alice_manifest.head, fx.runtime.wal().head().await?);
        assert!(!alice_manifest.objects.is_empty());
        for key in ["manifest.json", "ownership.json"] {
            assert!(
                alice_manifest
                    .objects
                    .iter()
                    .any(|object| object.key == key),
                "the wrapper must list {key}"
            );
        }

        let alice_objects = fetch_oxkv_objects!(&app, &alice, alice_manifest);
        let bob_objects = fetch_oxkv_objects!(&app, &bob, bob_manifest);
        assert!(
            alice_objects
                .iter()
                .zip(&bob_objects)
                .any(|(left, right)| left.1 != right.1),
            "two users with different entities must get different objects"
        );

        let alice_reader = open_oxkv_reader(alice_objects).await?;
        assert!(
            alice_reader.get_bytes("entity:e1:meta").await?.is_some(),
            "alice must see her own entity"
        );
        assert!(
            alice_reader.get_bytes("entity:e2:meta").await?.is_none(),
            "alice must not see bob's entity"
        );
        assert_eq!(
            reader_keys(&alice_reader, "entity:").await?,
            vec!["entity:e1:meta".to_string()]
        );

        let bob_reader = open_oxkv_reader(bob_objects).await?;
        assert!(
            bob_reader.get_bytes("entity:e2:meta").await?.is_some(),
            "bob must see his own entity"
        );
        assert_eq!(
            reader_keys(&bob_reader, "entity:").await?,
            vec!["entity:e2:meta".to_string()]
        );

        for key in ["missing.json", "0/manifest.json", "../manifest.json"] {
            let uri = format!("/eav/sync/oxkv/objects/{key}");
            let res = get_route!(&app, &uri, &alice).await;
            assert_eq!(
                res.status(),
                http::StatusCode::NOT_FOUND,
                "a key outside the wrapper must be 404: {uri}"
            );
        }
        Ok(())
    }

    #[actix_web::test]
    async fn an_oxkv_rebuild_increments_the_generation_and_keeps_the_old_manifest()
    -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let first = get_oxkv_manifest!(&app, &token);
        let first_objects = fetch_oxkv_objects!(&app, &token, first);

        create_entity(&fx, "e2").await?;
        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let second = get_oxkv_manifest!(&app, &token);
        assert!(
            second.generation > first.generation,
            "a rebuild must increment the generation"
        );
        assert!(second.head > first.head, "a rebuild must raise the head");

        create_entity(&fx, "e3").await?;
        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
        let after_failure = get_oxkv_manifest!(&app, &token);
        assert_eq!(
            after_failure, second,
            "a failed build must keep the old wrapper"
        );
        let old = fetch_oxkv_objects!(&app, &token, second);
        assert!(
            old.iter().any(|(key, bytes)| first_objects
                .iter()
                .any(|(old_key, old_bytes)| old_key == key && old_bytes != bytes)),
            "a rebuild must replace at least one old object"
        );

        let future = second.head + 100;
        raise_replica_limit(&fx);
        fx.runtime
            .replicas()
            .put("alice", future, vec![b"[]".to_vec()])
            .await?;
        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::CONFLICT);
        let after_stale = get_oxkv_manifest!(&app, &token);
        assert_eq!(
            after_stale, second,
            "a stale head must not replace the wrapper"
        );
        let still_readable = fetch_oxkv_objects!(&app, &token, second);
        assert_eq!(still_readable, old, "the old objects must stay readable");
        Ok(())
    }

    #[actix_web::test]
    async fn an_empty_oxkv_replica_has_no_entity_rows_and_opens() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("bob")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let body: Value = actix_test::read_body_json(res).await;
        assert_eq!(body["count"], 0);

        let manifest = get_oxkv_manifest!(&app, &token);
        assert!(!manifest.objects.is_empty());
        let objects = fetch_oxkv_objects!(&app, &token, manifest);
        let reader = open_oxkv_reader(objects).await?;
        assert!(
            reader_keys(&reader, "entity:").await?.is_empty(),
            "an empty user must have no entity row"
        );
        assert!(
            reader.get_bytes("replica:meta").await?.is_some(),
            "the empty store still has its own marker row"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn oxkv_routes_require_a_session_and_a_replica() -> anyhow::Result<()> {
        let fx = fixture().await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;

        for uri in [
            "/eav/sync/oxkv/manifest.json",
            "/eav/sync/oxkv/objects/manifest.json",
        ] {
            let res = actix_test::call_service(
                &app,
                actix_test::TestRequest::get().uri(uri).to_request(),
            )
            .await;
            assert_eq!(res.status(), http::StatusCode::UNAUTHORIZED, "{uri}");
        }

        let token = fx.token("alice")?;
        for uri in [
            "/eav/sync/oxkv/manifest.json",
            "/eav/sync/oxkv/objects/manifest.json",
        ] {
            let res = get_route!(&app, uri, &token).await;
            assert_eq!(res.status(), http::StatusCode::NOT_FOUND, "{uri}");
        }
        Ok(())
    }

    #[actix_web::test]
    async fn an_oxkv_reset_removes_the_manifest_and_the_objects() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let manifest = get_oxkv_manifest!(&app, &token);
        let key = manifest
            .objects
            .first()
            .expect("the wrapper lists an object")
            .key
            .clone();

        let res = delete_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);

        let res = get_route!(&app, "/eav/sync/oxkv/manifest.json", &token).await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        let uri = format!("/eav/sync/oxkv/objects/{key}");
        let res = get_route!(&app, &uri, &token).await;
        assert_eq!(res.status(), http::StatusCode::NOT_FOUND);
        Ok(())
    }

    #[actix_web::test]
    async fn a_reset_clears_an_oxkv_only_replica() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert!(fx.runtime.replicas().clear("alice").await?);
        assert!(fx.runtime.replicas().status("alice").await?.is_none());
        assert!(fx.runtime.oxkv().manifest("alice").await?.is_some());

        let res = delete_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        assert!(fx.runtime.replicas().status("alice").await?.is_none());
        assert!(fx.runtime.oxkv().manifest("alice").await?.is_none());
        Ok(())
    }

    #[actix_web::test]
    async fn a_reset_clears_a_json_only_replica() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        assert!(fx.runtime.oxkv().clear("alice").await?);
        assert!(fx.runtime.oxkv().manifest("alice").await?.is_none());
        assert!(fx.runtime.replicas().status("alice").await?.is_some());

        let res = delete_route!(&app, "/eav/sync/replica", &token).await;
        assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
        assert!(fx.runtime.replicas().status("alice").await?.is_none());
        assert!(fx.runtime.oxkv().manifest("alice").await?.is_none());
        Ok(())
    }

    #[actix_web::test]
    async fn a_reset_waits_for_a_build_and_leaves_neither_replica() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let guard = fx.runtime.oxkv().lock_subject("alice").await;
        let build = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::post().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        );
        let reset = actix_test::call_service(
            &app,
            auth(
                actix_test::TestRequest::delete().uri("/eav/sync/replica"),
                &token,
            )
            .to_request(),
        );
        let release = async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(guard);
        };
        let (build_res, reset_res, ()) = tokio::join!(build, reset, release);

        assert_eq!(build_res.status(), http::StatusCode::OK);
        assert_eq!(reset_res.status(), http::StatusCode::NO_CONTENT);
        assert!(fx.runtime.replicas().status("alice").await?.is_none());
        assert!(fx.runtime.oxkv().manifest("alice").await?.is_none());
        Ok(())
    }

    #[actix_web::test]
    async fn a_failed_oxkv_publish_keeps_the_old_wrapper_and_the_next_build_reconciles()
    -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let first = get_oxkv_manifest!(&app, &token);
        let first_objects = fetch_oxkv_objects!(&app, &token, first);

        fx.runtime.oxkv().fail_next_publish();
        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::CONFLICT);
        let after_failure = get_oxkv_manifest!(&app, &token);
        assert_eq!(
            after_failure, first,
            "a failed publish must keep the old wrapper"
        );
        assert_eq!(
            fetch_oxkv_objects!(&app, &token, first),
            first_objects,
            "a failed publish must keep the old objects readable"
        );

        let stored = fx
            .runtime
            .replicas()
            .get("alice")
            .await?
            .expect("the JSON replica committed");
        assert!(
            stored.generation > first.generation,
            "the JSON replica advanced before the failed publish"
        );

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let built: Value = actix_test::read_body_json(res).await;
        let reconciled = get_oxkv_manifest!(&app, &token);
        assert_eq!(built["generation"], reconciled.generation);
        assert_eq!(built["head"], reconciled.head);
        assert!(
            reconciled.generation > stored.generation,
            "the next build must reconcile to a newer generation"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn the_oxkv_wrapper_matches_the_json_replica_generation_and_head() -> anyhow::Result<()> {
        let fx = fixture().await?;
        publish_task_schema(&fx).await?;
        create_entity(&fx, "e1").await?;
        grant_collection_read(&fx, "alice").await?;
        let module = fx.module().await?;
        let app = actix_test::init_service(App::new().configure(|cfg| module.configure(cfg))).await;
        let token = fx.token("alice")?;

        let res = post_replica!(&app, &token).await;
        assert_eq!(res.status(), http::StatusCode::OK);
        let built: Value = actix_test::read_body_json(res).await;
        let manifest = get_oxkv_manifest!(&app, &token);

        assert_eq!(built["generation"], manifest.generation);
        assert_eq!(built["head"], manifest.head);
        assert_eq!(manifest.generation, 1);
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
        assert!(
            paths["/eav/sync/replica"]["delete"].is_object(),
            "spec missing DELETE /eav/sync/replica"
        );
        assert!(paths.contains_key("/eav/sync/replica/status"));
        assert!(paths.contains_key("/eav/sync/oxkv/manifest.json"));
        assert!(paths.contains_key("/eav/sync/oxkv/objects/{object}"));
        let schemas = spec["components"]["schemas"]
            .as_object()
            .expect("component schemas");
        for name in [
            "EavSyncStatusResponse",
            "SyncEvent",
            "SyncEventsResponse",
            "SyncEventsQuery",
            "SnapshotPage",
            "ReplicaBuildResponse",
            "ReplicaChunkQuery",
            "ReplicaChunkResponse",
            "ReplicaStatusResponse",
            "ReplicaManifest",
            "ReplicaObject",
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
