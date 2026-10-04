//! Cost controls for endpoints whose work is not bounded by the request.
//!
//! # Why rate limiting is not the whole answer
//!
//! `GET /sync/db/{object}` serves a replica object, and a replica prefix
//! holds oxkv's own files -- an SST segment runs to hundreds of megabytes.
//! A token bucket does not help much there: a client allowed 60 requests a
//! minute can still have 60 multi-hundred-megabyte reads in flight at once,
//! and that is the shape that actually hurts. What bounds it is a cap on
//! *concurrency*, so that is the primary control here and
//! [`ConcurrencyGate`](crate::limits::ConcurrencyGate) is the important part of this module.
//!
//! [`TokenBucket`](crate::limits::TokenBucket) still earns its place, for the endpoints where request
//! *rate* is the cost: `POST /sync/sync` fans out into store scans, and
//! `/auth/login` is an outbound round trip to the identity provider.
//!
//! # Keying, and what it does not do
//!
//! Buckets are keyed by peer address, not by authenticated subject. The JWT
//! middleware inserts generically-typed claims, so a limiter that keyed on
//! `sub` would need either a bound on the claims type or a second parse of
//! the token to pull one field out. Neither is worth it for a coarse control:
//! the concurrency gate, which is the control that matters for the expensive
//! route, is keyed on nothing at all and so is unaffected.
//!
//! The consequence is honest rather than hidden -- clients behind one NAT
//! share a bucket. That is a fairness property, not a safety one.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use actix_web::{
    Error, HttpResponse, ResponseError,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};

use crate::http::error::ApiError;

/// How long a bucket may go untouched before it is dropped.
///
/// A background floor, not the bound. Ten minutes is far longer than any
/// bucket takes to refill, so a dropped bucket is indistinguishable from a
/// full one -- but an insert path can outrun it: a refused request still
/// inserts (see [`TokenBucket::take`]), so a client with a routed IPv6
/// prefix fills the map faster than the window drains it. The hard bound is
/// [`MAX_TRACKED_PEERS`].
const IDLE_EVICT: Duration = Duration::from_secs(600);

/// Hard ceiling on how many peers are tracked at once.
///
/// The map is keyed by bare peer IP, so its size is chosen by whoever is
/// sending, and it grows BEFORE any budget check: `take` inserts on the way
/// to refusing. [`IDLE_EVICT`] cannot be the only bound because the insert
/// path outruns a ten-minute window with a single burst of distinct source
/// addresses.
///
/// Beyond the cap the LEAST RECENTLY SEEN entry is dropped, rather than the
/// new one being refused: refusing an unseen peer would let an attacker lock
/// every legitimate new client out of the limiter for the life of the
/// process with no way to evict their own entries, and this map exists to
/// bound cost, not to allocate it. Dropping the coldest entry also preserves
/// the property [`peer_key`] exists for -- a peer that is still sending keeps
/// its bucket, and its own budget, instead of being handed a fresh full one
/// by everyone else's rotation.
///
/// A fixed ceiling, not a multiple of the fleet: nothing here can tell a load
/// balancer's pool of legitimate peers from a rotation, and evicting the
/// coldest is a better answer to being wrong in either direction than
/// refusing to track anyone.
const MAX_TRACKED_PEERS: usize = 4096;

/// A token bucket per key.
///
/// Refills continuously rather than in steps, so a client that waits does not
/// have to wait for a whole window to reopen, and a client that bursts is
/// capped at `capacity` rather than at `capacity * window`.
#[derive(Clone)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Arc<Mutex<HashMap<String, BucketState>>>,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

/// Drops the coldest entries until there is room for one more.
///
/// Evicts by `last`, so the peer that is still sending keeps its bucket.
/// Doing this only when a NEW key arrives is what keeps the cost off the
/// common path: a repeat request from a tracked peer does not scan at all.
fn make_room(buckets: &mut HashMap<String, BucketState>) {
    while buckets.len() >= MAX_TRACKED_PEERS {
        let Some(coldest) = buckets
            .iter()
            .min_by_key(|(_, b)| b.last)
            .map(|(k, _)| k.clone())
        else {
            // Unreachable: an empty map is under the cap, and the cap is a
            // non-zero constant. Written rather than unwrapped because the
            // crate denies `unwrap`.
            return;
        };
        buckets.remove(&coldest);
    }
}

impl TokenBucket {
    /// `capacity` requests may burst, refilling at `per_minute` / 60 per
    /// second.
    ///
    /// `per_minute == 0` disables the limiter, which is the documented way to
    /// turn it off for a trusted deployment.
    pub fn new(capacity: u32, per_minute: u32) -> Self {
        let capacity = f64::from(capacity);
        Self {
            capacity,
            refill_per_sec: f64::from(per_minute) / 60.0,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// True when the limiter is not doing anything.
    pub fn is_disabled(&self) -> bool {
        self.refill_per_sec == 0.0
    }

    /// Takes one token for `key`, or reports the caller is over budget.
    ///
    /// Inserts BEFORE deciding, so a refused request from a never-seen
    /// address still grows the map. That is deliberate in one direction --
    /// the alternative lets a client retry into a fresh full bucket -- and
    /// is exactly why [`MAX_TRACKED_PEERS`] exists rather than a cap on
    /// spendable tokens.
    pub fn take(&self, key: &str) -> bool {
        if self.is_disabled() {
            return true;
        }
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);

        // Room is made only for a NEW key: an already-tracked entry must keep
        // its tokens and its `last`, so this must not run for it or every
        // repeat request would evict a bystander.
        if !buckets.contains_key(key) {
            make_room(&mut buckets);
        }
        let state = buckets.entry(key.to_string()).or_insert(BucketState {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(state.last).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        state.last = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Tokens `key` could still spend, for tests and diagnostics.
    #[cfg(test)]
    pub fn available(&self, key: &str) -> f64 {
        self.buckets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .map_or(self.capacity, |b| b.tokens)
    }

    /// Drops buckets untouched for the idle window (ten minutes).
    ///
    /// Called on the request path rather than from a timer: a timer would be
    /// another background task to own and shut down. The scan is bounded by
    /// [`MAX_TRACKED_PEERS`], because the map cannot be larger than the cap
    /// -- which is what makes running it per request acceptable, rather than
    /// the amortisation argument the old comment made. That argument was
    /// inverted: entries are inserted before the budget check, so the map
    /// grows with REFUSED requests too, not only with new peers.
    ///
    /// Returns immediately when disabled, which is what makes it acceptable to
    /// leave the middleware installed with a zero limit -- the default -- since
    /// a disabled bucket then costs one atomic load per request and no lock.
    pub fn evict_idle(&self) {
        if self.is_disabled() {
            return;
        }
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        buckets.retain(|_, b| now.duration_since(b.last) < IDLE_EVICT);
    }

    /// Number of tracked keys, for tests.
    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Caps how many expensive operations may be in flight at once.
///
/// This is the control that bounds the real cost of the replica gateway. A
/// permit is held by the response *body*, not by the handler, so it is
/// released when the download actually finishes rather than when the handler
/// returns: with the permit scoped to the handler, a client that opened a
/// stream and then stopped reading would have given its slot back while still
/// holding the memory.
#[derive(Clone)]
pub struct ConcurrencyGate {
    /// `None` disables the gate. It cannot be expressed as a zero-permit
    /// semaphore, because that refuses everything -- the opposite of off.
    max: Option<usize>,
    permits: Arc<tokio::sync::Semaphore>,
}

impl ConcurrencyGate {
    /// A gate allowing `max` concurrent operations.
    ///
    /// `max == 0` disables the gate, documented for trusted deployments.
    pub fn new(max: usize) -> Self {
        match max {
            0 => Self {
                max: None,
                permits: Arc::new(tokio::sync::Semaphore::new(0)),
            },
            n => Self {
                max: Some(n),
                permits: Arc::new(tokio::sync::Semaphore::new(n)),
            },
        }
    }

    /// True when the gate is not doing anything.
    pub fn is_disabled(&self) -> bool {
        self.max.is_none()
    }

    /// Takes a permit, or `None` when the caller must wait.
    ///
    /// `None` is overloaded: it means "no slot" when the gate is enabled and
    /// "no gate" when it is disabled, so callers distinguish with
    /// [`is_disabled`](Self::is_disabled) rather than by inspecting this.
    pub fn acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        if self.is_disabled() {
            return None;
        }
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }
}

/// Key for a peer: address only, no port, so a client reconnecting does not
/// get a fresh budget.
pub fn peer_key(addr: Option<std::net::SocketAddr>) -> String {
    match addr.map(|a| a.ip()) {
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => v6.to_string(),
        // No peer address (in-process tests, or a trusted proxy that did not
        // forward one). One shared bucket is the conservative choice: it caps
        // the fleet rather than exempting it.
        None => "unknown".to_string(),
    }
}

/// Rejects a request with the uniform envelope when a limit is hit.
pub fn too_many(what: &str) -> HttpResponse {
    tracing::warn!("rate limited: {what}");
    // `ResponseError` is what renders the uniform envelope, so the limited
    // response is byte-identical in shape to every other error.
    ResponseError::error_response(&ApiError::TooManyRequests)
}

/// Wraps a stream so a concurrency permit is held for as long as it is.
///
/// The permit is released on drop, which covers all three endings: the
/// download completing, the client disconnecting mid-stream, and the task
/// being cancelled at shutdown. A separate release path would miss at least
/// one of them.
///
/// A `Stream` rather than a `MessageBody` because actix blanket-implements
/// `MessageBody` for streams, which keeps this free of `unsafe` pinning in a
/// crate that denies `unwrap` and `expect`.
pub struct GatedStream<S> {
    /// Boxed so the wrapper is `Unpin` whatever the stream is, which keeps the
    /// `poll_next` below free of `unsafe` projection.
    inner: std::pin::Pin<Box<S>>,
    /// Dropped with the stream, releasing the slot.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl<S> GatedStream<S> {
    /// Wraps `inner`, holding `permit` until the wrapper is dropped.
    pub fn new(inner: S, permit: Option<tokio::sync::OwnedSemaphorePermit>) -> Self {
        Self {
            inner: Box::pin(inner),
            _permit: permit,
        }
    }
}

impl<S, B, E> futures_util::Stream for GatedStream<S>
where
    S: futures_util::Stream<Item = Result<B, E>>,
{
    type Item = Result<B, E>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // `Self` is `Unpin` -- a pinned box and an `Option` of one -- so this
        // is a plain mutable borrow.
        let this = self.get_mut();
        this.inner.as_mut().poll_next(cx)
    }
}

/// Actix middleware enforcing a [`TokenBucket`] before the handler runs.
///
/// Applied outermost, so it also covers the routes no subject-keyed limiter
/// could reach: `/auth/login`, which is an outbound round trip to the
/// identity provider, and `/health`, which a load balancer polls hard.
pub struct RateLimit {
    bucket: TokenBucket,
}

impl RateLimit {
    /// Wraps `bucket` for use as middleware.
    pub fn new(bucket: TokenBucket) -> Self {
        Self { bucket }
    }
}

/// The installed limiter. See [`RateLimit`].
pub struct RateLimitMiddleware<S> {
    service: std::rc::Rc<S>,
    bucket: TokenBucket,
}

impl<S, B> Transform<S, ServiceRequest> for RateLimit
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B, actix_web::body::BoxBody>>;
    type Error = Error;
    type Transform = RateLimitMiddleware<S>;
    type InitError = ();
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Transform, ()>>>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let bucket = self.bucket.clone();
        Box::pin(async move {
            Ok(RateLimitMiddleware {
                service: std::rc::Rc::new(service),
                bucket,
            })
        })
    }
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: actix_web::body::MessageBody + 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B, actix_web::body::BoxBody>>;
    type Error = Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = std::rc::Rc::clone(&self.service);
        // Both of these ride along on the request path under the one mutex
        // `take` also needs, so their cost is paid by every worker in the
        // process -- including by peers that are over budget and here only
        // to be refused. The map is capped at `MAX_TRACKED_PEERS` on insert,
        // and that cap is what bounds both the scan and the eviction it
        // performs.
        self.bucket.evict_idle();
        if self.bucket.take(&peer_key(req.peer_addr())) {
            let fut = service.call(req);
            Box::pin(async move { fut.await.map(ServiceResponse::map_into_left_body) })
        } else {
            Box::pin(async move {
                Ok(req.into_response(too_many("api").map_into_boxed_body().map_into_right_body()))
            })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_alls_its_burst_then_refuses() {
        let bucket = TokenBucket::new(3, 60);
        assert!(bucket.take("a"));
        assert!(bucket.take("a"));
        assert!(bucket.take("a"));
        assert!(!bucket.take("a"), "burst is capped at capacity");
    }

    #[test]
    fn buckets_are_per_key() {
        let bucket = TokenBucket::new(1, 60);
        assert!(bucket.take("a"));
        assert!(!bucket.take("a"), "a is out");
        assert!(bucket.take("b"), "b is unaffected by a");
    }

    /// A full bucket must not accumulate tokens while idle, or a client that
    /// waits an hour gets a burst proportional to the wait.
    #[test]
    fn refill_is_capped_at_capacity() {
        let bucket = TokenBucket::new(2, 600_000);
        assert!(bucket.take("a"));
        assert!(bucket.take("a"));
        assert!(!bucket.take("a"));
        // Move the clock forward rather than sleeping: `last` is what the
        // refill is computed from.
        let mut buckets = bucket.buckets.lock().unwrap();
        let state = buckets.get_mut("a").expect("bucket exists");
        state.last -= Duration::from_secs(3600);
        drop(buckets);
        assert!(
            bucket.available("a") <= 2.0,
            "refill must not exceed capacity, got {}",
            bucket.available("a")
        );
    }

    #[test]
    fn a_disabled_bucket_never_refuses() {
        let bucket = TokenBucket::new(1, 0);
        assert!(bucket.is_disabled());
        for _ in 0..1000 {
            assert!(bucket.take("a"));
        }
    }

    #[test]
    fn idle_buckets_are_evicted_so_the_map_cannot_grow_without_bound() {
        let bucket = TokenBucket::new(10, 60);
        for i in 0..100 {
            bucket.take(&format!("peer-{i}"));
        }
        assert_eq!(bucket.tracked(), 100);
        // Nothing has been idle for ten minutes, so eviction must be a no-op
        // here rather than dropping live buckets on every request.
        bucket.evict_idle();
        assert_eq!(bucket.tracked(), 100);

        // Age every entry past the window instead of sleeping ten minutes:
        // `last` is the only thing `evict_idle` reads.
        let mut buckets = bucket.buckets.lock().unwrap();
        for state in buckets.values_mut() {
            state.last -= IDLE_EVICT + Duration::from_secs(1);
        }
        drop(buckets);
        bucket.evict_idle();
        assert_eq!(
            bucket.tracked(),
            0,
            "entries untouched for longer than the window must be dropped"
        );
    }

    /// The map is bounded by COUNT, not only by idle time.
    ///
    /// This is the regression: `evict_idle` was the only bound, and its
    /// amortisation argument was inverted. `take` inserts on the way to
    /// REFUSING, so a client rotating through a routed IPv6 prefix grows
    /// the map with every request it is turned away for -- and nothing is
    /// dropped for ten minutes. Reaching the cap here needs
    /// `MAX_TRACKED_PEERS + 500` distinct keys rather than a ten-minute
    /// wait, which is the shape the old code could not survive: it asserted
    /// only that eviction left a freshly-filled map alone, which is true
    /// whether or not the map is bounded at all.
    ///
    /// Fails on the pre-fix code with `tracked() == MAX_TRACKED_PEERS + 500`.
    #[test]
    fn the_map_stays_bounded_when_peers_outrun_the_idle_window() {
        let bucket = TokenBucket::new(1, 60);
        for i in 0..MAX_TRACKED_PEERS + 500 {
            // Most of these are REFUSED: capacity 1, one call per key, so the
            // first key drains its bucket and the rest are all over budget --
            // which is the path that inserts and is therefore the one the
            // bound has to cover.
            bucket.take(&format!("peer-{i}"));
            bucket.evict_idle();
        }
        assert!(
            bucket.tracked() <= MAX_TRACKED_PEERS,
            "tracked {} peers past a cap of {MAX_TRACKED_PEERS}",
            bucket.tracked(),
        );
    }

    /// The cap evicts the COLDEST entry, so an active peer is not punished
    /// for someone else's rotation.
    ///
    /// Refusing the new key instead would hand any attacker who fills the map
    /// a way to lock every legitimate first-time client out of the limiter for
    /// the life of the process.
    #[test]
    fn the_cap_evicts_the_coldest_peer_not_the_new_one() {
        let bucket = TokenBucket::new(10, 60);
        bucket.take("cold");
        {
            let mut buckets = bucket.buckets.lock().unwrap();
            buckets.get_mut("cold").expect("bucket exists").last -= Duration::from_secs(3600);
        }
        // Fill to the cap so "cold" is the only candidate, then overflow once.
        for i in 0..MAX_TRACKED_PEERS - 1 {
            bucket.take(&format!("peer-{i}"));
        }
        assert_eq!(bucket.tracked(), MAX_TRACKED_PEERS);
        assert!(bucket.take("newcomer"));
        assert!(
            bucket.available("newcomer") < 10.0,
            "the new peer must be tracked, not refused for lack of room"
        );
        assert_eq!(
            bucket.tracked(),
            MAX_TRACKED_PEERS,
            "and the map must not have grown past the cap"
        );
    }

    /// A peer that is ALREADY tracked is not evicted by its own repeat
    /// request, and keeps its budget across the overflow.
    ///
    /// Room is made before the insert, so an implementation that does not
    /// check for an existing key evicts a bystander on every single request
    /// once the map is at the cap -- turning the limiter into a source of
    /// free budget for anyone sending fast enough.
    #[test]
    fn a_tracked_peer_keeps_its_budget_across_the_overflow() {
        let bucket = TokenBucket::new(10, 60);
        for i in 0..MAX_TRACKED_PEERS {
            bucket.take(&format!("peer-{i}"));
        }
        assert!(bucket.take("busy"), "first request spends a token");
        for _ in 0..200 {
            bucket.take("busy");
        }
        assert_eq!(
            bucket.tracked(),
            MAX_TRACKED_PEERS,
            "repeat requests must not evict anything"
        );
        assert!(
            bucket.available("busy") < 10.0,
            "a tracked peer must keep accruing its own debt, not be handed \
             fresh tokens by evicting itself"
        );
    }

    #[tokio::test]
    async fn a_gate_refuses_past_its_limit() {
        let gate = ConcurrencyGate::new(2);
        let first = gate.acquire().expect("slot 1");
        let second = gate.acquire().expect("slot 2");
        assert!(gate.acquire().is_none(), "third must wait");
        drop(first);
        assert!(gate.acquire().is_some(), "a released slot is reusable");
        drop(second);
    }

    #[tokio::test]
    async fn a_gated_stream_holds_its_slot_for_the_bodys_lifetime() {
        let gate = ConcurrencyGate::new(1);
        let permit = gate.acquire().expect("slot");
        let gated = GatedStream::new(
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(bytes::Bytes::from("a"))]),
            Some(permit),
        );

        // While the body is alive the slot is gone. This is the half that
        // matters: a gate that released on handler return would let a client
        // open a stream, stop reading, and walk away with the memory still
        // resident -- the permit would look returned while the slot was not
        // actually bounding anything.
        assert!(
            gate.acquire().is_none(),
            "the slot must be held while the body exists"
        );

        // Dropping mid-stream is the other half: a client that opened a read
        // and disconnected must still give the slot back, or the gate slowly
        // wedges as dead reads accumulate.
        drop(gated);
        assert!(
            gate.acquire().is_some(),
            "the slot must come back when the body is dropped"
        );
    }

    #[tokio::test]
    async fn a_disabled_gate_never_refuses() {
        let gate = ConcurrencyGate::new(0);
        assert!(gate.is_disabled());
        for _ in 0..100 {
            assert!(gate.acquire().is_none(), "no permit, and no refusal either");
        }
    }

    #[test]
    fn peer_key_ignores_the_port() {
        use std::net::SocketAddr;
        let a: SocketAddr = "10.0.0.1:1234".parse().expect("addr");
        let b: SocketAddr = "10.0.0.1:9999".parse().expect("addr");
        assert_eq!(peer_key(Some(a)), peer_key(Some(b)));
        assert_ne!(
            peer_key(Some(a)),
            peer_key(Some("10.0.0.2:1234".parse().expect("addr")))
        );
    }

    /// The envelope is the same one every other error uses, so a client that
    /// parses errors does not need a special case for being limited.
    ///
    /// The status code alone does not establish that, and this test used to
    /// assert nothing else. `too_many` was free to return
    /// `HttpResponse::TooManyRequests().finish()` -- a bare 429 with no body
    /// at all -- and this stayed green, which is exactly the duplication
    /// `http::error::tests::the_envelope_has_one_construction_site` exists
    /// to rule out. That guard is structural: it counts files that build the
    /// envelope, so a 429 built outside it is invisible to it, and this is
    /// the behavioural half.
    ///
    /// `RateLimitMiddleware` is the path that matters, so the response is
    /// read through the middleware rather than off `too_many` directly: a
    /// hand-built 429 inside the transform that is not the one `too_many`
    /// returns is the regression worth catching, and only a request can
    /// catch it. `sync::route`'s `FsError::TooManyRequests` path is the
    /// other one, and is asserted there.
    #[actix_web::test]
    async fn the_limit_response_uses_the_uniform_envelope() {
        use actix_web::{App, http::StatusCode, test};

        // Capacity 1: the first request spends the token and the second is
        // over budget. No peer address on an in-process request, so both
        // land in the same bucket via `peer_key(None)`.
        let app = test::init_service(
            App::new()
                .wrap(RateLimit::new(TokenBucket::new(1, 60)))
                .route("/", actix_web::web::get().to(|| async { "served" })),
        )
        .await;
        let request = || test::TestRequest::get().uri("/").to_request();

        // The control first: it proves this app serves, so the 429 below is
        // the limiter and not a route that never matched.
        let served = test::call_service(&app, request()).await;
        assert_eq!(served.status(), StatusCode::OK);

        let res = test::call_service(&app, request()).await;
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        let parsed: crate::http::error::ErrorBody =
            serde_json::from_slice(&test::read_body(res).await).expect(
                "the 429 body must deserialize as ErrorBody, i.e. it is the \
                 uniform envelope and not a bare or hand-rolled response",
            );
        assert_eq!(parsed.error, "too many requests");
    }
}
