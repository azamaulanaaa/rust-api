//! Cost controls for endpoints whose work is not bounded by the request.
//!
//! # Why rate limiting is not the whole answer
//!
//! `GET /sync/db/{object}` serves one object of a replica. A replica prefix
//! holds the files of oxkv, and one SST segment reaches hundreds of
//! megabytes. A token bucket does not help much there. A client that is
//! allowed 60 requests a minute can still have 60 reads of hundreds of
//! megabytes at the same time. That is the shape that causes harm. So a cap
//! on *concurrency* is the primary control here.
//! [`ConcurrencyGate`](crate::limits::ConcurrencyGate) is the important part
//! of this module.
//!
//! [`TokenBucket`](crate::limits::TokenBucket) still has a use. It applies to
//! the endpoints where the request *rate* is the cost. An example is
//! `POST /sync/sync`, which starts store scans. Another is `/auth/login`,
//! which makes an outgoing round trip to the identity provider.
//!
//! # Keying, and what it does not do
//!
//! Buckets are keyed by peer address, not by the subject that authenticated.
//! The JWT middleware inserts claims of a type that the caller does not
//! choose. So a limiter that used `sub` as its key would need one of two
//! things:
//!
//! - A bound on the type of the claims.
//! - A second parse of the token to get one field.
//!
//! Neither is worth it for a coarse control. The concurrency gate is the
//! control that matters for the expensive route. Its key is nothing at all,
//! so the choice does not affect it.
//!
//! The result is a fairness property, not a hidden one. Clients behind one
//! NAT share a bucket.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use actix_web::{
    Error, HttpResponse, ResponseError,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};

use crate::http::error::ApiError;

/// How long a bucket may go untouched before the function drops it.
///
/// This duration is a floor, not the bound. Ten minutes is far longer than
/// any bucket takes to fill again. A dropped bucket therefore looks the same
/// as a full one. But an insert path can be faster than the floor. A
/// refused request still inserts, as [`TokenBucket::take`] shows. So a client
/// with a routed IPv6 prefix fills the map faster than the window drains it.
/// The hard bound is [`MAX_TRACKED_PEERS`].
const IDLE_EVICT: Duration = Duration::from_secs(600);

/// How many requests pass between two idle sweeps.
///
/// `make_room` now sets the bound on the map at insert. So this sweep is no
/// longer what keeps the map bounded. The sweep only reclaims memory early.
/// The sweep used to run on every request. Each run then walked up to
/// [`MAX_TRACKED_PEERS`] entries under the one mutex that `take` also needs.
/// That ran for every request, including requests that were over budget and
/// were there only to be refused. A sweep on a fixed cadence keeps the
/// reclamation, and stops the limiter from being the amplifier that it
/// exists to bound.
const IDLE_SWEEP_EVERY: u64 = 64;

/// Highest number of peers that the map tracks at the same time.
///
/// The map is keyed by the bare peer IP. So whoever sends, decides the size
/// of the map. The map grows *before* any check of the budget, because `take`
/// inserts on the way to refusing. [`IDLE_EVICT`] cannot be the only bound,
/// because the insert path is faster than a ten-minute window when a single
/// burst has many different source addresses.
///
/// Past the cap, the function drops the LEAST RECENTLY SEEN entry. The
/// function does not refuse the new one. Refusing an unseen peer would let
/// an attacker lock every valid new client out of the limiter for the life
/// of the process. No client could then remove its own entry. The purpose of
/// this map is to bound cost, not to allocate cost. Dropping the coldest
/// entry also keeps the property that [`peer_key`] exists for. A peer that
/// is still sending keeps its bucket, and keeps its own budget, instead of
/// receiving a new full one from the rotation of other peers.
///
/// This is a fixed ceiling, not a multiple of the size of the fleet. Nothing
/// here can tell the pool of valid peers of a load balancer from an
/// attacker. Removing the coldest entry is the better answer to being wrong
/// in either direction than refusing to track anyone.
const MAX_TRACKED_PEERS: usize = 4096;

/// A token bucket for each key.
///
/// The bucket refills at a steady rate, not in steps. A client that waits
/// does not have to wait for a whole window to open again. A client that
/// bursts is capped at `capacity`, not at `capacity * window`.
#[derive(Clone)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Arc<Mutex<HashMap<String, BucketState>>>,
    /// Requests that were seen since the last idle sweep. The field is a plain
    /// atomic value, not a field under `buckets`, so that the common path
    /// never touches the mutex.
    since_sweep: Arc<AtomicU64>,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

/// Drops the coldest entries until there is room for one more.
///
/// The function removes entries by `last`. So the peer that is still sending
/// keeps its bucket. The function runs only when a NEW key arrives. That is
/// what keeps the cost off the common path. A request that repeats from a
/// tracked peer does not scan the map at all.
fn make_room(buckets: &mut HashMap<String, BucketState>) {
    while buckets.len() >= MAX_TRACKED_PEERS {
        let Some(coldest) = buckets
            .iter()
            .min_by_key(|(_, b)| b.last)
            .map(|(k, _)| k.clone())
        else {
            // The map cannot be empty here, because an empty map is
            // under the cap and the cap is not zero. The code returns
            // instead of calling `unwrap`, because the crate denies
            // `unwrap`.
            return;
        };
        buckets.remove(&coldest);
    }
}

impl TokenBucket {
    /// `capacity` requests may burst. The bucket refills at `per_minute` / 60
    /// per second.
    ///
    /// A value of `per_minute` equal to `0` disables the limiter. That is the
    /// documented way to turn it off in a trusted deployment.
    pub fn new(capacity: u32, per_minute: u32) -> Self {
        let capacity = f64::from(capacity);
        Self {
            capacity,
            refill_per_sec: f64::from(per_minute) / 60.0,
            buckets: Arc::new(Mutex::new(HashMap::new())),
            since_sweep: Arc::new(AtomicU64::new(IDLE_SWEEP_EVERY - 1)),
        }
    }

    /// Whether the periodic idle sweep is due. The function does not take the
    /// lock.
    ///
    /// The answer is true once every [`IDLE_SWEEP_EVERY`] requests.
    /// `fetch_update` sets the counter back to zero in the same step that
    /// claims the sweep. So two workers cannot both believe that they are
    /// the one that is due. At worst, a pair that races loses one sweep.
    /// That is harmless for housekeeping. The counter starts one short of the
    /// threshold, so the first call sweeps. That keeps a process with little
    /// traffic reclaiming memory, instead of never doing so.
    fn sweep_due(&self) -> bool {
        let seen = self.since_sweep.fetch_add(1, Ordering::Relaxed);
        if seen + 1 < IDLE_SWEEP_EVERY {
            return false;
        }
        // The function claims the window. It drops everything that was
        // counted since the last sweep.
        self.since_sweep.fetch_sub(seen + 1, Ordering::Relaxed);
        true
    }

    /// True when the limiter does nothing.
    pub fn is_disabled(&self) -> bool {
        self.refill_per_sec == 0.0
    }

    /// Takes one token for `key`, or reports that the caller is over budget.
    ///
    /// The function inserts BEFORE it decides. So a refused request from an
    /// address that was never seen grows the map. That is deliberate in one
    /// direction, because the other choice lets a client retry into a new
    /// full bucket. It is also why `MAX_TRACKED_PEERS` exists, instead of
    /// a cap on the tokens that a client can spend.
    pub fn take(&self, key: &str) -> bool {
        if self.is_disabled() {
            return true;
        }
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);

        // The function makes room only for a NEW key. An entry that is
        // already tracked must keep its tokens and its `last`. So the code
        // must not run for it, or every request that repeats would remove
        // another peer.
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

    /// Tokens that `key` can still spend. The function is for tests and
    /// diagnostics.
    #[cfg(test)]
    pub fn available(&self, key: &str) -> f64 {
        self.buckets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .map_or(self.capacity, |b| b.tokens)
    }

    /// Drops the buckets that no request touched for the idle window, which is
    /// ten minutes.
    ///
    /// The function runs on the request path instead of in a timer. A timer
    /// would be a second background task to own and to stop. The scan is
    /// bounded by `MAX_TRACKED_PEERS`, because the map cannot be larger
    /// than the cap.
    ///
    /// The function returns at once when the limiter is disabled. That is
    /// what makes it acceptable to leave the middleware installed with a
    /// limit of zero, which is the default. A disabled bucket then costs one
    /// atomic load per request, and no lock.
    pub fn evict_idle(&self) {
        if self.is_disabled() {
            return;
        }
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        buckets.retain(|_, b| now.duration_since(b.last) < IDLE_EVICT);
    }

    /// Number of tracked keys. The function is for tests.
    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Moves the clock of every tracked entry back by `by`. The function is for
    /// tests.
    #[cfg(test)]
    pub fn age_all_for_test(&self, by: Duration) {
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        for state in buckets.values_mut() {
            state.last -= by;
        }
    }
}

/// Caps the number of expensive operations that may run at the same time.
///
/// This is the control that bounds the real cost of the replica gateway. The
/// response *body* holds a permit, not the handler. So the permit goes back
/// when the download actually ends, not when the handler returns. If the
/// permit belonged to the handler, a client that opened a stream and then
/// stopped reading would give back its slot while it still held the memory.
#[derive(Clone)]
pub struct ConcurrencyGate {
    /// `None` disables the gate. A semaphore with zero permits cannot
    /// represent this. A semaphore with zero permits refuses everything,
    /// which is the opposite of off.
    max: Option<usize>,
    permits: Arc<tokio::sync::Semaphore>,
}

impl ConcurrencyGate {
    /// A gate that allows `max` operations at the same time.
    ///
    /// A value of `max` equal to `0` disables the gate. That is documented
    /// for trusted deployments.
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

    /// True when the gate does nothing.
    pub fn is_disabled(&self) -> bool {
        self.max.is_none()
    }

    /// Takes a permit, or returns `None` when the caller must wait.
    ///
    /// `None` carries two meanings. It means "no slot" when the gate is
    /// enabled. It also means "no gate" when the gate is disabled. So a
    /// caller must use [`is_disabled`](Self::is_disabled) to tell them
    /// apart, instead of reading this value.
    pub fn acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        if self.is_disabled() {
            return None;
        }
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }
}

/// Key for a peer. The key is the address only, with no port. So a client
/// that connects again does not receive a new budget.
pub fn peer_key(addr: Option<std::net::SocketAddr>) -> String {
    match addr.map(|a| a.ip()) {
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => v6.to_string(),
        // The peer sent no address. A test in this process sends none. A
        // trusted proxy that did not forward one also sends none. One shared
        // bucket is then the safe choice. It caps the whole fleet instead
        // of exempting the fleet.
        None => "unknown".to_string(),
    }
}

/// Rejects a request with the uniform error body when a limit is reached.
pub fn too_many(what: &str) -> HttpResponse {
    tracing::warn!("rate limited: {what}");
    // `ResponseError` renders the uniform error body. So a limited response
    // has the same form as every other error.
    ResponseError::error_response(&ApiError::TooManyRequests)
}

/// Wraps a stream, so that a concurrency permit is held for as long as the
/// stream exists.
///
/// The permit goes back when the wrapper drops. That covers all three
/// endings:
///
/// - The download ends.
/// - The client stops reading in the middle of the stream.
/// - The task is cancelled at shutdown.
///
/// A separate path for the release would miss at least one of them.
///
/// The type is a `Stream`, not a `MessageBody`. Actix has a blanket
/// implementation of `MessageBody` for streams, which keeps this free of
/// `unsafe` pinning in a crate that denies `unwrap` and `expect`.
pub struct GatedStream<S> {
    /// The field is boxed so that the wrapper is `Unpin` whatever the
    /// stream is. That keeps the `poll_next` below free of `unsafe`.
    inner: std::pin::Pin<Box<S>>,
    /// The field is dropped with the stream, which releases the slot.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl<S> GatedStream<S> {
    /// Wraps `inner` and holds `permit` until the wrapper drops.
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
        // `Self` is `Unpin`, because it is a pinned box and an `Option` of
        // one. So a plain mutable borrow is enough here.
        let this = self.get_mut();
        this.inner.as_mut().poll_next(cx)
    }
}

/// Actix middleware that applies a [`TokenBucket`] before the handler runs.
///
/// The middleware is the outermost one. So it also covers the routes that no
/// limiter keyed on the subject could reach. Examples are `/auth/login`,
/// which makes an outgoing round trip to the identity provider, and
/// `/health`, which a load balancer polls often.
pub struct RateLimit {
    bucket: TokenBucket,
}

impl RateLimit {
    /// Wraps `bucket` for use as middleware.
    pub fn new(bucket: TokenBucket) -> Self {
        Self { bucket }
    }
}

/// The limiter that is installed. See [`RateLimit`].
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
        // The cap of `MAX_TRACKED_PEERS` at insert is what bounds the map.
        // The idle sweep only reclaims memory early. So the sweep runs once
        // every `IDLE_SWEEP_EVERY` requests, instead of on every request. If
        // it ran on every request, each request would walk up to the cap
        // under the mutex that `take` also needs. Every worker would pay
        // that cost, including peers that are over budget and are there only
        // to be refused.
        if self.bucket.sweep_due() {
            self.bucket.evict_idle();
        }
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

    /// A full bucket must not add tokens while it is idle. Otherwise a client
    /// that waits an hour receives a burst that matches the wait.
    #[test]
    fn refill_is_capped_at_capacity() {
        let bucket = TokenBucket::new(2, 600_000);
        assert!(bucket.take("a"));
        assert!(bucket.take("a"));
        assert!(!bucket.take("a"));
        // Move the clock forward instead of sleeping. The refill is
        // computed from `last`.
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

    /// The idle window drops entries, and it drops ONLY the idle ones.
    ///
    /// The test pins two separate properties, and each half pins one of them.
    /// If the test removed the `retain` in `evict_idle` entirely, the map
    /// would grow without a bound. That is the property in the name of this
    /// test. The half below that moves the clock is what makes the name mean
    /// something. An implementation that dropped EVERY entry as soon as any
    /// one entry was idle would satisfy both halves. That implementation
    /// would also throw away the budgets of live peers on every request, and
    /// it would hand unlimited new tokens to anyone who left a bucket idle
    /// for ten minutes. Only the mixed half catches that case.
    #[test]
    fn idle_buckets_are_evicted_so_the_map_cannot_grow_without_bound() {
        let bucket = TokenBucket::new(10, 60);
        for i in 0..100 {
            bucket.take(&format!("peer-{i}"));
        }
        assert_eq!(bucket.tracked(), 100);
        // No entry was idle for ten minutes, so the eviction must
        // change nothing here. It must not drop live buckets on every
        // request.
        bucket.evict_idle();
        assert_eq!(bucket.tracked(), 100);

        // Move the clock of every entry past the window instead of
        // sleeping for ten minutes. `last` is the only value that
        // `evict_idle` reads.
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

    /// The eviction works on each entry. An idle peer goes. An active peer
    /// keeps its budget.
    ///
    /// The test above shows that entries past the window are dropped. It also
    /// shows that a map with new entries is left alone. An implementation
    /// with `buckets.clear()` satisfies both tests. That implementation is
    /// more than wasteful. `evict_idle` runs on EVERY request, in
    /// `RateLimitMiddleware::call`. So clearing would set the tokens of every
    /// tracked peer back to a full bucket about once per request. The limiter
    /// would then limit nothing at all for a client whose requests are so far
    /// apart that it never touches two keys inside ten minutes.
    ///
    /// The test moves `last` directly instead of sleeping, as the other tests
    /// in this module do.
    #[test]
    fn eviction_drops_the_idle_peers_and_leaves_the_active_ones_alone() {
        let bucket = TokenBucket::new(2, 60);
        // Take both buckets down to refusal. Then a full bucket cannot be
        // mistaken for a bucket that was kept. The refill is real at
        // 1 token per second. The loop ends in microseconds, which is well
        // inside the time that a refill would need.
        for key in ["active", "quiet"] {
            while bucket.take(key) {}
            assert!(
                bucket.available(key) < 2.0,
                "{key} is over budget to begin with"
            );
        }
        let drained_active = bucket.available("active");

        {
            let mut buckets = bucket.buckets.lock().unwrap();
            buckets.get_mut("quiet").expect("bucket exists").last -=
                IDLE_EVICT + Duration::from_secs(1);
        }

        bucket.evict_idle();

        assert_eq!(
            bucket.tracked(),
            1,
            "exactly the idle peer is dropped, not the whole map"
        );
        assert_eq!(
            bucket.available("active"),
            drained_active,
            "an active peer must keep the budget it had, not be handed a \
             fresh full bucket because some other key went quiet"
        );
    }

    /// The map is bounded by COUNT, not only by idle time.
    ///
    /// This is the regression. `evict_idle` was the only bound, and its
    /// argument about cost was wrong. `take` inserts on the way to REFUSING.
    /// So a client that rotates through a routed IPv6 prefix grows the map
    /// with every request that the server turns away. Nothing is dropped for
    /// ten minutes. Reaching the cap in this test needs
    /// `MAX_TRACKED_PEERS + 500` different keys, not a wait of ten minutes.
    /// That is the shape that the old code could not survive. The old test
    /// only checked that the eviction left a new map alone. That check holds
    /// whether or not the map has any bound at all.
    ///
    /// The test fails on the code before the fix, with
    /// `tracked() == MAX_TRACKED_PEERS + 500`.
    #[test]
    fn the_map_stays_bounded_when_peers_outrun_the_idle_window() {
        let bucket = TokenBucket::new(1, 60);
        for i in 0..MAX_TRACKED_PEERS + 500 {
            // Most of these requests are REFUSED. The capacity is 1, and
            // each key is used once. So the first key uses up its bucket,
            // and every other key is over budget. That is the path that
            // inserts, so the bound has to cover it.
            bucket.take(&format!("peer-{i}"));
            bucket.evict_idle();
        }
        assert!(
            bucket.tracked() <= MAX_TRACKED_PEERS,
            "tracked {} peers past a cap of {MAX_TRACKED_PEERS}",
            bucket.tracked(),
        );
    }

    /// The cap removes the COLDEST entry. So an active peer does not pay for
    /// the rotation of another peer.
    ///
    /// Refusing the new key instead would give any attacker who fills the map
    /// a way to lock every valid first-time client out of the limiter for the
    /// life of the process.
    #[test]
    fn the_cap_evicts_the_coldest_peer_not_the_new_one() {
        let bucket = TokenBucket::new(10, 60);
        bucket.take("cold");
        {
            let mut buckets = bucket.buckets.lock().unwrap();
            buckets.get_mut("cold").expect("bucket exists").last -= Duration::from_secs(3600);
        }
        // Fill the map to the cap, so that "cold" is the only candidate.
        // Then go past the cap once.
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

    /// A peer that is ALREADY tracked is not removed by its own repeated
    /// request. The peer keeps its budget through the overflow.
    ///
    /// The function makes room before the insert. So an implementation that
    /// does not check for an existing key removes another peer on every
    /// single request, once the map is at the cap. That would turn the
    /// limiter into a source of free budget for anyone who sends fast
    /// enough.
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
    async fn a_gated_stream_holds_its_slot_for_the_body() {
        let gate = ConcurrencyGate::new(1);
        let permit = gate.acquire().expect("slot");
        let gated = GatedStream::new(
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(bytes::Bytes::from("a"))]),
            Some(permit),
        );

        // While the body exists, the slot is gone. This is the half that
        // matters. A gate that returned the permit when the handler returned
        // would let a client open a stream, stop reading, and leave with
        // the memory still in use. The permit would look returned while the
        // slot bounded nothing.
        assert!(
            gate.acquire().is_none(),
            "the slot must be held while the body exists"
        );

        // Dropping in the middle of the stream is the other half. A client
        // that opened a read and then disconnected must still give the slot
        // back. Otherwise the gate slowly stops working as dead reads build
        // up.
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

    /// The response for a limit uses the same error body that every other error
    /// uses. So a client that parses errors does not need a separate case for
    /// the case where the server limits it.
    ///
    /// The status code alone does not show that. This test used to check
    /// nothing else. The function `too_many` was free to return
    /// `HttpResponse::TooManyRequests().finish()`, which is a bare 429 with
    /// no body at all. The test stayed green in that case. That is exactly
    /// the duplication that
    /// `http::error::tests::the_envelope_has_one_construction_site` exists to
    /// prevent. That guard checks the form of the source files, so it counts
    /// the files that build the error body. A 429 built outside it is
    /// invisible to that guard. This test is the other half, which checks
    /// the behaviour.
    ///
    /// The path that matters is `RateLimitMiddleware`. So the test reads the
    /// response through the middleware, not directly from `too_many`. A 429
    /// that is built inside the transform, and that is not the one
    /// `too_many` returns, is the failure that this test must catch. Only a
    /// request can catch it. The other path is
    /// `FsError::TooManyRequests` in `sync::route`. That path is asserted in
    /// its own module.
    #[actix_web::test]
    async fn the_limit_response_uses_the_uniform_envelope() {
        use actix_web::{App, http::StatusCode, test};

        // The capacity is 1. The first request uses the token, and the
        // second is over budget. A request in this process has no peer
        // address, so both requests land in the same bucket through
        // `peer_key(None)`.
        let app = test::init_service(
            App::new()
                .wrap(RateLimit::new(TokenBucket::new(1, 60)))
                .route("/", actix_web::web::get().to(|| async { "served" })),
        )
        .await;
        let request = || test::TestRequest::get().uri("/").to_request();

        // The control request comes first. It shows that the app serves, so
        // the 429 below comes from the limiter and not from a route
        // that never matched.
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

    /// The idle sweep reclaims memory early. The bound is `make_room`. So the
    /// sweep must not walk the map on every request.
    ///
    /// At the cap, the sweep walks the map under the mutex that `take` also
    /// needs. It used to pay that cost on every request, for every worker.
    /// That includes requests that are over budget and are there only to be
    /// refused. That made the limiter the point of amplification that it
    /// exists to bound.
    #[test]
    fn the_idle_sweep_is_not_walked_on_every_request() {
        let bucket = TokenBucket::new(1, 60);

        let mut sweeps = 0;
        for _ in 0..(IDLE_SWEEP_EVERY * 4) {
            if bucket.sweep_due() {
                bucket.evict_idle();
                sweeps += 1;
            }
        }

        assert_eq!(
            sweeps,
            4,
            "expected one sweep per {IDLE_SWEEP_EVERY} requests, got {sweeps} in {}",
            IDLE_SWEEP_EVERY * 4
        );
    }

    /// The cadence still reclaims memory. An entry whose clock moved past the
    /// window is dropped once the cadence comes round. Without this test,
    /// the cadence could become "never", and the test above would still pass.
    #[test]
    fn the_cadence_still_reclaims_idle_entries() {
        let bucket = TokenBucket::new(10, 60);
        for i in 0..5 {
            assert!(bucket.take(&format!("peer-{i}")), "peer {i} has budget");
        }
        assert_eq!(bucket.tracked(), 5);

        bucket.age_all_for_test(IDLE_EVICT + Duration::from_secs(1));
        for _ in 0..=IDLE_SWEEP_EVERY {
            if bucket.sweep_due() {
                bucket.evict_idle();
            }
        }

        assert_eq!(
            bucket.tracked(),
            0,
            "the cadence must not have become 'never': aged entries should be reclaimed"
        );
    }
}
