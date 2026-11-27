//! The replica loader and its in-memory cache.
//!
//! The client downloads a per-user replica that the server built. The server
//! filters the replica for the authenticated subject.
//!
//! A [`ReplicaSource`] names the manifest path and the object path prefix.
//! The file replica uses `/sync/db/`. The EAV oxkv replica uses
//! `/eav/sync/oxkv/`.
//!
//! The client downloads the manifest and then every object that the manifest
//! names.
//!
//! The loader verifies the size and the SHA-256 of every object. It builds
//! the new cache in a temporary map and swaps it in only after every object
//! passes. A failed load keeps the old cache, except for a `401` or `403`
//! answer, which clears the cache.
//!
//! A load checks the stored generation before it downloads and again before
//! it commits. A newer load or a clear replaces an older load that has not
//! committed, so the older load cannot overwrite newer data or repopulate
//! the cache after a logout.
//!
//! This version shares the raw object bytes through a `BTreeMap` of
//! `Arc<[u8]>`. The plan names `oxkv-cached` for the local store. Its async
//! oxkv record and snapshot API is a larger integration than this loader
//! needs, so it is a later change.

use core::fmt;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Arc;

use rust_api_model::wire::{ReplicaManifest, ReplicaObject};
use sha2::{Digest, Sha256};

use crate::auth::{Credentials, Method, Request, Transport, TransportError};

/// The route that serves the file replica manifest.
const FILE_MANIFEST_PATH: &str = "/sync/db/manifest.json";

/// The prefix of the route that serves one file replica object.
const FILE_OBJECT_PREFIX: &str = "/sync/db/";

/// The route that serves the EAV oxkv replica manifest.
const EAV_MANIFEST_PATH: &str = "/eav/sync/oxkv/manifest.json";

/// The prefix of the route that serves one EAV oxkv replica object.
const EAV_OBJECT_PREFIX: &str = "/eav/sync/oxkv/objects/";

/// The two routes that serve one replica.
///
/// The source keeps the manifest path and the object path prefix together,
/// so one client cannot mix the routes of two replicas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplicaSource {
    /// The route that returns the replica manifest.
    pub manifest_path: &'static str,
    /// The route prefix for one replica object.
    pub object_prefix: &'static str,
}

impl ReplicaSource {
    /// The file replica under `/sync/db/`.
    ///
    /// The file replica holds no EAV entity row.
    pub const FILE: Self = Self {
        manifest_path: FILE_MANIFEST_PATH,
        object_prefix: FILE_OBJECT_PREFIX,
    };

    /// The per-user EAV oxkv replica under `/eav/sync/oxkv/`.
    ///
    /// The object keys are relative to the replica root.
    pub const EAV_OXKV: Self = Self {
        manifest_path: EAV_MANIFEST_PATH,
        object_prefix: EAV_OBJECT_PREFIX,
    };
}

/// The generation and the sync position of the stored replica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplicaState {
    /// The build generation of the replica.
    pub generation: u64,
    /// The highest change feed sequence in the replica.
    pub head: u64,
    /// The change feed sequence that the client applied.
    pub applied_seq: u64,
}

/// A failure to load the replica.
///
/// The error keeps the HTTP status of an unexpected answer, so a caller can
/// tell a missing object from a server fault.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReplicaError {
    /// The transport failed before the client read an answer.
    Transport(TransportError),
    /// The server answered with an expected body and an unexpected status.
    Request {
        /// The HTTP status code.
        status: u16,
    },
    /// The server has no valid session for this browser.
    LoginRequired,
    /// The server denied the replica access.
    Forbidden,
    /// The manifest generation is older than the stored generation.
    StaleGeneration {
        /// The generation of the stored replica.
        stored: u64,
        /// The generation of the manifest.
        manifest: u64,
    },
    /// A newer load or a clear replaced this load before it could commit.
    Superseded,
    /// An object does not match the size or the SHA-256 in the manifest.
    Integrity {
        /// The object key from the manifest.
        key: String,
    },
    /// An object key is not a safe path inside the replica.
    InvalidKey {
        /// The object key from the manifest.
        key: String,
    },
    /// The manifest body is not a valid [`ReplicaManifest`].
    Manifest(serde_json::Error),
}

impl ReplicaError {
    /// Return the stable JavaScript status name for this error.
    ///
    /// A name, once added, stays part of the stable surface.
    pub fn status_name(&self) -> &'static str {
        match self {
            Self::LoginRequired => "login_required",
            Self::Forbidden => "forbidden",
            Self::StaleGeneration { .. } => "stale_generation",
            Self::Superseded => "superseded",
            Self::Integrity { .. } => "integrity",
            _ => "request",
        }
    }
}

impl fmt::Display for ReplicaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "the request failed: {error}"),
            Self::Request { status } => write!(formatter, "the server answered HTTP {status}"),
            Self::LoginRequired => formatter.write_str("a login is required"),
            Self::Forbidden => formatter.write_str("the server denied the replica access"),
            Self::StaleGeneration { stored, manifest } => write!(
                formatter,
                "the manifest generation {manifest} is older than the stored generation {stored}"
            ),
            Self::Superseded => formatter.write_str("a newer load or a clear replaced this load"),
            Self::Integrity { key } => {
                write!(formatter, "the object {key} does not match the manifest")
            }
            Self::InvalidKey { key } => {
                write!(formatter, "the object key {key} is not a safe replica path")
            }
            Self::Manifest(error) => write!(formatter, "the manifest is not valid: {error}"),
        }
    }
}

impl std::error::Error for ReplicaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Manifest(error) => Some(error),
            _ => None,
        }
    }
}

/// The stored replica and its state.
#[derive(Debug, Default)]
struct ReplicaCache {
    /// The state of the stored replica, if a load has succeeded.
    state: Option<ReplicaState>,
    /// The shared object bytes, keyed by the manifest key.
    ///
    /// One `Arc` lets a reader keep the map after the cache changes.
    objects: Arc<BTreeMap<String, Arc<[u8]>>>,
}

/// Downloads and stores the per-user replica over one transport.
///
/// The client stores the last replica in memory. [`load`](Self::load)
/// replaces the cache only when every object passes. A `401` or `403`
/// answer clears the cache. A newer load or a clear replaces an older load
/// that has not committed.
#[derive(Debug)]
pub struct ReplicaClient<T: Transport> {
    transport: T,
    source: ReplicaSource,
    cache: RefCell<ReplicaCache>,
    /// The number of the newest load. A load that is not the newest one
    /// cannot commit.
    load_epoch: Cell<u64>,
    /// The number of clears. A load that started before a clear cannot
    /// commit.
    clear_epoch: Cell<u64>,
}

impl<T: Transport> ReplicaClient<T> {
    /// Build a client over one transport for the file replica.
    ///
    /// This constructor does no network work.
    pub fn new(transport: T) -> Self {
        Self::with_source(transport, ReplicaSource::FILE)
    }

    /// Build a client over one transport for one replica source.
    ///
    /// This constructor does no network work.
    pub fn with_source(transport: T, source: ReplicaSource) -> Self {
        Self {
            transport,
            source,
            cache: RefCell::new(ReplicaCache::default()),
            load_epoch: Cell::new(0),
            clear_epoch: Cell::new(0),
        }
    }

    /// Return the route source of this client.
    pub fn source(&self) -> ReplicaSource {
        self.source
    }

    /// Return the state of the stored replica.
    ///
    /// The value is `None` until a load succeeds or after [`clear`](Self::clear).
    pub fn state(&self) -> Option<ReplicaState> {
        self.cache.borrow().state
    }

    /// Return a shared handle to the bytes of one object.
    ///
    /// The value is `None` when no object has this key.
    pub fn object(&self, key: &str) -> Option<Arc<[u8]>> {
        self.cache.borrow().objects.get(key).cloned()
    }

    /// Return the number of stored objects.
    pub fn object_count(&self) -> usize {
        self.cache.borrow().objects.len()
    }

    /// Return the stored object map, if a load has succeeded.
    ///
    /// The caller can keep the map while a later load replaces the cache.
    /// The map holds the bytes of one generation only.
    pub fn objects(&self) -> Option<Arc<BTreeMap<String, Arc<[u8]>>>> {
        let cache = self.cache.borrow();
        cache.state.map(|_| Arc::clone(&cache.objects))
    }

    /// Remove the stored replica.
    ///
    /// A load that is in flight cannot repopulate the cache after a clear.
    pub fn clear(&self) {
        self.clear_epoch.set(self.clear_epoch.get().wrapping_add(1));
        *self.cache.borrow_mut() = ReplicaCache::default();
    }

    /// Download the manifest and every object, then store the new replica.
    ///
    /// The load fetches the manifest of the source and then each object from
    /// the object prefix of the source with cookie credentials. It rejects a
    /// manifest generation that is older than the stored generation. It
    /// verifies the byte length and the SHA-256 of every object. The new
    /// objects replace the stored objects only after every check passes.
    ///
    /// A newer load or a clear replaces this load before it commits. In
    /// that case the cache stays as it is.
    pub async fn load(&self) -> Result<ReplicaState, ReplicaError> {
        // Capture the load and clear epochs before the first await. Copy
        // the stored state too. The borrow ends here, so state() and
        // clear() keep working during the download.
        let load_epoch = self.load_epoch.get().wrapping_add(1);
        self.load_epoch.set(load_epoch);
        let clear_epoch = self.clear_epoch.get();
        let stored = self.cache.borrow().state;

        let manifest_body = self.get(self.source.manifest_path).await?;
        let manifest: ReplicaManifest =
            serde_json::from_slice(&manifest_body).map_err(ReplicaError::Manifest)?;

        if let Some(stored) = stored
            && stored.generation > manifest.generation
        {
            return Err(ReplicaError::StaleGeneration {
                stored: stored.generation,
                manifest: manifest.generation,
            });
        }

        let mut objects = BTreeMap::new();
        for object in &manifest.objects {
            validate_key(&object.key)?;
            let path = format!("{}{}", self.source.object_prefix, object.key);
            let bytes = self.get(&path).await?;
            verify_object(object, &bytes)?;
            objects.insert(object.key.clone(), Arc::<[u8]>::from(bytes));
        }

        let state = ReplicaState {
            generation: manifest.generation,
            head: manifest.head,
            applied_seq: manifest.head,
        };
        // Check the current cache and the epochs under the same borrow
        // that commits. No await runs between the checks and the swap.
        let mut cache = self.cache.borrow_mut();
        if let Some(current) = cache.state
            && current.generation > state.generation
        {
            return Err(ReplicaError::StaleGeneration {
                stored: current.generation,
                manifest: state.generation,
            });
        }
        if self.clear_epoch.get() != clear_epoch || self.load_epoch.get() != load_epoch {
            return Err(ReplicaError::Superseded);
        }
        cache.objects = Arc::new(objects);
        cache.state = Some(state);
        Ok(state)
    }

    /// Send one `GET` request with cookie credentials and return the body.
    ///
    /// A `401` or `403` answer clears the cache.
    async fn get(&self, path: &str) -> Result<Vec<u8>, ReplicaError> {
        let request = Request {
            method: Method::Get,
            path: path.to_owned(),
            credentials: Credentials::Include,
        };
        let response = self
            .transport
            .send(request)
            .await
            .map_err(ReplicaError::Transport)?;
        match response.status {
            200 => Ok(response.body),
            401 => {
                self.clear();
                Err(ReplicaError::LoginRequired)
            }
            403 => {
                self.clear();
                Err(ReplicaError::Forbidden)
            }
            status => Err(ReplicaError::Request { status }),
        }
    }
}

/// Reject a key that can leave the replica prefix.
///
/// A key must be relative. It must hold only ASCII letters, digits, `/`,
/// `.`, `_`, and `-`. It must not hold an empty segment or a `..` segment.
/// The allowlist keeps URL syntax out of the request path. A backslash,
/// `?`, `#`, `%`, whitespace, or a control byte would change the request.
fn validate_key(key: &str) -> Result<(), ReplicaError> {
    let invalid = key.is_empty()
        || key.starts_with('/')
        || !key.bytes().all(is_key_byte)
        || key
            .split('/')
            .any(|segment| segment.is_empty() || segment == "..");
    if invalid {
        Err(ReplicaError::InvalidKey {
            key: key.to_owned(),
        })
    } else {
        Ok(())
    }
}

/// Return `true` when one key byte is in the replica key allowlist.
fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
}

/// Check the byte length and the SHA-256 of one object.
fn verify_object(object: &ReplicaObject, bytes: &[u8]) -> Result<(), ReplicaError> {
    let digest = Sha256::digest(bytes);
    if bytes.len() as u64 != object.size || hex_lower(&digest) != object.sha256 {
        return Err(ReplicaError::Integrity {
            key: object.key.clone(),
        });
    }
    Ok(())
}

/// Encode bytes as lowercase hexadecimal text.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Response;
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::{Pin, pin};
    use std::rc::Rc;
    use std::task::{Context, Poll, Waker};

    /// One scripted transport answer.
    #[derive(Clone, Debug)]
    struct Reply {
        /// The HTTP status code.
        status: u16,
        /// The response body.
        body: Vec<u8>,
    }

    impl Reply {
        /// Build a `200` answer with one body.
        fn ok(body: Vec<u8>) -> Self {
            Self { status: 200, body }
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

    /// A transport that records requests and returns scripted answers.
    struct FakeTransport {
        requests: Requests,
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

    /// A gate that the test opens when its cell becomes true.
    type Gate = Rc<Cell<bool>>;

    /// A future that stays pending until its gate opens.
    struct WaitForGate(Gate);

    impl Future for WaitForGate {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
            if self.get_mut().0.get() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    /// One scripted answer with an optional gate.
    struct GatedReply {
        /// The answer.
        reply: Reply,
        /// The gate that the transport waits on before it returns the answer.
        gate: Option<Gate>,
    }

    /// The gated scripted answers of the gated transport.
    type GatedReplies = Rc<RefCell<VecDeque<GatedReply>>>;

    /// A transport that records requests and returns gated scripted answers.
    struct GatedTransport {
        requests: Requests,
        replies: GatedReplies,
    }

    impl GatedTransport {
        /// Build a transport with no scripted answers.
        fn new() -> (Requests, GatedReplies, Self) {
            let requests = Rc::new(RefCell::new(Vec::new()));
            let replies = Rc::new(RefCell::new(VecDeque::new()));
            (
                Rc::clone(&requests),
                Rc::clone(&replies),
                Self { requests, replies },
            )
        }
    }

    impl Transport for GatedTransport {
        async fn send(&self, request: Request) -> Result<Response, TransportError> {
            self.requests.borrow_mut().push(request);
            let GatedReply { reply, gate } = self
                .replies
                .borrow_mut()
                .pop_front()
                .expect("a scripted reply");
            if let Some(gate) = gate {
                WaitForGate(gate).await;
            }
            Ok(Response {
                status: reply.status,
                body: reply.body,
            })
        }
    }

    /// Build one gated scripted answer.
    fn gated(reply: Reply, gate: Option<Gate>) -> GatedReply {
        GatedReply { reply, gate }
    }

    /// Poll one future until it completes. Call it after the gate opens.
    fn finish<F: Future>(future: &mut Pin<&mut F>, context: &mut Context<'_>) -> F::Output {
        loop {
            if let Poll::Ready(value) = future.as_mut().poll(context) {
                return value;
            }
            std::thread::yield_now();
        }
    }

    /// Run one future to completion. The fake transport is always ready.
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

    /// Build one manifest object with the correct size and hash.
    fn object(key: &str, bytes: &[u8]) -> ReplicaObject {
        ReplicaObject {
            key: key.to_owned(),
            size: bytes.len() as u64,
            sha256: hex_lower(&Sha256::digest(bytes)),
        }
    }

    /// Serialize one manifest.
    fn manifest_body(manifest: &ReplicaManifest) -> Vec<u8> {
        serde_json::to_vec(manifest).expect("the manifest serializes")
    }

    /// Script one full load for a list of object bodies.
    fn script_load(
        replies: &Replies,
        generation: u64,
        head: u64,
        objects: &[(&str, &[u8])],
    ) -> ReplicaManifest {
        let manifest = ReplicaManifest {
            generation,
            head,
            objects: objects
                .iter()
                .map(|(key, bytes)| object(key, bytes))
                .collect(),
        };
        replies
            .borrow_mut()
            .push_back(Reply::ok(manifest_body(&manifest)));
        for (_, bytes) in objects {
            replies.borrow_mut().push_back(Reply::ok((*bytes).to_vec()));
        }
        manifest
    }

    /// A load sends the manifest and object requests with cookie credentials.
    #[test]
    fn a_load_downloads_the_manifest_and_every_object() {
        let (requests, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        script_load(
            &replies,
            7,
            42,
            &[("e0/sst/a.sst", b"alpha"), ("e0/wal/b.wal", b"bravo")],
        );

        let state = block_on(client.load()).expect("the load succeeds");

        assert_eq!(
            state,
            ReplicaState {
                generation: 7,
                head: 42,
                applied_seq: 42,
            }
        );
        assert_eq!(client.state(), Some(state));
        assert_eq!(client.object_count(), 2);
        assert_eq!(
            client.object("e0/sst/a.sst").as_deref(),
            Some(&b"alpha"[..])
        );
        assert_eq!(
            client.object("e0/wal/b.wal").as_deref(),
            Some(&b"bravo"[..])
        );
        let first = client.object("e0/sst/a.sst").expect("the object is stored");
        let second = client.object("e0/sst/a.sst").expect("the object is stored");
        assert!(Arc::ptr_eq(&first, &second));

        let requests = requests.borrow();
        let paths: Vec<&str> = requests
            .iter()
            .map(|request| request.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "/sync/db/manifest.json",
                "/sync/db/e0/sst/a.sst",
                "/sync/db/e0/wal/b.wal",
            ]
        );
        assert!(requests.iter().all(|request| {
            request.method == Method::Get && request.credentials == Credentials::Include
        }));
    }

    /// The EAV source uses the EAV manifest and object routes.
    #[test]
    fn the_eav_source_uses_the_eav_routes() {
        let (requests, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::with_source(transport, ReplicaSource::EAV_OXKV);
        script_load(&replies, 3, 9, &[("manifest.json", b"{}")]);

        block_on(client.load()).expect("the load succeeds");

        let requests = requests.borrow();
        let paths: Vec<&str> = requests
            .iter()
            .map(|request| request.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "/eav/sync/oxkv/manifest.json",
                "/eav/sync/oxkv/objects/manifest.json",
            ]
        );
        assert_eq!(client.source(), ReplicaSource::EAV_OXKV);
    }

    /// The stored map keeps one generation after a later load.
    #[test]
    fn a_stored_map_keeps_its_bytes_after_a_later_load() {
        let (_, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        script_load(&replies, 1, 5, &[("e0/old", b"old")]);
        block_on(client.load()).expect("the first load succeeds");
        let stored = client.objects().expect("the map is stored");

        script_load(&replies, 2, 6, &[("e0/new", b"new")]);
        block_on(client.load()).expect("the second load succeeds");

        assert_eq!(stored.get("e0/old").map(AsRef::as_ref), Some(&b"old"[..]));
        assert!(!stored.contains_key("e0/new"));
        assert_eq!(client.objects().as_deref().map(BTreeMap::len), Some(1));
    }

    /// A mismatched hash is rejected and the old cache stays in place.
    #[test]
    fn a_tampered_hash_is_rejected_and_keeps_the_old_cache() {
        let (requests, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        let old_state = {
            script_load(&replies, 5, 10, &[("e0/sst/a.sst", b"old")]);
            block_on(client.load()).expect("the first load succeeds")
        };

        let mut tampered = object("e0/sst/a.sst", b"new");
        tampered.sha256 = hex_lower(&Sha256::digest(b"other"));
        let manifest = ReplicaManifest {
            generation: 6,
            head: 11,
            objects: vec![tampered],
        };
        replies
            .borrow_mut()
            .push_back(Reply::ok(manifest_body(&manifest)));
        replies.borrow_mut().push_back(Reply::ok(b"new".to_vec()));

        let error = block_on(client.load()).expect_err("the hash mismatch is rejected");
        assert!(matches!(error, ReplicaError::Integrity { .. }));
        assert_eq!(client.state(), Some(old_state));
        assert_eq!(client.object("e0/sst/a.sst").as_deref(), Some(&b"old"[..]));
        assert_eq!(requests.borrow().len(), 4);
    }

    /// A mismatched size is rejected and the old cache stays in place.
    #[test]
    fn a_wrong_size_is_rejected_and_keeps_the_old_cache() {
        let (_, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        let old_state = {
            script_load(&replies, 5, 10, &[("e0/sst/a.sst", b"old")]);
            block_on(client.load()).expect("the first load succeeds")
        };

        let mut wrong_size = object("e0/sst/a.sst", b"new");
        wrong_size.size += 1;
        let manifest = ReplicaManifest {
            generation: 6,
            head: 11,
            objects: vec![wrong_size],
        };
        replies
            .borrow_mut()
            .push_back(Reply::ok(manifest_body(&manifest)));
        replies.borrow_mut().push_back(Reply::ok(b"new".to_vec()));

        let error = block_on(client.load()).expect_err("the size mismatch is rejected");
        assert!(matches!(error, ReplicaError::Integrity { .. }));
        assert_eq!(client.state(), Some(old_state));
        assert_eq!(client.object("e0/sst/a.sst").as_deref(), Some(&b"old"[..]));
    }

    /// An older manifest generation is rejected and the old cache stays.
    #[test]
    fn a_stale_generation_is_rejected_and_keeps_the_old_cache() {
        let (requests, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        let old_state = {
            script_load(&replies, 7, 10, &[("e0/sst/a.sst", b"old")]);
            block_on(client.load()).expect("the first load succeeds")
        };

        let stale = ReplicaManifest {
            generation: 6,
            head: 20,
            objects: vec![object("e0/sst/a.sst", b"new")],
        };
        replies
            .borrow_mut()
            .push_back(Reply::ok(manifest_body(&stale)));

        let error = block_on(client.load()).expect_err("the stale generation is rejected");
        match error {
            ReplicaError::StaleGeneration { stored, manifest } => {
                assert_eq!(stored, 7);
                assert_eq!(manifest, 6);
            }
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(client.state(), Some(old_state));
        assert_eq!(client.object("e0/sst/a.sst").as_deref(), Some(&b"old"[..]));

        // The stale load stopped after the manifest request.
        assert_eq!(requests.borrow().len(), 3);
    }

    /// A newer generation that commits first is not overwritten.
    #[test]
    fn an_older_load_cannot_overwrite_a_newer_generation() {
        let older_gate = Rc::new(Cell::new(false));
        let (_, replies, transport) = GatedTransport::new();
        let client = ReplicaClient::new(transport);

        let older_manifest = ReplicaManifest {
            generation: 1,
            head: 10,
            objects: vec![object("e0/old", b"old")],
        };
        let newer_manifest = ReplicaManifest {
            generation: 2,
            head: 20,
            objects: vec![object("e0/new", b"new")],
        };
        replies
            .borrow_mut()
            .push_back(gated(Reply::ok(manifest_body(&older_manifest)), None));
        replies.borrow_mut().push_back(gated(
            Reply::ok(b"old".to_vec()),
            Some(Rc::clone(&older_gate)),
        ));
        replies
            .borrow_mut()
            .push_back(gated(Reply::ok(manifest_body(&newer_manifest)), None));
        replies
            .borrow_mut()
            .push_back(gated(Reply::ok(b"new".to_vec()), None));

        let mut context = Context::from_waker(Waker::noop());
        let mut older = pin!(client.load());
        assert!(matches!(older.as_mut().poll(&mut context), Poll::Pending));

        let newer_state = block_on(client.load()).expect("the newer load commits");
        assert_eq!(newer_state.generation, 2);

        older_gate.set(true);
        let error = finish(&mut older, &mut context).expect_err("the older load is rejected");
        assert!(matches!(
            error,
            ReplicaError::StaleGeneration {
                stored: 2,
                manifest: 1,
            }
        ));
        assert_eq!(client.state(), Some(newer_state));
        assert_eq!(client.object("e0/new").as_deref(), Some(&b"new"[..]));
        assert_eq!(client.object("e0/old"), None);
    }

    /// A newer load that has not committed still supersedes an older load.
    #[test]
    fn a_newer_load_supersedes_an_older_load_before_commit() {
        let older_gate = Rc::new(Cell::new(false));
        let newer_gate = Rc::new(Cell::new(false));
        let (_, replies, transport) = GatedTransport::new();
        let client = ReplicaClient::new(transport);

        let older_manifest = ReplicaManifest {
            generation: 1,
            head: 10,
            objects: vec![object("e0/old", b"old")],
        };
        let newer_manifest = ReplicaManifest {
            generation: 2,
            head: 20,
            objects: vec![object("e0/new", b"new")],
        };
        replies
            .borrow_mut()
            .push_back(gated(Reply::ok(manifest_body(&older_manifest)), None));
        replies.borrow_mut().push_back(gated(
            Reply::ok(b"old".to_vec()),
            Some(Rc::clone(&older_gate)),
        ));
        replies
            .borrow_mut()
            .push_back(gated(Reply::ok(manifest_body(&newer_manifest)), None));
        replies.borrow_mut().push_back(gated(
            Reply::ok(b"new".to_vec()),
            Some(Rc::clone(&newer_gate)),
        ));

        let mut context = Context::from_waker(Waker::noop());
        let mut older = pin!(client.load());
        assert!(matches!(older.as_mut().poll(&mut context), Poll::Pending));
        let mut newer = pin!(client.load());
        assert!(matches!(newer.as_mut().poll(&mut context), Poll::Pending));

        older_gate.set(true);
        let error = finish(&mut older, &mut context).expect_err("the older load is superseded");
        assert!(matches!(error, ReplicaError::Superseded));
        assert_eq!(client.state(), None);

        newer_gate.set(true);
        let newer_state = finish(&mut newer, &mut context).expect("the newer load commits");
        assert_eq!(newer_state.generation, 2);
        assert_eq!(client.state(), Some(newer_state));
    }

    /// A clear during a load keeps the cache empty.
    #[test]
    fn a_clear_during_a_load_prevents_repopulation() {
        let gate = Rc::new(Cell::new(false));
        let (_, replies, transport) = GatedTransport::new();
        let client = ReplicaClient::new(transport);

        let manifest = ReplicaManifest {
            generation: 1,
            head: 10,
            objects: vec![object("e0/old", b"old")],
        };
        replies
            .borrow_mut()
            .push_back(gated(Reply::ok(manifest_body(&manifest)), None));
        replies
            .borrow_mut()
            .push_back(gated(Reply::ok(b"old".to_vec()), Some(Rc::clone(&gate))));

        let mut context = Context::from_waker(Waker::noop());
        let mut load = pin!(client.load());
        assert!(matches!(load.as_mut().poll(&mut context), Poll::Pending));

        client.clear();
        gate.set(true);

        let error = finish(&mut load, &mut context).expect_err("the load is superseded");
        assert!(matches!(error, ReplicaError::Superseded));
        assert_eq!(error.status_name(), "superseded");
        assert_eq!(client.state(), None);
        assert_eq!(client.object_count(), 0);
    }

    /// A `401` answer requires a login and clears the cache.
    #[test]
    fn a_401_answer_requires_a_login_and_clears_the_cache() {
        let (_, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        script_load(&replies, 1, 5, &[("e0/sst/a.sst", b"old")]);
        block_on(client.load()).expect("the first load succeeds");
        assert_eq!(client.object_count(), 1);

        replies.borrow_mut().push_back(Reply::status(401));

        let error = block_on(client.load()).expect_err("the 401 is rejected");
        assert!(matches!(error, ReplicaError::LoginRequired));
        assert_eq!(error.status_name(), "login_required");
        assert_eq!(client.state(), None);
        assert_eq!(client.object_count(), 0);
    }

    /// A `403` answer is forbidden and clears the cache.
    #[test]
    fn a_403_answer_is_forbidden_and_clears_the_cache() {
        let (_, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        script_load(&replies, 1, 5, &[("e0/sst/a.sst", b"old")]);
        block_on(client.load()).expect("the first load succeeds");
        assert_eq!(client.object_count(), 1);

        replies.borrow_mut().push_back(Reply::status(403));

        let error = block_on(client.load()).expect_err("the 403 is rejected");
        assert!(matches!(error, ReplicaError::Forbidden));
        assert_eq!(error.status_name(), "forbidden");
        assert_eq!(client.state(), None);
        assert_eq!(client.object_count(), 0);
    }

    /// A missing object keeps the old cache and reports its status.
    #[test]
    fn a_missing_object_is_rejected_and_keeps_the_old_cache() {
        let (_, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        let old_state = {
            script_load(&replies, 1, 5, &[("e0/old", b"old")]);
            block_on(client.load()).expect("the first load succeeds")
        };

        let manifest = ReplicaManifest {
            generation: 2,
            head: 6,
            objects: vec![
                object("e0/sst/a.sst", b"alpha"),
                object("e0/wal/b.wal", b"bravo"),
            ],
        };
        replies
            .borrow_mut()
            .push_back(Reply::ok(manifest_body(&manifest)));
        replies.borrow_mut().push_back(Reply::ok(b"alpha".to_vec()));
        replies.borrow_mut().push_back(Reply::status(404));

        let error = block_on(client.load()).expect_err("the missing object is rejected");
        match error {
            ReplicaError::Request { status } => assert_eq!(status, 404),
            other => panic!("unexpected error: {other}"),
        }
        assert_eq!(client.state(), Some(old_state));
        assert_eq!(client.object("e0/old").as_deref(), Some(&b"old"[..]));
        assert_eq!(client.object("e0/sst/a.sst"), None);
    }

    /// A manifest that is not valid JSON is rejected.
    #[test]
    fn a_manifest_parse_error_is_rejected() {
        let (_, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        replies
            .borrow_mut()
            .push_back(Reply::ok(b"not a manifest".to_vec()));

        let error = block_on(client.load()).expect_err("the manifest is rejected");
        assert!(matches!(error, ReplicaError::Manifest(_)));
        assert_eq!(error.status_name(), "request");
        assert_eq!(client.state(), None);
    }

    /// An unsafe object key is rejected before the client fetches it.
    #[test]
    fn an_unsafe_object_key_is_rejected() {
        for key in [
            "e0/../secret",
            "..",
            "/manifest.json",
            "e0//sst/a.sst",
            "e0/",
            r"..\..\auth/me",
            "a?b",
            "a#b",
            "%2e%2e",
            "a b",
            "a\tb",
            "e0/\u{0}name",
        ] {
            let (requests, replies, transport) = FakeTransport::new();
            let client = ReplicaClient::new(transport);
            let manifest = ReplicaManifest {
                generation: 1,
                head: 2,
                objects: vec![object(key, b"secret")],
            };
            replies
                .borrow_mut()
                .push_back(Reply::ok(manifest_body(&manifest)));

            let error = block_on(client.load()).expect_err("the key is rejected");
            assert!(
                matches!(error, ReplicaError::InvalidKey { .. }),
                "the key {key} must be invalid"
            );
            assert_eq!(error.status_name(), "request");
            assert_eq!(requests.borrow().len(), 1);
            assert_eq!(client.state(), None);
        }

        // A plain nested key stays valid.
        assert!(validate_key("e0/sst/a.sst").is_ok());
    }

    /// The cache clears on request.
    #[test]
    fn a_clear_removes_the_stored_replica() {
        let (_, replies, transport) = FakeTransport::new();
        let client = ReplicaClient::new(transport);
        script_load(&replies, 1, 5, &[("e0/old", b"old")]);
        block_on(client.load()).expect("the load succeeds");

        client.clear();

        assert_eq!(client.state(), None);
        assert_eq!(client.object_count(), 0);
        assert_eq!(client.object("e0/old"), None);
    }

    /// The error status names are stable.
    #[test]
    fn the_replica_error_names_are_stable() {
        assert_eq!(ReplicaError::LoginRequired.status_name(), "login_required");
        assert_eq!(ReplicaError::Forbidden.status_name(), "forbidden");
        assert_eq!(
            ReplicaError::StaleGeneration {
                stored: 2,
                manifest: 1,
            }
            .status_name(),
            "stale_generation"
        );
        assert_eq!(ReplicaError::Superseded.status_name(), "superseded");
        assert_eq!(
            ReplicaError::Integrity {
                key: "e0/sst/a.sst".to_owned(),
            }
            .status_name(),
            "integrity"
        );
        assert_eq!(
            ReplicaError::Request { status: 500 }.status_name(),
            "request"
        );
        assert_eq!(
            ReplicaError::InvalidKey {
                key: "../secret".to_owned(),
            }
            .status_name(),
            "request"
        );
    }
}
