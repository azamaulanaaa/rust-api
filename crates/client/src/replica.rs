//! The replica loader and its in-memory cache.
//!
//! The client downloads the per-user replica that the server built. The
//! server filters the replica for the authenticated subject. This version
//! downloads and stores the manifest. A later version adds the object
//! download and the integrity checks.

use core::fmt;
use std::cell::RefCell;

use rust_api_model::wire::ReplicaManifest;

use crate::auth::{Credentials, Method, Request, Transport, TransportError};

/// The route that serves the replica manifest.
const MANIFEST_PATH: &str = "/sync/db/manifest.json";

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
    /// The manifest body is not a valid [`ReplicaManifest`].
    Manifest(serde_json::Error),
}

impl fmt::Display for ReplicaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "the request failed: {error}"),
            Self::Request { status } => write!(formatter, "the server answered HTTP {status}"),
            Self::LoginRequired => formatter.write_str("a login is required"),
            Self::Forbidden => formatter.write_str("the server denied the replica access"),
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
}

/// Downloads and stores the per-user replica over one transport.
///
/// The client stores the last replica in memory. [`load`](Self::load)
/// replaces the cache only when the manifest is valid. A `401` or `403`
/// answer clears the cache.
#[derive(Debug)]
pub struct ReplicaClient<T: Transport> {
    transport: T,
    cache: RefCell<ReplicaCache>,
}

impl<T: Transport> ReplicaClient<T> {
    /// Build a client over one transport.
    ///
    /// This constructor does no network work.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            cache: RefCell::new(ReplicaCache::default()),
        }
    }

    /// Return the state of the stored replica.
    ///
    /// The value is `None` until a load succeeds or after [`clear`](Self::clear).
    pub fn state(&self) -> Option<ReplicaState> {
        self.cache.borrow().state
    }

    /// Remove the stored replica.
    pub fn clear(&self) {
        *self.cache.borrow_mut() = ReplicaCache::default();
    }

    /// Download the manifest and store its state.
    ///
    /// The load fetches `GET /sync/db/manifest.json` with cookie
    /// credentials. It validates the body as a [`ReplicaManifest`].
    pub async fn load(&self) -> Result<ReplicaState, ReplicaError> {
        let manifest_body = self.get(MANIFEST_PATH).await?;
        let manifest: ReplicaManifest =
            serde_json::from_slice(&manifest_body).map_err(ReplicaError::Manifest)?;

        let state = ReplicaState {
            generation: manifest.generation,
            head: manifest.head,
            applied_seq: manifest.head,
        };
        self.cache.borrow_mut().state = Some(state);
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
