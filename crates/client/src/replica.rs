//! The replica loader and its in-memory cache.
//!
//! The client downloads the per-user replica that the server built. The
//! server filters the replica for the authenticated subject. The client
//! downloads `GET /sync/db/manifest.json` and then every object that the
//! manifest names.
//!
//! The loader verifies the size and the SHA-256 of every object. It builds
//! the new cache in a temporary map and swaps it in only after every object
//! passes. A failed load keeps the old cache, except for a `401` or `403`
//! answer, which clears the cache.
//!
//! This version stores the raw object bytes in a `BTreeMap`. The plan
//! names `oxkv-cached` for the local store. Its async oxkv record and
//! snapshot API is a larger integration than this loader needs, so it is a
//! later change.

use core::fmt;
use std::cell::RefCell;
use std::collections::BTreeMap;

use rust_api_model::wire::{ReplicaManifest, ReplicaObject};
use sha2::{Digest, Sha256};

use crate::auth::{Credentials, Method, Request, Transport, TransportError};

/// The route that serves the replica manifest.
const MANIFEST_PATH: &str = "/sync/db/manifest.json";

/// The prefix of the route that serves one replica object.
const OBJECT_PREFIX: &str = "/sync/db/";

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
    /// The raw object bytes, keyed by the manifest key.
    objects: BTreeMap<String, Vec<u8>>,
}

/// Downloads and stores the per-user replica over one transport.
///
/// The client stores the last replica in memory. [`load`](Self::load)
/// replaces the cache only when every object passes. A `401` or `403`
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

    /// Return the stored bytes of one object.
    ///
    /// The value is `None` when no object has this key.
    pub fn object(&self, key: &str) -> Option<Vec<u8>> {
        self.cache.borrow().objects.get(key).cloned()
    }

    /// Return the number of stored objects.
    pub fn object_count(&self) -> usize {
        self.cache.borrow().objects.len()
    }

    /// Remove the stored replica.
    pub fn clear(&self) {
        *self.cache.borrow_mut() = ReplicaCache::default();
    }

    /// Download the manifest and every object, then store the new replica.
    ///
    /// The load fetches `GET /sync/db/manifest.json` and then each object
    /// from `GET /sync/db/{key}` with cookie credentials. It rejects a
    /// manifest generation that is older than the stored generation. It
    /// verifies the byte length and the SHA-256 of every object. The new
    /// objects replace the stored objects only after every check passes.
    pub async fn load(&self) -> Result<ReplicaState, ReplicaError> {
        // Copy the stored state before the first await. The borrow ends
        // here, so state() and clear() keep working during the download.
        let stored = self.cache.borrow().state;

        let manifest_body = self.get(MANIFEST_PATH).await?;
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
            let path = format!("{OBJECT_PREFIX}{}", object.key);
            let bytes = self.get(&path).await?;
            verify_object(object, &bytes)?;
            objects.insert(object.key.clone(), bytes);
        }

        let state = ReplicaState {
            generation: manifest.generation,
            head: manifest.head,
            applied_seq: manifest.head,
        };
        let mut cache = self.cache.borrow_mut();
        cache.objects = objects;
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
/// A key must be relative. It must not hold an empty segment or a `..`
/// segment.
fn validate_key(key: &str) -> Result<(), ReplicaError> {
    let invalid = key.is_empty()
        || key.starts_with('/')
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
