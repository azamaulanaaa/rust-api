//! The JavaScript-facing client surface.
//!
//! This module builds only for `wasm32`. The surface is small on purpose.
//! Later features add methods for local reads and jobs. This version sends
//! the session probe and downloads the per-user replica. It has no
//! persistent storage.

use wasm_bindgen::prelude::*;

use crate::auth::AuthClient;
use crate::auth::browser::BrowserTransport;
use crate::replica::ReplicaClient;

/// The JavaScript-facing client for the rust-api server.
///
/// Create one instance in JavaScript with `new Client()`. The constructor
/// does no network or storage work. A method, once added, stays part of the
/// stable surface.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Client {
    auth: AuthClient<BrowserTransport>,
    replica: ReplicaClient<BrowserTransport>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl Client {
    /// Create a client.
    ///
    /// The constructor does not contact the server, read browser storage,
    /// or read a cookie. It only builds the client value.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            auth: AuthClient::new(BrowserTransport),
            replica: ReplicaClient::new(BrowserTransport),
        }
    }

    /// Check the session and return its stable name.
    ///
    /// The promise resolves to `"authenticated"`, `"login_required"`,
    /// `"error"`, or `"unknown"`. The browser sends the `auth_token` cookie
    /// with the request. The client does not read the cookie value.
    /// A method once added stays part of the stable surface.
    pub async fn check_session(&self) -> String {
        self.auth.check_session().await.as_str().to_owned()
    }

    /// Download the per-user replica and return its state or an error name.
    ///
    /// The method downloads `GET /sync/db/manifest.json` and then every
    /// object that the manifest names, with the `auth_token` cookie. It
    /// verifies the byte length and the SHA-256 of each object. The new
    /// replica replaces the stored replica only after every check passes.
    ///
    /// A successful load returns a JSON string:
    ///
    /// ```text
    /// {"generation":7,"head":42,"applied_seq":42,"objects":3}
    /// ```
    ///
    /// A failed load returns one stable status string:
    ///
    /// - `"login_required"`: the server answered `401` and cleared the cache.
    /// - `"forbidden"`: the server answered `403` and cleared the cache.
    /// - `"stale_generation"`: the manifest is older than the stored replica.
    /// - `"superseded"`: a newer load or a clear replaced this load.
    /// - `"integrity"`: an object does not match its size or SHA-256.
    /// - `"request"`: a transport failure, a manifest parse error, an unsafe
    ///   object key, or an unexpected status.
    ///
    /// The cache stays unchanged on every error except `login_required` and
    /// `forbidden`. The JSON field names and the status strings are stable.
    /// A method once added stays part of the stable surface.
    pub async fn load_replica(&self) -> String {
        match self.replica.load().await {
            Ok(state) => format!(
                "{{\"generation\":{},\"head\":{},\"applied_seq\":{},\"objects\":{}}}",
                state.generation,
                state.head,
                state.applied_seq,
                self.replica.object_count()
            ),
            Err(error) => error.status_name().to_owned(),
        }
    }
}
