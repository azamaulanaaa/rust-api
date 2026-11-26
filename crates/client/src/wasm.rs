//! The JavaScript-facing client surface.
//!
//! This module builds only for `wasm32`. The surface is small on purpose.
//! Later features add methods for replica reads, queries, and jobs. This
//! version sends only the session probe. It has no storage.

use wasm_bindgen::prelude::*;

use crate::auth::AuthClient;
use crate::auth::browser::BrowserTransport;

/// The JavaScript-facing client for the rust-api server.
///
/// Create one instance in JavaScript with `new Client()`. The constructor
/// does no network or storage work. A method, once added, stays part of the
/// stable surface.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Client {
    auth: AuthClient<BrowserTransport>,
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
}
