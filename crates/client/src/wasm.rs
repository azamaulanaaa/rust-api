//! The JavaScript-facing client surface.
//!
//! This module builds only for `wasm32`. The surface is small on purpose.
//! This version sends the session probe, downloads the per-user file replica,
//! downloads the per-user EAV oxkv replica, and answers one local entity
//! query. It has no persistent storage.
//!
//! The string shapes and the status names are stable. A name, once added,
//! stays part of the stable surface.

use serde_json::json;
use wasm_bindgen::prelude::*;

use crate::auth::AuthClient;
use crate::auth::browser::BrowserTransport;
use crate::eav::{QueryError, ReplicaQuery};
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
    query: ReplicaQuery<BrowserTransport>,
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
            query: ReplicaQuery::new(BrowserTransport),
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

    /// Download the per-user file replica and return its state or an error name.
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

    /// Download the per-user EAV oxkv replica and return its state or an error name.
    ///
    /// The method downloads `GET /eav/sync/oxkv/manifest.json` and then
    /// every object that the manifest names. It uses the same cookie
    /// credentials, size check, SHA-256 check, and generation rule as
    /// [`load_replica`](Self::load_replica).
    ///
    /// A successful load returns a JSON string:
    ///
    /// ```text
    /// {"generation":7,"head":42,"applied_seq":42,"objects":3}
    /// ```
    ///
    /// A failed load returns one stable status string:
    /// `"login_required"`, `"forbidden"`, `"stale_generation"`,
    /// `"superseded"`, `"integrity"`, or `"request"`.
    ///
    /// The file replica and the EAV replica have separate caches. A
    /// successful EAV load makes [`query_replica`](Self::query_replica)
    /// ready. A method once added stays part of the stable surface.
    pub async fn load_eav_replica(&self) -> String {
        match self.query.load().await {
            Ok(state) => format!(
                "{{\"generation\":{},\"head\":{},\"applied_seq\":{},\"objects\":{}}}",
                state.generation,
                state.head,
                state.applied_seq,
                self.query.replica().object_count()
            ),
            Err(error) => error.status_name().to_owned(),
        }
    }

    /// Run one local query for an exact EAV attribute value.
    ///
    /// `value_json` is a JSON string. It must hold a JSON string, number, or
    /// boolean. A JSON `null`, array, or object is not a valid query value.
    /// `limit` is the page size. The default is 50 and the maximum is 200.
    /// `after` is the last id of the previous page.
    ///
    /// A successful query returns a JSON string:
    ///
    /// ```text
    /// {"items":["e1"],"next":"e2"}
    /// ```
    ///
    /// The `next` field is `null` when no match remains. A failed query
    /// returns one stable error name:
    ///
    /// ```text
    /// {"error":"not_loaded"}
    /// ```
    ///
    /// The error names are `not_loaded`, `corrupt_replica`,
    /// `unsupported_value`, `invalid_query`, and `replica`.
    ///
    /// The query reads only the replica that the server built for this
    /// subject. It makes no authorization decision. A JSON attribute row is
    /// not part of the view. A method once added stays part of the stable
    /// surface.
    pub async fn query_replica(
        &self,
        attribute: &str,
        value_json: &str,
        limit: Option<u32>,
        after: Option<String>,
    ) -> String {
        let value: serde_json::Value = match serde_json::from_str(value_json) {
            Ok(value) => value,
            Err(_) => return error_json(QueryError::InvalidQuery),
        };
        match self
            .query
            .query_attribute(
                attribute,
                &value,
                limit.map(|value| value as usize),
                after.as_deref(),
            )
            .await
        {
            Ok(page) => json!({"items": page.items, "next": page.next}).to_string(),
            Err(error) => error_json(error),
        }
    }
}

/// Return the stable JSON body of one query error.
fn error_json(error: QueryError) -> String {
    json!({"error": error.status_name()}).to_string()
}
