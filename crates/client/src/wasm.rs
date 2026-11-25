//! The JavaScript-facing client surface.
//!
//! This module builds only for `wasm32`. The surface is small on purpose.
//! Later features add methods for auth, replica reads, queries, and jobs.
//! This version has no network access, no storage, and no business behavior.

use wasm_bindgen::prelude::*;

/// The JavaScript-facing client for the rust-api server.
///
/// Create one instance in JavaScript with `new Client()`. This version has
/// no methods other than the constructor. Later features add methods. A
/// method, once added, stays part of the stable surface.
#[wasm_bindgen]
#[derive(Debug, Default)]
pub struct Client {}

#[wasm_bindgen]
impl Client {
    /// Create a client.
    ///
    /// The constructor does not contact the server, read browser storage,
    /// or read a cookie. It only builds the empty client value.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {}
    }
}
