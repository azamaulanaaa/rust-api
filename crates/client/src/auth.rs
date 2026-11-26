//! The auth transport seam and the session check.
//!
//! The client asks the server whether the browser has a session. The browser
//! sends the `auth_token` cookie with the request. The client never reads the
//! cookie value. A `401` answer turns into [`AuthState::LoginRequired`].

use core::cell::Cell;
use core::fmt;

/// The route that reports the current session.
const SESSION_PATH: &str = "/auth/me";

/// The session state of the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthState {
    /// The client has not checked the session yet.
    Unknown,
    /// The server accepted the session.
    Authenticated,
    /// The server has no valid session for this browser.
    LoginRequired,
    /// The check failed before the client learned the session state.
    Error,
}

impl AuthState {
    /// Return the stable JavaScript name for this state.
    ///
    /// A name, once added, stays part of the stable surface.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Authenticated => "authenticated",
            Self::LoginRequired => "login_required",
            Self::Error => "error",
        }
    }
}

/// The browser credential mode for a request.
///
/// The mode maps to the `credentials` option of the browser `fetch` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credentials {
    /// Send cookies, including cross-origin cookies.
    Include,
    /// Send cookies only to the same origin.
    SameOrigin,
    /// Do not send cookies.
    Omit,
}

/// The HTTP method of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// A `GET` request.
    Get,
    /// A `POST` request.
    Post,
    /// A `PUT` request.
    Put,
    /// A `DELETE` request.
    Delete,
}

/// One request for a transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The HTTP method.
    pub method: Method,
    /// The request path. A relative path stays on the page origin.
    pub path: String,
    /// The browser credential mode.
    pub credentials: Credentials,
}

/// The status of one response.
///
/// The session check reads only the status. It does not read the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status code.
    pub status: u16,
}

/// A failure to send a request or to read its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportError;

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the transport failed to send the request")
    }
}

impl std::error::Error for TransportError {}

/// Sends one request and returns the response status.
///
/// A transport is a seam for the browser and for tests.
// The native async-in-trait form is enough here. The client runs on one
// browser thread, and no caller needs a `Send` bound on the future.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Send one request.
    async fn send(&self, request: Request) -> Result<Response, TransportError>;
}

/// Runs the session check over one transport.
///
/// The client stores the last state in a [`Cell`], because `check_session`
/// takes `&self`. The JavaScript client wraps this type.
#[derive(Debug)]
pub struct AuthClient<T: Transport> {
    transport: T,
    state: Cell<AuthState>,
}

impl<T: Transport> AuthClient<T> {
    /// Build a client over one transport.
    ///
    /// This constructor does no network work.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: Cell::new(AuthState::Unknown),
        }
    }

    /// Return the state from the last check.
    pub fn state(&self) -> AuthState {
        self.state.get()
    }

    /// Ask the server for the current session and store the state.
    ///
    /// The request is `GET /auth/me` with cookie credentials. A `200` answer
    /// means [`AuthState::Authenticated`]. A `401` answer means
    /// [`AuthState::LoginRequired`]. Any other answer or a transport failure
    /// means [`AuthState::Error`]. The browser sends the cookie. The client
    /// does not read it.
    pub async fn check_session(&self) -> AuthState {
        let request = Request {
            method: Method::Get,
            path: SESSION_PATH.to_owned(),
            credentials: Credentials::Include,
        };
        let state = match self.transport.send(request).await {
            Ok(response) => match response.status {
                200 => AuthState::Authenticated,
                401 => AuthState::LoginRequired,
                _ => AuthState::Error,
            },
            Err(_) => AuthState::Error,
        };
        self.state.set(state);
        state
    }
}

/// The browser transport.
#[cfg(target_arch = "wasm32")]
pub mod browser {
    use super::{Credentials, Method, Request, Response, Transport, TransportError};
    use gloo_net::http::Request as FetchRequest;
    use web_sys::RequestCredentials;

    /// Sends one request through the browser `fetch` call.
    ///
    /// The transport uses a same-origin relative path. The browser adds the
    /// cookies for the page origin.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct BrowserTransport;

    impl Transport for BrowserTransport {
        async fn send(&self, request: Request) -> Result<Response, TransportError> {
            let builder = match request.method {
                Method::Get => FetchRequest::get(&request.path),
                Method::Post => FetchRequest::post(&request.path),
                Method::Put => FetchRequest::put(&request.path),
                Method::Delete => FetchRequest::delete(&request.path),
            };
            let builder = builder.credentials(map_credentials(request.credentials));
            let response = builder.send().await.map_err(|_| TransportError)?;
            Ok(Response {
                status: response.status(),
            })
        }
    }

    /// Map one credential mode to the browser `fetch` value.
    fn map_credentials(credentials: Credentials) -> RequestCredentials {
        match credentials {
            Credentials::Include => RequestCredentials::Include,
            Credentials::SameOrigin => RequestCredentials::SameOrigin,
            Credentials::Omit => RequestCredentials::Omit,
        }
    }
}
