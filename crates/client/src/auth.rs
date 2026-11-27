//! The auth transport seam and the session check.
//!
//! The client asks the server whether the browser has a session. The browser
//! sends the `auth_token` cookie with the request. The client never reads the
//! cookie value. A `401` answer turns into `LoginRequired`.

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
///
/// The error keeps the detail message from the transport. The message must
/// not contain a cookie or a token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportError {
    message: String,
}

impl TransportError {
    /// Build an error with one detail message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Return the detail message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
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
/// takes `&self`. Each check carries a generation. Only the newest check
/// writes the state, so an older check that finishes later cannot overwrite
/// a newer result. The JavaScript client wraps this type.
#[derive(Debug)]
pub struct AuthClient<T: Transport> {
    transport: T,
    state: Cell<AuthState>,
    generation: Cell<u64>,
}

impl<T: Transport> AuthClient<T> {
    /// Build a client over one transport.
    ///
    /// This constructor does no network work.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: Cell::new(AuthState::Unknown),
            generation: Cell::new(0),
        }
    }

    /// Return the stored state.
    ///
    /// The stored state changes only when the newest check completes. A
    /// slower older check cannot overwrite the state of a newer check.
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
    ///
    /// A check stores its state only while no later check has started. A
    /// later check supersedes an earlier check. The return value is always
    /// the state of this check.
    pub async fn check_session(&self) -> AuthState {
        let generation = self.generation.get().wrapping_add(1);
        self.generation.set(generation);
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
        if self.generation.get() == generation {
            self.state.set(state);
        }
        state
    }
}

/// The browser transport.
#[cfg(target_arch = "wasm32")]
pub mod browser {
    use super::{Credentials, Method, Request, Response, Transport, TransportError};
    use gloo_net::http::Request as FetchRequest;
    use web_sys::{RequestCredentials, RequestRedirect};

    /// Sends one request through the browser `fetch` call.
    ///
    /// The transport uses a same-origin relative path. The browser adds the
    /// cookies for the page origin. The transport does not follow a
    /// redirect.
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
            // Do not follow a redirect. A login page that answers 200 after a
            // redirect must not look like an authenticated session. The fetch
            // call fails on a redirect, and the client maps that failure to
            // `AuthState::Error`.
            let builder = builder
                .credentials(map_credentials(request.credentials))
                .redirect(RequestRedirect::Error);
            let response = builder
                .send()
                .await
                .map_err(|error| TransportError::new(error.to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::future::Future;
    use std::pin::{Pin, pin};
    use std::rc::Rc;
    use std::task::{Context, Poll, Waker};

    /// A transport that records every request and returns one answer.
    struct FakeTransport {
        requests: Rc<RefCell<Vec<Request>>>,
        reply: Result<Response, TransportError>,
    }

    impl FakeTransport {
        /// Build a transport that returns one status.
        fn with_status(status: u16) -> (Rc<RefCell<Vec<Request>>>, Self) {
            let requests = Rc::new(RefCell::new(Vec::new()));
            (
                Rc::clone(&requests),
                Self {
                    requests,
                    reply: Ok(Response { status }),
                },
            )
        }

        /// Build a transport that fails with one detail message.
        fn with_error() -> (Rc<RefCell<Vec<Request>>>, Self) {
            let requests = Rc::new(RefCell::new(Vec::new()));
            (
                Rc::clone(&requests),
                Self {
                    requests,
                    reply: Err(TransportError::new("the fake transport failed")),
                },
            )
        }
    }

    impl Transport for FakeTransport {
        async fn send(&self, request: Request) -> Result<Response, TransportError> {
            self.requests.borrow_mut().push(request);
            self.reply.clone()
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

    /// A future that stays pending until its gate opens.
    struct WaitForGate(Rc<Cell<bool>>);

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

    /// A transport that answers each call after its own gate opens.
    ///
    /// The first call returns `200`. The second call returns `401`.
    struct GatedTransport {
        calls: Rc<Cell<usize>>,
        first_gate: Rc<Cell<bool>>,
        second_gate: Rc<Cell<bool>>,
    }

    impl Transport for GatedTransport {
        async fn send(&self, _request: Request) -> Result<Response, TransportError> {
            let call = self.calls.get();
            self.calls.set(call + 1);
            let gate = if call == 0 {
                Rc::clone(&self.first_gate)
            } else {
                Rc::clone(&self.second_gate)
            };
            WaitForGate(gate).await;
            let status = if call == 0 { 200 } else { 401 };
            Ok(Response { status })
        }
    }

    /// The client starts in the unknown state.
    #[test]
    fn the_client_starts_unknown() {
        let (_, transport) = FakeTransport::with_status(200);
        let client = AuthClient::new(transport);
        assert_eq!(client.state(), AuthState::Unknown);
    }

    /// The session check sends `GET /auth/me` with cookie credentials.
    #[test]
    fn the_session_check_sends_a_get_request_with_cookie_credentials() {
        let (requests, transport) = FakeTransport::with_status(200);
        let client = AuthClient::new(transport);
        block_on(client.check_session());

        let requests = requests.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::Get);
        assert_eq!(requests[0].path, "/auth/me");
        assert_eq!(requests[0].credentials, Credentials::Include);
    }

    /// A `200` answer authenticates the session.
    #[test]
    fn a_200_answer_authenticates_the_session() {
        let (_, transport) = FakeTransport::with_status(200);
        let client = AuthClient::new(transport);

        assert_eq!(block_on(client.check_session()), AuthState::Authenticated);
        assert_eq!(client.state(), AuthState::Authenticated);
    }

    /// A `401` answer requires a login.
    #[test]
    fn a_401_answer_requires_a_login() {
        let (_, transport) = FakeTransport::with_status(401);
        let client = AuthClient::new(transport);

        assert_eq!(block_on(client.check_session()), AuthState::LoginRequired);
        assert_eq!(client.state(), AuthState::LoginRequired);
    }

    /// A `500` answer sets the error state.
    #[test]
    fn a_500_answer_sets_the_error_state() {
        let (_, transport) = FakeTransport::with_status(500);
        let client = AuthClient::new(transport);

        assert_eq!(block_on(client.check_session()), AuthState::Error);
        assert_eq!(client.state(), AuthState::Error);
    }

    /// A `302` answer sets the error state.
    ///
    /// The native test does not run the browser fetch call, so 302 is the
    /// final status here. The browser redirect mode is compile-checked for
    /// `wasm32` only.
    #[test]
    fn a_302_answer_sets_the_error_state() {
        let (_, transport) = FakeTransport::with_status(302);
        let client = AuthClient::new(transport);

        assert_eq!(block_on(client.check_session()), AuthState::Error);
        assert_eq!(client.state(), AuthState::Error);
    }

    /// A transport failure sets the error state.
    #[test]
    fn a_transport_failure_sets_the_error_state() {
        let (_, transport) = FakeTransport::with_error();
        let client = AuthClient::new(transport);

        assert_eq!(block_on(client.check_session()), AuthState::Error);
        assert_eq!(client.state(), AuthState::Error);
    }

    /// A slow older check cannot overwrite the state of a newer check.
    #[test]
    fn a_slow_older_check_cannot_overwrite_a_newer_state() {
        let first_gate = Rc::new(Cell::new(false));
        let second_gate = Rc::new(Cell::new(false));
        let transport = GatedTransport {
            calls: Rc::new(Cell::new(0)),
            first_gate: Rc::clone(&first_gate),
            second_gate: Rc::clone(&second_gate),
        };
        let client = AuthClient::new(transport);
        let mut context = Context::from_waker(Waker::noop());

        let mut older = pin!(client.check_session());
        assert_eq!(older.as_mut().poll(&mut context), Poll::Pending);
        let mut newer = pin!(client.check_session());
        assert_eq!(newer.as_mut().poll(&mut context), Poll::Pending);

        // The newer 401 check completes first and stores its state.
        second_gate.set(true);
        assert_eq!(
            newer.as_mut().poll(&mut context),
            Poll::Ready(AuthState::LoginRequired)
        );
        assert_eq!(client.state(), AuthState::LoginRequired);

        // The older 200 check completes last. It returns its own state and
        // does not overwrite the stored state.
        first_gate.set(true);
        assert_eq!(
            older.as_mut().poll(&mut context),
            Poll::Ready(AuthState::Authenticated)
        );
        assert_eq!(client.state(), AuthState::LoginRequired);
    }

    /// The state names are stable.
    #[test]
    fn the_state_names_are_stable() {
        assert_eq!(AuthState::Unknown.as_str(), "unknown");
        assert_eq!(AuthState::Authenticated.as_str(), "authenticated");
        assert_eq!(AuthState::LoginRequired.as_str(), "login_required");
        assert_eq!(AuthState::Error.as_str(), "error");
    }

    /// The transport error keeps its message and implements `Error`.
    #[test]
    fn the_transport_error_keeps_its_message() {
        let error = TransportError::new("the browser rejected the request");
        assert_eq!(error.message(), "the browser rejected the request");

        let error: &dyn std::error::Error = &error;
        assert_eq!(error.to_string(), "the browser rejected the request");
    }
}
