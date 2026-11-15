//! The liveness probe. The readiness probe.
//!
//! [`health`](crate::http::health::health) always returns 200. A stuck
//! dependency cannot fail the liveness check.
//! [`ready`](crate::http::health::ready) reflects the injected
//! [`ReadyCheck`](crate::http::health::ReadyCheck) and the optional
//! [`DependencyHealth`](crate::http::health::DependencyHealth).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use actix_web::{HttpResponse, Responder, get, web};

/// How often the background task refreshes the dependency flags.
const PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// The longest time that one probe operation may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The synchronous dependency check that backs `/ready`.
///
/// The server runs the check on every probe poll. An implementation must
/// be cheap. An implementation must not block. A lock `try_read` is
/// acceptable. I/O is not acceptable. `true` means ready.
pub type ReadyCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// Last-known health of the external dependencies that `/ready` covers.
///
/// The probes that refresh these flags run in the background, so reading
/// them never blocks the request path. `true` means the last probe
/// succeeded. The flags start as `true`: startup already verified the
/// dependencies before the listener bound.
#[derive(Clone)]
pub struct DependencyHealth {
    /// Last-known reachability of the object store (S3 or compatible).
    pub s3: Arc<AtomicBool>,
    /// Last-known reachability of the OIDC discovery document.
    pub oidc: Arc<AtomicBool>,
}

impl std::fmt::Debug for DependencyHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DependencyHealth")
            .field("s3", &self.s3.load(Ordering::Relaxed))
            .field("oidc", &self.oidc.load(Ordering::Relaxed))
            .finish()
    }
}

impl Default for DependencyHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyHealth {
    /// Creates a health record whose flags both start as `true`.
    pub fn new() -> Self {
        Self {
            s3: Arc::new(AtomicBool::new(true)),
            oidc: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Creates a health record from two existing flags.
    pub fn from_flags(s3: Arc<AtomicBool>, oidc: Arc<AtomicBool>) -> Self {
        Self { s3, oidc }
    }

    /// Returns the last-known S3 reachability.
    pub fn s3(&self) -> bool {
        self.s3.load(Ordering::Relaxed)
    }

    /// Returns the last-known S3 reachability.
    pub fn s3_ok(&self) -> bool {
        self.s3()
    }

    /// Returns the last-known S3 reachability.
    pub fn s3_healthy(&self) -> bool {
        self.s3()
    }

    /// Returns the last-known S3 reachability.
    pub fn is_s3_healthy(&self) -> bool {
        self.s3()
    }

    /// Returns the last-known OIDC reachability.
    pub fn oidc(&self) -> bool {
        self.oidc.load(Ordering::Relaxed)
    }

    /// Returns the last-known OIDC reachability.
    pub fn oidc_ok(&self) -> bool {
        self.oidc()
    }

    /// Returns the last-known OIDC reachability.
    pub fn oidc_healthy(&self) -> bool {
        self.oidc()
    }

    /// Returns the last-known OIDC reachability.
    pub fn is_oidc_healthy(&self) -> bool {
        self.oidc()
    }

    /// Returns `true` when both dependencies were reachable at the last probe.
    pub fn is_healthy(&self) -> bool {
        self.s3() && self.oidc()
    }

    /// Returns `true` when both dependencies were reachable at the last probe.
    pub fn all_ok(&self) -> bool {
        self.is_healthy()
    }

    /// Returns `true` when both dependencies were reachable at the last probe.
    pub fn healthy(&self) -> bool {
        self.is_healthy()
    }

    /// Returns `true` when both dependencies were reachable at the last probe.
    pub fn ok(&self) -> bool {
        self.is_healthy()
    }

    /// Stores the last-known S3 reachability.
    pub fn set_s3(&self, value: bool) {
        self.s3.store(value, Ordering::Relaxed);
    }

    /// Stores the last-known S3 reachability.
    pub fn set_s3_ok(&self, value: bool) {
        self.set_s3(value);
    }

    /// Stores the last-known S3 reachability.
    pub fn set_s3_healthy(&self, value: bool) {
        self.set_s3(value);
    }

    /// Stores the last-known OIDC reachability.
    pub fn set_oidc(&self, value: bool) {
        self.oidc.store(value, Ordering::Relaxed);
    }

    /// Stores the last-known OIDC reachability.
    pub fn set_oidc_ok(&self, value: bool) {
        self.set_oidc(value);
    }

    /// Stores the last-known OIDC reachability.
    pub fn set_oidc_healthy(&self, value: bool) {
        self.set_oidc(value);
    }

    /// Spawns a background task that refreshes both flags periodically.
    ///
    /// The task never blocks the request path. The first probe runs as soon
    /// as the task is scheduled. Each interval runs one probe pass with a
    /// timeout around each probe operation.
    pub fn spawn_probes<C: crate::CancelToken>(
        &self,
        s3_store: Arc<dyn object_store::ObjectStore>,
        oidc_discovery_url: String,
        cancel: C,
    ) -> tokio::task::JoinHandle<()> {
        self.spawn_probes_with_interval(
            s3_store,
            oidc_discovery_url,
            cancel,
            PROBE_INTERVAL,
            PROBE_TIMEOUT,
        )
    }

    /// Spawns the probes with explicit timing. Tests use this function to
    /// avoid a ten second wait.
    fn spawn_probes_with_interval<C: crate::CancelToken>(
        &self,
        s3_store: Arc<dyn object_store::ObjectStore>,
        oidc_discovery_url: String,
        cancel: C,
        interval: Duration,
        probe_timeout: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let dep_health = self.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if cancel.is_cancelled() {
                    break;
                }
                // A failed request and a timeout both report the dependency
                // as down.
                let s3_ok =
                    match tokio::time::timeout(probe_timeout, s3_store.list_with_delimiter(None))
                        .await
                    {
                        Ok(result) => result.is_ok(),
                        Err(_) => false,
                    };
                dep_health.set_s3(s3_ok);
                if cancel.is_cancelled() {
                    break;
                }
                let oidc_ok = match tokio::time::timeout(
                    probe_timeout,
                    client.get(&oidc_discovery_url).send(),
                )
                .await
                {
                    Ok(Ok(response)) => response.status().is_success(),
                    Ok(Err(_)) | Err(_) => false,
                };
                dep_health.set_oidc(oidc_ok);
            }
        })
    }
}

/// The readiness probe returns `200` when the injected [`ReadyCheck`]
/// and the optional [`DependencyHealth`] pass. It returns `503` when the
/// dependencies are stuck. It returns `200` when no check is wired.
/// Startup already waits for S3/OIDC/JWKS before it binds the listener.
#[utoipa::path(get, path = "/ready", tag = "health", responses((status = 200, description = "ready"), (status = 503, description = "not ready")))]
#[get("/ready")]
pub async fn ready(
    check: Option<web::Data<ReadyCheck>>,
    dependency_health: Option<web::Data<DependencyHealth>>,
) -> impl Responder {
    if let Some(check) = check
        && !check.get_ref()()
    {
        return HttpResponse::ServiceUnavailable().finish();
    }
    if let Some(dep_health) = dependency_health
        && !dep_health.is_healthy()
    {
        return HttpResponse::ServiceUnavailable().finish();
    }
    HttpResponse::Ok().finish()
}

/// The liveness probe endpoint returns `200 OK` with an empty body.
#[utoipa::path(get, path = "/health", tag = "health", responses((status = 200, description = "OK")))]
#[get("/health")]
pub async fn health() -> impl Responder {
    HttpResponse::Ok().finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test};

    /// An in-memory object store that fails listing on demand.
    ///
    /// The wrapper delegates every other operation to
    /// [`object_store::memory::InMemory`].
    #[derive(Debug)]
    struct FlakyStore {
        inner: Arc<dyn object_store::ObjectStore>,
        fail: Arc<AtomicBool>,
    }

    impl std::fmt::Display for FlakyStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("FlakyStore")
        }
    }

    #[async_trait::async_trait]
    impl object_store::ObjectStore for FlakyStore {
        async fn put_opts(
            &self,
            location: &object_store::path::Path,
            payload: object_store::PutPayload,
            opts: object_store::PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            self.inner.put_opts(location, payload, opts).await
        }

        async fn put_multipart_opts(
            &self,
            _location: &object_store::path::Path,
            _opts: object_store::PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            Err(object_store::Error::NotSupported {
                source: "the probe test does not use multipart".to_string().into(),
            })
        }

        async fn get_opts(
            &self,
            location: &object_store::path::Path,
            options: object_store::GetOptions,
        ) -> object_store::Result<object_store::GetResult> {
            self.inner.get_opts(location, options).await
        }

        async fn delete(&self, location: &object_store::path::Path) -> object_store::Result<()> {
            self.inner.delete(location).await
        }

        fn list(
            &self,
            prefix: Option<&object_store::path::Path>,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
        {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&object_store::path::Path>,
        ) -> object_store::Result<object_store::ListResult> {
            if self.fail.load(Ordering::Relaxed) {
                return Err(object_store::Error::Generic {
                    store: "probe-test",
                    source: Box::new(std::io::Error::other("injected failure")),
                });
            }
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy(
            &self,
            from: &object_store::path::Path,
            to: &object_store::path::Path,
        ) -> object_store::Result<()> {
            self.inner.copy(from, to).await
        }

        async fn copy_if_not_exists(
            &self,
            from: &object_store::path::Path,
            to: &object_store::path::Path,
        ) -> object_store::Result<()> {
            self.inner.copy_if_not_exists(from, to).await
        }

        fn list_with_offset(
            &self,
            prefix: Option<&object_store::path::Path>,
            offset: &object_store::path::Path,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
        {
            self.inner.list_with_offset(prefix, offset)
        }
    }

    /// Serves the OIDC discovery document with `status`.
    async fn serve_oidc(server: &wiremock::MockServer, status: u16) {
        server.reset().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/oidc"))
            .respond_with(wiremock::ResponseTemplate::new(status))
            .mount(server)
            .await;
    }

    /// Yields until `condition` is true.
    ///
    /// The test pauses the tokio clock. Each yield lets a pending probe
    /// finish, so the call needs no wall-clock timer.
    async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
        for _ in 0..10_000 {
            if condition() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("timed out waiting for {what}");
    }

    /// Advances the paused clock by `by`, then yields until `condition` is
    /// true.
    async fn advance_until(by: Duration, what: &str, condition: impl FnMut() -> bool) {
        tokio::time::advance(by).await;
        wait_for(what, condition).await;
    }

    /// A failed probe clears the flag. A later successful probe sets it
    /// again. This is the regression test for a probe loop that never ran.
    #[tokio::test(start_paused = true)]
    async fn probes_clear_and_restore_the_dependency_flags() {
        let server = wiremock::MockServer::start().await;
        serve_oidc(&server, 200).await;

        let fail_s3 = Arc::new(AtomicBool::new(true));
        let store: Arc<dyn object_store::ObjectStore> = Arc::new(FlakyStore {
            inner: Arc::new(object_store::memory::InMemory::new()),
            fail: Arc::clone(&fail_s3),
        });
        let dep_health = DependencyHealth::new();
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = dep_health.spawn_probes_with_interval(
            store,
            format!("{}/oidc", server.uri()),
            Arc::clone(&cancel),
            Duration::from_millis(100),
            Duration::from_secs(60),
        );

        // The first tick is immediate. The failing store clears the S3 flag.
        wait_for("the S3 flag to clear", || !dep_health.s3()).await;

        // A passing store restores the S3 flag.
        fail_s3.store(false, Ordering::Relaxed);
        advance_until(Duration::from_millis(100), "the S3 flag to recover", || {
            dep_health.s3()
        })
        .await;

        // A failing OIDC endpoint clears the OIDC flag.
        serve_oidc(&server, 500).await;
        advance_until(Duration::from_millis(100), "the OIDC flag to clear", || {
            !dep_health.oidc()
        })
        .await;

        // A passing OIDC endpoint restores the OIDC flag.
        serve_oidc(&server, 200).await;
        advance_until(
            Duration::from_millis(100),
            "the OIDC flag to recover",
            || dep_health.oidc(),
        )
        .await;

        cancel.store(true, Ordering::Relaxed);
        handle.abort();
    }

    #[actix_web::test]
    async fn health_returns_200() {
        let app = test::init_service(App::new().service(health)).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn ready_returns_200_when_no_check_is_wired() {
        let app = test::init_service(App::new().service(ready)).await;
        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn ready_reflects_the_result_of_the_check() {
        let passing: ReadyCheck = Arc::new(|| true);
        let app =
            test::init_service(App::new().app_data(web::Data::new(passing)).service(ready)).await;
        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(resp.status(), 200);

        let failing: ReadyCheck = Arc::new(|| false);
        let app =
            test::init_service(App::new().app_data(web::Data::new(failing)).service(ready)).await;
        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(resp.status(), 503);
    }

    #[actix_web::test]
    async fn ready_reflects_dependency_health() {
        let healthy = DependencyHealth::new();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(healthy.clone()))
                .service(ready),
        )
        .await;
        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(resp.status(), 200);

        let unhealthy = DependencyHealth::new();
        unhealthy.set_s3(false);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(unhealthy))
                .service(ready),
        )
        .await;
        let resp =
            test::call_service(&app, test::TestRequest::get().uri("/ready").to_request()).await;
        assert_eq!(resp.status(), 503);
    }
}
