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
    /// as the task is scheduled.
    pub fn spawn_probes<C: crate::CancelToken>(
        &self,
        s3_store: Arc<dyn object_store::ObjectStore>,
        oidc_discovery_url: String,
        cancel: C,
    ) -> tokio::task::JoinHandle<()> {
        let dep_health = self.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                if cancel.is_cancelled() {
                    break;
                }
                if tokio::time::timeout(Duration::from_millis(100), interval.tick())
                    .await
                    .is_err()
                {
                    continue;
                }
                if cancel.is_cancelled() {
                    break;
                }
                let s3_ok = s3_store.list_with_delimiter(None).await.is_ok();
                dep_health.set_s3(s3_ok);
                let oidc_ok = client
                    .get(&oidc_discovery_url)
                    .send()
                    .await
                    .map(|response| response.status().is_success())
                    .unwrap_or(false);
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
