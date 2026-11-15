//! Middleware that adds the security response headers.
//!
//! The middleware sets four headers on every response:
//!
//! - `X-Content-Type-Options: nosniff`
//! - `X-Frame-Options: DENY`
//! - `Referrer-Policy: no-referrer`
//! - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
//!
//! The middleware does not set the policy on `/openapi.json` and
//! `/swagger-ui/*`. Swagger UI loads its own scripts and styles, so the
//! policy would break it.
//!
//! The middleware sets `Strict-Transport-Security` only when the request
//! uses HTTPS. The header on a plain HTTP response makes no sense, and a
//! browser ignores it.

use std::{
    future::{Ready, ready},
    rc::Rc,
};

use actix_web::{
    Error,
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{self, HeaderValue},
};
use futures_util::future::LocalBoxFuture;

/// The lifetime of the HSTS rule, in seconds. The value is one year.
pub const HSTS_MAX_AGE_SECS: u64 = 31_536_000;

/// The renderable value of the HSTS header.
pub const STRICT_TRANSPORT_SECURITY_VALUE: &str = "max-age=31536000; includeSubDomains";

/// The policy for an API response. It blocks every resource type. It also
/// blocks every frame.
pub const API_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; frame-ancestors 'none'";

/// The route of the OpenAPI document. The policy is off for this route.
const OPENAPI_PATH: &str = "/openapi.json";

/// The route prefix of the Swagger UI. The policy is off for this prefix.
const SWAGGER_UI_PREFIX: &str = "/swagger-ui";

/// Returns `true` when the path is an API route.
///
/// The Swagger UI needs its own policy. The OpenAPI document is JSON, but
/// the code keeps one rule for both docs routes.
fn allows_api_policy(path: &str) -> bool {
    path != OPENAPI_PATH && path != SWAGGER_UI_PREFIX && !path.starts_with("/swagger-ui/")
}

/// The middleware factory that adds the security response headers.
///
/// Register the middleware next to
/// [`ServerTimeMiddleware`](super::server_time::ServerTimeMiddleware). The
/// middleware then covers the handlers, the rate limiter, and the errors.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersService {
            service: Rc::new(service),
        }))
    }
}

/// The middleware service for one worker.
pub struct SecurityHeadersService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let path = req.path().to_string();
        let is_https = req.connection_info().scheme() == "https";

        Box::pin(async move {
            let mut res = service.call(req).await?;
            let headers = res.headers_mut();
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
            headers.insert(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            );
            if allows_api_policy(&path) {
                headers.insert(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static(API_CONTENT_SECURITY_POLICY),
                );
            }
            if is_https {
                headers.insert(
                    header::STRICT_TRANSPORT_SECURITY,
                    HeaderValue::from_static(STRICT_TRANSPORT_SECURITY_VALUE),
                );
            }
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{HttpResponse, http::StatusCode, test, web};

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    /// Returns the header value as a string.
    fn header<'a>(res: &'a ServiceResponse, name: &str) -> &'a str {
        res.headers()
            .get(name)
            .unwrap_or_else(|| panic!("{name} header is missing"))
            .to_str()
            .expect("ascii header value")
    }

    /// A normal API response carries every header except HSTS. The request
    /// uses plain HTTP.
    #[actix_web::test]
    async fn api_responses_carry_the_security_headers() {
        let app = test::init_service(
            actix_web::App::new()
                .wrap(SecurityHeaders)
                .route("/thing", web::get().to(ok)),
        )
        .await;
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/thing").to_request()).await;

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(header(&res, "x-content-type-options"), "nosniff");
        assert_eq!(header(&res, "x-frame-options"), "DENY");
        assert_eq!(header(&res, "referrer-policy"), "no-referrer");
        assert_eq!(
            header(&res, "content-security-policy"),
            API_CONTENT_SECURITY_POLICY
        );
        assert!(
            res.headers().get("strict-transport-security").is_none(),
            "a plain HTTP response must not carry HSTS"
        );
    }

    /// The liveness probe is a normal API response. It must carry the same
    /// headers, because a proxy in front of the server also covers `/health`.
    #[actix_web::test]
    async fn health_carries_the_security_headers() {
        let app = test::init_service(
            actix_web::App::new()
                .wrap(SecurityHeaders)
                .service(crate::http::health::health),
        )
        .await;
        let res =
            test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(header(&res, "x-content-type-options"), "nosniff");
        assert_eq!(header(&res, "x-frame-options"), "DENY");
        assert_eq!(header(&res, "referrer-policy"), "no-referrer");
        assert_eq!(
            header(&res, "content-security-policy"),
            API_CONTENT_SECURITY_POLICY
        );
    }

    /// A request that arrives through TLS gets HSTS. The proxy reports the
    /// scheme in `X-Forwarded-Proto`.
    #[actix_web::test]
    async fn https_requests_carry_hsts() {
        let app = test::init_service(
            actix_web::App::new()
                .wrap(SecurityHeaders)
                .route("/thing", web::get().to(ok)),
        )
        .await;
        let res = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/thing")
                .insert_header(("x-forwarded-proto", "https"))
                .to_request(),
        )
        .await;

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            header(&res, "strict-transport-security"),
            STRICT_TRANSPORT_SECURITY_VALUE
        );
        assert!(
            STRICT_TRANSPORT_SECURITY_VALUE.contains("includeSubDomains"),
            "HSTS must cover subdomains"
        );
        let max_age = STRICT_TRANSPORT_SECURITY_VALUE
            .split(';')
            .next()
            .and_then(|directive| directive.trim().strip_prefix("max-age="))
            .and_then(|value| value.parse::<u64>().ok());
        assert_eq!(
            max_age,
            Some(HSTS_MAX_AGE_SECS),
            "the HSTS header must use the declared one-year lifetime"
        );
    }

    /// Swagger UI must load its assets. The API policy blocks those assets,
    /// so the docs routes omit it. The other headers still apply.
    #[actix_web::test]
    async fn docs_routes_skip_the_api_policy() {
        let app = test::init_service(
            actix_web::App::new()
                .wrap(SecurityHeaders)
                .route("/openapi.json", web::get().to(ok))
                .route("/swagger-ui/index.html", web::get().to(ok)),
        )
        .await;

        for uri in ["/openapi.json", "/swagger-ui/index.html"] {
            let res =
                test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
            assert_eq!(res.status(), StatusCode::OK, "{uri}");
            assert!(
                res.headers().get("content-security-policy").is_none(),
                "{uri} must not carry the API policy"
            );
            assert_eq!(header(&res, "x-content-type-options"), "nosniff", "{uri}");
            assert_eq!(header(&res, "x-frame-options"), "DENY", "{uri}");
            assert_eq!(header(&res, "referrer-policy"), "no-referrer", "{uri}");
        }
    }
}
