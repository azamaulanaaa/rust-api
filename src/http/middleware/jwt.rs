//! Actix middleware validating JWTs against a JWKS-backed key store.
//!
//! Validated claims (generic over `C`) are inserted into request extensions
//! — consume them with [`Validated`](crate::http::middleware::jwt::Validated) —
//! and requests without any token pass through unmodified so routes decide
//! their own auth requirements.

use std::{
    future::{Ready, ready},
    marker::PhantomData,
    rc::Rc,
};

use actix_web::{
    Error, FromRequest, HttpMessage, HttpRequest,
    dev::{Payload, Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::SET_COOKIE,
};
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::decode;
pub use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde::{Deserialize, de::DeserializeOwned};

use super::bearer_token::BearerToken;
use super::jwks::JwksKeys;
use crate::http::error::ApiError;

// Preserve the public API surface for consumers of this module.
pub use super::jwks::SigningKey;

/// Literal segment marking a multi-tenant issuer template (Azure AD style:
/// `https://login.microsoftonline.com/{tenantid}/v2.0`).
const TENANT_PLACEHOLDER: &str = "{tenantid}";

/// Path of the browser session cookie this middleware reads.
const AUTH_COOKIE: &str = "auth_token";

/// A multi-tenant issuer template: the provider's discovery document
/// publishes an issuer containing a literal `{tenantid}` placeholder that
/// each token resolves to its issuing tenant.
///
/// # Why the allowlist is not optional
///
/// The expected issuer is necessarily derived from the token's *own*
/// unverified `tid` claim, because no static issuer can match a placeholder.
/// That derivation is a tautology over attacker-supplied data: any token
/// whose `iss` and `tid` agree with each other satisfies it. Signature
/// validation does not help either — a multi-tenant app registration publishes
/// one JWKS containing every tenant's keys, so a token minted by a tenant the
/// operator never intended to trust verifies against keys already cached here.
///
/// Audience is **not** a substitute: `aud` is the client ID, which is
/// identical for every tenant that has consented to the app registration. The
/// tenant gate is therefore the allowlist and nothing else, and it fails
/// closed — an empty allowlist accepts no tenant at all, and
/// [`crate::config::Config::validate`] refuses to start a templated issuer
/// without one.
#[derive(Debug, Clone)]
pub struct IssuerTemplate {
    /// Issuer portion before the `{tenantid}` placeholder.
    prefix: String,
    /// Issuer portion after the `{tenantid}` placeholder.
    suffix: String,
    /// The only tenant identifiers this deployment accepts.
    allowed_tenants: Vec<String>,
}

impl IssuerTemplate {
    /// Parses a template from a discovered issuer; `None` when the issuer is
    /// not templated (the common single-tenant case).
    ///
    /// `allowed_tenants` is the tenant allowlist and applies only to the
    /// templated case; it is required to be non-empty by config validation,
    /// but an empty list is still honoured here as "reject everything" rather
    /// than "allow everything".
    pub fn parse(issuer: &str, allowed_tenants: Vec<String>) -> Option<Self> {
        let (prefix, suffix) = issuer.split_once(TENANT_PLACEHOLDER)?;
        Some(Self {
            prefix: prefix.to_string(),
            suffix: suffix.to_string(),
            allowed_tenants,
        })
    }

    /// Resolves the template for a tenant identifier that is *known* to be
    /// allowed, without re-checking it.
    ///
    /// Prefer [`IssuerTemplate::resolve_checked`]. This exists for tests and
    /// for building the set of issuers to accept, not for validating a token.
    pub fn resolve(&self, tenant_id: &str) -> String {
        format!("{}{}{}", self.prefix, tenant_id, self.suffix)
    }

    /// Resolves the template for a tenant identifier, rejecting any tenant
    /// outside the configured allowlist.
    ///
    /// The error string names the rejected tenant and is safe to log; it is
    /// never serialized into a client response.
    pub fn resolve_checked(&self, tenant_id: &str) -> Result<String, String> {
        if !self
            .allowed_tenants
            .iter()
            .any(|allowed| allowed == tenant_id)
        {
            return Err(format!(
                "tenant `{tenant_id}` is not in the configured allowlist"
            ));
        }
        Ok(self.resolve(tenant_id))
    }

    /// The tenant identifiers this deployment accepts.
    pub fn allowed_tenants(&self) -> &[String] {
        &self.allowed_tenants
    }
}

/// Extracts a top-level string field from an unverified JWT payload.
///
/// Used only to *derive validation inputs* (e.g. the expected issuer from
/// `tid`) before the verified decode; every security decision still goes
/// through the signature-checked decode afterwards.
pub(crate) fn extract_unverified_claim(token: &str, field: &str) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let payload_b64 = token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    value.get(field)?.as_str().map(str::to_string)
}

/// Audience (`aud`) claim values: providers emit either a single string or
/// an array of strings, both of which deserialize into this enum.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience value.
    Single(String),
    /// Multiple audience values.
    Multi(Vec<String>),
}

/// Standard ID-token claims extracted from a validated JWT and inserted
/// into request extensions.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    /// Issuer: the identity provider that issued the token.
    pub iss: String,
    /// Subject: the stable user identifier.
    pub sub: String,
    /// Audience(s) the token was issued for.
    pub aud: Audience,
    /// Expiration time (unix seconds); validated on every request.
    pub exp: u64,
    /// Not-before time (unix seconds), when present.
    pub nbf: Option<u64>,
    /// Issued-at time (unix seconds), when present.
    pub iat: Option<u64>,
    /// Nonce echoed back by the provider during the OIDC flow.
    pub nonce: Option<String>,
    /// Unique token identifier; usable as a revocation key.
    pub jti: Option<String>,
}

/// Actix middleware validating JWTs against a [`JwksKeys`] store before the
/// request reaches the wrapped service. Validated claims (generic over `C`)
/// are inserted into request extensions — consume them with [`Validated`] —
/// and requests without any token pass through unmodified so routes decide
/// their own auth requirements.
#[derive(Clone)]
pub struct JwtClaimsMiddleware<C>
where
    C: DeserializeOwned,
{
    keys: JwksKeys,
    validation: Validation,
    issuer_template: Option<IssuerTemplate>,
    _claims: PhantomData<C>,
}

impl<C> JwtClaimsMiddleware<C>
where
    C: DeserializeOwned,
{
    /// Assembles the middleware from an existing key store and base
    /// validation config (audience/issuer/leeway).
    pub fn new(keys: JwksKeys, validation: Validation) -> Self {
        Self {
            keys,
            validation,
            issuer_template: None,
            _claims: PhantomData,
        }
    }

    /// Fetches the JWKS document from `jwks_url` and builds the middleware,
    /// pinning `audience` and `issuer` validation. See [`JwksKeys`] for the
    /// refresh behavior.
    pub async fn new_with_jks(
        jwks_url: &str,
        audience: &str,
        issuer: &str,
    ) -> anyhow::Result<Self> {
        let keys = JwksKeys::new(jwks_url).await?;

        // Base validation carries the audience/issuer checks; the expected
        // algorithm is re-pinned per request from the selected signing key.
        // A templated issuer ({tenantid}) cannot be pinned statically — the
        // middleware resolves it per request from the token's tid claim, and
        // checks that claim against the allowlist.
        let issuer_template = IssuerTemplate::parse(issuer, Vec::new());
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        if issuer_template.is_none() {
            validation.set_issuer(&[issuer]);
        }

        Ok(Self {
            keys,
            validation,
            issuer_template,
            _claims: PhantomData,
        })
    }

    /// Sets the tenant allowlist for a templated (`{tenantid}`) issuer.
    ///
    /// Required for such an issuer and ignored for a single-tenant one,
    /// where the issuer is pinned statically. Left unset, the allowlist is
    /// empty, which **rejects every tenant** — fail closed by construction,
    /// so forgetting this cannot silently open the deployment to every tenant
    /// that has consented to a multi-tenant app registration.
    ///
    /// [`crate::oidc::OidcClient::new`] rejects a templated issuer with an
    /// empty allowlist, so a served app cannot reach the unset state.
    pub fn with_allowed_tenants(mut self, allowed_tenants: Vec<String>) -> Self {
        if let Some(template) = &mut self.issuer_template {
            template.allowed_tenants = allowed_tenants;
        }
        self
    }
}

impl<S, B, C> Transform<S, ServiceRequest> for JwtClaimsMiddleware<C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    C: DeserializeOwned + Clone + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtClaimsMiddlewareService<S, C>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtClaimsMiddlewareService {
            service: Rc::new(service),
            keys: self.keys.clone(),
            validation: self.validation.clone(),
            issuer_template: self.issuer_template.clone(),
            _claims: PhantomData,
        }))
    }
}

/// Extractor for claims validated by [`JwtClaimsMiddleware`].
///
/// Unlike `web::ReqData`, which fails extraction with a 500 when the
/// middleware did not run or no token was presented, this resolves to a
/// **401 Unauthorized** — anonymous hits on protected routes must not look
/// like server faults.
#[derive(Debug)]
pub struct Validated<C>(pub C);

impl<C> std::ops::Deref for Validated<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C> FromRequest for Validated<C>
where
    C: DeserializeOwned + Clone + 'static,
{
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(
            req.extensions()
                .get::<C>()
                .cloned()
                .map(Self)
                .ok_or_else(|| ApiError::MissingCredentials.into()),
        )
    }
}

/// The per-worker instantiated middleware produced by
/// [`JwtClaimsMiddleware::new_transform`]. Not constructed directly.
pub struct JwtClaimsMiddlewareService<S, C> {
    service: Rc<S>,
    keys: JwksKeys,
    validation: Validation,
    issuer_template: Option<IssuerTemplate>,
    _claims: PhantomData<C>,
}

impl<S, B, C> Service<ServiceRequest> for JwtClaimsMiddlewareService<S, C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    C: DeserializeOwned + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let keys = self.keys.clone();
        let validation = self.validation.clone();
        let issuer_template = self.issuer_template.clone();

        // Bearer header wins over the auth cookie: a stale/expired browser
        // session cookie must not shadow an explicitly presented header.
        // NOTE: these must be separate statements — `cookie()` mutates the
        // request's extension-based parse cache, which would collide with a
        // live extensions() borrow held across an array literal.
        let bearer = req.extensions().get::<BearerToken>().cloned().map(|v| v.0);
        let cookie_token = req.cookie(AUTH_COOKIE).map(|c| c.value().to_string());
        // Which source the CHOSEN token came from, not merely that one was
        // chosen. Only a stale cookie is worth clearing; a bad `Authorization`
        // header says nothing about the cookie, and clearing on it would
        // destroy a working session.
        let chosen_from_cookie = bearer.is_none() && cookie_token.is_some();
        let token = bearer.or(cookie_token);
        Box::pin(async move {
            // An unusable credential is NOT the same as a missing one, and
            // this middleware is wrapped over the whole /auth scope --
            // including /auth/login, /auth/callback and /auth/logout, none of
            // which take a `Validated<C>`. Hard-failing here made the cookie's
            // own lifetime the lockout: `callback` sets it with a 7-day
            // max_age while the token's `exp` is provider-controlled and
            // typically ~1h, so an hour after login every browser request
            // carried an expired JWT, `/auth/login` 401'd before its handler
            // ran, and the user could neither re-authenticate nor clear the
            // cookie.
            //
            // So an unusable credential now degrades to anonymous and the
            // request proceeds. Routes that need a subject still 401, because
            // `Validated<C>` is what produces that 401 -- not this
            // middleware. An invalid token is evidence of an expired session,
            // not a reason to refuse to serve the endpoints whose entire job
            // is to establish a new one.
            //
            // The precedence above is unaffected: a valid header still wins,
            // and a stale cookie still cannot shadow it.
            let mut unusable: Option<String> = None;

            if let Some(token) = token {
                // `Ok` inserts the claims. `Err((reason, true))` is a security decision
                // and stays a hard 401 -- see the line table below. `Err((reason, false))` is an
                // unusable *session* and degrades to anonymous below.
                //
                // The distinction is load-bearing. A token from a tenant the
                // allowlist rejects is an attack, and Blocker 1's whole point
                // is that it fails CLOSED -- so it must not quietly become "no
                // credential", which would serve every unauthenticated route
                // with a forged token in hand. An expired `exp` is the opposite:
                // it is a browser replaying its own dead cookie, and refusing it
                // locks the user out of the very endpoints that would fix it.
                let claims = async {
                    let header = jsonwebtoken::decode_header(&token)
                        .map_err(|e| (format!("undecodable header: {e}"), true))?;

                    let signing_key = keys
                        .get(header.kid.as_deref())
                        .await
                        .ok_or_else(|| ("no signing key matches kid".to_string(), true))?;

                    // Pin validation to the selected key's own algorithm so a
                    // token cannot downgrade to an unexpected algorithm. For
                    // multi-tenant providers, derive the exact expected issuer
                    // from the token's tid claim first.
                    let mut validation = validation.clone();
                    validation.algorithms = vec![signing_key.algorithm];
                    if let Some(template) = &issuer_template {
                        let tenant_id = extract_unverified_claim(&token, "tid")
                            .filter(|t| !t.is_empty())
                            .ok_or_else(|| ("token has no tenant identifier".to_string(), true))?;
                        // The issuer is derived from the token's own `tid`, so
                        // resolving it proves nothing on its own. This check is
                        // the tenant gate and it fails closed.
                        let expected = template
                            .resolve_checked(&tenant_id)
                            .map_err(|cause| (cause, true))?;
                        validation.set_issuer(&[expected]);
                    }

                    decode::<C>(&token, &signing_key.decoding_key, &validation)
                        .map(|td| td.claims)
                        .map_err(|e| (format!("token failed validation: {e}"), false))
                }
                .await;

                match claims {
                    Ok(claims) => {
                        req.extensions_mut().insert(claims);
                    }
                    Err((reason, hard)) if hard => {
                        // Fail closed: a token the tenant gate rejects never
                        // reaches a handler.
                        return Err(ApiError::InvalidCredentials(reason.into()).into());
                    }
                    Err((reason, _)) => {
                        tracing::warn!(
                            reason,
                            "unusable credential; continuing unauthenticated so the public \
                             auth routes stay reachable"
                        );
                        unusable = Some(reason);
                    }
                }
            }

            let mut resp = svc.call(req).await?;

            // Clear the stale cookie on the way out, so the browser stops
            // replaying an expired JWT until the next successful login.
            //
            // Both conditions below are load-bearing.
            //
            // Only when the CHOSEN credential was the cookie: a request whose
            // token came from an `Authorization` header has told us nothing
            // about the cookie, and clearing it would delete a working session
            // the client never asked us to touch.
            //
            // And never when the handler has already SET `auth_token`. This
            // middleware wraps `/auth/callback`, which sets a fresh session
            // cookie with `max_age` 7 days. Appending our own
            // `auth_token=; Max-Age=0` after it puts two `Set-Cookie` headers
            // with the same (name, domain, path) on one response, and browsers
            // apply them in order with the LAST write winning -- so the callback
            // would complete having DELETED the session it had just established.
            // The user would see a 200 and a token, and be anonymous on the
            // next request: the exact lockout this change exists to remove,
            // reached through the endpoint meant to cure it.
            let clears_session = unusable.is_some() && chosen_from_cookie;
            let handler_set_session = resp.headers().get_all(SET_COOKIE).any(|value| {
                value.to_str().is_ok_and(|v| {
                    v.starts_with(&format!("{AUTH_COOKIE}="))
                        && !v.starts_with(&format!("{AUTH_COOKIE}=;"))
                })
            });
            if clears_session && !handler_set_session {
                resp.headers_mut().append(
                    actix_web::http::header::SET_COOKIE,
                    actix_web::http::header::HeaderValue::from_static(
                        "auth_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
                    ),
                );
            }
            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::middleware::jwks::test_support::*;
    use serde_json::json;

    #[tokio::test]
    async fn loads_keys_and_decodes_token() -> anyhow::Result<()> {
        let (key_a, enc_a) = rsa_key("kid-a")?;
        let server = spawn_jwks(json!({ "keys": [key_a] })).await;

        let keys = JwksKeys::new(format!("{}/jwks", server.uri())).await?;

        let token = sign_rs256(
            &json!({ "sub": "u1", "exp": 2000000000u64 }),
            "kid-a",
            &enc_a,
        )?;
        let signing_key = keys.get(Some("kid-a")).await.expect("kid-a should resolve");
        assert_eq!(signing_key.algorithm, Algorithm::RS256);

        let validation = Validation::new(Algorithm::RS256);
        let decoded = decode::<TestClaims>(&token, &signing_key.decoding_key, &validation)?;
        assert_eq!(decoded.claims.sub, "u1");

        Ok(())
    }

    fn sample_claims() -> Claims {
        Claims {
            iss: "https://idp.test".to_string(),
            sub: "u1".to_string(),
            aud: Audience::Single("client".to_string()),
            exp: 2000000000,
            nbf: None,
            iat: Some(1000000000),
            nonce: None,
            jti: None,
        }
    }

    #[actix_web::test]
    async fn validated_extractor_resolves_inserted_claims() {
        use actix_web::test::TestRequest;

        let (req, mut payload) = TestRequest::default().to_http_parts();
        req.extensions_mut().insert(sample_claims());

        let extracted = Validated::<Claims>::from_request(&req, &mut payload)
            .await
            .expect("claims present");
        assert_eq!(extracted.sub, "u1"); // Deref to the inner claims
    }

    #[actix_web::test]
    async fn validated_extractor_is_unauthorized_when_missing() {
        use actix_web::test::TestRequest;

        let (req, mut payload) = TestRequest::default().to_http_parts();

        let result = Validated::<Claims>::from_request(&req, &mut payload).await;
        assert_eq!(result.unwrap_err().as_response_error().status_code(), 401);
    }

    #[test]
    fn issuer_template_parses_and_resolves() {
        let tpl = IssuerTemplate::parse(
            "https://login.test/{tenantid}/v2.0",
            vec!["abc-123".to_string()],
        )
        .expect("templated issuer should parse");
        assert_eq!(tpl.resolve("abc-123"), "https://login.test/abc-123/v2.0");
        assert!(IssuerTemplate::parse("https://plain.test/v2.0", Vec::new()).is_none());
    }

    /// The allowlist is the only real gate on a templated issuer: the
    /// expected issuer is derived from the token's own `tid`, and `aud` is
    /// the shared client ID, so neither can distinguish tenants.
    #[test]
    fn templated_issuer_rejects_a_tenant_outside_the_allowlist() {
        let tpl = IssuerTemplate::parse(
            "https://login.test/{tenantid}/v2.0",
            vec!["trusted-tenant".to_string()],
        )
        .expect("templated issuer should parse");

        assert_eq!(
            tpl.resolve_checked("trusted-tenant").ok().as_deref(),
            Some("https://login.test/trusted-tenant/v2.0"),
        );
        let err = tpl
            .resolve_checked("attacker-guid")
            .expect_err("an unlisted tenant must be rejected");
        assert!(
            err.contains("attacker-guid"),
            "error names the tenant: {err}"
        );
    }

    /// Fail closed: an unset allowlist accepts nobody, so forgetting to
    /// configure one cannot open the deployment to every consenting tenant.
    #[test]
    fn templated_issuer_with_no_allowlist_rejects_every_tenant() {
        let tpl = IssuerTemplate::parse("https://login.test/{tenantid}/v2.0", Vec::new())
            .expect("templated issuer should parse");
        assert!(
            tpl.resolve_checked("any-tenant").is_err(),
            "an empty allowlist must reject every tenant"
        );
    }

    #[tokio::test]
    async fn templated_issuer_resolves_from_tid_claim() -> anyhow::Result<()> {
        let (key, enc) = rsa_key("kid-t")?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;
        let tenant_guid = "11111111-2222-3333-4444-555555555555";

        let mw = JwtClaimsMiddleware::<TestClaims>::new_with_jks(
            &format!("{}/jwks", server.uri()),
            "test-aud",
            &format!("{}/{{tenantid}}/v2.0", server.uri()),
        )
        .await?
        .with_allowed_tenants(vec![tenant_guid.to_string()]);

        let svc = actix_web::test::init_service(
            actix_web::App::new()
                .wrap(mw)
                .service(actix_web::web::resource("/protected").to(|| async { "ok" })),
        )
        .await;

        let sign_for = |iss: String, tid: &str| {
            sign_rs256(
                &json!({
                    "sub": "u9",
                    "aud": "test-aud",
                    "exp": 2000000000u64,
                    "iss": iss,
                    "tid": tid,
                }),
                "kid-t",
                &enc,
            )
        };

        // Matching tid/iss pair resolves through the template.
        let good = sign_for(
            format!("{}/{}/v2.0", server.uri(), tenant_guid),
            tenant_guid,
        )?;
        let res = actix_web::test::call_service(
            &svc,
            actix_web::test::TestRequest::get()
                .uri("/protected")
                .insert_header(("Cookie", format!("auth_token={good}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 200);

        // tid pointing at another tenant while iss names ours must bind them
        // together and fail.
        let forged = sign_for(
            format!("{}/{}/v2.0", server.uri(), tenant_guid),
            "99999999-9999-9999-9999-999999999999",
        )?;
        let res = actix_web::test::try_call_service(
            &svc,
            actix_web::test::TestRequest::get()
                .uri("/protected")
                .insert_header(("Cookie", format!("auth_token={forged}")))
                .to_request(),
        )
        .await;
        let err = res.expect_err("forged tenant binding must be rejected");
        assert_eq!(err.as_response_error().status_code(), 401);

        // A token without a tenant claim cannot resolve the template.
        let no_tid = sign_rs256(
            &json!({
                "sub": "u9",
                "aud": "test-aud",
                "exp": 2000000000u64,
                "iss": format!("{}/{}/v2.0", server.uri(), tenant_guid),
            }),
            "kid-t",
            &enc,
        )?;
        let res = actix_web::test::try_call_service(
            &svc,
            actix_web::test::TestRequest::get()
                .uri("/protected")
                .insert_header(("Cookie", format!("auth_token={no_tid}")))
                .to_request(),
        )
        .await;
        let err = res.expect_err("missing tid must be rejected");
        assert_eq!(err.as_response_error().status_code(), 401);

        Ok(())
    }

    /// The `Authorization` header wins over the `auth_token` cookie.
    ///
    /// The precedence rule is three lines in
    /// `JwtClaimsMiddlewareService::call`:
    ///
    ///     let bearer = req.extensions().get::<BearerToken>().cloned().map(|v| v.0);
    ///     let cookie_token = req.cookie(AUTH_COOKIE).map(|c| c.value().to_string());
    ///     let token = bearer.or(cookie_token);
    ///
    /// and before this test NOTHING in the crate exercised it. Every
    /// request in the suite authenticates with
    /// `insert_header(("Cookie", format!("auth_token={token}")))`; a
    /// crate-wide grep for `Authorization` finds it only in `cors()`'s
    /// `allowed_headers` and in `extract_bearer_token`. So `BearerToken`
    /// was never in extensions, `bearer` was always `None`, and the
    /// `.or()` was dead code as far as the suite was concerned.
    ///
    /// Reverting to the pre-fix `cookie_token.or(bearer)` therefore fails
    /// ZERO tests -- verified by flipping it: a client presenting a valid
    /// fresh header alongside a stale cookie is then authenticated as the
    /// COOKIE's subject, which is the wrong user entirely. That is not a
    /// nuisance: the header is what an API client sends and the cookie is
    /// what a browser session leaves behind, so the stale one wins for
    /// exactly the case the fix was made for.
    ///
    /// Both mechanisms are given a DIFFERENT subject, so the test pins
    /// which one was used rather than merely that the request
    /// authenticated. The cookie-only request at the end is what makes it
    /// an ordering assertion rather than "bearer works": without it,
    /// `bearer.or(cookie)` and a hypothetical "bearer only" would both
    /// pass.
    ///
    /// `BearerTokenMiddleware` is wrapped here for the same reason. It is
    /// what puts `BearerToken` into extensions in the first place, and it
    /// had no test at all -- only the pure `parse_bearer_token` string
    /// parser was covered, leaving the whole
    /// middleware -> extensions -> JWT handoff unexercised.
    ///
    /// The wrap order matters and is the reverse of how it reads: actix
    /// applies the LAST `.wrap` outermost, so `BearerTokenMiddleware` is
    /// listed after the validator to run BEFORE it. Written the other way
    /// round the extractor never sees the request -- which is exactly the
    /// mistake this test caught while being written, and the reason the
    /// ordering is called out rather than left to be discovered again.
    #[actix_web::test]
    async fn a_bearer_header_outranks_a_stale_cookie() -> anyhow::Result<()> {
        use super::super::bearer_token::BearerTokenMiddleware;
        use actix_web::{App, HttpResponse, test};

        let (key, enc) = rsa_key("kid-prec")?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;

        let mw = JwtClaimsMiddleware::<TestClaims>::new_with_jks(
            &format!("{}/jwks", server.uri()),
            "test-aud",
            "https://idp.test",
        )
        .await?;

        // The handler reports the subject the middleware actually resolved,
        // so the assertion is about authentication rather than about status.
        async fn whoami(claims: Validated<TestClaims>) -> HttpResponse {
            HttpResponse::Ok().body(claims.sub.clone())
        }

        let svc = test::init_service(
            App::new()
                .wrap(mw)
                .wrap(BearerTokenMiddleware)
                .route("/whoami", actix_web::web::get().to(whoami)),
        )
        .await;

        let token_for = |sub: &str| {
            sign_rs256(
                &json!({ "sub": sub, "aud": "test-aud", "exp": 2000000000u64 }),
                "kid-prec",
                &enc,
            )
        };
        let bearer_token = token_for("bearer-user")?;
        let cookie_token = token_for("cookie-user")?;

        // Both present, different subjects: the header must win.
        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/whoami")
                .insert_header((
                    actix_web::http::header::AUTHORIZATION,
                    format!("Bearer {bearer_token}"),
                ))
                .insert_header(("Cookie", format!("auth_token={cookie_token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 200);
        let sub = String::from_utf8(test::read_body(res).await.to_vec()).expect("utf-8 body");
        assert_eq!(
            sub, "bearer-user",
            "a stale auth_token cookie must not shadow an explicitly \
             presented Authorization header"
        );

        // The cookie path still works, so the test pins the ORDER rather
        // than "bearer is the only thing accepted".
        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/whoami")
                .insert_header(("Cookie", format!("auth_token={cookie_token}")))
                .to_request(),
        )
        .await;
        assert_eq!(res.status(), 200);
        let sub = String::from_utf8(test::read_body(res).await.to_vec()).expect("utf-8 body");
        assert_eq!(
            sub, "cookie-user",
            "a browser session with no Authorization header must still \
             authenticate from its cookie"
        );

        // ...and an unparseable header does not silently fall through to
        // the cookie. The extractor is permissive by design and leaves the
        // accept/reject decision to the validator, so with a malformed
        // header present there is no token in extensions AND no cookie to
        // fall back to: the request must be a 401, not a cookie session.
        let res = test::call_service(
            &svc,
            test::TestRequest::get()
                .uri("/whoami")
                .insert_header(("Authorization", "Basic dXNlcjpwYXNz"))
                .to_request(),
        )
        .await;
        assert_eq!(
            res.status(),
            401,
            "a non-Bearer Authorization header is not a credential, and \
             must not authenticate the request"
        );

        Ok(())
    }
    /// Regression for the lockout: an unusable credential must degrade to
    /// anonymous rather than 401, or the cookie becomes the lockout.
    ///
    /// `callback` sets `auth_token` with a 7-day `max_age` while the token's own
    /// `exp` is provider-controlled and typically ~1h. So an hour after login a
    /// browser sends an expired JWT on *every* request, and because this middleware
    /// is wrapped over the whole `/auth` scope — including `/auth/login`,
    /// `/auth/callback` and `/auth/logout`, none of which take a `Validated<C>` —
    /// a hard 401 there meant the user could neither re-authenticate nor clear the
    /// cookie. Recovery required deleting cookies by hand.
    ///
    /// The degraded request reaches a handler that needs no subject, and carries a
    /// `Set-Cookie` that clears the dead cookie so the browser stops replaying it.
    #[tokio::test]
    async fn an_expired_cookie_does_not_lock_out_the_public_auth_routes() -> anyhow::Result<()> {
        let (key, enc) = rsa_key("kid-t")?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;

        let mw = JwtClaimsMiddleware::<TestClaims>::new_with_jks(
            &format!("{}/jwks", server.uri()),
            "test-aud",
            &format!("{}/{{tenantid}}/v2.0", server.uri()),
        )
        .await?
        .with_allowed_tenants(vec!["tenant-guid".to_string()]);

        let svc = actix_web::test::init_service(
            actix_web::App::new()
                .wrap(mw)
                // Stands in for /auth/login and /auth/callback: a handler that
                // takes no `Validated<C>`, so it must be reachable anonymously.
                .service(actix_web::web::resource("/auth/login").to(|| async { "redirect" })),
        )
        .await;

        // exp in the past, but signed by the key the middleware trusts, so this is
        // an EXPIRED SESSION rather than a forged token.
        let expired = sign_rs256(
            &json!({
                "sub": "u9",
                "aud": "test-aud",
                "iss": format!("{}/tenant-guid/v2.0", server.uri()),
                "tid": "tenant-guid",
                "exp": 1_000_000u64,
            }),
            "kid-t",
            &enc,
        )?;

        let res = actix_web::test::try_call_service(
            &svc,
            actix_web::test::TestRequest::get()
                .uri("/auth/login")
                .insert_header(("Cookie", format!("auth_token={expired}")))
                .to_request(),
        )
        .await
        .expect("the expired-cookie request is served, not refused");

        assert_eq!(
            res.status(),
            200,
            "an expired session cookie must not 401 the route that re-authenticates"
        );

        // And the dead cookie is cleared, so the browser stops replaying it.
        let cleared = res
            .headers()
            .get(actix_web::http::header::SET_COOKIE)
            .expect("the expired cookie is cleared on the way out")
            .to_str()?
            .to_string();
        assert!(
            cleared.contains("auth_token=") && cleared.contains("Max-Age=0"),
            "expected the session cookie to be expired, got: {cleared}"
        );

        Ok(())
    }

    /// The degradation is scoped to an expired SESSION. A forged tenant binding is
    /// an attack, and Blocker 1 exists so it fails CLOSED — it must not become
    /// "no credential", which would serve unauthenticated routes with a forged
    /// token in hand.
    #[tokio::test]
    async fn a_forged_tenant_still_fails_closed_rather_than_degrading() -> anyhow::Result<()> {
        let (key, enc) = rsa_key("kid-t")?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;

        let mw = JwtClaimsMiddleware::<TestClaims>::new_with_jks(
            &format!("{}/jwks", server.uri()),
            "test-aud",
            &format!("{}/{{tenantid}}/v2.0", server.uri()),
        )
        .await?
        .with_allowed_tenants(vec!["tenant-guid".to_string()]);

        let svc = actix_web::test::init_service(
            actix_web::App::new()
                .wrap(mw)
                .service(actix_web::web::resource("/auth/login").to(|| async { "redirect" })),
        )
        .await;

        let forged = sign_rs256(
            &json!({
                "sub": "attacker",
                "aud": "test-aud",
                "iss": format!("{}/tenant-guid/v2.0", server.uri()),
                "tid": "attacker-guid",
                "exp": 2000000000u64,
            }),
            "kid-t",
            &enc,
        )?;

        let res = actix_web::test::try_call_service(
            &svc,
            actix_web::test::TestRequest::get()
                .uri("/auth/login")
                .insert_header(("Cookie", format!("auth_token={forged}")))
                .to_request(),
        )
        .await;

        let err = res.expect_err("a token from an untrusted tenant must not degrade to anonymous");
        assert_eq!(err.as_response_error().status_code(), 401);

        Ok(())
    }

    /// Regression for the BLOCKER the second review caught: the cookie-clear
    /// must not destroy the session cookie `/auth/callback` just SET.
    ///
    /// `/auth/callback` sets `auth_token=<fresh>; Max-Age=7d`. This middleware
    /// wants to clear the stale cookie it found on the request. Both end up as
    /// `Set-Cookie` on one response with the same (name, domain, path)
    /// identity; browsers apply them in order and the LAST write wins, so an
    /// appended `auth_token=; Max-Age=0` left the callback having deleted the
    /// session it had just established. The user saw a 200 and a token, and was
    /// anonymous on the next request -- the exact lockout the degradation exists
    /// to remove, reached through the endpoint meant to cure it.
    ///
    /// A top-level GET redirect carries cookies (`SameSite=Lax` allows it), so a
    /// stale cookie really does arrive on a callback, not only in theory.
    #[tokio::test]
    async fn a_fresh_session_cookie_survives_the_middleware_cookie_clear() -> anyhow::Result<()> {
        use actix_web::{HttpResponse, cookie::Cookie};

        let (key, enc) = rsa_key("kid-t")?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;

        let mw = JwtClaimsMiddleware::<TestClaims>::new_with_jks(
            &format!("{}/jwks", server.uri()),
            "test-aud",
            &format!("{}/{{tenantid}}/v2.0", server.uri()),
        )
        .await?
        .with_allowed_tenants(vec!["tenant-guid".to_string()]);

        // Stands in for the callback: the same shape, a handler that SETS the
        // session cookie on its way out.
        let svc = actix_web::test::init_service(actix_web::App::new().wrap(mw).service(
            actix_web::web::resource("/auth/callback").to(|| async {
                HttpResponse::Ok()
                    .cookie(
                        Cookie::build(AUTH_COOKIE, "fresh-session-token")
                            .path("/")
                            .http_only(true)
                            .max_age(actix_web::cookie::time::Duration::days(7))
                            .finish(),
                    )
                    .finish()
            }),
        ))
        .await;

        let expired = sign_rs256(
            &json!({
                "sub": "u9",
                "aud": "test-aud",
                "iss": format!("{}/tenant-guid/v2.0", server.uri()),
                "tid": "tenant-guid",
                "exp": 1_000_000u64,
            }),
            "kid-t",
            &enc,
        )?;

        let res = actix_web::test::try_call_service(
            &svc,
            actix_web::test::TestRequest::get()
                .uri("/auth/callback")
                .insert_header(("Cookie", format!("auth_token={expired}")))
                .to_request(),
        )
        .await
        .expect("the callback runs; a stale cookie does not refuse it");

        assert_eq!(res.status(), 200);

        let set_cookies: Vec<String> = res
            .headers()
            .get_all(SET_COOKIE)
            .map(|v| v.to_str().expect("utf-8 cookie header").to_string())
            .filter(|v| v.starts_with(&format!("{AUTH_COOKIE}=")))
            .collect();

        assert!(
            !set_cookies.is_empty(),
            "the callback must still set the session cookie"
        );
        for cookie in &set_cookies {
            assert!(
                !cookie.contains("Max-Age=0"),
                "a later header deletes the cookie the callback set: {cookie:?} (all: \
                 {set_cookies:?})"
            );
        }
        assert!(
            set_cookies
                .iter()
                .any(|c| c.contains("fresh-session-token")),
            "the fresh session must be the cookie that survives: {set_cookies:?}"
        );
        Ok(())
    }

    /// A bad `Authorization` header says nothing about the cookie, so it must
    /// not delete a working one.
    ///
    /// `bearer.or(cookie_token)` means the expired header is the token that gets
    /// classified while the valid cookie sits untouched on the request.
    /// Clearing on that basis logs the client out of a session it never asked us
    /// to end.
    #[tokio::test]
    async fn an_expired_bearer_header_does_not_clear_a_valid_cookie() -> anyhow::Result<()> {
        let (key, enc) = rsa_key("kid-t")?;
        let server = spawn_jwks(json!({ "keys": [key] })).await;

        let mw = JwtClaimsMiddleware::<TestClaims>::new_with_jks(
            &format!("{}/jwks", server.uri()),
            "test-aud",
            &format!("{}/{{tenantid}}/v2.0", server.uri()),
        )
        .await?
        .with_allowed_tenants(vec!["tenant-guid".to_string()]);

        let svc = actix_web::test::init_service(
            actix_web::App::new()
                // Needed so the Authorization header becomes the BearerToken
                // extension the precedence rule actually reads.
                .wrap(mw)
                .wrap(crate::http::middleware::bearer_token::BearerTokenMiddleware)
                .service(actix_web::web::resource("/protected").to(|| async { "ok" })),
        )
        .await;

        let expired = sign_rs256(
            &json!({
                "sub": "u9",
                "aud": "test-aud",
                "iss": format!("{}/tenant-guid/v2.0", server.uri()),
                "tid": "tenant-guid",
                "exp": 1_000_000u64,
            }),
            "kid-t",
            &enc,
        )?;

        let res = actix_web::test::try_call_service(
            &svc,
            actix_web::test::TestRequest::get()
                .uri("/protected")
                .insert_header(("Authorization", format!("Bearer {expired}")))
                .insert_header(("Cookie", "auth_token=still-valid"))
                .to_request(),
        )
        .await
        .expect("an unusable header degrades rather than erroring");

        let cleared = res.headers().get_all(SET_COOKIE).any(|v| {
            v.to_str()
                .is_ok_and(|v| v.starts_with(&format!("{AUTH_COOKIE}=;")))
        });
        assert!(
            !cleared,
            "a bad Authorization header must not delete an unrelated session cookie"
        );
        Ok(())
    }
}
