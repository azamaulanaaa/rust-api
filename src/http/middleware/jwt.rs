//! Actix middleware that validates JWTs against a key store that uses
//! JWKS.
//!
//! The code puts the validated claims (generic over `C`) into the request
//! extensions. Read the claims with
//! [`Validated`](crate::http::middleware::jwt::Validated). A request that
//! sends no token passes through unchanged, so each route decides its own
//! authentication requirements.

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

// Re-exports the public API for the users of this module.
pub use super::jwks::SigningKey;

/// The literal segment that marks a template for a multi-tenant issuer.
/// The format follows Azure AD, for example
/// `https://login.microsoftonline.com/{tenantid}/v2.0`.
const TENANT_PLACEHOLDER: &str = "{tenantid}";

/// The browser session cookie that this middleware reads.
const AUTH_COOKIE: &str = "auth_token";

/// A template for a multi-tenant issuer. The discovery document of the
/// provider publishes an issuer that contains the literal placeholder
/// `{tenantid}`. Each token resolves the placeholder to the tenant that
/// issued it.
///
/// # Why the allowlist is not optional
///
/// The expected issuer must come from the `tid` claim of the token itself,
/// because the claim is not verified. No static issuer can match an issuer
/// that contains a placeholder. The derivation therefore proves nothing,
/// because it uses data that an attacker supplied. Any token whose `iss` and
/// `tid` claims agree satisfies it. Signature validation does not help
/// either. A multi-tenant app registration publishes one JWKS with the keys
/// of every tenant. Therefore a token that a tenant the operator never
/// intended to trust signed verifies against keys that this store already
/// caches.
///
/// Audience is **not** a substitute. The `aud` claim is the client ID, and
/// that ID is the same for every tenant that consented to the app
/// registration. The allowlist is therefore the only tenant gate, and it
/// fails closed. An empty allowlist accepts no tenant at all, and
/// `Config::validate` refuses to start a templated issuer without an
/// allowlist.
#[derive(Debug, Clone)]
pub struct IssuerTemplate {
    /// The issuer part before the `{tenantid}` placeholder.
    prefix: String,
    /// The issuer part after the `{tenantid}` placeholder.
    suffix: String,
    /// The only tenant identifiers that this deployment accepts.
    allowed_tenants: Vec<String>,
}

impl IssuerTemplate {
    /// Parses a template from a discovered issuer. The function returns `None`
    /// when the issuer is not templated, which is the usual single-tenant
    /// case.
    ///
    /// `allowed_tenants` is the tenant allowlist. It applies only to the
    /// templated case. The configuration validation requires the list to be
    /// non-empty. The function still accepts an empty list here, and an
    /// empty list means "reject everything" instead of "allow everything".
    pub fn parse(issuer: &str, allowed_tenants: Vec<String>) -> Option<Self> {
        let (prefix, suffix) = issuer.split_once(TENANT_PLACEHOLDER)?;
        Some(Self {
            prefix: prefix.to_string(),
            suffix: suffix.to_string(),
            allowed_tenants,
        })
    }

    /// Resolves the template for a tenant identifier that is *known* to be
    /// allowed. The function does not check the identifier again.
    ///
    /// Prefer [`IssuerTemplate::resolve_checked`]. Use this function for
    /// tests, and to build the set of issuers to accept. Do not use it to
    /// validate a token.
    pub fn resolve(&self, tenant_id: &str) -> String {
        format!("{}{}{}", self.prefix, tenant_id, self.suffix)
    }

    /// Resolves the template for a tenant identifier, and rejects every tenant
    /// outside the configured allowlist.
    ///
    /// The error string names the rejected tenant, and it is safe to log. The
    /// code never serializes the string into a client response.
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

    /// The tenant identifiers that this deployment accepts.
    pub fn allowed_tenants(&self) -> &[String] {
        &self.allowed_tenants
    }
}

/// Extracts a top-level string field from an unverified JWT payload.
///
/// The function only serves to *derive validation inputs*, for example the
/// expected issuer from `tid`, before the verified decode. Every security
/// decision still goes through the decode that checks the signature
/// afterwards.
pub(crate) fn extract_unverified_claim(token: &str, field: &str) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let payload_b64 = token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    value.get(field)?.as_str().map(str::to_string)
}

/// The values of the audience (`aud`) claim. A provider sends either one
/// string or an array of strings, and this enum accepts both.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Audience {
    /// One audience value.
    Single(String),
    /// Multiple audience values.
    Multi(Vec<String>),
}

/// The standard ID-token claims that the code takes from a validated JWT
/// and puts into the request extensions.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    /// The issuer, which is the identity provider that signed the token.
    pub iss: String,
    /// The subject, which is the stable user identifier.
    pub sub: String,
    /// The audience that the token was issued for.
    pub aud: Audience,
    /// The expiration time in unix seconds. The code checks it on every
    /// request.
    pub exp: u64,
    /// The not-before time in unix seconds. The field is optional.
    pub nbf: Option<u64>,
    /// The issued-at time in unix seconds. The field is optional.
    pub iat: Option<u64>,
    /// The nonce that the provider sends back during the OIDC flow. The
    /// field is optional.
    pub nonce: Option<String>,
    /// The unique token identifier. A server can use it as a revocation
    /// key. The field is optional.
    pub jti: Option<String>,
}

/// The Actix middleware that validates JWTs against a [`JwksKeys`] store
/// before the request reaches the wrapped service. The code puts the
/// validated claims (generic over `C`) into the request extensions. Read the
/// claims with [`Validated`]. A request that sends no token passes through
/// unchanged, so each route decides its own authentication requirements.
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
    /// Builds the middleware from an existing key store and the base
    /// validation configuration (audience, issuer, and leeway).
    pub fn new(keys: JwksKeys, validation: Validation) -> Self {
        Self {
            keys,
            validation,
            issuer_template: None,
            _claims: PhantomData,
        }
    }

    /// Fetches the JWKS document from `jwks_url` and builds the middleware.
    /// The function pins the `audience` and `issuer` checks. See
    /// [`JwksKeys`] for the refresh behavior.
    pub async fn new_with_jks(
        jwks_url: &str,
        audience: &str,
        issuer: &str,
    ) -> anyhow::Result<Self> {
        let keys = JwksKeys::new(jwks_url).await?;

        // The base validation holds the audience and issuer checks. The
        // middleware sets the expected algorithm again for each request,
        // from the selected signing key. A templated issuer ({tenantid})
        // cannot be pinned statically. The middleware resolves it for each
        // request from the `tid` claim of the token, and checks that claim
        // against the allowlist.
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
    /// A templated issuer requires this allowlist. A single-tenant issuer
    /// does not need it, because the code pins that issuer statically. If
    /// the caller leaves the allowlist unset, the list is empty. An empty
    /// list **rejects every tenant**, so the function fails closed. A
    /// caller who forgets this call therefore cannot silently open the
    /// deployment to every tenant that consented to a multi-tenant app
    /// registration.
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

/// The extractor for the claims that [`JwtClaimsMiddleware`] validated.
///
/// `web::ReqData` fails the extraction with a 500 when the middleware did
/// not run, or when the client sent no token. This extractor returns a
/// **401 Unauthorized** instead. An anonymous request to a protected route
/// must not look like a server fault.
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

/// The middleware service for one worker, which
/// [`JwtClaimsMiddleware::new_transform`] creates. The code does not build
/// this type directly.
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

        // The bearer header wins over the authentication cookie. A stale or
        // expired browser session cookie must not hide a header that the
        // client sent explicitly.
        // NOTE: the code must keep these as separate statements. `cookie()`
        // changes the parse cache in the request extensions, which would
        // conflict with a live `extensions()` borrow that is held across an
        // array literal.
        let bearer = req.extensions().get::<BearerToken>().cloned().map(|v| v.0);
        let cookie_token = req.cookie(AUTH_COOKIE).map(|c| c.value().to_string());
        // The code records the source of the CHOSEN token. It does not
        // record only that one token was chosen. Only a stale cookie is
        // worth clearing. A bad `Authorization` header says nothing about
        // the cookie, and clearing it would destroy a working session.
        let chosen_from_cookie = bearer.is_none() && cookie_token.is_some();
        let token = bearer.or(cookie_token);
        Box::pin(async move {
            // An unusable credential is NOT the same as a missing one. The
            // code wraps this middleware over the whole /auth scope. That
            // scope includes /auth/login, /auth/callback, and /auth/logout.
            // None of them takes a `Validated<C>`. An earlier version
            // refused the request here, so the lifetime of the cookie became
            // the lockout. `callback` sets the cookie with a max_age of 7
            // days, but the `exp` of the token is set by the provider and is
            // usually about 1 hour. An hour after the login, every browser
            // request therefore carried an expired JWT, and `/auth/login`
            // returned 401 before its handler ran. The user could neither log
            // in again nor clear the cookie.
            //
            // Now an unusable credential changes to anonymous, and the
            // request proceeds. A route that needs a subject still returns
            // 401, because `Validated<C>` produces that 401, and not this
            // middleware. An invalid token shows that a session has expired.
            // It is not a reason to refuse the endpoints whose only task is
            // to establish a new session.
            //
            // The precedence above is unchanged. A valid header still wins,
            // and a stale cookie still cannot hide it.
            let mut unusable: Option<String> = None;

            if let Some(token) = token {
                // `Ok` inserts the claims. `Err((reason, true))` is a
                // security decision and stays a hard 401, as the line table
                // below shows. `Err((reason, false))` is an unusable
                // *session*, and it changes to anonymous below.
                //
                // The difference matters. A token from a tenant that the
                // allowlist rejects is an attack, and Blocker 1 exists so
                // that it fails CLOSED. Therefore the code must not quietly
                // treat it as "no credential", because that state would
                // serve every unauthenticated route with a forged token in
                // hand. An expired `exp` is the opposite case. It is a
                // browser that replays its own dead cookie, and refusing it
                // locks the user out of the very endpoints that would fix
                // it.
                let claims = async {
                    let header = jsonwebtoken::decode_header(&token)
                        .map_err(|e| (format!("undecodable header: {e}"), true))?;

                    let signing_key = keys
                        .get(header.kid.as_deref())
                        .await
                        .ok_or_else(|| ("no signing key matches kid".to_string(), true))?;

                    // The code pins the validation to the algorithm of the
                    // selected key, so a token cannot change to an unexpected
                    // algorithm. For a multi-tenant provider, the code derives
                    // the exact expected issuer from the `tid` claim of the
                    // token first.
                    let mut validation = validation.clone();
                    validation.algorithms = vec![signing_key.algorithm];
                    if let Some(template) = &issuer_template {
                        let tenant_id = extract_unverified_claim(&token, "tid")
                            .filter(|t| !t.is_empty())
                            .ok_or_else(|| ("token has no tenant identifier".to_string(), true))?;
                        // The issuer comes from the `tid` claim of the token
                        // itself, so resolving the template proves nothing on
                        // its own. This check is the tenant gate, and it fails
                        // closed.
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
                        // Fail closed. A token that the tenant gate rejects
                        // never reaches a handler.
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

            // Clear the stale cookie on the way out, so the browser
            // stops replaying an expired JWT until the next successful login.
            //
            // Both conditions below matter.
            //
            // The code clears the cookie only when the CHOSEN credential was
            // the cookie. A request whose token came from an `Authorization`
            // header has told the server nothing about the cookie, and
            // clearing it would delete a working session that the client
            // never asked the server to touch.
            //
            // The code never clears the cookie when the handler has already
            // SET `auth_token`. This middleware wraps `/auth/callback`, which
            // sets a new session cookie with a `max_age` of 7 days. Appending
            // `auth_token=; Max-Age=0` after it puts two `Set-Cookie` headers
            // with the same (name, domain, path) on one response. Browsers
            // apply them in order, and the LAST write wins. Therefore the
            // callback would complete after it DELETED the session that it
            // had just established. The user would see a 200 and a token, and
            // would be anonymous on the next request. That is exactly the
            // lockout that this change removes, reached through the endpoint
            // that is meant to cure it.
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
    async fn loads_keys_and_decodes_a_token() -> anyhow::Result<()> {
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
    async fn validated_extractor_reads_the_inserted_claims() {
        use actix_web::test::TestRequest;

        let (req, mut payload) = TestRequest::default().to_http_parts();
        req.extensions_mut().insert(sample_claims());

        let extracted = Validated::<Claims>::from_request(&req, &mut payload)
            .await
            .expect("claims present");
        assert_eq!(extracted.sub, "u1"); // The extractor reads the inner claims.
    }

    #[actix_web::test]
    async fn validated_extractor_returns_401_when_claims_are_missing() {
        use actix_web::test::TestRequest;

        let (req, mut payload) = TestRequest::default().to_http_parts();

        let result = Validated::<Claims>::from_request(&req, &mut payload).await;
        assert_eq!(result.unwrap_err().as_response_error().status_code(), 401);
    }

    #[test]
    fn issuer_template_parses_a_template_and_resolves_it() {
        let tpl = IssuerTemplate::parse(
            "https://login.test/{tenantid}/v2.0",
            vec!["abc-123".to_string()],
        )
        .expect("templated issuer should parse");
        assert_eq!(tpl.resolve("abc-123"), "https://login.test/abc-123/v2.0");
        assert!(IssuerTemplate::parse("https://plain.test/v2.0", Vec::new()).is_none());
    }

    /// The allowlist is the only real gate on a templated issuer. The expected
    /// issuer comes from the `tid` claim of the token, and `aud` is the
    /// shared client ID. Neither value can tell one tenant from another.
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

    /// Fail closed. An unset allowlist accepts nobody, so a caller who forgets
    /// to configure one cannot open the deployment to every consenting
    /// tenant.
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

        // A matching tid and iss pair resolves through the template.
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

        // The tid claim points at another tenant while iss names the
        // first tenant. The code must bind them together and fail.
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
    /// Before this test, NOTHING in the crate exercised that rule. Every
    /// request in the suite authenticates with
    /// `insert_header(("Cookie", format!("auth_token={token}")))`. A
    /// crate-wide search for `Authorization` finds it only in the
    /// `allowed_headers` of `cors()` and in `extract_bearer_token`.
    /// Therefore `BearerToken` was never in the extensions, `bearer` was
    /// always `None`, and the `.or()` was dead code as far as the suite was
    /// concerned.
    ///
    /// Therefore going back to the pre-fix `cookie_token.or(bearer)` fails
    /// ZERO tests, and the author confirmed this by making the change. A
    /// client that presents a valid fresh header next to a stale cookie
    /// then authenticates as the subject of the COOKIE, which is the wrong
    /// user entirely. That is not a nuisance. The header is what an API
    /// client sends, and the cookie is what a browser session leaves behind,
    /// so the stale one wins in exactly the case that the fix addresses.
    ///
    /// The test gives both mechanisms a DIFFERENT subject, so the test pins
    /// which mechanism was used. The test does more than check that the
    /// request authenticated. The cookie-only request at the end makes it an
    /// ordering assertion instead of a "bearer works" assertion. Without
    /// that request, `bearer.or(cookie)` and a hypothetical "bearer only"
    /// would both pass.
    ///
    /// The test wraps `BearerTokenMiddleware` for the same reason. That
    /// middleware puts `BearerToken` into the extensions, and it had no test
    /// at all. Only the pure `parse_bearer_token` string parser had a test.
    /// The step from middleware to extensions to JWT therefore had no test.
    ///
    /// The wrap order matters, and it is the reverse of the order that it
    /// reads. actix applies the LAST `.wrap` as the outermost one, so the
    /// code lists `BearerTokenMiddleware` after the validator to make it run
    /// BEFORE the validator. In the other order the extractor never sees the
    /// request. That is exactly the mistake that this test found while
    /// someone was writing it, and it is why the code names the order here
    /// instead of leaving the next reader to discover it again.
    #[actix_web::test]
    async fn a_bearer_header_wins_over_a_stale_cookie() -> anyhow::Result<()> {
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

        // The handler returns the subject that the middleware actually
        // resolved, so the assertion checks the authentication rather than
        // the status code.
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

        // Both credentials are present, and the subjects differ, so the
        // header must win.
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

        // The cookie path still works, so the test pins the ORDER instead
        // of only checking that the bearer token is the accepted value.
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

        // ...and a header that the extractor cannot parse does not
        // silently fall through to the cookie. The extractor is permissive
        // by design, and it leaves the accept or reject decision to the
        // validator. So with a malformed header there is no token in the
        // extensions AND no cookie to use as a fallback. The request must
        // return 401, and it must not become a cookie session.
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
    /// Regression test for the lockout. An unusable credential must change to
    /// anonymous instead of returning 401, or the cookie becomes the cause
    /// of the lockout.
    ///
    /// `callback` sets `auth_token` with a 7-day `max_age` while the `exp`
    /// of the token is set by the provider and is typically ~1h. An hour
    /// after the login, a browser sends an expired JWT on *every* request.
    /// The code wraps this middleware over the whole `/auth` scope. That
    /// scope includes `/auth/login`, `/auth/callback` and `/auth/logout`,
    /// and none of them takes a `Validated<C>`. A hard 401 there meant that
    /// the user could neither log in again nor clear the cookie. The user
    /// had to delete the cookies by hand.
    ///
    /// The degraded request reaches a handler that needs no subject, and it
    /// carries a `Set-Cookie` that clears the dead cookie, so the browser
    /// stops replaying it.
    #[tokio::test]
    async fn an_expired_cookie_does_not_block_the_public_auth_routes() -> anyhow::Result<()> {
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

        // The exp claim is in the past, but the provider signed the token
        // with a key that the middleware trusts. Therefore this is an
        // EXPIRED SESSION rather than a forged token.
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

        // The response also clears the dead cookie, so the browser stops
        // replaying it.
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

    /// The degradation applies only to an expired SESSION. A forged tenant
    /// binding is an attack, and Blocker 1 exists so that it fails CLOSED.
    /// It must not become "no credential", which would serve the
    /// unauthenticated routes with a forged token in hand.
    #[tokio::test]
    async fn a_forged_tenant_still_fails_closed_and_does_not_degrade() -> anyhow::Result<()> {
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

    /// Regression test for the BLOCKER that the second review found: the
    /// cookie clear must not destroy the session cookie that
    /// `/auth/callback` has just SET.
    ///
    /// `/auth/callback` sets `auth_token=<fresh>; Max-Age=7d`. This
    /// middleware wants to clear the stale cookie that it found on the
    /// request. Both become `Set-Cookie` headers on one response with the same
    /// (name, domain, path) identity. Browsers apply them in order, and
    /// the LAST write wins. Therefore an appended `auth_token=; Max-Age=0`
    /// left the callback having deleted the session that it had just
    /// established. The user saw a 200 and a token, and was anonymous on
    /// the next request. That is exactly the lockout that the degradation
    /// exists to remove, reached through the endpoint that is meant to cure
    /// it.
    ///
    /// A redirect on a top-level GET carries cookies (`SameSite=Lax` allows
    /// it), so a stale cookie really does arrive on a callback, and not
    /// only in theory.
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

        // Stands in for the callback: the same shape, a handler that SETS
        // the session cookie on its way out.
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
    /// `bearer.or(cookie_token)` means that the expired header is the token
    /// that gets classified, while the valid cookie stays untouched on the
    /// request. Clearing it on that basis signs the client out of a session
    /// that it never asked the server to end.
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
                // extension that the precedence rule actually reads.
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
