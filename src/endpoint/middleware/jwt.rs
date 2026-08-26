use std::{
    collections::HashMap,
    future::{Ready, ready},
    marker::PhantomData,
    rc::Rc,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use actix_web::{
    Error, FromRequest, HttpMessage, HttpRequest,
    dev::{Payload, Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
};
use futures_util::future::LocalBoxFuture;
pub use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use jsonwebtoken::{
    decode,
    jwk::{AlgorithmParameters, Jwk, KeyAlgorithm},
};
use serde::{Deserialize, de::DeserializeOwned};

use super::bearer_token::BearerToken;
use crate::endpoint::error::ApiError;

/// Minimum interval between two JWKS fetches triggered by unknown-key misses.
/// Prevents a flood of junk tokens from hammering the identity provider.
const JWKS_REFRESH_DEBOUNCE: Duration = Duration::from_secs(5);

#[allow(dead_code)]
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

/// A single verification key resolved from the provider's JWKS, paired
/// with the algorithm tokens signed by it must use.
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// The raw key material used to verify token signatures.
    decoding_key: DecodingKey,
    /// Verification algorithm derived from this key's own `alg` (or the OIDC
    /// default RS256 when the JWK omits it). Tokens are validated against
    /// exactly this algorithm, preventing algorithm-confusion attacks.
    algorithm: Algorithm,
}

/// Refreshable JWKS-backed signing key store.
///
/// Keys are loaded once on construction and served from cache afterwards.
/// When a token references an unknown `kid` (typically right after the
/// provider rotated its signing keys), the JWKS document is refetched —
/// debounced by [`JWKS_REFRESH_DEBOUNCE`] so repeated misses cannot be used
/// to flood the provider.
#[derive(Clone)]
pub struct JwksKeys {
    inner: Arc<JwksKeysInner>,
}

struct JwksKeysInner {
    url: String,
    keys: tokio::sync::RwLock<Arc<HashMap<String, SigningKey>>>,
    last_refresh: tokio::sync::Mutex<Instant>,
    refresh_debounce: Duration,
}

impl JwksKeys {
    /// Fetches the JWKS document and builds the initial cache.
    pub async fn new(url: impl Into<String>) -> anyhow::Result<Self> {
        Self::build(url.into(), JWKS_REFRESH_DEBOUNCE).await
    }

    /// Test-only variant with an injectable debounce window; `Duration::ZERO`
    /// makes every on-miss refresh fire immediately.
    #[cfg(test)]
    async fn with_refresh_debounce(
        url: impl Into<String>,
        debounce: Duration,
    ) -> anyhow::Result<Self> {
        Self::build(url.into(), debounce).await
    }

    async fn build(url: String, refresh_debounce: Duration) -> anyhow::Result<Self> {
        let keys = fetch_keys(&url).await?;

        anyhow::ensure!(
            !keys.is_empty(),
            "No usable signing keys found in JWKS at {}",
            url
        );

        Ok(Self {
            inner: Arc::new(JwksKeysInner {
                url,
                keys: tokio::sync::RwLock::new(Arc::new(keys)),
                last_refresh: tokio::sync::Mutex::new(Instant::now()),
                refresh_debounce,
            }),
        })
    }

    /// Resolves the verification key for a token.
    ///
    /// A missing `kid` is only resolvable when the provider publishes exactly
    /// one key; otherwise the request cannot select safely and `None` is
    /// returned.
    pub async fn get(&self, kid: Option<&str>) -> Option<SigningKey> {
        // Fast path: cached hit.
        if let Some(key) = self.lookup(kid).await {
            return Some(key);
        }

        // Miss: the provider may have rotated signing keys. Refresh once
        // (debounced), then retry the lookup against fresh material.
        self.maybe_refresh().await;
        self.lookup(kid).await
    }

    async fn lookup(&self, kid: Option<&str>) -> Option<SigningKey> {
        let keys = self.inner.keys.read().await.clone(); // cheap Arc clone
        match kid {
            Some(id) => keys.get(id).cloned(),
            None => {
                if keys.len() == 1 {
                    keys.values().next().cloned()
                } else {
                    None
                }
            }
        }
    }

    async fn maybe_refresh(&self) {
        let mut last_refresh = self.inner.last_refresh.lock().await;
        if last_refresh.elapsed() < self.inner.refresh_debounce {
            return;
        }

        match fetch_keys(&self.inner.url).await {
            Ok(keys) if !keys.is_empty() => {
                *last_refresh = Instant::now();
                *self.inner.keys.write().await = Arc::new(keys);
            }
            Ok(_) => tracing::warn!(
                "Refreshed JWKS at {} but it contains no usable signing keys; keeping previous keys",
                self.inner.url
            ),
            Err(e) => tracing::warn!(
                "Failed to refresh JWKS from {}: {}; keeping previous keys",
                self.inner.url,
                e
            ),
        }
    }
}

async fn fetch_keys(url: &str) -> anyhow::Result<HashMap<String, SigningKey>> {
    let jwks: JwkSet = reqwest::get(url).await?.json().await?;

    Ok(jwks.keys.iter().filter_map(to_signing_key).collect())
}

/// Converts a JWK into a verification entry.
///
/// - HMAC (`oct`) keys are rejected outright: an OIDC provider must never
///   publish shared secrets in its JWKS, and trusting them would enable
///   algorithm-confusion attacks.
/// - The algorithm is taken from the key's own `alg` parameter, falling back
///   to RS256 (the de-facto OIDC default) when omitted — common among older
///   providers.
/// - Encryption-only or unrecognized `alg` values fail the parse and are
///   skipped, as are keys without a `kid` that tokens could never address.
fn to_signing_key(jwk: &Jwk) -> Option<(String, SigningKey)> {
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        return None;
    }

    let algorithm = match &jwk.common.key_algorithm {
        Some(KeyAlgorithm::UNKNOWN_ALGORITHM) | None => Algorithm::RS256,
        Some(alg) => Algorithm::from_str(&alg.to_string()).ok()?,
    };

    let decoding_key = DecodingKey::from_jwk(jwk).ok()?;
    let kid = jwk.common.key_id.clone()?;

    Some((
        kid,
        SigningKey {
            decoding_key,
            algorithm,
        },
    ))
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
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[issuer]);

        Ok(Self::new(keys, validation))
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
            _claims: PhantomData,
        }))
    }
}

/// The per-worker instantiated middleware produced by
/// [`JwtClaimsMiddleware::new_transform`](JwtClaimsMiddleware). Not
/// constructed directly.
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

        // Bearer header wins over the auth cookie: a stale/expired browser
        // session cookie must not shadow an explicitly presented header.
        let token = [
            req.extensions().get::<BearerToken>().cloned().map(|v| v.0),
            req.cookie("auth_token").map(|c| c.value().to_string()),
        ]
        .into_iter()
        .flatten()
        .next();

        Box::pin(async move {
            if let Some(token) = token {
                let header = match jsonwebtoken::decode_header(&token) {
                    Ok(h) => h,
                    Err(e) => {
                        return Err(ApiError::InvalidCredentials(Box::new(e)).into());
                    }
                };

                let Some(signing_key) = keys.get(header.kid.as_deref()).await else {
                    let cause = format!("no signing key matches kid {:?}", header.kid);
                    return Err(ApiError::InvalidCredentials(cause.into()).into());
                };

                // Pin validation to the selected key's own algorithm so a
                // token cannot downgrade to an unexpected algorithm.
                let mut validation = validation.clone();
                validation.algorithms = vec![signing_key.algorithm];

                match decode::<C>(&token, &signing_key.decoding_key, &validation) {
                    Ok(token_data) => req.extensions_mut().insert(token_data.claims),
                    Err(e) => return Err(ApiError::InvalidCredentials(Box::new(e)).into()),
                };
            }

            svc.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
    use serde_json::json;
    use wiremock::MockServer;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    #[derive(Debug, Deserialize)]
    struct TestClaims {
        sub: String,
    }

    async fn spawn_jwks(body: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        server
    }

    /// Generates an RSA keypair and returns (jwks JSON entry, encoding key).
    fn rsa_key(kid: &str) -> anyhow::Result<(serde_json::Value, EncodingKey)> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048)?;
        let public = RsaPublicKey::from(&private);
        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());

        let entry = json!({
            "kty": "RSA",
            "use": "sig",
            "kid": kid,
            "alg": "RS256",
            "n": n,
            "e": e,
        });

        let der = private.to_pkcs1_der()?;
        Ok((entry, EncodingKey::from_rsa_der(der.as_bytes())))
    }

    fn sign_rs256(
        claims: &serde_json::Value,
        kid: &str,
        key: &EncodingKey,
    ) -> anyhow::Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        Ok(encode(&header, claims, key)?)
    }

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

    #[tokio::test]
    async fn unknown_kid_triggers_refresh() -> anyhow::Result<()> {
        let (key_a, _) = rsa_key("kid-a")?;
        let (key_b, enc_b) = rsa_key("kid-b")?;
        let server = MockServer::start().await;

        let serve_jwks = |body: serde_json::Value| {
            let server = &server;
            async move {
                // Reset first so wiremock doesn't keep serving older mounts
                // (it matches the FIRST mounted mock, not the latest).
                server.reset().await;
                Mock::given(method("GET"))
                    .and(path("/jwks"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(body))
                    .mount(server)
                    .await;
            }
        };

        serve_jwks(json!({ "keys": [key_a] })).await;

        // Zero debounce so the on-miss refresh fires immediately.
        let keys =
            JwksKeys::with_refresh_debounce(format!("{}/jwks", server.uri()), Duration::ZERO)
                .await?;
        assert!(keys.get(Some("kid-a")).await.is_some());
        assert!(keys.get(Some("kid-b")).await.is_none()); // miss → debounced refresh

        // Provider rotates: JWKS now serves only kid-b.
        serve_jwks(json!({ "keys": [key_b] })).await;

        let refreshed = keys.get(Some("kid-b")).await;
        assert!(
            refreshed.is_some(),
            "rotation should be picked up after refresh"
        );
        assert!(
            keys.get(Some("kid-a")).await.is_none(),
            "retired kid must be dropped"
        );

        // The refreshed key must actually verify a token signed with kid-b.
        let token = sign_rs256(
            &json!({ "sub": "u2", "exp": 2000000000u64 }),
            "kid-b",
            &enc_b,
        )?;
        let signing_key = keys.get(Some("kid-b")).await.unwrap();
        let validation = Validation::new(signing_key.algorithm);
        let decoded = decode::<TestClaims>(&token, &signing_key.decoding_key, &validation)?;
        assert_eq!(decoded.claims.sub, "u2");

        Ok(())
    }

    #[tokio::test]
    async fn rejects_algorithm_confusion() -> anyhow::Result<()> {
        // Provider publishes an RSA key; attacker signs an HS256 token trying
        // to use the RSA public material as an HMAC secret.
        let (key_a, _) = rsa_key("kid-a")?;
        let server = spawn_jwks(json!({ "keys": [key_a] })).await;
        let keys = JwksKeys::new(format!("{}/jwks", server.uri())).await?;

        let signing_key = keys.get(Some("kid-a")).await.expect("kid-a should resolve");
        let mut validation = Validation::new(signing_key.algorithm);
        assert_eq!(validation.algorithms.as_slice(), &[Algorithm::RS256]);

        let forged_header = Header::new(Algorithm::HS256);
        let forged = encode(
            &forged_header,
            &json!({ "sub": "evil", "exp": 2000000000u64 }),
            &EncodingKey::from_secret(b"attacker-controlled"),
        )?;

        assert!(decode::<TestClaims>(&forged, &signing_key.decoding_key, &validation).is_err());
        validation.algorithms = vec![Algorithm::HS256];
        assert!(
            decode::<TestClaims>(&forged, &signing_key.decoding_key, &validation).is_err(),
            "HMAC family can never verify against an RSA decoding key"
        );

        Ok(())
    }

    #[tokio::test]
    async fn hmac_octet_keys_are_rejected() -> anyhow::Result<()> {
        let oct_key = json!({
            "kty": "oct",
            "kid": "shared",
            "alg": "HS256",
            "k": URL_SAFE_NO_PAD.encode(b"never-a-secret"),
        });
        let server = spawn_jwks(json!({ "keys": [oct_key] })).await;

        let result = JwksKeys::new(format!("{}/jwks", server.uri())).await;
        assert!(
            result.is_err(),
            "a JWKS containing only oct keys must fail construction"
        );

        Ok(())
    }

    #[tokio::test]
    async fn derives_es256_from_ec_key() -> anyhow::Result<()> {
        // Arbitrary P-256 point coordinates — parsing a JWK never validates
        // curve membership, so this exercises the EC code path without a
        // signer dependency.
        let coord = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let ec_entry = json!({
            "kty": "EC",
            "kid": "ec-1",
            "alg": "ES256",
            "crv": "P-256",
            "x": coord,
            "y": coord,
        });
        let server = spawn_jwks(json!({ "keys": [ec_entry] })).await;

        let keys = JwksKeys::new(format!("{}/jwks", server.uri())).await?;
        let signing_key = keys.get(Some("ec-1")).await.expect("ec-1 should resolve");
        assert_eq!(signing_key.algorithm, Algorithm::ES256);

        Ok(())
    }

    #[test]
    fn omits_alg_falls_back_to_rs256() {
        let (key_a, _) = rsa_key("kid-legacy").unwrap();
        let mut legacy = key_a.clone();
        legacy["alg"] = serde_json::Value::Null;

        let jwk: Jwk = serde_json::from_value(legacy).unwrap();
        let parsed = to_signing_key(&jwk).expect("legacy key without alg should load");
        assert_eq!(parsed.0, "kid-legacy");
        assert_eq!(parsed.1.algorithm, Algorithm::RS256);

        let _ = key_a;
    }

    #[test]
    fn encryption_only_alg_is_skipped() {
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "RSA",
            "kid": "enc-key",
            "alg": "RSA-OAEP-256",
            "n": URL_SAFE_NO_PAD.encode([1u8; 16]),
            "e": URL_SAFE_NO_PAD.encode([1u8; 3]),
        }))
        .unwrap();

        assert!(to_signing_key(&jwk).is_none());
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
}
