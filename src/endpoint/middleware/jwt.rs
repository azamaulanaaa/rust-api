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
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    error::ErrorUnauthorized,
};
use futures_util::future::LocalBoxFuture;
pub use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use jsonwebtoken::{decode, jwk::{AlgorithmParameters, Jwk, KeyAlgorithm}};
use serde::{Deserialize, de::DeserializeOwned};

use super::bearer_token::BearerToken;

/// Minimum interval between two JWKS fetches triggered by unknown-key misses.
/// Prevents a flood of junk tokens from hammering the identity provider.
const JWKS_REFRESH_DEBOUNCE: Duration = Duration::from_secs(5);

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multi(Vec<String>),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    pub iss: String,           // Issuer
    pub sub: String,           // Subject (User ID)
    pub aud: Audience,         // Handle both String and [String]
    pub exp: u64,              // Expiration (u64 for 2038+ safety)
    pub nbf: Option<u64>,      // Not Before
    pub iat: Option<u64>,      // Issued At
    pub nonce: Option<String>, // Required for OIDC flow verification
    pub jti: Option<String>,   // JWT ID (Good for revocation)
}

#[derive(Debug, Clone)]
pub struct SigningKey {
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
            Ok(_) => log::warn!(
                "Refreshed JWKS at {} but it contains no usable signing keys; keeping previous keys",
                self.inner.url
            ),
            Err(e) => log::warn!(
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
    pub fn new(keys: JwksKeys, validation: Validation) -> Self {
        Self {
            keys,
            validation,
            _claims: PhantomData,
        }
    }

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

        let token = [
            req.cookie("auth_token").map(|c| c.value().to_string()),
            req.extensions().get::<BearerToken>().cloned().map(|v| v.0),
        ]
        .into_iter()
        .flatten()
        .next();

        Box::pin(async move {
            if let Some(token) = token {
                let header = match jsonwebtoken::decode_header(&token) {
                    Ok(h) => h,
                    Err(e) => return Err(ErrorUnauthorized(e)),
                };

                let Some(signing_key) = keys.get(header.kid.as_deref()).await else {
                    return Err(ErrorUnauthorized("No matching signing key found for token"));
                };

                // Pin validation to the selected key's own algorithm so a
                // token cannot downgrade to an unexpected algorithm.
                let mut validation = validation.clone();
                validation.algorithms = vec![signing_key.algorithm];

                match decode::<C>(&token, &signing_key.decoding_key, &validation) {
                    Ok(token_data) => req.extensions_mut().insert(token_data.claims),
                    Err(e) => return Err(ErrorUnauthorized(format!("Invalid Token: {}", e))),
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

    fn sign_rs256(claims: &serde_json::Value, kid: &str, key: &EncodingKey) -> anyhow::Result<String> {
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
        let keys = JwksKeys::with_refresh_debounce(
            format!("{}/jwks", server.uri()),
            Duration::ZERO,
        )
        .await?;
        assert!(keys.get(Some("kid-a")).await.is_some());
        assert!(keys.get(Some("kid-b")).await.is_none()); // miss → debounced refresh

        // Provider rotates: JWKS now serves only kid-b.
        serve_jwks(json!({ "keys": [key_b] })).await;

        let refreshed = keys.get(Some("kid-b")).await;
        assert!(refreshed.is_some(), "rotation should be picked up after refresh");
        assert!(keys.get(Some("kid-a")).await.is_none(), "retired kid must be dropped");

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
        assert!(decode::<TestClaims>(&forged, &signing_key.decoding_key, &validation).is_err(),
            "HMAC family can never verify against an RSA decoding key");

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
        assert!(result.is_err(), "a JWKS containing only oct keys must fail construction");

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
}
