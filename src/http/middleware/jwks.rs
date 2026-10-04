//! Refreshable JWKS-backed signing-key store.
//!
//! Keys are loaded once on construction and served from cache afterwards.
//! When a token references an unknown `kid` (typically right after the
//! provider rotated its signing keys), the JWKS document is refetched —
//! debounced so repeated misses cannot be used to flood the provider.

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use jsonwebtoken::{
    Algorithm, DecodingKey,
    jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm},
};

/// Shared `reqwest` client for JWKS fetches — reuses the same connection
/// pool and avoids constructing a new client per refresh (previously
/// `reqwest::get` did that). The client is `rustls`-only to match the
/// workspace-wide `reqwest` feature set and save `native-tls` compile time.
///
/// The `expect` is the crate's convention for a build-time-only failure
/// that cannot be surfaced to a caller (same as `db::build_test_store`):
/// it fires at first use and only on a malformed TLS backend, so there is
/// no request to fail.
#[allow(clippy::expect_used)]
static JWKS_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("JWKS reqwest client must build")
});

/// Minimum interval between two JWKS fetches triggered by unknown-key misses.
/// Prevents a flood of junk tokens from hammering the identity provider.
///
/// The window is consumed when a refresh is ATTEMPTED, not when it succeeds,
/// so the bound holds against a provider that is down as firmly as against one
/// that is healthy.
const JWKS_REFRESH_DEBOUNCE: Duration = Duration::from_secs(5);

/// A single verification key resolved from the provider's JWKS, paired
/// with the algorithm tokens signed by it must use.
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// The raw key material used to verify token signatures.
    pub(crate) decoding_key: DecodingKey,
    /// Verification algorithm derived from this key's own `alg` (or the OIDC
    /// default RS256 when the JWK omits it). Tokens are validated against
    /// exactly this algorithm, preventing algorithm-confusion attacks.
    pub(crate) algorithm: Algorithm,
}

/// Refreshable JWKS-backed signing key store.
///
/// One cache per process, shared by every `JwtClaimsMiddleware` clone
/// (clones share the `Arc` state, so one provider fetch serves all
/// workers). On an unknown-`kid` miss the document is refetched at most
/// once per `JWKS_REFRESH_DEBOUNCE`, and a fetch that fails or returns
/// no usable keys keeps the previous set rather than dropping it.
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

    /// Refetches at most once per debounce window, and drops the previous
    /// keys rather than emptying the cache on a failure.
    ///
    /// The timestamp is advanced BEFORE the fetch, in the same critical
    /// section that decides whether to fetch, so a failure consumes the
    /// window exactly like a success. It previously advanced only in the
    /// success arm, which meant the bound this module documents -- "at most
    /// once per `JWKS_REFRESH_DEBOUNCE`" -- held only while the provider was
    /// reachable. Against a slow or down IdP, `elapsed()` kept growing past
    /// the window on every request, and each miss issued a fresh outbound
    /// GET: the exact flood the module doc claims is prevented, amplified at
    /// the provider rather than at this process.
    ///
    /// The guard is also released before the fetch rather than held across
    /// it. It used to be held across a round trip with a ten-second client
    /// timeout, so one slow GET parked every other worker's unknown-`kid`
    /// miss behind it. Scoping the claim to its own critical section keeps
    /// the mutual exclusion that matters -- see below -- without holding a
    /// lock over I/O.
    ///
    /// Two concurrent misses still produce ONE fetch: the winner is the one
    /// that finds the timestamp stale and rewrites it, and every other caller
    /// then reads a fresh one and returns without fetching. The loser does
    /// not wait for the winner's result -- it does not need to, because the
    /// lookup it performs afterwards is against the shared cache, which the
    /// winner updates when it lands. So the concurrency is bounded to one
    /// in-flight refresh process-wide, not one per worker.
    ///
    /// The trade is that the window is measured from the START of an attempt,
    /// so a fetch that outlives the debounce leaves it already elapsed and
    /// the next miss may refresh again immediately. That is still the
    /// documented bound -- one refresh per `JWKS_REFRESH_DEBOUNCE` -- and it
    /// is the right direction: a provider slow enough for the fetch to
    /// exceed the window is exactly the one where re-checking for a rotation
    /// is worth more than waiting.
    async fn maybe_refresh(&self) {
        {
            let mut last_refresh = self.inner.last_refresh.lock().await;
            if last_refresh.elapsed() < self.inner.refresh_debounce {
                return;
            }
            *last_refresh = Instant::now();
        }

        match fetch_keys(&self.inner.url).await {
            Ok(keys) if !keys.is_empty() => {
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
    let jwks: JwkSet = JWKS_CLIENT.get(url).send().await?.json().await?;

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

/// Shared fixtures for JWT/JWKS test modules across this crate.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::EncodingKey;
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
    use serde::Deserialize;
    use serde_json::json;
    use wiremock::MockServer;

    /// Minimal claims shape used by decode assertions.
    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct TestClaims {
        pub sub: String,
    }

    /// Serves a static JWKS document on a fresh mock provider.
    pub(crate) async fn spawn_jwks(body: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        server
    }

    /// Generates an RSA keypair and returns (jwks JSON entry, encoding key).
    pub(crate) fn rsa_key(kid: &str) -> anyhow::Result<(serde_json::Value, EncodingKey)> {
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

    /// Signs `claims` as an RS256 JWT under the given `kid`.
    pub(crate) fn sign_rs256(
        claims: &serde_json::Value,
        kid: &str,
        key: &EncodingKey,
    ) -> anyhow::Result<String> {
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        Ok(jsonwebtoken::encode(&header, claims, key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::middleware::jwks::test_support::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{EncodingKey, Header, Validation, decode, encode};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Requests the mock provider has served so far.
    ///
    /// `received_requests` is `None` when recording is disabled, which the
    /// pooled servers this crate starts do not do -- but a zero default keeps
    /// the assertions below reading as counts rather than as `Option` arms.
    async fn served_requests(server: &MockServer) -> usize {
        server.received_requests().await.map_or(0, |r| r.len())
    }

    #[tokio::test]
    async fn loads_keys_and_resolves_kid() -> anyhow::Result<()> {
        let (key_a, _) = rsa_key("kid-a")?;
        let server = spawn_jwks(json!({ "keys": [key_a] })).await;

        let keys = JwksKeys::new(format!("{}/jwks", server.uri())).await?;
        let signing_key = keys.get(Some("kid-a")).await.expect("kid-a should resolve");
        assert_eq!(signing_key.algorithm, Algorithm::RS256);

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

    /// A FAILED refresh must consume the debounce window.
    ///
    /// The regression: `last_refresh` advanced only in the
    /// success-with-keys arm, so against an unreachable or broken provider
    /// `elapsed()` kept growing past the window and every subsequent miss
    /// issued a fresh outbound GET -- the flood the module doc claims is
    /// prevented, aimed at the identity provider. Nothing here is an authz
    /// question: the lookup still fails closed and the previous keys are
    /// kept. It is availability, at a third party, amplified by unauthenticated
    /// junk tokens.
    ///
    /// The assertion is on the provider's request count rather than on a
    /// returned value, because the returned value is `None` either way and
    /// cannot distinguish "debounced" from "refetched and failed again".
    ///
    /// Both failure arms are covered -- a transport/parse error and an empty
    /// key set -- because they are separate branches and either one alone
    /// would reintroduce the flood for a provider that hits it.
    ///
    /// The debounce is a real 500ms with a sleep past it, rather than the
    /// `Duration::ZERO` the other tests use: the window has to be over for
    /// the FIRST miss to fetch, and then closed again for the second. 500ms
    /// is orders of magnitude longer than the two lookups either side of it,
    /// so this is not a timing race.
    #[tokio::test]
    async fn a_failed_refresh_still_consumes_the_debounce_window() -> anyhow::Result<()> {
        let (key_a, _) = rsa_key("kid-a")?;
        let server = MockServer::start().await;

        let serve = |status: u16, body: String| {
            let server = &server;
            async move {
                server.reset().await;
                Mock::given(method("GET"))
                    .and(path("/jwks"))
                    .respond_with(ResponseTemplate::new(status).set_body_string(body))
                    .mount(server)
                    .await;
            }
        };

        // Healthy to start, so the cache is populated and `kid-a` resolves.
        serve(200, json!({ "keys": [key_a] }).to_string()).await;
        let debounce = Duration::from_millis(500);
        let keys =
            JwksKeys::with_refresh_debounce(format!("{}/jwks", server.uri()), debounce).await?;
        assert!(keys.get(Some("kid-a")).await.is_some());
        let after_construction = served_requests(&server).await;

        // The provider starts failing in both ways in turn.
        for (status, body) in [(503u16, "upstream unavailable".to_string())] {
            tokio::time::sleep(debounce).await;
            serve(status, body).await;
            let before = served_requests(&server).await;

            assert!(
                keys.get(Some("kid-unknown")).await.is_none(),
                "an unresolvable kid must fail closed"
            );
            let after_first = served_requests(&server).await;
            assert_eq!(
                after_first,
                before + 1,
                "the first miss inside an elapsed window must fetch once"
            );

            // The next miss, well inside the window the failure just
            // consumed, must not reach the provider at all.
            assert!(keys.get(Some("kid-unknown")).await.is_none());
            assert_eq!(
                served_requests(&server).await,
                after_first,
                "a FAILED refresh must consume the debounce window; the old \
                 timestamp advanced only on success, so every junk token \
                 issued its own GET at the identity provider"
            );
        }

        // Same window, different failure arm: a 200 whose body carries no
        // usable key. It took the `Ok(_)` branch before, and the old code
        // advanced `last_refresh` in neither failure path.
        tokio::time::sleep(debounce).await;
        serve(200, json!({ "keys": [] }).to_string()).await;
        let before = served_requests(&server).await;
        assert!(keys.get(Some("kid-unknown")).await.is_none());
        let after_first = served_requests(&server).await;
        assert_eq!(after_first, before + 1, "the first miss fetches once");
        assert!(keys.get(Some("kid-unknown")).await.is_none());
        assert_eq!(
            served_requests(&server).await,
            after_first,
            "an empty key set must consume the window too"
        );

        assert!(
            after_construction >= 1,
            "the fixture itself must have fetched, or the counts above prove nothing"
        );
        Ok(())
    }

    /// The refresh mutex is not held across the network call, and concurrent
    /// misses still collapse into ONE fetch.
    ///
    /// These are one change, so they are one test. The guard used to be held
    /// for the whole `fetch_keys` await, whose client timeout is ten
    /// seconds: one slow GET parked every other worker's unknown-`kid` miss
    /// behind it. Narrowing the lock is only safe if the mutual exclusion it
    /// provided survives, so both halves are asserted: the parked fetch does
    /// not block the second miss, and the second miss does not start a
    /// second fetch.
    ///
    /// The miss that loses the race answers `None` rather than waiting for
    /// the winner's result -- it re-reads the shared cache, which the winner
    /// updates when it lands, and fails closed until then. That is the
    /// intended behaviour and it is asserted, not left implied: this is an
    /// authentication path, so "concurrent misses may miss" must be a
    /// deliberate, pinned property.
    ///
    /// Deterministic rather than a race: the mock delays its response for
    /// longer than the whole test's patience for the second miss, so the
    /// first fetch is provably still in flight when the second runs.
    #[tokio::test]
    async fn concurrent_misses_collapse_into_one_unblocked_fetch() -> anyhow::Result<()> {
        let (key_a, _) = rsa_key("kid-a")?;
        let (key_b, _) = rsa_key("kid-new")?;
        let server = MockServer::start().await;

        // Healthy and fast to begin with, so the fixture caches kid-a.
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [key_a] })))
            .mount(&server)
            .await;

        // Short but real: long enough that the second miss below is inside
        // the window the first one consumes, short enough that the window has
        // elapsed by the time the first miss runs. `Duration::ZERO` would let
        // both fetch and prove nothing.
        let debounce = Duration::from_millis(500);
        let keys =
            JwksKeys::with_refresh_debounce(format!("{}/jwks", server.uri()), debounce).await?;
        assert!(keys.get(Some("kid-a")).await.is_some(), "fixture cache");

        // The provider rotates AND gets slow: the refresh the miss below
        // triggers takes five seconds to come back.
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(5))
                    .set_body_json(json!({ "keys": [key_b] })),
            )
            .mount(&server)
            .await;

        tokio::time::sleep(debounce).await;
        let first = tokio::spawn({
            let keys = keys.clone();
            async move { keys.get(Some("kid-new")).await }
        });
        // Let the winner claim the window and enter the fetch.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let before = served_requests(&server).await;
        assert_eq!(before, 1, "the winner must have started exactly one fetch");

        let second =
            tokio::time::timeout(Duration::from_millis(500), keys.get(Some("kid-new"))).await;
        assert!(
            second.is_ok(),
            "a miss must not block behind an in-flight refresh; the mutex is \
             held across the fetch's ten-second client timeout"
        );
        assert!(
            second.expect("timeout did not fire").is_none(),
            "the losing miss fails closed rather than waiting for the winner"
        );
        assert_eq!(
            served_requests(&server).await,
            before,
            "two concurrent misses must produce ONE refresh, not one each"
        );

        // The winner eventually lands the rotated key.
        let resolved = tokio::time::timeout(Duration::from_secs(20), first)
            .await
            .expect("the parked fetch must finish")
            .expect("task must not panic");
        assert!(
            resolved.is_some(),
            "and the winner's fetch must still install the rotated key"
        );
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
}
