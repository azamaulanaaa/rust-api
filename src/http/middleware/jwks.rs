//! A signing key store that uses JWKS and can refresh its keys.
//!
//! The store loads the keys once when it is created. It serves the keys
//! from the cache afterwards. When a token refers to an unknown `kid`, which
//! usually happens right after the provider rotated its signing keys, the
//! store fetches the JWKS document again. A debounce limit stops repeated
//! misses from flooding the provider.

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

/// The shared `reqwest` client for the JWKS fetches. The client reuses one
/// connection pool, so it avoids creating a new client for each refresh.
/// `reqwest::get` created a new client each time. The client uses only
/// `rustls`, to match the `reqwest` feature set of the whole workspace and
/// to save the `native-tls` compile time.
///
/// The `expect` follows the convention of this crate for a build-time
/// failure that the code cannot pass to a caller, as in
/// `db::build_test_store`. It runs at first use, and only when the TLS
/// backend is malformed, so there is no request that can fail.
#[allow(clippy::expect_used)]
static JWKS_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("JWKS reqwest client must build")
});

/// The minimum time between two JWKS fetches that an unknown-key miss
/// triggers. The limit stops a flood of junk tokens from overloading the
/// identity provider.
///
/// The code consumes the window when it ATTEMPTS a refresh, and not when the
/// refresh succeeds. Therefore the limit holds against a provider that is
/// down as firmly as it holds against one that is healthy.
const JWKS_REFRESH_DEBOUNCE: Duration = Duration::from_secs(5);

/// One verification key that the code resolved from the JWKS of the
/// provider. The key also holds the algorithm that every token signed with it
/// must use.
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// The raw key material that verifies the token signatures.
    pub(crate) decoding_key: DecodingKey,
    /// The verification algorithm that comes from the `alg` of this key. The
    /// code uses the OIDC default RS256 when the JWK has no `alg`. The code
    /// validates the tokens against exactly this algorithm, which prevents
    /// algorithm-confusion attacks.
    pub(crate) algorithm: Algorithm,
}

/// A signing key store that uses JWKS and can refresh its keys.
///
/// The process has one cache. Every clone of `JwtClaimsMiddleware` shares
/// that cache, because the clones share the `Arc` state. Therefore one fetch
/// from the provider serves every worker. On an unknown-`kid` miss, the
/// store fetches the document again at most once per
/// `JWKS_REFRESH_DEBOUNCE`. A fetch that fails, or that returns no usable
/// keys, keeps the previous set instead of dropping it.
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

    /// The test-only variant with a debounce window that a test can set.
    /// `Duration::ZERO` makes every refresh on a miss fire at once.
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
    /// The store can resolve a missing `kid` only when the provider
    /// publishes exactly one key. Otherwise the request cannot select a key
    /// safely, and the function returns `None`.
    pub async fn get(&self, kid: Option<&str>) -> Option<SigningKey> {
        // The fast path: the cache holds the key.
        if let Some(key) = self.lookup(kid).await {
            return Some(key);
        }

        // The code misses. The provider may have rotated its signing keys.
        // The store refreshes once, within the debounce limit, and then looks
        // up the key again.
        self.maybe_refresh().await;
        self.lookup(kid).await
    }

    async fn lookup(&self, kid: Option<&str>) -> Option<SigningKey> {
        let keys = self.inner.keys.read().await.clone(); // The Arc clone is cheap
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

    /// Fetches the keys again at most once per debounce window, and keeps the
    /// previous keys instead of emptying the cache on a failure.
    ///
    /// The code advances the timestamp BEFORE the fetch, in the same critical
    /// section that decides whether to fetch. Therefore a failure consumes the
    /// window exactly like a success. The code used to advance the timestamp
    /// only in the success arm, so the bound that this module documents,
    /// "at most once per `JWKS_REFRESH_DEBOUNCE`", held only while the
    /// provider was reachable. Against a slow or down IdP, `elapsed()` grew
    /// past the window on every request, and each miss sent a new outbound
    /// GET. That is the exact flood that the module doc claims to prevent,
    /// amplified at the provider instead of at this process.
    ///
    /// The code also releases the guard before the fetch, and it does not
    /// hold the guard across the fetch. It used to hold the guard across a
    /// round trip with a ten-second client timeout, so one slow GET parked
    /// every other worker's unknown-`kid` miss behind it. Scoping the guard
    /// to its own critical section keeps the mutual exclusion that matters,
    /// as described below, without holding a lock over I/O.
    ///
    /// Two concurrent misses still produce ONE fetch. The winner finds the
    /// timestamp stale and rewrites it. Every other caller then reads a
    /// fresh timestamp and returns without fetching. The loser does not wait
    /// for the winner's result, and it does not need to. The lookup that it
    /// runs afterwards reads the shared cache, and the winner updates that
    /// cache when the result lands. The concurrency is therefore bounded to
    /// one refresh for the whole process, and not one for each worker.
    ///
    /// The trade is that the window is measured from the START of an attempt.
    /// A fetch that takes longer than the debounce therefore leaves the
    /// window already elapsed, and the next miss may refresh again at once.
    /// That is still the documented bound of one refresh per
    /// `JWKS_REFRESH_DEBOUNCE`, and it is the right direction. A provider
    /// that is slow enough for the fetch to exceed the window is exactly the
    /// provider for which another check for a rotation is worth more than a
    /// wait.
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
/// - The function rejects every HMAC (`oct`) key. An OIDC provider must never
///   publish shared secrets in its JWKS, and trusting such a key would allow
///   algorithm-confusion attacks.
/// - The function reads the algorithm from the `alg` parameter of the key. It
///   falls back to RS256, which is the usual OIDC default, when the parameter
///   is absent. Many older providers omit the parameter.
/// - The function skips a key when its `alg` value is for encryption only, or
///   when the value is not recognized. It also skips a key without a `kid`,
///   because a token could never refer to that key.
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

/// The fixtures that the JWT and JWKS test modules of this crate share.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::EncodingKey;
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
    use serde::Deserialize;
    use serde_json::json;
    use wiremock::MockServer;

    /// The smallest claims shape that the decode assertions use.
    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct TestClaims {
        pub sub: String,
    }

    /// Serves a static JWKS document on a new mock provider.
    pub(crate) async fn spawn_jwks(body: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/jwks"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        server
    }

    /// Creates an RSA key pair. The function returns the JWKS JSON entry and the
    /// encoding key.
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

    /// Signs `claims` as an RS256 JWT with the given `kid`.
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

    /// The number of requests that the mock provider has served so far.
    ///
    /// The value `received_requests` is `None` when the recording is
    /// disabled. The pooled servers that this crate starts do not disable
    /// the recording, but a default of zero keeps the assertions below
    /// reading as counts instead of as `Option` arms.
    async fn served_requests(server: &MockServer) -> usize {
        server.received_requests().await.map_or(0, |r| r.len())
    }

    #[tokio::test]
    async fn loads_keys_and_resolves_a_kid() -> anyhow::Result<()> {
        let (key_a, _) = rsa_key("kid-a")?;
        let server = spawn_jwks(json!({ "keys": [key_a] })).await;

        let keys = JwksKeys::new(format!("{}/jwks", server.uri())).await?;
        let signing_key = keys.get(Some("kid-a")).await.expect("kid-a should resolve");
        assert_eq!(signing_key.algorithm, Algorithm::RS256);

        Ok(())
    }

    #[tokio::test]
    async fn an_unknown_kid_triggers_a_refresh() -> anyhow::Result<()> {
        let (key_a, _) = rsa_key("kid-a")?;
        let (key_b, enc_b) = rsa_key("kid-b")?;
        let server = MockServer::start().await;

        let serve_jwks = |body: serde_json::Value| {
            let server = &server;
            async move {
                // Reset first, so that wiremock does not keep serving older
                // mounts. Wiremock matches the FIRST mounted mock, and not
                // the latest one.
                server.reset().await;
                Mock::given(method("GET"))
                    .and(path("/jwks"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(body))
                    .mount(server)
                    .await;
            }
        };

        serve_jwks(json!({ "keys": [key_a] })).await;

        // The debounce is zero, so the refresh on a miss fires at once.
        let keys =
            JwksKeys::with_refresh_debounce(format!("{}/jwks", server.uri()), Duration::ZERO)
                .await?;
        assert!(keys.get(Some("kid-a")).await.is_some());
        assert!(keys.get(Some("kid-b")).await.is_none()); // A miss causes a refresh

        // The provider rotates its keys, so the JWKS document now serves
        // only kid-b.
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

        // The refreshed key must verify a token that kid-b signed.
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
    /// The regression: `last_refresh` advanced only in the success-with-keys
    /// arm, so against an unreachable or broken provider `elapsed()` grew
    /// past the window on every request. Every later miss sent a new
    /// outbound GET. That is the flood that the module doc claims to
    /// prevent, aimed at the identity provider. Nothing here is a question
    /// about authorization. The lookup still fails closed, and the store
    /// keeps the previous keys. It is a question of availability, at a third
    /// party, and unauthenticated junk tokens amplify the effect.
    ///
    /// The assertion checks the number of requests at the provider, not a
    /// returned value. The returned value is `None` in both cases, so it
    /// cannot tell "debounced" from "fetched again and failed again".
    ///
    /// The test covers both failure arms, a transport or parse error and an
    /// empty key set. They are separate branches, and either one alone would
    /// reintroduce the flood for a provider that hits it.
    ///
    /// The debounce is a real 500ms with a sleep past it, and not the
    /// `Duration::ZERO` that the other tests use. The window has to be over
    /// for the FIRST miss to fetch, and then closed again for the second.
    /// 500ms is much longer than the two lookups on either side of it, so
    /// this is not a timing race.
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

        // The provider is healthy at first, so the cache holds the keys
        // and `kid-a` resolves.
        serve(200, json!({ "keys": [key_a] }).to_string()).await;
        let debounce = Duration::from_millis(500);
        let keys =
            JwksKeys::with_refresh_debounce(format!("{}/jwks", server.uri()), debounce).await?;
        assert!(keys.get(Some("kid-a")).await.is_some());
        let after_construction = served_requests(&server).await;

        // The provider then fails in both ways in turn.
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

            // The next miss, well inside the window that the failure just
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

        // The same window with a different failure arm: a 200 whose body
        // has no usable key. That case took the `Ok(_)` branch before, and
        // the old code advanced `last_refresh` in neither failure path.
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
    /// One change produced both properties, so one test covers them. The guard
    /// used to be held for the whole `fetch_keys` await, whose client timeout
    /// is ten seconds. One slow GET parked every other worker's unknown-`kid`
    /// miss behind it. Narrowing the lock is only safe if the mutual
    /// exclusion that it provided survives, so the test asserts both halves.
    /// The parked fetch does not block the second miss, and the second miss
    /// does not start a second fetch.
    ///
    /// The miss that loses the race answers `None` instead of waiting for the
    /// winner's result. It reads the shared cache again, which the winner
    /// updates when the result lands, and it fails closed until then. That is
    /// the intended behavior, and the test asserts it instead of leaving it
    /// implied. This is an authentication path, so "concurrent misses may
    /// miss" must be a deliberate property that a test pins.
    ///
    /// The test is deterministic rather than a race. The mock delays its
    /// response for longer than the whole test waits for the second miss, so
    /// the first fetch is still in flight when the second miss runs.
    #[tokio::test]
    async fn concurrent_misses_collapse_into_one_unblocked_fetch() -> anyhow::Result<()> {
        let (key_a, _) = rsa_key("kid-a")?;
        let (key_b, _) = rsa_key("kid-new")?;
        let server = MockServer::start().await;

        // The provider is healthy and fast at first, so the fixture caches
        // kid-a.
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [key_a] })))
            .mount(&server)
            .await;

        // The debounce is short but real. It is long enough that the
        // second miss below is inside the window that the first one
        // consumes, and short enough that the window has elapsed by the time
        // the first miss runs. `Duration::ZERO` would let both misses fetch
        // and would prove nothing.
        let debounce = Duration::from_millis(500);
        let keys =
            JwksKeys::with_refresh_debounce(format!("{}/jwks", server.uri()), debounce).await?;
        assert!(keys.get(Some("kid-a")).await.is_some(), "fixture cache");

        // The provider rotates its keys AND becomes slow, so the refresh
        // that the miss below triggers takes five seconds to come back.
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

        // The winner eventually installs the rotated key.
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
    async fn rejects_algorithm_confusion_attacks() -> anyhow::Result<()> {
        // The provider publishes an RSA key. The attacker signs an HS256
        // token and tries to use the RSA public material as an HMAC secret.
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
    async fn rejects_hmac_octet_keys() -> anyhow::Result<()> {
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
    async fn derives_es256_from_an_ec_key() -> anyhow::Result<()> {
        // Arbitrary P-256 point coordinates. Parsing a JWK never checks
        // that a point is on the curve, so this reaches the EC code path
        // without a signer dependency.
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
    fn a_missing_alg_falls_back_to_rs256() {
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
    fn an_encryption_only_alg_is_skipped() {
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
