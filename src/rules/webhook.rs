//! An outbound webhook action.
//!
//! The action sends one JSON `POST` request for one rule event.
//! The action can send the request directly.
//! The action can also enqueue a `webhook.deliver` job.
//! The queue retries a failed job.
//! The queue idempotency key deduplicates one rule and one event.
//! The receiver must deduplicate on the `X-Event-Id` header.
//! The action adds no business logic.
//!
//! A strict host allowlist limits the destinations.
//! The client follows no redirects.
//! The allowlist and the disabled redirects limit the destinations.
//! A compromised allowlisted host remains trusted.
//! The action cannot stop that host from reading the payload.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use url::Url;

use crate::eav::metrics::EavMetrics;
use crate::queue::{Job, JobHandler, JobQueue};
use crate::records::{AttributeChange, EntityEventKind};
use crate::rules::action::{ActionContext, RuleAction};

/// The job kind for one webhook delivery.
const JOB_KIND: &str = "webhook.deliver";

/// The default maximum number of delivery attempts.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// The maximum length of a webhook URL in bytes.
const MAX_URL_BYTES: usize = 2048;

/// The request timeout in seconds.
const TIMEOUT_SECS: u64 = 10;

/// Records the result of one webhook delivery.
///
/// The call adds one to the delivered or the failed counter.
fn record_delivery(succeeded: bool, elapsed: Duration) {
    let metrics = EavMetrics::global();
    if succeeded {
        metrics.record_webhook_delivered(elapsed);
    } else {
        metrics.record_webhook_failure();
    }
}

/// An action that posts one event to an allowlisted host.
///
/// The action builds one client with a 10 second timeout.
/// The client follows no redirects.
#[derive(Clone)]
pub struct WebhookAction {
    /// The parsed allowlist entries.
    allowed_hosts: Vec<AllowedHost>,
    /// The shared HTTP client.
    client: reqwest::Client,
    /// The optional queue for durable delivery.
    queue: Option<Arc<dyn JobQueue>>,
    /// The optional HMAC-SHA256 signing secret.
    signing_secret: Option<Vec<u8>>,
    /// The maximum number of delivery attempts.
    max_attempts: u32,
}

impl std::fmt::Debug for WebhookAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookAction")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("has_queue", &self.queue.is_some())
            .field("has_signing_secret", &self.signing_secret.is_some())
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl WebhookAction {
    /// Creates the action from the allowed host entries.
    ///
    /// Each entry is a host or a `host:port` pair.
    /// An empty list rejects every webhook rule.
    /// The direct mode uses no queue and no signing secret.
    pub fn new(allowed_hosts: Vec<String>) -> Self {
        let allowed_hosts = allowed_hosts
            .iter()
            .filter_map(|entry| parse_allowed_host(entry))
            .collect();
        Self {
            allowed_hosts,
            client: build_client(),
            queue: None,
            signing_secret: None,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Uses the shared queue for delivery.
    ///
    /// The queue retries a failed job.
    /// The call stores the optional HMAC secret and the maximum attempt count.
    pub fn with_queue(
        mut self,
        queue: Arc<dyn JobQueue>,
        signing_secret: Option<Vec<u8>>,
        max_attempts: u32,
    ) -> Self {
        self.queue = Some(queue);
        self.signing_secret = signing_secret;
        self.max_attempts = max_attempts;
        self
    }

    /// Builds the job handler for the queue path.
    ///
    /// The handler holds the allowlist, the HTTP client, and the signing
    /// secret.
    pub fn job_handler(&self) -> WebhookJobHandler {
        WebhookJobHandler::new(self.client.clone(), self.signing_secret.clone())
            .with_allowed_hosts(self.allowed_hosts.clone())
    }
}

#[async_trait]
impl RuleAction for WebhookAction {
    fn kind(&self) -> &str {
        "webhook"
    }

    /// Checks one object with a `url` string.
    ///
    /// The call accepts `http` and `https`.
    /// It accepts `http` only for a loopback host in the allowlist.
    /// It rejects user information, a missing host, a fragment, a long URL,
    /// and a host that is not in the allowlist.
    fn validate(&self, params: &serde_json::Value) -> Result<(), anyhow::Error> {
        let url = url_from_params(params)?;
        validate_url(&url, &self.allowed_hosts)
    }

    async fn execute(&self, ctx: ActionContext) -> Result<(), anyhow::Error> {
        self.validate(&ctx.params)?;
        let url = url_from_params(&ctx.params)?;
        let payload = WebhookPayload {
            rule_id: &ctx.rule.id,
            event_id: &ctx.event.event_id,
            entity_id: &ctx.event.entity_id,
            entity_version: ctx.event.entity_version,
            kind: ctx.event.kind,
            schemas: &ctx.event.schemas,
            changed: &ctx.event.changed,
            occurred_at: ctx.event.occurred_at,
            correlation_id: &ctx.event.correlation_id,
            causation_id: ctx.event.causation_id.as_deref(),
            params: &ctx.params,
        };
        let Some(queue) = &self.queue else {
            let body = serde_json::to_vec(&payload)
                .map_err(|_| anyhow::anyhow!("webhook payload is not valid"))?;
            let started = Instant::now();
            let result = send_webhook(
                &self.client,
                url,
                &body,
                ctx.event.event_id.as_str(),
                ctx.rule.id.as_str(),
                self.signing_secret.as_deref(),
            )
            .await;
            record_delivery(result.is_ok(), started.elapsed());
            return result;
        };
        let envelope = WebhookJobPayload {
            url: url.to_string(),
            body: serde_json::to_value(&payload)
                .map_err(|_| anyhow::anyhow!("webhook payload is not valid"))?,
        };
        let body = serde_json::to_vec(&envelope)
            .map_err(|_| anyhow::anyhow!("webhook job payload is not valid"))?;
        let now = chrono::Utc::now().timestamp();
        let job = Job {
            id: uuid::Uuid::now_v7(),
            kind: JOB_KIND.to_string(),
            payload: body,
            priority: 0,
            attempt: 0,
            max_attempts: self.max_attempts.max(1),
            created_at: now,
            scheduled_at: now,
            idempotency_key: Some(format!("webhook:{}:{}", ctx.rule.id, ctx.event.event_id)),
            headers: BTreeMap::new(),
        };
        queue
            .enqueue(job)
            .await
            .map_err(|error| anyhow::anyhow!("webhook job enqueue failed: {error}"))?;
        Ok(())
    }
}

/// A job handler that delivers one queued webhook.
///
/// The handler holds the allowlist, the HTTP client, and the signing secret.
#[derive(Clone)]
pub struct WebhookJobHandler {
    /// The parsed allowlist entries.
    allowed_hosts: Vec<AllowedHost>,
    /// The shared HTTP client.
    client: reqwest::Client,
    /// The optional HMAC-SHA256 signing secret.
    signing_secret: Option<Vec<u8>>,
}

impl WebhookJobHandler {
    /// Creates a handler from the HTTP client and the signing secret.
    ///
    /// The handler starts with an empty allowlist.
    /// Use [`WebhookAction::job_handler`](crate::rules::webhook::WebhookAction::job_handler) to add allowlist entries.
    pub fn new(client: reqwest::Client, signing_secret: Option<Vec<u8>>) -> Self {
        Self {
            allowed_hosts: Vec::new(),
            client,
            signing_secret,
        }
    }

    /// Adds the parsed allowlist entries.
    ///
    /// Each entry is a host or a `host:port` pair.
    /// An empty list rejects every webhook job.
    fn with_allowed_hosts(mut self, allowed_hosts: Vec<AllowedHost>) -> Self {
        self.allowed_hosts = allowed_hosts;
        self
    }
}

#[async_trait]
impl JobHandler for WebhookJobHandler {
    fn kind(&self) -> &'static str {
        JOB_KIND
    }

    /// Delivers one queued webhook.
    ///
    /// The call decodes the job body.
    /// It validates the URL again against the allowlist.
    /// It posts the body with the event, rule, and user-agent headers.
    /// It adds the `X-Signature` header when a signing secret exists.
    /// A 2xx status is a success.
    /// Any other status or a network error returns an error.
    async fn handle(&self, job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
        let started = Instant::now();
        let result = self.deliver(job).await;
        record_delivery(result.is_ok(), started.elapsed());
        result
    }
}

impl WebhookJobHandler {
    /// Delivers one queued webhook and returns the handler result.
    ///
    /// The call decodes the job body.
    /// It validates the URL again against the allowlist.
    /// It posts the body with the event, rule, and user-agent headers.
    /// It adds the `X-Signature` header when a signing secret exists.
    /// A 2xx status is a success.
    /// Any other status or a network error returns an error.
    async fn deliver(&self, job: &Job) -> Result<Option<Vec<u8>>, anyhow::Error> {
        let envelope: WebhookJobPayload = serde_json::from_slice(&job.payload)
            .map_err(|_| anyhow::anyhow!("webhook job payload is not valid"))?;
        let url = Url::parse(&envelope.url)
            .map_err(|_| anyhow::anyhow!("webhook job URL is not valid"))?;
        validate_url(&url, &self.allowed_hosts)?;
        let event_id = envelope
            .body
            .get("event_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("webhook job body has no event id"))?;
        let rule_id = envelope
            .body
            .get("rule_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("webhook job body has no rule id"))?;
        let body = serde_json::to_vec(&envelope.body)
            .map_err(|_| anyhow::anyhow!("webhook job body is not valid"))?;
        send_webhook(
            &self.client,
            url,
            &body,
            event_id,
            rule_id,
            self.signing_secret.as_deref(),
        )
        .await?;
        Ok(None)
    }
}

/// The JSON body of one webhook request.
///
/// The body holds no entity snapshot.
#[derive(Debug, Serialize)]
struct WebhookPayload<'a> {
    /// The rule id.
    rule_id: &'a str,
    /// The event id.
    event_id: &'a str,
    /// The entity id.
    entity_id: &'a str,
    /// The entity version after the event.
    entity_version: u64,
    /// The event kind.
    kind: EntityEventKind,
    /// The schemas that apply to the entity.
    schemas: &'a [String],
    /// The attributes that the event changed.
    changed: &'a [AttributeChange],
    /// The event time as a Unix timestamp in seconds.
    occurred_at: i64,
    /// The request or workflow correlation id.
    correlation_id: &'a str,
    /// The id of the event that caused this change.
    causation_id: Option<&'a str>,
    /// The action parameters from the rule.
    params: &'a serde_json::Value,
}

/// The stored payload of one webhook job.
#[derive(Debug, Serialize, Deserialize)]
struct WebhookJobPayload {
    /// The target URL.
    url: String,
    /// The request body.
    body: serde_json::Value,
}

/// One parsed allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowedHost {
    /// The host in lowercase, without brackets.
    host: String,
    /// The optional port. `None` matches any port.
    port: Option<u16>,
}

/// Sends one webhook request.
///
/// The call signs the exact body bytes when a secret exists.
/// It returns an error for any status that is not 2xx.
async fn send_webhook(
    client: &reqwest::Client,
    url: Url,
    body: &[u8],
    event_id: &str,
    rule_id: &str,
    signing_secret: Option<&[u8]>,
) -> Result<(), anyhow::Error> {
    let mut request = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Event-Id", event_id)
        .header("X-Rule-Id", rule_id)
        .header(reqwest::header::USER_AGENT, "rust-api-eav")
        .body(body.to_vec());
    if let Some(secret) = signing_secret {
        request = request.header("X-Signature", signature_header(secret, body)?);
    }
    let response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("webhook request failed"))?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "webhook returned status {}",
            response.status().as_u16()
        ));
    }
    Ok(())
}

/// Signs one body with HMAC-SHA256.
///
/// The call returns the `sha256=<hex>` header value.
fn signature_header(secret: &[u8], body: &[u8]) -> Result<String, anyhow::Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|_| anyhow::anyhow!("webhook signing secret is not valid"))?;
    mac.update(body);
    let bytes = mac.finalize().into_bytes();
    let mut header = String::with_capacity(7 + bytes.len() * 2);
    header.push_str("sha256=");
    for byte in bytes.iter() {
        use std::fmt::Write as _;
        let _ = write!(header, "{byte:02x}");
    }
    Ok(header)
}

/// Checks one URL against the allowlist.
///
/// The call accepts `http` and `https`.
/// It accepts `http` only for a loopback host in the allowlist.
/// It rejects user information, a missing host, a fragment, a long URL,
/// and a host that is not in the allowlist.
fn validate_url(url: &Url, allowed_hosts: &[AllowedHost]) -> Result<(), anyhow::Error> {
    if url.scheme() != "http" && url.scheme() != "https" {
        bail!("webhook URL must use http or https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("webhook URL must not contain user information");
    }
    let Some(host) = url.host_str() else {
        bail!("webhook URL has no host");
    };
    if url.fragment().is_some() {
        bail!("webhook URL must not contain a fragment");
    }
    let host = normalize_host(host);
    if url.scheme() == "http" && !is_loopback(&host) {
        bail!("webhook URL must use https for this host");
    }
    if !allows(allowed_hosts, &host, url.port_or_known_default()) {
        bail!("webhook host is not allowed");
    }
    Ok(())
}

/// Returns true when the URL host and port are in the allowlist.
fn allows(allowed_hosts: &[AllowedHost], host: &str, port: Option<u16>) -> bool {
    let host = normalize_host(host);
    allowed_hosts.iter().any(|allowed| {
        allowed.host == host
            && match allowed.port {
                None => true,
                Some(expected) => port == Some(expected),
            }
    })
}

/// Parses one allowlist entry as a host or a `host:port` pair.
///
/// The call returns `None` for an empty or malformed entry.
fn parse_allowed_host(entry: &str) -> Option<AllowedHost> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let (host, port) = if let Some(rest) = entry.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let tail = &rest[close + 1..];
        if tail.is_empty() {
            (host.to_string(), None)
        } else {
            (
                host.to_string(),
                Some(tail.strip_prefix(':')?.parse().ok()?),
            )
        }
    } else if entry.matches(':').count() > 1 {
        (entry.to_string(), None)
    } else if let Some((host, port)) = entry.rsplit_once(':') {
        (host.to_string(), Some(port.parse().ok()?))
    } else {
        (entry.to_string(), None)
    };
    if host.is_empty() {
        return None;
    }
    Some(AllowedHost {
        host: normalize_host(&host),
        port,
    })
}

/// Returns the host in lowercase, without IPv6 brackets.
fn normalize_host(host: &str) -> String {
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    host.to_ascii_lowercase()
}

/// Returns true for a loopback host.
fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Reads the `url` string from one params object.
fn url_from_params(params: &serde_json::Value) -> Result<Url, anyhow::Error> {
    let object = params
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("webhook action parameters must be an object"))?;
    let raw = object
        .get("url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("webhook action requires a url string"))?;
    if raw.len() > MAX_URL_BYTES {
        bail!("webhook URL is longer than 2048 bytes");
    }
    Url::parse(raw).map_err(|_| anyhow::anyhow!("webhook URL is not valid"))
}

/// Builds the shared HTTP client with a timeout and no redirects.
#[allow(clippy::expect_used)]
fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("webhook HTTP client must build")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::EntityStore;
    use crate::eav::schema::SchemaRegistry;
    use crate::queue::{JobQueue, MemoryQueue};
    use crate::records::{AttributeChange, EntityEvent};
    use crate::rules::engine::RuleEngine;
    use crate::rules::rule::{ActionRef, Condition, Rule, RuleTrigger};
    use crate::rules::store::RuleStore;

    /// Builds one action context for the tests.
    fn context(params: serde_json::Value, event_id: &str) -> ActionContext {
        ActionContext {
            rule: Rule {
                id: "alpha".to_string(),
                version: 1,
                name: "alpha".to_string(),
                enabled: true,
                priority: 0,
                trigger: RuleTrigger {
                    events: vec![EntityEventKind::Created],
                    schemas: vec!["invoice".to_string()],
                },
                condition: Condition::Always,
                action: ActionRef {
                    kind: "webhook".to_string(),
                    params: params.clone(),
                },
                created_at: 0,
                updated_at: 0,
            },
            event: EntityEvent {
                event_id: event_id.to_string(),
                entity_id: "e1".to_string(),
                entity_version: 3,
                kind: EntityEventKind::Updated,
                schemas: vec!["invoice".to_string()],
                changed: vec![AttributeChange {
                    key: "total".to_string(),
                    old: Some(json!(10)),
                    new: Some(json!(20)),
                }],
                actor: "tester".to_string(),
                causation_id: Some("cause-1".to_string()),
                causation_depth: 1,
                correlation_id: "req-1".to_string(),
                snapshot: None,
                occurred_at: 42,
            },
            entity: None,
            params,
        }
    }

    /// Builds an engine with one webhook action.
    async fn engine_with(action: WebhookAction) -> RuleEngine {
        let raw = build_test_store(&test_prefix("rules-webhook")).await;
        let schema = build_test_store(&test_prefix("rules-webhook-schema")).await;
        RuleEngine::new(
            RuleStore::new(raw.clone()),
            EntityStore::new(raw, SchemaRegistry::new(schema)),
            vec![Arc::new(action)],
        )
        .expect("webhook action kind is valid")
    }

    /// Returns a fixed signing secret for the tests.
    fn secret() -> Vec<u8> {
        b"0123456789abcdef0123456789abcdef".to_vec()
    }

    #[test]
    fn validate_rejects_bad_parameters() {
        let action = WebhookAction::new(vec!["example.com".to_string()]);
        let long_url = format!("https://example.com/{}", "a".repeat(MAX_URL_BYTES));
        let cases = [
            json!({}),
            json!("not an object"),
            json!({"url": 42}),
            json!({"url": "ftp://example.com/hook"}),
            json!({"url": "https://user:pass@example.com/hook"}),
            json!({"url": "https://example.com/hook#frag"}),
            json!({"url": "https:///hook"}),
            json!({"url": "https://evil.example/hook"}),
            json!({"url": "http://example.com/hook"}),
            json!({"url": long_url}),
        ];
        for params in cases {
            assert!(action.validate(&params).is_err(), "{params}");
        }
    }

    #[test]
    fn validate_accepts_allowed_hosts_and_loopback_http() {
        let action = WebhookAction::new(vec![
            "example.com".to_string(),
            "api.example.com:8443".to_string(),
            "127.0.0.1".to_string(),
        ]);
        for params in [
            json!({"url": "https://example.com/hook"}),
            json!({"url": "https://example.com:9443/hook"}),
            json!({"url": "https://api.example.com:8443/hook"}),
            json!({"url": "http://127.0.0.1:8080/hook"}),
        ] {
            assert!(action.validate(&params).is_ok(), "{params}");
        }
    }

    #[test]
    fn validate_rejects_a_port_that_is_not_in_the_allowlist() {
        let action = WebhookAction::new(vec!["example.com:8443".to_string()]);

        assert!(
            action
                .validate(&json!({"url": "https://example.com:9443/hook"}))
                .is_err()
        );
    }

    #[test]
    fn validate_matches_the_effective_port() {
        let default_https = WebhookAction::new(vec!["example.com:443".to_string()]);
        assert!(
            default_https
                .validate(&json!({"url": "https://example.com/hook"}))
                .is_ok()
        );

        let other_https = WebhookAction::new(vec!["example.com:8443".to_string()]);
        assert!(
            other_https
                .validate(&json!({"url": "https://example.com/hook"}))
                .is_err()
        );

        let default_http = WebhookAction::new(vec!["127.0.0.1:80".to_string()]);
        assert!(
            default_http
                .validate(&json!({"url": "http://127.0.0.1/hook"}))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn execute_posts_the_safe_payload_and_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let action = WebhookAction::new(vec![server.address().to_string()]);
        let params = json!({"url": format!("{}/hook", server.uri())});

        action.execute(context(params, "evt-1")).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        let content_type = request
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(content_type.starts_with("application/json"));
        assert_eq!(
            request
                .headers
                .get("x-event-id")
                .and_then(|value| value.to_str().ok()),
            Some("evt-1")
        );
        assert_eq!(
            request
                .headers
                .get("x-rule-id")
                .and_then(|value| value.to_str().ok()),
            Some("alpha")
        );
        assert_eq!(
            request
                .headers
                .get("user-agent")
                .and_then(|value| value.to_str().ok()),
            Some("rust-api-eav")
        );
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["rule_id"], "alpha");
        assert_eq!(body["event_id"], "evt-1");
        assert_eq!(body["entity_id"], "e1");
        assert_eq!(body["entity_version"], 3);
        assert_eq!(body["kind"], "Updated");
        assert_eq!(body["schemas"][0], "invoice");
        assert_eq!(body["changed"][0]["key"], "total");
        assert_eq!(body["occurred_at"], 42);
        assert_eq!(body["correlation_id"], "req-1");
        assert_eq!(body["causation_id"], "cause-1");
        assert_eq!(body["params"]["url"], format!("{}/hook", server.uri()));
        assert!(body.get("snapshot").is_none());
    }

    #[tokio::test]
    async fn execute_rejects_a_500_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let action = WebhookAction::new(vec![server.address().to_string()]);
        let params = json!({"url": format!("{}/hook", server.uri())});

        assert!(action.execute(context(params, "evt-1")).await.is_err());
    }

    #[tokio::test]
    async fn execute_rejects_a_redirect_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/next"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/next"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let action = WebhookAction::new(vec![server.address().to_string()]);
        let params = json!({"url": format!("{}/hook", server.uri())});

        assert!(action.execute(context(params, "evt-1")).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_engine_rejects_a_bad_webhook_and_accepts_a_good_one() {
        let engine = engine_with(WebhookAction::new(vec!["example.com".to_string()])).await;

        let bad = engine.validate_action("webhook", &json!({"url": "https://evil.example/hook"}));
        assert!(matches!(
            bad,
            Err(crate::rules::error::RuleError::Invalid(_))
        ));

        let good = engine.validate_action("webhook", &json!({"url": "https://example.com/hook"}));
        assert!(good.is_ok());
    }

    #[tokio::test]
    async fn the_queue_action_enqueues_one_job_with_the_expected_fields() {
        let queue = Arc::new(MemoryQueue::new());
        let action = WebhookAction::new(vec!["example.com".to_string()]).with_queue(
            queue.clone(),
            Some(secret()),
            7,
        );
        let params = json!({"url": "https://example.com/hook"});

        action.execute(context(params, "evt-1")).await.unwrap();

        let leased = queue
            .reserve("test", 10, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(leased.len(), 1);
        let job = &leased[0].job;
        assert_eq!(job.kind, JOB_KIND);
        assert_eq!(job.priority, 0);
        assert_eq!(job.attempt, 0);
        assert_eq!(job.max_attempts, 7);
        assert_eq!(job.idempotency_key.as_deref(), Some("webhook:alpha:evt-1"));
        let envelope: WebhookJobPayload = serde_json::from_slice(&job.payload).unwrap();
        assert_eq!(envelope.url, "https://example.com/hook");
        assert_eq!(envelope.body["event_id"], "evt-1");
        assert_eq!(envelope.body["rule_id"], "alpha");
        assert!(envelope.body.get("snapshot").is_none());
    }

    #[tokio::test]
    async fn a_second_enqueue_of_the_same_event_keeps_one_job() {
        let queue = Arc::new(MemoryQueue::new());
        let action =
            WebhookAction::new(vec!["example.com".to_string()]).with_queue(queue.clone(), None, 5);
        let params = json!({"url": "https://example.com/hook"});

        action
            .execute(context(params.clone(), "evt-1"))
            .await
            .unwrap();
        action.execute(context(params, "evt-1")).await.unwrap();

        let leased = queue
            .reserve("test", 10, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(
            leased[0].job.idempotency_key.as_deref(),
            Some("webhook:alpha:evt-1")
        );
    }

    #[tokio::test]
    async fn the_handler_posts_the_body_and_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let queue = Arc::new(MemoryQueue::new());
        let action = WebhookAction::new(vec![server.address().to_string()]).with_queue(
            queue.clone(),
            Some(secret()),
            5,
        );
        let params = json!({"url": format!("{}/hook", server.uri())});
        action.execute(context(params, "evt-1")).await.unwrap();
        let handler = action.job_handler();
        let leased = queue
            .reserve("test", 10, Duration::from_secs(30))
            .await
            .unwrap();

        handler.handle(&leased[0].job).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(
            request
                .headers
                .get("x-event-id")
                .and_then(|value| value.to_str().ok()),
            Some("evt-1")
        );
        assert_eq!(
            request
                .headers
                .get("x-rule-id")
                .and_then(|value| value.to_str().ok()),
            Some("alpha")
        );
        assert_eq!(
            request
                .headers
                .get("user-agent")
                .and_then(|value| value.to_str().ok()),
            Some("rust-api-eav")
        );
        let expected = signature_header(&secret(), &request.body).unwrap();
        assert_eq!(
            request
                .headers
                .get("x-signature")
                .and_then(|value| value.to_str().ok()),
            Some(expected.as_str())
        );
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["rule_id"], "alpha");
        assert_eq!(body["event_id"], "evt-1");
        assert_eq!(body["entity_id"], "e1");
        assert_eq!(body["params"]["url"], format!("{}/hook", server.uri()));
        assert!(body.get("snapshot").is_none());
    }

    #[tokio::test]
    async fn the_handler_rejects_a_500_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let queue = Arc::new(MemoryQueue::new());
        let action = WebhookAction::new(vec![server.address().to_string()]).with_queue(
            queue.clone(),
            None,
            5,
        );
        let params = json!({"url": format!("{}/hook", server.uri())});
        action.execute(context(params, "evt-1")).await.unwrap();
        let handler = action.job_handler();
        let leased = queue
            .reserve("test", 10, Duration::from_secs(30))
            .await
            .unwrap();

        assert!(handler.handle(&leased[0].job).await.is_err());
    }

    #[test]
    fn hmac_signing_matches_a_known_vector() {
        let header = signature_header(b"secret", b"body").unwrap();

        assert_eq!(
            header,
            "sha256=dc46983557fea127b43af721467eb9b3fde2338fe3e14f51952aa8478c13d355"
        );
    }
}
