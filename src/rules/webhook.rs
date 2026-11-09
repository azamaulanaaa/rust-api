//! An outbound webhook action.
//!
//! The action sends one JSON `POST` request for one rule event.
//! Delivery is at least once.
//! The `X-Event-Id` header lets the receiver deduplicate.
//! The action adds no business logic.
//!
//! A strict host allowlist limits the destinations.
//! The client follows no redirects.
//! The allowlist and the disabled redirects limit the destinations.
//! A compromised allowlisted host remains trusted.
//! The action cannot stop that host from reading the payload.

use std::time::Duration;

use anyhow::bail;
use async_trait::async_trait;
use serde::Serialize;
use url::Url;

use crate::records::{AttributeChange, EntityEventKind};
use crate::rules::action::{ActionContext, RuleAction};

/// The maximum length of a webhook URL in bytes.
const MAX_URL_BYTES: usize = 2048;

/// The request timeout in seconds.
const TIMEOUT_SECS: u64 = 10;

/// An action that posts one event to an allowlisted host.
///
/// The action builds one client with a 10 second timeout.
/// The client follows no redirects.
#[derive(Debug, Clone)]
pub struct WebhookAction {
    /// The parsed allowlist entries.
    allowed_hosts: Vec<AllowedHost>,
    /// The shared HTTP client.
    client: reqwest::Client,
}

impl WebhookAction {
    /// Creates the action from the allowed host entries.
    ///
    /// Each entry is a host or a `host:port` pair.
    /// An empty list rejects every webhook rule.
    pub fn new(allowed_hosts: Vec<String>) -> Self {
        let allowed_hosts = allowed_hosts
            .iter()
            .filter_map(|entry| parse_allowed_host(entry))
            .collect();
        Self {
            allowed_hosts,
            client: build_client(),
        }
    }

    /// Returns true when the URL host and port are in the allowlist.
    fn allows(&self, host: &str, port: Option<u16>) -> bool {
        let host = normalize_host(host);
        self.allowed_hosts.iter().any(|allowed| {
            allowed.host == host
                && match allowed.port {
                    None => true,
                    Some(expected) => port == Some(expected),
                }
        })
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
        if !self.allows(&host, url.port_or_known_default()) {
            bail!("webhook host is not allowed");
        }
        Ok(())
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
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-Event-Id", ctx.event.event_id.as_str())
            .header("X-Rule-Id", ctx.rule.id.as_str())
            .header(reqwest::header::USER_AGENT, "rust-api-eav")
            .json(&payload)
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

/// One parsed allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowedHost {
    /// The host in lowercase, without brackets.
    host: String,
    /// The optional port. `None` matches any port.
    port: Option<u16>,
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

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::EntityStore;
    use crate::eav::schema::SchemaRegistry;
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
}
