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
//! The action resolves the URL host before each request.
//! It rejects a host when any address is not global.
//! The rejected IPv4 ranges are the current network, loopback, private,
//! link-local, carrier-grade NAT, IETF assignment, 6to4 relay, benchmarking,
//! documentation, multicast, and reserved.
//! The rejected IPv6 ranges are loopback, unspecified, link-local,
//! unique-local, 6to4, Teredo, NAT64, benchmarking, documentation,
//! segment routing, discard-only, and ORCHID.
//! An operator can permit a private address with
//! `[eav].webhook_allow_private_hosts`.
//! Rule validation also rejects a URL that the delivery path would reject
//! for a static reason.
//! It checks a literal address and the scheme without a DNS lookup.
//! The action pins the resolved address to the HTTP client.
//! A second DNS answer cannot change the target.
//! The client disables system proxies. A proxy resolves the host itself, so a
//! proxy would bypass the pinned address.
//! The client keeps the original host name for TLS certificate validation.
//! The allowlist and the disabled redirects limit the destinations.
//! A compromised allowlisted host remains trusted.
//! The action cannot stop that host from reading the payload.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use url::Url;

use crate::eav::metrics::EavMetrics;
use crate::queue::{Job, JobError, JobHandler, JobQueue};
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

/// The maximum retry delay that a `Retry-After` header can set, in seconds.
const MAX_RETRY_AFTER_SECS: u64 = 3600;

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
/// The action builds one client for each request with a 10 second timeout.
/// The client follows no redirects.
/// The client uses only the address that the action resolved.
#[derive(Clone)]
pub struct WebhookAction {
    /// The parsed allowlist entries.
    allowed_hosts: Vec<AllowedHost>,
    /// The optional queue for durable delivery.
    queue: Option<Arc<dyn JobQueue>>,
    /// The optional HMAC-SHA256 signing secret.
    signing_secret: Option<Vec<u8>>,
    /// The maximum number of delivery attempts.
    max_attempts: u32,
    /// Allows delivery to a private address when true.
    allow_private_hosts: bool,
}

impl std::fmt::Debug for WebhookAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookAction")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("has_queue", &self.queue.is_some())
            .field("has_signing_secret", &self.signing_secret.is_some())
            .field("max_attempts", &self.max_attempts)
            .field("allow_private_hosts", &self.allow_private_hosts)
            .finish()
    }
}

impl WebhookAction {
    /// Creates the action from the allowed host entries.
    ///
    /// Each entry is a host or a `host:port` pair.
    /// A host entry matches only the default port of the URL scheme.
    /// An empty list rejects every webhook rule.
    /// The direct mode uses no queue and no signing secret.
    /// The action rejects a private address by default.
    pub fn new(allowed_hosts: Vec<String>) -> Self {
        let allowed_hosts = allowed_hosts
            .iter()
            .filter_map(|entry| parse_allowed_host(entry))
            .collect();
        Self {
            allowed_hosts,
            queue: None,
            signing_secret: None,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            allow_private_hosts: false,
        }
    }

    /// Sets whether a private address is allowed.
    ///
    /// The action resolves and pins the address in both modes.
    /// The value `true` preserves an intentional internal webhook.
    pub fn allow_private_hosts(mut self, allow: bool) -> Self {
        self.allow_private_hosts = allow;
        self
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
    /// The handler holds the allowlist, the private-address flag, and the
    /// signing secret.
    pub fn job_handler(&self) -> WebhookJobHandler {
        WebhookJobHandler::new(self.signing_secret.clone(), self.allow_private_hosts)
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
    /// a non-public literal address, and a host that is not in the allowlist.
    /// It does not resolve the host.
    fn validate(&self, params: &serde_json::Value) -> Result<(), anyhow::Error> {
        let url = url_from_params(params)?;
        validate_url(&url, &self.allowed_hosts, self.allow_private_hosts)
    }

    async fn execute(&self, ctx: ActionContext) -> Result<(), anyhow::Error> {
        let url = url_from_params(&ctx.params)?;
        // The delivery path applies the address policy.
        // This early check keeps the scheme and the allowlist rules.
        validate_url(&url, &self.allowed_hosts, true)?;
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
                url,
                &body,
                ctx.event.event_id.as_str(),
                ctx.rule.id.as_str(),
                self.signing_secret.as_deref(),
                self.allow_private_hosts,
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
/// The handler holds the allowlist, the private-address flag, and the signing
/// secret.
#[derive(Clone)]
pub struct WebhookJobHandler {
    /// The parsed allowlist entries.
    allowed_hosts: Vec<AllowedHost>,
    /// The optional HMAC-SHA256 signing secret.
    signing_secret: Option<Vec<u8>>,
    /// Allows delivery to a private address when true.
    allow_private_hosts: bool,
}

impl WebhookJobHandler {
    /// Creates a handler from the signing secret and the private-address flag.
    ///
    /// The handler starts with an empty allowlist.
    /// Use [`WebhookAction::job_handler`](crate::rules::webhook::WebhookAction::job_handler) to add allowlist entries.
    pub fn new(signing_secret: Option<Vec<u8>>, allow_private_hosts: bool) -> Self {
        Self {
            allowed_hosts: Vec::new(),
            signing_secret,
            allow_private_hosts,
        }
    }

    /// Adds the parsed allowlist entries.
    ///
    /// Each entry is a host or a `host:port` pair.
    /// A host entry matches only the default port of the URL scheme.
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
        validate_url(&url, &self.allowed_hosts, self.allow_private_hosts)?;
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
            url,
            &body,
            event_id,
            rule_id,
            self.signing_secret.as_deref(),
            self.allow_private_hosts,
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
    /// The optional port.
    ///
    /// `None` matches only the default port of the URL scheme.
    /// `Some` matches only that port.
    port: Option<u16>,
}

/// Sends one webhook request.
///
/// The call resolves the URL host and pins the resolved address to a new
/// client.
/// It rejects the request when any address is not public, unless the caller
/// allows a private host.
/// It signs the exact body bytes when a secret exists.
/// It returns a permanent [`JobError`] for a non-retryable status.
/// It returns a retryable [`JobError`] for a temporary status.
async fn send_webhook(
    url: Url,
    body: &[u8],
    event_id: &str,
    rule_id: &str,
    signing_secret: Option<&[u8]>,
    allow_private_hosts: bool,
) -> Result<(), anyhow::Error> {
    let client = build_pinned_client(&url, allow_private_hosts).await?;
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
        let status = response.status();
        let retry_after = retry_after(&response);
        return Err(classify_response(status, retry_after).into());
    }
    Ok(())
}

/// Returns the retry decision for one non-2xx response.
///
/// The call retries `408`, `425`, `429`, and `503`.
/// A retry for `429` or `503` uses the `Retry-After` delay when it exists.
/// The call retries every other `5xx` status.
/// The call does not retry every other status.
fn classify_response(status: reqwest::StatusCode, retry_after: Option<Duration>) -> JobError {
    let message = format!("webhook returned status {}", status.as_u16());
    match status.as_u16() {
        429 | 503 => match retry_after {
            Some(delay) => JobError::retry_after(message, delay),
            None => JobError::retryable(message),
        },
        408 | 425 => JobError::retryable(message),
        code if (500..600).contains(&code) => JobError::retryable(message),
        _ => JobError::permanent(message),
    }
}

/// Reads the `Retry-After` header as a delay.
///
/// The call accepts the delta-seconds form and the HTTP-date form.
/// It caps the delay at [`MAX_RETRY_AFTER_SECS`].
/// It returns `None` for a missing or an invalid value.
fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    let value = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?;
    parse_retry_after(value)
}

/// Parses one `Retry-After` value as a delay.
///
/// The call accepts the delta-seconds form and the HTTP-date form.
/// It caps the delay at [`MAX_RETRY_AFTER_SECS`].
/// It returns `None` for an invalid value.
fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    let seconds = match value.parse::<u64>() {
        Ok(seconds) => seconds,
        Err(_) => {
            let date = chrono::DateTime::parse_from_rfc2822(value).ok()?;
            let now = chrono::Utc::now().timestamp();
            date.timestamp().saturating_sub(now).max(0) as u64
        }
    };
    Some(Duration::from_secs(seconds.min(MAX_RETRY_AFTER_SECS)))
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
/// a non-public literal address, and a host that is not in the allowlist.
/// The call does not resolve the host. It stays offline and synchronous.
fn validate_url(
    url: &Url,
    allowed_hosts: &[AllowedHost],
    allow_private_hosts: bool,
) -> Result<(), anyhow::Error> {
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
    if let Ok(address) = host.parse::<IpAddr>()
        && !allow_private_hosts
        && !is_public_ip(address)
    {
        bail!("webhook URL must not target a private address or another non-public address");
    }
    if url.scheme() == "http" && !is_loopback(&host) {
        bail!("webhook URL must use https for this host");
    }
    if !allows(
        allowed_hosts,
        &host,
        url.port_or_known_default(),
        url.scheme(),
    ) {
        bail!("webhook host is not allowed");
    }
    Ok(())
}

/// Returns true when the URL host and port are in the allowlist.
///
/// An entry with no port matches only the default port of `scheme`.
fn allows(allowed_hosts: &[AllowedHost], host: &str, port: Option<u16>, scheme: &str) -> bool {
    let host = normalize_host(host);
    let default_port = default_port_for_scheme(scheme);
    allowed_hosts.iter().any(|allowed| {
        allowed.host == host
            && match allowed.port {
                None => port == default_port,
                Some(expected) => port == Some(expected),
            }
    })
}

/// Returns the default port for one URL scheme.
fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
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

/// Builds a client that sends every request to one resolved address.
///
/// The call resolves the URL host with the URL port.
/// It rejects a non-public address unless `allow_private_hosts` is true.
/// It pins every resolved address to the host name in the client.
/// The URL keeps the original host name, so TLS certificate validation still
/// uses that name.
async fn build_pinned_client(
    url: &Url,
    allow_private_hosts: bool,
) -> Result<reqwest::Client, anyhow::Error> {
    let (host, addresses) = resolve_webhook_target(url, allow_private_hosts).await?;
    Ok(build_client(&host, &addresses))
}

/// Resolves one webhook URL to a host and socket addresses.
///
/// The lookup includes the URL port.
/// The call rejects the URL when any address is not public, unless
/// `allow_private_hosts` is true.
async fn resolve_webhook_target(
    url: &Url,
    allow_private_hosts: bool,
) -> Result<(String, Vec<SocketAddr>), anyhow::Error> {
    let Some(raw_host) = url.host_str() else {
        bail!("webhook URL has no host");
    };
    let host = normalize_host(raw_host);
    let Some(port) = url.port_or_known_default() else {
        bail!("webhook URL has no port");
    };
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|_| anyhow::anyhow!("webhook host does not resolve"))?
        .collect();
    if addresses.is_empty() {
        bail!("webhook host does not resolve");
    }
    if !allow_private_hosts && addresses.iter().any(|address| !is_public_ip(address.ip())) {
        bail!("webhook host resolves to a private address");
    }
    Ok((host, addresses))
}

/// Builds one HTTP client with a timeout, no redirects, and pinned addresses.
///
/// The call disables system proxies.
/// A system proxy resolves the host itself, so it bypasses the pinned address.
/// The pinned address must stay the only target of the client.
#[allow(clippy::expect_used)]
fn build_client(host: &str, addresses: &[SocketAddr]) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        // Disable system proxies. Reqwest enables them by default, and a proxy
        // resolves the host itself. A proxy thus bypasses the pinned address.
        .no_proxy()
        .resolve_to_addrs(host, addresses)
        .build()
        .expect("webhook HTTP client must build")
}

/// Returns true when one address is global.
///
/// The call checks an IPv4-mapped IPv6 address as an IPv4 address.
/// It rejects every network in the two tables below.
fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_ipv4(mapped);
            }
            is_public_ipv6(address)
        }
    }
}

/// The IPv4 networks that are not global.
const NON_GLOBAL_IPV4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),  // 0.0.0.0/8 is the current network.
    (Ipv4Addr::new(10, 0, 0, 0), 8), // 10.0.0.0/8 is private.
    (Ipv4Addr::new(100, 64, 0, 0), 10), // 100.64.0.0/10 is carrier-grade NAT.
    (Ipv4Addr::new(127, 0, 0, 0), 8), // 127.0.0.0/8 is loopback.
    (Ipv4Addr::new(169, 254, 0, 0), 16), // 169.254.0.0/16 is link-local.
    (Ipv4Addr::new(172, 16, 0, 0), 12), // 172.16.0.0/12 is private.
    (Ipv4Addr::new(192, 0, 0, 0), 24), // 192.0.0.0/24 is an IETF assignment.
    (Ipv4Addr::new(192, 0, 2, 0), 24), // 192.0.2.0/24 is TEST-NET-1.
    (Ipv4Addr::new(192, 88, 99, 0), 24), // 192.88.99.0/24 is a 6to4 relay.
    (Ipv4Addr::new(192, 168, 0, 0), 16), // 192.168.0.0/16 is private.
    (Ipv4Addr::new(198, 18, 0, 0), 15), // 198.18.0.0/15 is benchmarking.
    (Ipv4Addr::new(198, 51, 100, 0), 24), // 198.51.100.0/24 is TEST-NET-2.
    (Ipv4Addr::new(203, 0, 113, 0), 24), // 203.0.113.0/24 is TEST-NET-3.
    (Ipv4Addr::new(224, 0, 0, 0), 4), // 224.0.0.0/4 is multicast.
    (Ipv4Addr::new(240, 0, 0, 0), 4), // 240.0.0.0/4 is reserved.
];

/// Returns true when one IPv4 address is global.
///
/// The call rejects every network in [`NON_GLOBAL_IPV4`].
fn is_public_ipv4(address: Ipv4Addr) -> bool {
    !NON_GLOBAL_IPV4
        .iter()
        .any(|(network, prefix)| in_ipv4_network(address, *network, *prefix))
}

/// Returns true when one IPv4 address is in one network.
fn in_ipv4_network(address: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    (u32::from(address) & mask) == (u32::from(network) & mask)
}

/// The IPv6 networks that are not global.
const NON_GLOBAL_IPV6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 128), // ::/128 is unspecified.
    (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128), // ::1/128 is loopback.
    (Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96), // 64:ff9b::/96 is NAT64.
    (Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0), 48), // 64:ff9b:1::/48 is local NAT64.
    (Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64), // 100::/64 is discard-only.
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32), // 2001::/32 is Teredo.
    (Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0), 48), // 2001:2::/48 is benchmarking.
    (Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0), 28), // 2001:10::/28 is ORCHIDv1.
    (Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0), 28), // 2001:20::/28 is ORCHIDv2.
    (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32), // 2001:db8::/32 is documentation.
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16), // 2002::/16 is 6to4.
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20), // 3fff::/20 is documentation.
    (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16), // 5f00::/16 is segment routing.
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7), // fc00::/7 is unique-local.
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10), // fe80::/10 is link-local.
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8), // ff00::/8 is multicast.
];

/// Returns true when one IPv6 address is global.
///
/// The call rejects every network in [`NON_GLOBAL_IPV6`].
fn is_public_ipv6(address: Ipv6Addr) -> bool {
    !NON_GLOBAL_IPV6
        .iter()
        .any(|(network, prefix)| in_ipv6_network(address, *network, *prefix))
}

/// Returns true when one IPv6 address is in one network.
fn in_ipv6_network(address: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - u32::from(prefix));
    (u128::from(address) & mask) == (u128::from(network) & mask)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::Ipv6Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;
    use tokio_util::sync::CancellationToken;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::EntityStore;
    use crate::eav::schema::SchemaRegistry;
    use crate::queue::{JobQueue, JobStatus, MemoryQueue, QueueWorker};
    use crate::records::{AttributeChange, EntityEvent};
    use crate::rules::engine::RuleEngine;
    use crate::rules::rule::{ActionRef, Condition, Rule, RuleCapabilities, RuleTrigger};
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
                capabilities: RuleCapabilities::default(),
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

    /// Builds one queued webhook job for a test server.
    fn webhook_job(server: &MockServer) -> Job {
        let envelope = WebhookJobPayload {
            url: format!("{}/hook", server.uri()),
            body: json!({"event_id": "evt-1", "rule_id": "alpha"}),
        };
        Job {
            id: uuid::Uuid::now_v7(),
            kind: JOB_KIND.to_string(),
            payload: serde_json::to_vec(&envelope).unwrap(),
            priority: 0,
            attempt: 0,
            max_attempts: 5,
            created_at: 0,
            scheduled_at: 0,
            idempotency_key: None,
            headers: BTreeMap::new(),
        }
    }

    /// Starts one worker for the webhook handler.
    fn start_worker(
        queue: Arc<MemoryQueue>,
        handler: WebhookJobHandler,
    ) -> (CancellationToken, tokio::task::JoinHandle<()>) {
        let worker = QueueWorker::new(
            queue as Arc<dyn JobQueue>,
            vec![Arc::new(handler) as Arc<dyn JobHandler>],
            "worker-1".to_string(),
        )
        .with_poll_interval(Duration::from_millis(1))
        .with_retry_base(Duration::from_secs(60))
        .with_retry_max(Duration::from_secs(60));
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let handle = tokio::spawn(async move { worker.run(token).await });
        (cancel, handle)
    }

    /// Waits until the mock server receives `count` requests.
    async fn wait_for_requests(server: &MockServer, count: usize) {
        for _ in 0..2000 {
            if server.received_requests().await.unwrap().len() >= count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("the mock server did not receive {count} requests");
    }

    /// Waits until a job reaches the expected status.
    async fn wait_for_status<F>(queue: &MemoryQueue, id: uuid::Uuid, ready: F) -> JobStatus
    where
        F: Fn(&JobStatus) -> bool,
    {
        for _ in 0..2000 {
            let status = queue.status(id).await.unwrap();
            if ready(&status) {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("the job did not reach the expected status");
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
            "127.0.0.1:8080".to_string(),
        ])
        .allow_private_hosts(true);
        for params in [
            json!({"url": "https://example.com/hook"}),
            json!({"url": "https://api.example.com:8443/hook"}),
            json!({"url": "http://127.0.0.1:8080/hook"}),
        ] {
            assert!(action.validate(&params).is_ok(), "{params}");
        }
    }

    #[test]
    fn a_host_entry_matches_only_the_default_port() {
        let cases = [
            ("example.com", "https://example.com/hook", true),
            ("example.com", "https://example.com:443/hook", true),
            ("example.com", "https://example.com:8443/hook", false),
            ("127.0.0.1", "http://127.0.0.1/hook", true),
            ("127.0.0.1", "http://127.0.0.1:8080/hook", false),
            ("127.0.0.1", "https://127.0.0.1/hook", true),
            ("127.0.0.1:8080", "http://127.0.0.1:8080/hook", true),
            ("127.0.0.1:8080", "http://127.0.0.1/hook", false),
        ];
        for (entry, url, expected) in cases {
            let action = WebhookAction::new(vec![entry.to_string()]).allow_private_hosts(true);
            let result = action.validate(&json!({ "url": url }));
            assert_eq!(
                result.is_ok(),
                expected,
                "entry {entry} and url {url}: {result:?}"
            );
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

        let default_http =
            WebhookAction::new(vec!["127.0.0.1:80".to_string()]).allow_private_hosts(true);
        assert!(
            default_http
                .validate(&json!({"url": "http://127.0.0.1/hook"}))
                .is_ok()
        );
    }

    #[test]
    fn validate_rejects_a_loopback_url_when_private_hosts_are_disallowed() {
        let denied = WebhookAction::new(vec!["127.0.0.1".to_string()]);
        let error = denied
            .validate(&json!({"url": "http://127.0.0.1/hook"}))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "webhook URL must not target a private address or another non-public address"
        );

        let allowed = WebhookAction::new(vec!["127.0.0.1".to_string()]).allow_private_hosts(true);
        assert!(
            allowed
                .validate(&json!({"url": "http://127.0.0.1/hook"}))
                .is_ok()
        );
    }

    #[test]
    fn validate_requires_https_for_a_non_loopback_host() {
        let action = WebhookAction::new(vec!["example.com".to_string()]);

        assert!(
            action
                .validate(&json!({"url": "http://example.com/hook"}))
                .is_err()
        );
        assert!(
            action
                .validate(&json!({"url": "https://example.com/hook"}))
                .is_ok()
        );
    }

    #[test]
    fn validate_rejects_a_private_literal_when_private_hosts_are_disallowed() {
        let denied = WebhookAction::new(vec!["10.0.0.1".to_string()]);
        let error = denied
            .validate(&json!({"url": "https://10.0.0.1/hook"}))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "webhook URL must not target a private address or another non-public address"
        );

        let allowed = WebhookAction::new(vec!["10.0.0.1".to_string()]).allow_private_hosts(true);
        assert!(
            allowed
                .validate(&json!({"url": "https://10.0.0.1/hook"}))
                .is_ok()
        );
    }

    #[test]
    fn the_address_classifier_rejects_non_public_addresses() {
        let rejected_ipv4 = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
        ];
        for raw in rejected_ipv4 {
            let address: Ipv4Addr = raw.parse().unwrap();
            assert!(!is_public_ip(address.into()), "{raw}");
        }

        let rejected_ipv6 = ["::1", "::", "fc00::1", "fe80::1", "ff02::1"];
        for raw in rejected_ipv6 {
            let address: Ipv6Addr = raw.parse().unwrap();
            assert!(!is_public_ip(address.into()), "{raw}");
        }
    }

    #[test]
    fn the_address_classifier_rejects_new_non_global_ipv4_ranges() {
        let rejected_ipv4 = [
            "0.0.0.1",       // Current network.
            "0.255.255.255", // Current network.
            "100.64.0.1",    // Carrier-grade NAT.
            "192.0.0.1",     // IETF assignment.
            "192.88.99.1",   // 6to4 relay.
            "198.18.0.1",    // Benchmarking.
            "192.0.2.1",     // Documentation.
            "198.51.100.1",  // Documentation.
            "203.0.113.1",   // Documentation.
            "240.0.0.1",     // Reserved.
        ];
        for raw in rejected_ipv4 {
            let address: Ipv4Addr = raw.parse().unwrap();
            assert!(!is_public_ip(address.into()), "{raw}");
        }
    }

    #[test]
    fn the_address_classifier_rejects_new_non_global_ipv6_ranges() {
        let rejected_ipv6 = [
            "2002::1",      // 6to4.
            "2001::1",      // Teredo.
            "64:ff9b::1",   // NAT64.
            "64:ff9b:1::1", // Local NAT64.
            "2001:db8::1",  // Documentation.
            "100::1",       // Discard-only.
            "2001:10::1",   // ORCHIDv1.
            "2001:20::1",   // ORCHIDv2.
            "2001:2::1",    // Benchmarking.
            "3fff::1",      // Documentation.
            "5f00::1",      // Segment routing.
        ];
        for raw in rejected_ipv6 {
            let address: Ipv6Addr = raw.parse().unwrap();
            assert!(!is_public_ip(address.into()), "{raw}");
        }
    }

    #[test]
    fn the_address_classifier_accepts_addresses_next_to_the_ranges() {
        for raw in ["1.0.0.0", "8.8.8.8", "1.1.1.1"] {
            let address: Ipv4Addr = raw.parse().unwrap();
            assert!(is_public_ip(address.into()), "{raw}");
        }

        for raw in [
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "4000::1",
            "6000::1",
        ] {
            let address: Ipv6Addr = raw.parse().unwrap();
            assert!(is_public_ip(address.into()), "{raw}");
        }
    }

    #[test]
    fn the_address_classifier_accepts_public_addresses() {
        for raw in ["8.8.8.8", "1.1.1.1"] {
            let address: Ipv4Addr = raw.parse().unwrap();
            assert!(is_public_ip(address.into()), "{raw}");
        }

        for raw in ["2001:4860:4860::8888", "2606:4700:4700::1111"] {
            let address: Ipv6Addr = raw.parse().unwrap();
            assert!(is_public_ip(address.into()), "{raw}");
        }
    }

    #[test]
    fn an_ipv4_mapped_private_address_is_rejected() {
        let address: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(!is_public_ip(address.into()));

        let address: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(!is_public_ip(address.into()));

        let address: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(is_public_ip(address.into()));
    }

    #[tokio::test]
    async fn the_resolver_keeps_the_url_host_and_port() {
        let url = Url::parse("http://127.0.0.1:8080/hook").unwrap();

        let (host, addresses) = resolve_webhook_target(&url, true).await.unwrap();

        assert_eq!(host, "127.0.0.1");
        assert!(addresses.contains(&"127.0.0.1:8080".parse().unwrap()));
    }

    #[tokio::test]
    async fn the_resolver_rejects_a_private_address_by_default() {
        let url = Url::parse("http://127.0.0.1:8080/hook").unwrap();

        let error = resolve_webhook_target(&url, false).await.unwrap_err();

        assert!(error.to_string().contains("private address"), "{error}");
    }

    #[tokio::test]
    async fn execute_rejects_a_private_address_by_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let action = WebhookAction::new(vec![server.address().to_string()]);
        let params = json!({"url": format!("{}/hook", server.uri())});

        let error = action.execute(context(params, "evt-1")).await.unwrap_err();

        assert!(error.to_string().contains("private address"), "{error}");
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn execute_accepts_a_private_address_when_allowed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let action =
            WebhookAction::new(vec![server.address().to_string()]).allow_private_hosts(true);
        let params = json!({"url": format!("{}/hook", server.uri())});

        action.execute(context(params, "evt-1")).await.unwrap();

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_handler_rejects_a_private_address_by_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
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

        let error = handler.handle(&leased[0].job).await.unwrap_err();

        assert!(error.to_string().contains("private address"), "{error}");
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn execute_posts_the_safe_payload_and_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let action =
            WebhookAction::new(vec![server.address().to_string()]).allow_private_hosts(true);
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
        let action =
            WebhookAction::new(vec![server.address().to_string()]).allow_private_hosts(true);
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
        let action =
            WebhookAction::new(vec![server.address().to_string()]).allow_private_hosts(true);
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
        let action = WebhookAction::new(vec![server.address().to_string()])
            .allow_private_hosts(true)
            .with_queue(queue.clone(), Some(secret()), 5);
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
        let action = WebhookAction::new(vec![server.address().to_string()])
            .allow_private_hosts(true)
            .with_queue(queue.clone(), None, 5);
        let params = json!({"url": format!("{}/hook", server.uri())});
        action.execute(context(params, "evt-1")).await.unwrap();
        let handler = action.job_handler();
        let leased = queue
            .reserve("test", 10, Duration::from_secs(30))
            .await
            .unwrap();

        assert!(handler.handle(&leased[0].job).await.is_err());
    }

    #[tokio::test]
    async fn a_400_response_fails_the_job_with_one_attempt() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let queue = Arc::new(MemoryQueue::new());
        let action =
            WebhookAction::new(vec![server.address().to_string()]).allow_private_hosts(true);
        let job = webhook_job(&server);
        let id = job.id;
        queue.enqueue(job).await.unwrap();
        let (cancel, run) = start_worker(queue.clone(), action.job_handler());

        wait_for_requests(&server, 1).await;
        let status = wait_for_status(&queue, id, |s| matches!(s, JobStatus::Failed { .. })).await;
        cancel.cancel();
        run.await.unwrap();

        assert!(matches!(status, JobStatus::Failed { .. }), "got {status:?}");
        assert!(
            queue
                .reserve("probe", 1, Duration::from_secs(30))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_429_response_queues_a_retry_with_the_retry_after_delay() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "2"))
            .mount(&server)
            .await;
        let queue = Arc::new(MemoryQueue::new());
        let action =
            WebhookAction::new(vec![server.address().to_string()]).allow_private_hosts(true);
        let job = webhook_job(&server);
        let id = job.id;
        queue.enqueue(job).await.unwrap();
        let (cancel, run) = start_worker(queue.clone(), action.job_handler());

        wait_for_requests(&server, 1).await;
        let status = wait_for_status(&queue, id, |s| matches!(s, JobStatus::Queued)).await;
        cancel.cancel();
        run.await.unwrap();

        assert!(matches!(status, JobStatus::Queued), "got {status:?}");
        assert!(
            queue
                .reserve("probe", 1, Duration::from_secs(30))
                .await
                .unwrap()
                .is_empty()
        );

        tokio::time::sleep(Duration::from_millis(2100)).await;
        let leased = queue
            .reserve("probe", 1, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(leased.len(), 1);
        assert_eq!(leased[0].job.attempt, 1);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_500_response_queues_a_retry() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let queue = Arc::new(MemoryQueue::new());
        let action =
            WebhookAction::new(vec![server.address().to_string()]).allow_private_hosts(true);
        let job = webhook_job(&server);
        let id = job.id;
        queue.enqueue(job).await.unwrap();
        let (cancel, run) = start_worker(queue.clone(), action.job_handler());

        wait_for_requests(&server, 1).await;
        let status = wait_for_status(&queue, id, |s| matches!(s, JobStatus::Queued)).await;
        cancel.cancel();
        run.await.unwrap();

        assert!(matches!(status, JobStatus::Queued), "got {status:?}");
        assert!(
            queue
                .reserve("probe", 1, Duration::from_secs(30))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_retry_after_parser_reads_and_caps_the_delay() {
        assert_eq!(parse_retry_after("2"), Some(Duration::from_secs(2)));
        assert_eq!(parse_retry_after("0"), Some(Duration::ZERO));
        assert_eq!(
            parse_retry_after("99999"),
            Some(Duration::from_secs(MAX_RETRY_AFTER_SECS))
        );
        assert_eq!(parse_retry_after("not a date"), None);
    }

    #[tokio::test]
    async fn the_pinned_client_uses_the_resolved_address() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pin"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let client = build_client("webhook.invalid", &[*server.address()]);

        let response = client
            .get("http://webhook.invalid/pin")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
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
