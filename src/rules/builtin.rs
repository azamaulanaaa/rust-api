//! Built-in rule actions for the stock binary.
//!
//! The actions are generic.
//! They add no business logic.
//! A host application can use them in tests and in dry runs.

use async_trait::async_trait;
use serde_json::Value;

use crate::rules::action::{ActionContext, ActionError, RuleAction};

/// The text that replaces a secret value in a log line.
const REDACTED: &str = "[REDACTED]";

/// The key fragments that mark a secret value.
const SECRET_KEY_FRAGMENTS: &[&str] = &["token", "secret", "password", "key", "authorization"];

/// Returns a copy of one parameter value with secret parts replaced.
///
/// The call redacts a value when its key name holds a secret fragment.
/// It also redacts the user information and the query values of an `http` or
/// `https` URL. A URL without user information and without a query stays as
/// it is.
fn redact_params(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let value = if is_secret_key(key) {
                        Value::String(REDACTED.to_string())
                    } else {
                        redact_params(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_params).collect()),
        Value::String(text) => Value::String(redact_url(text)),
        other => other.clone(),
    }
}

/// Returns true when one key name looks like a secret.
fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SECRET_KEY_FRAGMENTS
        .iter()
        .any(|fragment| key.contains(fragment))
}

/// Returns one URL string with user information and query values redacted.
fn redact_url(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return raw.to_string();
    };
    if url.scheme() != "http" && url.scheme() != "https" {
        return raw.to_string();
    }
    let has_userinfo = !url.username().is_empty() || url.password().is_some();
    if !has_userinfo && url.query().is_none() {
        return raw.to_string();
    }
    if !url.username().is_empty() {
        let _ = url.set_username(REDACTED);
    }
    if url.password().is_some() {
        let _ = url.set_password(Some(REDACTED));
    }
    if url.query().is_some() {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, _)| (key.into_owned(), REDACTED.to_string()))
            .collect();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    url.to_string()
}

/// An action that does nothing.
///
/// Use this action in tests and in dry runs.
/// It changes no state and is safe to repeat.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAction;

#[async_trait]
impl RuleAction for NoopAction {
    fn kind(&self) -> &str {
        "noop"
    }

    async fn execute(&self, _ctx: ActionContext) -> Result<(), ActionError> {
        Ok(())
    }
}

/// An action that writes one log line.
///
/// The action changes no state and is safe to repeat.
/// The line holds the rule id, the event id, the entity id, the event kind,
/// and the action parameters.
/// The line holds no entity snapshot and no attribute value.
/// The action redacts secret values in the parameters. It redacts a value
/// whose key name looks like a secret. It redacts the user information and
/// the query values of a URL.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogAction;

#[async_trait]
impl RuleAction for LogAction {
    fn kind(&self) -> &str {
        "log"
    }

    async fn execute(&self, ctx: ActionContext) -> Result<(), ActionError> {
        let params = redact_params(&ctx.params);
        tracing::info!(
            rule.id = %ctx.rule.id,
            event.event_id = %ctx.event.event_id,
            event.entity_id = %ctx.event.entity_id,
            event.kind = ?ctx.event.kind,
            ctx.params = %params,
            "rule action log"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::EntityStore;
    use crate::eav::schema::SchemaRegistry;
    use crate::records::{EntityEvent, EntityEventKind};
    use crate::rules::engine::RuleEngine;
    use crate::rules::rule::{
        ActionRef, Condition, Rule, RuleCapabilities, RuleDraft, RuleTrigger,
    };
    use crate::rules::store::RuleStore;

    /// Builds one action context for the tests.
    fn context(kind: &str) -> ActionContext {
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
                    kind: kind.to_string(),
                    params: json!({ "note": "hello" }),
                },
                capabilities: RuleCapabilities::default(),
                created_at: 0,
                updated_at: 0,
            },
            event: EntityEvent {
                event_id: "evt-1".to_string(),
                entity_id: "e1".to_string(),
                entity_version: 1,
                kind: EntityEventKind::Created,
                schemas: vec!["invoice".to_string()],
                changed: Vec::new(),
                actor: "tester".to_string(),
                causation_id: None,
                causation_depth: 0,
                correlation_id: "req-1".to_string(),
                snapshot: None,
                occurred_at: 0,
            },
            entity: None,
            params: json!({ "note": "hello" }),
        }
    }

    /// Builds one engine with both built-in actions.
    async fn engine_with_builtins() -> RuleEngine {
        let raw = build_test_store(&test_prefix("rules-builtin")).await;
        let schema_store = build_test_store(&test_prefix("rules-builtin-schema")).await;
        RuleEngine::new(
            RuleStore::new(raw.clone()),
            EntityStore::new(raw, SchemaRegistry::new(schema_store)),
            vec![Arc::new(NoopAction), Arc::new(LogAction)],
        )
        .expect("built-in action kinds are valid")
    }

    #[tokio::test]
    async fn noop_action_reports_its_kind_and_succeeds() {
        let action = NoopAction;
        assert_eq!(action.kind(), "noop");
        assert!(action.execute(context("noop")).await.is_ok());
    }

    /// Serializes the tests that hit the `LogAction` callsite.
    ///
    /// The callsite interest cache is global. An emission from a test without
    /// a subscriber can thus disable the callsite for a test that captures
    /// the line. One lock keeps the two tests from interleaving.
    static LOG_ACTION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn log_action_reports_its_kind_and_succeeds() {
        let _lock = LOG_ACTION_LOCK.lock().await;
        let action = LogAction;
        assert_eq!(action.kind(), "log");
        assert!(action.execute(context("log")).await.is_ok());
    }

    #[tokio::test]
    async fn an_engine_with_the_builtins_finds_both_kinds() {
        let engine = engine_with_builtins().await;
        assert!(engine.has_action("noop"));
        assert!(engine.has_action("log"));
    }

    #[tokio::test]
    async fn a_rule_with_the_log_action_passes_the_engine_lookup() {
        let engine = engine_with_builtins().await;
        let draft = RuleDraft {
            id: "alpha".to_string(),
            name: "alpha".to_string(),
            enabled: true,
            priority: 0,
            trigger: RuleTrigger {
                events: vec![EntityEventKind::Created],
                schemas: vec!["invoice".to_string()],
            },
            condition: Condition::Always,
            action: ActionRef {
                kind: "log".to_string(),
                params: json!({}),
            },
            capabilities: RuleCapabilities::default(),
        };
        assert!(engine.has_action(&draft.action.kind));
    }

    /// A [`std::io::Write`] sink. It shares one buffer with the subscriber.
    #[derive(Clone)]
    struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_log_action_redacts_secrets() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let _lock = LOG_ACTION_LOCK.lock().await;
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&buffer);
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || SharedBuf(std::sync::Arc::clone(&sink)));
        let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(layer));
        // The callsite interest cache is global. Another test hits the same
        // callsite without a subscriber, so rebuild the cache for this
        // subscriber before the action writes the line.
        tracing::callsite::rebuild_interest_cache();

        let mut ctx = context("log");
        ctx.params = json!({
            "url": "https://user:hunter2password@example.com/hook?token=supersecret",
            "access_token": "supersecret",
            "note": "hello",
        });
        LogAction.execute(ctx).await.unwrap();
        drop(guard);

        let output =
            String::from_utf8(buffer.lock().expect("log buffer").clone()).expect("utf-8 log line");
        assert!(
            !output.contains("supersecret"),
            "the log line holds the token: {output}"
        );
        assert!(
            !output.contains("hunter2password"),
            "the log line holds the password: {output}"
        );
        assert!(
            output.contains(REDACTED),
            "the log line has no marker at level {:?}: {output}",
            tracing::level_filters::LevelFilter::current()
        );
        assert!(
            output.contains("hello"),
            "the log line lost a safe value: {output}"
        );
    }
}
