//! Built-in rule actions for the stock binary.
//!
//! The actions are generic.
//! They add no business logic.
//! A host application can use them in tests and in dry runs.

use async_trait::async_trait;

use crate::rules::action::{ActionContext, RuleAction};

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

    async fn execute(&self, _ctx: ActionContext) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

/// An action that writes one log line.
///
/// The action changes no state and is safe to repeat.
/// The line holds the rule id, the event id, the entity id, the event kind,
/// and the action parameters.
/// The line holds no entity snapshot and no attribute value.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogAction;

#[async_trait]
impl RuleAction for LogAction {
    fn kind(&self) -> &str {
        "log"
    }

    async fn execute(&self, ctx: ActionContext) -> Result<(), anyhow::Error> {
        tracing::info!(
            rule.id = %ctx.rule.id,
            event.event_id = %ctx.event.event_id,
            event.entity_id = %ctx.event.entity_id,
            event.kind = ?ctx.event.kind,
            ctx.params = %ctx.params,
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
    use crate::rules::rule::{ActionRef, Condition, Rule, RuleDraft, RuleTrigger};
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

    #[tokio::test]
    async fn log_action_reports_its_kind_and_succeeds() {
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
        };
        assert!(engine.has_action(&draft.action.kind));
    }
}
