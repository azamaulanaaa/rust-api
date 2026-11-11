//! Rule definitions, triggers, and condition evaluation.
//!
//! A rule joins a trigger, a condition, and an action reference.
//! The trigger selects entity events by kind and schema.
//! The condition tests the entity state and the changed attributes.
//! The action reference is data only.
//! This module executes no action.
//!
//! [`Condition`] is a small tree.
//! [`Condition::eval`] returns `bool` for one entity state and one event.
//! A deleted entity passes `None` as the entity state.
//! [`Condition::Script`] is a sandboxed Rhai expression.
//! The rule engine resolves a script through
//! [the script engine](crate::rules::script::ScriptEngine), not through
//! [`Condition::eval`].

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::eav::entity::Entity;
use crate::records::{EntityEvent, EntityEventKind};
use crate::rules::error::RuleError;
use crate::rules::script::MAX_SOURCE_BYTES;
use crate::rules::script_host::ScriptCapabilities;

/// Maximum size of a rule id, a schema id, or an action kind, in bytes.
const MAX_NAME_BYTES: usize = 128;

/// Maximum depth of a condition tree. The root counts as depth 1.
const MAX_DEPTH: usize = 16;

/// Maximum count of ids in one capability list.
const MAX_CAPABILITY_IDS: usize = 32;

/// The identifier of a rule.
pub type RuleId = String;

/// A new rule, before the store assigns a version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RuleDraft {
    /// The rule id.
    pub id: RuleId,
    /// The display name of the rule.
    pub name: String,
    /// True when the rule is active.
    pub enabled: bool,
    /// The order key. A higher value comes first.
    pub priority: i32,
    /// The events that start the rule.
    pub trigger: RuleTrigger,
    /// The condition that the entity must pass.
    pub condition: Condition,
    /// The action to run. The store does not run it.
    pub action: ActionRef,
    /// The schema ids that the rule script may read and write.
    #[serde(default)]
    pub capabilities: RuleCapabilities,
}

impl RuleDraft {
    /// Checks the draft before the store writes it.
    ///
    /// The call rejects an empty trigger, a duplicate trigger entry, an
    /// invalid identifier, a condition tree deeper than 16 levels, or an
    /// invalid capability list.
    pub fn validate(&self) -> Result<(), RuleError> {
        validate_identifier("rule id", &self.id)?;
        validate_identifier("action kind", &self.action.kind)?;
        if self.trigger.events.is_empty() {
            return Err(RuleError::Invalid("trigger events are empty".to_string()));
        }
        if self.trigger.schemas.is_empty() {
            return Err(RuleError::Invalid("trigger schemas are empty".to_string()));
        }
        for (index, event) in self.trigger.events.iter().enumerate() {
            if self.trigger.events[..index].contains(event) {
                return Err(RuleError::Invalid(
                    "trigger events contain a duplicate".to_string(),
                ));
            }
        }
        for (index, schema) in self.trigger.schemas.iter().enumerate() {
            validate_identifier("schema id", schema)?;
            if self.trigger.schemas[..index].contains(schema) {
                return Err(RuleError::Invalid(
                    "trigger schemas contain a duplicate".to_string(),
                ));
            }
        }
        self.capabilities.validate()?;
        if self.condition.depth() > MAX_DEPTH {
            return Err(RuleError::ConditionDepth);
        }
        self.condition.validate_source_size()?;
        Ok(())
    }
}

/// The schema ids that a rule script may read and write.
///
/// An old stored rule without this field gets two empty lists.
/// An empty list grants no access.
/// The ids do not need a schema that exists. A rule can be saved before its
/// schema.
/// The host enforces the stored lists at run time.
/// The author needs the collection grant on `eav_entities`, and the rule
/// narrows that grant to the listed schemas.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RuleCapabilities {
    /// The schema ids that the script may read.
    #[serde(default)]
    pub read: Vec<String>,
    /// The schema ids that the script may write.
    #[serde(default)]
    pub write: Vec<String>,
}

impl RuleCapabilities {
    /// Checks the two capability lists.
    ///
    /// The call rejects an invalid id, a duplicate id in one list, or a list
    /// with more than 32 ids.
    pub fn validate(&self) -> Result<(), RuleError> {
        validate_capability_list("read", &self.read)?;
        validate_capability_list("write", &self.write)?;
        Ok(())
    }

    /// Builds the read-side capability set for the script host.
    ///
    /// The call uses only the `read` list.
    /// It returns an invalid-input error for an invalid schema id.
    /// The write side stays in the rule until the host supports it.
    pub fn to_script_capabilities(&self) -> Result<ScriptCapabilities, RuleError> {
        ScriptCapabilities::new(self.read.iter().cloned())
            .map_err(|error| RuleError::Invalid(error.to_string()))
    }
}

/// Checks one capability list.
///
/// The call rejects a list with more than 32 ids, an invalid id, or a
/// duplicate id.
fn validate_capability_list(kind: &str, ids: &[String]) -> Result<(), RuleError> {
    if ids.len() > MAX_CAPABILITY_IDS {
        return Err(RuleError::Invalid(format!(
            "capability {kind} list has more than 32 ids"
        )));
    }
    for (index, id) in ids.iter().enumerate() {
        validate_identifier("capability schema id", id)?;
        if ids[..index].contains(id) {
            return Err(RuleError::Invalid(format!(
                "capability {kind} list contains a duplicate"
            )));
        }
    }
    Ok(())
}

/// A stored rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Rule {
    /// The rule id.
    pub id: RuleId,
    /// The rule version. The first version is 1.
    pub version: u64,
    /// The display name of the rule.
    pub name: String,
    /// True when the rule is active.
    pub enabled: bool,
    /// The order key. A higher value comes first.
    pub priority: i32,
    /// The events that start the rule.
    pub trigger: RuleTrigger,
    /// The condition that the entity must pass.
    pub condition: Condition,
    /// The action to run. The store does not run it.
    pub action: ActionRef,
    /// The schema ids that the rule script may read and write.
    #[serde(default)]
    pub capabilities: RuleCapabilities,
    /// The creation time as a Unix timestamp in seconds.
    pub created_at: i64,
    /// The last update time as a Unix timestamp in seconds.
    pub updated_at: i64,
}

/// The events and schemas that start a rule.
///
/// A rule matches an event when the event kind is in `events` and any event
/// schema is in `schemas`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RuleTrigger {
    /// The event kinds that start the rule.
    pub events: Vec<EntityEventKind>,
    /// The schema ids that the event must carry.
    pub schemas: Vec<String>,
}

impl RuleTrigger {
    /// True when this trigger matches `event`.
    pub fn matches(&self, event: &EntityEvent) -> bool {
        if !self.events.contains(&event.kind) {
            return false;
        }
        event
            .schemas
            .iter()
            .any(|schema| self.schemas.iter().any(|id| id == schema))
    }
}

/// A condition on an entity or an event.
///
/// A [`Condition::Script`] is a sandboxed Rhai expression.
/// The server must enable scripts with `[eav].script_enabled`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum Condition {
    /// Always true.
    Always,
    /// True when every child is true.
    #[schema(no_recursion)]
    All(Vec<Condition>),
    /// True when one or more children are true.
    #[schema(no_recursion)]
    Any(Vec<Condition>),
    /// True when the child is false.
    #[schema(no_recursion)]
    Not(Box<Condition>),
    /// Compares one attribute with a JSON value.
    Compare {
        /// The attribute name.
        key: String,
        /// The comparison operator.
        op: CompareOp,
        /// The JSON value to compare with.
        value: serde_json::Value,
    },
    /// True when the attribute is present.
    Exists {
        /// The attribute name.
        key: String,
    },
    /// True when the event changed the attribute.
    Changed {
        /// The attribute name.
        key: String,
    },
    /// A sandboxed Rhai expression that returns a boolean.
    ///
    /// The rule engine compiles the source at save time and evaluates it at
    /// run time.
    /// The script cannot read the store, write, call the network, read the
    /// clock, use random values, load files, or evaluate more code.
    /// The server enables scripts with `[eav].script_enabled`.
    Script {
        /// The Rhai source. The value is at most 8 KiB.
        source: String,
    },
}

impl Condition {
    /// Returns the result of this condition for `entity` and `event`.
    ///
    /// `Compare` and `Exists` read `event.snapshot` when it is `Some`.
    /// The event-time state then decides, not a newer entity.
    /// They read the current entity only when the snapshot is `None`.
    /// A missing attribute makes both conditions false.
    /// A deleted entity passes `None` as `entity`.
    /// In that case only [`Condition::Always`], [`Condition::Changed`], and
    /// logical combinations can be true, unless the snapshot supplies the
    /// attribute.
    ///
    /// This method does not evaluate [`Condition::Script`].
    /// A script always returns `false` here.
    /// The rule engine must resolve a script through
    /// [eval_bool](crate::rules::script::ScriptEngine::eval_bool).
    pub fn eval(&self, entity: Option<&Entity>, event: &EntityEvent) -> bool {
        match self {
            Self::Always => true,
            Self::All(children) => children.iter().all(|child| child.eval(entity, event)),
            Self::Any(children) => children.iter().any(|child| child.eval(entity, event)),
            Self::Not(child) => !child.eval(entity, event),
            Self::Compare { key, op, value } => match &event.snapshot {
                Some(snapshot) => snapshot
                    .get(key)
                    .is_some_and(|actual| compare_values(actual, *op, value)),
                None => entity
                    .and_then(|entity| entity.attributes.get(key))
                    .is_some_and(|actual| compare_values(&actual.as_json(), *op, value)),
            },
            Self::Exists { key } => match &event.snapshot {
                Some(snapshot) => snapshot.contains_key(key),
                None => entity.is_some_and(|entity| entity.attributes.contains_key(key)),
            },
            Self::Changed { key } => event.changed.iter().any(|change| change.key == *key),
            Self::Script { .. } => false,
        }
    }

    /// Returns the depth of this tree. The root counts as depth 1.
    fn depth(&self) -> usize {
        match self {
            Self::Always
            | Self::Compare { .. }
            | Self::Exists { .. }
            | Self::Changed { .. }
            | Self::Script { .. } => 1,
            Self::Not(child) => 1 + child.depth(),
            Self::All(children) | Self::Any(children) => {
                1 + children.iter().map(Self::depth).max().unwrap_or(0)
            }
        }
    }

    /// Rejects a script source that is larger than [`MAX_SOURCE_BYTES`].
    fn validate_source_size(&self) -> Result<(), RuleError> {
        match self {
            Self::Script { source } if source.len() > MAX_SOURCE_BYTES => Err(RuleError::Invalid(
                "rule script source is larger than 8 KiB".to_string(),
            )),
            Self::Not(child) => child.validate_source_size(),
            Self::All(children) | Self::Any(children) => {
                for child in children {
                    child.validate_source_size()?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// The comparison operator of a [`Condition::Compare`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum CompareOp {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
}

/// A reference to an action. This type is data only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ActionRef {
    /// The action kind.
    pub kind: String,
    /// The action parameters.
    pub params: serde_json::Value,
}

/// Compares two plain JSON values.
///
/// `Eq` and `Ne` use JSON equality.
/// An ordered operator accepts two numbers or two strings.
/// Any other pair is false.
fn compare_values(actual: &serde_json::Value, op: CompareOp, expected: &serde_json::Value) -> bool {
    match op {
        CompareOp::Eq => actual == expected,
        CompareOp::Ne => actual != expected,
        CompareOp::Gt => ordering(actual, expected) == Some(Ordering::Greater),
        CompareOp::Ge => matches!(
            ordering(actual, expected),
            Some(Ordering::Greater | Ordering::Equal)
        ),
        CompareOp::Lt => ordering(actual, expected) == Some(Ordering::Less),
        CompareOp::Le => matches!(
            ordering(actual, expected),
            Some(Ordering::Less | Ordering::Equal)
        ),
    }
}

/// Returns the order of two numbers or two strings.
fn ordering(left: &serde_json::Value, right: &serde_json::Value) -> Option<Ordering> {
    match (left, right) {
        (serde_json::Value::Number(left), serde_json::Value::Number(right)) => {
            number_ordering(left, right)
        }
        (serde_json::Value::String(left), serde_json::Value::String(right)) => {
            Some(left.cmp(right))
        }
        _ => None,
    }
}

/// Returns the exact order of two JSON numbers.
///
/// An integer pair stays exact and never converts to `f64`.
/// A negative `i64` stays below a non-negative `u64`.
/// If one number is a float, the call compares both as `f64`.
fn number_ordering(left: &serde_json::Number, right: &serde_json::Number) -> Option<Ordering> {
    if left.is_f64() || right.is_f64() {
        return left.as_f64()?.partial_cmp(&right.as_f64()?);
    }
    let left_i64 = left.as_i64();
    let right_i64 = right.as_i64();
    match (left_i64, right_i64) {
        (Some(left), Some(right)) if left < 0 || right < 0 => Some(left.cmp(&right)),
        (Some(left), _) if left < 0 => Some(Ordering::Less),
        (_, Some(right)) if right < 0 => Some(Ordering::Greater),
        _ => Some(left.as_u64()?.cmp(&right.as_u64()?)),
    }
}

/// Checks a rule id, a schema id, or an action kind against the key rules.
///
/// The value must be 1 to 128 bytes.
/// It may contain only lowercase ASCII letters, digits, `_`, and `-`.
/// These rules reject `:`, `/`, and whitespace.
pub(crate) fn validate_identifier(kind: &str, value: &str) -> Result<(), RuleError> {
    if value.is_empty() {
        return Err(RuleError::Invalid(format!("{kind} is empty")));
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(RuleError::Invalid(format!(
            "{kind} is longer than 128 bytes"
        )));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
    }) {
        return Err(RuleError::Invalid(format!(
            "{kind} has an invalid character"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eav::entity::AttributeValue;
    use crate::eav::schema::SchemaRef;
    use crate::records::AttributeChange;
    use std::collections::BTreeMap;

    fn entity(attributes: Vec<(&str, AttributeValue)>) -> Entity {
        Entity {
            id: "e1".to_string(),
            version: 1,
            schemas: vec![SchemaRef {
                id: "invoice".to_string(),
                version: 1,
            }],
            attributes: attributes
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect::<BTreeMap<_, _>>(),
            created_at: 1,
            updated_at: 1,
        }
    }

    fn event(changed: Vec<&str>) -> EntityEvent {
        EntityEvent {
            event_id: "evt-1".to_string(),
            entity_id: "e1".to_string(),
            entity_version: 2,
            kind: EntityEventKind::Updated,
            schemas: vec!["invoice".to_string()],
            changed: changed
                .into_iter()
                .map(|key| AttributeChange {
                    key: key.to_string(),
                    old: None,
                    new: Some(serde_json::json!(1)),
                })
                .collect(),
            actor: "alice".to_string(),
            causation_id: None,
            causation_depth: 0,
            correlation_id: "req-1".to_string(),
            snapshot: None,
            occurred_at: 2,
        }
    }

    fn compare(key: &str, op: CompareOp, value: serde_json::Value) -> Condition {
        Condition::Compare {
            key: key.to_string(),
            op,
            value,
        }
    }

    #[test]
    fn always_is_true() {
        assert!(Condition::Always.eval(None, &event(vec![])));
    }

    #[test]
    fn all_any_and_not_combine_children() {
        let yes = Condition::Always;
        let no = Condition::Not(Box::new(Condition::Always));
        let missing = Condition::Exists {
            key: "missing".to_string(),
        };

        assert!(Condition::All(vec![yes.clone(), yes.clone()]).eval(None, &event(vec![])));
        assert!(!Condition::All(vec![yes.clone(), no.clone()]).eval(None, &event(vec![])));
        assert!(Condition::Any(vec![no.clone(), yes.clone()]).eval(None, &event(vec![])));
        assert!(!Condition::Any(vec![no.clone(), missing]).eval(None, &event(vec![])));
        assert!(Condition::Not(Box::new(no)).eval(None, &event(vec![])));
    }

    #[test]
    fn compare_covers_numbers_and_strings() {
        let e = entity(vec![
            ("total", AttributeValue::Integer(10)),
            ("label", AttributeValue::String("beta".to_string())),
        ]);

        let number_cases = [
            (CompareOp::Eq, serde_json::json!(10), true),
            (CompareOp::Ne, serde_json::json!(11), true),
            (CompareOp::Gt, serde_json::json!(9), true),
            (CompareOp::Ge, serde_json::json!(10), true),
            (CompareOp::Lt, serde_json::json!(11), true),
            (CompareOp::Le, serde_json::json!(10), true),
            (CompareOp::Gt, serde_json::json!(10), false),
            (CompareOp::Lt, serde_json::json!(10), false),
        ];
        for (op, value, expected) in number_cases {
            assert_eq!(
                compare("total", op, value).eval(Some(&e), &event(vec![])),
                expected,
                "number case {op:?}"
            );
        }

        let string_cases = [
            (CompareOp::Eq, serde_json::json!("beta"), true),
            (CompareOp::Ne, serde_json::json!("alpha"), true),
            (CompareOp::Gt, serde_json::json!("alpha"), true),
            (CompareOp::Ge, serde_json::json!("beta"), true),
            (CompareOp::Lt, serde_json::json!("gamma"), true),
            (CompareOp::Le, serde_json::json!("beta"), true),
            (CompareOp::Gt, serde_json::json!("beta"), false),
            (CompareOp::Lt, serde_json::json!("beta"), false),
        ];
        for (op, value, expected) in string_cases {
            assert_eq!(
                compare("label", op, value).eval(Some(&e), &event(vec![])),
                expected,
                "string case {op:?}"
            );
        }
    }

    #[test]
    fn compare_keeps_large_integers_exact() {
        let e = entity(vec![(
            "big",
            AttributeValue::Integer(9_007_199_254_740_993),
        )]);
        let smaller = serde_json::json!(9_007_199_254_740_992_i64);

        assert!(compare("big", CompareOp::Gt, smaller.clone()).eval(Some(&e), &event(vec![])));
        assert!(!compare("big", CompareOp::Eq, smaller.clone()).eval(Some(&e), &event(vec![])));
        assert!(compare("big", CompareOp::Ne, smaller).eval(Some(&e), &event(vec![])));

        assert_eq!(
            ordering(
                &serde_json::json!(u64::MAX),
                &serde_json::json!(u64::MAX - 1)
            ),
            Some(Ordering::Greater)
        );
        assert_eq!(
            ordering(&serde_json::json!(-1_i64), &serde_json::json!(u64::MAX)),
            Some(Ordering::Less)
        );
        assert_eq!(
            ordering(&serde_json::json!(u64::MAX), &serde_json::json!(-1_i64)),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn compare_with_a_missing_attribute_is_false() {
        let e = entity(vec![]);

        assert!(
            !compare("total", CompareOp::Eq, serde_json::json!(1)).eval(Some(&e), &event(vec![]))
        );
    }

    #[test]
    fn compare_with_mismatched_types_is_false() {
        let e = entity(vec![
            ("total", AttributeValue::Integer(10)),
            ("label", AttributeValue::String("beta".to_string())),
        ]);

        assert!(
            !compare("total", CompareOp::Eq, serde_json::json!("10"))
                .eval(Some(&e), &event(vec![]))
        );
        assert!(
            !compare("total", CompareOp::Gt, serde_json::json!("9")).eval(Some(&e), &event(vec![]))
        );
        assert!(
            !compare("label", CompareOp::Gt, serde_json::json!(1)).eval(Some(&e), &event(vec![]))
        );
    }

    #[test]
    fn exists_and_changed_behave_correctly() {
        let e = entity(vec![("total", AttributeValue::Integer(10))]);
        let ev = event(vec!["total"]);

        assert!(
            Condition::Exists {
                key: "total".to_string()
            }
            .eval(Some(&e), &ev)
        );
        assert!(
            !Condition::Exists {
                key: "label".to_string()
            }
            .eval(Some(&e), &ev)
        );
        assert!(
            Condition::Changed {
                key: "total".to_string()
            }
            .eval(Some(&e), &ev)
        );
        assert!(
            !Condition::Changed {
                key: "label".to_string()
            }
            .eval(Some(&e), &ev)
        );
    }

    /// A snapshot decides the comparison, even when the entity has changed.
    ///
    /// The event-time state is the fact that the rule must see.
    /// The current entity may already hold a newer value.
    #[test]
    fn a_condition_reads_the_snapshot_and_not_a_newer_entity() {
        let e = entity(vec![("total", AttributeValue::Integer(20))]);
        let mut ev = event(vec![]);
        ev.snapshot = Some(BTreeMap::from([(
            "total".to_string(),
            serde_json::json!(10),
        )]));

        assert!(compare("total", CompareOp::Eq, serde_json::json!(10)).eval(Some(&e), &ev));
        assert!(!compare("total", CompareOp::Eq, serde_json::json!(20)).eval(Some(&e), &ev));
        assert!(
            Condition::Exists {
                key: "total".to_string()
            }
            .eval(Some(&e), &ev)
        );
    }

    /// An old event has no snapshot, so the condition reads the entity.
    ///
    /// The fallback keeps an old durable event usable.
    #[test]
    fn an_old_event_without_a_snapshot_uses_the_current_entity() {
        let e = entity(vec![("total", AttributeValue::Integer(20))]);
        let ev = event(vec![]);
        assert_eq!(ev.snapshot, None);

        assert!(compare("total", CompareOp::Eq, serde_json::json!(20)).eval(Some(&e), &ev));
        assert!(
            Condition::Exists {
                key: "total".to_string()
            }
            .eval(Some(&e), &ev)
        );
    }

    /// A delete has no current entity, but its snapshot holds the before state.
    ///
    /// A rule can then compare the attributes that the delete removed.
    #[test]
    fn a_deleted_event_with_a_snapshot_compares_the_before_state() {
        let mut ev = event(vec!["total"]);
        ev.kind = EntityEventKind::Deleted;
        ev.snapshot = Some(BTreeMap::from([(
            "total".to_string(),
            serde_json::json!(10),
        )]));

        assert!(compare("total", CompareOp::Eq, serde_json::json!(10)).eval(None, &ev));
        assert!(
            Condition::Exists {
                key: "total".to_string()
            }
            .eval(None, &ev)
        );
    }

    #[test]
    fn a_deleted_entity_can_match_always_and_changed() {
        let ev = event(vec!["total"]);

        assert!(Condition::Always.eval(None, &ev));
        assert!(
            Condition::Changed {
                key: "total".to_string()
            }
            .eval(None, &ev)
        );
        assert!(
            Condition::All(vec![
                Condition::Always,
                Condition::Changed {
                    key: "total".to_string()
                }
            ])
            .eval(None, &ev)
        );
        assert!(!compare("total", CompareOp::Eq, serde_json::json!(10)).eval(None, &ev));
        assert!(
            !Condition::Exists {
                key: "total".to_string()
            }
            .eval(None, &ev)
        );
    }

    /// A script counts as one level, and `eval` never resolves it.
    #[test]
    fn a_script_condition_has_depth_one_and_eval_is_false() {
        let script = Condition::Script {
            source: "true".to_string(),
        };

        assert_eq!(script.depth(), 1);
        assert!(!script.eval(None, &event(vec![])));
        assert_eq!(Condition::Not(Box::new(script)).depth(), 2);
    }

    /// The draft rejects a script source above the size limit.
    #[test]
    fn a_rule_draft_rejects_an_oversized_script() {
        let draft = RuleDraft {
            id: "alpha".to_string(),
            name: "alpha".to_string(),
            enabled: true,
            priority: 0,
            trigger: RuleTrigger {
                events: vec![EntityEventKind::Created],
                schemas: vec!["invoice".to_string()],
            },
            condition: Condition::Script {
                source: " ".repeat(MAX_SOURCE_BYTES + 1),
            },
            action: ActionRef {
                kind: "record".to_string(),
                params: serde_json::json!({}),
            },
            capabilities: RuleCapabilities::default(),
        };

        assert!(matches!(
            draft.validate(),
            Err(RuleError::Invalid(message)) if message.contains("8 KiB")
        ));
    }

    /// Builds a valid draft with the default capability lists.
    fn draft() -> RuleDraft {
        RuleDraft {
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
                kind: "record".to_string(),
                params: serde_json::json!({}),
            },
            capabilities: RuleCapabilities::default(),
        }
    }

    /// An old stored rule has no capability field, so it gets two empty lists.
    #[test]
    fn an_old_rule_without_capabilities_gets_two_empty_lists() {
        let stored = serde_json::json!({
            "id": "alpha",
            "version": 1,
            "name": "alpha",
            "enabled": true,
            "priority": 0,
            "trigger": {
                "events": ["Created"],
                "schemas": ["invoice"]
            },
            "condition": "Always",
            "action": {"kind": "record", "params": {}},
            "created_at": 1,
            "updated_at": 1
        });
        let rule: Rule = serde_json::from_value(stored).expect("old rule parses");

        assert!(rule.capabilities.read.is_empty());
        assert!(rule.capabilities.write.is_empty());
    }

    /// A duplicate id in one list is invalid.
    #[test]
    fn a_duplicate_capability_id_is_rejected() {
        let mut rule = draft();
        rule.capabilities.read = vec!["task".to_string(), "task".to_string()];

        assert!(matches!(
            rule.validate(),
            Err(RuleError::Invalid(message)) if message.contains("duplicate")
        ));
    }

    /// An id that breaks the identifier rule is invalid.
    #[test]
    fn an_invalid_capability_id_is_rejected() {
        let mut rule = draft();
        rule.capabilities.write = vec!["Task/one".to_string()];

        assert!(matches!(
            rule.validate(),
            Err(RuleError::Invalid(message)) if message.contains("invalid")
        ));
    }

    /// A list with 33 ids is invalid.
    #[test]
    fn a_capability_list_above_32_ids_is_rejected() {
        let mut rule = draft();
        rule.capabilities.read = (0..33).map(|index| format!("s{index}")).collect();

        assert!(matches!(
            rule.validate(),
            Err(RuleError::Invalid(message)) if message.contains("more than 32")
        ));
    }

    /// The read list becomes the read-side script capability set.
    #[test]
    fn capabilities_build_the_read_side_script_set() {
        let mut rule = draft();
        rule.capabilities.read = vec!["task".to_string()];
        rule.capabilities.write = vec!["other".to_string()];

        let script = rule
            .capabilities
            .to_script_capabilities()
            .expect("read list is valid");

        assert!(script.allows("task"));
        assert!(!script.allows("other"));
    }
}
