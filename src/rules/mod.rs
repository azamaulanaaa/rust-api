//! Generic rules for entity events.
//!
//! A rule has a trigger, a condition, and an action reference.
//! The trigger selects entity events by kind and schema.
//! The condition tests one entity state and one event.
//! The action reference names one registered action.
//!
//! [`store::RuleStore`](crate::rules::store::RuleStore) stores rules on OxKV.
//! It keeps one index marker for each trigger event and schema pair.
//! It lists the rules that match one event.
//!
//! [`engine::RuleEngine`](crate::rules::engine::RuleEngine) runs the matching rules through an action.
//! [`action::RuleAction`](crate::rules::action::RuleAction) is the only extension point.
//! The engine also tails the durable change feed.
//! Delivery is at least once, so an action must be idempotent.
//!
//! [A script condition](crate::rules::rule::Condition::Script) holds a
//! sandboxed Rhai expression.
//! [The script engine](crate::rules::script::ScriptEngine) compiles and
//! evaluates it.
//! A script is pure: it cannot read the store, write, call the network, read
//! the clock, use random values, load files, or evaluate more code.
//! The server enables scripts with `[eav].script_enabled`.
//!
//! The module has no HTTP routes and no business rules.

/// Rule actions and the action context.
pub mod action;

/// Built-in actions for tests and dry runs.
pub mod builtin;

/// The generic rule runner.
pub mod engine;

/// Errors for the rule store and the rule engine.
pub mod error;

/// Rule definitions, triggers, and condition evaluation.
pub mod rule;

/// Sandboxed Rhai condition scripts.
pub mod script;

/// Durable rule storage and index lookup.
pub mod store;

/// The outbound webhook action.
pub mod webhook;

pub use action::{ActionContext, RuleAction};
pub use builtin::{LogAction, NoopAction};
pub use engine::{ExecutionOutcome, RuleEngine, RuleExecution, RuleObserver};
pub use error::RuleError;
pub use rule::{ActionRef, CompareOp, Condition, Rule, RuleDraft, RuleId, RuleTrigger};
pub use script::{ScriptContext, ScriptEngine, ScriptError};
pub use store::RuleStore;
pub use webhook::WebhookAction;
