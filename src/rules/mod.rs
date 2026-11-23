//! Generic rules for entity events.
//!
//! A rule has a trigger, a condition, and an action reference.
//! The trigger selects entity events by kind and schema.
//! The condition tests one entity state and one event.
//! The action reference names one registered action.
//!
//! A rule declares the schema ids that it may read and write.
//! The engine applies the read set to a non-script action and a non-script
//! condition, as it does to a script.
//! A rule with an empty read set sees no attribute value.
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
//! A condition script is pure: it cannot read the store, write, call the
//! network, read the clock, use random values, load files, or evaluate more
//! code.
//! The server enables scripts with `[eav].script_enabled`.
//!
//! # Script actions
//!
//! An action of kind `script` runs one sandboxed Rhai script.
//! The action parameters hold the source:
//!
//! ```json
//! { "kind": "script", "params": { "source": "<rhai>" } }
//! ```
//!
//! The source must be a non-empty string of at most 64 KiB.
//! It must compile.
//! An unknown parameter key is invalid.
//! The error never repeats the source.
//!
//! The script gets the same `event`, `entity`, and `now` values as a
//! condition script, plus a `host` value.
//! The host reads entities and stages create, update, and delete effects.
//! Nothing commits during the script.
//!
//! ```rhai
//! let t = host.get_entity("task-1");
//! if t != () {
//!     host.update_entity("task-1", t.version, #{ status: "done" });
//! }
//! ```
//!
//! The host methods are:
//!
//! - `host.get_entity(id)` returns a map or `()`.
//! - `host.find(schema, key, value, limit)` returns an array of ids.
//! - `host.find_by_schema(schema, limit)` returns an array of ids.
//! - `host.create_entity(id, schemas, attributes)` stages a create.
//! - `host.update_entity(id, expected_version, patch)` stages an update.
//! - `host.delete_entity(id, expected_version)` stages a delete.
//!
//! A `()` value in an update patch removes the attribute.
//! Any other patch value sets the attribute.
//!
//! One evaluation makes at most 200 host read calls and stages at most 100
//! effects.
//! The operation, call-depth, string, array, map, and source limits still
//! apply.
//! Reads see committed state only.
//! A write that the script stages does not appear in a later read.
//!
//! The `read` capability list controls the read methods.
//! A `get_entity` result holds only the attributes that the allowed pinned
//! schemas define.
//! A denied `get_entity` returns `()`.
//! A denied find returns the stable error
//! `rule script read access denied`.
//! The `write` capability list controls every staged write.
//! A create needs every schema in the write set.
//! A create must set only attributes that its schemas define.
//! An update may set only the attributes that the pinned schemas in the
//! write set define.
//! A delete needs at least one pinned schema in the write set.
//! A write outside the set returns the stable error
//! `rule script write access denied`.
//!
//! After the script returns, the engine applies the staged effects and the
//! execution marker in one transaction.
//! A script error or an effect error writes no marker and no effect.
//! A successful script with no effects still writes the marker.
//!
//! The host has no function for HTTP, files, the clock, random values, or
//! processes.
//! A script that calls an unknown function fails at evaluation.
//! A condition script has no `host` value.
//!
//! The module has no HTTP routes and no business rules.

/// Rule actions and the action context.
pub mod action;

/// Built-in actions for tests and dry runs.
pub mod builtin;

/// Atomic entity effect plans.
pub mod effect;

/// The generic rule runner.
pub mod engine;

/// Errors for the rule store and the rule engine.
pub mod error;

/// Rule definitions, triggers, and condition evaluation.
pub mod rule;

/// Sandboxed Rhai condition scripts.
pub mod script;

/// The read-only data API for the future script engine.
pub mod script_host;

/// Durable rule storage and index lookup.
pub mod store;

/// The outbound webhook action.
pub mod webhook;

pub use action::{ActionContext, RuleAction};
pub use builtin::{LogAction, NoopAction};
pub use effect::{EffectPlan, EntityEffect, MAX_EFFECTS};
pub use engine::{ExecutionOutcome, RuleEngine, RuleExecution, RuleObserver};
pub use error::RuleError;
pub use rule::{
    ActionRef, CompareOp, Condition, Rule, RuleCapabilities, RuleDraft, RuleId, RuleTrigger,
};
pub use script::{ScriptActionContext, ScriptContext, ScriptEngine, ScriptError, ScriptHost};
pub use script_host::{MAX_FIND_RESULTS, ScriptCapabilities, ScriptHostError, ScriptReadHost};
pub use store::{RuleDeadLetter, RuleStore};
pub use webhook::WebhookAction;
