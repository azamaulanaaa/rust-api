//! Generic rules for entity events.
//!
//! A rule has a trigger, a condition, and an action reference.
//! The trigger selects entity events by kind and schema.
//! The condition tests one entity state and one event.
//! The action reference is data only.
//! This module runs no rule and executes no action.
//!
//! [`store::RuleStore`] stores rules on OxKV.
//! It keeps one index marker for each trigger event and schema pair.
//! It lists the rules that match one event.
//!
//! The module has no HTTP routes and no business rules.

/// Errors for the rule store.
pub mod error;

/// Rule definitions, triggers, and condition evaluation.
pub mod rule;

/// Durable rule storage and index lookup.
pub mod store;

pub use error::RuleError;
pub use rule::{ActionRef, CompareOp, Condition, Rule, RuleDraft, RuleId, RuleTrigger};
pub use store::RuleStore;
