//! Sandboxed Rhai condition scripts.
//!
//! A script is a pure boolean expression.
//! It reads the event, the optional entity, and the current time.
//! It cannot read the store, write, call the network, read the clock, use
//! random values, load files, or evaluate more code.
//!
//! [`ScriptEngine`] holds one Rhai engine and a bounded compiled-AST cache.
//! The cache is a speed aid, not a correctness requirement.
//! A cache miss or a cache clear only costs one compile.
//!
//! The engine uses the Rhai operation limit for a deterministic budget.
//! The wall-time guard is a last-resort safety net.
//! The engine registers only pure packages.
//! It does not register the Rhai time package or the language-core `sleep`
//! function.
//! The registered packages have no file, network, process, clock, or random
//! API.
//! The engine disables `eval` and `import` explicitly.
//! It also replaces `print` and `debug` with no-ops, so a script cannot flood
//! stdout or the log.

use std::cell::Cell;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rhai::packages::{
    ArithmeticPackage, BasicArrayPackage, BasicFnPackage, BasicIteratorPackage, BasicMapPackage,
    BasicMathPackage, BasicStringPackage, BitFieldPackage, LogicPackage, MoreStringPackage,
    Package,
};
use rhai::{AST, Dynamic, Engine, EvalAltResult, Map, Scope};
use thiserror::Error;

use crate::eav::entity::Entity;
use crate::records::{EntityEvent, EntityEventKind};

/// The largest accepted script source, in bytes.
pub(crate) const MAX_SOURCE_BYTES: usize = 8 * 1024;

/// The largest number of compiled scripts in the cache.
const CACHE_CAPACITY: usize = 256;

/// The maximum number of Rhai operations for one evaluation.
const MAX_OPERATIONS: u64 = 10_000;

/// The maximum number of Rhai call levels for one evaluation.
const MAX_CALL_LEVELS: usize = 16;

/// The maximum Rhai string size, in bytes.
const MAX_STRING_SIZE: usize = 64 * 1024;

/// The maximum Rhai array size.
const MAX_ARRAY_SIZE: usize = 1_000;

/// The maximum Rhai map size.
const MAX_MAP_SIZE: usize = 1_000;

/// The wall-time guard for one evaluation.
const WALL_TIME_GUARD: Duration = Duration::from_millis(50);

thread_local! {
    /// The deadline for the evaluation on this thread.
    ///
    /// The progress callback reads this value.
    /// A thread-local value keeps concurrent evaluations independent.
    static EVAL_DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// A failure of a condition script.
///
/// Each message is stable and sanitized.
/// A message never holds the script source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ScriptError {
    /// The script did not compile.
    #[error("rule script failed to compile")]
    Compile,
    /// The script failed at run time.
    #[error("rule script failed at run time")]
    Runtime,
    /// The script used more than its operation, call, or data budget.
    #[error("rule script exceeded its execution budget")]
    Budget,
    /// The script returned a value that is not a boolean.
    #[error("rule script did not return a boolean")]
    ReturnType,
    /// The server disables condition scripts.
    #[error("rule scripts are disabled")]
    Disabled,
    /// The script source is larger than 8 KiB.
    #[error("rule script source is larger than 8 KiB")]
    SourceTooLarge,
}

/// The inputs of one script evaluation.
///
/// `event` is always present.
/// `entity` is `None` for a deleted entity.
/// `now` is a Unix timestamp in seconds.
pub struct ScriptContext<'a> {
    /// The event that started the rule.
    pub event: &'a EntityEvent,
    /// The current entity, or `None` when the entity is absent.
    pub entity: Option<&'a Entity>,
    /// The current Unix time in seconds.
    pub now: i64,
}

/// A cached compiled script.
struct CachedScript {
    /// The source that produced `ast`.
    source: String,
    /// The compiled script.
    ast: AST,
}

/// A sandboxed Rhai engine for condition scripts.
///
/// One engine serves every rule.
/// The compiled-AST cache is bounded to 256 entries.
/// When the cache is full, the engine clears it and starts again.
#[derive(Clone)]
pub struct ScriptEngine {
    /// The shared Rhai engine.
    engine: Arc<Engine>,
    /// The compiled-AST cache, keyed by a hash of the source.
    cache: Arc<Mutex<HashMap<u64, CachedScript>>>,
    /// True when the server enables condition scripts.
    enabled: bool,
}

impl ScriptEngine {
    /// Creates an engine.
    ///
    /// `enabled` comes from `[eav].script_enabled`.
    /// A disabled engine rejects every compile and every evaluation with
    /// [`ScriptError::Disabled`].
    pub fn new(enabled: bool) -> Self {
        // Register only the packages that a pure expression needs.
        // The standard package adds the time package, which exposes the
        // clock and `sleep`. The core package adds `sleep` too. Neither is
        // registered here.
        let mut engine = Engine::new_raw();
        ArithmeticPackage::new().register_into_engine(&mut engine);
        BasicArrayPackage::new().register_into_engine(&mut engine);
        BasicFnPackage::new().register_into_engine(&mut engine);
        BasicIteratorPackage::new().register_into_engine(&mut engine);
        BasicMapPackage::new().register_into_engine(&mut engine);
        BasicMathPackage::new().register_into_engine(&mut engine);
        BasicStringPackage::new().register_into_engine(&mut engine);
        BitFieldPackage::new().register_into_engine(&mut engine);
        LogicPackage::new().register_into_engine(&mut engine);
        MoreStringPackage::new().register_into_engine(&mut engine);
        engine
            .set_max_operations(MAX_OPERATIONS)
            .set_max_call_levels(MAX_CALL_LEVELS)
            .set_max_string_size(MAX_STRING_SIZE)
            .set_max_array_size(MAX_ARRAY_SIZE)
            .set_max_map_size(MAX_MAP_SIZE)
            .disable_symbol("eval")
            .disable_symbol("import");
        // A script must not write to stdout or the log.
        // A no-op is safer than a debug log: a loop with `print` cannot then
        // amplify the log volume.
        engine.on_print(|_| {});
        engine.on_debug(|_, _, _| {});
        engine.on_progress(|_| {
            let expired = EVAL_DEADLINE.with(|deadline| {
                deadline
                    .get()
                    .is_some_and(|deadline| Instant::now() >= deadline)
            });
            expired.then(|| Dynamic::from("rule script exceeded its execution budget"))
        });
        Self {
            engine: Arc::new(engine),
            cache: Arc::new(Mutex::new(HashMap::new())),
            enabled,
        }
    }

    /// Returns true when the server enables condition scripts.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Compiles a script and caches the AST.
    ///
    /// The call rejects a disabled engine, a source larger than 8 KiB, and a
    /// syntax error.
    /// It returns no detail from the Rhai parser, so the caller cannot echo
    /// the source.
    pub fn compile(&self, source: &str) -> Result<(), ScriptError> {
        self.ast_for(source).map(|_| ())
    }

    /// Evaluates a script and returns its boolean result.
    ///
    /// The call compiles the script on a cache miss.
    /// A result that is not a boolean returns [`ScriptError::ReturnType`].
    /// Any script failure returns a sanitized [`ScriptError`].
    pub fn eval_bool(&self, source: &str, ctx: &ScriptContext<'_>) -> Result<bool, ScriptError> {
        let ast = self.ast_for(source)?;
        let mut scope = Scope::new();
        scope.push_constant("event", event_map(ctx.event));
        scope.push_constant("entity", entity_value(ctx.entity));
        scope.push_constant("now", ctx.now);

        EVAL_DEADLINE.with(|deadline| deadline.set(Some(Instant::now() + WALL_TIME_GUARD)));
        let result = self.engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast);
        EVAL_DEADLINE.with(|deadline| deadline.set(None));

        match result {
            Ok(value) => value.as_bool().map_err(|_| ScriptError::ReturnType),
            Err(error) => Err(classify(&error)),
        }
    }

    /// Returns the AST for `source`, or compiles and caches it.
    ///
    /// The cache is a speed aid, not a correctness requirement.
    /// A hash collision does not change the result because the entry also
    /// holds the source.
    fn ast_for(&self, source: &str) -> Result<AST, ScriptError> {
        if !self.enabled {
            return Err(ScriptError::Disabled);
        }
        if source.len() > MAX_SOURCE_BYTES {
            return Err(ScriptError::SourceTooLarge);
        }
        let key = source_hash(source);
        {
            let cache = lock_cache(&self.cache);
            if let Some(entry) = cache.get(&key)
                && entry.source == source
            {
                return Ok(entry.ast.clone());
            }
        }

        let ast = self
            .engine
            .compile(source)
            .map_err(|_| ScriptError::Compile)?;
        let mut cache = lock_cache(&self.cache);
        if cache.len() >= CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(
            key,
            CachedScript {
                source: source.to_string(),
                ast: ast.clone(),
            },
        );
        Ok(ast)
    }

    /// Returns the number of cached scripts.
    #[cfg(test)]
    fn cache_len(&self) -> usize {
        lock_cache(&self.cache).len()
    }
}

/// Locks the cache and recovers from a poisoned lock.
fn lock_cache(
    cache: &Mutex<HashMap<u64, CachedScript>>,
) -> MutexGuard<'_, HashMap<u64, CachedScript>> {
    cache.lock().unwrap_or_else(|error| error.into_inner())
}

/// Returns a stable hash of one script source.
fn source_hash(source: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    source.hash(&mut hasher);
    hasher.finish()
}

/// Maps a Rhai evaluation error into a sanitized script error.
fn classify(error: &EvalAltResult) -> ScriptError {
    match error {
        EvalAltResult::ErrorTooManyOperations(_)
        | EvalAltResult::ErrorTooManyVariables(_)
        | EvalAltResult::ErrorTooManyModules(_)
        | EvalAltResult::ErrorStackOverflow(_)
        | EvalAltResult::ErrorDataTooLarge(_, _)
        | EvalAltResult::ErrorTerminated(_, _) => ScriptError::Budget,
        EvalAltResult::ErrorInFunctionCall(_, _, inner, _)
        | EvalAltResult::ErrorInModule(_, inner, _) => classify(inner),
        _ => ScriptError::Runtime,
    }
}

/// Returns the Rhai map for one event.
fn event_map(event: &EntityEvent) -> Dynamic {
    let mut map = Map::new();
    map.insert("event_id".into(), Dynamic::from(event.event_id.clone()));
    map.insert("entity_id".into(), Dynamic::from(event.entity_id.clone()));
    map.insert("kind".into(), Dynamic::from(kind_name(event.kind)));
    map.insert(
        "schemas".into(),
        Dynamic::from_array(event.schemas.iter().cloned().map(Dynamic::from).collect()),
    );
    map.insert(
        "changed".into(),
        Dynamic::from_array(
            event
                .changed
                .iter()
                .map(|change| {
                    let mut item = Map::new();
                    item.insert("key".into(), Dynamic::from(change.key.clone()));
                    item.insert("before".into(), json_value(&change.old));
                    item.insert("after".into(), json_value(&change.new));
                    Dynamic::from_map(item)
                })
                .collect(),
        ),
    );
    map.insert(
        "correlation_id".into(),
        Dynamic::from(event.correlation_id.clone()),
    );
    map.insert(
        "causation_id".into(),
        match &event.causation_id {
            Some(value) => Dynamic::from(value.clone()),
            None => Dynamic::UNIT,
        },
    );
    Dynamic::from_map(map)
}

/// Returns the Rhai value for one optional entity.
fn entity_value(entity: Option<&Entity>) -> Dynamic {
    let Some(entity) = entity else {
        return Dynamic::UNIT;
    };
    let mut map = Map::new();
    map.insert("id".into(), Dynamic::from(entity.id.clone()));
    map.insert("version".into(), Dynamic::from(entity.version));
    map.insert(
        "schemas".into(),
        Dynamic::from_array(
            entity
                .schemas
                .iter()
                .map(|schema| {
                    let mut item = Map::new();
                    item.insert("id".into(), Dynamic::from(schema.id.clone()));
                    item.insert("version".into(), Dynamic::from(schema.version));
                    Dynamic::from_map(item)
                })
                .collect(),
        ),
    );
    let mut attributes = Map::new();
    for (key, value) in &entity.attributes {
        attributes.insert(key.clone().into(), json_to_dynamic(&value.as_json()));
    }
    map.insert("attributes".into(), Dynamic::from_map(attributes));
    Dynamic::from_map(map)
}

/// Returns the lowercase wire name of one event kind.
fn kind_name(kind: EntityEventKind) -> &'static str {
    match kind {
        EntityEventKind::Created => "created",
        EntityEventKind::Updated => "updated",
        EntityEventKind::Deleted => "deleted",
        EntityEventKind::SchemaApplied => "schema_applied",
        EntityEventKind::SchemaRemoved => "schema_removed",
        EntityEventKind::Timer => "timer",
    }
}

/// Converts one optional JSON value into a Rhai value.
fn json_value(value: &Option<serde_json::Value>) -> Dynamic {
    match value {
        Some(value) => json_to_dynamic(value),
        None => Dynamic::UNIT,
    }
}

/// Converts one plain JSON value into a Rhai value.
fn json_to_dynamic(value: &serde_json::Value) -> Dynamic {
    match value {
        serde_json::Value::Null => Dynamic::UNIT,
        serde_json::Value::Bool(value) => Dynamic::from(*value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Dynamic::from(value)
            } else if let Some(value) = value.as_u64() {
                match i64::try_from(value) {
                    Ok(value) => Dynamic::from(value),
                    Err(_) => value.to_string().into(),
                }
            } else {
                match value.as_f64() {
                    Some(value) => Dynamic::from(value),
                    None => Dynamic::UNIT,
                }
            }
        }
        serde_json::Value::String(value) => Dynamic::from(value.clone()),
        serde_json::Value::Array(values) => {
            Dynamic::from_array(values.iter().map(json_to_dynamic).collect())
        }
        serde_json::Value::Object(values) => {
            let mut map = Map::new();
            for (key, value) in values {
                map.insert(key.clone().into(), json_to_dynamic(value));
            }
            Dynamic::from_map(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eav::entity::AttributeValue;
    use crate::eav::schema::SchemaRef;
    use crate::records::AttributeChange;
    use std::collections::BTreeMap;

    fn engine() -> ScriptEngine {
        ScriptEngine::new(true)
    }

    fn entity(attributes: Vec<(&str, AttributeValue)>) -> Entity {
        Entity {
            id: "e1".to_string(),
            version: 3,
            schemas: vec![SchemaRef {
                id: "invoice".to_string(),
                version: 1,
            }],
            attributes: attributes
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect::<BTreeMap<_, _>>(),
            created_at: 1,
            updated_at: 2,
        }
    }

    fn event(kind: EntityEventKind, changed: Vec<AttributeChange>) -> EntityEvent {
        EntityEvent {
            event_id: "evt-1".to_string(),
            entity_id: "e1".to_string(),
            entity_version: 3,
            kind,
            schemas: vec!["invoice".to_string()],
            changed,
            actor: "alice".to_string(),
            causation_id: Some("evt-0".to_string()),
            causation_depth: 0,
            correlation_id: "req-1".to_string(),
            snapshot: None,
            occurred_at: 1_700_000_000,
        }
    }

    fn context<'a>(event: &'a EntityEvent, entity: Option<&'a Entity>) -> ScriptContext<'a> {
        ScriptContext {
            event,
            entity,
            now: 1_700_000_100,
        }
    }

    #[test]
    fn a_script_returns_true_and_false_on_the_inputs() {
        let subject = engine();
        let item = entity(vec![(
            "status",
            AttributeValue::String("urgent".to_string()),
        )]);
        let ev = event(EntityEventKind::Updated, Vec::new());
        let ctx = context(&ev, Some(&item));

        assert_eq!(
            subject.eval_bool(
                r#"event.kind == "updated" && entity.attributes.status == "urgent""#,
                &ctx
            ),
            Ok(true)
        );
        assert_eq!(
            subject.eval_bool(
                r#"event.kind == "updated" && entity.attributes.status == "normal""#,
                &ctx
            ),
            Ok(false)
        );
    }

    #[test]
    fn a_script_reads_the_changed_list_and_the_event_kind() {
        let subject = engine();
        let ev = event(
            EntityEventKind::Updated,
            vec![AttributeChange {
                key: "status".to_string(),
                old: Some(serde_json::json!("normal")),
                new: Some(serde_json::json!("urgent")),
            }],
        );
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(
                r#"event.changed[0].key == "status" && event.changed[0].before == "normal" && event.changed[0].after == "urgent""#,
                &ctx
            ),
            Ok(true)
        );
        assert_eq!(
            subject.eval_bool(r#"event.kind == "deleted""#, &ctx),
            Ok(false)
        );
    }

    #[test]
    fn a_script_reads_a_nested_attribute_and_a_timestamp() {
        let subject = engine();
        let item = entity(vec![
            (
                "meta",
                AttributeValue::Json(serde_json::json!({ "priority": 2 })),
            ),
            ("due", AttributeValue::Timestamp(1_700_000_000)),
        ]);
        let ev = event(EntityEventKind::Updated, Vec::new());
        let ctx = context(&ev, Some(&item));

        assert_eq!(
            subject.eval_bool(
                "entity.attributes.meta.priority == 2 && entity.attributes.due == 1700000000",
                &ctx
            ),
            Ok(true)
        );
    }

    #[test]
    fn a_deleted_event_can_compare_the_entity_with_unit() {
        let subject = engine();
        let ev = event(EntityEventKind::Deleted, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(r#"entity == () && event.kind == "deleted""#, &ctx),
            Ok(true)
        );
    }

    #[test]
    fn a_syntax_error_fails_compile() {
        let subject = engine();
        assert_eq!(subject.compile("let x = ;"), Err(ScriptError::Compile));
    }

    #[test]
    fn an_infinite_loop_fails_with_the_operation_budget() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool("let x = 0; while true { x += 1; } true", &ctx),
            Err(ScriptError::Budget)
        );
    }

    #[test]
    fn deep_recursion_fails_with_the_call_level_limit() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool("fn f(n) { f(n + 1) } f(0)", &ctx),
            Err(ScriptError::Budget)
        );
    }

    #[test]
    fn a_huge_string_fails_with_the_size_limit() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(
                r#"let s = "x"; while s.len() < 70000 { s += s; } true"#,
                &ctx
            ),
            Err(ScriptError::Budget)
        );
    }

    #[test]
    fn a_huge_array_fails_with_the_size_limit() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool("let a = []; while true { a.push(1); } true", &ctx),
            Err(ScriptError::Budget)
        );
    }

    #[test]
    fn a_non_boolean_result_fails_with_the_return_type_error() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(subject.eval_bool("42", &ctx), Err(ScriptError::ReturnType));
    }

    #[test]
    fn eval_and_import_are_unavailable() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(r#"eval("true")"#, &ctx),
            Err(ScriptError::Compile)
        );
        assert_eq!(
            subject.eval_bool(r#"import "other" as other; true"#, &ctx),
            Err(ScriptError::Compile)
        );
    }

    #[test]
    fn clock_sleep_and_random_helpers_are_unavailable() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool("timestamp()", &ctx),
            Err(ScriptError::Runtime)
        );
        assert_eq!(
            subject.eval_bool("sleep(1); true", &ctx),
            Err(ScriptError::Runtime)
        );
        assert_eq!(
            subject.eval_bool("rand(); true", &ctx),
            Err(ScriptError::Runtime)
        );
    }

    #[test]
    fn a_disabled_engine_rejects_compile_and_evaluation() {
        let subject = ScriptEngine::new(false);
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(subject.compile("true"), Err(ScriptError::Disabled));
        assert_eq!(subject.eval_bool("true", &ctx), Err(ScriptError::Disabled));
    }

    #[test]
    fn the_cache_returns_the_same_result_for_repeated_evaluations() {
        let subject = engine();
        let item = entity(vec![(
            "status",
            AttributeValue::String("urgent".to_string()),
        )]);
        let ev = event(EntityEventKind::Updated, Vec::new());
        let ctx = context(&ev, Some(&item));
        let source = r#"event.kind == "updated" && entity.attributes.status == "urgent""#;

        assert_eq!(subject.eval_bool(source, &ctx), Ok(true));
        assert_eq!(subject.cache_len(), 1);
        assert_eq!(subject.eval_bool(source, &ctx), Ok(true));
        assert_eq!(subject.cache_len(), 1);
    }

    #[test]
    fn the_cache_clears_when_it_reaches_the_capacity() {
        let subject = engine();
        for index in 0..=CACHE_CAPACITY {
            subject
                .compile(&format!("let value = {index}; true"))
                .unwrap();
        }
        assert_eq!(subject.cache_len(), 1);
    }

    #[test]
    fn a_source_larger_than_the_limit_is_rejected() {
        let subject = engine();
        let source = " ".repeat(MAX_SOURCE_BYTES + 1);
        assert_eq!(subject.compile(&source), Err(ScriptError::SourceTooLarge));
    }
}
