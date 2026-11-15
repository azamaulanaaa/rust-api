//! Sandboxed Rhai scripts.
//!
//! A condition script is a pure boolean expression.
//! It reads the event, the optional entity, and the current time.
//! It cannot read the store, write, call the network, read the clock, use
//! random values, load files, or evaluate more code.
//!
//! An action script runs when a rule action has kind `script`.
//! The action parameters hold the source: `{ "source": "<rhai>" }`.
//! An action script also gets a `host` value.
//! The host reads entities and stages create, update, and delete effects.
//! Nothing commits during the script.
//! The rule engine applies the staged effects and the execution marker in one
//! transaction after the script returns.
//!
//! # Host methods
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
//! The existing operation, call-depth, string, array, map, and source limits
//! still apply.
//!
//! Reads see committed state only.
//! A write that the script stages does not appear in a later read.
//!
//! The read capability set controls `get_entity` and both find methods.
//! A denied `get_entity` returns `()`.
//! A `get_entity` result holds only the attributes that the allowed pinned
//! schemas define.
//! A denied find returns the stable error `rule script read access denied`.
//! The write capability set controls every staged write.
//! A create must pin only schemas in the set.
//! An update may set only the attributes that the pinned schemas in the set
//! define.
//! A write that breaks these rules returns the stable error
//! `rule script write access denied`.
//! A delete requires that the entity pins at least one schema in the set.
//!
//! The host has no function for HTTP, files, the clock, random values, or
//! processes.
//! A script that calls an unknown function fails at evaluation.
//!
//! A condition script has no `host` value.
//! A condition that calls `host.get_entity` fails with an unknown-variable
//! error.
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
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rhai::packages::{
    ArithmeticPackage, BasicArrayPackage, BasicFnPackage, BasicIteratorPackage, BasicMapPackage,
    BasicMathPackage, BasicStringPackage, BitFieldPackage, LogicPackage, MoreStringPackage,
    Package,
};
use rhai::{AST, Array, Dynamic, Engine, EvalAltResult, Map, Position, Scope};
use thiserror::Error;
use tokio::runtime::Handle;

use crate::eav::entity::{AttributeValue, Entity, EntityStore};
use crate::eav::entity_error::EntityError;
use crate::eav::schema::{EffectiveSchema, SchemaRef};
use crate::records::{EntityEvent, EntityEventKind};
use crate::rules::effect::{EntityEffect, MAX_EFFECTS};
use crate::rules::script_host::{ScriptCapabilities, ScriptHostError, ScriptReadHost};

/// The action kind of a script action.
pub(crate) const SCRIPT_ACTION_KIND: &str = "script";

/// The largest accepted script source, in bytes.
pub(crate) const MAX_SOURCE_BYTES: usize = 64 * 1024;

/// The largest number of host read calls in one action evaluation.
pub(crate) const MAX_READ_CALLS: usize = 200;

/// The stable message for a read limit failure.
const READ_LIMIT_MESSAGE: &str = "rule script exceeded its read limit";

/// The stable message for an effect limit failure.
const EFFECT_LIMIT_MESSAGE: &str = "rule script exceeded its effect limit";

/// The stable message for a denied find call.
const READ_DENIED_MESSAGE: &str = "rule script read access denied";

/// The stable message for a denied write call.
const WRITE_DENIED_MESSAGE: &str = "rule script write access denied";

/// The stable message for an invalid host argument.
const INVALID_ARGUMENT_MESSAGE: &str = "rule script argument is not valid";

/// The stable message for a failed store operation.
const STORE_MESSAGE: &str = "rule script store operation failed";

/// The largest number of compiled scripts in the cache.
const CACHE_CAPACITY: usize = 256;

/// The maximum number of Rhai operations for one evaluation.
const MAX_OPERATIONS: u64 = 250_000;

/// The maximum number of Rhai call levels for one evaluation.
const MAX_CALL_LEVELS: usize = 64;

/// The maximum Rhai string size, in bytes.
const MAX_STRING_SIZE: usize = 256 * 1024;

/// The maximum Rhai array size.
const MAX_ARRAY_SIZE: usize = 10_000;

/// The maximum Rhai map size.
const MAX_MAP_SIZE: usize = 10_000;

/// The wall-time guard for one evaluation.
const WALL_TIME_GUARD: Duration = Duration::from_millis(200);

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
    /// The server disables scripts.
    #[error("rule scripts are disabled")]
    Disabled,
    /// The script source is larger than 64 KiB.
    #[error("rule script source is larger than 64 KiB")]
    SourceTooLarge,
    /// The script made more than 200 host read calls.
    #[error("rule script exceeded its read limit")]
    ReadLimit,
    /// The script staged more than 100 effects.
    #[error("rule script exceeded its effect limit")]
    EffectLimit,
    /// The script read a schema that its read capability does not allow.
    #[error("rule script read access denied")]
    ReadDenied,
    /// The script wrote a schema that its write capability does not allow.
    #[error("rule script write access denied")]
    WriteDenied,
}

/// The owned inputs of one script action evaluation.
///
/// `event` is always present.
/// `entity` is `None` for a deleted entity.
/// `now` is a Unix timestamp in seconds.
pub struct ScriptActionContext {
    /// The event that started the rule.
    pub event: EntityEvent,
    /// The current entity, or `None` when the entity is absent.
    pub entity: Option<Entity>,
    /// The current Unix time in seconds.
    pub now: i64,
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

/// The mutable state of one script host.
#[derive(Default)]
struct HostState {
    /// The number of read calls that the script made.
    reads: usize,
    /// The effects that the script staged.
    effects: Vec<EntityEffect>,
}

/// The data API for one script action.
///
/// The host reads entities through [`ScriptReadHost`] and stages effects.
/// It commits nothing.
/// The rule engine applies the staged effects after the script returns.
///
/// One host belongs to one rule and one event.
/// The host is `Clone`, `Send`, and `Sync`, because the Rhai engine uses the
/// `sync` feature.
#[derive(Clone)]
pub struct ScriptHost {
    /// The read-only host that enforces the read capability set.
    read_host: ScriptReadHost,
    /// The store that supplies the entity data.
    entities: EntityStore,
    /// The schema ids that the script may write.
    write: BTreeSet<String>,
    /// The staged effects and the read count.
    state: Arc<Mutex<HostState>>,
    /// The runtime handle for one blocking store call.
    runtime: Handle,
    /// The rule id for audit messages.
    rule_id: String,
    /// The event id for audit messages.
    event_id: String,
}

impl ScriptHost {
    /// Creates a host for one rule and one event.
    ///
    /// `read` holds the read capability set.
    /// `write` holds the write capability set.
    /// `runtime` is the handle of the async runtime.
    /// The host calls `block_on` on that handle from a blocking thread.
    pub fn new(
        entities: EntityStore,
        read: ScriptCapabilities,
        write: Vec<String>,
        rule_id: String,
        event_id: String,
        runtime: Handle,
    ) -> Self {
        Self {
            read_host: ScriptReadHost::new(entities.clone(), read),
            entities,
            write: write.into_iter().collect(),
            state: Arc::new(Mutex::new(HostState::default())),
            runtime,
            rule_id,
            event_id,
        }
    }

    /// Returns the effects that the script staged.
    pub(crate) fn take_effects(&self) -> Vec<EntityEffect> {
        std::mem::take(&mut self.lock_state().effects)
    }

    /// Returns one entity as a Rhai map or `()`.
    ///
    /// A denied read returns `()`, as
    /// [`ScriptReadHost::get_entity`](crate::rules::script_host::ScriptReadHost::get_entity)
    /// does.
    /// A missing entity also returns `()`.
    pub fn get_entity(&mut self, id: &str) -> Result<Dynamic, Box<EvalAltResult>> {
        self.count_read()?;
        match self.runtime.block_on(self.read_host.get_entity(id)) {
            Ok(Some(entity)) => Ok(json_to_dynamic(&entity)),
            Ok(None) => Ok(Dynamic::UNIT),
            Err(error) => Err(self.map_read_error(error)),
        }
    }

    /// Returns the ids that match one schema and one indexed attribute.
    ///
    /// A denied read returns the stable error
    /// `rule script read access denied`.
    pub fn find(
        &mut self,
        schema: &str,
        key: &str,
        value: Dynamic,
        limit: i64,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        self.count_read()?;
        let value = dynamic_to_json(&value).ok_or_else(|| host_error(INVALID_ARGUMENT_MESSAGE))?;
        let limit = usize::try_from(limit).unwrap_or(0);
        match self
            .runtime
            .block_on(self.read_host.find(schema, Some(key), Some(&value), limit))
        {
            Ok(ids) => Ok(ids_to_dynamic(ids)),
            Err(error) => Err(self.map_read_error(error)),
        }
    }

    /// Returns the ids of the entities that pin one schema.
    ///
    /// A denied read returns the stable error
    /// `rule script read access denied`.
    pub fn find_by_schema(
        &mut self,
        schema: &str,
        limit: i64,
    ) -> Result<Dynamic, Box<EvalAltResult>> {
        self.count_read()?;
        let limit = usize::try_from(limit).unwrap_or(0);
        match self
            .runtime
            .block_on(self.read_host.find_by_schema(schema, limit))
        {
            Ok(ids) => Ok(ids_to_dynamic(ids)),
            Err(error) => Err(self.map_read_error(error)),
        }
    }

    /// Stages one create.
    ///
    /// Every schema id must be in the write capability set.
    /// Every attribute must be one that the schemas define.
    /// The call reads no entity and commits nothing.
    pub fn create_entity(
        &mut self,
        id: &str,
        schemas: Array,
        attributes: Map,
    ) -> Result<(), Box<EvalAltResult>> {
        let schemas =
            strings_from_array(&schemas).ok_or_else(|| host_error(INVALID_ARGUMENT_MESSAGE))?;
        if schemas.is_empty() {
            return Err(host_error(INVALID_ARGUMENT_MESSAGE));
        }
        if schemas.iter().any(|schema| !self.write.contains(schema)) {
            return Err(host_error(WRITE_DENIED_MESSAGE));
        }
        let attributes = attributes_from_map(&attributes)?;
        self.require_create(&schemas, &attributes)?;
        self.stage(EntityEffect::Create {
            id: id.to_string(),
            schemas,
            attributes,
        })
    }

    /// Stages one update.
    ///
    /// The call reads the entity to check that every attribute in the patch is
    /// one that a pinned schema in the write capability set defines.
    /// The call commits nothing.
    pub fn update_entity(
        &mut self,
        id: &str,
        expected_version: i64,
        patch: Map,
    ) -> Result<(), Box<EvalAltResult>> {
        let expected_version =
            u64::try_from(expected_version).map_err(|_| host_error(INVALID_ARGUMENT_MESSAGE))?;
        let attributes = patch_from_map(&patch)?;
        self.require_update(id, &attributes)?;
        self.stage(EntityEffect::Update {
            id: id.to_string(),
            expected_version,
            attributes,
        })
    }

    /// Stages one delete.
    ///
    /// The call reads the entity to check that at least one pinned schema is in
    /// the write capability set.
    /// The call commits nothing.
    pub fn delete_entity(
        &mut self,
        id: &str,
        expected_version: i64,
    ) -> Result<(), Box<EvalAltResult>> {
        let expected_version =
            u64::try_from(expected_version).map_err(|_| host_error(INVALID_ARGUMENT_MESSAGE))?;
        self.require_write(id)?;
        self.stage(EntityEffect::Delete {
            id: id.to_string(),
            expected_version,
            force: false,
        })
    }

    /// Counts one read call and rejects a call above the read limit.
    fn count_read(&self) -> Result<(), Box<EvalAltResult>> {
        let mut state = self.lock_state();
        if state.reads >= MAX_READ_CALLS {
            return Err(host_error(READ_LIMIT_MESSAGE));
        }
        state.reads += 1;
        Ok(())
    }

    /// Stages one effect and rejects an effect above the effect limit.
    fn stage(&self, effect: EntityEffect) -> Result<(), Box<EvalAltResult>> {
        let mut state = self.lock_state();
        if state.effects.len() >= MAX_EFFECTS {
            return Err(host_error(EFFECT_LIMIT_MESSAGE));
        }
        state.effects.push(effect);
        Ok(())
    }

    /// Checks that a create writes only attributes of its schemas.
    ///
    /// The caller has already checked that every schema is in the write set.
    /// The call reads the effective attributes of the schemas.
    /// An attribute that no schema defines is a denied write.
    fn require_create(
        &self,
        schemas: &[String],
        attributes: &BTreeMap<String, AttributeValue>,
    ) -> Result<(), Box<EvalAltResult>> {
        let effective = self
            .runtime
            .block_on(self.entities.resolve_schemas(schemas))
            .map_err(|error| self.map_write_schema_error(error))?;
        let allowed = attribute_names(&effective);
        if attributes.keys().any(|key| !allowed.contains(key)) {
            return Err(host_error(WRITE_DENIED_MESSAGE));
        }
        Ok(())
    }

    /// Checks that a patch sets only attributes of the write set.
    ///
    /// The call keeps the pinned schemas that the write set allows.
    /// It reads the effective attributes of those schemas.
    /// An entity with no allowed pinned schema is a denied write.
    /// A patch attribute that no allowed schema defines is a denied write.
    /// The call reads committed state only.
    fn require_update(
        &self,
        id: &str,
        patch: &BTreeMap<String, Option<AttributeValue>>,
    ) -> Result<(), Box<EvalAltResult>> {
        let entity = self.load_for_write(id)?;
        let pinned: Vec<SchemaRef> = entity
            .schemas
            .into_iter()
            .filter(|schema| self.write.contains(&schema.id))
            .collect();
        if pinned.is_empty() {
            return Err(host_error(WRITE_DENIED_MESSAGE));
        }
        let effective = self
            .runtime
            .block_on(self.entities.resolve_refs(&pinned))
            .map_err(|error| self.map_write_schema_error(error))?;
        let allowed = attribute_names(&effective);
        if patch.keys().any(|key| !allowed.contains(key)) {
            return Err(host_error(WRITE_DENIED_MESSAGE));
        }
        Ok(())
    }

    /// Checks that the entity pins at least one schema in the write set.
    ///
    /// The call reads committed state only.
    /// A missing entity is a denied write, because no pinned schema can allow
    /// it.
    fn require_write(&self, id: &str) -> Result<(), Box<EvalAltResult>> {
        let entity = self.load_for_write(id)?;
        if entity
            .schemas
            .iter()
            .any(|schema| self.write.contains(&schema.id))
        {
            Ok(())
        } else {
            Err(host_error(WRITE_DENIED_MESSAGE))
        }
    }

    /// Loads one entity for a write check.
    ///
    /// A missing entity is a denied write.
    /// A store failure is a stable store error.
    fn load_for_write(&self, id: &str) -> Result<Entity, Box<EvalAltResult>> {
        match self.runtime.block_on(self.entities.get(id)) {
            Ok(Some(entity)) => Ok(entity),
            Ok(None) => Err(host_error(WRITE_DENIED_MESSAGE)),
            Err(error) => {
                tracing::warn!(
                    rule_id = %self.rule_id,
                    event_id = %self.event_id,
                    error = %error,
                    "script host store read failed"
                );
                Err(host_error(STORE_MESSAGE))
            }
        }
    }

    /// Maps one schema read error from a write check to a stable Rhai error.
    ///
    /// An unknown schema is a denied write.
    /// An invalid schema list is an invalid argument.
    /// Any other error is a stable store error.
    fn map_write_schema_error(&self, error: EntityError) -> Box<EvalAltResult> {
        match error {
            EntityError::UnknownSchema(_) => host_error(WRITE_DENIED_MESSAGE),
            EntityError::Invalid(_) => host_error(INVALID_ARGUMENT_MESSAGE),
            other => {
                tracing::warn!(
                    rule_id = %self.rule_id,
                    event_id = %self.event_id,
                    error = %other,
                    "script host schema read failed"
                );
                host_error(STORE_MESSAGE)
            }
        }
    }

    /// Maps one read host error to a stable Rhai error.
    fn map_read_error(&self, error: ScriptHostError) -> Box<EvalAltResult> {
        match error {
            ScriptHostError::Denied => host_error(READ_DENIED_MESSAGE),
            ScriptHostError::Invalid(message) => host_error(&message),
            ScriptHostError::Store(_) => {
                tracing::warn!(
                    rule_id = %self.rule_id,
                    event_id = %self.event_id,
                    "script host store read failed"
                );
                host_error(STORE_MESSAGE)
            }
        }
    }

    /// Locks the host state and recovers from a poisoned lock.
    fn lock_state(&self) -> MutexGuard<'_, HostState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
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
    /// The wall-time guard for one evaluation.
    ///
    /// [`ScriptEngine::new`] always uses [`WALL_TIME_GUARD`].
    /// A unit test can set another value with `with_wall_guard`.
    wall_guard: Duration,
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
        // Register the action host one time.
        // A condition script has no `host` value, so these methods are
        // unreachable from a condition.
        engine.register_type_with_name::<ScriptHost>("Host");
        engine.register_fn("get_entity", ScriptHost::get_entity);
        engine.register_fn("find", ScriptHost::find);
        engine.register_fn("find_by_schema", ScriptHost::find_by_schema);
        engine.register_fn("create_entity", ScriptHost::create_entity);
        engine.register_fn("update_entity", ScriptHost::update_entity);
        engine.register_fn("delete_entity", ScriptHost::delete_entity);
        Self {
            engine: Arc::new(engine),
            cache: Arc::new(Mutex::new(HashMap::new())),
            enabled,
            wall_guard: WALL_TIME_GUARD,
        }
    }

    /// Sets the wall-time guard for this engine.
    ///
    /// A unit test uses this method to keep the wall clock out of a functional
    /// test.
    /// Production code always uses [`WALL_TIME_GUARD`].
    #[cfg(test)]
    fn with_wall_guard(mut self, guard: Duration) -> Self {
        self.wall_guard = guard;
        self
    }

    /// Returns true when the server enables condition scripts.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Compiles a script and caches the AST.
    ///
    /// The call rejects a disabled engine, a source larger than 64 KiB, and a
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

        EVAL_DEADLINE.with(|deadline| deadline.set(Some(Instant::now() + self.wall_guard)));
        let result = self.engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast);
        EVAL_DEADLINE.with(|deadline| deadline.set(None));

        match result {
            Ok(value) => value.as_bool().map_err(|_| ScriptError::ReturnType),
            Err(error) => Err(classify(&error)),
        }
    }

    /// Evaluates one action script and returns its staged effects.
    ///
    /// The call compiles the script on a cache miss.
    /// It pushes the event, the optional entity, the time, and the `host`.
    /// A condition script never gets the `host`.
    /// Any script failure returns a sanitized [`ScriptError`].
    /// The call commits nothing.
    /// The caller applies the effects and the execution marker in one
    /// transaction.
    ///
    /// The caller must run this call on a blocking thread.
    /// A host method calls `block_on` on the runtime handle, so a call on an
    /// async worker thread would block the reactor.
    pub fn eval_action(
        &self,
        source: &str,
        ctx: &ScriptActionContext,
        host: ScriptHost,
    ) -> Result<Vec<EntityEffect>, ScriptError> {
        let ast = self.ast_for(source)?;
        let staged = host.clone();
        let mut scope = Scope::new();
        scope.push_constant("event", event_map(&ctx.event));
        scope.push_constant("entity", entity_value(ctx.entity.as_ref()));
        scope.push_constant("now", ctx.now);
        scope.push("host", host);

        EVAL_DEADLINE.with(|deadline| deadline.set(Some(Instant::now() + self.wall_guard)));
        let result = self.engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast);
        EVAL_DEADLINE.with(|deadline| deadline.set(None));

        match result {
            Ok(_) => Ok(staged.take_effects()),
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
        EvalAltResult::ErrorRuntime(value, _) => match value.clone().into_string() {
            Ok(message) if message == READ_LIMIT_MESSAGE => ScriptError::ReadLimit,
            Ok(message) if message == EFFECT_LIMIT_MESSAGE => ScriptError::EffectLimit,
            Ok(message) if message == READ_DENIED_MESSAGE => ScriptError::ReadDenied,
            Ok(message) if message == WRITE_DENIED_MESSAGE => ScriptError::WriteDenied,
            _ => ScriptError::Runtime,
        },
        _ => ScriptError::Runtime,
    }
}

/// Returns one stable Rhai runtime error.
fn host_error(message: &str) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(Dynamic::from(message.to_string()), Position::NONE).into()
}

/// Converts one Rhai array of strings into a string list.
fn strings_from_array(array: &Array) -> Option<Vec<String>> {
    array
        .iter()
        .map(|item| item.clone().into_string().ok())
        .collect()
}

/// Converts one Rhai map into entity attributes.
///
/// A plain string becomes a string attribute.
/// A boolean becomes a boolean attribute.
/// An integer becomes an integer attribute.
/// A float becomes a float attribute.
/// An array, an object, or `()` becomes a JSON attribute.
fn attributes_from_map(map: &Map) -> Result<BTreeMap<String, AttributeValue>, Box<EvalAltResult>> {
    let mut attributes = BTreeMap::new();
    for (key, value) in map {
        let json = dynamic_to_json(value).ok_or_else(|| host_error(INVALID_ARGUMENT_MESSAGE))?;
        attributes.insert(key.to_string(), json_to_attribute(json));
    }
    Ok(attributes)
}

/// Converts one Rhai map into an update patch.
///
/// A `()` value removes the attribute.
/// Any other value sets the attribute.
fn patch_from_map(
    map: &Map,
) -> Result<BTreeMap<String, Option<AttributeValue>>, Box<EvalAltResult>> {
    let mut attributes = BTreeMap::new();
    for (key, value) in map {
        let value = if value.is_unit() {
            None
        } else {
            let json =
                dynamic_to_json(value).ok_or_else(|| host_error(INVALID_ARGUMENT_MESSAGE))?;
            Some(json_to_attribute(json))
        };
        attributes.insert(key.to_string(), value);
    }
    Ok(attributes)
}

/// Returns the attribute names that the effective schemas define.
fn attribute_names(effective: &[EffectiveSchema]) -> BTreeSet<String> {
    effective
        .iter()
        .flat_map(|schema| schema.attributes.keys().cloned())
        .collect()
}

/// Converts one Rhai value into a plain JSON value.
fn dynamic_to_json(value: &Dynamic) -> Option<serde_json::Value> {
    if value.is_unit() {
        return Some(serde_json::Value::Null);
    }
    if let Ok(value) = value.as_bool() {
        return Some(serde_json::Value::Bool(value));
    }
    if let Ok(value) = value.as_int() {
        return Some(serde_json::Value::Number(value.into()));
    }
    if let Ok(value) = value.as_float() {
        return serde_json::Number::from_f64(value).map(serde_json::Value::Number);
    }
    if let Ok(value) = value.clone().into_string() {
        return Some(serde_json::Value::String(value));
    }
    if let Some(array) = value.clone().try_cast::<Array>() {
        let mut values = Vec::with_capacity(array.len());
        for item in &array {
            values.push(dynamic_to_json(item)?);
        }
        return Some(serde_json::Value::Array(values));
    }
    if let Some(map) = value.clone().try_cast::<Map>() {
        let mut object = serde_json::Map::new();
        for (key, item) in &map {
            object.insert(key.to_string(), dynamic_to_json(item)?);
        }
        return Some(serde_json::Value::Object(object));
    }
    None
}

/// Converts one plain JSON value into an attribute value.
fn json_to_attribute(value: serde_json::Value) -> AttributeValue {
    match value {
        serde_json::Value::String(value) => AttributeValue::String(value),
        serde_json::Value::Bool(value) => AttributeValue::Boolean(value),
        serde_json::Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                AttributeValue::Integer(value)
            } else if let Some(value) = number.as_f64() {
                AttributeValue::Float(value)
            } else {
                AttributeValue::Json(serde_json::Value::Number(number))
            }
        }
        other => AttributeValue::Json(other),
    }
}

/// Converts one id list into a Rhai array.
fn ids_to_dynamic(ids: Vec<String>) -> Dynamic {
    Dynamic::from_array(ids.into_iter().map(Dynamic::from).collect())
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
    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::{AttributeValue, EntityDraft, WriteContext};
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft, SchemaRef, SchemaRegistry};
    use crate::records::AttributeChange;
    use std::collections::BTreeMap;

    fn engine() -> ScriptEngine {
        ScriptEngine::new(true)
    }

    fn attr(name: &str, ty: AttributeType, indexed: bool) -> AttributeDef {
        AttributeDef {
            name: name.to_string(),
            ty,
            required: false,
            indexed,
            unique: false,
            default: None,
        }
    }

    fn schema(id: &str, attrs: Vec<AttributeDef>) -> SchemaDraft {
        SchemaDraft {
            id: id.to_string(),
            extends: Vec::new(),
            attributes: attrs.into_iter().map(|a| (a.name.clone(), a)).collect(),
        }
    }

    /// Builds one action host and its store.
    ///
    /// The store has a `task` schema and a `secret` schema.
    async fn action_host(read: &[&str], write: &[&str]) -> (ScriptHost, EntityStore) {
        let registry =
            SchemaRegistry::new(build_test_store(&test_prefix("script-action-schema")).await);
        let raw = build_test_store(&test_prefix("script-action")).await;
        let store = EntityStore::new(raw, registry.clone());
        registry
            .publish(schema(
                "task",
                vec![
                    attr("status", AttributeType::String, true),
                    attr("total", AttributeType::Integer, true),
                ],
            ))
            .await
            .unwrap();
        registry
            .publish(schema(
                "secret",
                vec![attr("code", AttributeType::String, true)],
            ))
            .await
            .unwrap();
        let host = ScriptHost::new(
            store.clone(),
            ScriptCapabilities::new(read.iter().copied()).unwrap(),
            write.iter().map(|schema| (*schema).to_string()).collect(),
            "rule-1".to_string(),
            "evt-1".to_string(),
            Handle::current(),
        );
        (host, store)
    }

    async fn create_task(store: &EntityStore, id: &str, status: &str, total: i64) {
        store
            .create(
                EntityDraft {
                    id: id.to_string(),
                    schemas: vec!["task".to_string()],
                    attributes: BTreeMap::from([
                        (
                            "status".to_string(),
                            AttributeValue::String(status.to_string()),
                        ),
                        ("total".to_string(), AttributeValue::Integer(total)),
                    ]),
                },
                &WriteContext::new("tester"),
            )
            .await
            .unwrap();
    }

    /// Creates one entity that pins the `task` and `secret` schemas.
    async fn create_task_and_secret(store: &EntityStore, id: &str, status: &str, code: &str) {
        store
            .create(
                EntityDraft {
                    id: id.to_string(),
                    schemas: vec!["task".to_string(), "secret".to_string()],
                    attributes: BTreeMap::from([
                        (
                            "status".to_string(),
                            AttributeValue::String(status.to_string()),
                        ),
                        ("code".to_string(), AttributeValue::String(code.to_string())),
                    ]),
                },
                &WriteContext::new("tester"),
            )
            .await
            .unwrap();
    }

    /// Runs one action script on a blocking thread, as the engine does.
    async fn eval_action(
        subject: &ScriptEngine,
        host: ScriptHost,
        source: &str,
        event: &EntityEvent,
        entity: Option<&Entity>,
    ) -> Result<Vec<EntityEffect>, ScriptError> {
        let subject = subject.clone();
        let source = source.to_string();
        let ctx = ScriptActionContext {
            event: event.clone(),
            entity: entity.cloned(),
            now: 1_700_000_100,
        };
        tokio::task::spawn_blocking(move || subject.eval_action(&source, &ctx, host))
            .await
            .expect("the blocking evaluation must finish")
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
                r#"let s = "x"; while s.len() < 270000 { s += s; } true"#,
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
    fn a_user_function_returns_the_same_result_on_each_call() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(
                "fn area(width, height) { width * height } area(6, 7) == 42 && area(3, 5) == 15",
                &ctx
            ),
            Ok(true)
        );
    }

    #[test]
    fn trigonometry_roots_and_power_return_the_expected_values() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(
                r#"let s = sin(0.5);
let c = cos(0.5);
let r = sqrt(2.0);
let p = 2.0 ** 10.0;
abs(s - 0.479425538604203) < 0.000000001
    && abs(c - 0.8775825618903728) < 0.000000001
    && abs(r - 1.4142135623730951) < 0.000000001
    && abs(p - 1024.0) < 0.000000001"#,
                &ctx
            ),
            Ok(true)
        );
    }

    #[test]
    fn a_tax_function_uses_integer_cents_and_rounds() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(
                r#"fn tax_cents(income_cents) {
    let brackets = [
        #{ cap: 1_100_000, rate: 10 },
        #{ cap: 4_500_000, rate: 22 },
        #{ cap: 0, rate: 37 }
    ];
    let total = 0;
    let lower = 0;
    for b in brackets {
        if income_cents <= lower { break; }
        let upper = if b.cap == 0 { income_cents } else { b.cap };
        let slice = (if income_cents < upper { income_cents } else { upper }) - lower;
        if slice > 0 {
            total += (slice * b.rate + 50) / 100;
        }
        lower = upper;
        if b.cap == 0 { break; }
    }
    total
}
tax_cents(3_000_000) == 528_000 && tax_cents(5_000_000) == 1_043_000"#,
                &ctx
            ),
            Ok(true)
        );
    }

    #[test]
    fn a_projectile_loop_returns_the_expected_height() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(
                r#"fn height(v0, angle, g, h0, steps) {
    let vy = v0 * sin(angle);
    let flight = (vy + sqrt(vy * vy + 2.0 * g * h0)) / g;
    let dt = flight / steps;
    let t = 0.0;
    for i in 0..steps {
        t += dt;
    }
    h0 + vy * t - 0.5 * g * t * t
}
abs(height(20.0, 0.7, 9.81, 1.5, 100)) < 0.000000001"#,
                &ctx
            ),
            Ok(true)
        );
    }

    /// A calculation-heavy script finishes within the operation budget.
    ///
    /// The operation limit is the deterministic budget.
    /// The wall guard is a last-resort safety net, so this test sets a wide
    /// guard and does not measure the host clock.
    #[test]
    fn a_script_builds_and_sums_a_large_array() {
        let subject = engine().with_wall_guard(Duration::from_secs(5));
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(
                "let a = []; let total = 0; for i in 0..1000 { a.push(i); total += i; } a.len() == 1000 && total == 499500",
                &ctx
            ),
            Ok(true)
        );
    }

    /// The wall guard rejects a script that runs past its deadline.
    ///
    /// A zero guard expires the deadline before the first loop tick.
    /// The result therefore does not depend on host speed.
    /// The test proves that the guard stops a script and reports the budget
    /// error.
    #[test]
    fn the_wall_guard_stops_a_script_that_runs_past_the_deadline() {
        let subject = engine().with_wall_guard(Duration::ZERO);
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool(
                "let total = 0; for i in 0..100 { total += i; } total == 4950",
                &ctx
            ),
            Err(ScriptError::Budget)
        );
    }

    #[test]
    fn a_loop_above_the_operation_budget_fails() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        assert_eq!(
            subject.eval_bool("let i = 0; while i < 300000 { i += 1; } true", &ctx),
            Err(ScriptError::Budget)
        );
    }

    #[test]
    fn a_source_above_sixty_four_kib_fails_with_the_source_size_error() {
        let subject = engine();
        let source = " ".repeat(64 * 1024 + 1);

        assert_eq!(subject.compile(&source), Err(ScriptError::SourceTooLarge));
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

    #[tokio::test]
    async fn an_action_script_reads_an_allowed_entity() {
        let subject = engine();
        let (host, store) = action_host(&["task"], &[]).await;
        create_task(&store, "e1", "open", 10).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let effects = eval_action(
            &subject,
            host,
            r#"let t = host.get_entity("e1"); if t == () { throw "missing"; } t.attributes.total == 10"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(effects, Ok(Vec::new()));
    }

    #[tokio::test]
    async fn the_find_methods_return_ids_in_order() {
        let subject = engine();
        let (host, store) = action_host(&["task"], &[]).await;
        create_task(&store, "a", "open", 1).await;
        create_task(&store, "b", "open", 2).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let effects = eval_action(
            &subject,
            host,
            r#"let all = host.find_by_schema("task", 10); if all.len() != 2 || all[0] != "a" || all[1] != "b" { throw "bad schema find"; } let open = host.find("task", "status", "open", 10); if open.len() != 2 || open[0] != "a" || open[1] != "b" { throw "bad attribute find"; }"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(effects, Ok(Vec::new()));
    }

    #[tokio::test]
    async fn a_denied_get_entity_returns_unit() {
        let subject = engine();
        let (host, store) = action_host(&["secret"], &[]).await;
        create_task(&store, "e1", "open", 10).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let effects = eval_action(
            &subject,
            host,
            r#"if host.get_entity("e1") != () { throw "denied read did not return unit"; }"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(effects, Ok(Vec::new()));
    }

    #[tokio::test]
    async fn a_denied_find_returns_the_read_denied_error() {
        let subject = engine();
        let (host, store) = action_host(&["secret"], &[]).await;
        create_task(&store, "e1", "open", 10).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let result = eval_action(
            &subject,
            host,
            r#"host.find("task", "status", "open", 10)"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(result, Err(ScriptError::ReadDenied));
    }

    #[tokio::test]
    async fn a_create_outside_the_write_set_is_denied() {
        let subject = engine();
        let (host, _store) = action_host(&["task"], &["secret"]).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let result = eval_action(
            &subject,
            host,
            r#"host.create_entity("new", ["task"], #{ status: "open", total: 1 })"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(result, Err(ScriptError::WriteDenied));
    }

    #[tokio::test]
    async fn an_update_outside_the_write_set_is_denied() {
        let subject = engine();
        let (host, store) = action_host(&["task"], &["secret"]).await;
        create_task(&store, "e1", "open", 10).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let result = eval_action(
            &subject,
            host,
            r#"host.update_entity("e1", 1, #{ status: "done" })"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(result, Err(ScriptError::WriteDenied));
    }

    #[tokio::test]
    async fn an_update_of_an_attribute_outside_the_write_set_is_denied() {
        let subject = engine();
        let (host, store) = action_host(&["task", "secret"], &["task"]).await;
        create_task_and_secret(&store, "e1", "open", "s1").await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let result = eval_action(
            &subject,
            host,
            r#"host.update_entity("e1", 1, #{ code: "s2" })"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(result, Err(ScriptError::WriteDenied));
    }

    #[tokio::test]
    async fn an_update_of_an_allowed_attribute_on_a_shared_entity_is_staged() {
        let subject = engine();
        let (host, store) = action_host(&["task", "secret"], &["task"]).await;
        create_task_and_secret(&store, "e1", "open", "s1").await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let effects = eval_action(
            &subject,
            host,
            r#"host.update_entity("e1", 1, #{ status: "done" })"#,
            &ev,
            None,
        )
        .await
        .expect("the script must finish");

        assert_eq!(
            effects,
            vec![EntityEffect::Update {
                id: "e1".to_string(),
                expected_version: 1,
                attributes: BTreeMap::from([(
                    "status".to_string(),
                    Some(AttributeValue::String("done".to_string())),
                )]),
            }]
        );
    }

    #[tokio::test]
    async fn a_create_of_an_attribute_outside_the_write_set_is_denied() {
        let subject = engine();
        let (host, _store) = action_host(&["task"], &["task"]).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let result = eval_action(
            &subject,
            host,
            r#"host.create_entity("new", ["task"], #{ code: "s1" })"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(result, Err(ScriptError::WriteDenied));
    }

    #[tokio::test]
    async fn a_delete_outside_the_write_set_is_denied() {
        let subject = engine();
        let (host, store) = action_host(&["task"], &["secret"]).await;
        create_task(&store, "e1", "open", 10).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let result = eval_action(&subject, host, r#"host.delete_entity("e1", 1)"#, &ev, None).await;

        assert_eq!(result, Err(ScriptError::WriteDenied));
    }

    #[tokio::test]
    async fn staged_writes_are_not_visible_to_a_later_read() {
        let subject = engine();
        let (host, _store) = action_host(&["task"], &["task"]).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let effects = eval_action(
            &subject,
            host,
            r#"host.create_entity("new", ["task"], #{ status: "open", total: 1 }); if host.get_entity("new") != () { throw "staged write is visible"; }"#,
            &ev,
            None,
        )
        .await
        .expect("the script must finish");

        assert_eq!(effects.len(), 1);
        assert!(matches!(effects[0], EntityEffect::Create { .. }));
    }

    #[tokio::test]
    async fn the_read_limit_stops_the_two_hundred_and_first_call() {
        let subject = engine();
        let (host, store) = action_host(&["task"], &[]).await;
        create_task(&store, "e1", "open", 10).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let result = eval_action(
            &subject,
            host,
            r#"let i = 0; while i < 201 { host.get_entity("e1"); i += 1; }"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(result, Err(ScriptError::ReadLimit));
    }

    #[tokio::test]
    async fn the_effect_limit_stops_the_hundred_and_first_effect() {
        let subject = engine();
        let (host, _store) = action_host(&[], &["task"]).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let result = eval_action(
            &subject,
            host,
            r#"let i = 0; while i < 101 { host.create_entity("x", ["task"], #{ status: "open", total: 1 }); i += 1; }"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(result, Err(ScriptError::EffectLimit));
    }

    #[test]
    fn a_condition_script_cannot_reach_the_host() {
        let subject = engine();
        let ev = event(EntityEventKind::Created, Vec::new());
        let ctx = context(&ev, None);

        let result = subject.eval_bool(r#"host.get_entity("e1") == ()"#, &ctx);

        assert_eq!(result, Err(ScriptError::Runtime));
    }

    #[tokio::test]
    async fn an_http_function_name_is_unknown() {
        let subject = engine();
        let (host, _store) = action_host(&[], &[]).await;
        let ev = event(EntityEventKind::Created, Vec::new());

        let result = eval_action(
            &subject,
            host,
            r#"http_get("https://example.test")"#,
            &ev,
            None,
        )
        .await;

        assert_eq!(result, Err(ScriptError::Runtime));
    }
}
