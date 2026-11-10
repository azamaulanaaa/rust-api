//! Criterion benchmarks for the EAV hot paths.
//!
//! Each group builds an in-memory scratch store with a unique prefix.
//! The prefix combines the process id and a counter.
//! Setup runs outside the timed loop.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{BatchSize, Criterion, black_box};
use oxkv::GetSet as _;
use rust_api::db::build_scratch_store;
use rust_api::eav::entity::{AttributeValue, EntityDraft, EntityStore, WriteContext};
use rust_api::eav::schema::{AttributeDef, AttributeType, SchemaDraft, SchemaRegistry};
use tokio::runtime::{Builder, Runtime};

/// The schema id that every group publishes.
const SCHEMA_ID: &str = "bench-person";

/// The indexed string attribute that every group writes.
const INDEXED_ATTRIBUTE: &str = "name";

/// Returns a unique store prefix for one group.
fn next_prefix(group: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{group}-{}-{count}", std::process::id())
}

/// Returns the draft of the schema that every group publishes.
fn schema_draft() -> SchemaDraft {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        INDEXED_ATTRIBUTE.to_string(),
        AttributeDef {
            name: INDEXED_ATTRIBUTE.to_string(),
            ty: AttributeType::String,
            required: true,
            indexed: true,
            unique: false,
            default: None,
        },
    );
    SchemaDraft {
        id: SCHEMA_ID.to_string(),
        extends: Vec::new(),
        attributes,
    }
}

/// Returns one entity draft with a required indexed string attribute.
fn entity_draft(id: String, value: &str) -> EntityDraft {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        INDEXED_ATTRIBUTE.to_string(),
        AttributeValue::String(value.to_string()),
    );
    EntityDraft {
        id,
        schemas: vec![SCHEMA_ID.to_string()],
        attributes,
    }
}

/// Builds a store and registry, and publishes the benchmark schema.
async fn fresh_store(prefix: &str) -> (EntityStore, SchemaRegistry) {
    let store = build_scratch_store(prefix).await;
    let schemas = SchemaRegistry::new(store.clone());
    schemas
        .publish(schema_draft())
        .await
        .unwrap_or_else(|error| panic!("schema publish failed: {error}"));
    let entities = EntityStore::new(store, schemas.clone());
    (entities, schemas)
}

/// Creates `count` entities with distinct ids and the same attribute value.
async fn seed_entities(entities: &EntityStore, count: usize) {
    let ctx = WriteContext::new("bench");
    for index in 0..count {
        entities
            .create(entity_draft(format!("e{index:04}"), "same"), &ctx)
            .await
            .unwrap_or_else(|error| panic!("seed create failed: {error}"));
    }
}

/// Builds a current-thread runtime for the async routines.
fn current_thread_runtime() -> Runtime {
    Builder::new_current_thread()
        .build()
        .unwrap_or_else(|error| panic!("runtime build failed: {error}"))
}

/// Benchmarks the creation of one entity against a published schema.
fn bench_entity_create(criterion: &mut Criterion) {
    let runtime = current_thread_runtime();
    let prefix = next_prefix("entity-create");
    let (entities, _schemas) = runtime.block_on(fresh_store(&prefix));
    let ctx = WriteContext::new("bench");
    let next_id = AtomicU64::new(0);

    let mut group = criterion.benchmark_group("entity/create");
    group.bench_function("one", |b| {
        b.to_async(&runtime).iter_batched(
            || {
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                entity_draft(format!("create-e{id:08}"), "new")
            },
            |draft| entities.create(draft, black_box(&ctx)),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// Benchmarks the read of one existing entity by id.
fn bench_entity_get(criterion: &mut Criterion) {
    let runtime = current_thread_runtime();
    let prefix = next_prefix("entity-get");
    let (entities, _schemas) = runtime.block_on(fresh_store(&prefix));
    let ctx = WriteContext::new("bench");
    let id = "get-target".to_string();
    runtime
        .block_on(entities.create(entity_draft(id.clone(), "same"), &ctx))
        .unwrap_or_else(|error| panic!("get target create failed: {error}"));

    let mut group = criterion.benchmark_group("entity/get");
    group.bench_function("one", |b| {
        b.to_async(&runtime).iter(|| entities.get(black_box(&id)));
    });
    group.finish();
}

/// Benchmarks one page of 100 entities from a store with 1000 entities.
fn bench_entity_list_after(criterion: &mut Criterion) {
    let runtime = current_thread_runtime();
    let prefix = next_prefix("entity-list-after");
    let (entities, _schemas) = runtime.block_on(fresh_store(&prefix));
    runtime.block_on(seed_entities(&entities, 1_000));
    runtime
        .block_on(entities.list_after(1, None))
        .unwrap_or_else(|error| panic!("entity index warm up failed: {error}"));

    let mut group = criterion.benchmark_group("entity/list_after");
    group.bench_function("100_of_1000", |b| {
        b.to_async(&runtime).iter(|| entities.list_after(100, None));
    });
    group.finish();
}

/// Benchmarks an indexed attribute query over 1000 entities.
fn bench_entity_query_by_attribute(criterion: &mut Criterion) {
    let runtime = current_thread_runtime();
    let prefix = next_prefix("entity-query-by-attribute");
    let (entities, _schemas) = runtime.block_on(fresh_store(&prefix));
    runtime.block_on(seed_entities(&entities, 1_000));
    let value = AttributeValue::String("same".to_string());
    runtime
        .block_on(entities.list_by_attribute_after(INDEXED_ATTRIBUTE, &value, 1, None))
        .unwrap_or_else(|error| panic!("attribute index warm up failed: {error}"));

    let mut group = criterion.benchmark_group("entity/query_by_attribute");
    group.bench_function("100_of_1000", |b| {
        b.to_async(&runtime).iter(|| {
            entities.list_by_attribute_after(INDEXED_ATTRIBUTE, black_box(&value), 100, None)
        });
    });
    group.finish();
}

/// Benchmarks an effective schema lookup that is already cached.
fn bench_schema_effective(criterion: &mut Criterion) {
    let runtime = current_thread_runtime();
    let prefix = next_prefix("schema-effective");
    let (_entities, schemas) = runtime.block_on(fresh_store(&prefix));
    let cached = runtime
        .block_on(schemas.effective(SCHEMA_ID, 1))
        .unwrap_or_else(|error| panic!("effective warm up failed: {error}"))
        .unwrap_or_else(|| panic!("benchmark schema is missing"));
    let version = cached.version;

    let mut group = criterion.benchmark_group("schema/effective");
    group.bench_function("cached", |b| {
        b.to_async(&runtime)
            .iter(|| schemas.effective(SCHEMA_ID, black_box(version)));
    });
    group.finish();
}

/// Benchmarks the outbox count with 1000 pending rows.
fn bench_outbox_count(criterion: &mut Criterion) {
    let runtime = current_thread_runtime();
    let prefix = next_prefix("outbox-count");
    let store = runtime.block_on(build_scratch_store(&prefix));
    runtime.block_on(async {
        for index in 0..1_000u64 {
            store
                .set_bytes(&format!("outbox:bench-{index:08}"), b"")
                .await
                .unwrap_or_else(|error| panic!("outbox seed failed: {error}"));
        }
    });
    let schemas = SchemaRegistry::new(store.clone());
    let entities = EntityStore::new(store, schemas);

    let mut group = criterion.benchmark_group("outbox/count");
    group.bench_function("1000_rows", |b| {
        b.to_async(&runtime).iter(|| entities.outbox_count());
    });
    group.finish();
}

/// Runs every benchmark group.
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_entity_create(&mut criterion);
    bench_entity_get(&mut criterion);
    bench_entity_list_after(&mut criterion);
    bench_entity_query_by_attribute(&mut criterion);
    bench_schema_effective(&mut criterion);
    bench_outbox_count(&mut criterion);
    criterion.final_summary();
}
