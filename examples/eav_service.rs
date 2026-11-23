//! Example: a small EAV service over an in-memory store.
//!
//! The example publishes two schemas.
//! It creates entities, updates one entity, queries an indexed attribute, and
//! pages the entity list.
//! The page method is the same cursor that `/eav/sync/snapshot` uses.
//! The example needs no S3 bucket and no network.
//!
//! Run with `cargo run --example eav_service`.

use std::collections::BTreeMap;

use rust_api::db::build_scratch_store;
use rust_api::eav::entity::{AttributeValue, EntityDraft, EntityPatch, EntityStore, WriteContext};
use rust_api::eav::schema::{AttributeDef, AttributeType, SchemaDraft, SchemaRegistry};

/// Builds one attribute definition.
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

/// Builds one schema draft.
fn schema(id: &str, extends: &[&str], attrs: Vec<AttributeDef>) -> SchemaDraft {
    SchemaDraft {
        id: id.to_string(),
        extends: extends.iter().map(|value| value.to_string()).collect(),
        attributes: attrs.into_iter().map(|a| (a.name.clone(), a)).collect(),
    }
}

/// Builds one entity draft.
fn draft(id: &str, schemas: &[&str], attrs: Vec<(&str, AttributeValue)>) -> EntityDraft {
    EntityDraft {
        id: id.to_string(),
        schemas: schemas.iter().map(|value| value.to_string()).collect(),
        attributes: attrs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    }
}

/// Returns the ids of a list of entities.
fn ids(entities: &[rust_api::eav::entity::Entity]) -> Vec<String> {
    entities.iter().map(|entity| entity.id.clone()).collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let prefix = format!("eav-example-{}", std::process::id());
    let store = build_scratch_store(&prefix).await?;
    let schemas = SchemaRegistry::new(store.clone());
    let entities = EntityStore::new(store, schemas.clone());
    let actor = WriteContext::new("example");

    schemas
        .publish(schema(
            "person",
            &[],
            vec![attr("name", AttributeType::String, true)],
        ))
        .await?;
    schemas
        .publish(schema(
            "employee",
            &["person"],
            vec![
                attr("team", AttributeType::String, true),
                attr("title", AttributeType::String, false),
                attr("manager", AttributeType::EntityRef, false),
            ],
        ))
        .await?;
    println!("published: person v1, employee v1 (employee extends person)");

    for (id, name) in [("m1", "Ada"), ("m2", "Grace")] {
        entities
            .create(
                draft(
                    id,
                    &["person"],
                    vec![("name", AttributeValue::String(name.to_string()))],
                ),
                &actor,
            )
            .await?;
    }

    let rows = [
        ("e1", "Lin", "platform", "m1", "Engineer"),
        ("e2", "Sam", "platform", "m2", "Engineer"),
        ("e3", "Nia", "support", "m1", "Support Lead"),
    ];
    for (id, name, team, manager, title) in rows {
        entities
            .create(
                draft(
                    id,
                    &["employee"],
                    vec![
                        ("name", AttributeValue::String(name.to_string())),
                        ("team", AttributeValue::String(team.to_string())),
                        ("manager", AttributeValue::EntityRef(manager.to_string())),
                        ("title", AttributeValue::String(title.to_string())),
                    ],
                ),
                &actor,
            )
            .await?;
    }
    println!("created: 2 people, 3 employees");

    let patch = EntityPatch {
        attributes: [(
            "title".to_string(),
            Some(AttributeValue::String("Staff Engineer".to_string())),
        )]
        .into_iter()
        .collect::<BTreeMap<_, _>>(),
    };
    let change = entities.update("e1", 1, patch, &actor).await?;
    let version = change
        .after
        .as_ref()
        .map(|entity| entity.version)
        .unwrap_or(0);
    println!("updated: e1 to version {version}");

    let (matches, next) = entities
        .list_by_attribute_after(
            "team",
            &AttributeValue::String("platform".to_string()),
            10,
            None,
        )
        .await?;
    println!("query team=platform: {:?} next={next:?}", ids(&matches));

    let (first, mut cursor) = entities.list_after(2, None).await?;
    let mut pages = 1;
    println!("page 1: {:?}", ids(&first));
    while let Some(after) = cursor {
        let (page, next) = entities.list_after(2, Some(&after)).await?;
        pages += 1;
        println!("page {pages}: {:?}", ids(&page));
        cursor = next;
    }
    println!("paged {pages} pages with the entity key cursor");

    Ok(())
}
