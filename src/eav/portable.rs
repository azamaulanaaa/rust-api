//! Portable export, import, index rebuild, and restore checks for EAV data.
//!
//! # File format
//!
//! The format is line-oriented JSON.
//! Each line holds one JSON object with a `kind` field.
//! The lines appear in this order:
//!
//! 1. One `header` line with the format number.
//! 2. Zero or more `schema` lines. Each line holds one [`SchemaDef`].
//! 3. Zero or more `entity` lines. Each line holds one [`Entity`].
//! 4. Zero or more `rule` lines. Each line holds one [`Rule`].
//! 5. One `end` line with the record counts.
//!
//! The format number is [`FORMAT_VERSION`].
//! A schema line keeps the exact version and the pinned parent versions.
//! An entity line keeps the exact version, the pinned schema versions, and the
//! timestamps.
//! A rule line keeps the exact version and the timestamps.
//! The import checks the number in the header before it reads a record.
//! The import checks the counts in the end line after the last record.
//!
//! # Import safety
//!
//! The import accepts an empty prefix only.
//! It validates every record before it writes any key.
//! It writes the schemas, then the rules, then the entities.
//! A validation failure removes the keys of the earlier steps.
//! A version conflict stops the import before the first write.
//!
//! The import writes no entity event and no outbox row.
//! A restore must not replay the history of the source prefix.
//!
//! # Restore checks
//!
//! [`validate`] reads the stored data and reports these problems:
//!
//! - An entity pins a schema version that is absent.
//! - A unique claim is missing, stale, or shared.
//! - A reference names no stored entity.

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::eav::entity::{
    DanglingRefIssue, Entity, EntityStore, IndexValidationReport, MissingSchemaIssue,
    RebuildReport, UniqueClaimIssue,
};
use crate::eav::entity_error::EntityError;
use crate::eav::error::SchemaError;
use crate::eav::schema::{SchemaDef, SchemaRegistry};
use crate::rules::error::RuleError;
use crate::rules::rule::Rule;
use crate::rules::store::RuleStore;

/// The format number of the export file.
pub const FORMAT_VERSION: u32 = 1;

/// One line of a portable export file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Line {
    /// The first line of the file.
    Header {
        /// The format number. The import accepts [`FORMAT_VERSION`] only.
        format: u32,
    },
    /// One schema version.
    Schema {
        /// The exact schema record.
        schema: SchemaDef,
    },
    /// One entity.
    Entity {
        /// The exact entity record.
        entity: Entity,
    },
    /// One rule.
    Rule {
        /// The exact rule record.
        rule: Rule,
    },
    /// The last line of the file.
    End {
        /// The number of schema records.
        schemas: usize,
        /// The number of entity records.
        entities: usize,
        /// The number of rule records.
        rules: usize,
    },
}

/// An error from a portable export, import, or restore check.
#[derive(Debug, thiserror::Error)]
pub enum PortableError {
    /// The file could not be read or written.
    #[error("cannot access the export file: {0}")]
    Io(#[from] std::io::Error),
    /// One line is not valid JSON.
    #[error("line {line} is not valid JSON: {source}")]
    Json {
        /// The 1-based line number.
        line: usize,
        /// The decode failure.
        source: serde_json::Error,
    },
    /// One record could not be encoded as JSON.
    #[error("cannot encode an export record: {0}")]
    Encode(serde_json::Error),
    /// One line holds a record that the import cannot accept.
    #[error("line {line}: {message}")]
    Invalid {
        /// The 1-based line number.
        line: usize,
        /// A short description of the problem.
        message: String,
    },
    /// The schema store rejected a record.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// The entity store rejected a record.
    #[error(transparent)]
    Entity(#[from] EntityError),
    /// The rule store rejected a record.
    #[error(transparent)]
    Rule(#[from] RuleError),
}

/// The counts from one portable export.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportReport {
    /// The number of schema records.
    pub schemas: usize,
    /// The number of entity records.
    pub entities: usize,
    /// The number of rule records.
    pub rules: usize,
}

/// The counts from one portable import.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// The number of schema records that the import wrote.
    pub schemas: usize,
    /// The number of entity records that the import wrote.
    pub entities: usize,
    /// The number of rule records that the import wrote.
    pub rules: usize,
}

/// The result of one restore check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationReport {
    /// The number of stored schema versions.
    pub schemas: usize,
    /// The number of stored entities.
    pub entities: usize,
    /// The number of stored rules.
    pub rules: usize,
    /// The entities that pin an absent schema version.
    pub missing_schemas: Vec<MissingSchemaIssue>,
    /// The references that name no stored entity.
    pub dangling_refs: Vec<DanglingRefIssue>,
    /// The unique claims that fail the check.
    pub unique_claim_issues: Vec<UniqueClaimIssue>,
    /// The entities whose pinned schemas conflict.
    pub schema_conflicts: Vec<String>,
}

impl ValidationReport {
    /// Returns true when the check found no problem.
    pub fn is_ok(&self) -> bool {
        self.missing_schemas.is_empty()
            && self.dangling_refs.is_empty()
            && self.unique_claim_issues.is_empty()
            && self.schema_conflicts.is_empty()
    }
}

/// Writes the stored schemas, entities, and rules to `out`.
///
/// The call writes the schemas in id and version order.
/// It writes the entities in id order, one page at a time.
/// It writes the rules in the order of the rule store.
/// The result holds the record counts.
pub async fn export<W: Write>(
    schemas: &SchemaRegistry,
    entities: &EntityStore,
    rules: &RuleStore,
    out: &mut W,
) -> Result<ExportReport, PortableError> {
    write_line(
        out,
        &Line::Header {
            format: FORMAT_VERSION,
        },
    )?;

    let schema_rows = schemas.versions().await?;
    for schema in &schema_rows {
        write_line(
            out,
            &Line::Schema {
                schema: schema.clone(),
            },
        )?;
    }

    let mut entity_count = 0;
    let mut after: Option<String> = None;
    loop {
        let (page, next) = entities.list_after(200, after.as_deref()).await?;
        for entity in page {
            write_line(
                out,
                &Line::Entity {
                    entity: entity.clone(),
                },
            )?;
            entity_count += 1;
        }
        match next {
            Some(cursor) => after = Some(cursor),
            None => break,
        }
    }

    let rule_rows = rules.list().await?;
    for rule in &rule_rows {
        write_line(out, &Line::Rule { rule: rule.clone() })?;
    }

    let report = ExportReport {
        schemas: schema_rows.len(),
        entities: entity_count,
        rules: rule_rows.len(),
    };
    write_line(
        out,
        &Line::End {
            schemas: report.schemas,
            entities: report.entities,
            rules: report.rules,
        },
    )?;
    out.flush()?;
    Ok(report)
}

/// Reads a portable export file into an empty target prefix.
///
/// The call checks that the target prefix is empty.
/// It validates the file and every record before it writes any key.
/// It writes the schemas, then the rules, then the entities.
/// A later failure removes the keys of the earlier steps.
/// The result holds the record counts.
pub async fn import<R: BufRead>(
    schemas: &SchemaRegistry,
    entities: &EntityStore,
    rules: &RuleStore,
    input: R,
) -> Result<ImportReport, PortableError> {
    let (schema_rows, entity_rows, rule_rows) = read_file(input)?;

    ensure_empty(schemas, entities, rules).await?;

    let schema_keys = schemas.import_versions(&schema_rows).await?;
    let rule_keys = match rules.import_rules(&rule_rows).await {
        Ok(keys) => keys,
        Err(error) => {
            schemas.remove_import_keys(&schema_keys).await?;
            return Err(error.into());
        }
    };
    if let Err(error) = entities.import_entities(&entity_rows).await {
        rules.remove_import_keys(&rule_keys).await?;
        schemas.remove_import_keys(&schema_keys).await?;
        return Err(error.into());
    }

    Ok(ImportReport {
        schemas: schema_rows.len(),
        entities: entity_rows.len(),
        rules: rule_rows.len(),
    })
}

/// Checks the stored schemas, entities, and rules.
///
/// The call reports an absent pinned schema version.
/// It reports a unique claim that is missing, stale, or shared.
/// It reports a reference that names no stored entity.
pub async fn validate(
    schemas: &SchemaRegistry,
    entities: &EntityStore,
    rules: &RuleStore,
) -> Result<ValidationReport, PortableError> {
    let index: IndexValidationReport = entities.validate_indexes().await?;
    Ok(ValidationReport {
        schemas: schemas.versions().await?.len(),
        entities: index.entities,
        rules: rules.list().await?.len(),
        missing_schemas: index.missing_schemas,
        dangling_refs: index.dangling_refs,
        unique_claim_issues: index.unique_claim_issues,
        schema_conflicts: index.schema_conflicts,
    })
}

/// Rewrites every index row of the stored entities.
///
/// The call is idempotent and resumable.
/// With `schema`, it rewrites only the entities that pin that schema.
pub async fn rebuild_indexes(
    entities: &EntityStore,
    schema: Option<&str>,
) -> Result<RebuildReport, EntityError> {
    entities.rebuild_indexes(schema).await
}

/// Writes one line to `out`.
fn write_line<W: Write>(out: &mut W, line: &Line) -> Result<(), PortableError> {
    serde_json::to_writer(&mut *out, line).map_err(PortableError::Encode)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// The records of one export file.
type FileRecords = (Vec<SchemaDef>, Vec<Entity>, Vec<Rule>);

/// Reads every record of one export file.
fn read_file<R: BufRead>(input: R) -> Result<FileRecords, PortableError> {
    let mut schemas = Vec::new();
    let mut entities = Vec::new();
    let mut rules = Vec::new();
    let mut header_seen = false;
    let mut end_seen = false;

    for (index, line) in input.lines().enumerate() {
        let number = index + 1;
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: Line = serde_json::from_str(line).map_err(|source| PortableError::Json {
            line: number,
            source,
        })?;
        if end_seen {
            return Err(PortableError::Invalid {
                line: number,
                message: "the end line must be the last line".to_string(),
            });
        }
        match record {
            Line::Header { format } => {
                if header_seen {
                    return Err(PortableError::Invalid {
                        line: number,
                        message: "the file has more than one header".to_string(),
                    });
                }
                if format != FORMAT_VERSION {
                    return Err(PortableError::Invalid {
                        line: number,
                        message: format!(
                            "format number {format} is not supported; this build reads {FORMAT_VERSION}"
                        ),
                    });
                }
                header_seen = true;
            }
            Line::Schema { schema } => {
                if !header_seen {
                    return Err(PortableError::Invalid {
                        line: number,
                        message: "a schema line comes before the header".to_string(),
                    });
                }
                schemas.push(schema);
            }
            Line::Entity { entity } => {
                if !header_seen {
                    return Err(PortableError::Invalid {
                        line: number,
                        message: "an entity line comes before the header".to_string(),
                    });
                }
                entities.push(entity);
            }
            Line::Rule { rule } => {
                if !header_seen {
                    return Err(PortableError::Invalid {
                        line: number,
                        message: "a rule line comes before the header".to_string(),
                    });
                }
                rules.push(rule);
            }
            Line::End {
                schemas: schema_count,
                entities: entity_count,
                rules: rule_count,
            } => {
                if !header_seen {
                    return Err(PortableError::Invalid {
                        line: number,
                        message: "the end line comes before the header".to_string(),
                    });
                }
                if schema_count != schemas.len()
                    || entity_count != entities.len()
                    || rule_count != rules.len()
                {
                    return Err(PortableError::Invalid {
                        line: number,
                        message: format!(
                            "the end line says {schema_count} schemas, {entity_count} entities, and {rule_count} rules; the file holds {} schemas, {} entities, and {} rules",
                            schemas.len(),
                            entities.len(),
                            rules.len()
                        ),
                    });
                }
                end_seen = true;
            }
        }
    }

    if !header_seen {
        return Err(PortableError::Invalid {
            line: 1,
            message: "the file has no header line".to_string(),
        });
    }
    if !end_seen {
        return Err(PortableError::Invalid {
            line: 1,
            message: "the file has no end line".to_string(),
        });
    }
    Ok((schemas, entities, rules))
}

/// Returns an error unless the three target stores hold no record.
async fn ensure_empty(
    schemas: &SchemaRegistry,
    entities: &EntityStore,
    rules: &RuleStore,
) -> Result<(), PortableError> {
    if !schemas.versions().await?.is_empty() {
        return Err(PortableError::Invalid {
            line: 1,
            message: "the target prefix is not empty: it holds schema records".to_string(),
        });
    }
    if !entities.is_empty().await? {
        return Err(PortableError::Invalid {
            line: 1,
            message: "the target prefix is not empty: it holds entity records".to_string(),
        });
    }
    if !rules.is_empty().await? {
        return Err(PortableError::Invalid {
            line: 1,
            message: "the target prefix is not empty: it holds rule records".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::db::{build_test_store, test_prefix};
    use crate::eav::entity::{AttributeValue, EntityDraft, WriteContext};
    use crate::eav::schema::{AttributeDef, AttributeType, SchemaDraft};
    use crate::records::EntityEventKind;
    use crate::rules::rule::{ActionRef, Condition, RuleDraft, RuleTrigger};
    use oxkv::{Direction, GetSet, OxKvStore};

    fn attr(name: &str, ty: AttributeType, indexed: bool, unique: bool) -> AttributeDef {
        AttributeDef {
            name: name.to_string(),
            ty,
            required: false,
            indexed,
            unique,
            default: None,
        }
    }

    fn draft(id: &str) -> SchemaDraft {
        SchemaDraft {
            id: id.to_string(),
            extends: Vec::new(),
            attributes: BTreeMap::new(),
        }
    }

    async fn triple() -> (SchemaRegistry, EntityStore, RuleStore, OxKvStore) {
        let entity_store = build_test_store(&test_prefix("eav-portable-entity")).await;
        let schemas =
            SchemaRegistry::new(build_test_store(&test_prefix("eav-portable-schema")).await);
        let entities = EntityStore::new(entity_store.clone(), schemas.clone());
        let rules = RuleStore::new(build_test_store(&test_prefix("eav-portable-rules")).await);
        (schemas, entities, rules, entity_store)
    }

    fn values(pairs: &[(&str, AttributeValue)]) -> BTreeMap<String, AttributeValue> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), value.clone()))
            .collect()
    }

    fn row_snapshot(rows: Vec<oxkv::KeyValue>) -> Vec<(String, Vec<u8>)> {
        rows.into_iter().map(|row| (row.key, row.value)).collect()
    }

    async fn index_rows(store: &OxKvStore) -> Vec<(String, Vec<u8>)> {
        let rows = store
            .gets_bytes(None, Direction::Next, (None, None))
            .await
            .expect("scan the entity store");
        row_snapshot(
            rows.into_iter()
                .filter(|row| {
                    row.key.starts_with("idx:attr:")
                        || row.key.starts_with("idx:attr-key:")
                        || row.key.starts_with("idx:unique:")
                        || row.key.starts_with("idx:unique-key:")
                        || row.key.starts_with("idx:time:")
                        || row.key.starts_with("idx:time-key:")
                })
                .collect(),
        )
    }

    #[tokio::test]
    async fn a_portable_export_round_trips_schemas_entities_and_rules() -> anyhow::Result<()> {
        let (schemas, entities, rules, _) = triple().await;
        let mut first = draft("person");
        first.attributes.insert(
            "name".to_string(),
            attr("name", AttributeType::String, true, false),
        );
        first.attributes.insert(
            "email".to_string(),
            attr("email", AttributeType::String, false, true),
        );
        schemas.publish(first).await?;

        let ctx = WriteContext::new("test");
        entities
            .create(
                EntityDraft {
                    id: "alice".to_string(),
                    schemas: vec!["person".to_string()],
                    attributes: values(&[
                        ("name", AttributeValue::String("Alice".to_string())),
                        (
                            "email",
                            AttributeValue::String("alice@example.test".to_string()),
                        ),
                    ]),
                },
                &ctx,
            )
            .await?;

        let mut second = draft("person");
        second.attributes.insert(
            "name".to_string(),
            attr("name", AttributeType::String, true, false),
        );
        second.attributes.insert(
            "email".to_string(),
            attr("email", AttributeType::String, false, true),
        );
        second.attributes.insert(
            "nickname".to_string(),
            attr("nickname", AttributeType::String, true, false),
        );
        schemas.publish(second).await?;
        entities
            .create(
                EntityDraft {
                    id: "bob".to_string(),
                    schemas: vec!["person".to_string()],
                    attributes: values(&[
                        ("name", AttributeValue::String("Bob".to_string())),
                        (
                            "email",
                            AttributeValue::String("bob@example.test".to_string()),
                        ),
                        ("nickname", AttributeValue::String("b".to_string())),
                    ]),
                },
                &ctx,
            )
            .await?;
        rules
            .upsert(RuleDraft {
                id: "greet".to_string(),
                name: "Greet".to_string(),
                enabled: true,
                priority: 1,
                trigger: RuleTrigger {
                    events: vec![EntityEventKind::Created],
                    schemas: vec!["person".to_string()],
                },
                condition: Condition::Always,
                action: ActionRef {
                    kind: "log".to_string(),
                    params: serde_json::json!({"level": "info"}),
                },
                capabilities: Default::default(),
            })
            .await?;

        let mut source_bytes = Vec::new();
        let exported = export(&schemas, &entities, &rules, &mut source_bytes).await?;
        assert_eq!(exported.schemas, 2, "two schema versions");
        assert_eq!(exported.entities, 2, "two entities");
        assert_eq!(exported.rules, 1, "one rule");

        let (target_schemas, target_entities, target_rules, _) = triple().await;
        let imported = import(
            &target_schemas,
            &target_entities,
            &target_rules,
            source_bytes.as_slice(),
        )
        .await?;
        assert_eq!(imported.schemas, 2);
        assert_eq!(imported.entities, 2);
        assert_eq!(imported.rules, 1);

        let mut target_bytes = Vec::new();
        export(
            &target_schemas,
            &target_entities,
            &target_rules,
            &mut target_bytes,
        )
        .await?;
        assert_eq!(
            source_bytes, target_bytes,
            "a round trip must keep every record and every pinned version"
        );

        let alice = target_entities
            .get("alice")
            .await?
            .expect("alice is present");
        assert_eq!(
            alice.schemas[0].version, 1,
            "alice keeps her pinned version"
        );
        let bob = target_entities.get("bob").await?.expect("bob is present");
        assert_eq!(bob.schemas[0].version, 2, "bob keeps his pinned version");

        let validation = validate(&target_schemas, &target_entities, &target_rules).await?;
        assert!(
            validation.is_ok(),
            "the restored prefix must pass: {validation:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_rebuild_restores_a_removed_index_row() -> anyhow::Result<()> {
        let (schemas, entities, _rules, raw) = triple().await;
        let mut schema = draft("item");
        schema.attributes.insert(
            "tag".to_string(),
            attr("tag", AttributeType::String, true, false),
        );
        schema.attributes.insert(
            "email".to_string(),
            attr("email", AttributeType::String, false, true),
        );
        schema.attributes.insert(
            "due".to_string(),
            attr("due", AttributeType::Timestamp, true, false),
        );
        schemas.publish(schema).await?;

        let ctx = WriteContext::new("test");
        for (id, tag, email, due) in [
            ("one", "red", "one@example.test", 100),
            ("two", "blue", "two@example.test", 200),
        ] {
            entities
                .create(
                    EntityDraft {
                        id: id.to_string(),
                        schemas: vec!["item".to_string()],
                        attributes: values(&[
                            ("tag", AttributeValue::String(tag.to_string())),
                            ("email", AttributeValue::String(email.to_string())),
                            ("due", AttributeValue::Timestamp(due)),
                        ]),
                    },
                    &ctx,
                )
                .await?;
        }

        let red = AttributeValue::String("red".to_string());
        assert_eq!(entities.list_by_attribute("tag", &red).await?.len(), 1);

        let rows = raw
            .gets_keys(
                Some(usize::MAX),
                Direction::Next,
                (
                    Some("idx:attr:tag:".to_string()),
                    oxkv::KeyPrefix::new("idx:attr:tag:").upper_bound(),
                ),
            )
            .await?;
        assert!(!rows.is_empty(), "the write must add an index row");
        for key in rows {
            raw.delete(&key).await?;
        }
        assert!(
            entities.list_by_attribute("tag", &red).await?.is_empty(),
            "the removed row must hide the entity"
        );

        let first = rebuild_indexes(&entities, None).await?;
        assert_eq!(first.entities, 2);
        assert_eq!(entities.list_by_attribute("tag", &red).await?.len(), 1);

        let before = index_rows(&raw).await;
        let second = rebuild_indexes(&entities, None).await?;
        let after = index_rows(&raw).await;
        assert_eq!(first.entities, second.entities);
        assert_eq!(before, after, "a second rebuild must change no index row");
        assert_eq!(entities.list_by_attribute("tag", &red).await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn validate_reports_a_dangling_reference() -> anyhow::Result<()> {
        let (schemas, entities, rules, _) = triple().await;
        let mut schema = draft("post");
        schema.attributes.insert(
            "author".to_string(),
            attr("author", AttributeType::EntityRef, false, false),
        );
        schemas.publish(schema).await?;

        let ctx = WriteContext::new("test");
        entities
            .create(
                EntityDraft {
                    id: "target".to_string(),
                    schemas: vec!["post".to_string()],
                    attributes: BTreeMap::new(),
                },
                &ctx,
            )
            .await?;
        entities
            .create(
                EntityDraft {
                    id: "source".to_string(),
                    schemas: vec!["post".to_string()],
                    attributes: values(&[(
                        "author",
                        AttributeValue::EntityRef("target".to_string()),
                    )]),
                },
                &ctx,
            )
            .await?;

        let mut bytes = Vec::new();
        export(&schemas, &entities, &rules, &mut bytes).await?;
        let text = String::from_utf8(bytes).expect("the export is UTF-8");
        let text = text.replace("\"value\":\"target\"", "\"value\":\"missing\"");

        let (target_schemas, target_entities, target_rules, _) = triple().await;
        import(
            &target_schemas,
            &target_entities,
            &target_rules,
            text.as_bytes(),
        )
        .await?;

        let report = validate(&target_schemas, &target_entities, &target_rules).await?;
        assert!(!report.is_ok(), "a dangling reference must fail the check");
        assert_eq!(report.dangling_refs.len(), 1, "{report:?}");
        assert_eq!(report.dangling_refs[0].entity_id, "source");
        assert_eq!(report.dangling_refs[0].target, "missing");
        assert!(report.missing_schemas.is_empty(), "{report:?}");
        assert!(report.unique_claim_issues.is_empty(), "{report:?}");
        Ok(())
    }
}
