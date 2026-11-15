//! Entity effect plans for atomic multi-entity writes.
//!
//! An effect plan holds an ordered list of entity changes.
//! A future script engine builds one plan and applies it in one call.
//! The store applies the whole plan in one transaction.
//! This module holds data only.
//! It holds no Rhai type and no I/O.
//!
//! [`EffectPlan::validate`] rejects an empty plan.
//! [`EffectPlan::validate_allow_empty`] accepts an empty plan.
//! [`EntityStore::apply_effects`](crate::eav::entity::EntityStore::apply_effects)
//! uses the second form, because a script can decide to do nothing.
//!
//! Every id and every attribute name must pass the entity store rules.
//! A plan holds at most [`MAX_EFFECTS`] effects.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::eav::entity::{AttributeValue, validate_name};
use crate::eav::entity_error::EntityError;

/// The maximum number of effects in one plan.
pub const MAX_EFFECTS: usize = 100;

/// One entity change in an effect plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntityEffect {
    /// Create one entity.
    Create {
        /// The entity id.
        id: String,
        /// The schema ids that the entity pins.
        schemas: Vec<String>,
        /// The initial attributes, keyed by name.
        attributes: BTreeMap<String, AttributeValue>,
    },
    /// Update the attributes of one entity.
    Update {
        /// The entity id.
        id: String,
        /// The version that the caller expects.
        expected_version: u64,
        /// The attribute patch.
        ///
        /// A `Some` value sets the attribute.
        /// A `None` value removes the attribute.
        attributes: BTreeMap<String, Option<AttributeValue>>,
    },
    /// Delete one entity.
    Delete {
        /// The entity id.
        id: String,
        /// The version that the caller expects.
        expected_version: u64,
        /// True to delete an entity that other entities reference.
        force: bool,
    },
}

impl EntityEffect {
    /// Checks the ids and the attribute names of this effect.
    ///
    /// The call uses the entity store rules.
    /// An empty create schema list and an empty update patch are invalid.
    pub fn validate(&self) -> Result<(), EntityError> {
        match self {
            Self::Create {
                id,
                schemas,
                attributes,
            } => {
                validate_name("entity id", id)?;
                if schemas.is_empty() {
                    return Err(EntityError::Invalid(
                        "at least one schema is required".to_string(),
                    ));
                }
                for schema in schemas {
                    validate_name("schema id", schema)?;
                }
                for key in attributes.keys() {
                    validate_name("attribute name", key)?;
                }
            }
            Self::Update { id, attributes, .. } => {
                validate_name("entity id", id)?;
                if attributes.is_empty() {
                    return Err(EntityError::Invalid("patch is empty".to_string()));
                }
                for key in attributes.keys() {
                    validate_name("attribute name", key)?;
                }
            }
            Self::Delete { id, .. } => validate_name("entity id", id)?,
        }
        Ok(())
    }
}

/// An ordered list of entity effects.
///
/// The store applies the effects in list order.
/// A later effect sees every earlier effect.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EffectPlan {
    /// The effects in apply order.
    effects: Vec<EntityEffect>,
}

impl EffectPlan {
    /// Creates a plan from `effects`.
    ///
    /// The call does not validate the plan.
    pub fn new(effects: Vec<EntityEffect>) -> Self {
        Self { effects }
    }

    /// Returns the effects in apply order.
    pub fn effects(&self) -> &[EntityEffect] {
        &self.effects
    }

    /// Returns the number of effects.
    pub fn len(&self) -> usize {
        self.effects.len()
    }

    /// True when the plan holds no effect.
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }

    /// Checks the plan for a non-empty apply.
    ///
    /// The call rejects more than [`MAX_EFFECTS`] effects.
    /// It rejects an empty plan.
    /// It checks every id and every attribute name.
    pub fn validate(&self) -> Result<(), EntityError> {
        self.validate_allow_empty()?;
        if self.effects.is_empty() {
            return Err(EntityError::Invalid("effect plan is empty".to_string()));
        }
        Ok(())
    }

    /// Checks the plan and accepts an empty plan.
    ///
    /// The call rejects more than [`MAX_EFFECTS`] effects.
    /// It checks every id and every attribute name.
    /// It rejects an update or a delete after a delete of the same id.
    /// An empty plan is valid, because a script can decide to do nothing.
    pub fn validate_allow_empty(&self) -> Result<(), EntityError> {
        if self.effects.len() > MAX_EFFECTS {
            return Err(EntityError::Invalid(format!(
                "effect plan has more than {MAX_EFFECTS} effects"
            )));
        }
        let mut deleted: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (index, effect) in self.effects.iter().enumerate() {
            effect.validate()?;
            match effect {
                EntityEffect::Update { id, .. } | EntityEffect::Delete { id, .. }
                    if deleted.contains(id.as_str()) =>
                {
                    return Err(EntityError::Invalid(format!(
                        "effect {index} changes entity {id} after a delete in the same plan"
                    )));
                }
                EntityEffect::Delete { id, .. } => {
                    deleted.insert(id.as_str());
                }
                EntityEffect::Create { id, .. } => {
                    deleted.remove(id.as_str());
                }
                EntityEffect::Update { .. } => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(id: &str) -> EntityEffect {
        EntityEffect::Create {
            id: id.to_string(),
            schemas: vec!["person".to_string()],
            attributes: BTreeMap::new(),
        }
    }

    fn update(id: &str) -> EntityEffect {
        EntityEffect::Update {
            id: id.to_string(),
            expected_version: 1,
            attributes: BTreeMap::from([(
                "name".to_string(),
                Some(AttributeValue::String("Alice".to_string())),
            )]),
        }
    }

    fn delete(id: &str) -> EntityEffect {
        EntityEffect::Delete {
            id: id.to_string(),
            expected_version: 1,
            force: false,
        }
    }

    fn plan(count: usize) -> EffectPlan {
        EffectPlan::new(
            (0..count)
                .map(|index| create(&format!("e{index}")))
                .collect(),
        )
    }

    #[test]
    fn a_plan_accepts_one_hundred_effects() {
        assert!(plan(MAX_EFFECTS).validate().is_ok());
        assert!(plan(MAX_EFFECTS).validate_allow_empty().is_ok());
    }

    #[test]
    fn a_plan_rejects_one_hundred_and_one_effects() {
        let error = plan(MAX_EFFECTS + 1).validate().unwrap_err();
        assert!(
            matches!(&error, EntityError::Invalid(message) if message.contains("more than 100")),
            "unexpected error: {error}"
        );
        assert!(plan(MAX_EFFECTS + 1).validate_allow_empty().is_err());
    }

    #[test]
    fn an_empty_plan_is_valid_for_apply_but_not_for_validation() {
        let empty = EffectPlan::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.validate_allow_empty().is_ok());
        let error = empty.validate().unwrap_err();
        assert!(
            matches!(&error, EntityError::Invalid(message) if message == "effect plan is empty"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_plan_rejects_an_update_or_a_delete_after_a_delete_of_one_id() {
        let update_after_delete = EffectPlan::new(vec![delete("e1"), update("e1")]);
        let delete_after_delete = EffectPlan::new(vec![delete("e1"), delete("e1")]);
        let create_after_delete = EffectPlan::new(vec![delete("e1"), create("e1")]);

        for plan in [update_after_delete, delete_after_delete] {
            let error = plan.validate().unwrap_err();
            assert!(
                matches!(&error, EntityError::Invalid(message) if message.contains("after a delete")),
                "unexpected error: {error}"
            );
        }
        assert!(create_after_delete.validate().is_ok());
    }

    #[test]
    fn every_effect_kind_passes_validation() {
        let plan = EffectPlan::new(vec![create("e1"), update("e1"), delete("e1")]);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan.effects().len(), 3);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn an_invalid_entity_id_is_rejected() {
        for effect in [create("bad:id"), update("bad:id"), delete("bad:id")] {
            let error = effect.validate().unwrap_err();
            assert!(
                matches!(&error, EntityError::Invalid(message) if message.contains("entity id")),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn an_invalid_attribute_name_is_rejected() {
        let create = EntityEffect::Create {
            id: "e1".to_string(),
            schemas: vec!["person".to_string()],
            attributes: BTreeMap::from([(
                "bad:name".to_string(),
                AttributeValue::String("Alice".to_string()),
            )]),
        };
        let update = EntityEffect::Update {
            id: "e1".to_string(),
            expected_version: 1,
            attributes: BTreeMap::from([("bad:name".to_string(), None)]),
        };

        for effect in [create, update] {
            let error = effect.validate().unwrap_err();
            assert!(
                matches!(&error, EntityError::Invalid(message) if message.contains("attribute name")),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn an_invalid_schema_id_is_rejected() {
        let effect = EntityEffect::Create {
            id: "e1".to_string(),
            schemas: vec!["bad:schema".to_string()],
            attributes: BTreeMap::new(),
        };
        let error = effect.validate().unwrap_err();
        assert!(
            matches!(&error, EntityError::Invalid(message) if message.contains("schema id")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_create_needs_one_schema_and_an_update_needs_one_attribute() {
        let no_schema = EntityEffect::Create {
            id: "e1".to_string(),
            schemas: Vec::new(),
            attributes: BTreeMap::new(),
        };
        let no_attribute = EntityEffect::Update {
            id: "e1".to_string(),
            expected_version: 1,
            attributes: BTreeMap::new(),
        };

        assert!(matches!(
            no_schema.validate(),
            Err(EntityError::Invalid(message)) if message == "at least one schema is required"
        ));
        assert!(matches!(
            no_attribute.validate(),
            Err(EntityError::Invalid(message)) if message == "patch is empty"
        ));
    }
}
