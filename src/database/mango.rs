use std::collections::HashMap;

use sea_orm::{
    ExprTrait, Value as SeaValue,
    sea_query::{Alias, Condition, Expr, IntoCondition},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MangoError {
    #[error("Failed to map operator: {0}")]
    OperatorMapping(String),
    #[error("Invalid field type or structure")]
    InvalidStructure,
    #[error("Unsupported JSON value for SeaORM conversion: {0}")]
    UnsupportedValue(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MangoFilter {
    Operators(HashMap<String, serde_json::Value>),
    Scalar(serde_json::Value),
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MangoSelector {
    #[serde(flatten)]
    pub fields: HashMap<String, MangoFilter>,

    #[serde(rename = "$and")]
    pub and: Option<Vec<MangoSelector>>,

    #[serde(rename = "$or")]
    pub or: Option<Vec<MangoSelector>>,

    #[serde(rename = "$nor")]
    pub nor: Option<Vec<MangoSelector>>,
}

impl TryFrom<MangoSelector> for Condition {
    type Error = MangoError;

    fn try_from(selector: MangoSelector) -> Result<Self, Self::Error> {
        let mut main_condition = Condition::all();

        // Handle standard fields and operators
        for (field, filter) in selector.fields {
            let col = Expr::col(Alias::new(&field));

            match filter {
                MangoFilter::Scalar(val) => {
                    let condition = if serde_json::Value::is_null(&val) {
                        Expr::is_null(col)
                    } else {
                        // Using ? here because json_to_sea_val is now fallible
                        col.eq(json_to_sea_val(&val)?)
                    };
                    main_condition = main_condition.add(condition);
                }
                MangoFilter::Operators(ops) => {
                    for (op_str, val) in ops {
                        let cond = map_op_to_cond(&field, &op_str, val)?;
                        main_condition = main_condition.add(cond);
                    }
                }
            }
        }

        // Handle $and
        if let Some(subs) = selector.and {
            let and_conditions = subs
                .into_iter()
                .map(Condition::try_from)
                .collect::<Result<Vec<_>, MangoError>>()?;

            main_condition = and_conditions
                .into_iter()
                .fold(main_condition, Condition::add);
        }

        // Handle $or
        if let Some(subs) = selector.or {
            let or_conditions = subs
                .into_iter()
                .map(Condition::try_from)
                .collect::<Result<Vec<_>, MangoError>>()?;

            let or_group = or_conditions
                .into_iter()
                .fold(Condition::any(), Condition::add);

            main_condition = main_condition.add(or_group);
        }

        // Handle $nor (NOT OR)
        if let Some(subs) = selector.nor {
            let nor_conditions = subs
                .into_iter()
                .map(Condition::try_from)
                .collect::<Result<Vec<_>, MangoError>>()?;

            let nor_group = nor_conditions
                .into_iter()
                .fold(Condition::any(), Condition::add);

            main_condition = main_condition.add(nor_group.not());
        }

        Ok(main_condition)
    }
}

fn map_op_to_cond(field: &str, op: &str, val: serde_json::Value) -> Result<Condition, MangoError> {
    let col = Expr::col(Alias::new(field));

    // Handle Array-based operators ($in, $nin)
    match op {
        "$in" | "$nin" => {
            if let serde_json::Value::Array(arr) = val {
                // Safely attempt to convert all JSON elements to SeaValues
                let sea_vals = arr
                    .iter()
                    .map(json_to_sea_val)
                    .collect::<Result<Vec<SeaValue>, MangoError>>()?;

                return match op {
                    "$in" => Ok(col.is_in(sea_vals).into_condition()),
                    "$nin" => Ok(col.is_not_in(sea_vals).into_condition()),
                    _ => unreachable!(), // Safe because of outer match arm
                };
            }
            return Err(MangoError::OperatorMapping(format!(
                "Operator {} requires a JSON array",
                op
            )));
        }
        _ => {}
    }

    // Handle Null comparisons idiomatically
    if serde_json::Value::is_null(&val) {
        return match op {
            "$eq" => Ok(col.is_null().into_condition()),
            "$ne" => Ok(col.is_not_null().into_condition()),
            _ => Err(MangoError::OperatorMapping(format!(
                "Operator {} cannot be used with null",
                op
            ))),
        };
    }

    // Handle scalar comparisons
    let sea_val = json_to_sea_val(&val)?;
    match op {
        "$eq" => Ok(col.eq(sea_val).into_condition()),
        "$ne" => Ok(col.ne(sea_val).into_condition()),
        "$gt" => Ok(col.gt(sea_val).into_condition()),
        "$gte" => Ok(col.gte(sea_val).into_condition()),
        "$lt" => Ok(col.lt(sea_val).into_condition()),
        "$lte" => Ok(col.lte(sea_val).into_condition()),
        _ => Err(MangoError::OperatorMapping(format!(
            "Unsupported or invalid operator: {}",
            op
        ))),
    }
}

fn json_to_sea_val(val: &serde_json::Value) -> Result<SeaValue, MangoError> {
    match val {
        serde_json::Value::Bool(b) => Ok((*b).into()),
        serde_json::Value::Number(n) => {
            // Attempt lossless conversion in order of preference
            if let Some(i) = n.as_i64() {
                Ok(i.into())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into())
            } else {
                Err(MangoError::UnsupportedValue(format!(
                    "Unparseable number: {}",
                    n
                )))
            }
        }
        serde_json::Value::String(s) => Ok(s.as_str().into()),
        // Bubble up an error instead of panicking on Objects/Arrays passed where a scalar is expected
        _ => Err(MangoError::UnsupportedValue(format!(
            "Cannot convert nested JSON object/array to SeaValue: {}",
            val
        ))),
    }
}
