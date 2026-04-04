use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum MetaColumnType {
    #[sea_orm(string_value = "Text")]
    Text,
    #[sea_orm(string_value = "Number")]
    Number,
    #[sea_orm(string_value = "Bool")]
    Bool,
    #[sea_orm(string_value = "Datetime")]
    Datetime,
}

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "_meta_columns")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,
    #[sea_orm(unique_key = "table_column", indexed)]
    pub table_id: String,
    #[sea_orm(unique_key = "table_column", indexed)]
    pub display_name: String,
    pub col_type: MetaColumnType,
    #[sea_orm(belongs_to, from = "table_id", to = "id")]
    pub table: HasOne<super::meta_table::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
