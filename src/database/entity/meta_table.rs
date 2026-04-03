use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "_meta_tables")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique, index)]
    pub display_name: String,
    #[sea_orm(unique)]
    pub physical_name: String,
}

impl ActiveModelBehavior for ActiveModel {}
