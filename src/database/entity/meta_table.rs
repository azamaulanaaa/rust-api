use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "_meta_tables")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: String,
    #[sea_orm(unique, indexed)]
    pub display_name: String,
    #[sea_orm(has_many)]
    pub columns: HasMany<super::meta_column::Entity>,
}

impl ActiveModelBehavior for ActiveModel {}
