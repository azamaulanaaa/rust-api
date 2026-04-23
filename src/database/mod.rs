use base32ct::{Base32, Encoding};
use sea_orm::{
    ActiveModelTrait, ActiveValue, DbConn, DbErr, EntityTrait, ModelTrait, RuntimeErr,
    TransactionTrait,
};
use thiserror::Error;
use uuid::Uuid;

use dynamic_table::{ColumnDataType, DynamicTableEditor};
pub use entity::meta_column::MetaColumnType;
pub use mango::{MangoError, MangoFilter, MangoSelector};

pub mod dynamic_table;
pub mod entity;
pub mod mango;

const TABLE_PREFIX: &str = "tbl_";
const COLUMN_PREFIX: &str = "col_";

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Name '{0}' already exists")]
    NameTaken(String),
    #[error("Name '{0}' does not exists")]
    NameNotExists(String),
    #[error("Database execution error: {0}")]
    ExecutionError(#[from] DbErr),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<MetaColumnType> for ColumnDataType {
    fn from(value: MetaColumnType) -> Self {
        match value {
            MetaColumnType::Text => ColumnDataType::String,
            MetaColumnType::Number => ColumnDataType::Number,
            MetaColumnType::Bool => ColumnDataType::Bool,
            MetaColumnType::Datetime => ColumnDataType::Number,
        }
    }
}

pub struct Database {
    db: DbConn,
}

impl Database {
    pub async fn sync(&self) -> Result<(), DatabaseError> {
        let prefix = format!("{}::entity::*", module_path!());

        self.db.get_schema_registry(&prefix).sync(&self.db).await?;

        Ok(())
    }

    pub async fn create_table(&self, name: String) -> Result<(), DatabaseError> {
        let actual_name = format!("{}{}", TABLE_PREFIX, random_name());

        let txn = self.db.begin().await?;

        entity::meta_table::ActiveModel {
            id: ActiveValue::Set(actual_name.clone()),
            display_name: ActiveValue::Set(name.clone()),
        }
        .insert(&txn)
        .await
        .map_err(|e| {
            if let DbErr::Query(RuntimeErr::SqlxError(ref sqlx_err)) = e {
                let err_msg = sqlx_err.to_string().to_lowercase();

                if err_msg.contains("unique") || err_msg.contains("duplicate") {
                    return DatabaseError::NameTaken(name);
                }
            }

            DatabaseError::ExecutionError(e)
        })?;

        DynamicTableEditor::new(&txn)
            .create_table(&actual_name)
            .await?;

        txn.commit().await?;

        Ok(())
    }

    pub async fn drop_table(&self, name: String) -> Result<(), DatabaseError> {
        let txn = self.db.begin().await?;

        let result = entity::meta_table::Entity::find_by_display_name(name.clone())
            .one(&txn)
            .await?;
        let meta_table = match result {
            Some(v) => v,
            None => return Err(DatabaseError::NameNotExists(name)),
        };

        entity::meta_table::Entity::delete_by_id(&meta_table.id)
            .exec(&txn)
            .await?;

        DynamicTableEditor::new(&txn)
            .drop_table(&meta_table.id)
            .await?;

        txn.commit().await?;

        Ok(())
    }

    pub async fn rename_table(
        &self,
        old_name: String,
        new_name: String,
    ) -> Result<(), DatabaseError> {
        let txn = self.db.begin().await?;

        let result = entity::meta_table::Entity::find_by_display_name(old_name.clone())
            .one(&txn)
            .await?;
        let mut meta_table: entity::meta_table::ActiveModel = match result {
            Some(v) => v.into(),
            None => return Err(DatabaseError::NameNotExists(old_name)),
        };

        meta_table.display_name = ActiveValue::Set(new_name.clone());

        meta_table.update(&txn).await.map_err(|e| {
            if let DbErr::Query(RuntimeErr::SqlxError(ref sqlx_err)) = e {
                let err_msg = sqlx_err.to_string().to_lowercase();

                if err_msg.contains("unique") || err_msg.contains("duplicate") {
                    return DatabaseError::NameTaken(new_name);
                }
            }

            DatabaseError::ExecutionError(e)
        })?;

        txn.commit().await?;

        Ok(())
    }

    pub async fn list_tables(&self) -> Result<Vec<String>, DatabaseError> {
        let txn = self.db.begin().await?;

        let result = entity::meta_table::Entity::find().all(&txn).await?;
        let names = result
            .into_iter()
            .map(|model| model.display_name)
            .collect::<Vec<_>>();

        txn.commit().await?;

        Ok(names)
    }

    pub async fn add_column(
        &self,
        table_name: String,
        column_name: String,
        coltype: MetaColumnType,
    ) -> Result<(), DatabaseError> {
        let txn = self.db.begin().await?;

        let result = entity::meta_table::Entity::find_by_display_name(&table_name)
            .one(&txn)
            .await?;
        let meta_table = match result {
            Some(v) => v,
            None => return Err(DatabaseError::NameNotExists(table_name)),
        };

        let actual_column_name = format!("{}{}", COLUMN_PREFIX, random_name());

        entity::meta_column::ActiveModel {
            id: ActiveValue::Set(actual_column_name.clone()),
            table_id: ActiveValue::Set(meta_table.id.clone()),
            display_name: ActiveValue::Set(column_name.clone()),
            col_type: ActiveValue::Set(coltype.clone()),
            ..Default::default()
        }
        .insert(&txn)
        .await
        .map_err(|e| {
            if let DbErr::Query(RuntimeErr::SqlxError(ref sqlx_err)) = e {
                let err_msg = sqlx_err.to_string().to_lowercase();

                if err_msg.contains("unique") || err_msg.contains("duplicate") {
                    return DatabaseError::NameTaken(column_name);
                }
            }

            DatabaseError::ExecutionError(e)
        })?;

        DynamicTableEditor::new(&txn)
            .add_column(&meta_table.id, &actual_column_name, coltype.into())
            .await?;

        txn.commit().await?;

        Ok(())
    }

    pub async fn drop_column(
        &self,
        table_name: String,
        column_name: String,
    ) -> Result<(), DatabaseError> {
        let txn = self.db.begin().await?;

        let result = entity::meta_table::Entity::find_by_display_name(&table_name)
            .one(&txn)
            .await?;
        let meta_table = match result {
            Some(v) => v,
            None => return Err(DatabaseError::NameNotExists(table_name)),
        };

        let result = entity::meta_column::Entity::delete_by_table_column((
            meta_table.id.clone(),
            column_name.clone(),
        ))
        .exec_with_returning(&txn)
        .await?;
        let meta_column = match result {
            Some(v) => v,
            None => return Err(DatabaseError::NameNotExists(column_name)),
        };

        DynamicTableEditor::new(&txn)
            .drop_column(&meta_table.id, &meta_column.id)
            .await?;

        txn.commit().await?;

        Ok(())
    }

    pub async fn rename_column(
        &self,
        table_name: String,
        old_column_name: String,
        new_column_name: String,
    ) -> Result<(), DatabaseError> {
        let txn = self.db.begin().await?;

        let result = entity::meta_table::Entity::find_by_display_name(&table_name)
            .one(&txn)
            .await?;
        let meta_table = match result {
            Some(v) => v,
            None => return Err(DatabaseError::NameNotExists(table_name)),
        };

        let result = entity::meta_column::Entity::find_by_table_column((
            meta_table.id.clone(),
            old_column_name.clone(),
        ))
        .one(&txn)
        .await?;
        let mut meta_column: entity::meta_column::ActiveModel = match result {
            Some(v) => v.into(),
            None => return Err(DatabaseError::NameNotExists(old_column_name)),
        };

        meta_column.display_name = ActiveValue::Set(new_column_name.clone());

        meta_column.update(&txn).await.map_err(|e| {
            if let DbErr::Query(RuntimeErr::SqlxError(ref sqlx_err)) = e {
                let err_msg = sqlx_err.to_string().to_lowercase();

                if err_msg.contains("unique") || err_msg.contains("duplicate") {
                    return DatabaseError::NameTaken(new_column_name);
                }
            }

            DatabaseError::ExecutionError(e)
        })?;

        txn.commit().await?;

        Ok(())
    }

    pub async fn list_columns(&self, table_name: String) -> Result<Vec<String>, DatabaseError> {
        let txn = self.db.begin().await?;

        let result = entity::meta_table::Entity::find_by_display_name(&table_name)
            .one(&txn)
            .await?;
        let meta_table = match result {
            Some(v) => v,
            None => return Err(DatabaseError::NameNotExists(table_name)),
        };

        let meta_columns = meta_table
            .find_related(entity::meta_column::Entity)
            .all(&txn)
            .await?;

        let names = meta_columns
            .into_iter()
            .map(|model| model.display_name)
            .collect::<Vec<_>>();

        txn.commit().await?;

        Ok(names)
    }
}

fn random_name() -> String {
    let uuid = Uuid::now_v7();
    let encoded = Base32::encode_string(uuid.as_bytes());

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database as SeaDatabase, DatabaseConnection};

    async fn setup_test_db() -> Database {
        let db: DatabaseConnection = SeaDatabase::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to in-memory SQLite");

        let database = Database { db };

        database.sync().await.expect("Failed to sync schema");

        database
    }

    #[tokio::test]
    async fn test_create_table_success() {
        let database = setup_test_db().await;
        let table_name = "My Awesome Table".to_string();

        let result = database.create_table(table_name.clone()).await;

        assert!(
            result.is_ok(),
            "Table creation should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_create_table_duplicate_name_error() {
        let database = setup_test_db().await;
        let table_name = "UniqueTable".to_string();

        database
            .create_table(table_name.clone())
            .await
            .expect("success create table for first time");
        let result = database.create_table(table_name.clone()).await;

        match result {
            Err(DatabaseError::NameTaken(name)) => assert_eq!(name, "UniqueTable"),
            other => panic!("Expected NameTaken error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_drop_table_success() {
        let database = setup_test_db().await;
        let table_name = "TableToDrop".to_string();

        database
            .create_table(table_name.clone())
            .await
            .expect("Failed to create table for dropping");

        let result = database.drop_table(table_name.clone()).await;
        assert!(
            result.is_ok(),
            "Drop table should succeed: {:?}",
            result.err()
        );

        let second_drop = database.drop_table(table_name).await;
        match second_drop {
            Err(DatabaseError::NameNotExists(_)) => (),
            other => panic!(
                "Expected NameNotExists error after successful drop, got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_drop_table_not_found_error() {
        let database = setup_test_db().await;
        let table_name = "NonExistentTable".to_string();

        let result = database.drop_table(table_name).await;

        match result {
            Err(DatabaseError::NameNotExists(name)) => assert_eq!(name, "NonExistentTable"),
            other => panic!("Expected NameNotExists error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_rename_table_success() {
        let database = setup_test_db().await;
        let old_name = "OriginalName".to_string();
        let new_name = "NewAndImproved".to_string();

        database
            .create_table(old_name.clone())
            .await
            .expect("Failed to create table");

        let result = database
            .rename_table(old_name.clone(), new_name.clone())
            .await;
        assert!(result.is_ok(), "Rename should succeed: {:?}", result.err());

        let old_check = database.drop_table(old_name).await;
        assert!(matches!(old_check, Err(DatabaseError::NameNotExists(_))));

        let new_check = database.drop_table(new_name).await;
        assert!(new_check.is_ok(), "New table name should exist in metadata");
    }

    #[tokio::test]
    async fn test_rename_table_not_found_error() {
        let database = setup_test_db().await;

        let result = database
            .rename_table("NonExistent".into(), "Target".into())
            .await;

        match result {
            Err(DatabaseError::NameNotExists(name)) => assert_eq!(name, "NonExistent"),
            other => panic!("Expected NameNotExists error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_rename_table_collision_error() {
        let database = setup_test_db().await;
        let table_a = "TableA".to_string();
        let table_b = "TableB".to_string();

        database.create_table(table_a.clone()).await.unwrap();
        database.create_table(table_b.clone()).await.unwrap();

        let result = database.rename_table(table_a, table_b.clone()).await;

        match result {
            Err(DatabaseError::NameTaken(name)) => assert_eq!(name, table_b),
            other => panic!("Expected NameTaken error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_tables_empty() {
        let database = setup_test_db().await;

        let tables = database.list_tables().await.expect("List tables failed");

        assert!(
            tables.is_empty(),
            "Expected empty list for new database, got {:?}",
            tables
        );
    }

    #[tokio::test]
    async fn test_list_tables_multiple() {
        let database = setup_test_db().await;
        let expected_names = vec![
            "Table One".to_string(),
            "Table Two".to_string(),
            "Table Three".to_string(),
        ];

        // Create multiple tables
        for name in &expected_names {
            database
                .create_table(name.clone())
                .await
                .expect("Failed to create table during list test");
        }

        let mut actual_names = database.list_tables().await.expect("List tables failed");

        // Sort both for comparison since DB order isn't always guaranteed
        actual_names.sort();
        let mut sorted_expected = expected_names.clone();
        sorted_expected.sort();

        assert_eq!(
            actual_names, sorted_expected,
            "The list of table names does not match"
        );
        assert_eq!(actual_names.len(), 3);
    }

    #[tokio::test]
    async fn test_add_column_success() {
        let database = setup_test_db().await;
        let table_name = "UserTable".to_string();
        let column_name = "email".to_string();

        database
            .create_table(table_name.clone())
            .await
            .expect("Failed to create table");

        let result = database
            .add_column(
                table_name.clone(),
                column_name.clone(),
                MetaColumnType::Text,
            )
            .await;

        assert!(
            result.is_ok(),
            "Adding column should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_add_column_table_not_found_error() {
        let database = setup_test_db().await;
        let table_name = "GhostTable".to_string();
        let column_name = "some_col".to_string();

        let result = database
            .add_column(table_name.clone(), column_name, MetaColumnType::Bool)
            .await;

        match result {
            Err(DatabaseError::NameNotExists(name)) => assert_eq!(name, table_name),
            other => panic!("Expected NameNotExists error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_add_column_duplicate_name_error() {
        let database = setup_test_db().await;
        let table_name = "ProductTable".to_string();
        let column_name = "price".to_string();

        database
            .create_table(table_name.clone())
            .await
            .expect("Failed to create table");

        // Add first time
        database
            .add_column(
                table_name.clone(),
                column_name.clone(),
                MetaColumnType::Number,
            )
            .await
            .expect("First column add should succeed");

        // Add second time (duplicate)
        let result = database
            .add_column(table_name, column_name.clone(), MetaColumnType::Number)
            .await;

        match result {
            Err(DatabaseError::NameTaken(name)) => assert_eq!(name, column_name),
            other => panic!(
                "Expected NameTaken error for duplicate column, got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_drop_column_success() {
        let database = setup_test_db().await;
        let table_name = "DeletableTable".to_string();
        let column_name = "temporary_col".to_string();

        database
            .create_table(table_name.clone())
            .await
            .expect("Failed to create table");

        database
            .add_column(
                table_name.clone(),
                column_name.clone(),
                MetaColumnType::Text,
            )
            .await
            .expect("Failed to add column");

        let result = database
            .drop_column(table_name.clone(), column_name.clone())
            .await;

        assert!(
            result.is_ok(),
            "Dropping column should succeed: {:?}",
            result.err()
        );

        // Verify it's gone by trying to drop it again
        let second_drop = database.drop_column(table_name, column_name).await;
        match second_drop {
            Err(DatabaseError::NameNotExists(_)) => (),
            other => panic!(
                "Expected NameNotExists error on second drop, got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_drop_column_table_not_found_error() {
        let database = setup_test_db().await;

        let result = database
            .drop_column("NonExistentTable".to_string(), "any_col".to_string())
            .await;

        match result {
            Err(DatabaseError::NameNotExists(name)) => assert_eq!(name, "NonExistentTable"),
            other => panic!("Expected NameNotExists for table, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_drop_column_column_not_found_error() {
        let database = setup_test_db().await;
        let table_name = "ExistingTable".to_string();

        database
            .create_table(table_name.clone())
            .await
            .expect("Failed to create table");

        let result = database
            .drop_column(table_name, "ghost_column".to_string())
            .await;

        match result {
            Err(DatabaseError::NameNotExists(name)) => assert_eq!(name, "ghost_column"),
            other => panic!("Expected NameNotExists for column, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_rename_column_success() {
        let database = setup_test_db().await;
        let table_name = "EmployeeTable".to_string();
        let old_col = "fname".to_string();
        let new_col = "first_name".to_string();

        database.create_table(table_name.clone()).await.unwrap();
        database
            .add_column(table_name.clone(), old_col.clone(), MetaColumnType::Text)
            .await
            .unwrap();

        let result = database
            .rename_column(table_name.clone(), old_col.clone(), new_col.clone())
            .await;

        assert!(
            result.is_ok(),
            "Rename column should succeed: {:?}",
            result.err()
        );

        // Verify: Old name should no longer exist
        let old_check = database.drop_column(table_name.clone(), old_col).await;
        assert!(matches!(old_check, Err(DatabaseError::NameNotExists(_))));

        // Verify: New name should exist (we can drop it to check)
        let new_check = database.drop_column(table_name, new_col).await;
        assert!(
            new_check.is_ok(),
            "New column name should exist in metadata"
        );
    }

    #[tokio::test]
    async fn test_rename_column_collision_error() {
        let database = setup_test_db().await;
        let table_name = "CollisionTable".to_string();
        let col_a = "column_a".to_string();
        let col_b = "column_b".to_string();

        database.create_table(table_name.clone()).await.unwrap();
        database
            .add_column(table_name.clone(), col_a.clone(), MetaColumnType::Text)
            .await
            .unwrap();
        database
            .add_column(table_name.clone(), col_b.clone(), MetaColumnType::Number)
            .await
            .unwrap();

        // Try to rename A to B
        let result = database
            .rename_column(table_name, col_a, col_b.clone())
            .await;

        match result {
            Err(DatabaseError::NameTaken(name)) => assert_eq!(name, col_b),
            other => panic!("Expected NameTaken error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_rename_column_not_found_error() {
        let database = setup_test_db().await;
        let table_name = "ValidTable".to_string();

        database.create_table(table_name.clone()).await.unwrap();

        let result = database
            .rename_column(table_name, "missing_col".into(), "new_name".into())
            .await;

        match result {
            Err(DatabaseError::NameNotExists(name)) => assert_eq!(name, "missing_col"),
            other => panic!("Expected NameNotExists error for column, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_rename_column_table_missing_error() {
        let database = setup_test_db().await;

        let result = database
            .rename_column("GhostTable".into(), "any_col".into(), "new_col".into())
            .await;

        match result {
            Err(DatabaseError::NameNotExists(name)) => assert_eq!(name, "GhostTable"),
            other => panic!("Expected NameNotExists error for table, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_list_columns_empty() {
        let database = setup_test_db().await;
        let table_name = "EmptyTable".to_string();

        database
            .create_table(table_name.clone())
            .await
            .expect("Failed to create table");

        let columns = database
            .list_columns(table_name)
            .await
            .expect("List columns failed");

        assert!(
            columns.is_empty(),
            "Expected empty column list, got {:?}",
            columns
        );
    }

    #[tokio::test]
    async fn test_list_columns_multiple() {
        let database = setup_test_db().await;
        let table_name = "MultiColTable".to_string();
        let expected_columns = vec![
            ("id".to_string(), MetaColumnType::Number),
            ("username".to_string(), MetaColumnType::Text),
            ("is_active".to_string(), MetaColumnType::Bool),
            ("created_at".to_string(), MetaColumnType::Datetime),
        ];

        database
            .create_table(table_name.clone())
            .await
            .expect("Failed to create table");

        // Add all columns
        for (name, col_type) in &expected_columns {
            database
                .add_column(table_name.clone(), name.clone(), col_type.clone())
                .await
                .expect("Failed to add column during list test");
        }

        let mut actual_columns = database
            .list_columns(table_name)
            .await
            .expect("List columns failed");

        // Sort for deterministic comparison
        actual_columns.sort();
        let mut sorted_expected = expected_columns
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        sorted_expected.sort();

        assert_eq!(
            actual_columns, sorted_expected,
            "The list of column names does not match"
        );
        assert_eq!(actual_columns.len(), 4);
    }

    #[tokio::test]
    async fn test_list_columns_table_not_found_error() {
        let database = setup_test_db().await;
        let table_name = "GhostTable".to_string();

        let result = database.list_columns(table_name.clone()).await;

        match result {
            Err(DatabaseError::NameNotExists(name)) => assert_eq!(name, table_name),
            other => panic!(
                "Expected NameNotExists error for missing table, got {:?}",
                other
            ),
        }
    }
}
