use base32ct::{Base32, Encoding};
use sea_orm::{
    ActiveModelTrait, ActiveValue, DbConn, DbErr, EntityTrait, RuntimeErr, TransactionTrait,
};
use thiserror::Error;
use uuid::Uuid;

use dynamic_table::DynamicTableEditor;

pub mod dynamic_table;
pub mod entity;
pub mod mango;

const TABLE_PREFIX: &str = "tbl_";

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
            id: ActiveValue::NotSet,
            display_name: ActiveValue::Set(name.clone()),
            physical_name: ActiveValue::Set(actual_name.clone()),
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

        entity::meta_table::Entity::delete_by_id(meta_table.id)
            .exec(&txn)
            .await?;

        DynamicTableEditor::new(&txn)
            .drop_table(&meta_table.physical_name)
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
}
