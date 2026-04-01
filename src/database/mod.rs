use std::collections::HashMap;

use sea_orm::sea_query::{Alias, Asterisk, ColumnDef, ColumnType, Query, Table};
use sea_orm::{
    Condition, ConnectionTrait, DbConn, DbErr, FromQueryResult, JsonValue, Value as SeaValue,
    prelude::{Expr, StringLen},
};

pub mod mango;

pub enum ColumnDataType {
    Bool,
    Number,
    String,
}

impl From<ColumnDataType> for ColumnType {
    fn from(data_type: ColumnDataType) -> Self {
        match data_type {
            ColumnDataType::Bool => ColumnType::Boolean,
            ColumnDataType::Number => ColumnType::Integer,
            ColumnDataType::String => ColumnType::String(StringLen::None),
        }
    }
}

pub struct DynamicTableEditor<'a> {
    db: &'a DbConn,
}

impl<'a> DynamicTableEditor<'a> {
    pub fn new(db: &'a DbConn) -> Self {
        Self { db }
    }

    pub async fn create_table(&self, table_name: &str) -> Result<(), DbErr> {
        let draft_statement = Table::create()
            .table(Alias::new(table_name))
            .if_not_exists()
            .col(
                ColumnDef::new(Alias::new("id"))
                    .integer()
                    .not_null()
                    .auto_increment()
                    .primary_key(),
            )
            .to_owned();

        let statement = self.db.get_database_backend().build(&draft_statement);
        self.db.execute_raw(statement).await?;

        Ok(())
    }

    pub async fn add_column(
        &self,
        table_name: &str,
        col_name: &str,
        col_type: ColumnDataType,
    ) -> Result<(), DbErr> {
        let sea_type: ColumnType = col_type.into();
        let column_def = ColumnDef::new_with_type(Alias::new(col_name), sea_type).to_owned();

        let draft_statement = Table::alter()
            .table(Alias::new(table_name))
            .add_column(column_def)
            .to_owned();

        let statement = self.db.get_database_backend().build(&draft_statement);
        self.db.execute_raw(statement).await?;

        Ok(())
    }

    pub async fn drop_column(&self, table_name: &str, col_name: &str) -> Result<(), DbErr> {
        let draft_statement = Table::alter()
            .table(Alias::new(table_name))
            .drop_column(Alias::new(col_name))
            .to_owned();

        let statement = self.db.get_database_backend().build(&draft_statement);
        self.db.execute_raw(statement).await?;

        Ok(())
    }

    pub async fn drop_table(&self, table_name: &str) -> Result<(), DbErr> {
        let draft_statement = Table::drop().table(Alias::new(table_name)).to_owned();

        let statement = self.db.get_database_backend().build(&draft_statement);
        self.db.execute_raw(statement).await?;

        Ok(())
    }
}

impl<'a> DynamicTableEditor<'a> {
    pub async fn insert_row(
        &self,
        table_name: &str,
        data: HashMap<String, SeaValue>,
    ) -> Result<(), DbErr> {
        let (columns, values): (Vec<_>, Vec<_>) = data.into_iter().collect();

        let mut draft_statement = Query::insert();
        draft_statement
            .into_table(Alias::new(table_name))
            .columns(columns.into_iter().map(Alias::new))
            .values_panic(values.into_iter().map(Expr::val));

        let statement = self.db.get_database_backend().build(&draft_statement);
        self.db.execute_raw(statement).await?;

        Ok(())
    }

    /// READ: Select rows with Condition
    pub async fn select_rows(
        &self,
        table_name: &str,
        condition: Condition,
    ) -> Result<Vec<JsonValue>, DbErr> {
        let builder = self.db.get_database_backend();

        let draft_statement = Query::select()
            .column(Asterisk)
            .from(Alias::new(table_name))
            .cond_where(condition)
            .take();
        let statement = builder.build(&draft_statement);

        let rows = self.db.query_all_raw(statement).await?;

        let mut results = Vec::new();
        for row in rows {
            results.push(JsonValue::from_query_result(&row, "")?);
        }

        Ok(results)
    }

    /// UPDATE: Update specific columns based on Condition
    pub async fn update_rows(
        &self,
        table_name: &str,
        condition: Condition,
        updates: HashMap<String, SeaValue>,
    ) -> Result<u64, DbErr> {
        if updates.is_empty() {
            return Ok(0);
        }

        let mut draft_statement = Query::update();
        draft_statement
            .table(Alias::new(table_name))
            .cond_where(condition); // Replaced filter loop with cond_where

        let values: Vec<_> = updates
            .into_iter()
            .map(|(col, val)| (Alias::new(col), Expr::val(val)))
            .collect();

        draft_statement.values(values);

        let statement = self.db.get_database_backend().build(&draft_statement);
        let result = self.db.execute_raw(statement).await?;

        Ok(result.rows_affected())
    }

    /// DELETE: Delete rows based on Condition
    pub async fn delete_rows(&self, table_name: &str, condition: Condition) -> Result<u64, DbErr> {
        let mut draft_statement = Query::delete();
        draft_statement
            .from_table(Alias::new(table_name))
            .cond_where(condition); // Replaced filter loop with cond_where

        let statement = self.db.get_database_backend().build(&draft_statement);
        let result = self.db.execute_raw(statement).await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::sea_query::Alias;
    use sea_orm::{Database, DbBackend, DbConn, ExprTrait, Statement};
    use std::collections::HashMap;

    async fn setup() -> DbConn {
        Database::connect("sqlite::memory:")
            .await
            .expect("Failed to setup in-memory DB")
    }

    async fn setup_users_table() -> Result<DbConn, DbErr> {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to setup in-memory DB");

        let editor = DynamicTableEditor::new(&db);
        editor.create_table("users").await?;
        editor
            .add_column("users", "name", ColumnDataType::String)
            .await?;
        editor
            .add_column("users", "age", ColumnDataType::Number)
            .await?;

        Ok(db)
    }

    #[tokio::test]
    async fn test_create_table_verification() -> Result<(), DbErr> {
        let db = setup().await;
        let editor = DynamicTableEditor::new(&db);
        let name = "users";

        editor.create_table(name).await?;

        let query = Statement::from_string(
            DbBackend::Sqlite,
            format!(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{}'",
                name
            ),
        );

        let row = db.query_one_raw(query).await?.unwrap();
        let count: i32 = row.try_get_by_index(0)?;

        assert_eq!(count, 1, "Table should exist in sqlite_master");
        Ok(())
    }

    #[tokio::test]
    async fn test_add_column_verification() -> Result<(), DbErr> {
        let db = setup().await;
        let editor = DynamicTableEditor::new(&db);
        let table = "profile";

        editor.create_table(table).await?;
        editor
            .add_column(table, "nickname", ColumnDataType::String)
            .await?;

        // SQL Query check: Use PRAGMA to inspect columns
        let query =
            Statement::from_string(DbBackend::Sqlite, format!("PRAGMA table_info({})", table));

        let columns = db.query_all_raw(query).await?;
        // index 0 is 'id' (from create_table), index 1 should be 'nickname'
        let has_nickname = columns.iter().any(|res| {
            let name: String = res.try_get("", "name").unwrap_or_default();
            name == "nickname"
        });

        assert!(has_nickname, "Column 'nickname' should exist in table info");
        Ok(())
    }

    #[tokio::test]
    async fn test_drop_column_verification() -> Result<(), DbErr> {
        let db = setup().await;
        let editor = DynamicTableEditor::new(&db);
        let table = "settings";

        editor.create_table(table).await?;
        editor
            .add_column(table, "temp_val", ColumnDataType::Number)
            .await?;

        // Drop it
        editor.drop_column(table, "temp_val").await?;

        // SQL Query check
        let query =
            Statement::from_string(DbBackend::Sqlite, format!("PRAGMA table_info({})", table));

        let columns = db.query_all_raw(query).await?;
        let has_temp = columns.iter().any(|res| {
            let name: String = res.try_get("", "name").unwrap_or_default();
            name == "temp_val"
        });

        assert!(!has_temp, "Column 'temp_val' should no longer exist");
        Ok(())
    }

    #[tokio::test]
    async fn test_drop_table_verification() -> Result<(), DbErr> {
        let db = setup().await;
        let editor = DynamicTableEditor::new(&db);
        let name = "temporary_data";

        editor.create_table(name).await?;
        editor.drop_table(name).await?;

        // SQL Query check
        let query = Statement::from_string(
            DbBackend::Sqlite,
            format!(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{}'",
                name
            ),
        );

        let row = db.query_one_raw(query).await?.unwrap();
        let count: i32 = row.try_get_by_index(0)?;

        assert_eq!(count, 0, "Table should be removed from sqlite_master");
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_row() -> Result<(), DbErr> {
        let db = setup_users_table().await?;
        let editor = DynamicTableEditor::new(&db);

        let mut data = HashMap::new();
        data.insert("name".to_string(), SeaValue::from("Alice"));
        data.insert("age".to_string(), SeaValue::from(30));

        // Execute Insert
        editor.insert_row("users", data).await?;

        // VERIFY: Use raw SQL to ensure the DB state is correct independently of editor.select_rows
        let query =
            Statement::from_string(DbBackend::Sqlite, "SELECT name, age FROM users LIMIT 1");
        let query_res = db
            .query_one_raw(query)
            .await?
            .expect("Row should exist in DB");

        let name: String = query_res.try_get("", "name")?;
        let age: i32 = query_res.try_get("", "age")?;

        assert_eq!(name, "Alice");
        assert_eq!(age, 30);

        Ok(())
    }

    #[tokio::test]
    async fn test_select_rows_with_condition() -> Result<(), DbErr> {
        let db = setup_users_table().await?;
        let editor = DynamicTableEditor::new(&db);

        // SETUP: Use raw SQL to insert so we aren't testing insert_row here
        db.execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "INSERT INTO users (name, age) VALUES ('Bob', 25), ('Charlie', 40)",
        ))
        .await?;

        // Execute Select: Testing the actual logic of the editor
        let condition = Condition::all().add(Expr::col(Alias::new("name")).eq("Charlie"));
        let results = editor.select_rows("users", condition).await?;

        assert_eq!(results.len(), 1, "Should only return Charlie");
        assert_eq!(results[0]["name"], "Charlie");
        assert_eq!(results[0]["age"], 40);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_rows() -> Result<(), DbErr> {
        let db = setup_users_table().await?;
        let editor = DynamicTableEditor::new(&db);

        // SETUP: Manual insert
        db.execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "INSERT INTO users (name, age) VALUES ('Diana', 28)",
        ))
        .await?;

        // Execute Update
        let condition = Condition::all().add(Expr::col(Alias::new("name")).eq("Diana"));
        let updates = HashMap::from([("age".to_string(), SeaValue::from(29))]);
        editor.update_rows("users", condition, updates).await?;

        // VERIFY: Raw SQL check
        let statement = Statement::from_string(
            DbBackend::Sqlite,
            "SELECT age FROM users WHERE name = 'Diana'",
        );
        let res = db
            .query_one_raw(statement)
            .await?
            .expect("Diana should exist");
        let age: i32 = res.try_get("", "age")?;

        assert_eq!(age, 29, "Database should reflect the update");

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_rows() -> Result<(), DbErr> {
        let db = setup_users_table().await?;
        let editor = DynamicTableEditor::new(&db);

        // SETUP: Manual insert
        db.execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "INSERT INTO users (name, age) VALUES ('Evan', 50)",
        ))
        .await?;

        // Execute Delete
        let condition = Condition::all().add(Expr::col(Alias::new("name")).eq("Evan"));
        editor.delete_rows("users", condition).await?;

        // VERIFY: Raw SQL count
        let statement = Statement::from_string(
            DbBackend::Sqlite,
            "SELECT COUNT(*) as count FROM users WHERE name = 'Evan'",
        );
        let res = db
            .query_one_raw(statement)
            .await?
            .expect("Query should return a count");
        let count: i32 = res.try_get("", "count")?;

        assert_eq!(count, 0, "Row should be physically gone from the database");

        Ok(())
    }
}
