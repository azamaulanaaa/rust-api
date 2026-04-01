use sea_orm::sea_query::{Alias, ColumnDef, ColumnType, Table};
use sea_orm::{ConnectionTrait, DbConn, DbErr, prelude::StringLen};

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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{Database, DbBackend, DbConn, Statement};

    async fn setup() -> DbConn {
        Database::connect("sqlite::memory:")
            .await
            .expect("Failed to setup in-memory DB")
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
}
