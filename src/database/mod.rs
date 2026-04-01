use std::borrow::Cow;
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
        let db_backend = self.db.get_database_backend();

        let statement = Table::create()
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

        self.db.execute_raw(db_backend.build(&statement)).await?;

        Ok(())
    }

    pub async fn drop_table(&self, table_name: &str) -> Result<(), DbErr> {
        let db_backend = self.db.get_database_backend();

        let statement = Table::drop().table(Alias::new(table_name)).to_owned();

        self.db.execute_raw(db_backend.build(&statement)).await?;

        Ok(())
    }

    pub async fn add_column(
        &self,
        table_name: &str,
        col_name: &str,
        col_type: ColumnDataType,
    ) -> Result<(), DbErr> {
        let db_backend = self.db.get_database_backend();

        let statement = Table::alter()
            .table(Alias::new(table_name))
            .add_column(ColumnDef::new_with_type(Alias::new(col_name), col_type.into()).to_owned())
            .to_owned();

        self.db.execute_raw(db_backend.build(&statement)).await?;

        Ok(())
    }

    pub async fn drop_column(&self, table_name: &str, col_name: &str) -> Result<(), DbErr> {
        let db_backend = self.db.get_database_backend();

        let statement = Table::alter()
            .table(Alias::new(table_name))
            .drop_column(Alias::new(col_name))
            .to_owned();

        self.db.execute_raw(db_backend.build(&statement)).await?;

        Ok(())
    }
}

impl<'a> DynamicTableEditor<'a> {
    pub async fn insert_row(
        &self,
        table_name: &str,
        data: HashMap<String, SeaValue>,
    ) -> Result<(), DbErr> {
        let db_backend = self.db.get_database_backend();

        let (columns, values): (Vec<_>, Vec<_>) = data.into_iter().collect();

        let statement = Query::insert()
            .into_table(Alias::new(table_name))
            .columns(columns.into_iter().map(Alias::new))
            .values_panic(values.into_iter().map(Expr::val))
            .to_owned();

        self.db.execute_raw(db_backend.build(&statement)).await?;

        Ok(())
    }

    pub async fn select_rows<'b, C>(
        &self,
        table_name: &'b str,
        columns: Option<C>,
        condition: Condition,
    ) -> Result<Vec<JsonValue>, DbErr>
    where
        C: IntoIterator,
        C::Item: Into<Cow<'b, str>>,
    {
        let db_backend = self.db.get_database_backend();

        let statement = {
            let mut statement = Query::select();

            match columns {
                Some(columns) => {
                    statement.columns(columns.into_iter().map(|v| Alias::new(v.into())))
                }
                None => statement.column(Asterisk),
            };

            statement
                .from(Alias::new(table_name))
                .cond_where(condition)
                .to_owned()
        };

        let rows = self.db.query_all_raw(db_backend.build(&statement)).await?;

        let results = rows
            .into_iter()
            .map(|row| JsonValue::from_query_result(&row, ""))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    pub async fn update_rows(
        &self,
        table_name: &str,
        condition: Condition,
        updates: HashMap<String, SeaValue>,
    ) -> Result<u64, DbErr> {
        if updates.is_empty() {
            return Ok(0);
        }

        let db_backend = self.db.get_database_backend();

        let values = updates
            .into_iter()
            .map(|(col, val)| (Alias::new(col), Expr::val(val)))
            .collect::<Vec<_>>();

        let statement = Query::update()
            .table(Alias::new(table_name))
            .cond_where(condition)
            .values(values)
            .to_owned();

        let result = self.db.execute_raw(db_backend.build(&statement)).await?;

        Ok(result.rows_affected())
    }

    pub async fn delete_rows(&self, table_name: &str, condition: Condition) -> Result<u64, DbErr> {
        let db_backend = self.db.get_database_backend();

        let statement = Query::delete()
            .from_table(Alias::new(table_name))
            .cond_where(condition)
            .to_owned();

        let result = self.db.execute_raw(db_backend.build(&statement)).await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::sea_query::{Alias, Func};
    use sea_orm::{Database, DbConn, ExprTrait, Statement};
    use std::collections::HashMap;

    pub mod prep {
        use super::*;

        pub async fn setup() -> DbConn {
            Database::connect("sqlite::memory:")
                .await
                .expect("Failed to setup in-memory DB")
        }

        pub async fn create_users_table(db: &DbConn) -> Result<(), DbErr> {
            let db_backend = db.get_database_backend();

            let statement = Table::create()
                .table(Alias::new("users"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("id"))
                        .integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(ColumnDef::new(Alias::new("name")).string())
                .col(ColumnDef::new(Alias::new("age")).integer())
                .to_owned();

            db.execute_raw(db_backend.build(&statement)).await?;

            Ok(())
        }
    }

    #[tokio::test]
    async fn test_create_table() -> Result<(), DbErr> {
        let db = prep::setup().await;
        let db_backend = db.get_database_backend();

        let editor = DynamicTableEditor::new(&db);
        let table_name = "account";

        editor.create_table(table_name).await?;

        let statement = Query::select()
            .expr_as(Func::count(Expr::col(Asterisk)), Alias::new("count"))
            .from(Alias::new("sqlite_master"))
            .cond_where(
                Condition::all()
                    .add(Expr::col("type").eq("table"))
                    .add(Expr::col("name").eq(table_name)),
            )
            .to_owned();

        let row = db
            .query_one_raw(db_backend.build(&statement))
            .await?
            .unwrap();
        let count: i32 = row.try_get("", "count")?;

        assert_eq!(
            count, 1,
            "Table '{}' should exist in sqlite_master",
            table_name
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_drop_table() -> Result<(), DbErr> {
        let db = prep::setup().await;
        prep::create_users_table(&db).await?;

        let db_backend = db.get_database_backend();

        let editor = DynamicTableEditor::new(&db);
        let table_name = "users";

        editor.drop_table(table_name).await?;

        let statement = Query::select()
            .expr(Func::count(Expr::col(Asterisk)))
            .from(Alias::new("sqlite_master"))
            .cond_where(
                Condition::all()
                    .add(Expr::col("type").eq("table"))
                    .add(Expr::col("name").eq(table_name)),
            )
            .to_owned();

        let row = db
            .query_one_raw(db_backend.build(&statement))
            .await?
            .unwrap();
        let count: i32 = row.try_get_by_index(0)?;

        assert_eq!(
            count, 0,
            "Table '{}' should be removed from sqlite_master",
            table_name
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_add_column() -> Result<(), DbErr> {
        let db = prep::setup().await;
        prep::create_users_table(&db).await?;

        let db_backend = db.get_database_backend();

        let editor = DynamicTableEditor::new(&db);
        let table_name = "users";
        let column_name = "nickname";

        editor
            .add_column(table_name, column_name, ColumnDataType::String)
            .await?;

        let statement =
            Statement::from_string(db_backend, format!("PRAGMA table_info({})", table_name));

        let columns = db.query_all_raw(statement).await?;

        let has_nickname = columns.iter().any(|res| {
            let name: String = res.try_get("", "name").unwrap_or_default();
            name == column_name
        });

        assert!(
            has_nickname,
            "Column '{}' should exist in table info",
            column_name
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_drop_column() -> Result<(), DbErr> {
        let db = prep::setup().await;
        prep::create_users_table(&db).await?;

        let db_backend = db.get_database_backend();

        let editor = DynamicTableEditor::new(&db);
        let table_name = "users";
        let column_name = "name";

        editor.drop_column(table_name, column_name).await?;

        let statement =
            Statement::from_string(db_backend, format!("PRAGMA table_info({})", table_name));

        let columns = db.query_all_raw(statement).await?;
        let has_name = columns.iter().any(|res| {
            let name: String = res.try_get("", "name").unwrap_or_default();
            name == column_name
        });

        assert!(!has_name, "Column '{}' should no longer exist", column_name);
        Ok(())
    }

    #[tokio::test]
    async fn test_insert_row() -> Result<(), DbErr> {
        let db = prep::setup().await;
        prep::create_users_table(&db).await?;

        let db_backend = db.get_database_backend();

        let editor = DynamicTableEditor::new(&db);
        let table_name = "users";

        let data = HashMap::from([
            ("name".to_string(), SeaValue::from("Alice")),
            ("age".to_string(), SeaValue::from(30)),
        ]);
        editor.insert_row(table_name, data).await?;

        let statement = Query::select()
            .column(Asterisk)
            .from(Alias::new(table_name))
            .limit(1)
            .to_owned();
        let query_result = db
            .query_one_raw(db_backend.build(&statement))
            .await?
            .unwrap();

        let name: String = query_result.try_get("", "name")?;
        let age: i32 = query_result.try_get("", "age")?;

        assert_eq!(name, "Alice");
        assert_eq!(age, 30);

        Ok(())
    }

    #[tokio::test]
    async fn test_select_rows() -> Result<(), DbErr> {
        let db = prep::setup().await;
        prep::create_users_table(&db).await?;

        let db_backend = db.get_database_backend();

        let editor = DynamicTableEditor::new(&db);
        let table_name = "users";

        let statement = Query::insert()
            .into_table(Alias::new(table_name))
            .columns([Alias::new("name"), Alias::new("age")])
            .values_panic([Expr::val("Bob"), Expr::val(25)])
            .values_panic([Expr::val("Charlie"), Expr::val(40)])
            .to_owned();
        db.execute_raw(db_backend.build(&statement)).await?;

        let condition = Condition::all().add(Expr::col(Alias::new("name")).eq("Charlie"));
        let results = editor
            .select_rows("users", Some(["name", "age"]), condition)
            .await?;

        assert_eq!(results.len(), 1, "Should only return Charlie");
        assert_eq!(results[0]["name"], "Charlie");
        assert_eq!(results[0]["age"], 40);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_rows() -> Result<(), DbErr> {
        let db = prep::setup().await;
        prep::create_users_table(&db).await?;

        let db_backend = db.get_database_backend();

        let editor = DynamicTableEditor::new(&db);
        let table_name = "users";

        let statement = Query::insert()
            .into_table(Alias::new(table_name))
            .columns([Alias::new("name"), Alias::new("age")])
            .values_panic([Expr::val("Diana"), Expr::val(28)])
            .to_owned();
        db.execute_raw(db_backend.build(&statement)).await?;

        let condition = Condition::all().add(Expr::col(Alias::new("name")).eq("Diana"));
        let updates = HashMap::from([("age".to_string(), SeaValue::from(29))]);
        editor
            .update_rows("users", condition.clone(), updates)
            .await?;

        let statement = Query::select()
            .column(Alias::new("age"))
            .from(Alias::new(table_name))
            .cond_where(condition)
            .to_owned();
        let query_result = db
            .query_one_raw(db_backend.build(&statement))
            .await?
            .unwrap();
        let age: i32 = query_result.try_get("", "age")?;

        assert_eq!(age, 29, "Database should reflect the update");

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_rows() -> Result<(), DbErr> {
        let db = prep::setup().await;
        prep::create_users_table(&db).await?;

        let db_backend = db.get_database_backend();

        let editor = DynamicTableEditor::new(&db);
        let table_name = "users";

        let statement = Query::insert()
            .into_table(Alias::new(table_name))
            .columns([Alias::new("name"), Alias::new("age")])
            .values_panic([Expr::val("Evan"), Expr::val(50)])
            .to_owned();
        db.execute_raw(db_backend.build(&statement)).await?;

        let condition = Condition::all().add(Expr::col(Alias::new("name")).eq("Evan"));
        editor.delete_rows("users", condition.clone()).await?;

        let statement = Query::select()
            .expr_as(Func::count(Expr::col(Asterisk)), Alias::new("count"))
            .from(Alias::new(table_name))
            .cond_where(condition)
            .to_owned();
        let query_result = db
            .query_one_raw(db_backend.build(&statement))
            .await?
            .unwrap();
        let count: i32 = query_result.try_get("", "count")?;

        assert_eq!(count, 0, "Row should be physically gone from the database");

        Ok(())
    }
}
