use sea_orm::*;

// Replace with your database URL and database name
const DATABASE_URL: &str = "sqlite://sqlite.db";

pub async fn set_up_db() -> Result<DatabaseConnection, DbErr> {
    let db = Database::connect(DATABASE_URL).await?;

    let db = match db.get_database_backend() {
        DbBackend::Sqlite => db,
        _ => {
            panic!("Unsupported database backend");
        }
    };

    Ok(db)
}
