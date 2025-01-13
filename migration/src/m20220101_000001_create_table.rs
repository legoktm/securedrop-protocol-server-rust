use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Journalist::Table)
                    .if_not_exists()
                    .col(pk_auto(Journalist::Id))
                    .col(blob(Journalist::Keys))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Journalist::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Journalist {
    Table,
    Id,
    Keys,
}
