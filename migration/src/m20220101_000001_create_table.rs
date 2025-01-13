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
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(EphemeralKey::Table)
                    .if_not_exists()
                    .col(pk_auto(EphemeralKey::Id))
                    .col(integer(EphemeralKey::JournalistId))
                    .col(blob(EphemeralKey::Key))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-ephemeral-journalist")
                            .from(
                                EphemeralKey::Table,
                                EphemeralKey::JournalistId,
                            )
                            .to(Journalist::Table, Journalist::Id),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Journalist::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(EphemeralKey::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Journalist {
    Table,
    Id,
    Keys,
}

#[derive(DeriveIden)]
enum EphemeralKey {
    Table,
    Id,
    JournalistId,
    Key,
}
