touch sqlite.db
DATABASE_URL="sqlite://sqlite.db" sea-orm-cli migrate
DATABASE_URL="sqlite://sqlite.db" sea-orm-cli generate entity -o src/entity/
