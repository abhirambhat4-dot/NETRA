"""Development schema initialisation.

Creates any missing NETRA tables. Existing tables and data are never dropped or altered.
Run with:  python -m app.db.init_db
"""

from sqlalchemy import Connection, inspect

import app.models  # noqa: F401  (registers all models on Base.metadata)
from app.db.base import Base
from app.db.session import engine


def create_tables(connection: Connection) -> list[str]:
    """Create missing tables and return the names that were newly created."""
    existing = set(inspect(connection).get_table_names())
    Base.metadata.create_all(connection, checkfirst=True)
    return sorted(set(Base.metadata.tables) - existing)


def main() -> None:
    with engine.begin() as connection:
        created = create_tables(connection)
        all_tables = sorted(inspect(connection).get_table_names())

    print(f"Created {len(created)} table(s): {', '.join(created) or 'none'}")
    print(f"Tables now in database ({len(all_tables)}): {', '.join(all_tables)}")
    engine.dispose()


if __name__ == "__main__":
    main()
