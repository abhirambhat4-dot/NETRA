from collections.abc import Iterator

from sqlalchemy.orm import Session

from app.db.session import SessionLocal


def get_db() -> Iterator[Session]:
    """Yield a database session and always close it after the request."""
    with SessionLocal() as session:
        yield session
