from collections.abc import Iterator

from sqlalchemy.exc import OperationalError

from app.db.dependencies import get_db
from app.main import app
from tests.conftest import AsgiGet


def test_database_health_check(asgi_get: AsgiGet) -> None:
    """Runs a read-only SELECT 1 against the configured PostgreSQL database."""
    status, data = asgi_get("/api/health/db")

    assert status == 200
    assert data == {
        "status": "healthy",
        "service": "NETRA API",
        "version": "1.0.0",
        "database": "connected",
    }


def test_database_health_check_unreachable(asgi_get: AsgiGet) -> None:
    class FailingSession:
        def execute(self, *args: object, **kwargs: object) -> None:
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    def failing_db() -> Iterator[FailingSession]:
        yield FailingSession()

    app.dependency_overrides[get_db] = failing_db
    try:
        status, data = asgi_get("/api/health/db")
    finally:
        app.dependency_overrides.clear()

    assert status == 503
    assert data["status"] == "unhealthy"
    assert data["database"] == "unreachable"
    assert "connection refused" not in str(data)
