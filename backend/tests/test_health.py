from app.core.config import get_settings
from tests.conftest import AsgiGet


def test_health_check(asgi_get: AsgiGet) -> None:
    status, data = asgi_get("/api/health")

    assert status == 200
    assert data["status"] == "healthy"
    assert data["service"] == get_settings().app_name
    assert data["version"] == "1.0.0"
