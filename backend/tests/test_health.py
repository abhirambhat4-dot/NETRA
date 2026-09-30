from tests.conftest import AsgiGet


def test_health_check(asgi_get: AsgiGet) -> None:
    status, data = asgi_get("/api/health")

    assert status == 200
    assert data["status"] == "healthy"
    assert data["service"] == "NETRA API"
    assert data["version"] == "1.0.0"
