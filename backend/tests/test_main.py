"""
Unit Tests for FastAPI Main Application (backend/app/main.py)
"""

import pytest
from httpx import AsyncClient, ASGITransport
from fastapi.testclient import TestClient

from app.main import app, create_app
from app.config import settings
from app.database import init_db, set_database_path


@pytest.fixture
async def async_test_client(tmp_path):
    """Async test client with temporary database configured."""
    db_file = tmp_path / "main_test.db"
    set_database_path(db_file)
    await init_db(db_file)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.mark.asyncio
async def test_health_check_endpoint(async_test_client):
    """GET /api/health returns status and all core subsystem reports."""
    response = await async_test_client.get("/api/health")
    assert response.status_code == 200

    data = response.json()
    assert "status" in data
    assert "app_name" in data
    assert "version" in data
    assert "environment" in data
    assert "components" in data

    components = data["components"]
    assert "ffmpeg" in components
    assert "go2rtc" in components
    assert "database" in components
    assert "vault" in components

    # FFmpeg should be available via imageio_ffmpeg
    assert components["ffmpeg"]["status"] == "available"
    # Database is initialized in test
    assert components["database"]["status"] == "connected"


@pytest.mark.asyncio
async def test_security_headers_and_csp(async_test_client):
    """Verify CSP and HTTP security headers are injected into responses."""
    response = await async_test_client.get("/api/health")
    headers = response.headers

    assert "content-security-policy" in headers
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "mediastream:" in csp
    assert "blob:" in csp
    assert "ws:" in csp

    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("x-xss-protection") == "1; mode=block"
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"


@pytest.mark.asyncio
async def test_cors_headers(async_test_client):
    """Verify CORS preflight and origin headers."""
    response = await async_test_client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


@pytest.mark.asyncio
async def test_404_json_error_envelope(async_test_client):
    """Verify 404 responses return structured JSON error envelopes."""
    response = await async_test_client.get("/api/non_existent_route_404")
    assert response.status_code == 404
    data = response.json()
    assert data.get("error") is True
    assert data.get("status_code") == 404
    assert "detail" in data


def test_create_app_factory():
    """Verify create_app factory produces valid FastAPI instance with routes."""
    instance = create_app()
    assert instance.title == settings.APP_NAME
    assert instance.version == settings.APP_VERSION

    # Check that /api/health route is registered
    route_paths = [route.path for route in instance.routes]
    assert "/api/health" in route_paths
