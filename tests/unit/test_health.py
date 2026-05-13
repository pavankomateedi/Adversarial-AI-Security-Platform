"""Unit tests for the /health endpoint — DB and Redis are stubbed."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from agentforge.api import health as health_module
from agentforge.main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _stub(name: str, up: bool):
    return health_module.DependencyStatus(
        name=name, status="up" if up else "down", detail=None if up else "stubbed failure"
    )


def test_health_returns_200_when_all_deps_up(client: TestClient):
    with (
        patch.object(health_module, "_check_database", new=AsyncMock(return_value=_stub("database", True))),
        patch.object(health_module, "_check_redis", new=AsyncMock(return_value=_stub("redis", True))),
    ):
        r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "healthy"
    assert body["version"]
    deps = {d["name"]: d["status"] for d in body["dependencies"]}
    assert deps == {"database": "up", "redis": "up"}


def test_health_returns_503_when_any_dep_down(client: TestClient):
    with (
        patch.object(health_module, "_check_database", new=AsyncMock(return_value=_stub("database", True))),
        patch.object(health_module, "_check_redis", new=AsyncMock(return_value=_stub("redis", False))),
    ):
        r = client.get("/api/v1/health")
    assert r.status_code == 503
    assert r.json()["status"] == "degraded"


def test_request_id_header_is_set(client: TestClient):
    with (
        patch.object(health_module, "_check_database", new=AsyncMock(return_value=_stub("database", True))),
        patch.object(health_module, "_check_redis", new=AsyncMock(return_value=_stub("redis", True))),
    ):
        r = client.get("/api/v1/health")
    assert "x-request-id" in {k.lower() for k in r.headers}
