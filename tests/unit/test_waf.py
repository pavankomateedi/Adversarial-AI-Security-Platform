"""Unit tests for the WAF middleware."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentforge.security.waf import WAFMiddleware


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.add_middleware(WAFMiddleware)

    @app.get("/api/v1/health")
    def health():
        return {"ok": True}

    @app.post("/api/v1/findings/x")
    def findings(body: dict):
        return {"ok": True}

    return TestClient(app)


class TestWAFBlocks:
    def test_allows_healthy_request(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200

    def test_blocks_sql_injection_in_query(self, client):
        r = client.get("/api/v1/health?q=union+select+*+from+users")
        assert r.status_code == 400
        assert r.json()["blocked_by"] == "waf"

    def test_blocks_path_traversal_in_query(self, client):
        r = client.get("/api/v1/health?file=..%2f..%2fetc%2fpasswd")
        assert r.status_code == 400

    def test_blocks_scanner_user_agent(self, client):
        r = client.get("/api/v1/health", headers={"User-Agent": "sqlmap/1.0"})
        assert r.status_code == 403

    def test_blocks_oversized_body(self, client):
        big_payload = "x" * (50 * 1024 + 1)
        r = client.post("/api/v1/findings/x", content=big_payload, headers={"Content-Type": "application/json"})
        assert r.status_code == 413

    def test_blocks_sqli_in_body(self, client):
        r = client.post("/api/v1/findings/x", json={"q": "1' OR 1=1 --"})
        assert r.status_code == 400

    def test_allows_normal_body(self, client):
        r = client.post("/api/v1/findings/x", json={"status": "IN_PROGRESS"})
        assert r.status_code == 200
