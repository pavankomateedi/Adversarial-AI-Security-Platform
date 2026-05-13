"""Unit tests for the AgentForgeError hierarchy + FastAPI handler wiring."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentforge.errors import (
    AgentExecutionError,
    AgentForgeError,
    BudgetExceededError,
    TargetError,
    register_exception_handlers,
)


@pytest.fixture
def app() -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/raise/budget")
    def _budget():
        raise BudgetExceededError("Hard ceiling hit", detail={"limit": 5.0, "spent": 5.5})

    @app.get("/raise/target")
    def _target():
        raise TargetError("Co-Pilot returned 500", detail={"status": 500})

    @app.get("/raise/agent")
    def _agent():
        raise AgentExecutionError("RedTeam failed to produce a mutation")

    @app.get("/raise/unknown")
    def _unknown():
        raise RuntimeError("oops")

    return app


def test_budget_exceeded_returns_402(app):
    r = TestClient(app).get("/raise/budget")
    assert r.status_code == 402
    body = r.json()
    assert body["error_code"] == "budget_exceeded"
    assert body["metadata"]["limit"] == 5.0


def test_target_error_returns_502(app):
    r = TestClient(app).get("/raise/target")
    assert r.status_code == 502
    assert r.json()["error_code"] == "target_error"


def test_agent_execution_error_returns_500(app):
    r = TestClient(app).get("/raise/agent")
    assert r.status_code == 500
    assert r.json()["error_code"] == "agent_execution_error"


def test_unknown_exception_returns_safe_500(app):
    # TestClient by default re-raises unhandled exceptions; we want the
    # handler-translated response instead.
    r = TestClient(app, raise_server_exceptions=False).get("/raise/unknown")
    assert r.status_code == 500
    body = r.json()
    assert body["error_code"] == "internal_server_error"
    # Must not leak the traceback / original message.
    assert "oops" not in body["detail"]


def test_base_error_class_carries_metadata():
    err = AgentForgeError("x", detail={"y": 1})
    assert err.message == "x"
    assert err.detail == {"y": 1}
    assert err.status_code == 500
