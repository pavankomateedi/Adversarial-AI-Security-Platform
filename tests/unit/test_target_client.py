"""Unit tests for target_client.

Uses httpx.MockTransport so we don't hit the live Co-Pilot in CI.
"""

from __future__ import annotations

import httpx
import pytest

from agentforge.config import get_settings
from agentforge.core.target_client import ClinicalCopilotClient, TargetAuthError
from agentforge.models.attack import AttackTurn


@pytest.fixture
def client():
    """Real ClinicalCopilotClient with its underlying httpx swapped for MockTransport."""
    settings = get_settings()
    c = ClinicalCopilotClient(settings)
    return c


async def _swap_transport(client: ClinicalCopilotClient, handler) -> None:
    await client._client.aclose()
    client._client = httpx.AsyncClient(
        base_url=get_settings().backend_url,
        transport=httpx.MockTransport(handler),
        timeout=2.0,
        follow_redirects=False,
    )


async def test_login_succeeds_on_200(monkeypatch, client):
    monkeypatch.setenv("BACKEND_USERNAME", "dr.pavan")
    monkeypatch.setenv("BACKEND_PASSWORD", "PavanDaily!2026")
    get_settings.cache_clear()
    client._settings = get_settings()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/auth/login"
        return httpx.Response(
            200,
            json={
                "user": {"id": 1, "username": "dr.pavan", "email": "x", "role": "physician", "totp_enrolled": False},
                "needs_mfa": False,
            },
        )

    await _swap_transport(client, handler)
    await client.login()
    assert client._authenticated
    await client.aclose()


async def test_login_raises_on_missing_credentials():
    from agentforge.config import Settings
    # Construct a Settings instance bypassing .env so we can simulate
    # "creds not configured" without depending on disk state.
    fake = Settings.model_construct(
        backend_url="http://localhost:9",
        backend_username=None,
        backend_password=None,
    )
    c = ClinicalCopilotClient(fake)
    with pytest.raises(TargetAuthError):
        await c.login()
    await c.aclose()


async def test_login_rejects_mfa_required(monkeypatch, client):
    monkeypatch.setenv("BACKEND_USERNAME", "u")
    monkeypatch.setenv("BACKEND_PASSWORD", "p")
    get_settings.cache_clear()
    client._settings = get_settings()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"user": None, "needs_mfa": True, "mfa_action": "challenge"})

    await _swap_transport(client, handler)
    with pytest.raises(TargetAuthError, match="MFA"):
        await client.login()
    await client.aclose()


async def test_send_message_normalizes_chat_response(monkeypatch, client):
    monkeypatch.setenv("BACKEND_USERNAME", "u")
    monkeypatch.setenv("BACKEND_PASSWORD", "p")
    get_settings.cache_clear()
    client._settings = get_settings()

    call_log = []

    def handler(request: httpx.Request) -> httpx.Response:
        call_log.append(request.url.path)
        if request.url.path == "/auth/login":
            return httpx.Response(200, json={"user": {"id": 1}, "needs_mfa": False})
        if request.url.path == "/chat":
            return httpx.Response(
                200,
                json={
                    "response": "I cannot help with that — clinical scope.",
                    "verified": False,
                    "trace": {"tool_calls": []},
                },
            )
        return httpx.Response(404)

    await _swap_transport(client, handler)
    r = await client.send_message("test", patient_id="P001")
    assert r.status_code == 200
    assert r.response_text.startswith("I cannot help")
    assert r.verified is False
    assert r.trace == {"tool_calls": []}
    assert r.is_refusal
    assert call_log == ["/auth/login", "/chat"]
    await client.aclose()


async def test_reauth_on_401(monkeypatch, client):
    monkeypatch.setenv("BACKEND_USERNAME", "u")
    monkeypatch.setenv("BACKEND_PASSWORD", "p")
    get_settings.cache_clear()
    client._settings = get_settings()

    state = {"login_count": 0, "chat_count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/login":
            state["login_count"] += 1
            return httpx.Response(200, json={"user": {"id": 1}, "needs_mfa": False})
        if request.url.path == "/chat":
            state["chat_count"] += 1
            if state["chat_count"] == 1:
                return httpx.Response(401, json={"detail": "Not authenticated"})
            return httpx.Response(200, json={"response": "ok", "verified": True, "trace": {}})
        return httpx.Response(404)

    await _swap_transport(client, handler)
    r = await client.send_message("hi", patient_id="P001")
    assert r.status_code == 200
    assert state["login_count"] == 2, "should re-login on 401"
    assert state["chat_count"] == 2
    await client.aclose()


async def test_send_conversation_threads_history(monkeypatch, client):
    monkeypatch.setenv("BACKEND_USERNAME", "u")
    monkeypatch.setenv("BACKEND_PASSWORD", "p")
    get_settings.cache_clear()
    client._settings = get_settings()

    captured_histories: list[list[dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/login":
            return httpx.Response(200, json={"user": {"id": 1}, "needs_mfa": False})
        if request.url.path == "/chat":
            import json as _json

            body = _json.loads(request.content.decode())
            captured_histories.append(body.get("history", []))
            return httpx.Response(200, json={"response": f"echo: {body['message']}", "verified": True, "trace": {}})
        return httpx.Response(404)

    await _swap_transport(client, handler)
    turns = [
        AttackTurn(role="user", content="first"),
        AttackTurn(role="user", content="second"),
    ]
    results = await client.send_conversation(turns, patient_id="P001")
    assert len(results) == 2
    # First call sees empty history; second call sees first user + first assistant echo.
    assert captured_histories[0] == []
    assert len(captured_histories[1]) == 2
    assert captured_histories[1][0]["content"] == "first"
    assert captured_histories[1][1]["role"] == "assistant"
    await client.aclose()
