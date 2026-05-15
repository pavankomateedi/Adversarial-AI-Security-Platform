"""HTTP client for the deployed OpenEMR Clinical Co-Pilot.

The Co-Pilot uses session-cookie auth (POST /auth/login). This client logs in
on first use, persists the cookie via httpx.AsyncClient, and transparently
re-authenticates on 401 so a long-running campaign doesn't break when the
session expires.

No changes to the Co-Pilot are required — this is purely an outbound adapter.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from typing import Any

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from agentforge.config import Settings, get_settings
from agentforge.models.attack import AttackTurn, TargetResponse

logger = logging.getLogger(__name__)

# Errors that warrant retry (network blips, target restart). 401/403 are NOT
# retried via tenacity — we handle re-auth explicitly so we don't burn retries
# on a known-bad session cookie.
_RETRYABLE_EXC = (
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.RemoteProtocolError,
    httpx.PoolTimeout,
)


class TargetAuthError(RuntimeError):
    """Raised when credentials are missing or rejected."""


class ClinicalCopilotClient:
    """Outbound adapter to the Clinical Co-Pilot.

    Lifecycle: instantiate once per campaign / per agent. Always close via
    `await client.aclose()` or use as an async context manager.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        timeout: float = 30.0,
        username_override: str | None = None,
        password_override: str | None = None,
    ) -> None:
        """Construct a client for the Co-Pilot.

        `username_override` / `password_override` let one campaign run as a
        different test user (e.g. `nurse.adams` for cross-user RBAC probes)
        without mutating the global settings. When omitted we fall back to
        BACKEND_USERNAME / BACKEND_PASSWORD.
        """
        self._settings = settings or get_settings()
        self._username_override = username_override
        self._password_override = password_override
        self._client = httpx.AsyncClient(
            base_url=self._settings.backend_url,
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=False,
            # Pretend to be a generic clinician browser. WAFs occasionally block
            # bare python-httpx user agents.
            headers={"User-Agent": "AgentForge/1.0 (security-evaluation)"},
        )
        self._authenticated = False

    # ----- context manager plumbing ----------------------------------------------

    async def __aenter__(self) -> ClinicalCopilotClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ----- auth ------------------------------------------------------------------

    async def login(self) -> None:
        """Authenticate.

        Prefers the per-client overrides (username_override / password_override)
        when set — this is what lets cross_user_attacks.py log in as a
        DIFFERENT user (nurse.adams) than the global BACKEND_USERNAME in .env
        (dr.pavan). Without honoring the overrides, every "cross-user"
        probe would silently run as the default admin user, invalidating
        the whole RBAC test class.
        """
        username = self._username_override or self._settings.backend_username
        if self._password_override is not None:
            password_plain: str | None = self._password_override
        elif self._settings.backend_password is not None:
            password_plain = self._settings.backend_password.get_secret_value()
        else:
            password_plain = None
        if not username or not password_plain:
            raise TargetAuthError(
                "Username / password not configured — pass overrides or set "
                "BACKEND_USERNAME / BACKEND_PASSWORD."
            )

        resp = await self._client.post(
            "/auth/login",
            json={"username": username, "password": password_plain},
        )
        if resp.status_code != 200:
            raise TargetAuthError(
                f"Login failed: HTTP {resp.status_code} {resp.text[:200]}"
            )
        body = resp.json()
        if body.get("needs_mfa"):
            raise TargetAuthError(
                "Co-Pilot requires MFA for this account — disable MFA on the test user "
                "or seed an MFA secret (not supported yet)."
            )
        self._authenticated = True
        self._authenticated_as = username  # for diagnostics
        logger.info("target_client logged in as %s", username)

    async def _ensure_authenticated(self) -> None:
        if not self._authenticated:
            await self.login()

    # ----- core request path -----------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        require_auth: bool = True,
    ) -> TargetResponse:
        """Send a request with retry on network errors + one re-auth on 401."""
        if require_auth:
            await self._ensure_authenticated()

        start = time.perf_counter()
        last_exc: Exception | None = None
        resp: httpx.Response | None = None
        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(3),
                wait=wait_exponential(multiplier=0.5, min=0.5, max=4.0),
                retry=retry_if_exception_type(_RETRYABLE_EXC),
                reraise=True,
            ):
                with attempt:
                    resp = await self._client.request(
                        method, path, json=json, files=files, data=data, params=params
                    )
        except Exception as e:  # noqa: BLE001
            last_exc = e
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return TargetResponse(
                status_code=0,
                body=str(e),
                response_text=str(e),
                latency_ms=elapsed_ms,
                error=str(e),
            )

        assert resp is not None
        # One re-auth retry if the session expired mid-campaign.
        if resp.status_code == 401 and require_auth:
            logger.info("target_client got 401, re-authenticating")
            self._authenticated = False
            await self.login()
            resp = await self._client.request(
                method, path, json=json, files=files, data=data, params=params
            )

        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return _build_response(resp, elapsed_ms, last_exc)

    # ----- public API methods (CLAUDE.md §4 + ARCHITECTURE.md) -------------------

    async def send_message(
        self,
        content: str,
        *,
        patient_id: str,
        history: Iterable[AttackTurn] | None = None,
        multi_agent: bool = False,
    ) -> TargetResponse:
        """Send a single message via POST /chat."""
        history_payload = (
            [{"role": t.role, "content": t.content} for t in history] if history else []
        )
        return await self._request(
            "POST",
            "/chat",
            json={
                "patient_id": patient_id,
                "message": content,
                "history": history_payload,
                "multi_agent": multi_agent,
            },
        )

    async def send_conversation(
        self,
        messages: list[AttackTurn],
        *,
        patient_id: str,
        multi_agent: bool = False,
    ) -> list[TargetResponse]:
        """Replay a multi-turn conversation, accumulating history server-side."""
        history: list[AttackTurn] = []
        responses: list[TargetResponse] = []
        for turn in messages:
            if turn.role != "user":
                # Pre-canned assistant turns are appended to history but not sent.
                history.append(turn)
                continue
            r = await self.send_message(
                turn.content, patient_id=patient_id, history=history, multi_agent=multi_agent
            )
            responses.append(r)
            history.append(turn)
            # Echo the actual assistant response into history for the next turn.
            if r.response_text:
                history.append(AttackTurn(role="assistant", content=r.response_text))
        return responses

    async def upload_document(
        self,
        content: bytes,
        *,
        patient_id: str,
        filename: str = "evidence.pdf",
        doc_type: str = "lab_pdf",
        content_type: str = "application/pdf",
    ) -> TargetResponse:
        """Upload a document via POST /documents/upload (indirect-injection vector)."""
        await self._ensure_authenticated()
        start = time.perf_counter()
        try:
            resp = await self._client.post(
                "/documents/upload",
                data={"patient_id": patient_id, "doc_type": doc_type},
                files={"file": (filename, content, content_type)},
            )
        except Exception as e:  # noqa: BLE001
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return TargetResponse(
                status_code=0,
                body=str(e),
                response_text=str(e),
                latency_ms=elapsed_ms,
                error=str(e),
            )
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return _build_response(resp, elapsed_ms, None)

    async def probe_patient_chart(self, patient_id: str) -> TargetResponse:
        """Try to read a patient identity / chart for cross-patient PHI probes."""
        return await self._request("GET", f"/patients/{patient_id}/identity")

    async def list_documents(self, patient_id: str) -> TargetResponse:
        return await self._request("GET", "/documents/list", params={"patient_id": patient_id})

    async def health(self) -> TargetResponse:
        return await self._request("GET", "/health", require_auth=False)


def _build_response(
    resp: httpx.Response,
    elapsed_ms: int,
    last_exc: Exception | None,
) -> TargetResponse:
    try:
        body = resp.json()
        body_for_text = body
    except ValueError:
        body = resp.text
        body_for_text = body

    # Normalize the /chat shape ({response, verified, trace}) into top-level fields.
    response_text: str
    verified: bool | None = None
    trace: dict[str, Any] = {}
    if isinstance(body_for_text, dict):
        response_text = str(body_for_text.get("response", "") or body_for_text.get("detail", ""))
        if not response_text:
            response_text = str(body_for_text)
        verified = body_for_text.get("verified")
        raw_trace = body_for_text.get("trace")
        if isinstance(raw_trace, dict):
            trace = raw_trace
    else:
        response_text = str(body_for_text)

    return TargetResponse(
        status_code=resp.status_code,
        body=body,
        response_text=response_text,
        latency_ms=elapsed_ms,
        verified=verified,
        trace=trace,
        headers=dict(resp.headers),
        error=str(last_exc) if last_exc else None,
    )
