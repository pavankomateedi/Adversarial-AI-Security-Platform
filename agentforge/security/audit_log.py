"""Immutable audit log writer (CLAUDE.md §8.4).

Every state mutation writes one row to the audit_log table. The DB trigger
installed in migration 001 ensures the row can never be updated or deleted,
so the audit trail is tamper-evident.

This module intentionally exposes both a function-call API (for routers and
agents) and a `record_via_middleware` FastAPI middleware that captures
common mutations automatically. They can be used together — the middleware
covers the easy 80% and routers can call `record_audit` for nuanced events
(e.g. CRITICAL approval, regression trigger reason).
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

from fastapi import Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

from agentforge.db.database import session_scope
from agentforge.db.models import AuditLog

logger = logging.getLogger(__name__)


# Actions the middleware auto-records, keyed by (method, prefix).
_AUTO_ACTIONS: dict[tuple[str, str], tuple[str, str]] = {
    ("POST", "/api/v1/campaigns"): ("CAMPAIGN_STARTED", "campaign"),
    ("DELETE", "/api/v1/campaigns"): ("CAMPAIGN_CANCELLED", "campaign"),
    ("PATCH", "/api/v1/findings"): ("FINDING_STATUS_CHANGED", "finding"),
    ("POST", "/api/v1/regression/run"): ("REGRESSION_TRIGGERED", "regression_run"),
    ("POST", "/api/v1/auth/token"): ("TOKEN_ISSUED", "auth"),
}


def _normalize_ip(addr: str | None) -> str | None:
    """Return `addr` only if it parses as a real IP address.

    Why: the audit_log.ip_address column is PostgreSQL INET. Strings like
    "testclient" (TestClient) or "unknown" (no socket) get rejected by the
    driver with a DataError. We'd rather store NULL than have audit-log
    writes fail and silently lose mutations from the audit trail.
    """
    if not addr:
        return None
    try:
        ipaddress.ip_address(addr)
        return addr
    except ValueError:
        return None


async def record_audit(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    resource_type: str | None = None,
    resource_id: UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    audit_metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """Insert a single audit_log row. Caller owns the session."""
    row = AuditLog(
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=_normalize_ip(ip_address),
        user_agent=(user_agent or "")[:500] or None,
        audit_metadata=audit_metadata,
    )
    session.add(row)
    await session.flush()
    return row


class AuditMiddleware(BaseHTTPMiddleware):
    """Auto-record mutation requests after they complete with 2xx/4xx.

    Only logs the request-level event ("this action was attempted by IP X").
    Per-action context (e.g. which finding_id was approved) is appended by
    the router calling `record_audit` with the structured fields.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:  # type: ignore[override]
        response = await call_next(request)

        key = (request.method, _prefix_match(request.url.path))
        action_tuple = _AUTO_ACTIONS.get(key)
        if action_tuple is None:
            return response

        action, resource_type = action_tuple
        # Best-effort: never let an audit failure break the request.
        try:
            principal = getattr(request.state, "principal", None)
            actor = (
                principal.subject if principal is not None else f"anon:{request.client.host if request.client else 'unknown'}"
            )
            async with session_scope() as session:
                await record_audit(
                    session,
                    actor=actor,
                    action=action,
                    resource_type=resource_type,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"),
                    audit_metadata={
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": response.status_code,
                    },
                )
        except Exception:  # noqa: BLE001
            logger.exception("audit_log_write_failed path=%s", request.url.path)

        return response


def _prefix_match(path: str) -> str:
    """Collapse parametric paths so /campaigns/<uuid> still matches /campaigns."""
    for prefix in (
        "/api/v1/campaigns",
        "/api/v1/findings",
        "/api/v1/regression/run",
        "/api/v1/auth/token",
    ):
        if path == prefix or path.startswith(prefix + "/"):
            return prefix
    return path
