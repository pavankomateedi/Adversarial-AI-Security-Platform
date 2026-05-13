"""Liveness + readiness health checks.

GET /api/v1/health  → 200 with dependency status, or 503 if any dependency down.
Railway uses this for healthchecks (railway.toml healthcheckPath).
"""
from __future__ import annotations

from typing import Literal

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge import __version__
from agentforge.config import Settings, get_settings
from agentforge.db.database import get_session
from agentforge.templates import HEALTH_HTML

router = APIRouter(tags=["health"])


class DependencyStatus(BaseModel):
    name: str
    status: Literal["up", "down"]
    detail: str | None = None


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded"]
    version: str
    environment: str
    dependencies: list[DependencyStatus]


async def _check_database(db: AsyncSession) -> DependencyStatus:
    try:
        await db.execute(text("SELECT 1"))
        return DependencyStatus(name="database", status="up")
    except Exception as e:  # noqa: BLE001 — surface broad failures as "down"
        return DependencyStatus(name="database", status="down", detail=str(e)[:200])


async def _check_redis(settings: Settings) -> DependencyStatus:
    client: aioredis.Redis | None = None
    try:
        client = aioredis.from_url(settings.redis_url, socket_timeout=2)
        pong = await client.ping()
        return DependencyStatus(
            name="redis", status="up" if pong else "down", detail=None if pong else "PING returned falsy"
        )
    except Exception as e:  # noqa: BLE001
        return DependencyStatus(name="redis", status="down", detail=str(e)[:200])
    finally:
        if client is not None:
            await client.aclose()


@router.get(
    "/health",
    summary="Liveness + dependency readiness check",
)
async def health_check(
    request: Request,
    response: Response,
    format: str | None = None,
    db: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
):
    """Content-negotiated: HTML for browsers, JSON for Railway / Prometheus.

    Force JSON with `?format=json` (the dashboard does this so the page can
    fetch its own status without re-rendering the page inside itself).
    """
    accept = request.headers.get("accept", "")
    wants_html = format != "json" and "text/html" in accept

    # Browser path — return the styled health card without computing deps
    # (the page polls /api/v1/health?format=json itself for live data).
    if wants_html:
        return HTMLResponse(content=HEALTH_HTML)

    deps = [await _check_database(db), await _check_redis(settings)]
    healthy = all(d.status == "up" for d in deps)
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(
        status="healthy" if healthy else "degraded",
        version=__version__,
        environment=settings.environment,
        dependencies=deps,
    )
