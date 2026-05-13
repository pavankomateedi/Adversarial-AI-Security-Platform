"""Rate limiting (CLAUDE.md §8.3).

Per-IP rate limits enforced via the `limits` library directly — slowapi is
decorator-only, so we use the underlying primitives to apply policy at
middleware level. Storage is Redis when available, in-memory otherwise
(both supported out of the box).
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import Request, Response
from limits import parse as limits_parse
from limits.aio.storage import MemoryStorage, RedisStorage
from limits.aio.strategies import MovingWindowRateLimiter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from agentforge.config import get_settings

logger = logging.getLogger(__name__)


# Per-path policy. Stricter on writes; defaults to 60/min.
_PATH_LIMITS: dict[str, str] = {
    "/api/v1/campaigns:POST": "5/minute",
    "/api/v1/auth/token:POST": "10/minute",
    "/api/v1/regression/run:POST": "5/minute",
    "/api/v1/findings:PATCH": "30/minute",
}
_DEFAULT_LIMIT = "60/minute"


def _client_ip(request: Request) -> str:
    """Best-effort client IP, honoring X-Forwarded-For for Railway's proxy."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _rule_for(method: str, path: str) -> str:
    return _PATH_LIMITS.get(f"{path}:{method}", _DEFAULT_LIMIT)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP token-bucket-style limiter.

    Why not slowapi: slowapi's `limit()` is a route decorator and refuses
    to operate at middleware level. The `limits` library — which slowapi
    itself wraps — gives us the same backends with a less opinionated API.
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        settings = get_settings()
        # Sync init; the async storage is what gets used per-request.
        try:
            self._storage = RedisStorage(settings.redis_url) if settings.redis_url else MemoryStorage()
        except Exception:  # noqa: BLE001
            logger.exception("rate_limiter: redis storage init failed — falling back to in-memory")
            self._storage = MemoryStorage()
        self._limiter = MovingWindowRateLimiter(self._storage)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:  # type: ignore[override]
        # /metrics is internal-only and must not be rate-limited — Prometheus
        # scrapers hit it every 15s.
        if request.url.path == "/metrics":
            return await call_next(request)

        rule = _rule_for(request.method, request.url.path)
        item = limits_parse(rule)
        ip = _client_ip(request)
        identifier = f"{ip}:{request.method}:{request.url.path}"

        try:
            allowed = await self._limiter.hit(item, identifier)
        except Exception:  # noqa: BLE001
            # Don't fail-closed on rate-limit backend errors; log and let through.
            logger.exception("rate_limiter backend error; allowing request")
            return await call_next(request)

        if not allowed:
            try:
                reset_in = int(await self._limiter.get_window_stats(item, identifier).reset_time)
            except Exception:  # noqa: BLE001
                reset_in = 60
            logger.info(
                "rate_limit_exceeded ip=%s method=%s path=%s rule=%s",
                ip,
                request.method,
                request.url.path,
                rule,
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded", "rule": rule},
                headers={"Retry-After": str(max(1, reset_in))},
            )
        return await call_next(request)
