"""Project-wide exception hierarchy + FastAPI exception handlers.

A small, deliberate hierarchy so callers can `except AgentForgeError` once
and get a structured detail back instead of bare 500s.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class AgentForgeError(Exception):
    """Base for all project-specific errors. status_code controls the HTTP code."""

    status_code: int = 500
    error_code: str = "agentforge_error"

    def __init__(self, message: str, *, detail: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class ConfigError(AgentForgeError):
    status_code = 500
    error_code = "config_error"


class TargetError(AgentForgeError):
    """Anything that goes wrong talking to the Clinical Co-Pilot."""

    status_code = 502
    error_code = "target_error"


class AgentExecutionError(AgentForgeError):
    """Wraps unexpected failures inside an agent run."""

    status_code = 500
    error_code = "agent_execution_error"


class BudgetExceededError(AgentForgeError):
    status_code = 402
    error_code = "budget_exceeded"


class RubricNotFoundError(AgentForgeError):
    status_code = 500
    error_code = "rubric_not_found"


def register_exception_handlers(app: FastAPI) -> None:
    """Convert AgentForgeError subclasses into clean JSON responses.

    Why: without this, FastAPI emits raw 500s with no structured detail —
    operators end up guessing what failed. Each error subclass carries its
    own status code so callers can branch on it without parsing strings.
    """

    @app.exception_handler(AgentForgeError)
    async def _handle_known(request: Request, exc: AgentForgeError) -> JSONResponse:
        logger.warning(
            "agentforge_error code=%s status=%s path=%s message=%s",
            exc.error_code,
            exc.status_code,
            request.url.path,
            exc.message,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error_code": exc.error_code,
                "detail": exc.message,
                "metadata": exc.detail,
            },
        )

    @app.exception_handler(Exception)
    async def _handle_unknown(request: Request, exc: Exception) -> JSONResponse:
        # Last-resort: never leak tracebacks to clients.
        logger.exception("unhandled_exception path=%s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error_code": "internal_server_error",
                "detail": "An unexpected error occurred. The team has been notified.",
            },
        )
