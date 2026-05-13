"""Structured JSON logging via structlog (CLAUDE.md §10 Phase 5).

Why JSON: Railway log drains, Datadog, and the audit_log table all parse
JSON cleanly. Plain-text logs would lose the structured fields agents emit.

Secrets are redacted globally — any field whose name matches the redaction
regex is replaced with `***` before the line is rendered.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog

_SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|secret|password|token|authorization|jwt|bearer)")


def _redact_secrets(_logger, _method_name, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Mask any field whose name looks secret. Runs early in the pipeline so
    every renderer (and any downstream forwarder) sees the masked value."""
    for k, v in list(event_dict.items()):
        if _SECRET_KEY_RE.search(k) and v is not None and v != "":
            event_dict[k] = "***"
        elif isinstance(v, dict):
            event_dict[k] = _redact_dict(v)
    return event_dict


def _redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in d.items():
        if _SECRET_KEY_RE.search(k) and v is not None and v != "":
            out[k] = "***"
        elif isinstance(v, dict):
            out[k] = _redact_dict(v)
        else:
            out[k] = v
    return out


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Idempotent setup of structlog + stdlib logging."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
        force=True,  # override any previous basicConfig from imports
    )

    processors: list[Any] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_secrets,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level.upper(), logging.INFO)),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name) if name else structlog.get_logger()
