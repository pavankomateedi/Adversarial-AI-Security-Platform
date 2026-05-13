"""Langfuse tracing wrapper (CLAUDE.md §10 Phase 5).

We don't use a heavy OTLP exporter — Langfuse's Python SDK ships its own
batched HTTP forwarder. Agents call `trace_agent_call()` around each LLM
invocation so prompt + response + cost end up in the Langfuse dashboard.

Safe to import even if LANGFUSE keys aren't configured — the helpers no-op.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any

from agentforge.config import Settings, get_settings

logger = logging.getLogger(__name__)

try:
    from langfuse import Langfuse  # type: ignore[import-untyped]

    _LANGFUSE_AVAILABLE = True
except ImportError:  # pragma: no cover
    Langfuse = None  # type: ignore[assignment,misc]
    _LANGFUSE_AVAILABLE = False


_client: Any = None


def get_langfuse_client(settings: Settings | None = None) -> Any:
    """Return a singleton Langfuse client or None if keys aren't configured."""
    global _client
    if _client is not None:
        return _client
    if not _LANGFUSE_AVAILABLE:
        return None
    s = settings or get_settings()
    if not s.langfuse_public_key or not s.langfuse_secret_key:
        logger.info("langfuse keys not configured — tracing disabled")
        return None
    try:
        _client = Langfuse(
            public_key=s.langfuse_public_key.get_secret_value(),
            secret_key=s.langfuse_secret_key.get_secret_value(),
            host=s.langfuse_host,
        )
    except Exception:  # noqa: BLE001
        logger.exception("langfuse client init failed — tracing disabled")
        return None
    return _client


@contextmanager
def trace_agent_call(
    *,
    agent: str,
    name: str,
    model: str | None = None,
    campaign_id: str | None = None,
    tags: list[str] | None = None,
    inputs: dict[str, Any] | None = None,
):
    """Yield a span that records inputs/outputs for one LLM call.

    Usage:
        with trace_agent_call(agent="judge", name="verdict", model="claude-sonnet-4-6") as span:
            response = await model.ainvoke(...)
            span.output(content=response.content, usage=response.usage_metadata)
    """
    client = get_langfuse_client()
    span = _NullSpan()
    if client is not None:
        try:
            # Newer Langfuse SDK
            trace = client.trace(
                name=name,
                tags=tags or [],
                metadata={"agent": agent, "model": model, "campaign_id": campaign_id},
                input=inputs,
            )
            span = _LangfuseSpan(trace)
        except Exception:  # noqa: BLE001
            logger.exception("langfuse span init failed")
            span = _NullSpan()
    try:
        yield span
    finally:
        try:
            span.close()
        except Exception:  # noqa: BLE001
            logger.debug("span close failed (ignored)", exc_info=True)


class _NullSpan:
    """No-op span used when Langfuse is disabled."""

    def output(self, **_: Any) -> None:
        return None

    def error(self, **_: Any) -> None:
        return None

    def close(self) -> None:
        return None


class _LangfuseSpan:
    def __init__(self, trace: Any) -> None:
        self._trace = trace
        self._output_recorded = False

    def output(
        self,
        *,
        content: Any = None,
        usage: dict[str, int] | None = None,
        cost_usd: float | None = None,
    ) -> None:
        try:
            self._trace.update(
                output=str(content)[:8000] if content else None,
                metadata={"usage": usage, "cost_usd": cost_usd},
            )
        except Exception:  # noqa: BLE001
            logger.debug("langfuse update failed", exc_info=True)
        self._output_recorded = True

    def error(self, *, message: str) -> None:
        try:
            self._trace.update(output=message[:1000], metadata={"error": True})
        except Exception:  # noqa: BLE001
            logger.debug("langfuse error update failed", exc_info=True)

    def close(self) -> None:
        if not self._output_recorded:
            try:
                self._trace.update(metadata={"closed_without_output": True})
            except Exception:  # noqa: BLE001
                pass


def flush_traces() -> None:
    """Force-flush pending Langfuse traces (e.g. on app shutdown)."""
    client = get_langfuse_client()
    if client is None:
        return
    try:
        client.flush()
    except Exception:  # noqa: BLE001
        logger.debug("langfuse flush failed", exc_info=True)
