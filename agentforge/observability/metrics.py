"""Prometheus metrics registry (CLAUDE.md §10 Phase 5).

The agents call these counters/histograms directly; the FastAPI middleware
also records api_latency for every request. `/metrics` exposes the
text-format scrape endpoint.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from fastapi import Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware

REGISTRY = CollectorRegistry(auto_describe=True)

attacks_total = Counter(
    "agentforge_attacks_total",
    "Total attacks sent to the target",
    ["category", "outcome"],
    registry=REGISTRY,
)
session_cost_usd = Histogram(
    "agentforge_session_cost_usd",
    "Per-campaign cumulative cost in USD",
    ["campaign_id"],
    buckets=(0.01, 0.05, 0.10, 0.25, 0.50, 1.0, 2.5, 5.0, 10.0, 25.0),
    registry=REGISTRY,
)
judge_confidence = Histogram(
    "agentforge_judge_confidence",
    "Distribution of Judge confidence scores",
    buckets=[0.1 * i for i in range(11)],
    registry=REGISTRY,
)
regression_outcome = Counter(
    "agentforge_regression_outcome",
    "Regression run outcomes",
    ["outcome"],
    registry=REGISTRY,
)
coverage_percent = Gauge(
    "agentforge_coverage_percent",
    "Attack-surface coverage percentage by category",
    ["category"],
    registry=REGISTRY,
)
api_latency = Histogram(
    "agentforge_api_request_duration_seconds",
    "API request duration (seconds)",
    ["method", "endpoint", "status"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    registry=REGISTRY,
)
llm_calls_total = Counter(
    "agentforge_llm_calls_total",
    "LLM API calls broken down by agent and model",
    ["agent", "model"],
    registry=REGISTRY,
)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record request latency by method, endpoint, status."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:  # type: ignore[override]
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        # Use the route template when available so high-cardinality UUIDs don't
        # explode the metric labels.
        endpoint = getattr(request.scope.get("route"), "path", request.url.path)
        api_latency.labels(
            method=request.method, endpoint=endpoint, status=str(response.status_code)
        ).observe(elapsed)
        return response


def metrics_response() -> Response:
    """Plaintext Prometheus exposition. Unauthenticated — keep behind WAF."""
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)
