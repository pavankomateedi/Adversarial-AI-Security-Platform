"""Per-campaign / per-agent token cost ledger.

Thin in-memory helper used by agents and graph nodes to enforce the
`MAX_TOKENS_PER_CAMPAIGN` circuit breaker. Persisted cost ends up in the
attack_results table for dashboards.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal
from threading import Lock
from typing import Any

# Price table — only the models we actually call. Update when providers change rates.
# Prices in USD per 1M tokens (input, output). Keep conservative — overestimating is safe.
_PRICES_PER_M = {
    # Anthropic Claude 4.x family
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (0.80, 4.0),
    "claude-opus-4-7": (15.0, 75.0),
    # Anthropic Claude 3.5 family (fallback if user pins older models)
    "claude-3-5-sonnet-20241022": (3.0, 15.0),
    "claude-3-5-haiku-20241022": (0.80, 4.0),
    # Groq (Llama 3.x) — public pricing as of 2026
    "llama-3.3-70b-versatile": (0.59, 0.79),
    "llama-3.1-70b-versatile": (0.59, 0.79),
    "llama-3.1-8b-instant": (0.05, 0.08),
    # OpenAI fallbacks
    "gpt-4o": (2.50, 10.0),
    "gpt-4o-mini": (0.15, 0.60),
}


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> Decimal:
    in_rate, out_rate = _PRICES_PER_M.get(model, (3.0, 15.0))  # default to Sonnet rate
    cost = (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000
    return Decimal(f"{cost:.6f}")


@dataclass
class CostLedger:
    total_usd: Decimal = Decimal("0")
    by_agent: dict[str, Decimal] = field(default_factory=lambda: defaultdict(lambda: Decimal("0")))
    by_model: dict[str, Decimal] = field(default_factory=lambda: defaultdict(lambda: Decimal("0")))
    by_campaign: dict[str, Decimal] = field(default_factory=lambda: defaultdict(lambda: Decimal("0")))
    call_count: int = 0


class CostTracker:
    """Thread-safe accumulator. One instance per campaign or one global instance."""

    def __init__(self, ceiling_usd: Decimal | float | None = None) -> None:
        self._ledger = CostLedger()
        self._lock = Lock()
        self._ceiling = Decimal(str(ceiling_usd)) if ceiling_usd is not None else None

    def record_call(
        self,
        *,
        agent: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        campaign_id: str | None = None,
    ) -> Decimal:
        cost = estimate_cost_usd(model, input_tokens, output_tokens)
        with self._lock:
            self._ledger.total_usd += cost
            self._ledger.by_agent[agent] += cost
            self._ledger.by_model[model] += cost
            if campaign_id:
                self._ledger.by_campaign[campaign_id] += cost
            self._ledger.call_count += 1
        return cost

    @property
    def total(self) -> Decimal:
        return self._ledger.total_usd

    def ceiling_breached(self) -> bool:
        return self._ceiling is not None and self._ledger.total_usd >= self._ceiling

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_usd": float(self._ledger.total_usd),
                "call_count": self._ledger.call_count,
                "by_agent": {k: float(v) for k, v in self._ledger.by_agent.items()},
                "by_model": {k: float(v) for k, v in self._ledger.by_model.items()},
                "by_campaign": {k: float(v) for k, v in self._ledger.by_campaign.items()},
                "ceiling_usd": float(self._ceiling) if self._ceiling is not None else None,
            }
