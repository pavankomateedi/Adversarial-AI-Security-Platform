"""Unit tests for cost_tracker (and coverage_tracker, which is exercised in integration)."""

from __future__ import annotations

from decimal import Decimal

from agentforge.core.cost_tracker import CostTracker, estimate_cost_usd


def test_estimate_cost_known_model():
    # claude-sonnet-4-6: $3/M input, $15/M output
    c = estimate_cost_usd("claude-sonnet-4-6", input_tokens=1_000_000, output_tokens=0)
    assert c == Decimal("3.000000")
    c = estimate_cost_usd("claude-sonnet-4-6", input_tokens=0, output_tokens=1_000_000)
    assert c == Decimal("15.000000")


def test_estimate_cost_unknown_model_falls_back():
    # Unknown models default to Sonnet rate, so it never returns zero unexpectedly.
    c = estimate_cost_usd("brand-new-model-9000", input_tokens=1_000_000, output_tokens=0)
    assert c == Decimal("3.000000")


def test_tracker_accumulates_per_agent_and_model():
    t = CostTracker(ceiling_usd=Decimal("0.10"))
    t.record_call(agent="red_team", model="llama-3.3-70b-versatile", input_tokens=10_000, output_tokens=500, campaign_id="c1")
    t.record_call(agent="judge", model="claude-sonnet-4-6", input_tokens=5_000, output_tokens=1_000, campaign_id="c1")
    snap = t.snapshot()
    assert snap["call_count"] == 2
    assert snap["by_agent"]["red_team"] > 0
    assert snap["by_agent"]["judge"] > snap["by_agent"]["red_team"]  # Claude more expensive
    assert snap["by_campaign"]["c1"] > 0


def test_ceiling_breach():
    t = CostTracker(ceiling_usd=Decimal("0.0001"))
    assert not t.ceiling_breached()
    t.record_call(agent="judge", model="claude-sonnet-4-6", input_tokens=1000, output_tokens=1000)
    assert t.ceiling_breached()


def test_no_ceiling_never_breaches():
    t = CostTracker()
    t.record_call(agent="judge", model="claude-sonnet-4-6", input_tokens=10**9, output_tokens=10**9)
    assert not t.ceiling_breached()
