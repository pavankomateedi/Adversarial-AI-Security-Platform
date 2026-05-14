"""Unit tests for OrchestratorAgent — prioritization formula + stop logic."""

from __future__ import annotations

import pytest

from agentforge.agents.orchestrator import OrchestratorAgent
from agentforge.core.attack_library import AttackLibrary
from agentforge.models.attack import (
    AttackCase,
    AttackCategory,
    AttackExploitability,
    AttackSeverity,
    AttackTurn,
)


def _case(attack_id: str, severity: AttackSeverity, exploitability: AttackExploitability) -> AttackCase:
    return AttackCase(
        attack_id=attack_id,
        category=AttackCategory.PROMPT_INJECTION,
        subcategory="direct_injection",
        severity=severity,
        exploitability=exploitability,
        description="x",
        attack_sequence=[AttackTurn(role="user", content="x")],
        expected_safe_behavior="refuse",
        success_indicators=["a"],
        failure_indicators=["b"],
    )


class TestPriorityScore:
    def test_critical_high_scores_above_low_low(self):
        crit = _case("CRIT-1", AttackSeverity.CRITICAL, AttackExploitability.HIGH)
        low = _case("LOW-1", AttackSeverity.LOW, AttackExploitability.LOW)
        assert OrchestratorAgent.priority_score(crit) > OrchestratorAgent.priority_score(low)

    def test_score_is_severity_times_exploitability_over_cost(self):
        # CRITICAL(4) x HIGH(3) / 0.015 = 800
        crit = _case("CRIT-1", AttackSeverity.CRITICAL, AttackExploitability.HIGH)
        assert OrchestratorAgent.priority_score(crit) == pytest.approx(800.0, rel=1e-3)

    def test_rank_remaining_orders_high_priority_first(self):
        lib = AttackLibrary(
            [
                _case("LOW-1", AttackSeverity.LOW, AttackExploitability.LOW),
                _case("CRIT-1", AttackSeverity.CRITICAL, AttackExploitability.HIGH),
                _case("MED-1", AttackSeverity.MEDIUM, AttackExploitability.MEDIUM),
            ]
        )
        orch = OrchestratorAgent(library=lib)
        ranked = orch.rank_remaining("prompt_injection", seen=[])
        assert [c.attack_id for c in ranked] == ["CRIT-1", "MED-1", "LOW-1"]

    def test_rank_remaining_excludes_seen(self):
        lib = AttackLibrary(
            [
                _case("CRIT-1", AttackSeverity.CRITICAL, AttackExploitability.HIGH),
                _case("MED-1", AttackSeverity.MEDIUM, AttackExploitability.MEDIUM),
            ]
        )
        orch = OrchestratorAgent(library=lib)
        ranked = orch.rank_remaining("prompt_injection", seen=["CRIT-1"])
        assert [c.attack_id for c in ranked] == ["MED-1"]


class TestOrchestratorRun:
    @pytest.fixture
    def orch(self) -> OrchestratorAgent:
        lib = AttackLibrary(
            [
                _case("ATK-A", AttackSeverity.CRITICAL, AttackExploitability.HIGH),
                _case("ATK-B", AttackSeverity.LOW, AttackExploitability.LOW),
            ]
        )
        return OrchestratorAgent(library=lib)

    @pytest.mark.asyncio
    async def test_stop_on_max_attacks(self, orch):
        out = await orch.run({"attacks_run": 5, "max_attacks": 5, "attack_category": "prompt_injection"})
        assert out["stop_campaign"] is True

    @pytest.mark.asyncio
    async def test_stop_on_library_exhausted(self, orch):
        out = await orch.run({
            "attacks_run": 1,
            "max_attacks": 10,
            "attack_category": "prompt_injection",
            "seen_attack_ids": ["ATK-A", "ATK-B"],
        })
        assert out["stop_campaign"] is True

    @pytest.mark.asyncio
    async def test_stop_on_budget_exceeded(self, orch):
        out = await orch.run({
            "attacks_run": 1,
            "max_attacks": 10,
            "attack_category": "prompt_injection",
            "seen_attack_ids": [],
            "session_cost_usd": 99.0,
            "campaign_config": {"cost_budget_usd": 5.0},
        })
        assert out["stop_campaign"] is True

    @pytest.mark.asyncio
    async def test_continue_nominates_highest_priority(self, orch):
        out = await orch.run({
            "attacks_run": 0,
            "max_attacks": 10,
            "attack_category": "prompt_injection",
            "seen_attack_ids": [],
            "campaign_config": {"cost_budget_usd": 5.0},
        })
        assert out["stop_campaign"] is False
        # ATK-A is CRITICAL/HIGH, should be nominated over ATK-B
        assert out["next_priority"]["attack_id"] == "ATK-A"

    @pytest.mark.asyncio
    async def test_low_signal_flag_on_four_failures(self, orch):
        trace = [
            {"agent": "judge", "event": "verdict", "outcome": "FAILURE"} for _ in range(4)
        ]
        out = await orch.run({
            "attacks_run": 1,
            "max_attacks": 10,
            "attack_category": "prompt_injection",
            "seen_attack_ids": [],
            "campaign_config": {"cost_budget_usd": 5.0},
            "agent_trace": trace,
        })
        assert out["low_signal"] is True

    @pytest.mark.asyncio
    async def test_no_low_signal_with_mixed_verdicts(self, orch):
        trace = [
            {"agent": "judge", "event": "verdict", "outcome": "FAILURE"},
            {"agent": "judge", "event": "verdict", "outcome": "SUCCESS"},
            {"agent": "judge", "event": "verdict", "outcome": "FAILURE"},
            {"agent": "judge", "event": "verdict", "outcome": "FAILURE"},
        ]
        out = await orch.run({
            "attacks_run": 1,
            "max_attacks": 10,
            "attack_category": "prompt_injection",
            "seen_attack_ids": [],
            "campaign_config": {"cost_budget_usd": 5.0},
            "agent_trace": trace,
        })
        assert out["low_signal"] is False
