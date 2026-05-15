"""OrchestratorAgent — campaign director.

Decides what the RedTeam targets next. Deterministic by design: the
prioritization math is reproducible, free, and instant — three properties
a security platform wants in its decision layer. (We do NOT give the
Orchestrator an LLM; an LLM here would add cost, latency, and
non-determinism to a decision that is fundamentally arithmetic. That is a
deliberate, defensible choice — see ARCHITECTURE.md.)

Decision logic (CLAUDE.md §4.1):
  1. Stop if a hard limit is hit (max_attacks, library exhausted, budget).
  2. Low-signal guard — if the last N attacks in this category were all
     FAILURE, the category is well-defended; flag it so the operator /
     a future multi-category run can redirect effort. We still continue
     (the campaign is single-category) but emit a `low_signal` trace.
  3. Priority score for the *next* candidate attack:
        score = (severity_weight x exploitability_weight) / cost_estimate
     The campaign is single-category in this MVP, so the score ranks
     which seed case RedTeam should pull next — highest score first.
"""

from __future__ import annotations

import logging
from typing import Any

from agentforge.agents.base import BaseAgent
from agentforge.agents.models import AgentRole
from agentforge.core.attack_library import AttackLibrary
from agentforge.models.attack import AttackCase

logger = logging.getLogger(__name__)

# Ordinal weights for the priority formula. Higher = test sooner.
_SEVERITY_WEIGHT = {"CRITICAL": 4.0, "HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}
_EXPLOITABILITY_WEIGHT = {"HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}
# Rough per-attack cost estimate in USD (RedTeam mutate + Judge verdict).
# Used only as the denominator in the priority score — exact value doesn't
# matter, the ratio does.
_COST_ESTIMATE_USD = 0.015

# If the last N attempts in a category were all FAILURE, treat the category
# as well-defended (low signal) and say so in the trace.
_LOW_SIGNAL_WINDOW = 4


class OrchestratorAgent(BaseAgent):
    role = AgentRole.ORCHESTRATOR
    name = "orchestrator"

    def __init__(self, *, library: AttackLibrary | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.library = library or AttackLibrary()

    # ---- priority scoring -------------------------------------------------------

    @staticmethod
    def priority_score(case: AttackCase) -> float:
        """(severity x exploitability) / cost_estimate — higher tests sooner."""
        sev = _SEVERITY_WEIGHT.get(str(case.severity), 2.0)
        exp = _EXPLOITABILITY_WEIGHT.get(str(case.exploitability), 2.0)
        return (sev * exp) / _COST_ESTIMATE_USD

    def rank_remaining(self, category: str, seen: list[str]) -> list[AttackCase]:
        """Remaining seed cases for a category, highest-priority first."""
        remaining = [a for a in self.library.by_category(category) if a.attack_id not in seen]
        return sorted(remaining, key=self.priority_score, reverse=True)

    # ---- low-signal detection ---------------------------------------------------

    @staticmethod
    def _low_signal(attack_results: list[dict[str, Any]]) -> bool:
        """True if the last _LOW_SIGNAL_WINDOW verdicts were all FAILURE.

        Why: a category where every recent attack was cleanly refused is
        producing no signal. Continuing to burn budget on it is the exact
        'cost accumulating without producing signal' case the PRD calls out.
        """
        verdicts = [
            str((r.get("target_response") or {}).get("verdict") or r.get("verdict") or "")
            for r in attack_results
        ]
        # The campaign state doesn't carry per-attack verdicts directly, so we
        # read from the trace-friendly `current_verdict` history if present.
        recent = [v for v in verdicts if v][-_LOW_SIGNAL_WINDOW:]
        return len(recent) >= _LOW_SIGNAL_WINDOW and all(v == "FAILURE" for v in recent)

    # ---- main -------------------------------------------------------------------

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        attacks_run = state.get("attacks_run", 0)
        max_attacks = state.get("max_attacks", 10)
        category = state.get("attack_category")
        seen = state.get("seen_attack_ids", [])
        trace = state.get("agent_trace", [])

        # 1. Hard stop conditions, in priority order.
        if state.get("stop_campaign"):
            return {"agent_trace": trace + [self._trace("stop_already_signaled")]}

        if attacks_run >= max_attacks:
            return {
                "stop_campaign": True,
                "agent_trace": trace + [self._trace(
                    "stop", reason="max_attacks_reached",
                    attacks_run=attacks_run, max_attacks=max_attacks,
                )],
            }

        ranked = self.rank_remaining(category, seen) if category else []
        if category and not ranked and not state.get("needs_mutation"):
            return {
                "stop_campaign": True,
                "agent_trace": trace + [self._trace(
                    "stop", reason="library_exhausted", category=category,
                )],
            }

        budget_usd = float(state.get("campaign_config", {}).get("cost_budget_usd", 5.0))
        if state.get("session_cost_usd", 0.0) >= budget_usd:
            return {
                "stop_campaign": True,
                "agent_trace": trace + [self._trace(
                    "stop", reason="budget_exceeded",
                    cost=state.get("session_cost_usd"), budget=budget_usd,
                )],
            }

        # 2. Low-signal guard — emit a trace but keep going (single-category MVP).
        agent_trace_history = [
            t for t in trace if t.get("agent") == "judge" and t.get("event") == "verdict"
        ]
        recent_outcomes = [str(t.get("outcome", "")) for t in agent_trace_history][-_LOW_SIGNAL_WINDOW:]
        low_signal = (
            len(recent_outcomes) >= _LOW_SIGNAL_WINDOW
            and all(o in ("FAILURE", "VerdictOutcome.FAILURE") for o in recent_outcomes)
        )

        # 3. Priority decision — which case RedTeam should pull next.
        next_case = ranked[0] if ranked else None
        next_priority = {
            "attack_id": next_case.attack_id if next_case else None,
            "score": round(self.priority_score(next_case), 1) if next_case else None,
            "severity": str(next_case.severity) if next_case else None,
            "exploitability": str(next_case.exploitability) if next_case else None,
        }

        return {
            "stop_campaign": False,
            "next_priority": next_priority,
            "low_signal": low_signal,
            "agent_trace": trace + [self._trace(
                "continue",
                attacks_run=attacks_run,
                max_attacks=max_attacks,
                next_attack=next_priority["attack_id"],
                priority_score=next_priority["score"],
                low_signal=low_signal,
            )],
        }
