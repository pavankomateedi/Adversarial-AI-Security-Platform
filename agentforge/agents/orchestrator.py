"""OrchestratorAgent — campaign director.

Decides what the RedTeam targets next based on:
  - Configured campaign category (priority)
  - Attacks still available in the seed library for the category
  - Session cost vs ceiling

Implementation is deterministic for the MVP — the LLM call is a nice-to-have
for natural-language reasoning but not required for correctness. We keep the
LLM hook in place for Phase 5 enrichment.
"""

from __future__ import annotations

import logging
from typing import Any

from agentforge.agents.base import BaseAgent
from agentforge.agents.models import AgentRole
from agentforge.core.attack_library import AttackLibrary

logger = logging.getLogger(__name__)


class OrchestratorAgent(BaseAgent):
    role = AgentRole.ORCHESTRATOR
    name = "orchestrator"

    def __init__(self, *, library: AttackLibrary | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.library = library or AttackLibrary()

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        attacks_run = state.get("attacks_run", 0)
        max_attacks = state.get("max_attacks", 10)
        category = state.get("attack_category")
        seen = state.get("seen_attack_ids", [])

        # Stop conditions, in order of priority.
        if state.get("stop_campaign"):
            return {"agent_trace": state.get("agent_trace", []) + [self._trace("stop_already_signaled")]}

        if attacks_run >= max_attacks:
            return {
                "stop_campaign": True,
                "agent_trace": state.get("agent_trace", []) + [self._trace("stop", reason="max_attacks_reached", attacks_run=attacks_run, max_attacks=max_attacks)],
            }

        # Library exhausted for category — stop (Phase 5 would broaden to another category).
        if category:
            remaining = [a for a in self.library.by_category(category) if a.attack_id not in seen]
            if not remaining and not state.get("needs_mutation"):
                return {
                    "stop_campaign": True,
                    "agent_trace": state.get("agent_trace", []) + [self._trace("stop", reason="library_exhausted", category=category)],
                }

        budget_usd = float(state.get("campaign_config", {}).get("cost_budget_usd", 5.0))
        if state.get("session_cost_usd", 0.0) >= budget_usd:
            return {
                "stop_campaign": True,
                "agent_trace": state.get("agent_trace", []) + [self._trace("stop", reason="budget_exceeded", cost=state.get("session_cost_usd"), budget=budget_usd)],
            }

        return {
            "stop_campaign": False,
            "agent_trace": state.get("agent_trace", []) + [self._trace("continue", attacks_run=attacks_run, max_attacks=max_attacks)],
        }
