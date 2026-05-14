"""Main campaign LangGraph — wires the 5 agents into a stateful loop."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from agentforge.agents.documentation import DocumentationAgent
from agentforge.agents.judge import JudgeAgent
from agentforge.agents.orchestrator import OrchestratorAgent
from agentforge.agents.red_team import RedTeamAgent
from agentforge.core.cost_tracker import CostTracker
from agentforge.core.target_client import ClinicalCopilotClient
from agentforge.graph.edges import (
    route_after_judge,
    route_after_orchestrator,
    route_after_red_team,
)
from agentforge.graph.state import AgentForgeState
from agentforge.observability.metrics import session_cost_usd as _session_cost_metric


def build_campaign_graph(
    *,
    target_client: ClinicalCopilotClient,
    cost_tracker: CostTracker | None = None,
):
    """Construct + compile the campaign graph.

    Caller owns `target_client` and is responsible for closing it.
    The compiled graph is invocable via `await graph.ainvoke(state)`.
    """
    tracker = cost_tracker or CostTracker()

    orchestrator = OrchestratorAgent(cost_tracker=tracker)
    red_team = RedTeamAgent(target_client=target_client, cost_tracker=tracker)
    judge = JudgeAgent(cost_tracker=tracker)
    documentation = DocumentationAgent(cost_tracker=tracker)

    async def orchestrator_node(state: AgentForgeState) -> dict[str, Any]:
        return await orchestrator.run(dict(state))

    async def red_team_node(state: AgentForgeState) -> dict[str, Any]:
        return await red_team.run(dict(state))

    async def judge_node(state: AgentForgeState) -> dict[str, Any]:
        return await judge.run(dict(state))

    async def documentation_node(state: AgentForgeState) -> dict[str, Any]:
        return await documentation.run(dict(state))

    async def cost_check_node(state: AgentForgeState) -> dict[str, Any]:
        snap = tracker.snapshot()
        new_total = float(snap["total_usd"])
        # Observe the running session cost into the Prometheus histogram so
        # /metrics shows the cost distribution per campaign — previously this
        # histogram was defined but never observed.
        campaign_id = str(state.get("campaign_id", "unknown"))
        try:
            _session_cost_metric.labels(campaign_id=campaign_id).observe(new_total)
        except Exception:  # noqa: BLE001 — never let a metric break the graph
            pass
        return {
            "session_cost_usd": new_total,
            "stop_campaign": tracker.ceiling_breached() or state.get("stop_campaign", False),
        }

    graph = StateGraph(AgentForgeState)
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("red_team", red_team_node)
    graph.add_node("judge", judge_node)
    graph.add_node("documentation", documentation_node)
    graph.add_node("cost_check", cost_check_node)

    graph.set_entry_point("orchestrator")

    graph.add_conditional_edges(
        "orchestrator",
        route_after_orchestrator,
        {"red_team": "red_team", "stop": END},
    )
    graph.add_conditional_edges(
        "red_team",
        route_after_red_team,
        {"judge": "judge", "orchestrator": "orchestrator"},
    )
    graph.add_conditional_edges(
        "judge",
        route_after_judge,
        {
            "documentation": "documentation",
            "red_team": "red_team",
            "orchestrator": "orchestrator",
            "stop": END,
        },
    )
    graph.add_edge("documentation", "cost_check")
    graph.add_conditional_edges(
        "cost_check",
        lambda s: "stop" if s.get("stop_campaign") else "orchestrator",
        {"orchestrator": "orchestrator", "stop": END},
    )

    return graph.compile()


def build_regression_graph(
    *,
    target_client: ClinicalCopilotClient,
    cost_tracker: CostTracker | None = None,
):
    """Standalone regression graph — RegressionAgent does its own work."""
    from agentforge.agents.regression import RegressionAgent

    tracker = cost_tracker or CostTracker()
    regression = RegressionAgent(target_client=target_client, cost_tracker=tracker)

    async def regression_node(state: AgentForgeState) -> dict[str, Any]:
        return await regression.run(dict(state))

    graph = StateGraph(AgentForgeState)
    graph.add_node("regression", regression_node)
    graph.set_entry_point("regression")
    graph.add_edge("regression", END)
    return graph.compile()
