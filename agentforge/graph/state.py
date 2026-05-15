"""Shared LangGraph state for AgentForge campaigns.

All 5 agents read/write via this TypedDict — see ARCHITECTURE.md "State Fields
by Agent" for the write-fences (Judge writes verdicts, RedTeam writes attack
results, etc.).
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langgraph.graph.message import add_messages


class AgentForgeState(TypedDict, total=False):
    """LangGraph state for one campaign run.

    `total=False` lets nodes return partial updates without re-asserting
    every field on every step.
    """

    # ----- campaign context -----
    campaign_id: str
    campaign_config: dict[str, Any]
    attack_category: str
    target_url: str
    patient_id: str | None
    session_cost_usd: float

    # ----- attack tracking -----
    current_attack: dict[str, Any] | None
    attack_results: list[dict[str, Any]]
    mutation_count: int
    max_mutations: int
    attacks_run: int
    max_attacks: int
    seen_attack_ids: list[str]

    # ----- verdicts -----
    current_verdict: dict[str, Any] | None
    confirmed_findings: list[str]   # finding IDs (VULN-xxx) created in this run

    # ----- control flow -----
    stop_campaign: bool
    escalate_to_human: bool
    needs_mutation: bool

    # ----- orchestrator output -----
    next_priority: dict[str, Any] | None  # {attack_id, score, severity, exploitability}
    low_signal: bool  # True when recent verdicts are all FAILURE (well-defended category)

    # ----- observability -----
    messages: Annotated[list, add_messages]
    agent_trace: list[dict[str, Any]]


def make_initial_state(
    *,
    campaign_id: str,
    attack_category: str,
    target_url: str,
    config: dict[str, Any],
    patient_id: str | None = None,
    max_attacks: int = 10,
    max_mutations: int = 3,
) -> AgentForgeState:
    """Construct an empty AgentForgeState with sensible defaults."""
    return AgentForgeState(
        campaign_id=campaign_id,
        campaign_config=config,
        attack_category=attack_category,
        target_url=target_url,
        patient_id=patient_id,
        session_cost_usd=0.0,
        current_attack=None,
        attack_results=[],
        mutation_count=0,
        max_mutations=max_mutations,
        attacks_run=0,
        max_attacks=max_attacks,
        seen_attack_ids=[],
        current_verdict=None,
        confirmed_findings=[],
        stop_campaign=False,
        escalate_to_human=False,
        needs_mutation=False,
        next_priority=None,
        low_signal=False,
        messages=[],
        agent_trace=[],
    )
