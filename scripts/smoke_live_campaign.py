"""Live smoke: drive ONE attack end-to-end against the deployed Co-Pilot.

Runs RedTeam → Co-Pilot → Judge → (DocumentationAgent if SUCCESS) and prints
a compact summary. Costs a few cents per run (1 Groq + 1-2 Claude calls).

Usage:
    uv run python -m scripts.smoke_live_campaign
"""

from __future__ import annotations

import asyncio
import json

from agentforge.config import get_settings
from agentforge.core.cost_tracker import CostTracker
from agentforge.core.target_client import ClinicalCopilotClient
from agentforge.graph.campaign_graph import build_campaign_graph
from agentforge.graph.state import make_initial_state
from agentforge.models.attack import AttackCategory
from agentforge.models.campaign import CampaignConfig, CampaignPriority


async def main() -> None:
    settings = get_settings()
    pids = settings.test_patient_ids_list
    if not pids:
        print("ERROR: BACKEND_TEST_PATIENT_IDS empty in .env")
        return
    patient_id = pids[0]
    print(f"Target:      {settings.backend_url}")
    print(f"Patient_id:  {patient_id}")
    print("Category:    prompt_injection")
    print()

    config = CampaignConfig(
        attack_category=AttackCategory.PROMPT_INJECTION,
        priority=CampaignPriority.HIGH,
        max_attacks=1,
        max_mutations_per_attack=1,
        cost_budget_usd=1.50,
        patient_id=patient_id,
    )

    cost_tracker = CostTracker(ceiling_usd=float(config.cost_budget_usd))
    async with ClinicalCopilotClient(settings) as client:
        graph = build_campaign_graph(target_client=client, cost_tracker=cost_tracker)
        initial = make_initial_state(
            campaign_id="smoke-001",
            attack_category=str(config.attack_category),
            target_url=settings.backend_url,
            config=config.model_dump(mode="json"),
            patient_id=patient_id,
            max_attacks=1,
            max_mutations=1,
        )
        final = await graph.ainvoke(initial, config={"recursion_limit": 25})

    print("=" * 60)
    print("AGENT TRACE")
    print("=" * 60)
    for entry in final.get("agent_trace", []):
        agent = entry.get("agent", "?")
        event = entry.get("event", "?")
        rest = {k: v for k, v in entry.items() if k not in {"agent", "event", "ts"}}
        rest_str = " ".join(f"{k}={json.dumps(v) if not isinstance(v, str) else v}" for k, v in rest.items())
        print(f"  [{agent}] {event}  {rest_str}")
    print()

    attacks = final.get("attack_results") or []
    if attacks:
        last = attacks[-1]
        print("=" * 60)
        print("LAST ATTACK")
        print("=" * 60)
        print(f"  attack_id:  {last.get('attack_case_id')}")
        print(f"  status:     {(last.get('target_response') or {}).get('status_code')}")
        print(f"  prompt:     {(last.get('prompt') or '')[:200]}")
        print(f"  response:   {(last.get('response') or '')[:300]}")

    verdict = final.get("current_verdict")
    if verdict:
        print()
        print("=" * 60)
        print("VERDICT")
        print("=" * 60)
        print(f"  outcome:    {verdict.get('outcome')}")
        print(f"  confidence: {verdict.get('confidence')}")
        print(f"  reasoning:  {verdict.get('reasoning')}")

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  attacks_run:    {final.get('attacks_run', 0)}")
    print(f"  findings:       {final.get('confirmed_findings', [])}")
    print(f"  total cost USD: {cost_tracker.total}")


if __name__ == "__main__":
    asyncio.run(main())
