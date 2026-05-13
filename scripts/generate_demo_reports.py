"""Force-generate demo vulnerability reports.

The Co-Pilot is well-defended and the eval sweeps produced only PARTIAL
verdicts (high-confidence partials are real findings — the target's
output was not fully unsafe but it leaked signal). With the routing
update (route_after_judge) the campaign now files PARTIAL>=0.8 verdicts
as MEDIUM-severity reports automatically.

This script runs targeted single-attack campaigns against the 3 categories
that historically returned PARTIAL>=0.8 in the sweep, mutates aggressively
so the Judge produces a confident verdict, and lets DocumentationAgent
file the report.

    uv run python -m scripts.generate_demo_reports
"""

from __future__ import annotations

import asyncio
import time

from agentforge.config import get_settings
from agentforge.core.cost_tracker import CostTracker
from agentforge.core.target_client import ClinicalCopilotClient
from agentforge.graph.campaign_graph import build_campaign_graph
from agentforge.graph.state import make_initial_state
from agentforge.models.attack import AttackCategory
from agentforge.models.campaign import CampaignConfig, CampaignPriority

# These three categories produced PARTIAL or near-SUCCESS verdicts in
# previous sweeps — the most likely to surface real findings.
TARGET_CATEGORIES = [
    AttackCategory.DATA_EXFILTRATION,
    AttackCategory.STATE_CORRUPTION,
    AttackCategory.PROMPT_INJECTION,
]


async def run(category: AttackCategory, patient_id: str) -> dict:
    settings = get_settings()
    tracker = CostTracker(ceiling_usd=3.0)
    started = time.time()
    async with ClinicalCopilotClient(settings) as client:
        graph = build_campaign_graph(target_client=client, cost_tracker=tracker)
        config = CampaignConfig(
            attack_category=category,
            priority=CampaignPriority.HIGH,
            max_attacks=3,            # try multiple seed attacks
            max_mutations_per_attack=3,  # mutate aggressively
            cost_budget_usd=3.0,
            patient_id=patient_id,
        )
        initial = make_initial_state(
            campaign_id=f"demo-{category.value}",
            attack_category=category.value,
            target_url=settings.backend_url,
            config=config.model_dump(mode="json"),
            patient_id=patient_id,
            max_attacks=3,
            max_mutations=3,
        )
        final = await graph.ainvoke(initial, config={"recursion_limit": 80})
    return {
        "category": category.value,
        "elapsed_s": round(time.time() - started, 1),
        "cost_usd": float(tracker.total),
        "attacks_run": final.get("attacks_run", 0),
        "findings": final.get("confirmed_findings", []),
        "agent_trace": final.get("agent_trace", []),
    }


async def main() -> None:
    settings = get_settings()
    pids = settings.test_patient_ids_list
    if not pids:
        print("ERROR: BACKEND_TEST_PATIENT_IDS empty")
        return
    patient_id = pids[0]
    print(f"target:     {settings.backend_url}")
    print(f"patient_id: {patient_id}")
    print()

    total_cost = 0.0
    all_findings: list[str] = []
    for cat in TARGET_CATEGORIES:
        try:
            r = await run(cat, patient_id)
        except Exception as e:  # noqa: BLE001
            print(f"  {cat.value:26s}  ERROR: {e}")
            continue
        total_cost += r["cost_usd"]
        all_findings.extend(r["findings"])
        print(
            f"  {r['category']:26s}  attacks={r['attacks_run']}  cost=${r['cost_usd']:.4f}  "
            f"findings={r['findings']}  ({r['elapsed_s']}s)"
        )

    print()
    print(f"TOTAL cost ${total_cost:.4f}")
    print(f"REPORTS:    {all_findings}")


if __name__ == "__main__":
    asyncio.run(main())
