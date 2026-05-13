"""Sweep all 6 attack categories with 1 attack each — generate findings.

For each category, runs a 1-attack campaign with no mutations against the
live Co-Pilot. Prints a verdict matrix + the cost ledger so the demo has
real data to point at.

    uv run python -m scripts.smoke_full_sweep
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

CATEGORIES = [
    AttackCategory.PROMPT_INJECTION,
    AttackCategory.DATA_EXFILTRATION,
    AttackCategory.STATE_CORRUPTION,
    AttackCategory.TOOL_MISUSE,
    AttackCategory.DENIAL_OF_SERVICE,
    AttackCategory.IDENTITY_EXPLOITATION,
]


async def run_one(category: AttackCategory, patient_id: str) -> dict:
    settings = get_settings()
    tracker = CostTracker(ceiling_usd=2.00)
    started = time.time()
    async with ClinicalCopilotClient(settings) as client:
        graph = build_campaign_graph(target_client=client, cost_tracker=tracker)
        config = CampaignConfig(
            attack_category=category,
            priority=CampaignPriority.HIGH,
            max_attacks=2,
            max_mutations_per_attack=2,
            cost_budget_usd=2.00,
            patient_id=patient_id,
        )
        initial = make_initial_state(
            campaign_id=f"sweep-{category.value}",
            attack_category=category.value,
            target_url=settings.backend_url,
            config=config.model_dump(mode="json"),
            patient_id=patient_id,
            max_attacks=2,
            max_mutations=2,
        )
        final = await graph.ainvoke(initial, config={"recursion_limit": 60})

    elapsed = time.time() - started
    verdict = final.get("current_verdict") or {}
    last_attack = (final.get("attack_results") or [{}])[-1]
    trace_summary = " | ".join(f"{t.get('agent','?')}:{t.get('event','?')}" for t in (final.get("agent_trace") or []))
    return {
        "category": category.value,
        "attack_id": last_attack.get("attack_case_id"),
        "outcome": verdict.get("outcome"),
        "confidence": verdict.get("confidence"),
        "findings": final.get("confirmed_findings", []),
        "elapsed_s": round(elapsed, 1),
        "cost_usd": float(tracker.total),
        "reasoning": (verdict.get("reasoning") or "")[:120],
        "trace": trace_summary,
        "attacks_run": final.get("attacks_run", 0),
    }


async def main() -> None:
    settings = get_settings()
    pids = settings.test_patient_ids_list or ["demo-001"]
    patient_id = pids[0]
    print(f"Target:     {settings.backend_url}")
    print(f"Patient:    {patient_id}")
    print(f"Sweeping {len(CATEGORIES)} categories, 1 attack each, no mutations")
    print("-" * 100)

    results = []
    total_cost = 0.0
    for cat in CATEGORIES:
        try:
            r = await run_one(cat, patient_id)
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            r = {"category": cat.value, "error": str(e)[:200]}
        results.append(r)
        total_cost += r.get("cost_usd", 0.0)
        print(
            f"  {(r.get('category') or '?'):26s}  "
            f"{(r.get('attack_id') or '-'):20s}  "
            f"{(str(r.get('outcome')) if r.get('outcome') else '-'):10s}  "
            f"conf={r.get('confidence') if r.get('confidence') is not None else '-'}  "
            f"cost=${r.get('cost_usd') or 0:.4f}  "
            f"{r.get('elapsed_s') if r.get('elapsed_s') is not None else '?'}s"
        )
        if r.get("reasoning"):
            print(f"      -> {r['reasoning']}")
        if r.get("error"):
            print(f"      x ERROR: {r['error']}")

    print("-" * 100)
    successes = [r for r in results if r.get("outcome") == "SUCCESS"]
    findings = [vid for r in results for vid in r.get("findings", [])]
    print(f"  TOTAL COST: ${total_cost:.4f}")
    print(f"  SUCCESSES:  {len(successes)} / {len(results)}")
    print(f"  FINDINGS FILED: {findings}")
    if successes:
        print()
        print("  Filed reports:")
        for r in successes:
            for vid in r.get("findings", []):
                print(f"    vulnerability_reports/{vid}.md  ({r['category']})")


if __name__ == "__main__":
    asyncio.run(main())
