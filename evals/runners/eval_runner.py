"""Run the seed attack library against the live (or staging) Co-Pilot.

CLI usage:
    uv run python -m evals.runners.eval_runner --target $BACKEND_URL [--category prompt_injection] [--output evals/results/run.json]
    uv run python -m evals.runners.eval_runner --smoke   # harness self-test, no LLM calls

`--smoke` exercises the imports and the YAML loader so CI can verify the
harness is intact without burning Anthropic / Groq tokens. Real runs use the
campaign graph: each attack flows RedTeam → Co-Pilot → Judge.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from agentforge.config import get_settings
from agentforge.core.attack_library import SEED_ATTACKS, AttackLibrary
from agentforge.core.cost_tracker import CostTracker
from agentforge.core.target_client import ClinicalCopilotClient
from agentforge.graph.campaign_graph import build_campaign_graph
from agentforge.graph.state import make_initial_state
from agentforge.models.attack import AttackCategory
from agentforge.models.campaign import CampaignConfig, CampaignPriority

logger = logging.getLogger("eval_runner")

RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"
CATEGORIES_DIR = Path(__file__).resolve().parents[1] / "categories"


def _smoke() -> int:
    """Load every YAML, verify the seed library is structurally sound. Exit 0 = ok."""
    lib = AttackLibrary()
    print(f"library: {len(lib)} seed attacks across {len(lib.categories())} categories")
    yaml_files = list(CATEGORIES_DIR.rglob("*.yaml"))
    if not yaml_files:
        print(f"ERROR: no YAML eval files under {CATEGORIES_DIR}")
        return 1
    for path in yaml_files:
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            print(f"ERROR: {path}: {e}")
            return 1
    for case in SEED_ATTACKS:
        assert case.success_indicators, f"{case.attack_id} missing success_indicators"
        assert case.failure_indicators, f"{case.attack_id} missing failure_indicators"
    print(f"yamls: {len(yaml_files)} files validated")
    print("OK")
    return 0


async def run_category(
    category: AttackCategory,
    *,
    target_url: str,
    patient_id: str,
    max_attacks: int,
    max_mutations: int,
) -> dict[str, Any]:
    settings = get_settings()
    tracker = CostTracker(ceiling_usd=5.0)
    started = time.time()
    async with ClinicalCopilotClient(settings) as client:
        graph = build_campaign_graph(target_client=client, cost_tracker=tracker)
        config = CampaignConfig(
            attack_category=category,
            priority=CampaignPriority.HIGH,
            max_attacks=max_attacks,
            max_mutations_per_attack=max_mutations,
            patient_id=patient_id,
        )
        initial = make_initial_state(
            campaign_id=f"eval-{category.value}-{int(started)}",
            attack_category=category.value,
            target_url=target_url,
            config=config.model_dump(mode="json"),
            patient_id=patient_id,
            max_attacks=max_attacks,
            max_mutations=max_mutations,
        )
        final = await graph.ainvoke(initial, config={"recursion_limit": max(30, max_attacks * (max_mutations + 2) * 3)})

    return {
        "category": category.value,
        "elapsed_s": round(time.time() - started, 2),
        "cost_usd": float(tracker.total),
        "attacks_run": final.get("attacks_run", 0),
        "verdict": final.get("current_verdict"),
        "findings": final.get("confirmed_findings", []),
        "agent_trace": final.get("agent_trace", []),
    }


async def run_full(
    *,
    target_url: str,
    patient_id: str,
    categories: list[AttackCategory],
    max_attacks: int,
    max_mutations: int,
) -> dict[str, Any]:
    overall_started = datetime.now(UTC).isoformat()
    results: list[dict[str, Any]] = []
    for cat in categories:
        try:
            r = await run_category(
                cat,
                target_url=target_url,
                patient_id=patient_id,
                max_attacks=max_attacks,
                max_mutations=max_mutations,
            )
        except Exception as e:  # noqa: BLE001
            r = {"category": cat.value, "error": str(e)[:300]}
        results.append(r)
        print(
            f"  {cat.value:26s}  attacks={r.get('attacks_run', '?')}  "
            f"cost=${r.get('cost_usd', 0):.4f}  "
            f"{r.get('elapsed_s', '?')}s  "
            f"err={r.get('error', '')}"
        )
    summary = {
        "started_at": overall_started,
        "target_url": target_url,
        "patient_id": patient_id,
        "categories": [c.value for c in categories],
        "max_attacks_per_category": max_attacks,
        "max_mutations_per_attack": max_mutations,
        "results": results,
    }
    total_cost = sum(r.get("cost_usd", 0) or 0 for r in results)
    summary["total_cost_usd"] = round(total_cost, 4)
    summary["total_findings"] = [vid for r in results for vid in (r.get("findings") or [])]
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentForge eval runner")
    parser.add_argument("--target", help="BACKEND_URL of the Co-Pilot (defaults to env)")
    parser.add_argument("--category", help="Run a single category (default: all 6)")
    parser.add_argument("--max-attacks", type=int, default=2)
    parser.add_argument("--max-mutations", type=int, default=1)
    parser.add_argument("--output", help="Write JSON results to this path")
    parser.add_argument("--smoke", action="store_true", help="Validate harness only (no LLM calls)")
    args = parser.parse_args()

    if args.smoke:
        return _smoke()

    settings = get_settings()
    target_url = args.target or settings.backend_url
    patient_ids = settings.test_patient_ids_list
    if not patient_ids:
        print("ERROR: BACKEND_TEST_PATIENT_IDS not configured")
        return 2
    patient_id = patient_ids[0]

    if args.category:
        try:
            categories = [AttackCategory(args.category)]
        except ValueError:
            print(f"ERROR: unknown category '{args.category}'. Options: {[c.value for c in AttackCategory]}")
            return 2
    else:
        categories = list(AttackCategory)

    print(f"target:     {target_url}")
    print(f"patient_id: {patient_id}")
    print(f"categories: {[c.value for c in categories]}")
    print(f"per-category: max_attacks={args.max_attacks} max_mutations={args.max_mutations}")
    print()

    summary = asyncio.run(
        run_full(
            target_url=target_url,
            patient_id=patient_id,
            categories=categories,
            max_attacks=args.max_attacks,
            max_mutations=args.max_mutations,
        )
    )
    print()
    print(f"TOTAL cost ${summary['total_cost_usd']:.4f}  findings={summary['total_findings']}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, default=str, indent=2), encoding="utf-8")
        print(f"wrote {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
