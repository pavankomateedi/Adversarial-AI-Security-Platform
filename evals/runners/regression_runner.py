"""Run the regression suite against a target Co-Pilot.

CLI usage:
    uv run python -m evals.runners.regression_runner --target $BACKEND_URL [--fail-on-regression]

Exit codes:
    0   all PASS
    1   FAIL (infrastructure problem — caller decides whether to retry)
    2   REGRESSION detected (and `--fail-on-regression` is set)
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

from agentforge.agents.regression import RegressionAgent
from agentforge.config import get_settings
from agentforge.core.cost_tracker import CostTracker
from agentforge.core.target_client import ClinicalCopilotClient

logger = logging.getLogger("regression_runner")

RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"


async def run_suite(target_url: str, patient_id: str, trigger: str) -> dict:
    settings = get_settings()
    tracker = CostTracker(ceiling_usd=5.0)
    async with ClinicalCopilotClient(settings) as client:
        agent = RegressionAgent(target_client=client, cost_tracker=tracker)
        started = time.time()
        result = await agent.run(
            {
                "trigger": trigger,
                "target_url": target_url,
                "patient_id": patient_id,
                "agent_trace": [],
            }
        )
        result["elapsed_s"] = round(time.time() - started, 2)
        result["cost_usd"] = float(tracker.total)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentForge regression runner")
    parser.add_argument("--target", help="BACKEND_URL of the Co-Pilot (defaults to env)")
    parser.add_argument("--trigger", default="manual", choices=["manual", "scheduled", "deployment"])
    parser.add_argument("--suite", default="all", help="(reserved) regression suite name")
    parser.add_argument("--output", help="Write JSON results to this path")
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    target_url = args.target or settings.backend_url
    patient_ids = settings.test_patient_ids_list
    if not patient_ids:
        print("ERROR: BACKEND_TEST_PATIENT_IDS not configured")
        return 2
    patient_id = patient_ids[0]

    print(f"target:    {target_url}")
    print(f"trigger:   {args.trigger}")
    print(f"suite:     {args.suite}")
    print()

    result = asyncio.run(run_suite(target_url, patient_id, args.trigger))
    summary = result.get("regression_summary", {})
    print(json.dumps(summary, indent=2))

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"completed_at": datetime.now(UTC).isoformat(), **result}
        out_path.write_text(json.dumps(payload, default=str, indent=2), encoding="utf-8")
        print(f"wrote {out_path}")

    if args.fail_on_regression and (summary.get("regression", 0) or 0) > 0:
        print("FAIL: regressions detected")
        return 2
    if (summary.get("fail", 0) or 0) > 0:
        print("WARN: some test infra failures")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
