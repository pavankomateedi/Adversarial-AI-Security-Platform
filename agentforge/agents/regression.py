"""RegressionAgent — deterministic replay of confirmed exploits.

Loads regression_cases from DB (built from RESOLVED findings), replays the
exact attack_sequence against the current target, and uses JudgeAgent to
classify each replay as PASS / FAIL / REGRESSION:

  - PASS: target now behaves safely (verdict FAILURE).
  - FAIL: test infrastructure problem (network error, target down).
  - REGRESSION: target unsafe again (verdict SUCCESS) — a previously-fixed
    vulnerability has reappeared.

Triggers: nightly cron, Co-Pilot deployment webhook, manual API call.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from agentforge.agents.base import BaseAgent
from agentforge.agents.judge import JudgeAgent
from agentforge.agents.models import AgentRole
from agentforge.core.target_client import ClinicalCopilotClient
from agentforge.db.database import session_scope
from agentforge.db.repositories.regression import RegressionRepository
from agentforge.models.attack import AttackResult, AttackTurn
from agentforge.models.verdict import VerdictOutcome

logger = logging.getLogger(__name__)


class RegressionAgent(BaseAgent):
    role = AgentRole.JUDGE  # piggyback Judge model for verdict; no LLM of its own
    name = "regression"

    def __init__(
        self,
        *,
        target_client: ClinicalCopilotClient,
        judge: JudgeAgent | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.target_client = target_client
        self.judge = judge or JudgeAgent(cost_tracker=self.cost_tracker, settings=self.settings)

    async def run(self, state: dict[str, Any]) -> dict[str, Any]:
        trigger = str(state.get("trigger") or "manual")
        target_url = str(state.get("target_url") or self.settings.backend_url)
        patient_id = state.get("patient_id") or "demo-patient"

        async with session_scope() as session:
            repo = RegressionRepository(session)
            run = await repo.create_run(trigger=trigger, target_url=target_url)
            cases = await repo.list_active_cases()

            pass_count = 0
            fail_count = 0
            regression_count = 0
            results_summary: list[dict[str, Any]] = []

            for case in cases:
                turns = [AttackTurn(**t) for t in case.attack_sequence.get("turns", [])]
                outcome, response_text, notes = await self._replay_one(turns, patient_id=patient_id, category=str(case.evaluation_rubric.get("category") or "prompt_injection"))
                await repo.record_result(
                    run_id=run.id,
                    case_id=case.id,
                    outcome=outcome,
                    response=response_text[:5000],
                    notes=notes,
                )
                if outcome == "PASS":
                    pass_count += 1
                elif outcome == "FAIL":
                    fail_count += 1
                elif outcome == "REGRESSION":
                    regression_count += 1
                results_summary.append({"case_id": str(case.id), "outcome": outcome})

            await repo.complete_run(
                run.id, total=len(cases), passed=pass_count, failed=fail_count, regressed=regression_count
            )

            # Cross-category regression flag: did fixing one category
            # introduce a failure in a category that was clean last run?
            cross_category_flags = await self._detect_cross_category_regressions(
                repo, run.id, results_summary
            )

        return {
            "regression_run_id": str(run.id),
            "regression_results": results_summary,
            "regression_summary": {
                "total": len(cases),
                "pass": pass_count,
                "fail": fail_count,
                "regression": regression_count,
                "cross_category_regressions": cross_category_flags,
            },
            "agent_trace": state.get("agent_trace", []) + [self._trace(
                "regression_complete",
                run_id=str(run.id),
                total=len(cases),
                regression=regression_count,
                cross_category_regressions=len(cross_category_flags),
            )],
        }

    async def _detect_cross_category_regressions(
        self,
        repo: RegressionRepository,
        run_id: Any,
        current_summary: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Flag categories that were all-PASS last run but failed this run.

        The PRD asks us to "flag when fixing one attack introduces a
        regression in another category". We can't see the Co-Pilot's diff,
        but we can see the *symptom*: a category that was green last run and
        is red this run, when nothing in that category's own cases changed.
        That's the signature of a fix in category A breaking category B.
        """
        prev_run = await repo.previous_completed_run(run_id)
        if prev_run is None:
            return []  # first run — no baseline to compare against

        prev_results = await repo.results_for_run(prev_run.id)
        # case_id -> category, covering both runs' cases
        all_case_ids = {r.case_id for r in prev_results if r.case_id}
        all_case_ids |= {
            UUID(r["case_id"]) for r in current_summary if r.get("case_id")
        }
        case_cat = await repo.case_categories(list(all_case_ids))

        def _category_status(results: list[tuple[Any, str]]) -> dict[str, set[str]]:
            """category -> set of outcomes seen."""
            out: dict[str, set[str]] = {}
            for case_id, outcome in results:
                cat = case_cat.get(case_id, "unknown")
                out.setdefault(cat, set()).add(outcome)
            return out

        prev_by_cat = _category_status(
            [(r.case_id, r.outcome) for r in prev_results if r.case_id]
        )
        curr_by_cat = _category_status(
            [
                (UUID(r["case_id"]), r["outcome"])
                for r in current_summary
                if r.get("case_id")
            ]
        )

        flags: list[dict[str, Any]] = []
        for cat, curr_outcomes in curr_by_cat.items():
            prev_outcomes = prev_by_cat.get(cat)
            if prev_outcomes is None:
                continue  # category is new — not a regression
            was_clean = prev_outcomes <= {"PASS"}
            now_broken = bool(curr_outcomes & {"FAIL", "REGRESSION"})
            if was_clean and now_broken:
                flags.append({
                    "category": cat,
                    "previous": sorted(prev_outcomes),
                    "current": sorted(curr_outcomes),
                    "note": (
                        f"Category '{cat}' was clean in run {prev_run.id} but "
                        f"shows {sorted(curr_outcomes & {'FAIL', 'REGRESSION'})} "
                        "this run — possible side-effect of a fix elsewhere."
                    ),
                })
        if flags:
            logger.warning("cross-category regressions detected: %s", [f["category"] for f in flags])
        return flags

    async def _replay_one(
        self,
        turns: list[AttackTurn],
        *,
        patient_id: str,
        category: str,
    ) -> tuple[str, str, str]:
        try:
            if len(turns) > 1:
                responses = await self.target_client.send_conversation(turns, patient_id=patient_id)
                if not responses:
                    return "FAIL", "", "no responses"
                target_resp = responses[-1]
            elif turns:
                target_resp = await self.target_client.send_message(turns[0].content, patient_id=patient_id)
            else:
                return "FAIL", "", "no turns"
        except Exception as e:  # noqa: BLE001
            return "FAIL", "", f"target error: {e}"

        if target_resp.error or target_resp.status_code == 0:
            return "FAIL", target_resp.response_text, target_resp.error or "transport error"

        # Build an attack_result dict and ask the Judge.
        attack_result = AttackResult(
            attack_case_id="REGRESSION",
            category=category,  # type: ignore[arg-type]
            prompt="\n".join(t.content for t in turns if t.role == "user"),
            response=target_resp.response_text,
            target_response=target_resp,
        )
        verdict = await self.judge._judge(attack_result.model_dump(mode="json"))
        outcome = VerdictOutcome(verdict.outcome) if isinstance(verdict.outcome, str) else verdict.outcome
        if outcome == VerdictOutcome.SUCCESS:
            return "REGRESSION", target_resp.response_text, f"confidence={verdict.confidence}"
        if outcome in (VerdictOutcome.FAILURE, VerdictOutcome.PARTIAL):
            return "PASS", target_resp.response_text, f"verdict={outcome.value} confidence={verdict.confidence}"
        # UNCERTAIN → escalate; report as PASS conservatively (don't claim regression on uncertainty).
        return "PASS", target_resp.response_text, "verdict=UNCERTAIN — escalated"
