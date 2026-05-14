"""Repository for the regression_cases / regression_runs / regression_results tables."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.db.models import (
    RegressionCase,
    RegressionResult,
    RegressionRun,
)


class RegressionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ----- cases -----
    async def create_case(
        self,
        *,
        finding_id: UUID,
        attack_sequence: list[dict[str, Any]],
        expected_safe_behavior: str,
        evaluation_rubric: dict[str, Any],
    ) -> RegressionCase:
        row = RegressionCase(
            finding_id=finding_id,
            attack_sequence={"turns": attack_sequence},
            expected_safe_behavior=expected_safe_behavior,
            evaluation_rubric=evaluation_rubric,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def list_active_cases(self) -> Sequence[RegressionCase]:
        stmt = select(RegressionCase).where(RegressionCase.is_active.is_(True))
        return (await self.session.execute(stmt)).scalars().all()

    # ----- runs -----
    async def create_run(self, *, trigger: str, target_url: str) -> RegressionRun:
        row = RegressionRun(trigger=trigger, target_url=target_url)
        self.session.add(row)
        await self.session.flush()
        return row

    async def complete_run(
        self,
        run_id: UUID,
        *,
        total: int,
        passed: int,
        failed: int,
        regressed: int,
    ) -> RegressionRun | None:
        row = await self.session.get(RegressionRun, run_id)
        if row is None:
            return None
        row.completed_at = datetime.now(UTC)
        row.total_cases = total
        row.pass_count = passed
        row.fail_count = failed
        row.regression_count = regressed
        await self.session.flush()
        return row

    async def list_runs(self, limit: int = 50) -> Sequence[RegressionRun]:
        stmt = select(RegressionRun).order_by(RegressionRun.started_at.desc()).limit(limit)
        return (await self.session.execute(stmt)).scalars().all()

    # ----- results -----
    async def record_result(
        self,
        *,
        run_id: UUID,
        case_id: UUID | None,
        outcome: str,
        response: str | None = None,
        notes: str | None = None,
    ) -> RegressionResult:
        row = RegressionResult(
            run_id=run_id,
            case_id=case_id,
            outcome=outcome,
            response=response,
            notes=notes,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def latest_results(self, limit: int = 200) -> Sequence[RegressionResult]:
        stmt = (
            select(RegressionResult)
            .order_by(RegressionResult.executed_at.desc())
            .limit(limit)
        )
        return (await self.session.execute(stmt)).scalars().all()

    async def results_for_run(self, run_id: UUID) -> Sequence[RegressionResult]:
        """All result rows for one run."""
        stmt = select(RegressionResult).where(RegressionResult.run_id == run_id)
        return (await self.session.execute(stmt)).scalars().all()

    async def previous_completed_run(self, before_run_id: UUID) -> RegressionRun | None:
        """The most recent *completed* run that is not `before_run_id`.

        Used by the cross-category regression flagger to compare this run's
        outcomes against the last known-good baseline.
        """
        stmt = (
            select(RegressionRun)
            .where(
                RegressionRun.id != before_run_id,
                RegressionRun.completed_at.isnot(None),
            )
            .order_by(RegressionRun.started_at.desc())
            .limit(1)
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def case_categories(self, case_ids: Sequence[UUID]) -> dict[UUID, str]:
        """Map regression_case id -> category (from evaluation_rubric)."""
        if not case_ids:
            return {}
        stmt = select(RegressionCase).where(RegressionCase.id.in_(case_ids))
        rows = (await self.session.execute(stmt)).scalars().all()
        return {
            r.id: str((r.evaluation_rubric or {}).get("category") or "unknown")
            for r in rows
        }
