"""Attack-surface coverage tracker.

Computes "how thoroughly have we tested each category?" from the
attack_results table. The Orchestrator uses this to prioritize the next
campaign.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.core.attack_library import AttackLibrary
from agentforge.db.models import AttackResult


@dataclass(frozen=True)
class CategoryCoverage:
    category: str
    cases_run: int
    successes: int
    total_seed_cases: int

    @property
    def coverage_pct(self) -> float:
        # Coverage is bounded at 100% per category — we may run a case
        # multiple times (mutations) but each attack_case_id only counts once
        # against the seed library.
        if self.total_seed_cases == 0:
            return 0.0
        return min(100.0, 100.0 * self.cases_run / self.total_seed_cases)


class CoverageTracker:
    def __init__(self, session: AsyncSession, library: AttackLibrary | None = None) -> None:
        self.session = session
        self.library = library or AttackLibrary()

    async def by_category(self) -> dict[str, CategoryCoverage]:
        """Distinct-case coverage per category.

        Counts the number of distinct seed cases tried per category, divided
        by the total seed cases in that category. Successes are counted across
        all attempts (including mutations).
        """
        distinct_cases_stmt = (
            select(
                AttackResult.category,
                func.count(func.distinct(AttackResult.attack_case_id)),
            )
            .where(AttackResult.attack_case_id.isnot(None))
            .group_by(AttackResult.category)
        )
        cases_run = {
            cat: int(c) for cat, c in (await self.session.execute(distinct_cases_stmt)).all()
        }

        success_stmt = (
            select(AttackResult.category, func.count())
            .where(AttackResult.verdict == "SUCCESS")
            .group_by(AttackResult.category)
        )
        successes = {cat: int(c) for cat, c in (await self.session.execute(success_stmt)).all()}

        out: dict[str, CategoryCoverage] = {}
        for cat in self.library.categories():
            total = len(self.library.by_category(cat))
            out[cat] = CategoryCoverage(
                category=cat,
                cases_run=cases_run.get(cat, 0),
                successes=successes.get(cat, 0),
                total_seed_cases=total,
            )
        return out

    async def gaps(self, *, threshold: float = 70.0) -> list[CategoryCoverage]:
        """Categories below the coverage threshold, worst first."""
        cov = await self.by_category()
        below = [c for c in cov.values() if c.coverage_pct < threshold]
        return sorted(below, key=lambda c: c.coverage_pct)
