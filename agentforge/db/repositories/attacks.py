"""Repository for the attack_results table."""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.db.models import AttackResult as AttackResultRow
from agentforge.models.attack import AttackResult as AttackResultModel


class AttackResultRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        result: AttackResultModel,
        *,
        verdict: str | None = None,
        confidence: Decimal | None = None,
    ) -> AttackResultRow:
        row = AttackResultRow(
            id=result.id,
            campaign_id=result.campaign_id,
            attack_case_id=result.attack_case_id,
            category=str(result.category),
            subcategory=result.subcategory,
            prompt=result.prompt,
            response=result.response,
            verdict=verdict,
            confidence=confidence,
            mutation_generation=result.mutation_generation,
            cost_usd=result.cost_usd,
            latency_ms=result.latency_ms,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def get(self, attack_id: UUID) -> AttackResultRow | None:
        return await self.session.get(AttackResultRow, attack_id)

    async def list_by_campaign(self, campaign_id: UUID) -> Sequence[AttackResultRow]:
        stmt = (
            select(AttackResultRow)
            .where(AttackResultRow.campaign_id == campaign_id)
            .order_by(AttackResultRow.created_at.asc())
        )
        return (await self.session.execute(stmt)).scalars().all()

    async def count_by_category(self) -> dict[str, int]:
        stmt = select(AttackResultRow.category, func.count()).group_by(AttackResultRow.category)
        return {cat: int(c) for cat, c in (await self.session.execute(stmt)).all()}

    async def total_cost_for_campaign(self, campaign_id: UUID) -> Decimal:
        stmt = select(func.coalesce(func.sum(AttackResultRow.cost_usd), 0)).where(
            AttackResultRow.campaign_id == campaign_id
        )
        return Decimal((await self.session.execute(stmt)).scalar_one() or 0)
