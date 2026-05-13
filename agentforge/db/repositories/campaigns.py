"""Repository for the campaigns table."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.db.models import Campaign
from agentforge.models.campaign import (
    CampaignConfig,
    CampaignStatus,
    CampaignSummary,
)


class CampaignRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, config: CampaignConfig) -> Campaign:
        row = Campaign(
            status=CampaignStatus.PENDING.value,
            attack_category=str(config.attack_category),
            config=config.model_dump(mode="json"),
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def get(self, campaign_id: UUID) -> Campaign | None:
        return await self.session.get(Campaign, campaign_id)

    async def list(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[Campaign]:
        stmt = select(Campaign).order_by(Campaign.started_at.desc()).limit(limit)
        if status:
            stmt = stmt.where(Campaign.status == status)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_status(
        self,
        campaign_id: UUID,
        status: CampaignStatus,
        *,
        total_cost_usd: Decimal | None = None,
        findings_count: int | None = None,
    ) -> Campaign | None:
        row = await self.get(campaign_id)
        if row is None:
            return None
        row.status = status.value
        if status in (CampaignStatus.COMPLETED, CampaignStatus.FAILED, CampaignStatus.CANCELLED):
            row.completed_at = datetime.now(timezone.utc)
        if total_cost_usd is not None:
            row.total_cost_usd = total_cost_usd
        if findings_count is not None:
            row.findings_count = findings_count
        await self.session.flush()
        return row

    @staticmethod
    def to_summary(row: Campaign) -> CampaignSummary:
        return CampaignSummary(
            id=row.id,
            status=CampaignStatus(row.status),
            attack_category=row.attack_category,  # type: ignore[arg-type]
            config=CampaignConfig.model_validate(row.config),
            started_at=row.started_at,
            completed_at=row.completed_at,
            total_cost_usd=row.total_cost_usd or Decimal("0"),
            findings_count=row.findings_count,
        )
