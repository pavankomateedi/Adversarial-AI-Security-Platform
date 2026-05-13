"""Campaign API: start / list / detail / cancel."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.db.database import get_session
from agentforge.db.repositories.campaigns import CampaignRepository
from agentforge.models.campaign import (
    CampaignConfig,
    CampaignStatus,
    CampaignSummary,
)
from agentforge.security.auth import (
    Principal,
    require_operator,
    require_viewer,
)
from agentforge.services.campaign_runner import start_campaign

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


class StartCampaignRequest(BaseModel):
    config: CampaignConfig
    patient_id: str | None = Field(
        default=None,
        description="Override patient_id; defaults to BACKEND_TEST_PATIENT_IDS[0] from env.",
    )


class StartCampaignResponse(BaseModel):
    campaign_id: UUID
    status: CampaignStatus
    started_at: datetime


@router.post("", response_model=StartCampaignResponse, status_code=status.HTTP_202_ACCEPTED)
async def start(
    req: StartCampaignRequest,
    _: Principal = Depends(require_operator),
) -> StartCampaignResponse:
    campaign_id = await start_campaign(req.config, patient_id=req.patient_id)
    return StartCampaignResponse(
        campaign_id=campaign_id,
        status=CampaignStatus.RUNNING,
        started_at=datetime.utcnow(),
    )


@router.get("", response_model=list[CampaignSummary])
async def list_campaigns(
    status_filter: str | None = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> list[CampaignSummary]:
    rows = await CampaignRepository(db).list(status=status_filter, limit=limit)
    return [CampaignRepository.to_summary(r) for r in rows]


@router.get("/{campaign_id}", response_model=CampaignSummary)
async def get_campaign(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> CampaignSummary:
    row = await CampaignRepository(db).get(campaign_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return CampaignRepository.to_summary(row)


@router.delete("/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_campaign(
    campaign_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_operator),
) -> None:
    # MVP: best-effort soft cancel — marks status; the running task will finish
    # the in-flight attack but the next orchestrator pass observes the status.
    repo = CampaignRepository(db)
    row = await repo.get(campaign_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if row.status in (CampaignStatus.COMPLETED.value, CampaignStatus.FAILED.value, CampaignStatus.CANCELLED.value):
        raise HTTPException(status_code=409, detail=f"Campaign already terminal ({row.status})")
    await repo.update_status(
        campaign_id, CampaignStatus.CANCELLED, total_cost_usd=row.total_cost_usd or Decimal("0")
    )
