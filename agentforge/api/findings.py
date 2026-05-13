"""Findings API: list / detail / status update / CRITICAL approval."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.db.database import get_session
from agentforge.db.repositories.findings import FindingRepository
from agentforge.models.finding import FindingStatus
from agentforge.security.auth import (
    Principal,
    require_admin_with_confirm,
    require_operator,
    require_viewer,
)

router = APIRouter(prefix="/findings", tags=["findings"])


class FindingOut(BaseModel):
    id: UUID
    vuln_id: str
    title: str
    severity: str
    status: str
    category: str
    cvss_score: float | None
    discovered_at: datetime
    resolved_at: datetime | None
    approved_by: str | None


class FindingDetail(FindingOut):
    report_markdown: str | None
    report_json: dict | None


class StatusUpdate(BaseModel):
    status: FindingStatus


def _to_out(row) -> FindingOut:  # type: ignore[no-untyped-def]
    return FindingOut(
        id=row.id,
        vuln_id=row.vuln_id,
        title=row.title,
        severity=row.severity,
        status=row.status,
        category=row.category,
        cvss_score=float(row.cvss_score) if row.cvss_score is not None else None,
        discovered_at=row.discovered_at,
        resolved_at=row.resolved_at,
        approved_by=row.approved_by,
    )


@router.get("", response_model=list[FindingOut])
async def list_findings(
    severity: str | None = None,
    status_filter: str | None = None,
    category: str | None = None,
    limit: int = 200,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> list[FindingOut]:
    rows = await FindingRepository(db).list(
        severity=severity, status=status_filter, category=category, limit=limit
    )
    return [_to_out(r) for r in rows]


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> FindingDetail:
    row = await FindingRepository(db).get(finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    out = _to_out(row).model_dump()
    out["report_markdown"] = row.report_markdown
    out["report_json"] = row.report_json
    return FindingDetail(**out)


@router.patch("/{finding_id}", response_model=FindingOut)
async def update_status(
    finding_id: UUID,
    body: StatusUpdate,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_operator),
) -> FindingOut:
    row = await FindingRepository(db).update_status(finding_id, body.status)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_out(row)


@router.post("/{finding_id}/approve", response_model=FindingOut)
async def approve(
    finding_id: UUID,
    db: AsyncSession = Depends(get_session),
    principal: Principal = Depends(require_admin_with_confirm),
) -> FindingOut:
    row = await FindingRepository(db).get(finding_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if row.status != FindingStatus.PENDING_APPROVAL.value:
        raise HTTPException(
            status_code=409,
            detail=f"Finding is not pending approval (status={row.status})",
        )
    row = await FindingRepository(db).update_status(
        finding_id, FindingStatus.OPEN, approved_by=principal.subject
    )
    assert row is not None
    return _to_out(row)
