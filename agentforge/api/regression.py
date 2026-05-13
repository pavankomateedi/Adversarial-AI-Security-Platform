"""Regression API: trigger / latest results / run history."""

from __future__ import annotations

import asyncio
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.config import get_settings
from agentforge.core.target_client import ClinicalCopilotClient
from agentforge.db.database import get_session
from agentforge.db.repositories.regression import RegressionRepository
from agentforge.graph.regression_graph import build_regression_graph
from agentforge.security.auth import Principal, require_operator, require_viewer

router = APIRouter(prefix="/regression", tags=["regression"])


class RunOut(BaseModel):
    id: UUID
    trigger: str
    target_url: str
    started_at: datetime
    completed_at: datetime | None
    total_cases: int | None
    pass_count: int | None
    fail_count: int | None
    regression_count: int | None


class RunResultOut(BaseModel):
    id: UUID
    run_id: UUID | None
    case_id: UUID | None
    outcome: str
    executed_at: datetime
    notes: str | None


class TriggerRequest(BaseModel):
    trigger: str = "manual"
    patient_id: str | None = None


class TriggerResponse(BaseModel):
    run_id: UUID
    summary: dict


@router.post("/run", response_model=TriggerResponse)
async def trigger_run(
    body: TriggerRequest,
    _: Principal = Depends(require_operator),
) -> TriggerResponse:
    settings = get_settings()
    patient_id = body.patient_id or (
        settings.test_patient_ids_list[0] if settings.test_patient_ids_list else None
    )
    target_client = ClinicalCopilotClient(settings=settings)
    graph = build_regression_graph(target_client=target_client)
    try:
        result = await asyncio.wait_for(
            graph.ainvoke(
                {
                    "trigger": body.trigger,
                    "target_url": settings.backend_url,
                    "patient_id": patient_id,
                }
            ),
            timeout=300,  # 5-minute cap; nightly runs that need longer go via the worker
        )
    finally:
        await target_client.aclose()
    return TriggerResponse(
        run_id=UUID(result["regression_run_id"]),
        summary=result.get("regression_summary", {}),
    )


@router.get("/results", response_model=list[RunResultOut])
async def latest_results(
    limit: int = 50,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> list[RunResultOut]:
    rows = await RegressionRepository(db).latest_results(limit=limit)
    return [
        RunResultOut(
            id=r.id, run_id=r.run_id, case_id=r.case_id, outcome=r.outcome,
            executed_at=r.executed_at, notes=r.notes,
        )
        for r in rows
    ]


@router.get("/history", response_model=list[RunOut])
async def history(
    limit: int = 50,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> list[RunOut]:
    rows = await RegressionRepository(db).list_runs(limit=limit)
    return [
        RunOut(
            id=r.id,
            trigger=r.trigger,
            target_url=r.target_url,
            started_at=r.started_at,
            completed_at=r.completed_at,
            total_cases=r.total_cases,
            pass_count=r.pass_count,
            fail_count=r.fail_count,
            regression_count=r.regression_count,
        )
        for r in rows
    ]
