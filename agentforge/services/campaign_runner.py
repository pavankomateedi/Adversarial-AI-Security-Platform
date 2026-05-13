"""Glue that drives a campaign from API call to finished record.

The API layer enqueues a campaign via `run_campaign()` and immediately
returns the campaign_id. This module runs the LangGraph in a background
task, persists each AttackResult as it lands, and finalizes the
campaign record with status + total cost.
"""

from __future__ import annotations

import asyncio
import logging
from decimal import Decimal
from typing import Any
from uuid import UUID

from agentforge.config import get_settings
from agentforge.core.cost_tracker import CostTracker
from agentforge.core.target_client import ClinicalCopilotClient
from agentforge.db.database import session_scope
from agentforge.db.repositories.attacks import AttackResultRepository
from agentforge.db.repositories.campaigns import CampaignRepository
from agentforge.graph.campaign_graph import build_campaign_graph
from agentforge.graph.state import make_initial_state
from agentforge.models.attack import AttackResult as AttackResultModel
from agentforge.models.campaign import CampaignConfig, CampaignStatus

logger = logging.getLogger(__name__)


async def start_campaign(config: CampaignConfig, *, patient_id: str | None = None) -> UUID:
    """Persist the campaign row and spawn a background task that runs it."""
    async with session_scope() as session:
        repo = CampaignRepository(session)
        row = await repo.create(config)
        campaign_id = row.id

    asyncio.create_task(_run_campaign_task(campaign_id, config, patient_id))
    return campaign_id


async def _run_campaign_task(campaign_id: UUID, config: CampaignConfig, patient_id: str | None) -> None:
    settings = get_settings()
    pid = patient_id or (settings.test_patient_ids_list[0] if settings.test_patient_ids_list else None)

    async with session_scope() as session:
        await CampaignRepository(session).update_status(campaign_id, CampaignStatus.RUNNING)

    cost_tracker = CostTracker(ceiling_usd=float(config.cost_budget_usd))
    target_client = ClinicalCopilotClient(settings=settings)

    final_state: dict[str, Any] = {}
    try:
        graph = build_campaign_graph(target_client=target_client, cost_tracker=cost_tracker)
        initial = make_initial_state(
            campaign_id=str(campaign_id),
            attack_category=str(config.attack_category),
            target_url=settings.backend_url,
            config=config.model_dump(mode="json"),
            patient_id=pid,
            max_attacks=config.max_attacks,
            max_mutations=config.max_mutations_per_attack,
        )
        # Bound the run defensively so a bug in routing can't loop forever.
        recursion_limit = max(40, config.max_attacks * (config.max_mutations_per_attack + 2) * 3)
        final_state = await graph.ainvoke(initial, config={"recursion_limit": recursion_limit})
    except Exception:
        logger.exception("campaign %s failed", campaign_id)
        async with session_scope() as session:
            await CampaignRepository(session).update_status(campaign_id, CampaignStatus.FAILED)
        await target_client.aclose()
        return

    # Persist each attack result, then finalize the campaign row.
    attacks_persisted = 0
    async with session_scope() as session:
        attack_repo = AttackResultRepository(session)
        verdict_lookup = {str(v.get("attack_result_id")): v for v in [final_state.get("current_verdict")] if v}
        for raw in final_state.get("attack_results", []):
            try:
                result_model = AttackResultModel.model_validate(raw)
            except Exception:  # noqa: BLE001
                logger.warning("dropping malformed attack result during persistence")
                continue
            result_model = result_model.model_copy(update={"campaign_id": campaign_id})
            # Only the latest verdict makes it back to state in this MVP — older
            # ones are lost from in-memory state but rebuildable from trace.
            verdict = verdict_lookup.get(str(result_model.id))
            await attack_repo.create(
                result_model,
                verdict=verdict.get("outcome") if verdict else None,
                confidence=Decimal(str(verdict.get("confidence"))) if verdict and verdict.get("confidence") is not None else None,
            )
            attacks_persisted += 1

        snap = cost_tracker.snapshot()
        total = Decimal(str(snap["total_usd"]))
        await CampaignRepository(session).update_status(
            campaign_id,
            CampaignStatus.COMPLETED,
            total_cost_usd=total,
            findings_count=len(final_state.get("confirmed_findings", [])),
        )

    await target_client.aclose()
    logger.info(
        "campaign %s complete: attacks=%d findings=%d cost_usd=%s",
        campaign_id,
        attacks_persisted,
        len(final_state.get("confirmed_findings", [])),
        snap["total_usd"],
    )
