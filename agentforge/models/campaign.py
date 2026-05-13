"""Campaign-level models."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from agentforge.models.attack import AttackCategory


class CampaignStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CampaignPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CampaignConfig(BaseModel):
    """What the Orchestrator emits to the RedTeam."""

    model_config = ConfigDict(use_enum_values=True)

    attack_category: AttackCategory
    priority: CampaignPriority = CampaignPriority.MEDIUM
    token_budget: int = Field(default=50_000, ge=1000)
    cost_budget_usd: Decimal = Decimal("5.00")
    target_endpoint: str = "/chat"
    max_attacks: int = Field(default=10, ge=1, le=200)
    max_mutations_per_attack: int = Field(default=3, ge=0, le=10)
    patient_id: str | None = None
    multi_agent_target: bool = False  # set Co-Pilot's `multi_agent: true` flag
    notes: str | None = None


class CampaignSummary(BaseModel):
    """Top-level campaign record returned by GET /campaigns and GET /campaigns/{id}."""

    id: UUID = Field(default_factory=uuid4)
    status: CampaignStatus
    attack_category: AttackCategory
    config: CampaignConfig
    started_at: datetime
    completed_at: datetime | None = None
    total_cost_usd: Decimal = Decimal("0")
    attacks_run: int = 0
    findings_count: int = 0
