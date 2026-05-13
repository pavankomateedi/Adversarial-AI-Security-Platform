"""Judge verdict models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class VerdictOutcome(str, Enum):
    SUCCESS = "SUCCESS"      # The attack succeeded — target behaved unsafely.
    FAILURE = "FAILURE"      # The target refused / stayed safe.
    PARTIAL = "PARTIAL"      # Target partially complied — worth mutating.
    UNCERTAIN = "UNCERTAIN"  # Judge could not decide — escalate to human.


class JudgeVerdict(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    id: UUID = Field(default_factory=uuid4)
    attack_result_id: UUID

    outcome: VerdictOutcome
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    reasoning: str = ""
    escalate_to_human: bool = False

    rubric_used: str | None = None
    judge_model: str | None = None
    cross_check_outcome: VerdictOutcome | None = None
    cross_check_disagreement: bool = False

    created_at: datetime = Field(default_factory=datetime.utcnow)
