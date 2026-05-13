"""Vulnerability finding model."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from agentforge.models.attack import AttackCategory, AttackSeverity


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    WONT_FIX = "WONT_FIX"


class VulnerabilityFinding(BaseModel):
    """One filed vulnerability — links the attack/judgment to the report.

    `report_markdown` is the full CVE-style document (CLAUDE.md §4.4);
    `report_json` is the structured form used by dashboards.
    """

    model_config = ConfigDict(use_enum_values=True)

    id: UUID = Field(default_factory=uuid4)
    vuln_id: str  # VULN-001, VULN-002, ...
    title: str
    severity: AttackSeverity
    status: FindingStatus = FindingStatus.OPEN
    category: AttackCategory
    cvss_score: Decimal | None = None

    attack_result_id: UUID | None = None
    report_markdown: str | None = None
    report_json: dict[str, Any] | None = None

    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
