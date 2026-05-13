"""Pydantic data models used across agents, API, and persistence layers."""

from agentforge.models.attack import (
    AttackCase,
    AttackCategory,
    AttackResult,
    AttackSeverity,
    TargetResponse,
)
from agentforge.models.campaign import CampaignConfig, CampaignStatus, CampaignSummary
from agentforge.models.finding import FindingStatus, VulnerabilityFinding
from agentforge.models.report import VulnerabilityReport
from agentforge.models.verdict import JudgeVerdict, VerdictOutcome

__all__ = [
    "AttackCase",
    "AttackCategory",
    "AttackResult",
    "AttackSeverity",
    "CampaignConfig",
    "CampaignStatus",
    "CampaignSummary",
    "FindingStatus",
    "JudgeVerdict",
    "TargetResponse",
    "VerdictOutcome",
    "VulnerabilityFinding",
    "VulnerabilityReport",
]
