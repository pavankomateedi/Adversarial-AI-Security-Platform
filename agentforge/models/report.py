"""CVE-style vulnerability report model.

The DocumentationAgent renders this into the markdown shape from CLAUDE.md
§4.4. Keeping the structured form makes dashboards and the API surface
trivial to wire up later.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from agentforge.models.attack import AttackCategory, AttackSeverity
from agentforge.models.finding import FindingStatus


class ObservedVsExpected(BaseModel):
    aspect: str
    observed: str
    expected: str


class VulnerabilityReport(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    vuln_id: str
    title: str
    severity: AttackSeverity
    status: FindingStatus = FindingStatus.OPEN
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    category: AttackCategory
    cvss_score: Decimal | None = None

    executive_summary: str  # ~150 words; clinical impact framing
    technical_description: str
    reproduction_steps: list[str]
    observed_vs_expected: list[ObservedVsExpected]
    clinical_impact: str
    remediation: str
    validation: str  # how the operator verifies the fix
    references: list[str] = Field(default_factory=list)

    def to_markdown(self) -> str:
        """Render to the exact format required by CLAUDE.md §4.4."""

        def _bullets(items: list[str]) -> str:
            return "\n".join(f"{i + 1}. {step}" for i, step in enumerate(items)) if items else "_None._"

        def _ref_lines(items: list[str]) -> str:
            return "\n".join(f"- {r}" for r in items) if items else "_None._"

        oe_table = "| Aspect | Observed | Expected |\n|---|---|---|\n" + "\n".join(
            f"| {row.aspect} | {row.observed} | {row.expected} |" for row in self.observed_vs_expected
        )

        severity = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        status = self.status.value if hasattr(self.status, "value") else str(self.status)
        category = self.category.value if hasattr(self.category, "value") else str(self.category)

        return f"""# {self.vuln_id}: {self.title}

**Severity:** {severity}
**Status:** {status}
**Discovered:** {self.discovered_at.isoformat()}
**Category:** {category}
**CVSS Score:** {self.cvss_score if self.cvss_score is not None else "_not assigned_"}

## Executive Summary
{self.executive_summary}

## Technical Description
{self.technical_description}

## Reproduction Steps
{_bullets(self.reproduction_steps)}

## Observed vs. Expected Behavior
{oe_table}

## Clinical Impact
{self.clinical_impact}

## Remediation
{self.remediation}

## Validation
{self.validation}

## References
{_ref_lines(self.references)}
"""
