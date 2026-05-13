"""Repository for vulnerability_findings."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.db.models import VulnerabilityFinding as FindingRow
from agentforge.models.finding import FindingStatus, VulnerabilityFinding


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def next_vuln_id(self) -> str:
        """Generate the next VULN-XXX id atomically per call."""
        # COUNT-based id assignment is fine at MVP scale; once we need
        # concurrent campaigns we move to a Postgres sequence.
        n = (await self.session.execute(select(func.count(FindingRow.id)))).scalar_one() or 0
        return f"VULN-{n + 1:03d}"

    async def create(self, finding: VulnerabilityFinding) -> FindingRow:
        row = FindingRow(
            id=finding.id,
            vuln_id=finding.vuln_id,
            title=finding.title,
            severity=str(finding.severity),
            status=str(finding.status),
            category=str(finding.category),
            cvss_score=finding.cvss_score,
            attack_result_id=finding.attack_result_id,
            report_markdown=finding.report_markdown,
            report_json=finding.report_json,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def get(self, finding_id: UUID) -> FindingRow | None:
        return await self.session.get(FindingRow, finding_id)

    async def get_by_vuln_id(self, vuln_id: str) -> FindingRow | None:
        stmt = select(FindingRow).where(FindingRow.vuln_id == vuln_id)
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def list(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        limit: int = 200,
    ) -> Sequence[FindingRow]:
        stmt = select(FindingRow).order_by(FindingRow.discovered_at.desc()).limit(limit)
        if severity:
            stmt = stmt.where(FindingRow.severity == severity)
        if status:
            stmt = stmt.where(FindingRow.status == status)
        if category:
            stmt = stmt.where(FindingRow.category == category)
        return (await self.session.execute(stmt)).scalars().all()

    async def update_status(
        self,
        finding_id: UUID,
        status: FindingStatus,
        *,
        approved_by: str | None = None,
    ) -> FindingRow | None:
        row = await self.get(finding_id)
        if row is None:
            return None
        row.status = status.value
        if status == FindingStatus.RESOLVED:
            row.resolved_at = datetime.now(UTC)
        if approved_by:
            row.approved_by = approved_by
            row.approved_at = datetime.now(UTC)
        await self.session.flush()
        return row
