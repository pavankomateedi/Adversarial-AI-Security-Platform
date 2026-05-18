"""Ingest hand-written VULN-*.md reports into the findings DB.

After running, `GET /api/v1/findings` exposes them via the API and they
flow through the same status / approval workflow as agent-generated reports.

Usage:
    uv run python -m scripts.ingest_findings              # local DB
    railway run python -m scripts.ingest_findings        # prod DB
"""

from __future__ import annotations

import asyncio
import re
from decimal import Decimal
from pathlib import Path

from agentforge.db.database import session_scope
from agentforge.db.repositories.findings import FindingRepository
from agentforge.models.attack import AttackCategory, AttackSeverity
from agentforge.models.finding import FindingStatus, VulnerabilityFinding

REPORTS_DIR = Path(__file__).resolve().parents[1] / "vulnerability_reports"

# Hand-curated metadata for each manually-written report. The markdown body
# stays the source of truth for content; this dict just tells the API what
# severity / status / category to surface in the dashboard.
HAND_WRITTEN: list[dict] = [
    {
        "vuln_id": "VULN-001",
        "title": "[RETRACTED] Cross-tenant PHI disclosure via /patients/{id}/identity",
        "severity": AttackSeverity.CRITICAL,
        "category": AttackCategory.DATA_EXFILTRATION,
        "cvss_score": Decimal("8.2"),
        "status": FindingStatus.WONT_FIX,
        "force_status": True,
    },
    {
        "vuln_id": "VULN-002",
        "title": "[RETRACTED] Cross-patient clinical-data disclosure via /chat",
        "severity": AttackSeverity.CRITICAL,
        "category": AttackCategory.DATA_EXFILTRATION,
        "cvss_score": Decimal("8.6"),
        "status": FindingStatus.WONT_FIX,
        "force_status": True,
    },
    {
        "vuln_id": "VULN-003",
        "title": "[RETRACTED] Patient enumeration via /documents/list",
        "severity": AttackSeverity.HIGH,
        "category": AttackCategory.DATA_EXFILTRATION,
        "cvss_score": Decimal("6.5"),
        "status": FindingStatus.WONT_FIX,
        "force_status": True,
    },
    {
        "vuln_id": "VULN-VERIFIED-001",
        "title": "Test-harness defect produced false-positive cross-user RBAC findings",
        "severity": AttackSeverity.HIGH,
        "category": AttackCategory.IDENTITY_EXPLOITATION,
        "cvss_score": Decimal("0.0"),
        "status": FindingStatus.RESOLVED,
        "force_status": True,
    },
]


def _extract_summary(md_path: Path) -> str:
    text = md_path.read_text(encoding="utf-8")
    m = re.search(r"## Executive Summary\s*\n(.+?)(?=\n##|\Z)", text, re.DOTALL)
    return (m.group(1).strip() if m else text)[:800]


async def ingest() -> None:
    async with session_scope() as session:
        repo = FindingRepository(session)
        for meta in HAND_WRITTEN:
            existing = await repo.get_by_vuln_id(meta["vuln_id"])
            md_path = REPORTS_DIR / f"{meta['vuln_id']}.md"
            if not md_path.exists():
                print(f"  SKIP {meta['vuln_id']}: file not found at {md_path}")
                continue
            md_body = md_path.read_text(encoding="utf-8")
            summary = _extract_summary(md_path)

            if existing:
                existing.report_markdown = md_body
                existing.title = meta["title"]
                existing.severity = meta["severity"].value
                existing.category = meta["category"].value
                existing.cvss_score = meta["cvss_score"]
                if meta.get("force_status"):
                    existing.status = meta["status"].value
                await session.flush()
                print(f"  refreshed {meta['vuln_id']} ({existing.status})")
                continue

            finding = VulnerabilityFinding(
                vuln_id=meta["vuln_id"],
                title=meta["title"],
                severity=meta["severity"],
                status=meta["status"],
                category=meta["category"],
                cvss_score=meta["cvss_score"],
                report_markdown=md_body,
                report_json={"executive_summary": summary, "source": "manual_ingest"},
            )
            await repo.create(finding)
            print(f"  inserted {meta['vuln_id']} ({meta['status'].value})")
    print("done")


if __name__ == "__main__":
    asyncio.run(ingest())
