"""Human-readable status summary generator.

Reads platform state from the DB + Prometheus registry and produces a
markdown-formatted snapshot suitable for a Slack paste, an exec update, or
an on-call handoff. Rule-based and deterministic — costs nothing to run,
no LLM calls.

The JSON form is what the dashboard consumes; the markdown form is what
humans share. Both reflect the same underlying numbers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.core.attack_library import AttackLibrary
from agentforge.core.coverage_tracker import CoverageTracker
from agentforge.db.models import (
    AttackResult,
    Campaign,
    RegressionResult,
    RegressionRun,
    VulnerabilityFinding,
)


async def build_summary(session: AsyncSession) -> dict[str, Any]:
    """Compute the structured numbers behind the summary."""
    # Findings
    sev_counts: dict[str, int] = {}
    sev_stmt = select(VulnerabilityFinding.severity, func.count()).group_by(VulnerabilityFinding.severity)
    for sev, n in (await session.execute(sev_stmt)).all():
        sev_counts[sev or "UNKNOWN"] = int(n)

    status_counts: dict[str, int] = {}
    status_stmt = select(VulnerabilityFinding.status, func.count()).group_by(VulnerabilityFinding.status)
    for st, n in (await session.execute(status_stmt)).all():
        status_counts[st or "UNKNOWN"] = int(n)

    # Recent CRITICAL/HIGH findings
    high_stmt = (
        select(VulnerabilityFinding)
        .where(VulnerabilityFinding.severity.in_(["CRITICAL", "HIGH"]))
        .order_by(VulnerabilityFinding.discovered_at.desc())
        .limit(5)
    )
    high_findings = [
        {"vuln_id": r.vuln_id, "severity": r.severity, "status": r.status, "title": r.title}
        for r in (await session.execute(high_stmt)).scalars().all()
    ]

    # Campaigns + cost
    campaigns_total = int((await session.execute(select(func.count(Campaign.id)))).scalar_one() or 0)
    attacks_total = int((await session.execute(select(func.count(AttackResult.id)))).scalar_one() or 0)
    # Authoritative cost is on Campaign.total_cost_usd; AttackResult.cost_usd
    # is often zero because the per-call ledger is in-memory.
    cost_total = Decimal(
        (await session.execute(select(func.coalesce(func.sum(Campaign.total_cost_usd), 0)))).scalar_one() or 0
    )

    # Verdict distribution (last 100 attacks for trend signal)
    verdict_stmt = (
        select(AttackResult.verdict, func.count())
        .where(AttackResult.verdict.isnot(None))
        .group_by(AttackResult.verdict)
    )
    verdict_counts: dict[str, int] = {
        v or "UNCLASSIFIED": int(n) for v, n in (await session.execute(verdict_stmt)).all()
    }

    # Regression
    runs_total = int((await session.execute(select(func.count(RegressionRun.id)))).scalar_one() or 0)
    regressions_total = int(
        (await session.execute(
            select(func.count(RegressionResult.id)).where(RegressionResult.outcome == "REGRESSION")
        )).scalar_one()
        or 0
    )

    # Coverage
    library = AttackLibrary()
    cov = await CoverageTracker(session, library=library).by_category()
    coverage_rows = [
        {
            "category": c.category,
            "cases_run": c.cases_run,
            "total_seed_cases": c.total_seed_cases,
            "coverage_pct": c.coverage_pct,
            "successes": c.successes,
        }
        for c in cov.values()
    ]
    avg_coverage = (
        sum(r["coverage_pct"] for r in coverage_rows) / len(coverage_rows) if coverage_rows else 0.0
    )
    lowest_coverage = sorted(coverage_rows, key=lambda r: r["coverage_pct"])[:3]

    # Headline
    pending_critical = sum(
        1
        for r in (await session.execute(
            select(VulnerabilityFinding).where(
                VulnerabilityFinding.severity == "CRITICAL",
                VulnerabilityFinding.status == "PENDING_APPROVAL",
            )
        )).scalars().all()
    )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "findings": {
            "by_severity": sev_counts,
            "by_status": status_counts,
            "high_recent": high_findings,
            "critical_pending_approval": pending_critical,
        },
        "activity": {
            "campaigns_total": campaigns_total,
            "attacks_total": attacks_total,
            "verdict_distribution": verdict_counts,
            "cost_usd_total": float(cost_total),
        },
        "regression": {
            "runs_total": runs_total,
            "regressions_detected_total": regressions_total,
        },
        "coverage": {
            "by_category": coverage_rows,
            "average_pct": round(avg_coverage, 1),
            "lowest_three": lowest_coverage,
        },
        "recommendations": _recommend(
            pending_critical=pending_critical,
            lowest_coverage=lowest_coverage,
            attacks_total=attacks_total,
            runs_total=runs_total,
            regressions_total=regressions_total,
        ),
    }


def _recommend(
    *,
    pending_critical: int,
    lowest_coverage: list[dict],
    attacks_total: int,
    runs_total: int,
    regressions_total: int,
) -> list[str]:
    out: list[str] = []
    if pending_critical:
        out.append(
            f"Approve {pending_critical} CRITICAL finding(s) awaiting admin review "
            "(POST /api/v1/findings/{id}/approve with X-Admin-Confirm: true)."
        )
    for r in lowest_coverage:
        if r["coverage_pct"] < 50:
            out.append(
                f"Lift coverage on `{r['category']}` — currently {r['coverage_pct']:.0f}% "
                f"({r['cases_run']}/{r['total_seed_cases']} seed cases run)."
            )
    if attacks_total == 0:
        out.append("Run a first campaign — `POST /api/v1/campaigns` against the live Co-Pilot.")
    if regressions_total:
        out.append(
            f"Investigate {regressions_total} regression(s) — previously-fixed vulnerabilities have reappeared."
        )
    if runs_total == 0:
        out.append(
            "Wire the Co-Pilot's Railway deploy webhook to POST /api/v1/regression/run so every deploy "
            "auto-runs the regression suite."
        )
    if not out:
        out.append("All defenses holding; no immediate action required.")
    return out


def render_markdown(snapshot: dict[str, Any]) -> str:
    f = snapshot["findings"]
    a = snapshot["activity"]
    r = snapshot["regression"]
    c = snapshot["coverage"]

    def _sev_line(name: str) -> str:
        return f"  - {name}: **{f['by_severity'].get(name, 0)}**"

    def _status_line(name: str) -> str:
        return f"  - {name}: **{f['by_status'].get(name, 0)}**"

    high_findings_md = "\n".join(
        f"  - `{h['vuln_id']}` [{h['severity']}] {h['title']} *({h['status']})*"
        for h in f["high_recent"]
    ) or "  *(none)*"

    verdict_md = ", ".join(f"**{k}**: {v}" for k, v in a["verdict_distribution"].items()) or "*no verdicts yet*"

    coverage_md = "\n".join(
        f"  - `{row['category']:<24}` {row['coverage_pct']:>5.1f}%   ({row['cases_run']}/{row['total_seed_cases']} run, {row['successes']} succeeded)"
        for row in c["by_category"]
    ) or "  *(no coverage data)*"

    rec_md = "\n".join(f"  {i + 1}. {rec}" for i, rec in enumerate(snapshot["recommendations"]))

    return f"""# AgentForge — Status Summary
*Generated {snapshot['generated_at']}*

## Headline
- **{f['critical_pending_approval']}** CRITICAL finding(s) awaiting admin approval
- **{a['attacks_total']}** total adversarial attacks executed across **{a['campaigns_total']}** campaigns
- Average attack-surface coverage: **{c['average_pct']:.1f}%**
- Total platform cost so far: **${a['cost_usd_total']:.4f}**

## Findings
**By severity:**
{_sev_line('CRITICAL')}
{_sev_line('HIGH')}
{_sev_line('MEDIUM')}
{_sev_line('LOW')}

**By status:**
{_status_line('OPEN')}
{_status_line('PENDING_APPROVAL')}
{_status_line('IN_PROGRESS')}
{_status_line('RESOLVED')}
{_status_line('WONT_FIX')}

**Top CRITICAL/HIGH:**
{high_findings_md}

## Verdict mix (all-time)
{verdict_md}

## Regression
- Runs to date: **{r['runs_total']}**
- Regressions detected: **{r['regressions_detected_total']}**

## Coverage by category
{coverage_md}

## Recommendations
{rec_md}

---
*This snapshot is auto-generated from `agentforge.services.summarizer`. The same numbers are available as JSON at `GET /api/v1/summary?format=json`.*
"""
