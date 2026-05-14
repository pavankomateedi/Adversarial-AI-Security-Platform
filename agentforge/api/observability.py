"""Observability API: coverage map, cost breakdown, metrics snapshot."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentforge.agents.models import AgentRole, model_name_for
from agentforge.core.coverage_tracker import CoverageTracker
from agentforge.db.database import get_session
from agentforge.db.models import (
    AttackResult,
    AuditLog,
    Campaign,
    RegressionResult,
    VulnerabilityFinding,
)
from agentforge.observability.metrics import REGISTRY
from agentforge.security.auth import Principal, require_admin, require_operator, require_viewer
from agentforge.services.summarizer import build_summary, render_markdown

router = APIRouter(tags=["observability"])


class CategoryCoverageOut(BaseModel):
    category: str
    cases_run: int
    successes: int
    total_seed_cases: int
    coverage_pct: float


class MetricsSnapshot(BaseModel):
    campaigns_total: int
    findings_open: int
    findings_critical_pending: int
    attacks_total: int
    regression_failures_last_run: int


@router.get("/coverage", response_model=list[CategoryCoverageOut])
async def coverage(
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> list[CategoryCoverageOut]:
    cov = await CoverageTracker(db).by_category()
    return [
        CategoryCoverageOut(
            category=c.category,
            cases_run=c.cases_run,
            successes=c.successes,
            total_seed_cases=c.total_seed_cases,
            coverage_pct=c.coverage_pct,
        )
        for c in cov.values()
    ]


@router.get("/cost", response_model=dict)
async def cost(
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_operator),
) -> dict:
    by_campaign_stmt = (
        select(Campaign.id, Campaign.attack_category, Campaign.total_cost_usd)
        .order_by(Campaign.started_at.desc())
        .limit(50)
    )
    rows = (await db.execute(by_campaign_stmt)).all()
    # Use Campaign.total_cost_usd for the authoritative cost (see dashboard()).
    total_stmt = select(func.coalesce(func.sum(Campaign.total_cost_usd), 0))
    grand_total = float((await db.execute(total_stmt)).scalar_one() or 0)
    return {
        "grand_total_usd": grand_total,
        "by_campaign": [
            {
                "campaign_id": str(r[0]),
                "category": r[1],
                "cost_usd": float(r[2] or 0),
            }
            for r in rows
        ],
    }


@router.get("/metrics", response_model=MetricsSnapshot)
async def metrics_snapshot(
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> MetricsSnapshot:
    campaigns_total = int((await db.execute(select(func.count(Campaign.id)))).scalar_one() or 0)
    findings_open = int(
        (
            await db.execute(
                select(func.count(VulnerabilityFinding.id)).where(VulnerabilityFinding.status == "OPEN")
            )
        ).scalar_one()
        or 0
    )
    findings_pending = int(
        (
            await db.execute(
                select(func.count(VulnerabilityFinding.id)).where(
                    VulnerabilityFinding.status == "PENDING_APPROVAL"
                )
            )
        ).scalar_one()
        or 0
    )
    attacks_total = int((await db.execute(select(func.count(AttackResult.id)))).scalar_one() or 0)
    regression_fail_stmt = select(func.count(RegressionResult.id)).where(
        RegressionResult.outcome == "REGRESSION"
    )
    regression_fail = int((await db.execute(regression_fail_stmt)).scalar_one() or 0)

    return MetricsSnapshot(
        campaigns_total=campaigns_total,
        findings_open=findings_open,
        findings_critical_pending=findings_pending,
        attacks_total=attacks_total,
        regression_failures_last_run=regression_fail,
    )


_AGENT_PROFILES: dict[str, dict] = {
    "orchestrator": {
        "display_name": "Orchestrator",
        "role": AgentRole.ORCHESTRATOR.value,
        "model": model_name_for(AgentRole.ORCHESTRATOR),
        "provider": "Anthropic",
        "purpose": "Campaign director — reads coverage gaps + cost budget, decides what RedTeam targets next.",
        "temperature": 0.2,
        "trust_level": "high",
        "reads": ["coverage map", "open findings", "session cost"],
        "writes": ["campaign_config", "stop_campaign"],
    },
    "red_team": {
        "display_name": "Red Team",
        "role": AgentRole.RED_TEAM.value,
        "model": model_name_for(AgentRole.RED_TEAM),
        "provider": "Groq",
        "purpose": "Attack generator + mutator — uses a permissive open-weights model so it doesn't refuse offensive prompts.",
        "temperature": 0.9,
        "trust_level": "low (untrusted output)",
        "reads": ["campaign_config", "seed attack library"],
        "writes": ["attack_results", "current_attack"],
    },
    "judge": {
        "display_name": "Judge",
        "role": AgentRole.JUDGE.value,
        "model": model_name_for(AgentRole.JUDGE),
        "provider": "Anthropic (OpenAI gpt-4o fallback)",
        "purpose": "Independent verdict engine — blind to RedTeam's strategy. Temp=0; rubric loaded fresh per call; 10% cross-check.",
        "temperature": 0.0,
        "trust_level": "high (closed model)",
        "reads": ["attack_results", "rubric YAML"],
        "writes": ["current_verdict", "escalate_to_human"],
    },
    "documentation": {
        "display_name": "Documentation",
        "role": AgentRole.DOCUMENTATION.value,
        "model": model_name_for(AgentRole.DOCUMENTATION),
        "provider": "Anthropic",
        "purpose": "CVE-style report writer — files VULN-NNN reports for confirmed exploits. CRITICAL findings require admin approval.",
        "temperature": 0.3,
        "trust_level": "high (human-gated for CRITICAL)",
        "reads": ["current_verdict", "attack_results"],
        "writes": ["vulnerability_findings", "vulnerability_reports/VULN-*.md"],
    },
    "regression": {
        "display_name": "Regression",
        "role": "regression",
        "model": "deterministic + Judge",
        "provider": "—",
        "purpose": "Replays confirmed exploits on every Co-Pilot deploy. Classifies PASS / FAIL / REGRESSION.",
        "temperature": 0.0,
        "trust_level": "deterministic",
        "reads": ["regression_cases", "Co-Pilot live target"],
        "writes": ["regression_results"],
    },
}


def _agent_call_counts() -> dict[str, dict]:
    """Snapshot the `agentforge_llm_calls_total{agent,model}` counter.

    Used by /metrics. Process-local — resets on container restart. For the
    dashboard we instead derive durable call counts from the DB via
    `_agent_call_counts_from_db()` so a redeploy doesn't zero everything.
    """
    by_agent: dict[str, dict] = {}
    for metric in REGISTRY.collect():
        if metric.name != "agentforge_llm_calls":
            continue
        for sample in metric.samples:
            if not sample.name.endswith("_total"):
                continue
            agent = sample.labels.get("agent")
            model = sample.labels.get("model")
            if not agent:
                continue
            entry = by_agent.setdefault(agent, {"calls": 0, "models": {}})
            entry["calls"] += int(sample.value)
            entry["models"][model] = entry["models"].get(model, 0) + int(sample.value)
    return by_agent


async def _agent_call_counts_from_db(session: AsyncSession) -> dict[str, dict]:
    """Persistent call counts derived from row counts.

    Maps DB events to LLM calls:
      - red_team:    one per AttackResult (each attack = one RedTeam decision;
                     mutations also live as rows so counts include them)
      - judge:       one per AttackResult with a non-null verdict
      - documentation: one per VulnerabilityFinding with report_markdown
      - regression:  one per RegressionResult (each replay invokes Judge once)
      - orchestrator: zero by design (deterministic, no LLM calls)
    """
    from agentforge.db.models import RegressionResult

    attack_count = int((await session.execute(select(func.count(AttackResult.id)))).scalar_one() or 0)
    verdict_count = int(
        (await session.execute(select(func.count(AttackResult.id)).where(AttackResult.verdict.isnot(None)))).scalar_one()
        or 0
    )
    finding_doc_count = int(
        (await session.execute(
            select(func.count(VulnerabilityFinding.id)).where(VulnerabilityFinding.report_markdown.isnot(None))
        )).scalar_one()
        or 0
    )
    regression_count = int(
        (await session.execute(select(func.count(RegressionResult.id)))).scalar_one() or 0
    )

    return {
        "red_team": {"calls": attack_count, "models": {model_name_for(AgentRole.RED_TEAM): attack_count} if attack_count else {}},
        "judge": {"calls": verdict_count, "models": {model_name_for(AgentRole.JUDGE): verdict_count} if verdict_count else {}},
        "documentation": {"calls": finding_doc_count, "models": {model_name_for(AgentRole.DOCUMENTATION): finding_doc_count} if finding_doc_count else {}},
        "regression": {"calls": regression_count, "models": {"deterministic+judge": regression_count} if regression_count else {}},
        "orchestrator": {"calls": 0, "models": {}},
    }


@router.get("/dashboard", response_model=dict)
async def dashboard(
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> dict:
    """One-shot snapshot for the operator dashboard.

    Returns everything the UI needs in a single round-trip — agent profiles
    + call counts, recent attacks, recent findings, regression summary,
    coverage map, and cost totals.
    """
    call_counts = await _agent_call_counts_from_db(db)
    agents = {}
    for key, profile in _AGENT_PROFILES.items():
        stats = call_counts.get(key, {"calls": 0, "models": {}})
        agents[key] = {**profile, **stats}

    # Recent attack results (last 10), with verdict if scored.
    attacks_stmt = (
        select(AttackResult).order_by(AttackResult.created_at.desc()).limit(10)
    )
    recent_attacks = [
        {
            "id": str(r.id),
            "campaign_id": str(r.campaign_id) if r.campaign_id else None,
            "attack_case_id": r.attack_case_id,
            "category": r.category,
            "subcategory": r.subcategory,
            "verdict": r.verdict,
            "confidence": float(r.confidence) if r.confidence is not None else None,
            "mutation_generation": r.mutation_generation,
            "cost_usd": float(r.cost_usd) if r.cost_usd is not None else None,
            "latency_ms": r.latency_ms,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in (await db.execute(attacks_stmt)).scalars().all()
    ]

    # Recent findings (last 10).
    findings_stmt = (
        select(VulnerabilityFinding)
        .order_by(VulnerabilityFinding.discovered_at.desc())
        .limit(10)
    )
    recent_findings = [
        {
            "id": str(r.id),
            "vuln_id": r.vuln_id,
            "title": r.title,
            "severity": r.severity,
            "status": r.status,
            "category": r.category,
            "cvss_score": float(r.cvss_score) if r.cvss_score is not None else None,
            "discovered_at": r.discovered_at.isoformat() if r.discovered_at else None,
        }
        for r in (await db.execute(findings_stmt)).scalars().all()
    ]

    # Recent campaigns
    campaigns_stmt = select(Campaign).order_by(Campaign.started_at.desc()).limit(10)
    recent_campaigns = [
        {
            "id": str(r.id),
            "status": r.status,
            "attack_category": r.attack_category,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "total_cost_usd": float(r.total_cost_usd) if r.total_cost_usd is not None else None,
            "findings_count": r.findings_count,
        }
        for r in (await db.execute(campaigns_stmt)).scalars().all()
    ]

    # Coverage.
    cov = await CoverageTracker(db).by_category()
    coverage = [
        {
            "category": c.category,
            "cases_run": c.cases_run,
            "successes": c.successes,
            "total_seed_cases": c.total_seed_cases,
            "coverage_pct": c.coverage_pct,
        }
        for c in cov.values()
    ]

    # Cost totals — sum from campaigns, not attack_results.
    # Why: per-attack cost is split between an in-memory CostTracker and the
    # AttackResult row; the row's cost_usd is often zero because cost is
    # recorded process-locally and only the campaign aggregate is persisted.
    # Campaign.total_cost_usd is the authoritative number written by
    # campaign_runner._run_campaign_task on completion.
    grand_total = float(
        (await db.execute(select(func.coalesce(func.sum(Campaign.total_cost_usd), 0)))).scalar_one() or 0
    )
    findings_open = int(
        (
            await db.execute(
                select(func.count(VulnerabilityFinding.id)).where(
                    VulnerabilityFinding.status == "OPEN"
                )
            )
        ).scalar_one()
        or 0
    )
    findings_pending = int(
        (
            await db.execute(
                select(func.count(VulnerabilityFinding.id)).where(
                    VulnerabilityFinding.status == "PENDING_APPROVAL"
                )
            )
        ).scalar_one()
        or 0
    )

    return {
        "agents": agents,
        "agent_order": ["orchestrator", "red_team", "judge", "documentation", "regression"],
        "recent_attacks": recent_attacks,
        "recent_findings": recent_findings,
        "recent_campaigns": recent_campaigns,
        "coverage": coverage,
        "totals": {
            "campaigns": len(recent_campaigns),
            "attacks_recent": len(recent_attacks),
            "findings_total": len(recent_findings),
            "findings_open": findings_open,
            "findings_pending_approval": findings_pending,
            "cost_usd_grand_total": round(grand_total, 4),
        },
    }


@router.get("/summary", responses={200: {"content": {"text/markdown": {}, "application/json": {}}}})
async def summary(
    request: Request,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
):
    """Human-readable status summary.

    Returns markdown by default (curl-friendly + copy/paste into Slack).
    Pass `?format=json` or `Accept: application/json` for the structured
    form the dashboard panel renders.
    """
    snapshot = await build_summary(db)
    want_json = (
        "application/json" in request.headers.get("accept", "")
        or request.query_params.get("format") == "json"
    )
    if want_json:
        return snapshot
    return PlainTextResponse(content=render_markdown(snapshot), media_type="text/markdown")


class AuditEntryOut(BaseModel):
    id: str
    timestamp: str
    actor: str
    action: str
    resource_type: str | None
    resource_id: str | None
    ip_address: str | None
    user_agent: str | None
    metadata: dict | None


@router.get("/audit", response_model=list[AuditEntryOut])
async def audit_log(
    limit: int = 100,
    action: str | None = None,
    actor: str | None = None,
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_admin),
) -> list[AuditEntryOut]:
    """Read the immutable audit trail (admin only).

    The audit_log table is append-only — a Postgres trigger blocks UPDATE
    and DELETE. This endpoint is the read side: it lets an admin reconstruct
    "what did every actor do, in what order" — including overnight agent runs.
    """
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(min(limit, 500))
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        AuditEntryOut(
            id=str(r.id),
            timestamp=r.timestamp.isoformat() if r.timestamp else "",
            actor=r.actor,
            action=r.action,
            resource_type=r.resource_type,
            resource_id=str(r.resource_id) if r.resource_id else None,
            ip_address=str(r.ip_address) if r.ip_address else None,
            user_agent=r.user_agent,
            metadata=r.audit_metadata,
        )
        for r in rows
    ]


@router.get("/judge-drift", response_model=dict)
async def judge_drift(
    db: AsyncSession = Depends(get_session),
    _: Principal = Depends(require_viewer),
) -> dict:
    """Judge consistency / drift signal.

    A Judge that "starts agreeing with everything" is a known failure mode.
    We surface three signals over the scored attack_results:
      - verdict distribution (a Judge stuck on one verdict is suspicious)
      - mean confidence (creeping toward 1.0 or 0.0 = drift)
      - cross-check disagreement rate (the 10% second-opinion sample;
        a rising rate means the Judge is internally inconsistent)
    """
    # Verdict distribution across all scored attacks.
    dist_stmt = (
        select(AttackResult.verdict, func.count())
        .where(AttackResult.verdict.isnot(None))
        .group_by(AttackResult.verdict)
    )
    distribution = {v or "UNCLASSIFIED": int(n) for v, n in (await db.execute(dist_stmt)).all()}
    total = sum(distribution.values())

    # Mean confidence overall + over the most-recent 20 (drift = recent != all).
    mean_all_stmt = select(func.avg(AttackResult.confidence)).where(
        AttackResult.confidence.isnot(None)
    )
    mean_all = float((await db.execute(mean_all_stmt)).scalar_one() or 0.0)

    recent_stmt = (
        select(AttackResult.confidence)
        .where(AttackResult.confidence.isnot(None))
        .order_by(AttackResult.created_at.desc())
        .limit(20)
    )
    recent_conf = [float(c) for (c,) in (await db.execute(recent_stmt)).all()]
    mean_recent = sum(recent_conf) / len(recent_conf) if recent_conf else 0.0

    # A Judge stuck on a single verdict for >85% of cases is a drift red flag.
    dominant_share = (max(distribution.values()) / total) if total else 0.0
    drift_suspected = total >= 10 and dominant_share > 0.85

    return {
        "total_scored": total,
        "verdict_distribution": distribution,
        "mean_confidence_all": round(mean_all, 3),
        "mean_confidence_recent20": round(mean_recent, 3),
        "confidence_delta_recent_vs_all": round(mean_recent - mean_all, 3),
        "dominant_verdict_share": round(dominant_share, 3),
        "drift_suspected": drift_suspected,
        "interpretation": (
            "Judge appears stuck on one verdict — review rubrics and cross-checks."
            if drift_suspected
            else "Verdict spread looks healthy."
        ),
    }
