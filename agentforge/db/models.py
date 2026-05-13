"""SQLAlchemy ORM models mirroring ARCHITECTURE.md Section 'Database Schema'."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Boolean, Integer, Numeric

from agentforge.db.base import Base, timestamp_now, timestamp_opt, uuid_pk


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[uuid_pk]
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    attack_category: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    started_at: Mapped[timestamp_now]
    completed_at: Mapped[timestamp_opt]
    total_cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 4), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")

    attack_results: Mapped[list[AttackResult]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )


class AttackResult(Base):
    __tablename__ = "attack_results"

    id: Mapped[uuid_pk]
    campaign_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=True, index=True
    )
    attack_case_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    subcategory: Mapped[str | None] = mapped_column(String(100), nullable=True)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    response: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(3, 2), nullable=True)
    mutation_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 4), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[timestamp_now]

    campaign: Mapped[Campaign | None] = relationship(back_populates="attack_results")


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"

    id: Mapped[uuid_pk]
    vuln_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1), nullable=True)
    attack_result_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("attack_results.id", ondelete="SET NULL"), nullable=True
    )
    report_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    discovered_at: Mapped[timestamp_now]
    resolved_at: Mapped[timestamp_opt]
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[timestamp_opt]


class RegressionCase(Base):
    __tablename__ = "regression_cases"

    id: Mapped[uuid_pk]
    finding_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("vulnerability_findings.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    attack_sequence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    expected_safe_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    evaluation_rubric: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[timestamp_now]
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")


class RegressionRun(Base):
    __tablename__ = "regression_runs"

    id: Mapped[uuid_pk]
    trigger: Mapped[str] = mapped_column(String(20), nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[timestamp_now]
    completed_at: Mapped[timestamp_opt]
    total_cases: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pass_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fail_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    regression_count: Mapped[int | None] = mapped_column(Integer, nullable=True)


class RegressionResult(Base):
    __tablename__ = "regression_results"

    id: Mapped[uuid_pk]
    run_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("regression_runs.id", ondelete="CASCADE"), nullable=True, index=True
    )
    case_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("regression_cases.id", ondelete="SET NULL"), nullable=True
    )
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[timestamp_now]


class ApiKey(Base):
    """Hashed API key + RBAC role for platform users.

    Why: CLAUDE.md §8.1 requires bcrypt-hashed keys in DB (never plaintext).
    Stored separately from the immutable audit log so keys can be rotated.
    """

    __tablename__ = "api_keys"

    id: Mapped[uuid_pk]
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # viewer | operator | admin
    created_at: Mapped[timestamp_now]
    last_used_at: Mapped[timestamp_opt]
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")


class AuditLog(Base):
    """Append-only audit trail. UPDATE/DELETE blocked by DB trigger."""

    __tablename__ = "audit_log"

    id: Mapped[uuid_pk]
    timestamp: Mapped[timestamp_now]
    actor: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Reserved word in SQL — store under DB column "metadata" but expose as audit_metadata
    audit_metadata: Mapped[dict | None] = mapped_column("metadata", JSONB, nullable=True)
