"""initial schema

Revision ID: 001_initial
Revises:
Create Date: 2026-05-11

Creates the 8 core tables (campaigns, attack_results, vulnerability_findings,
regression_cases, regression_runs, regression_results, api_keys, audit_log)
and installs the audit_log immutability trigger required by CLAUDE.md §8.4.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # pgcrypto provides gen_random_uuid()
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

    op.create_table(
        "campaigns",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("attack_category", sa.String(50), nullable=True),
        sa.Column("config", postgresql.JSONB, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_cost_usd", sa.Numeric(10, 4), nullable=True),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
    )
    op.create_index("ix_campaigns_status", "campaigns", ["status"])
    op.create_index("ix_campaigns_attack_category", "campaigns", ["attack_category"])

    op.create_table(
        "attack_results",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("attack_case_id", sa.String(50), nullable=True),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("subcategory", sa.String(100), nullable=True),
        sa.Column("prompt", sa.Text, nullable=False),
        sa.Column("response", sa.Text, nullable=False),
        sa.Column("verdict", sa.String(20), nullable=True),
        sa.Column("confidence", sa.Numeric(3, 2), nullable=True),
        sa.Column("mutation_generation", sa.Integer, nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Numeric(10, 4), nullable=True),
        sa.Column("latency_ms", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_attack_results_campaign_id", "attack_results", ["campaign_id"])
    op.create_index("ix_attack_results_category", "attack_results", ["category"])
    op.create_index("ix_attack_results_verdict", "attack_results", ["verdict"])
    op.create_index("ix_attack_results_attack_case_id", "attack_results", ["attack_case_id"])

    op.create_table(
        "vulnerability_findings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("vuln_id", sa.String(20), nullable=False, unique=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("cvss_score", sa.Numeric(3, 1), nullable=True),
        sa.Column(
            "attack_result_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("attack_results.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("report_markdown", sa.Text, nullable=True),
        sa.Column("report_json", postgresql.JSONB, nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_vulnerability_findings_vuln_id", "vulnerability_findings", ["vuln_id"])
    op.create_index("ix_vulnerability_findings_severity", "vulnerability_findings", ["severity"])
    op.create_index("ix_vulnerability_findings_status", "vulnerability_findings", ["status"])
    op.create_index("ix_vulnerability_findings_category", "vulnerability_findings", ["category"])

    op.create_table(
        "regression_cases",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerability_findings.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("attack_sequence", postgresql.JSONB, nullable=False),
        sa.Column("expected_safe_behavior", sa.Text, nullable=False),
        sa.Column("evaluation_rubric", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
    )
    op.create_index("ix_regression_cases_finding_id", "regression_cases", ["finding_id"])

    op.create_table(
        "regression_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("trigger", sa.String(20), nullable=False),
        sa.Column("target_url", sa.Text, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_cases", sa.Integer, nullable=True),
        sa.Column("pass_count", sa.Integer, nullable=True),
        sa.Column("fail_count", sa.Integer, nullable=True),
        sa.Column("regression_count", sa.Integer, nullable=True),
    )

    op.create_table(
        "regression_results",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("regression_runs.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("regression_cases.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("response", sa.Text, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_regression_results_run_id", "regression_results", ["run_id"])
    op.create_index("ix_regression_results_outcome", "regression_results", ["outcome"])

    op.create_table(
        "api_keys",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("key_hash", sa.String(255), nullable=False, unique=True),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"])

    op.create_table(
        "audit_log",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ip_address", postgresql.INET, nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_audit_log_actor", "audit_log", ["actor"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])

    # Immutability trigger — blocks UPDATE/DELETE on audit_log (CLAUDE.md §8.4).
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_modification()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Audit log is immutable - modification not permitted';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_immutable
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_immutable ON audit_log;")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_modification();")
    op.drop_table("audit_log")
    op.drop_table("api_keys")
    op.drop_table("regression_results")
    op.drop_table("regression_runs")
    op.drop_table("regression_cases")
    op.drop_table("vulnerability_findings")
    op.drop_table("attack_results")
    op.drop_table("campaigns")
