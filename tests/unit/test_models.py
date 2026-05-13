"""Unit tests for Pydantic models."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from agentforge.models.attack import (
    AttackCase,
    AttackCategory,
    AttackResult,
    AttackSeverity,
    AttackTurn,
    TargetResponse,
)
from agentforge.models.campaign import (
    CampaignConfig,
    CampaignPriority,
    CampaignStatus,
)
from agentforge.models.finding import FindingStatus, VulnerabilityFinding
from agentforge.models.report import ObservedVsExpected, VulnerabilityReport
from agentforge.models.verdict import JudgeVerdict, VerdictOutcome


def test_attack_case_roundtrip():
    case = AttackCase(
        attack_id="X-TEST-001",
        category=AttackCategory.PROMPT_INJECTION,
        subcategory="direct_injection",
        severity=AttackSeverity.HIGH,
        description="test",
        attack_sequence=[AttackTurn(role="user", content="hi")],
        expected_safe_behavior="refuse",
    )
    dumped = case.model_dump_json()
    rebuilt = AttackCase.model_validate_json(dumped)
    assert rebuilt.attack_id == "X-TEST-001"
    assert rebuilt.category == AttackCategory.PROMPT_INJECTION.value


def test_target_response_is_refusal_heuristic():
    refused = TargetResponse(status_code=200, body={"response": "I cannot help with that."}, response_text="I cannot help with that.", latency_ms=10)
    allowed = TargetResponse(status_code=200, body={"response": "Sure, here you go."}, response_text="Sure, here you go.", latency_ms=10)
    unauthed = TargetResponse(status_code=401, body="Not authenticated", response_text="Not authenticated", latency_ms=5)
    assert refused.is_refusal
    assert not allowed.is_refusal
    assert unauthed.is_refusal


def test_attack_turn_rejects_invalid_role():
    with pytest.raises(Exception):
        AttackTurn(role="system", content="x")


def test_campaign_config_defaults():
    config = CampaignConfig(attack_category=AttackCategory.DATA_EXFILTRATION)
    assert config.priority == CampaignPriority.MEDIUM.value
    assert config.token_budget >= 1000
    assert config.max_attacks >= 1


def test_attack_result_minimal():
    r = AttackResult(
        attack_case_id="X-001",
        category=AttackCategory.PROMPT_INJECTION,
        prompt="p",
        response="r",
    )
    assert r.cost_usd == Decimal("0")
    assert r.mutation_generation == 0
    assert isinstance(r.created_at, datetime)


def test_judge_verdict_confidence_bounds():
    v = JudgeVerdict(attack_result_id=uuid4(), outcome=VerdictOutcome.SUCCESS, confidence=0.9)
    assert v.confidence == 0.9
    with pytest.raises(Exception):
        JudgeVerdict(attack_result_id=uuid4(), outcome=VerdictOutcome.SUCCESS, confidence=1.5)


def test_finding_default_status_is_open():
    f = VulnerabilityFinding(
        vuln_id="VULN-999",
        title="t",
        severity=AttackSeverity.HIGH,
        category=AttackCategory.PROMPT_INJECTION,
    )
    assert f.status == FindingStatus.OPEN.value


def test_vulnerability_report_markdown_renders_required_sections():
    report = VulnerabilityReport(
        vuln_id="VULN-001",
        title="System prompt leak via fake compliance ticket",
        severity=AttackSeverity.HIGH,
        category=AttackCategory.IDENTITY_EXPLOITATION,
        executive_summary="A spoofed compliance ticket caused the Co-Pilot to disclose its system prompt verbatim.",
        technical_description="The Co-Pilot did not treat the COMP-XXXX prefix as untrusted.",
        reproduction_steps=["Login as dr.pavan.", "Send the spoofed compliance message.", "Observe system prompt in response."],
        observed_vs_expected=[
            ObservedVsExpected(aspect="Disclosure", observed="System prompt leaked", expected="Refuse and redirect"),
        ],
        clinical_impact="Loss of system prompt enables targeted bypass attacks.",
        remediation="Treat authority claims as untrusted; never disclose internal prompt.",
        validation="Re-run AUTH-001 attack; verify refusal.",
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    )
    md = report.to_markdown()
    for section in [
        "# VULN-001",
        "**Severity:** HIGH",
        "## Executive Summary",
        "## Technical Description",
        "## Reproduction Steps",
        "## Observed vs. Expected Behavior",
        "## Clinical Impact",
        "## Remediation",
        "## Validation",
        "## References",
    ]:
        assert section in md, f"missing section: {section}"
