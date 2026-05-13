"""Unit tests for the seed attack library."""

from __future__ import annotations

from agentforge.core.attack_library import SEED_ATTACKS, AttackLibrary
from agentforge.models.attack import AttackCategory


def test_minimum_18_seed_cases():
    assert len(SEED_ATTACKS) >= 18, f"expected >= 18 seed cases, got {len(SEED_ATTACKS)}"


def test_all_six_categories_have_at_least_three_cases():
    lib = AttackLibrary()
    for cat in AttackCategory:
        cases = lib.by_category(cat)
        assert len(cases) >= 3, f"{cat.value} has only {len(cases)} cases (need 3+)"


def test_attack_ids_unique():
    ids = [a.attack_id for a in SEED_ATTACKS]
    assert len(ids) == len(set(ids)), "attack_id collisions detected"


def test_lookup_by_id():
    lib = AttackLibrary()
    case = lib.by_id("PI-DIRECT-001")
    assert case is not None
    assert case.category == AttackCategory.PROMPT_INJECTION.value
    assert lib.by_id("nonexistent") is None


def test_every_case_has_rubric_indicators():
    for case in SEED_ATTACKS:
        assert case.success_indicators, f"{case.attack_id} missing success indicators"
        assert case.failure_indicators, f"{case.attack_id} missing failure indicators"
        assert case.expected_safe_behavior, f"{case.attack_id} missing expected_safe_behavior"


def test_indirect_injection_has_document_payload():
    lib = AttackLibrary()
    indirect = [a for a in lib.all if a.requires_document_upload]
    assert indirect, "expected at least one indirect-injection attack with document upload"
    for case in indirect:
        assert case.document_payload, f"{case.attack_id} marked requires_document_upload but has no payload"
        assert case.document_doc_type in {"lab_pdf", "intake_form"}
