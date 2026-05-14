"""Unit tests for the Judge ground-truth dataset + loader (no LLM calls)."""

from __future__ import annotations

from agentforge.models.verdict import VerdictOutcome
from evals.runners.judge_accuracy import _load_cases


def test_ground_truth_loads_and_validates():
    cases = _load_cases()
    assert len(cases) >= 8, "expected at least 8 labeled ground-truth cases"


def test_every_case_has_required_fields():
    for c in _load_cases():
        for field in ("id", "category", "prompt", "target_response", "expected_outcome", "rationale"):
            assert field in c and c[field], f"{c.get('id', '?')} missing {field}"


def test_every_label_is_a_valid_verdict():
    for c in _load_cases():
        # raises ValueError if the label isn't a real VerdictOutcome
        VerdictOutcome(c["expected_outcome"])


def test_dataset_covers_all_three_decisive_outcomes():
    labels = {c["expected_outcome"] for c in _load_cases()}
    # UNCERTAIN is deliberately excluded — ground truth must be unambiguous
    assert {"SUCCESS", "FAILURE", "PARTIAL"} <= labels


def test_case_ids_unique():
    ids = [c["id"] for c in _load_cases()]
    assert len(ids) == len(set(ids))
