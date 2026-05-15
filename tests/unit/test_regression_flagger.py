"""Unit tests for the cross-category regression flagger logic.

We test the pure decision logic — the _detect_cross_category_regressions
method's category-comparison math — without a DB by stubbing the repository.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from agentforge.agents.regression import RegressionAgent
from agentforge.core.target_client import ClinicalCopilotClient


class _StubRepo:
    """Minimal stand-in for RegressionRepository covering only what the
    flagger calls."""

    def __init__(self, prev_run, prev_results, case_categories):
        self._prev_run = prev_run
        self._prev_results = prev_results
        self._case_categories = case_categories

    async def previous_completed_run(self, before_run_id):
        return self._prev_run

    async def results_for_run(self, run_id):
        return self._prev_results

    async def case_categories(self, case_ids):
        return self._case_categories


@pytest.fixture
def agent() -> RegressionAgent:
    # target_client is never used by _detect_cross_category_regressions
    return RegressionAgent(target_client=ClinicalCopilotClient())


@pytest.mark.asyncio
async def test_no_baseline_returns_empty(agent):
    repo = _StubRepo(prev_run=None, prev_results=[], case_categories={})
    flags = await agent._detect_cross_category_regressions(repo, uuid4(), [])
    assert flags == []


@pytest.mark.asyncio
async def test_flags_category_that_went_from_pass_to_fail(agent):
    case_a = uuid4()  # tool_misuse case
    prev_run = SimpleNamespace(id=uuid4())
    prev_results = [SimpleNamespace(case_id=case_a, outcome="PASS")]
    case_cats = {case_a: "tool_misuse"}
    repo = _StubRepo(prev_run, prev_results, case_cats)

    current = [{"case_id": str(case_a), "outcome": "FAIL"}]
    flags = await agent._detect_cross_category_regressions(repo, uuid4(), current)

    assert len(flags) == 1
    assert flags[0]["category"] == "tool_misuse"
    assert "FAIL" in flags[0]["current"]


@pytest.mark.asyncio
async def test_no_flag_when_category_was_already_failing(agent):
    case_a = uuid4()
    prev_run = SimpleNamespace(id=uuid4())
    prev_results = [SimpleNamespace(case_id=case_a, outcome="FAIL")]  # already broken
    repo = _StubRepo(prev_run, prev_results, {case_a: "tool_misuse"})

    current = [{"case_id": str(case_a), "outcome": "FAIL"}]
    flags = await agent._detect_cross_category_regressions(repo, uuid4(), current)
    # Was not "clean last run" — not a *new* cross-category regression.
    assert flags == []


@pytest.mark.asyncio
async def test_no_flag_when_category_still_passing(agent):
    case_a = uuid4()
    prev_run = SimpleNamespace(id=uuid4())
    prev_results = [SimpleNamespace(case_id=case_a, outcome="PASS")]
    repo = _StubRepo(prev_run, prev_results, {case_a: "tool_misuse"})

    current = [{"case_id": str(case_a), "outcome": "PASS"}]
    flags = await agent._detect_cross_category_regressions(repo, uuid4(), current)
    assert flags == []


@pytest.mark.asyncio
async def test_new_category_is_not_flagged(agent):
    """A category with no prior run history is new, not a regression."""
    case_new = uuid4()
    prev_run = SimpleNamespace(id=uuid4())
    prev_results = []  # nothing ran last time
    repo = _StubRepo(prev_run, prev_results, {case_new: "denial_of_service"})

    current = [{"case_id": str(case_new), "outcome": "FAIL"}]
    flags = await agent._detect_cross_category_regressions(repo, uuid4(), current)
    assert flags == []
