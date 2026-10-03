"""Mutation-closing tests for `formatters/json.py`."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.dto.models import Level, Severity, Violation
from reporails_cli.core.platform.dto.results import PendingSemantic, ValidationResult
from reporails_cli.formatters.json import _format_pending_semantic, format_score


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_format_pending_semantic_returns_dict_for_present_value() -> None:
    """A non-None PendingSemantic must format into its dict shape.

    Kills the `pending is None -> is not None` mutant: with `is not None` a
    present value would short-circuit to None instead of the dict (and a None
    value would fall through and crash).
    """
    pending = PendingSemantic(rule_count=2, file_count=1, rules=("CORE:C:0044", "CORE:C:0049"))
    assert _format_pending_semantic(pending) == {
        "rule_count": 2,
        "file_count": 1,
        "rules": ["CORE:C:0044", "CORE:C:0049"],
    }
    assert _format_pending_semantic(None) is None


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_format_score_flags_critical_violation() -> None:
    """`has_critical` must be True when a violation is critical severity.

    Kills the `severity.value == "critical" -> !=` mutant: with `!=`, an
    all-critical violation set reports no critical.
    """
    result = ValidationResult(
        score=0.0,
        level=Level.L0,
        violations=(
            Violation(
                rule_id="CORE:S:0001",
                rule_title="T",
                location="CLAUDE.md:1",
                message="m",
                severity=Severity.CRITICAL,
            ),
        ),
        judgment_requests=(),
        rules_checked=1,
        rules_passed=0,
        rules_failed=1,
        feature_summary="",
        friction=None,
    )
    out = format_score(result)
    assert out["has_critical"] is True
