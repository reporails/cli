"""Tests for the structural-completeness signal shipped to the scoring server.

Structural completeness (missing required sections / config / hygiene) is detected by
client-side rules and shipped as a per-path error-count map. The server folds it into
the delivery factor that scales the score; the CLI only produces the IP-safe map. These
tests cover that map: which findings count, and how they group by path.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.policy.completeness import structural_gaps_by_path
from reporails_cli.core.platform.runtime.merger import FindingItem

_STRUCTURAL = frozenset({"CORE:C:0034", "CORE:S:0007"})


def _finding(rule: str, severity: str = "error", file: str = "a.md") -> FindingItem:
    return FindingItem(file=file, line=1, severity=severity, rule=rule, message="m")


class TestStructuralGapsByPath:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_groups_errors_by_path(self) -> None:
        findings = [
            _finding("CORE:C:0034", "error", file="a.md"),
            _finding("CORE:S:0007", "error", file="a.md"),
            _finding("CORE:C:0034", "error", file="b.md"),
            _finding("CORE:C:0034", "warning", file="a.md"),  # warning excluded
            _finding("CORE:C:0042", "error", file="a.md"),  # non-structural excluded
        ]
        assert structural_gaps_by_path(findings, _STRUCTURAL) == {"a.md": 2, "b.md": 1}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_warning_in_family_does_not_count(self) -> None:
        # Optional-section misses are warnings — they are not hard gaps.
        assert structural_gaps_by_path([_finding("CORE:C:0034", "warning")], _STRUCTURAL) == {}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_error_outside_family_does_not_count(self) -> None:
        # A compliance (theory) rule error is not a structural gap.
        assert structural_gaps_by_path([_finding("CORE:C:0042", "error")], _STRUCTURAL) == {}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_empty_id_set_is_empty(self) -> None:
        assert structural_gaps_by_path([_finding("CORE:C:0034", "error")], frozenset()) == {}
