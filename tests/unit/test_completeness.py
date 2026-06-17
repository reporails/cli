"""Tests for the structural-completeness signal shipped to the scoring server.

Structural completeness (missing required sections / config / hygiene) is detected by
client-side rules and shipped as a per-path error-count map. The server folds it into
the delivery factor that scales the score; the CLI only produces the IP-safe map. These
tests cover that map: which findings count, and how they group by path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.mechanical.runner import run_mechanical_checks
from reporails_cli.core.lint.rule_runner import _to_display_severity
from reporails_cli.core.platform.adapters.registry import structural_rule_ids
from reporails_cli.core.platform.dto.models import (
    Category,
    Check,
    ClassifiedFile,
    FileMatch,
    Rule,
    RuleType,
    Severity,
)
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


class TestCodexOverLimitGap:
    """Lock the over-limit AGENTS.md -> per-path structural gap path (REQ-199 item 1).

    An over-limit Codex `AGENTS.md` chain must produce a `structural_gaps_by_path`
    entry on the main file's path, so the server's completeness term pulls the score
    down. This exercises the real chain: `aggregate_byte_size` fires -> violation on the
    main path -> display severity `error` -> gap map.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_codex_e_0001_is_in_structural_set(self) -> None:
        # The structural set must be resolved under the SAME agent the findings carry:
        # CODEX:E:0001 supersedes CORE:E:0001, so it only appears under the codex agent.
        # The no-agent (core-only) set would miss it and drop the over-limit finding.
        assert "CODEX:E:0001" in structural_rule_ids("codex")
        assert "CODEX:E:0001" not in structural_rule_ids("")

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_over_limit_chain_yields_gap_on_main_path(self, tmp_path: Path) -> None:
        agents = tmp_path / "AGENTS.md"
        agents.write_text("x" * 40_000)  # > 32 KiB Codex cap
        classified = [ClassifiedFile(path=agents, file_type="main", properties={"format": "freeform"})]
        rule = Rule(
            id="CODEX:E:0001",
            title="AGENTS.md Within Size Limit",
            category=Category.EFFICIENCY,
            type=RuleType.MECHANICAL,
            severity=Severity.HIGH,
            match=FileMatch(format="freeform"),
            checks=[
                Check(
                    id="CODEX.E.0001.check",
                    type="mechanical",
                    check="aggregate_byte_size",
                    args={"max": 32768},
                )
            ],
        )

        violations = run_mechanical_checks({"CODEX:E:0001": rule}, tmp_path, classified)
        assert len(violations) == 1

        findings = [
            FindingItem(
                file=v.location.rsplit(":", 1)[0],
                line=0,
                severity=_to_display_severity(v.severity.value),
                rule=v.rule_id,
                message=v.message,
            )
            for v in violations
        ]
        gaps = structural_gaps_by_path(findings, frozenset({"CODEX:E:0001"}))
        assert gaps == {"AGENTS.md": 1}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_within_limit_chain_yields_no_gap(self, tmp_path: Path) -> None:
        agents = tmp_path / "AGENTS.md"
        agents.write_text("x" * 1_000)  # well under the cap
        classified = [ClassifiedFile(path=agents, file_type="main", properties={"format": "freeform"})]
        rule = Rule(
            id="CODEX:E:0001",
            title="AGENTS.md Within Size Limit",
            category=Category.EFFICIENCY,
            type=RuleType.MECHANICAL,
            severity=Severity.HIGH,
            match=FileMatch(format="freeform"),
            checks=[
                Check(
                    id="CODEX.E.0001.check",
                    type="mechanical",
                    check="aggregate_byte_size",
                    args={"max": 32768},
                )
            ],
        )
        assert run_mechanical_checks({"CODEX:E:0001": rule}, tmp_path, classified) == []
