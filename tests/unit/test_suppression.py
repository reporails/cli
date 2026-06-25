"""Tests for core/lint/suppression.py — inline per-line finding suppression."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.suppression import (
    apply_suppressions,
    build_index,
    parse_directives,
)
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.runtime.merger import merge_results
from reporails_cli.formatters.text.display_constants import rule_aliases


class TestParseDirectives:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_same_line_html_comment(self) -> None:
        text = "Do the thing.  <!-- ails-disable-line CORE:C:0049 -->\n"
        assert parse_directives(text) == {1: {"CORE:C:0049"}}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_multiple_rules_space_and_comma(self) -> None:
        text = "x\ny  <!-- ails-disable-line CORE:C:0049, CORE:C:0046 -->\n"
        assert parse_directives(text) == {2: {"CORE:C:0049", "CORE:C:0046"}}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_slug_token_accepted(self) -> None:
        text = "y  <!-- ails-disable-line italic-constraints -->\n"
        assert parse_directives(text) == {1: {"italic-constraints"}}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_bare_directive_names_nothing(self) -> None:
        # No rule named → targeted-only contract: suppress nothing.
        assert parse_directives("y  <!-- ails-disable-line -->\n") == {}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_directive(self) -> None:
        assert parse_directives("just prose\nmore prose\n") == {}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    # Line 2: directive for CORE:C:0049. Line 4: same rule, no directive.
    (tmp_path / "CLAUDE.md").write_text(
        "# Title\nDescribe behavior.  <!-- ails-disable-line CORE:C:0049 -->\nspacer\nAnother ambiguous instruction.\n",
        encoding="utf-8",
    )
    return tmp_path


def _result(project: Path):
    findings = [
        LocalFinding("CLAUDE.md", 2, "warning", "CORE:C:0049", "ambiguous", source="client_check"),
        LocalFinding("CLAUDE.md", 4, "warning", "CORE:C:0049", "ambiguous", source="client_check"),
    ]
    return merge_results([], findings, None, project_root=project)


class TestApplySuppressions:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_suppressed_line_silent_sibling_still_fires(self, project: Path) -> None:
        result = _result(project)
        assert len(result.findings) == 2

        out = apply_suppressions(result, project_root=project, alias_fn=rule_aliases)

        # Both directions: the annotated line is gone, the un-annotated sibling stays.
        lines = sorted(f.line for f in out.findings)
        assert lines == [4]
        assert out.stats.total_findings == 1
        assert out.stats.warnings == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unnamed_rule_on_line_does_not_suppress(self, project: Path) -> None:
        # Directive names CORE:C:0049 only; a different rule on the same line still fires.
        findings = [
            LocalFinding("CLAUDE.md", 2, "warning", "CORE:C:0046", "conflict", source="client_check"),
        ]
        result = merge_results([], findings, None, project_root=project)
        out = apply_suppressions(result, project_root=project, alias_fn=rule_aliases)
        assert len(out.findings) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_canonical_id_directive_matches_client_token(self, tmp_path: Path) -> None:
        # Author copies the displayed canonical ID; finding carries the raw client token.
        (tmp_path / "CLAUDE.md").write_text(
            "constraint first  <!-- ails-disable-line CORE:D:0003 -->\n", encoding="utf-8"
        )
        findings = [LocalFinding("CLAUDE.md", 1, "warning", "ordering", "order", source="client_check")]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_suppressions(result, project_root=tmp_path, alias_fn=rule_aliases)
        assert out.findings == ()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_directive_file_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("plain prose\n", encoding="utf-8")
        findings = [LocalFinding("CLAUDE.md", 1, "warning", "CORE:C:0049", "x", source="client_check")]
        result = merge_results([], findings, None, project_root=tmp_path)
        out = apply_suppressions(result, project_root=tmp_path, alias_fn=rule_aliases)
        assert out is result

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_default_alias_is_exact_rule_token(self, project: Path) -> None:
        # Without an alias_fn only the exact raw token matches.
        result = _result(project)
        out = apply_suppressions(result, project_root=project)
        assert sorted(f.line for f in out.findings) == [4]


class TestBuildIndex:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_missing_file_skipped(self, tmp_path: Path) -> None:
        assert build_index(["does-not-exist.md"], tmp_path) == {}
