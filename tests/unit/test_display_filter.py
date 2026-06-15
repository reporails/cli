"""Regression tests for `filter_result_to_paths` path normalization.

Capability targets like `ails check memories` resolve to out-of-tree paths
(`~/.claude/...`). The result filter must normalize its key set the same way
finding paths are normalized, or every out-of-tree finding is dropped and the
command reports "No findings" despite real diagnostics.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem, normalize_finding_path
from reporails_cli.formatters.text.display import filter_result_to_paths


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_out_of_tree_target_survives_filter(tmp_path: Path) -> None:
    """An out-of-tree (`~/.claude/...`) target keeps its findings through the filter."""
    home = Path.home()
    ext = home / ".claude" / "agent-memory" / "lead" / "note.md"
    finding = FindingItem(
        file=normalize_finding_path(str(ext), tmp_path),
        line=3,
        severity="warning",
        rule="CORE:C:0053",
        message="vague",
    )
    result = CombinedResult(findings=(finding,))

    filtered = filter_result_to_paths(result, {ext}, tmp_path)

    assert len(filtered.findings) == 1, "out-of-tree finding must survive the path filter"
    assert filtered.findings[0].rule == "CORE:C:0053"


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_in_tree_target_still_filters(tmp_path: Path) -> None:
    """In-tree filtering is unchanged: only findings for targeted paths survive."""
    keep = tmp_path / "CLAUDE.md"
    drop = tmp_path / "other.md"
    findings = (
        FindingItem(file=normalize_finding_path(str(keep), tmp_path), line=1, severity="error", rule="R1", message="m"),
        FindingItem(file=normalize_finding_path(str(drop), tmp_path), line=1, severity="error", rule="R2", message="m"),
    )
    result = CombinedResult(findings=findings)

    filtered = filter_result_to_paths(result, {keep}, tmp_path)

    rules = {f.rule for f in filtered.findings}
    assert rules == {"R1"}, "only the targeted in-tree file's findings survive"
