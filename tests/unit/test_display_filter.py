"""Regression tests for `filter_result_to_paths` path normalization.

Capability targets like `ails check memories` resolve to out-of-tree paths
(`~/.claude/...`). The result filter must normalize its key set the same way
finding paths are normalized, or every out-of-tree finding is dropped and the
command reports "No findings" despite real diagnostics.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem, normalize_finding_path
from reporails_cli.formatters.text.display import filter_result_to_paths
from reporails_cli.formatters.text.display_constants import get_group_atoms, per_file_stats


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


def _atom(file_path: str, charge: int, ambiguous: bool = False) -> SimpleNamespace:
    return SimpleNamespace(file_path=file_path, charge_value=charge, ambiguous=ambiguous)


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_per_file_stats_uses_passed_root_not_cwd(tmp_path: Path) -> None:
    """Stats header resolves atoms against the scan root, not `Path.cwd()`.

    Regression: a directory target (or `ails check <file>` from elsewhere) roots
    the scan away from cwd; keying atom lookup on cwd matched nothing and the
    per-file `N dir / N con` header rendered blank.
    """
    root = tmp_path / "proj"
    abs_file = root / "CLAUDE.md"
    rm = SimpleNamespace(atoms=[_atom(str(abs_file), 1), _atom(str(abs_file), -1), _atom(str(abs_file), 0, True)])

    out = per_file_stats("CLAUDE.md", rm, root)

    assert "1 dir" in out and "1 con" in out and "1 amb" in out, out


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_get_group_atoms_uses_passed_root_not_cwd(tmp_path: Path) -> None:
    """Group header atom rollup resolves against the scan root, not cwd."""
    root = tmp_path / "proj"
    abs_file = root / "CLAUDE.md"
    rm = SimpleNamespace(atoms=[_atom(str(abs_file), 1), _atom(str(abs_file), -1)])

    atoms = get_group_atoms("main", [("CLAUDE.md", [])], rm, root)

    assert len(atoms) == 2, "atoms under the scan root must match the group's files"
