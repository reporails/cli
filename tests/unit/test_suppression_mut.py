"""Mutation-closing tests for `core/lint/suppression.py` stats rebuild."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.suppression import apply_suppressions
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.runtime.merger import merge_results
from reporails_cli.formatters.text.display_constants import rule_aliases


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rebuilt_stats_count_each_severity_after_suppression(tmp_path: Path) -> None:
    """After a suppression removes a finding, the rebuilt per-severity counters
    must count each severity by its own label.

    Kills the `severity == "error" -> !=` and `severity == "info" -> !=`
    mutants: with `!=`, the error counter would count the non-errors (the kept
    info) and the info counter would count the non-infos (the kept errors), so
    a deliberately asymmetric mix reddens.
    """
    (tmp_path / "CLAUDE.md").write_text(
        "# Title\nDrop me.  <!-- ails-disable-line CORE:C:0049 -->\nc\nd\ne\nf\n",
        encoding="utf-8",
    )
    findings = [
        LocalFinding("CLAUDE.md", 2, "warning", "CORE:C:0049", "gone", source="client_check"),
        LocalFinding("CLAUDE.md", 4, "error", "CORE:C:0050", "kept", source="client_check"),
        LocalFinding("CLAUDE.md", 5, "error", "CORE:C:0051", "kept", source="client_check"),
        LocalFinding("CLAUDE.md", 6, "info", "CORE:C:0052", "kept", source="client_check"),
    ]
    result = merge_results([], findings, None, project_root=tmp_path)

    out = apply_suppressions(result, project_root=tmp_path, alias_fn=rule_aliases)

    assert out.stats.total_findings == 3
    assert out.stats.errors == 2
    assert out.stats.infos == 1
    assert out.stats.warnings == 0
