"""End-to-end coverage for `ails check <single-file>` discovery scope.

Bug 1 (0.5.11): `ails check <file>` was enumerating user-scope
`~/.claude/CLAUDE.md` even when the operator named one explicit project
file. The display surfaced findings from a file the operator hadn't
asked about; per-file count and summary count failed to reconcile.

The fix narrows the display to `{target.resolve()}` when arg1 is an
existing file path (not capability mode), reusing the existing
`filter_result_to_paths` machinery.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_single_file_target_does_not_surface_user_scope(tmp_path: Path) -> None:
    """`ails check <project-CLAUDE.md>` filters out user-scope `~/.claude/CLAUDE.md`."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Project\n\nA minimal CLAUDE.md.\n", encoding="utf-8")

    target = project / "CLAUDE.md"
    result = runner.invoke(app, ["check", str(target), "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    # capability_paths echo back the narrowed display set.
    paths = data.get("capability_paths", [])
    assert len(paths) == 1
    assert paths[0].endswith("CLAUDE.md")

    # No finding may reference a `~/...`-prefixed (user-scope) file.
    files = data.get("files", {})
    for key in files:
        assert not key.startswith("~/"), f"User-scope file leaked into display: {key}"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_single_file_target_reconciles_summary_and_panel_counts(tmp_path: Path) -> None:
    """Total findings count equals the per-file finding count for the single target."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Project\n\nA minimal CLAUDE.md.\n", encoding="utf-8")

    target = project / "CLAUDE.md"
    result = runner.invoke(app, ["check", str(target), "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    summary_total = int(data.get("stats", {}).get("total_findings", 0))
    per_file_total = sum(len(v.get("findings", [])) for v in data.get("files", {}).values())
    assert summary_total == per_file_total
