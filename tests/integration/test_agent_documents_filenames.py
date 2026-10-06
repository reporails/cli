"""Agent Documents Filenames (CORE:S:0012) reads the project's main instruction file.

The rule asks the file that introduces a project to its agents to name the instruction files they read.
A topical rule file (`.claude/rules/testing.md`) has no reason to list them; the rule targeted every rule
file before, so each topical rule was told to list instruction filenames.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_the_filenames_rule_reads_the_main_file_never_a_topical_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Project\n\nAlways run the tests before pushing.\n", encoding="utf-8")
    (project / ".claude" / "rules" / "testing.md").write_text(
        "# Testing\n\nRun the unit tests before every commit.\n", encoding="utf-8"
    )
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "-f", "json"])
    data = json.loads(result.output[result.output.index("{") :])
    fired = {path for path, record in data["files"].items() for f in record["findings"] if f["rule"] == "CORE:S:0012"}
    assert fired == {"CLAUDE.md"}
