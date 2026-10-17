"""`ails expected-loads` under Claude Code's `managed-only` setting, run through the real `ails` binary."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

PLUGIN_ID = "cc-plugin-agents-md@builtin"


def _write(path: Path, text: str = "# Notes\n\nRun the tests.\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _expected_loads(project: Path, home: Path) -> dict:
    ails = shutil.which("ails")
    assert ails is not None, "the `ails` binary is not on PATH"
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "NO_COLOR": "1"}
    proc = subprocess.run(
        [ails, "expected-loads", str(project), "--agent", "claude"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_managed_only_leaves_out_launch_files_and_keeps_on_demand_ones(tmp_path: Path) -> None:
    home = tmp_path / "home"
    project = tmp_path / "proj"
    _write(
        home / ".claude" / "settings.json",
        json.dumps({"pluginConfigs": {PLUGIN_ID: {"options": {"instructionFiles": "managed-only"}}}}),
    )
    _write(home / ".claude" / "rules" / "pref.md")
    _write(home / ".claude" / "CLAUDE.md", "")
    _write(project / "CLAUDE.md")
    _write(project / ".claude" / "rules" / "style.md")
    _write(project / "sub" / "CLAUDE.md")
    _write(project / "sub" / ".claude" / "rules" / "x.md")

    out = _expected_loads(project, home)

    skipped = {Path(i["path"]): i for i in out["skipped"]}
    for path in (
        project / "CLAUDE.md",
        project / ".claude" / "rules" / "style.md",
        home / ".claude" / "rules" / "pref.md",
    ):
        assert skipped[path]["reason"] == "setting_off", path
        assert skipped[path]["setting"] == "managed-only", path
    loaded = {Path(i["path"]): i for i in out["files"]}
    assert {p: i["loading"] for p, i in loaded.items()} == {
        project / "sub" / "CLAUDE.md": "on_demand",
        project / "sub" / ".claude" / "rules" / "x.md": "on_demand",
    }
    assert home / ".claude" / "CLAUDE.md" not in skipped
    assert home / ".claude" / "CLAUDE.md" not in loaded
