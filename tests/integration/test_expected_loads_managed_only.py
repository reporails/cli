"""`ails expected-loads` under Claude Code's `managed-only` setting, run through the real `ails` binary."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

PLUGIN_ID = "cc-plugin-agents-md@builtin"
# Claude Code's machine-wide managed folders, which `expected-loads` reads whatever HOME is.
MANAGED_FOLDERS = ("/etc/claude-code", "/Library/Application Support/ClaudeCode", "C:/Program Files/ClaudeCode")


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
    for folder in MANAGED_FOLDERS:
        if Path(folder).exists():
            pytest.skip(f"managed Claude Code files at {folder} would be listed beside the isolated HOME's")
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


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_expected_loads_prunes_the_event_logs_it_names(tmp_path: Path) -> None:
    for folder in MANAGED_FOLDERS:
        if Path(folder).exists():
            pytest.skip(f"managed Claude Code files at {folder} would be listed beside the isolated HOME's")
    home = tmp_path / "home"
    project = tmp_path / "proj"
    _write(project / "CLAUDE.md")
    xray = home / ".reporails" / "xray"
    stale = xray / "old.1700000000000.0.jsonl"
    fresh = xray / "new.1700000000000.0.jsonl"
    _write(stale, "{}")
    _write(fresh, "{}")
    long_ago = time.time() - 40 * 86400
    os.utime(stale, (long_ago, long_ago))
    fresh.chmod(0o644)

    out = _expected_loads(project, home)

    assert out["event_log_dir"] == str(xray)
    assert [Path(i["path"]).name for i in out["files"]] == ["CLAUDE.md"]
    assert sorted(p.name for p in xray.iterdir()) == [fresh.name]
    assert stat.S_IMODE(fresh.stat().st_mode) == 0o600
    assert stat.S_IMODE(xray.stat().st_mode) == 0o700
