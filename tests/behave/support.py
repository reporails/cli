"""Shared behave support — build a real project on disk and drive the real `ails` CLI.

Every behavioral feature builds a tmp project (a git repo with instruction files)
and shells out to the actual `ails` console script the user/harness invokes. These
helpers are the single foundation so each feature's steps stay thin and consistent.

The top of the test pyramid: nothing here runs the CLI in-process (no `CliRunner`) —
every assertion is against the real binary's stdout / exit code / persisted state.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

# The real console script (`[project.scripts] ails = …:app`), installed in the
# venv `uv run behave` runs in. None when not installed — a step asserts on it so
# a missing binary fails loudly, never passes vacuously.
AILS_BIN = shutil.which("ails")


def build_project(root: Path) -> Path:
    """Create a real git project under ``root`` and return its path.

    A git repo so `ails check` does not emit the `Not a git repository` governance
    finding as noise; steps layer the instruction files (a `CLAUDE.md`) on top.
    """
    project = root / "project"
    project.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.email", "behave@ails"], cwd=project, check=True)
    subprocess.run(["git", "config", "user.name", "behave"], cwd=project, check=True)
    return project


def write_claude(project: Path, content: str) -> Path:
    """Write ``content`` to ``project/CLAUDE.md`` (the instruction file under test)."""
    target = project / "CLAUDE.md"
    target.write_text(content, encoding="utf-8")
    return target


def run_ails(project: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run ``ails <args>`` with ``project`` as cwd; return the CompletedProcess.

    Runs from the project dir with no target so `ails` scans the whole project —
    the way a user invokes it in their repo. Forces a wide, color-free render so
    literal token assertions are not split by ANSI styling or column wrapping.
    Does NOT assert on the return code — a scenario testing `--strict` needs the
    non-zero exit, so the exit-code assertion belongs in the step.
    """
    assert AILS_BIN is not None, "`ails` console script not on PATH (run via `uv run behave`)"
    env = {**os.environ, "COLUMNS": "200", "NO_COLOR": "1"}
    return subprocess.run(
        [str(AILS_BIN), *args],
        cwd=str(project),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        env=env,
    )


def document(result: subprocess.CompletedProcess[str]) -> dict:
    """Parse the whole `--format json` envelope (files map, surface_health, level, …)."""
    return json.loads(result.stdout)


def findings(result: subprocess.CompletedProcess[str]) -> list[dict]:
    """Flatten every per-file finding from a `--format json` result into one list."""
    return [f for record in document(result).get("files", {}).values() for f in record.get("findings", [])]
