"""The source archive leaves out project settings, scratch folders, tool state and caches."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


@pytest.mark.unit
@pytest.mark.subsys_gates
@pytest.mark.parametrize(
    "entry",
    ["/.ails", "/.claude", "/.idea", "/.vscode", "/.venv", "/.mcp.json", "/tmp", "**/.import_linter_cache"],
)
def test_sdist_excludes_untracked_and_local_state(entry: str) -> None:
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    excluded = config["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"]

    assert entry in excluded
