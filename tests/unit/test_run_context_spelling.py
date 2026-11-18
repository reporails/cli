"""One run keeps each spelling of a linked folder apart: agents, aliases and config follow the path as written."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import detect_agents, get_all_instruction_files
from reporails_cli.core.discovery.file_aliases import get_file_aliases
from reporails_cli.core.platform.config.run_context import RunContext

pytestmark = [
    pytest.mark.unit,
    pytest.mark.subsys_lint,
    pytest.mark.skipif(sys.platform == "win32", reason="symlinks require admin on Windows"),
]


def _linked_project(tmp_path: Path) -> tuple[Path, Path]:
    real = tmp_path / "dotfiles" / "claude"
    real.mkdir(parents=True)
    (real / "CLAUDE.md").write_text("# Main\n", encoding="utf-8")
    link = tmp_path / "home" / ".claude"
    link.parent.mkdir()
    os.symlink(str(real), str(link))
    return real, link


def test_each_spelling_of_a_linked_folder_keeps_its_own_agent_paths(tmp_path: Path) -> None:
    real, link = _linked_project(tmp_path)
    run = RunContext()
    via_real = detect_agents(run, real)
    via_link = detect_agents(run, link)
    real_paths = {f for a in via_real for f in a.instruction_files}
    link_paths = {f for a in via_link for f in a.instruction_files}
    assert real_paths and link_paths
    assert all(real in p.parents for p in real_paths)
    assert all(link in p.parents for p in link_paths)


def test_each_spelling_keeps_its_own_project_config_entry(tmp_path: Path) -> None:
    real, link = _linked_project(tmp_path)
    run = RunContext()
    assert run.project_config(real) is not run.project_config(link)


def test_aliases_stay_keyed_by_the_resolved_root(tmp_path: Path) -> None:
    real, link = _linked_project(tmp_path)
    run = RunContext()
    get_all_instruction_files(run, link)
    assert get_file_aliases(run, real) == get_file_aliases(run, link)
