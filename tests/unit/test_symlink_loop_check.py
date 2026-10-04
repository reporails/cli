"""A circular symlink named like an instruction file is skipped by every stage of a check."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import get_all_instruction_files, get_all_scannable_files
from reporails_cli.core.discovery.walk import has_symlink_loop, is_under, safe_resolve


def _project_with_loop(root: Path) -> Path:
    (root / "CLAUDE.md").write_text("# Project\n\nRun the tests before every commit.\n", encoding="utf-8")
    loop = root / "loop"
    loop.mkdir()
    (loop / "CLAUDE.md").symlink_to("x")
    (loop / "x").symlink_to("CLAUDE.md")
    return loop / "CLAUDE.md"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_guard_reports_a_loop_and_resolves_it_to_itself(tmp_path: Path) -> None:
    looping = _project_with_loop(tmp_path)
    assert has_symlink_loop(looping) is True
    assert has_symlink_loop(tmp_path / "CLAUDE.md") is False
    assert safe_resolve(looping) == looping
    assert is_under(looping, tmp_path) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_mechanical_check_location_test_survives_a_loop(tmp_path: Path) -> None:
    from reporails_cli.core.lint.mechanical.runner import _is_under_root

    looping = _project_with_loop(tmp_path)
    assert _is_under_root(looping, tmp_path) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_discovery_leaves_out_a_looping_link_and_keeps_the_real_file(tmp_path: Path) -> None:
    looping = _project_with_loop(tmp_path)
    for files in (get_all_instruction_files(tmp_path), get_all_scannable_files(tmp_path)):
        assert looping not in files
        assert any(f.name == "CLAUDE.md" and f.parent == tmp_path for f in files)
