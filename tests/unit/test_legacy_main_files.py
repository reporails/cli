"""A cataloged agent's root instruction file (`.windsurfrules`) classifies as `main`."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify.file_tags import classify_file
from reporails_cli.core.discovery.agent_surfaces import agent_main_names
from reporails_cli.core.discovery.agents import get_known_agents
from reporails_cli.core.platform.config.capabilities import legacy_main_files

pytestmark = [pytest.mark.unit, pytest.mark.subsys_classify]


def test_matrix_row_lists_windsurf_rules_file() -> None:
    assert legacy_main_files()["windsurf"] == frozenset({".windsurfrules"})


def test_agent_main_names_includes_windsurfrules() -> None:
    assert ".windsurfrules" in agent_main_names()


def test_root_windsurfrules_classifies_as_main(tmp_path: Path) -> None:
    (tmp_path / ".windsurfrules").write_text("rules\n")
    assert classify_file(str(tmp_path / ".windsurfrules"), tmp_path) == "main"


def test_nested_windsurfrules_classifies_as_nested(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / ".windsurfrules").write_text("rules\n")
    assert classify_file(str(tmp_path / "pkg" / ".windsurfrules"), tmp_path) == "nested"


def test_windsurf_is_not_a_known_agent() -> None:
    assert "windsurf" not in get_known_agents()
