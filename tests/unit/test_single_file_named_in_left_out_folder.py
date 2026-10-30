"""A single file validated inside a config-excluded folder is named on both surfaces."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.pipeline import check_one
from reporails_cli.core.pipeline.mapping import discover_scope


def _project(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    (project / ".ails" / "config.yml").write_text("exclude_dirs: [skills]\n", encoding="utf-8")
    (project / "CLAUDE.md").write_text("# proj\n\nAlways run the tests.\n", encoding="utf-8")
    skill = project / ".claude" / "skills" / "foo" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: foo\ndescription: Does foo.\n---\n\nRun foo.\n", encoding="utf-8")
    return project, skill


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mcp_single_file_in_left_out_folder_is_named(tmp_path: Path) -> None:
    project, skill = _project(tmp_path)
    clear_agent_cache()
    exclusions = check_one.discover_files(project, single_file=skill).left_out.exclusions
    assert exclusions is not None
    assert skill in exclusions.named
    assert not exclusions.leaves_out(skill)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_single_file_pass_names_the_file_and_lists_nothing(tmp_path: Path) -> None:
    project, skill = _project(tmp_path)
    clear_agent_cache()
    found = discover_scope(project, "claude", None, None, scan_files=False, named=frozenset({skill}))
    assert found.exclusions is not None
    assert skill in found.exclusions.named
    assert not found.exclusions.leaves_out(skill)
    assert found.files == []
    assert found.excluded == ((), ())


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mcp_single_file_run_names_only_the_file(tmp_path: Path) -> None:
    project, skill = _project(tmp_path)
    clear_agent_cache()
    single = project / "CLAUDE.md"
    exclusions = check_one.discover_files(project, single_file=single, named=frozenset({skill})).left_out.exclusions
    assert exclusions is not None
    assert exclusions.named == frozenset({single.resolve()})
    assert exclusions.leaves_out(skill)
