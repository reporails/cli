"""A folder spelled two ways (a symlinked or Windows short `RUNNER~1` name beside its resolved name) reads as one.

A symlinked folder stands in for the short alias: the resolved and the written spelling differ, the folder is the same.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.external_patterns import external_anchor
from reporails_cli.core.discovery.walk import logical_path
from reporails_cli.core.pipeline.check_one import resolve_scan_target
from reporails_cli.core.platform.runtime.merger import normalize_finding_path
from reporails_cli.core.platform.utils.utils import expand_home_pattern, home_relative
from reporails_cli.formatters.text.display_constants import short_path
from reporails_cli.interfaces.cli.check_notices import _emit_unlisted_file

pytestmark = [pytest.mark.unit, pytest.mark.subsys_classify]


@pytest.fixture
def aliased(tmp_path: Path) -> tuple[Path, Path]:
    """`(real, alias)`: a folder and a symlink to it, so a path has a resolved and a written spelling."""
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    return real.resolve(), alias


@pytest.fixture
def aliased_home(aliased: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A home folder the environment spells through the alias; returns `(resolved home, written home)`."""
    real, alias = aliased
    (real / "home" / ".claude" / "skills").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(alias / "home"))
    monkeypatch.setenv("USERPROFILE", str(alias / "home"))
    return real / "home", alias / "home"


def test_a_home_pattern_expands_to_the_resolved_home(aliased_home: tuple[Path, Path]) -> None:
    home, _written = aliased_home
    assert expand_home_pattern("~/.claude/skills/*/SKILL.md") == f"{home.as_posix()}/.claude/skills/*/SKILL.md"
    assert expand_home_pattern("~") == home.as_posix()
    assert expand_home_pattern("src/*.md") == "src/*.md"


def test_an_external_anchor_is_the_resolved_home_folder(aliased_home: tuple[Path, Path]) -> None:
    home, _written = aliased_home
    anchor, below = external_anchor("~/.claude/skills/*/SKILL.md")
    assert anchor == home / ".claude" / "skills"
    assert below == "*/SKILL.md"


def test_a_path_is_home_relative_whichever_way_it_is_spelled(aliased_home: tuple[Path, Path]) -> None:
    home, written = aliased_home
    assert home_relative(home / ".claude" / "CLAUDE.md") == ".claude/CLAUDE.md"
    assert home_relative(written / ".claude" / "CLAUDE.md") == ".claude/CLAUDE.md"
    assert home_relative(home.parent / "elsewhere.md") is None


def test_a_finding_in_the_home_folder_is_named_with_a_tilde(aliased_home: tuple[Path, Path], tmp_path: Path) -> None:
    home, _written = aliased_home
    shown = normalize_finding_path(str(home / ".claude" / "CLAUDE.md"), tmp_path / "project")
    assert shown == "~/.claude/CLAUDE.md"
    assert short_path(str(home / ".claude" / "CLAUDE.md")) == "~/.claude/CLAUDE.md"


def test_a_link_keeps_its_name_under_the_resolved_folder_spelling(aliased: tuple[Path, Path]) -> None:
    real, alias = aliased
    shared = real / "shared.md"
    shared.write_text("# Shared\n", encoding="utf-8")
    rules = real / "proj" / ".claude" / "rules"
    rules.mkdir(parents=True)
    (rules / "style.md").symlink_to(shared)
    assert logical_path(alias / "proj" / ".claude" / "rules" / "style.md") == rules / "style.md"


def test_a_linked_rule_written_through_an_alias_is_checked_within_its_project(aliased: tuple[Path, Path]) -> None:
    real, alias = aliased
    shared = real / "shared.md"
    shared.write_text("# Shared\n", encoding="utf-8")
    project = real / "proj"
    rules = project / ".claude" / "rules"
    rules.mkdir(parents=True)
    (rules / "style.md").symlink_to(shared)
    scan_root, single = resolve_scan_target(alias / "proj" / ".claude" / "rules" / "style.md", project)
    assert scan_root == project
    assert single == rules / "style.md"


def test_a_file_in_the_run_folder_is_named_relative_to_it_with_slashes(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    guide = tmp_path / "docs" / "guide.md"
    _emit_unlisted_file(guide, tmp_path, tmp_path, "json")
    assert capsys.readouterr().err.strip() == "docs/guide.md is not an instruction file of this project."


def test_a_file_of_another_project_is_named_by_its_path(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    rule = tmp_path / "proj" / ".claude" / "rules" / "x.md"
    _emit_unlisted_file(rule, tmp_path / "proj", tmp_path / "cwd", "json")
    assert capsys.readouterr().err.startswith(f"{rule} is not an instruction file in the project at ")
