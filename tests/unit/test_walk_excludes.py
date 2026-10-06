"""Every walker enters exactly the directories its resolved exclude set leaves in."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import DEFAULT_EXCLUDE_DIRS, load_project_exclude_dirs
from reporails_cli.core.discovery.plugin_roots import find_plugin_roots
from reporails_cli.core.discovery.walk import walk_files, walk_glob, walk_markdown

_NOISE = (".git", "node_modules", "__pycache__")


def _tree(root: Path) -> None:
    (root / "CLAUDE.md").write_text("x\n", encoding="utf-8")
    for name in (*_NOISE, "docs", "scratch"):
        (root / name).mkdir()
        (root / name / "CLAUDE.md").write_text("x\n", encoding="utf-8")
        (root / name / "note.md").write_text("x\n", encoding="utf-8")


def _rel(root: Path, paths: object) -> set[str]:
    return {p.relative_to(root).as_posix() for p in paths}  # type: ignore[attr-defined]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_default_set_keeps_every_walker_out_of_vcs_cache_and_dependency_dirs(tmp_path: Path) -> None:
    _tree(tmp_path)
    expected_names = {"CLAUDE.md", "docs/CLAUDE.md", "scratch/CLAUDE.md"}
    assert _rel(tmp_path, walk_glob(tmp_path, "CLAUDE.md", DEFAULT_EXCLUDE_DIRS)) == expected_names
    assert _rel(tmp_path, walk_markdown(tmp_path, DEFAULT_EXCLUDE_DIRS)) == expected_names | {
        "docs/note.md",
        "scratch/note.md",
    }
    assert _rel(tmp_path, walk_files(tmp_path, DEFAULT_EXCLUDE_DIRS)) == _rel(
        tmp_path, walk_markdown(tmp_path, DEFAULT_EXCLUDE_DIRS)
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_walker_given_nothing_to_exclude_enters_everything(tmp_path: Path) -> None:
    _tree(tmp_path)
    found = _rel(tmp_path, walk_glob(tmp_path, "CLAUDE.md", frozenset()))
    assert {f"{name}/CLAUDE.md" for name in _NOISE} <= found


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_project_config_exclude_dirs_extend_the_default_set(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "config.yml").write_text("exclude_dirs:\n  - scratch\n", encoding="utf-8")
    resolved = load_project_exclude_dirs(tmp_path)
    assert resolved > DEFAULT_EXCLUDE_DIRS
    assert "scratch" in resolved
    assert _rel(tmp_path, walk_glob(tmp_path, "CLAUDE.md", resolved)) == {"CLAUDE.md", "docs/CLAUDE.md"}
    assert "scratch/note.md" not in _rel(tmp_path, walk_markdown(tmp_path, resolved))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_plugin_root_search_honours_the_exclude_set(tmp_path: Path) -> None:
    for name in ("vendored", "mine"):
        (tmp_path / name / ".claude-plugin").mkdir(parents=True)
        (tmp_path / name / ".claude-plugin" / "plugin.json").write_text("{}", encoding="utf-8")
    assert find_plugin_roots(tmp_path, ".claude-plugin/plugin.json", DEFAULT_EXCLUDE_DIRS | {"vendored"}) == [
        tmp_path / "mine"
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_local_config_exclude_dirs_reach_the_walkers_and_agent_detection(tmp_path: Path) -> None:
    from reporails_cli.core.discovery.agents import detect_agents

    _tree(tmp_path)
    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "config.local.yml").write_text("exclude_dirs:\n  - scratch\n", encoding="utf-8")
    resolved = load_project_exclude_dirs(tmp_path)
    assert "scratch" in resolved
    assert _rel(tmp_path, walk_glob(tmp_path, "CLAUDE.md", resolved)) == {"CLAUDE.md", "docs/CLAUDE.md"}
    detected = {path for agent in detect_agents(tmp_path) for path in _rel(tmp_path, agent.instruction_files)}
    assert "CLAUDE.md" in detected
    assert "scratch/CLAUDE.md" not in detected


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_global_config_exclude_dirs_extend_the_resolved_set(tmp_path: Path) -> None:
    home = Path.home() / ".reporails"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yml").write_text("exclude_dirs:\n  - elsewhere\n", encoding="utf-8")
    assert "elsewhere" in load_project_exclude_dirs(tmp_path)


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("pattern", "files"),
    [
        ("skills/foo/*.md", ["skills/foo/SKILL.md"]),
        ("node_modules/pkg/*.js", ["node_modules/pkg/i.js"]),
        ("node_modules/pkg/i.js", ["node_modules/pkg/i.js"]),
        ("../outside.md", []),
    ],
)
def test_a_glob_under_an_excluded_folder_or_above_the_root_matches_nothing(
    tmp_path: Path, pattern: str, files: list[str]
) -> None:
    from reporails_cli.core.discovery.walk import walk_glob_matches

    root = tmp_path / "proj"
    root.mkdir()
    (tmp_path / "outside.md").write_text("x\n", encoding="utf-8")
    for name in files:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text("x\n", encoding="utf-8")
    exclude = frozenset({"skills", "node_modules"})
    assert list(walk_glob_matches(root, pattern, exclude)) == []
