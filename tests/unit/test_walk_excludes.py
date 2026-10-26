"""Every walker enters exactly the directories its resolved exclude set leaves in."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.discovery.exclusions import RunExclusions, load_run_exclusions
from reporails_cli.core.discovery.plugin_roots import find_plugin_roots
from reporails_cli.core.discovery.walk import walk_files, walk_glob, walk_glob_matches, walk_markdown

_NOISE = (".git", "node_modules", "__pycache__")


class _PruneNothing:
    """A pruner that skips no folder."""

    def prunes(self, path: str, name: str, real: str) -> bool:
        return False


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
    skip = RunExclusions.none(tmp_path)
    assert _rel(tmp_path, walk_glob(tmp_path, "CLAUDE.md", skip)) == expected_names
    assert _rel(tmp_path, walk_markdown(tmp_path, skip)) == expected_names | {
        "docs/note.md",
        "scratch/note.md",
    }
    assert _rel(tmp_path, walk_files(tmp_path, skip)) == _rel(tmp_path, walk_markdown(tmp_path, skip))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_walker_given_nothing_to_exclude_enters_everything(tmp_path: Path) -> None:
    _tree(tmp_path)
    found = _rel(tmp_path, walk_glob(tmp_path, "CLAUDE.md", _PruneNothing()))
    assert {f"{name}/CLAUDE.md" for name in _NOISE} <= found


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_project_config_exclude_dirs_extend_the_default_set(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "config.yml").write_text("exclude_dirs:\n  - scratch\n", encoding="utf-8")
    resolved = load_run_exclusions(tmp_path)
    assert resolved.prunes(str(tmp_path / "scratch"), "scratch", os.path.realpath(str(tmp_path / "scratch")))
    assert resolved.prunes(
        str(tmp_path / "node_modules"), "node_modules", os.path.realpath(str(tmp_path / "node_modules"))
    )
    assert not resolved.prunes(str(tmp_path / "docs"), "docs", os.path.realpath(str(tmp_path / "docs")))
    assert _rel(tmp_path, walk_glob(tmp_path, "CLAUDE.md", resolved)) == {"CLAUDE.md", "docs/CLAUDE.md"}
    assert "scratch/note.md" not in _rel(tmp_path, walk_markdown(tmp_path, resolved))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_plugin_root_search_honours_the_exclude_set(tmp_path: Path) -> None:
    for name in ("vendored", "mine"):
        (tmp_path / name / ".claude-plugin").mkdir(parents=True)
        (tmp_path / name / ".claude-plugin" / "plugin.json").write_text("{}", encoding="utf-8")
    assert find_plugin_roots(
        tmp_path, ".claude-plugin/plugin.json", RunExclusions.parse(tmp_path, ["vendored"], ())
    ) == [tmp_path / "mine"]


def _vendored_plugin(project: Path) -> None:
    manifest = project / "pkg" / "vendored" / "demo" / ".claude-plugin" / "plugin.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"name": "demo", "description": "Demo plugin"}\n', encoding="utf-8")
    skill = manifest.parents[1] / "skills" / "fmt" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: fmt\ndescription: Formats files\n---\n\nRun `ruff format`.\n", encoding="utf-8")


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("config", "found"), [("", True), ("exclude_dirs:\n  - pkg/vendored\n", False)])
def test_agent_detection_skips_a_marker_under_a_config_folder_path(tmp_path: Path, config: str, found: bool) -> None:
    from reporails_cli.core.discovery.agent_markers import agent_has_marker
    from reporails_cli.core.discovery.agents import clear_agent_cache, detect_agents, get_known_agents

    _vendored_plugin(tmp_path)
    if config:
        (tmp_path / ".ails").mkdir()
        (tmp_path / ".ails" / "config.yml").write_text(config, encoding="utf-8")
    known = get_known_agents()
    assert agent_has_marker(tmp_path, known["claude"], known, load_run_exclusions(tmp_path)) is found
    clear_agent_cache()
    assert ("claude" in {a.agent_type.id for a in detect_agents(tmp_path)}) is found


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_local_config_exclude_dirs_reach_the_walkers_and_agent_detection(tmp_path: Path) -> None:
    from reporails_cli.core.discovery.agents import detect_agents

    _tree(tmp_path)
    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "config.local.yml").write_text("exclude_dirs:\n  - scratch\n", encoding="utf-8")
    resolved = load_run_exclusions(tmp_path)
    assert resolved.prunes(str(tmp_path / "scratch"), "scratch", os.path.realpath(str(tmp_path / "scratch")))
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
    assert load_run_exclusions(tmp_path).prunes(
        str(tmp_path / "elsewhere"), "elsewhere", os.path.realpath(str(tmp_path / "elsewhere"))
    )


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
    root = tmp_path / "proj"
    root.mkdir()
    (tmp_path / "outside.md").write_text("x\n", encoding="utf-8")
    for name in files:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text("x\n", encoding="utf-8")
    exclude = RunExclusions.parse(root, ["skills"], ())
    assert list(walk_glob_matches(root, pattern, exclude)) == []


@pytest.fixture
def listed(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The path of every directory a walk lists."""
    from reporails_cli.core.discovery import walk

    paths: list[str] = []
    real = walk.list_dir

    def counting(path: str) -> object:
        paths.append(path)
        return real(path)

    monkeypatch.setattr(walk, "list_dir", counting)
    return paths


def _docs_tree(root: Path) -> None:
    for rel in ("pkg/docs/a.md", "docs/b.md", "pkg/keep/c.md"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x\n", encoding="utf-8")


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("value", ["pkg/docs", "./pkg/docs"])
def test_a_folder_path_is_never_entered(tmp_path: Path, listed: list[str], value: str) -> None:
    _docs_tree(tmp_path)
    skip = RunExclusions.parse(tmp_path, [value], ())
    assert _rel(tmp_path, walk_markdown(tmp_path, skip)) == {"docs/b.md", "pkg/keep/c.md"}
    assert str(tmp_path / "pkg" / "docs") not in listed
    assert str(tmp_path / "docs") in listed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_folder_name_is_never_entered_at_any_depth(tmp_path: Path, listed: list[str]) -> None:
    _docs_tree(tmp_path)
    skip = RunExclusions.parse(tmp_path, ["docs"], ())
    assert _rel(tmp_path, walk_markdown(tmp_path, skip)) == {"pkg/keep/c.md"}
    assert not [p for p in listed if Path(p).name == "docs"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_symlink_to_an_excluded_folder_path_is_pruned(tmp_path: Path, listed: list[str]) -> None:
    _docs_tree(tmp_path)
    try:
        (tmp_path / "alias").symlink_to(tmp_path / "pkg" / "docs", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks cannot be created here")
    skip = RunExclusions.parse(tmp_path, ["pkg/docs"], ())
    assert _rel(tmp_path, walk_markdown(tmp_path, skip)) == {"docs/b.md", "pkg/keep/c.md"}
    assert str(tmp_path / "alias") not in listed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_folder_holding_a_named_file_is_entered_but_its_excluded_sibling_is_not(tmp_path: Path) -> None:
    for rel in ("pkg/docs/a.md", "pkg/docs/sub/s.md", "pkg/other/o.md", "node_modules/n.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x\n", encoding="utf-8")
    skip = RunExclusions.parse(tmp_path, ["pkg/docs", "pkg/other"], ()).with_named([tmp_path / "pkg" / "docs" / "a.md"])
    assert _rel(tmp_path, walk_markdown(tmp_path, skip)) == {"pkg/docs/a.md"}
    by_name = RunExclusions.parse(tmp_path, ["docs", "other"], ()).with_named([tmp_path / "pkg" / "docs" / "a.md"])
    assert _rel(tmp_path, walk_markdown(tmp_path, by_name)) == {"pkg/docs/a.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_default_folder_is_pruned_even_when_it_holds_a_named_file(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "n.md").write_text("x\n", encoding="utf-8")
    skip = RunExclusions.parse(tmp_path, ["other"], ()).with_named([tmp_path / "node_modules" / "n.md"])
    assert _rel(tmp_path, walk_markdown(tmp_path, skip)) == set()


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_glob_under_an_excluded_folder_path_matches_nothing(tmp_path: Path) -> None:
    _docs_tree(tmp_path)
    skip = RunExclusions.parse(tmp_path, ["pkg/docs"], ())
    assert list(walk_glob_matches(tmp_path, "pkg/docs/*.md", skip)) == []
    assert _rel(tmp_path, walk_glob_matches(tmp_path, "pkg/keep/*.md", skip)) == {"pkg/keep/c.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_symlink_into_a_folder_left_out_by_name_is_not_entered(tmp_path: Path) -> None:
    (tmp_path / "vendor" / "pkg").mkdir(parents=True)
    (tmp_path / "vendor" / "pkg" / "x.md").write_text("x\n", encoding="utf-8")
    (tmp_path / "keep.md").write_text("x\n", encoding="utf-8")
    try:
        (tmp_path / "link").symlink_to(tmp_path / "vendor" / "pkg", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks cannot be created here")
    skip = RunExclusions.parse(tmp_path, ["vendor"], ())
    assert _rel(tmp_path, walk_markdown(tmp_path, skip)) == {"keep.md"}
    assert skip.leaves_out(tmp_path / "link" / "x.md")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_folder_left_out_by_name_that_holds_a_named_file_is_entered_but_a_bare_subfolder_is_not(
    tmp_path: Path,
) -> None:
    for rel in ("pkg/docs/a.md", "pkg/docs/sub/s.md", "pkg/docs/hold/h.md", "pkg/keep/k.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x\n", encoding="utf-8")
    skip = RunExclusions.parse(tmp_path, ["docs"], ()).with_named(
        [tmp_path / "pkg" / "docs" / "a.md", tmp_path / "pkg" / "docs" / "hold" / "h.md"]
    )
    assert _rel(tmp_path, walk_markdown(tmp_path, skip)) == {"pkg/docs/a.md", "pkg/docs/hold/h.md", "pkg/keep/k.md"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_child_real_resolves_a_junction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.discovery.walk import child_real

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.mkdir()
    monkeypatch.setattr(os.path, "realpath", lambda p: str(target) if p == str(link) else p)
    monkeypatch.setattr(os.path, "isjunction", lambda p: p == str(link))
    assert child_real(str(link), "link", str(tmp_path), False) == str(target)
    assert child_real(str(tmp_path / "plain"), "plain", str(tmp_path), False) == str(tmp_path / "plain")
