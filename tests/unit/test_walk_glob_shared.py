"""The walkers read each directory once per discovery pass and resolve only symlinks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.discovery import walk as ad
from reporails_cli.core.discovery.agents import DEFAULT_EXCLUDE_DIRS


def _tree(root: Path) -> None:
    for sub in ("a/b/c", "a/d", "e"):
        (root / sub).mkdir(parents=True)
    (root / "CLAUDE.md").write_text("x\n", encoding="utf-8")
    (root / "a" / "b" / "AGENTS.md").write_text("x\n", encoding="utf-8")
    (root / "a" / "b" / "c" / "SKILL.md").write_text("x\n", encoding="utf-8")
    (root / "e" / "skill.md").write_text("x\n", encoding="utf-8")


@pytest.fixture
def scans(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every directory `os.scandir` is asked to read, in order."""
    seen: list[str] = []
    real = os.scandir

    def spy(path: str) -> object:
        seen.append(str(path))
        return real(path)

    monkeypatch.setattr(ad.os, "scandir", spy)
    return seen


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walks_in_one_pass_read_each_directory_once(tmp_path: Path, scans: list[str]) -> None:
    _tree(tmp_path)
    with ad.shared_dir_listings():
        found = [ad.walk_glob(tmp_path, name, DEFAULT_EXCLUDE_DIRS) for name in ("CLAUDE.md", "AGENTS.md", "SKILL.md")]
    assert [len(f) for f in found] == [1, 1, 2]
    assert len(scans) == len(set(scans)) == 6


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walks_outside_a_pass_read_the_disk_each_time(tmp_path: Path, scans: list[str]) -> None:
    _tree(tmp_path)
    for name in ("CLAUDE.md", "AGENTS.md"):
        ad.walk_glob(tmp_path, name, DEFAULT_EXCLUDE_DIRS)
    assert len(scans) == 12


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_new_pass_sees_a_file_added_since_the_last_one(tmp_path: Path) -> None:
    _tree(tmp_path)
    with ad.shared_dir_listings():
        before = ad.walk_glob(tmp_path, "AGENTS.md", DEFAULT_EXCLUDE_DIRS)
    (tmp_path / "a" / "d" / "AGENTS.md").write_text("x\n", encoding="utf-8")
    with ad.shared_dir_listings():
        after = ad.walk_glob(tmp_path, "AGENTS.md", DEFAULT_EXCLUDE_DIRS)
    assert len(before) == 1
    assert sorted(p.relative_to(tmp_path).as_posix() for p in after) == ["a/b/AGENTS.md", "a/d/AGENTS.md"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_shared_and_unshared_walks_find_the_same_files_in_the_same_order(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)
    (tmp_path / "e" / "link").symlink_to(tmp_path / "a" / "b", target_is_directory=True)
    plain = [ad.walk_glob(tmp_path, n, frozenset({"d"})) for n in ("agents.md", "skill.md")]
    with ad.shared_dir_listings():
        shared = [ad.walk_glob(tmp_path, n, frozenset({"d"})) for n in ("agents.md", "skill.md")]
    assert plain == shared
    assert all(plain)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_symlink_to_an_ancestor_is_entered_once(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / "a" / "b" / "up").symlink_to(tmp_path / "a", target_is_directory=True)
    found = ad.walk_glob(tmp_path, "SKILL.md", DEFAULT_EXCLUDE_DIRS)
    assert sorted(p.relative_to(tmp_path).as_posix() for p in found) == ["a/b/c/SKILL.md", "e/skill.md"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_markdown_walk_and_name_walk_share_one_scan_of_each_directory(tmp_path: Path, scans: list[str]) -> None:
    _tree(tmp_path)
    with ad.shared_dir_listings():
        by_name = ad.walk_glob(tmp_path, "AGENTS.md", DEFAULT_EXCLUDE_DIRS)
        markdown = sorted(p.name for p in ad.walk_markdown(tmp_path, DEFAULT_EXCLUDE_DIRS))
        files = sorted(p.name for p in ad.walk_files(tmp_path, DEFAULT_EXCLUDE_DIRS))
    assert [p.name for p in by_name] == ["AGENTS.md"]
    assert markdown == ["AGENTS.md", "CLAUDE.md", "SKILL.md", "skill.md"] == files
    assert len(scans) == len(set(scans)) == 6


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_markdown_walk_outside_a_pass_reads_the_disk_each_time(tmp_path: Path, scans: list[str]) -> None:
    _tree(tmp_path)
    list(ad.walk_markdown(tmp_path, DEFAULT_EXCLUDE_DIRS))
    list(ad.walk_markdown(tmp_path, DEFAULT_EXCLUDE_DIRS))
    assert len(scans) == 12


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_pass_entered_inside_a_pass_keeps_sharing_its_listings(tmp_path: Path, scans: list[str]) -> None:
    _tree(tmp_path)
    with ad.shared_dir_listings():
        ad.walk_glob(tmp_path, "AGENTS.md", DEFAULT_EXCLUDE_DIRS)
        with ad.shared_dir_listings():
            ad.walk_glob(tmp_path, "SKILL.md", DEFAULT_EXCLUDE_DIRS)
        ad.walk_glob(tmp_path, "CLAUDE.md", DEFAULT_EXCLUDE_DIRS)
    assert len(scans) == len(set(scans)) == 6


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_markdown_walk_order_and_content_match_os_walk(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)
    (tmp_path / "e" / "link").symlink_to(tmp_path / "a" / "b", target_is_directory=True)
    (tmp_path / "e" / "dangling.md").symlink_to(tmp_path / "missing.md")
    expected: list[Path] = []
    seen = {os.path.realpath(tmp_path)}
    for dirpath, dirs, files in os.walk(tmp_path, followlinks=True):
        dirs[:] = [d for d in dirs if os.path.realpath(os.path.join(dirpath, d)) not in seen]
        seen.update(os.path.realpath(os.path.join(dirpath, d)) for d in dirs)
        expected.extend(p for p in (Path(dirpath) / f for f in files) if p.suffix == ".md" and p.is_file())
    with ad.shared_dir_listings():
        shared = list(ad.walk_markdown(tmp_path, DEFAULT_EXCLUDE_DIRS))
    assert list(ad.walk_markdown(tmp_path, DEFAULT_EXCLUDE_DIRS)) == expected == shared
    assert expected


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_plugin_root_and_marker_scans_replay_the_walkers_listings(tmp_path: Path, scans: list[str]) -> None:
    from reporails_cli.core.discovery.agent_markers import scan_marker_at
    from reporails_cli.core.discovery.agents import get_known_agents
    from reporails_cli.core.discovery.plugin_roots import find_plugin_roots

    _tree(tmp_path)
    registry = get_known_agents()
    with ad.shared_dir_listings():
        ad.walk_glob(tmp_path, "CLAUDE.md", DEFAULT_EXCLUDE_DIRS)
        assert scan_marker_at(tmp_path, registry["claude"], registry)
        assert find_plugin_roots(tmp_path, ".claude-plugin/plugin.json", DEFAULT_EXCLUDE_DIRS) == []
    assert len(scans) == len(set(scans))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_glob_warns_on_circular_symlink_named_like_the_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x").symlink_to(tmp_path / "sub" / "CLAUDE.md")
    (tmp_path / "sub" / "CLAUDE.md").symlink_to(tmp_path / "sub" / "x")
    with caplog.at_level("WARNING"):
        assert ad.walk_glob(tmp_path, "CLAUDE.md", frozenset()) == []
    assert any("Circular symlink detected" in r.getMessage() for r in caplog.records)
