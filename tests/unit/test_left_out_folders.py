"""Left-out folders are tested through the one path matcher, in every walk and through symlinks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.discovery.exclusions import RunExclusions
from reporails_cli.core.discovery.plugin_roots import find_plugin_roots
from reporails_cli.core.discovery.walk import walk_glob_matches, walk_markdown
from reporails_cli.core.platform.policy.exclusion import folder_value_problem
from reporails_cli.core.platform.policy.preflight import _files_by_name, preflight_oversized


def _tree(root: Path, *rels: str) -> None:
    for rel in rels:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("x\n", encoding="utf-8")


def _walked(root: Path, skip: RunExclusions) -> set[str]:
    return {Path(p).relative_to(root).as_posix() for p in walk_markdown(root, skip)}


def _link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks cannot be created here")


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("value", "left_out", "kept"),
    [
        ("[slug]", ["[slug]/a.md", "app/[slug]/a.md"], ["s/a.md", "slug/a.md", "l/a.md"]),
        ("app/[id]", ["app/[id]/a.md"], ["app/i/a.md", "app/d/a.md", "app/id/a.md", "x/app/[id]/a.md"]),
        ("{a,b}", ["{a,b}/a.md", "p/{a,b}/a.md"], ["a/a.md", "b/a.md", "p/a/a.md", "a,b/a.md"]),
        ("a,b", ["a,b/a.md", "p/a,b/a.md"], ["a/a.md", "b/a.md", "{a,b}/a.md"]),
    ],
)
def test_a_folder_spelled_with_glob_characters_is_left_out_by_its_value_only(
    tmp_path: Path, value: str, left_out: list[str], kept: list[str]
) -> None:
    _tree(tmp_path, *left_out, *kept)
    skip = RunExclusions.parse(tmp_path, [value], ())
    assert _walked(tmp_path, skip) == set(kept)
    assert all(skip.leaves_out(tmp_path / rel) for rel in left_out)
    assert not any(skip.leaves_out(tmp_path / rel) for rel in kept)
    assert all(skip.covers((tmp_path / rel).parent) for rel in left_out)
    assert not any(skip.covers((tmp_path / rel).parent) for rel in kept)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_symlink_into_a_folder_left_out_by_name_is_entered_by_no_walk(tmp_path: Path) -> None:
    _tree(tmp_path, "docs/pkg/x.md", "docs/pkg/plugin.json", "keep.md")
    _link(tmp_path / "link", tmp_path / "docs" / "pkg")
    skip = RunExclusions.parse(tmp_path, ["docs"], ())
    open_ = RunExclusions.none(tmp_path)
    assert _walked(tmp_path, skip) == {"keep.md"}
    assert skip.covers(tmp_path / "link") and skip.covers(tmp_path / "link" / "x.md")
    assert not open_.covers(tmp_path / "link")
    assert [p.name for p in walk_glob_matches(tmp_path, "link/*.md", open_)] == ["x.md"]
    assert list(walk_glob_matches(tmp_path, "link/*.md", skip)) == []
    assert not skip.prunes(str(tmp_path / "keep.md"), "keep.md", str(tmp_path / "keep.md"))
    assert skip.prunes(str(tmp_path / "link"), "link", os.path.realpath(tmp_path / "link"))
    assert find_plugin_roots(tmp_path, "plugin.json", open_) == [tmp_path / "docs" / "pkg"]
    assert find_plugin_roots(tmp_path, "plugin.json", skip) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_plugin_root_inside_a_folder_left_out_is_not_found(tmp_path: Path) -> None:
    _tree(tmp_path, "docs/pl/plugin.json", "pl2/plugin.json")
    assert find_plugin_roots(tmp_path, "plugin.json", RunExclusions.none(tmp_path)) == [
        tmp_path / "docs" / "pl",
        tmp_path / "pl2",
    ]
    assert find_plugin_roots(tmp_path, "plugin.json", RunExclusions.parse(tmp_path, ["docs"], ())) == [tmp_path / "pl2"]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("value", ["docs", "pkg/docs"])
def test_a_left_out_folder_holding_a_named_file_is_entered_only_on_the_way_to_it(tmp_path: Path, value: str) -> None:
    _tree(tmp_path, "pkg/docs/a.md", "pkg/docs/sub/s.md", "pkg/docs/sub/deep/d.md", "pkg/docs/hold/h.md", "pkg/k.md")
    skip = RunExclusions.parse(tmp_path, [value], ()).with_named([tmp_path / "pkg" / "docs" / "hold" / "h.md"])
    assert _walked(tmp_path, skip) == {"pkg/docs/a.md", "pkg/docs/hold/h.md", "pkg/k.md"}
    assert not skip.covers(tmp_path / "pkg" / "docs" / "hold" / "h.md")
    assert skip.covers(tmp_path / "pkg" / "docs" / "sub")
    assert skip.covers(tmp_path / "pkg" / "docs" / "sub" / "deep" / "d.md")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_covers_and_the_walk_agree_on_every_folder(tmp_path: Path) -> None:
    _tree(
        tmp_path,
        "a.md",
        "docs/d.md",
        "docs/in/i.md",
        "pkg/p.md",
        "pkg/x/x.md",
        "pkg/x/deep/y.md",
        "pkg/ok/o.md",
        "pkg/ok/docs/z.md",
        "other/pkg/x/q.md",
        "[id]/b.md",
        "node_modules/n.md",
    )
    _link(tmp_path / "alias", tmp_path / "docs" / "in")
    _link(tmp_path / "pkg" / "ok" / "back", tmp_path / "pkg" / "x")
    skip = RunExclusions.parse(tmp_path, ["docs", "pkg/x", "[id]"], ())
    walked = _walked(tmp_path, skip)
    folders = sorted(p for p in tmp_path.rglob("*") if p.is_dir() or p.is_symlink())
    assert folders
    for folder in folders:
        rel = folder.relative_to(tmp_path).as_posix()
        reached = any(w == rel or w.startswith(rel + "/") for w in walked)
        assert skip.covers(folder) is (not reached), rel


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_folder_name_never_matches_a_folder_above_the_project_root(tmp_path: Path) -> None:
    root = tmp_path / "docs" / "proj"
    _tree(root, "a.md", "sub/b.md")
    skip = RunExclusions.parse(root, ["docs", "proj"], ())
    assert _walked(root, skip) == {"a.md", "sub/b.md"}
    assert not skip.leaves_out(root / "a.md")
    assert not skip.covers(root / "sub")
    assert not skip.prunes(str(root / "sub"), "sub", str(root / "sub"))
    assert skip.record() == ((("docs", "proj")), ())


@pytest.mark.unit
@pytest.mark.subsys_funnel
def test_the_over_cap_route_survives_paths_with_empty_or_dot_segments() -> None:
    per_file = {
        "a//b.md": 3,
        "./a/b.md": 3,
        "docs/x.md": 2,
        "x/./y/z.md": 1,
        "/abs/q.md": 1,
        "[id]/p.md": 1,
        "a b/c.md": 1,
    }
    by_name = _files_by_name(per_file)
    assert "" not in by_name and "." not in by_name
    assert all(folder_value_problem(name) is None for name in by_name)
    assert by_name["a"] == {"a//b.md", "./a/b.md"}
    assert by_name["docs"] == {"docs/x.md"}
    assert by_name["[id]"] == {"[id]/p.md"}
    assert by_name["a b"] == {"a b/c.md"}
    payload = {
        "files": [{"path": path} for path in per_file],
        "atoms": [{"fi": i} for i, n in enumerate(per_file.values()) for _ in range(n * 2000)],
    }
    err = preflight_oversized(payload, has_api_key=False)
    assert err is not None
    assert all(name and folder_value_problem(name) is None for name in err.exclude_route)
