"""Unit tests for `walk_markdown_links` reach-only behavior (targets derived from edge set)."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.classify.link_walker import walk_markdown_links

FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "generic-classification"


def _reached_targets(edges: list) -> set[Path]:
    """Collapse a `list[LinkEdge]` to the set of resolved target paths."""
    return {edge.target for edge in edges}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_finds_inline_md_targets(tmp_path: Path) -> None:
    main = tmp_path / "main.md"
    target = tmp_path / "linked.md"
    main.write_text("Read [the notes](linked.md).\n", encoding="utf-8")
    target.write_text("# notes\n", encoding="utf-8")
    edges = walk_markdown_links({main: "main"}, tmp_path, {main})
    assert _reached_targets(edges) == {target.resolve()}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_skips_urls_and_anchors(tmp_path: Path) -> None:
    main = tmp_path / "main.md"
    main.write_text(
        "URL [example](https://example.com)\nanchor [section](#section)\nmailto [link](mailto:nobody@example.com)\n",
        encoding="utf-8",
    )
    assert walk_markdown_links({main: "main"}, tmp_path, {main}) == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_skips_out_of_tree(tmp_path: Path) -> None:
    main = tmp_path / "project" / "main.md"
    main.parent.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("# outside\n", encoding="utf-8")
    main.write_text("Goes [outside](../outside.md).\n", encoding="utf-8")
    edges = walk_markdown_links({main: "main"}, main.parent, {main})
    assert edges == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_handles_cycle(tmp_path: Path) -> None:
    a = tmp_path / "a.md"
    b = tmp_path / "b.md"
    a.write_text("Goes to [b](b.md).\n", encoding="utf-8")
    b.write_text("Goes to [a](a.md).\n", encoding="utf-8")
    edges = walk_markdown_links({a: "main"}, tmp_path, {a})
    # b is reached; a is already-classified so it does not enter the edge set.
    assert _reached_targets(edges) == {b.resolve()}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_skips_already_classified(tmp_path: Path) -> None:
    main = tmp_path / "main.md"
    rule = tmp_path / "rule.md"
    main.write_text("See [rule](rule.md).\n", encoding="utf-8")
    rule.write_text("# rule\n", encoding="utf-8")
    # rule is already-classified; walker must not re-include it.
    edges = walk_markdown_links({main: "main"}, tmp_path, {main, rule})
    assert edges == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_classify_files_with_generic_scanning_off_does_not_walk(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("Read [arch](arch.md).\n", encoding="utf-8")
    (tmp_path / "arch.md").write_text("# arch\n", encoding="utf-8")
    file_types = load_file_types("claude")
    classified = classify_files(
        tmp_path,
        [tmp_path / "CLAUDE.md", tmp_path / "arch.md"],
        file_types,
        generic_scanning=False,
    )
    types = {cf.path.name: cf.file_type for cf in classified}
    assert types.get("CLAUDE.md") == "main"
    assert "arch.md" not in types  # no generic without scanning


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_classify_files_with_generic_scanning_on_walks_and_classifies(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("Read [arch](arch.md).\n", encoding="utf-8")
    (tmp_path / "arch.md").write_text("# arch\n", encoding="utf-8")
    file_types = load_file_types("claude")
    classified = classify_files(
        tmp_path,
        [tmp_path / "CLAUDE.md"],
        file_types,
        generic_scanning=True,
    )
    types = {cf.path.name: cf.file_type for cf in classified}
    assert types.get("CLAUDE.md") == "main"
    assert types.get("arch.md") == "generic"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_classify_files_generic_loading_is_session_start_when_main_links(tmp_path: Path) -> None:
    """A generic file reached from `main` inherits `loading: session_start` (derived from `link_source_type`)."""
    (tmp_path / "CLAUDE.md").write_text("Read [arch](arch.md).\n", encoding="utf-8")
    (tmp_path / "arch.md").write_text("# arch\n", encoding="utf-8")
    file_types = load_file_types("claude")
    classified = classify_files(
        tmp_path,
        [tmp_path / "CLAUDE.md"],
        file_types,
        generic_scanning=True,
    )
    arch = next((cf for cf in classified if cf.path.name == "arch.md"), None)
    assert arch is not None
    assert arch.properties.get("loading") == "session_start"
