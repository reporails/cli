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
def test_walk_markdown_links_finds_backtick_wrapped_link_text(tmp_path: Path) -> None:
    """Regression: a link whose text is backtick-wrapped (`[`name`](path)`) — a
    common form where the link text names a command, skill, or construct — must
    still be walked. Previously code-span stripping ran before link matching and deleted
    the `` `name` `` text, leaving `[](path)` which the link regex could not
    match, so every such link was silently dropped (0 edges on real corpora)."""
    main = tmp_path / "main.md"
    target = tmp_path / "linked.md"
    main.write_text("See [`the notes`](linked.md).\n", encoding="utf-8")
    target.write_text("# notes\n", encoding="utf-8")
    edges = walk_markdown_links({main: "main"}, tmp_path, {main})
    assert _reached_targets(edges) == {target.resolve()}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_skips_link_shown_as_inline_code_example(tmp_path: Path) -> None:
    """A whole link wrapped in inline code (`` `[text](path)` ``) is a literal
    documentation example, not a real link — it must NOT be walked."""
    main = tmp_path / "main.md"
    example = tmp_path / "example.md"
    main.write_text("Write a link like `[text](example.md)` in docs.\n", encoding="utf-8")
    example.write_text("# example\n", encoding="utf-8")
    edges = walk_markdown_links({main: "main"}, tmp_path, {main})
    assert edges == []


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
    # Markdown link `[arch](arch.md)` classifies the target as `referenced`
    # (discoverable, not auto-loaded by the harness).
    assert types.get("arch.md") == "referenced"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_classify_files_referenced_loading_is_discoverable_when_link_from_main(tmp_path: Path) -> None:
    """A file reached only via `[text](path)` link is `loading: discoverable` regardless of source eagerness."""
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
    # Harness doesn't auto-load `[text](path)` targets; they're discoverable
    # only. Eager-source dominance (main/memory/subagent_memory) no longer
    # applies to link-only reach — only `@<path>` imports get session_start.
    assert arch.properties.get("loading") == "discoverable"
    assert arch.file_type == "referenced"
