"""Unit tests for the Markdown link-walker — REQ-025 Phase C."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.classify.link_walker import walk_markdown_links

FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "generic-classification"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_finds_inline_md_targets(tmp_path: Path) -> None:
    main = tmp_path / "main.md"
    target = tmp_path / "linked.md"
    main.write_text("Read [the notes](linked.md).\n", encoding="utf-8")
    target.write_text("# notes\n", encoding="utf-8")
    reached = walk_markdown_links({main}, tmp_path, {main})
    assert reached == {target.resolve()}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_skips_urls_and_anchors(tmp_path: Path) -> None:
    main = tmp_path / "main.md"
    main.write_text(
        "URL [example](https://example.com)\nanchor [section](#section)\nmailto [link](mailto:nobody@example.com)\n",
        encoding="utf-8",
    )
    assert walk_markdown_links({main}, tmp_path, {main}) == set()


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_skips_out_of_tree(tmp_path: Path) -> None:
    main = tmp_path / "project" / "main.md"
    main.parent.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("# outside\n", encoding="utf-8")
    main.write_text("Goes [outside](../outside.md).\n", encoding="utf-8")
    reached = walk_markdown_links({main}, main.parent, {main})
    assert reached == set()


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_handles_cycle(tmp_path: Path) -> None:
    a = tmp_path / "a.md"
    b = tmp_path / "b.md"
    a.write_text("Goes to [b](b.md).\n", encoding="utf-8")
    b.write_text("Goes to [a](a.md).\n", encoding="utf-8")
    reached = walk_markdown_links({a}, tmp_path, {a})
    # b is reached; a is already-classified so it does not enter `found`.
    assert reached == {b.resolve()}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_markdown_links_skips_already_classified(tmp_path: Path) -> None:
    main = tmp_path / "main.md"
    rule = tmp_path / "rule.md"
    main.write_text("See [rule](rule.md).\n", encoding="utf-8")
    rule.write_text("# rule\n", encoding="utf-8")
    # rule is already-classified; walker must not re-include it.
    reached = walk_markdown_links({main}, tmp_path, {main, rule})
    assert reached == set()


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
def test_classify_files_generic_loading_is_on_demand(tmp_path: Path) -> None:
    """Generic files default to `loading: on_demand` so they don't pollute
    base-context cross-file analysis. See DIAGNOSTIC.md cross-file matrix."""
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
    assert arch.properties.get("loading") == "on_demand"
