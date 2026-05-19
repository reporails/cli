"""Edge-attribution coverage for `walk_markdown_links`.

One edge per `(source, target)`, depth tracking, verb (read/imported),
cycle termination, and `source_type` propagation from the seed map.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify.link_walker import LinkEdge, walk_markdown_links


def _edges_to(edges: list[LinkEdge], target: Path) -> list[LinkEdge]:
    """Filter edges down to a specific target (paths are already resolved)."""
    resolved = target.resolve()
    return [e for e in edges if e.target == resolved]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_emits_one_edge_per_source(tmp_path: Path) -> None:
    """File A and file B both link to C → two edges with distinct sources."""
    a = tmp_path / "A.md"
    b = tmp_path / "B.md"
    c = tmp_path / "C.md"
    a.write_text("Read [C](C.md).\n", encoding="utf-8")
    b.write_text("Read [C](C.md).\n", encoding="utf-8")
    c.write_text("# c\n", encoding="utf-8")

    edges = walk_markdown_links({a: "main", b: "skill"}, tmp_path, {a, b})
    c_edges = _edges_to(edges, c)
    assert {e.source for e in c_edges} == {a.resolve(), b.resolve()}
    assert {e.source_type for e in c_edges} == {"main", "skill"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_depth_tracked_correctly(tmp_path: Path) -> None:
    """main -> mid.md -> leaf.md emits edges at depth 1 and depth 2."""
    main = tmp_path / "main.md"
    mid = tmp_path / "mid.md"
    leaf = tmp_path / "leaf.md"
    main.write_text("[m](mid.md)\n", encoding="utf-8")
    mid.write_text("[l](leaf.md)\n", encoding="utf-8")
    leaf.write_text("# leaf\n", encoding="utf-8")

    edges = walk_markdown_links({main: "main"}, tmp_path, {main})
    by_target = {edge.target: edge for edge in edges}
    assert by_target[mid.resolve()].depth == 1
    assert by_target[leaf.resolve()].depth == 2


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_verb_distinguishes_md_link_vs_import(tmp_path: Path) -> None:
    """Same file emits two edges with verbs `read` and `imported`."""
    main = tmp_path / "main.md"
    md_target = tmp_path / "a.md"
    import_target = tmp_path / "b.md"
    main.write_text("Link: [a](a.md)\nImport: @b.md\n", encoding="utf-8")
    md_target.write_text("# a\n", encoding="utf-8")
    import_target.write_text("# b\n", encoding="utf-8")

    edges = walk_markdown_links({main: "main"}, tmp_path, {main})
    verbs_by_target = {edge.target: edge.verb for edge in edges}
    assert verbs_by_target[md_target.resolve()] == "read"
    assert verbs_by_target[import_target.resolve()] == "imported"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_cycle_breaks(tmp_path: Path) -> None:
    """a <-> b emits two edges and terminates without recursion."""
    a = tmp_path / "a.md"
    b = tmp_path / "b.md"
    a.write_text("[b](b.md)\n", encoding="utf-8")
    b.write_text("[a](a.md)\n", encoding="utf-8")

    # Seed only `a` so `b` is reached and emits an edge back to `a`.
    edges = walk_markdown_links({a: "main"}, tmp_path, {a})
    # `a` is in classified_paths -> the b->a edge is filtered out.
    # Only the a->b edge survives.
    assert {(e.source, e.target) for e in edges} == {(a.resolve(), b.resolve())}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_cycle_with_both_seeded_terminates(tmp_path: Path) -> None:
    """Pure cycle protection: both files seeded, walker still terminates."""
    a = tmp_path / "a.md"
    b = tmp_path / "b.md"
    a.write_text("[b](b.md)\n", encoding="utf-8")
    b.write_text("[a](a.md)\n", encoding="utf-8")

    edges = walk_markdown_links({a: "main", b: "main"}, tmp_path, {a, b})
    # Both are in classified_paths -> no generic edges emitted.
    assert edges == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_source_type_propagates(tmp_path: Path) -> None:
    """Seed map's file_type lands on the emitted edge's source_type."""
    skill = tmp_path / "SKILL.md"
    readme = tmp_path / "README.md"
    skill.write_text("[r](README.md)\n", encoding="utf-8")
    readme.write_text("# readme\n", encoding="utf-8")

    edges = walk_markdown_links({skill: "skill"}, tmp_path, {skill})
    assert len(edges) == 1
    assert edges[0].source_type == "skill"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_max_depth_cuts_off(tmp_path: Path) -> None:
    """Chain a -> b -> c -> d at max_depth=3 reaches d (depth 3), not beyond."""
    a = tmp_path / "a.md"
    b = tmp_path / "b.md"
    c = tmp_path / "c.md"
    d = tmp_path / "d.md"
    e = tmp_path / "e.md"
    a.write_text("[b](b.md)\n", encoding="utf-8")
    b.write_text("[c](c.md)\n", encoding="utf-8")
    c.write_text("[d](d.md)\n", encoding="utf-8")
    d.write_text("[e](e.md)\n", encoding="utf-8")
    e.write_text("# e\n", encoding="utf-8")

    edges = walk_markdown_links({a: "main"}, tmp_path, {a}, max_depth=3)
    reached = {edge.target for edge in edges}
    assert d.resolve() in reached
    assert e.resolve() not in reached
