"""Mutation-killing behavioral tests for core/classify/link_walker.py survivors.

Covers the BFS depth cap and the URL/mailto guards on link-target resolution.
Two survivors are equivalent mutants and documented rather than decorated:

  - L36 `@dataclass(frozen=True)` on LinkEdge: LinkEdge is only ever stored as a
    dict *value* and read for its `.target`; it is never hashed or used as a set
    member / dict key, so `frozen -> False` changes nothing observable.
  - L122 `start <= pos < end` in `_in_code_span`: `<=`->`<` differs only when a
    link's `[` position equals an inline-code span's opening-backtick position.
    A link's `[` can never coincide with a `` ` ``, so `pos == start` never
    occurs and the boundary never decides — equivalent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify.link_walker import (
    _looks_like_url,
    _resolve_md_target,
    walk_markdown_links,
)


def _targets(edges: list) -> set[Path]:
    return {edge.target for edge in edges}


# --- walk_markdown_links: depth cap (L72) ---------------------------------
@pytest.mark.unit
@pytest.mark.subsys_classify
def test_walk_stops_at_max_depth(tmp_path: Path) -> None:
    a = tmp_path / "a.md"
    b = tmp_path / "b.md"
    c = tmp_path / "c.md"
    a.write_text("Read [b](b.md).\n", encoding="utf-8")
    b.write_text("Read [c](c.md).\n", encoding="utf-8")
    c.write_text("# c\n", encoding="utf-8")
    edges = walk_markdown_links({a: "main"}, tmp_path, {a}, max_depth=1)
    targets = _targets(edges)
    assert b.resolve() in targets
    # `>=`->`>` would walk one level deeper and reach c.md beyond max_depth.
    assert c.resolve() not in targets


# --- _resolve_md_target: URL guard (L160) ---------------------------------
@pytest.mark.unit
@pytest.mark.subsys_classify
def test_resolve_md_target_rejects_url_ending_in_md(tmp_path: Path) -> None:
    # `or`->`and` on `not cleaned or _looks_like_url(cleaned)` stops rejecting
    # URLs, so a remote .md URL is wrongly resolved as a local target.
    assert _resolve_md_target(tmp_path, "https://example.com/doc.md") is None


# --- _looks_like_url: mailto branch (L175) --------------------------------
@pytest.mark.unit
@pytest.mark.subsys_classify
def test_looks_like_url_detects_mailto() -> None:
    # `or`->`and` would require BOTH "://" and a mailto prefix; a bare mailto:
    # link (no "://") would then read as a normal target.
    assert _looks_like_url("mailto:a@b.com") is True
