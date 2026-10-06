"""Links and `@path` imports are read from the markdown parse: code is never a link or an import.

A fenced block (any fence length, tildes, inside a list item, unclosed), an indented code block and a
code span (single or double backtick) hold documentation, not links or imports; a link whose text is
a code span, and a reference definition, are links.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify.link_walker import _outgoing_links
from reporails_cli.core.lint.mechanical.checks_advanced import (
    check_markdown_link_targets_exist,
    extract_imports,
    extract_markdown_links,
    import_depth,
)
from reporails_cli.core.mapper.imports import expand_imports, import_refs
from reporails_cli.core.mapper.structure import code_ranges, link_targets
from reporails_cli.core.platform.dto.models import ClassifiedFile

_CODE = [
    pytest.param("````\n```\n[a](t.md) @t.md\n```\n````\n", id="longer-fence-with-shorter-fence-inside"),
    pytest.param("~~~\n[a](t.md) @t.md\n~~~\n", id="tilde-fence"),
    pytest.param("see ``[a](t.md)`` and ``@t.md`` here\n", id="double-backtick-span"),
    pytest.param("run `[a](t.md)` and `@t.md` now\n", id="single-backtick-span"),
    pytest.param("para\n\n    [a](t.md) @t.md\n", id="indented-code-block"),
    pytest.param("- item\n  ```\n  [a](t.md) @t.md\n  ```\n", id="fence-inside-list-item"),
    pytest.param("```\n[a](t.md) @t.md\n", id="unclosed-fence"),
    pytest.param("> quoted `[a](t.md)`\n> more `@t.md` text\n", id="spans-in-blockquote"),
    pytest.param("| a | b |\n|---|---|\n| `[a](t.md)` | `@t.md` |\n", id="spans-in-table-cells"),
]


def _classified(root: Path, text: str) -> tuple[Path, list[ClassifiedFile]]:
    (root / "t.md").write_text("# target\n", encoding="utf-8")
    doc = root / "CLAUDE.md"
    doc.write_text(text, encoding="utf-8")
    return doc, [ClassifiedFile(path=doc, file_type="main")]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("text", _CODE)
def test_code_holds_no_link_or_import(text: str, tmp_path: Path) -> None:
    doc, classified = _classified(tmp_path, text)
    assert link_targets(text) == []
    assert import_refs(text) == []
    assert _outgoing_links(doc) == []
    assert not (extract_markdown_links(tmp_path, {}, classified).annotations or {})
    assert not (extract_imports(tmp_path, {}, classified).annotations or {})
    assert expand_imports(text, doc) == text


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("text", _CODE)
def test_import_depth_skips_code(text: str, tmp_path: Path) -> None:
    (tmp_path / "t.md").write_text("@t.md\n")
    _doc, classified = _classified(tmp_path, text)
    assert import_depth(tmp_path, {"max": 0}, classified).passed


@pytest.mark.unit
@pytest.mark.subsys_map
def test_reference_definition_is_a_link_at_its_line(tmp_path: Path) -> None:
    text = "# T\n\n[ref]: t.md\n\nsee [text][ref]\n"
    doc, classified = _classified(tmp_path, text)
    assert link_targets(text) == [(3, "t.md")]
    assert [(p.name, verb) for p, verb in _outgoing_links(doc)] == [("t.md", "read")]
    annotations = extract_markdown_links(tmp_path, {}, classified).annotations
    assert annotations == {"discovered_markdown_links": ["CLAUDE.md::t.md::3"]}


@pytest.mark.unit
@pytest.mark.subsys_map
def test_unused_reference_definition_is_a_link() -> None:
    assert link_targets("[ref]: other.md\n") == [(1, "other.md")]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_link_whose_text_is_a_code_span_is_a_link(tmp_path: Path) -> None:
    text = "Use [`name`](t.md) here.\n"
    _doc, classified = _classified(tmp_path, text)
    assert link_targets(text) == [(1, "t.md")]
    assert extract_markdown_links(tmp_path, {}, classified).annotations == {
        "discovered_markdown_links": ["CLAUDE.md::t.md::1"]
    }


@pytest.mark.unit
@pytest.mark.subsys_map
def test_links_and_imports_beside_code_are_found(tmp_path: Path) -> None:
    text = "``a`` [one](t.md) `b` @t.md\n\n```\n[x](no.md)\n```\n\n- [two](t.md)\n"
    doc, _classified_files = _classified(tmp_path, text)
    assert link_targets(text) == [(1, "t.md"), (7, "t.md")]
    assert import_refs(text) == ["t.md"]
    assert sorted((p.name, verb) for p, verb in _outgoing_links(doc)) == [
        ("t.md", "imported"),
        ("t.md", "read"),
        ("t.md", "read"),
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_import_in_frontmatter_is_not_in_code() -> None:
    text = "---\nname: x\ndescription: see @docs/a.md\n---\n```\n@docs/b.md\n```\n"
    assert import_refs(text) == ["docs/a.md"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_code_span_ranges_cover_the_span_in_the_file() -> None:
    text = "item ``a `b` @x.md`` after `c`\n\n    indented\n"
    spans = [text[a:b] for a, b in code_ranges(text)]
    assert spans == ["``a `b` @x.md``", "`c`", "    indented\n"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_expansion_splices_import_after_a_code_span(tmp_path: Path) -> None:
    (tmp_path / "child.md").write_text("CHILD")
    src = tmp_path / "CLAUDE.md"
    text = "``@child.md`` then @child.md\n"
    assert expand_imports(text, src) == "``@child.md`` then CHILD\n"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_unmatched_backtick_run_is_not_code() -> None:
    text = "Do not use triple backticks (```) to enclose, then @a.md and `b`.\n"
    assert [text[a:b] for a, b in code_ranges(text)] == ["`b`"]
    assert import_refs(text) == ["a.md"]


def _write_docs(root: Path, *names: str) -> None:
    (root / "docs").mkdir()
    for name in names:
        (root / "docs" / name).write_text("# Doc\n", encoding="utf-8")


def _broken(root: Path, text: str) -> list[str]:
    _doc, classified = _classified(root, text)
    found = extract_markdown_links(root, {}, classified).annotations or {}
    result = check_markdown_link_targets_exist(root, found, classified)
    return [message for _where, message in result.occurrences or []]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_link_targets_are_the_path_as_written() -> None:
    text = '[a](docs/útmutató.md) [b](<docs/my notes.md>) [c](docs/arch.md "T")\n\n[ref]: <docs/a b.md>\n'
    assert [t for _line, t in link_targets(text)] == [
        "docs/útmutató.md",
        "docs/my notes.md",
        "docs/arch.md",
        "docs/a b.md",
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_links_to_existing_files_with_unusual_names_are_not_broken(tmp_path: Path) -> None:
    _write_docs(tmp_path, "útmutató.md", "my notes.md", "arch.md")
    text = (
        '[a](docs/útmutató.md)\n[b](<docs/my notes.md>)\n[c](docs/arch.md "Architecture")\n'
        "[d](docs/my%20notes.md)\n[e](docs/arch.md#top)\n[f](docs/missing.md)\n"
    )
    broken = _broken(tmp_path, text)
    assert len(broken) == 1
    assert "docs/missing.md" in broken[0]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_walker_reaches_a_non_ascii_linked_file(tmp_path: Path) -> None:
    _write_docs(tmp_path, "útmutató.md")
    doc, _classified_files = _classified(tmp_path, "See [guide](docs/útmutató.md).\n")
    assert _outgoing_links(doc) == [((tmp_path / "docs" / "útmutató.md").resolve(), "read")]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "text",
    [
        pytest.param("| a | b |\n|---|---|\n| `a \\| npx @s/p.md` | x |\n", id="escaped-pipe-in-cell-span"),
        pytest.param("| a | b |\n|---|---|\n| `x` `a \\| @s/p.md` | y |\n", id="escaped-pipe-after-other-span"),
    ],
)
def test_import_in_table_cell_span_with_escaped_pipe_is_code(text: str) -> None:
    assert import_refs(text) == []


@pytest.mark.unit
@pytest.mark.subsys_map
def test_import_beside_escaped_pipe_span_in_table_is_found() -> None:
    text = "| a | b |\n|---|---|\n| `a \\| b` @s/p.md | x |\n"
    assert import_refs(text) == ["s/p.md"]
