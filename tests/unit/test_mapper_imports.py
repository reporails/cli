"""Behavioral tests for `core/mapper/imports.py`.

Covers two behaviours:

- Binary/non-markdown `@path` references (`.png`, `.pdf`, …) must NOT be
  expanded — a deny-list can only ever miss extensions one at a time; the fix
  inverts to an allow-list of markdown-compatible extensions.
- A repeated `@import` of the same file, as SIBLINGS in the same content,
  must expand at every occurrence — the prior global `visited` set treated a
  sibling repeat as already-visited and left the second occurrence literal.
  A real cycle (a file importing an ancestor still being expanded) must still
  be caught.
- M4 line-translation companion (`expand_imports_with_line_map`) is covered
  in `test_pipeline_import_lines.py`, since it is pipeline-facing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper.imports import expand_imports, expand_imports_with_line_map

# --- non-markdown extensions stay literal ------------------------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_png_reference_not_expanded(tmp_path: Path) -> None:
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\nBINARYGARBAGE\x00\x01")
    src = tmp_path / "main.md"
    content = "Load the asset @assets/logo.png now."
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\nBINARYGARBAGE\x00\x01")
    result = expand_imports(content, src)
    assert result == content
    assert "PNG" not in result and "BINARYGARBAGE" not in result


@pytest.mark.unit
@pytest.mark.subsys_map
def test_pdf_reference_not_expanded(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "spec.pdf").write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3garbage")
    src = tmp_path / "main.md"
    content = "See @docs/spec.pdf for details."
    result = expand_imports(content, src)
    assert result == content
    assert "PDF" not in result


@pytest.mark.unit
@pytest.mark.subsys_map
def test_svg_zip_jpg_references_not_expanded(tmp_path: Path) -> None:
    for name, body in (("icon.svg", b"<svg></svg>"), ("bundle.zip", b"PK\x03\x04"), ("photo.jpg", b"\xff\xd8\xff")):
        (tmp_path / "assets" / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "assets" / name).write_bytes(body)
    src = tmp_path / "main.md"
    content = "@assets/icon.svg @assets/bundle.zip @assets/photo.jpg"
    result = expand_imports(content, src)
    assert result == content


@pytest.mark.unit
@pytest.mark.subsys_map
def test_markdown_extensions_still_expand(tmp_path: Path) -> None:
    """Guard: the allow-list flip must not regress the extensions that DO expand.

    Slash-qualified paths are used for `.mdc`/`.markdown`/`.mdx` — the bare-name
    branch of `IMPORT_REF_RE` only recognizes a trailing `.md`; that regex shape
    is unrelated to this finding (`_resolve_import_target`'s extension gate) and
    is left untouched.
    """
    (tmp_path / "a.md").write_text("MD-BODY", encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "b.mdc").write_text("MDC-BODY", encoding="utf-8")
    (docs / "c.markdown").write_text("MARKDOWN-BODY", encoding="utf-8")
    (docs / "d.mdx").write_text("MDX-BODY", encoding="utf-8")
    (tmp_path / "README").write_text("README-BODY", encoding="utf-8")
    src = tmp_path / "main.md"
    content = "@a.md @docs/b.mdc @docs/c.markdown @docs/d.mdx @README"
    result = expand_imports(content, src)
    for body in ("MD-BODY", "MDC-BODY", "MARKDOWN-BODY", "MDX-BODY", "README-BODY"):
        assert body in result


# --- sibling repeats expand; real cycles are still caught --------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repeated_sibling_import_expands_both_occurrences(tmp_path: Path) -> None:
    (tmp_path / "b.md").write_text("SHARED-BODY", encoding="utf-8")
    main = tmp_path / "main.md"
    content = "First: @b.md\nSecond: @b.md\n"
    result = expand_imports(content, main)
    assert result.count("SHARED-BODY") == 2, result


@pytest.mark.unit
@pytest.mark.subsys_map
def test_real_cycle_still_detected_and_left_literal(tmp_path: Path) -> None:
    a = tmp_path / "a.md"
    b = tmp_path / "b.md"
    a.write_text("A-BODY @b.md", encoding="utf-8")
    b.write_text("B-BODY @a.md", encoding="utf-8")
    result = expand_imports(a.read_text(encoding="utf-8"), a)
    # b's expansion is spliced in, but b's own @a.md reference is a cycle
    # (a.md is still on the ancestor stack) and must stay literal.
    assert "B-BODY" in result
    assert "@a.md" in result
    # The cycle reference must not have re-spliced a's own body a second time.
    assert result.count("A-BODY") == 1


# --- inline-code false positive: an `@path`-shaped reference inside a code
# span must not expand, even when it doesn't sit at the span's start ---------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_at_path_inside_inline_code_not_expanded(tmp_path: Path) -> None:
    """`IMPORT_REF_RE`'s lookbehind only excludes a match starting immediately
    after a backtick; an `@path`-shaped reference elsewhere inside the span
    (`npx @reporails/cli check .`) was still treated as an import."""
    (tmp_path / "reporails").mkdir()
    (tmp_path / "reporails" / "cli").write_text("SHOULD-NOT-EXPAND", encoding="utf-8")
    src = tmp_path / "main.md"
    content = "Run `npx @reporails/cli check .` to lint your repo."
    result = expand_imports(content, src)
    assert result == content
    assert "SHOULD-NOT-EXPAND" not in result


@pytest.mark.unit
@pytest.mark.subsys_map
def test_at_path_outside_code_still_expands(tmp_path: Path) -> None:
    """Guard: masking inline code must not blind real imports outside a span."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("GUIDE-BODY", encoding="utf-8")
    src = tmp_path / "main.md"
    content = "Run `npx @reporails/cli check .` then read @docs/guide.md for setup."
    result = expand_imports(content, src)
    assert "GUIDE-BODY" in result


@pytest.mark.unit
@pytest.mark.subsys_map
def test_at_path_in_fenced_block_still_skipped_alongside_inline_code(tmp_path: Path) -> None:
    """Guard: the pre-existing fenced-block skip must keep working alongside the
    new inline-code mask. Both referenced targets are real files, so either one
    expanding would show up in the result."""
    (tmp_path / "x.md").write_text("FENCE-SHOULD-NOT-EXPAND", encoding="utf-8")
    (tmp_path / "reporails").mkdir()
    (tmp_path / "reporails" / "cli").write_text("INLINE-SHOULD-NOT-EXPAND", encoding="utf-8")
    src = tmp_path / "main.md"
    content = "```\n@x.md\n```\nRun `npx @reporails/cli check .` now."
    result = expand_imports(content, src)
    assert result == content
    assert "FENCE-SHOULD-NOT-EXPAND" not in result
    assert "INLINE-SHOULD-NOT-EXPAND" not in result


@pytest.mark.unit
@pytest.mark.subsys_map
def test_inline_code_mask_does_not_change_line_map(tmp_path: Path) -> None:
    """The line map must be unaffected by inline-code masking: no import inside
    or outside a code span on these lines means every line keeps its own number
    (the identity map)."""
    src = tmp_path / "main.md"
    content = "Run `npx @reporails/cli check .` here.\nSee @docs/guide.md there.\n"
    expanded, line_map = expand_imports_with_line_map(content, src)
    assert expanded == content  # neither reference resolves to a real file -> unexpanded
    assert line_map == [1, 2, 3]
