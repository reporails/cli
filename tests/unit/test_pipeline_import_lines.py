"""Behavioral tests for import line mapping: atom `line` after an `@import` must be the
importing file's OWN source line, not the import-EXPANDED line.

`pipeline._classify_file` expands imports, tokenizes the expanded content, and
translates every fresh atom's `line` back to source-file
coordinates via `imports.expand_imports_with_line_map` — BEFORE the per-file
cache `put`, so a cache hit and a cold tokenize agree.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper import pipeline as pl
from reporails_cli.core.mapper.imports import expand_imports_with_line_map


def _write_fixture(tmp_path: Path) -> Path:
    (tmp_path / "b.md").write_text(
        "Imported line one.\nImported line two.\nImported line three.",
        encoding="utf-8",
    )
    main = tmp_path / "main.md"
    main.write_text(
        "Setup step one.\n"
        "Setup step two.\n"
        "Setup step three.\n"
        "Setup step four.\n"
        "Setup step five.\n"
        "@b.md\n"
        "Never skip the final step.\n",
        encoding="utf-8",
    )
    return main


# --- expand_imports_with_line_map: the line-map primitive ------------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_line_map_attributes_import_content_to_reference_line(tmp_path: Path) -> None:
    main = _write_fixture(tmp_path)
    raw = main.read_text(encoding="utf-8")
    expanded, line_map = expand_imports_with_line_map(raw, main)

    expanded_lines = expanded.split("\n")
    # Sanity: the expansion did shift "Never skip..." down to expanded line 9,
    # the pre-fix (buggy) line number.
    never_skip_expanded_idx = next(i for i, ln in enumerate(expanded_lines) if "Never skip" in ln)
    assert never_skip_expanded_idx == 8  # 0-based -> expanded line 9

    # The line map takes it back to its OWN source line (7) in main.md.
    assert line_map[never_skip_expanded_idx] == 7

    # Every "Imported line ..." line is attributed to line 6 — the @b.md
    # reference's line in main.md — since it has no line of its own there.
    for i, ln in enumerate(expanded_lines):
        if ln.startswith("Imported line"):
            assert line_map[i] == 6, (ln, line_map[i])

    # Lines literal to main.md keep their own 1-based line number.
    for i in range(5):
        assert line_map[i] == i + 1


@pytest.mark.unit
@pytest.mark.subsys_map
def test_line_map_identity_when_no_imports(tmp_path: Path) -> None:
    content = "One.\nTwo.\nThree.\n"
    src = tmp_path / "plain.md"
    expanded, line_map = expand_imports_with_line_map(content, src)
    assert expanded == content
    assert line_map == [1, 2, 3, 4]  # trailing empty element from the final "\n"


# --- pipeline._classify_file: end-to-end atom.line translation -------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_classify_file_translates_import_shifted_atom_lines(tmp_path: Path) -> None:
    """Regression: pipeline.py tokenized the EXPANDED content and never translated
    `atom.line` back — every atom after an `@import` reported the wrong (expanded)
    line to the user. Demonstrated red against the pre-fix code (git-stashed
    imports.py/pipeline.py): 'Never skip...' landed at line 9, not 7."""
    main = _write_fixture(tmp_path)
    all_atoms: list = []
    atoms_needing_embed: list = []
    pl._classify_file(main, None, all_atoms, atoms_needing_embed, "legacy")

    by_text = {a.text: a.line for a in all_atoms}
    assert by_text["Never skip the final step."] == 7
    assert by_text["Setup step one."] == 1
    assert by_text["Setup step five."] == 5
    # Every atom sourced from inside b.md carries the @b.md reference's line (6).
    for text in ("Imported line one.", "Imported line two.", "Imported line three."):
        assert by_text[text] == 6, (text, by_text[text])


@pytest.mark.unit
@pytest.mark.subsys_map
def test_classify_file_no_imports_lines_unchanged(tmp_path: Path) -> None:
    plain = tmp_path / "plain.md"
    plain.write_text("Always do the thing.\nNever skip the check.\n", encoding="utf-8")
    all_atoms: list = []
    pl._classify_file(plain, None, all_atoms, [], "legacy")
    by_text = {a.text: a.line for a in all_atoms}
    assert by_text["Always do the thing."] == 1
    assert by_text["Never skip the check."] == 2


@pytest.mark.unit
@pytest.mark.subsys_map
def test_classify_file_position_index_order_preserved(tmp_path: Path) -> None:
    """Line translation must not reorder atoms — `position_index` still tracks
    emission order regardless of the (possibly out-of-source-order) line values."""
    main = _write_fixture(tmp_path)
    all_atoms: list = []
    pl._classify_file(main, None, all_atoms, [], "legacy")
    indices = [a.position_index for a in all_atoms]
    assert indices == sorted(indices)
