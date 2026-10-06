"""Mutation-killing behavioral tests for core/mapper/imports.py survivors.

Only the import-depth cap carries an observable contract here. The other two
survivors are equivalent mutants and are documented rather than decorated:

  - L70 `target.resolve(strict=False)`: `False -> True` only changes whether a
    missing/broken path raises inside the `try`. Either way the target is
    rejected — `strict=True` raises OSError (caught, returns None) and
    `strict=False` falls through to the `is_file()` guard (also returns None).
    For an existing file both resolve identically, so no input changes the
    result — equivalent.
  - L110 `start <= pos < end` in `_in_code_block`: `<=`->`<` differs only when an
    `@import` reference position equals a fenced block's start position. The
    fence begins with a backtick/tilde delimiter, never `@`, so `pos == start`
    never occurs and the boundary never decides — equivalent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper.imports import _MAX_IMPORT_DEPTH, expand_imports


# --- expand_imports: recursion depth cap (L102) ---------------------------
@pytest.mark.unit
@pytest.mark.subsys_map
def test_expand_stops_at_max_depth(tmp_path: Path) -> None:
    (tmp_path / "child.md").write_text("HELLO", encoding="utf-8")
    src = tmp_path / "main.md"
    result = expand_imports("@child.md", src, depth=_MAX_IMPORT_DEPTH)
    # At exactly the cap, expansion must stop and leave the reference verbatim.
    # `>=`->`>` would expand one hop past the cap and splice in the child body.
    assert result == "@child.md"
    assert "HELLO" not in result
