"""Mutation-killing tests for heal/mechanical_fixers.py.

Seam tests over the boundary conditions of each fixer: link-span overlap bounds,
line-index bounds, the constraint/kind guards, and the already-italic guard.
Also the dry-run write gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.heal.mechanical_fixers import (
    _fix_one_file,
    _wrap_site,
    fix_bold_on_constraints,
    fix_italic_constraints,
    fix_unformatted_code,
)
from reporails_cli.core.mapper.annotate import check_specificity
from reporails_cli.core.mapper.structure import LineSpans
from reporails_cli.core.platform.dto.ruleset import Atom


def _atom(
    line: int,
    text: str = "",
    *,
    charge_value: int = 0,
    position_index: int = 0,
    kind: str = "paragraph",
    unformatted_code: list[str] | None = None,
    file_path: str = "CLAUDE.md",
) -> Atom:
    return Atom(
        line=line,
        text=text,
        kind=kind,
        charge="CONSTRAINT" if charge_value < 0 else "DIRECTIVE" if charge_value > 0 else "NEUTRAL",
        charge_value=charge_value,
        modality="none",
        specificity="abstract",
        unformatted_code=unformatted_code or [],
        bold_tokens=check_specificity(text)[4],
        position_index=position_index,
        file_path=file_path,
    )


# ──────────────────────────────────────────────────────────────────
# _wrap_site link-span bounds  (L55 <=, >=)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_wrap_token_immediately_before_link() -> None:
    # Token ends exactly where the link starts (m.end() == span start): must still wrap.
    assert _wrap_site("npm[a](b)", "npm", LineSpans.of_fragment("npm[a](b)")) == (0, 3)  # kills L55 <=→<


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_wrap_token_immediately_after_link() -> None:
    # Token starts exactly where the link ends (m.start() == span end): must still wrap.
    assert _wrap_site("[a](b)npm", "npm", LineSpans.of_fragment("[a](b)npm")) == (6, 9)  # kills L55 >=→>


# ──────────────────────────────────────────────────────────────────
# fix_unformatted_code line-index bounds  (L70 or, >=)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_unformatted_code_out_of_range_line_skipped() -> None:
    lines = ["only line\n", "second line\n"]
    # atom.line == len(lines)+1 → idx == len(lines): must be skipped, not indexed.
    atom = _atom(len(lines) + 1, "third", unformatted_code=["third"])
    fixes = fix_unformatted_code([atom], lines)
    assert fixes == []
    assert lines == ["only line\n", "second line\n"]  # kills L70 or→and and >=→>


# ──────────────────────────────────────────────────────────────────
# fix_bold_on_constraints  (L109 guard, L112 bounds, L128 change guard)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_bold_converts_bold_to_italic_on_constraint() -> None:
    lines = ["Keep the **foo** value.\n"]
    atom = _atom(1, lines[0], charge_value=-1)
    fixes = fix_bold_on_constraints([atom], lines)
    assert lines[0] == "Keep the *foo* value.\n"  # kills L109 !=→== and L128 !=→==
    assert len(fixes) == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_bold_out_of_range_line_skipped() -> None:
    lines = ["Keep the **foo** value.\n"]
    atom = _atom(len(lines) + 1, "Keep the **foo** value.", charge_value=-1)
    fixes = fix_bold_on_constraints([atom], lines)
    assert fixes == []
    assert lines == ["Keep the **foo** value.\n"]  # kills L112 or→and and >=→>


# ──────────────────────────────────────────────────────────────────
# fix_italic_constraints  (L157 heading guard, L160 bounds, L175 italic guard)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_italic_wraps_paragraph_constraint() -> None:
    lines = ["Do not skip the tests\n"]
    atom = _atom(1, lines[0], charge_value=-1, kind="paragraph")
    fix_italic_constraints([atom], lines)
    assert lines[0] == "*Do not skip the tests*\n"  # kills L157 (skips paragraph) and L175 and2→or


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_italic_leaves_heading_constraint_untouched() -> None:
    lines = ["Do not skip the tests\n"]
    atom = _atom(1, lines[0], charge_value=-1, kind="heading")
    fixes = fix_italic_constraints([atom], lines)
    assert fixes == []
    assert lines[0] == "Do not skip the tests\n"  # kills L157 ==→! (would wrap a heading)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_italic_out_of_range_line_skipped() -> None:
    lines = ["Do not skip the tests\n"]
    atom = _atom(len(lines) + 1, "Do not skip the tests", charge_value=-1, kind="paragraph")
    fixes = fix_italic_constraints([atom], lines)
    assert fixes == []
    assert lines == ["Do not skip the tests\n"]  # kills L160 or→and and >=→>


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_italic_leaves_line_with_unpaired_leading_star_untouched() -> None:
    # An opening `*` with no closing partner: wrapping would double it into `**…*`.
    lines = ["*partial italic start\n"]
    atom = _atom(1, lines[0], charge_value=-1, kind="paragraph")
    fixes = fix_italic_constraints([atom], lines)
    assert fixes == []
    assert lines[0] == "*partial italic start\n"


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "line",
    ["- **Never commit state files**\n", "- **Set NO_PROXY appropriately**\n", "**Set NO_PROXY appropriately**\n"],
)
def test_fix_bold_leaves_a_line_that_is_bold_throughout(line: str) -> None:
    lines = [line]
    fixes = fix_bold_on_constraints([_atom(1, line.strip("- \n"), charge_value=-1)], lines)
    assert fixes == []
    assert lines[0] == line


# ──────────────────────────────────────────────────────────────────
# _fix_one_file dry-run write gate  (L322 and→or)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fix_one_file_dry_run_does_not_write(tmp_path: Path) -> None:
    p = tmp_path / "CLAUDE.md"
    p.write_text("Keep the **foo** value.\n", encoding="utf-8")
    atom = _atom(1, "Keep the **foo** value.", charge_value=-1, file_path=str(p))
    fixes = _fix_one_file(p, [atom], {"bold"}, dry_run=True)
    assert len(fixes) == 1  # the fix is computed
    # dry_run → file must be left untouched. L322 and→or would write it.
    assert p.read_text(encoding="utf-8") == "Keep the **foo** value.\n"
