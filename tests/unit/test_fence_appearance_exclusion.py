"""A code_block atom's markdown is LITERAL, not rendered.

A fenced directive line the cascade recovers carries `format="code_block"` and its
raw text (`Never use **mock**`). The `**` is text typed inside a fence, not
rendered bold, so the rendered-appearance checks (bold-on-directive,
italic-constraints, unformatted-code) must NOT fire on it — while the
charge/count checks (has_constraint_atoms / has_directive_atoms, the fenced-
directive win) must still see it. These drive the REAL tokenizer end-to-end.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.lint.client_checks import run_client_checks
from reporails_cli.core.lint.content_queries import (
    has_constraint_atoms,
    has_directive_atoms,
    has_non_italic_constraints,
)
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.platform.dto.ruleset import RulesetMap


def _rm(md: str, path: str = "rules.md") -> RulesetMap:
    atoms = tokenize(md)
    for a in atoms:
        a.file_path = path
    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(),
        atoms=tuple(atoms),
    )


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fenced_constraint_appearance_fields_are_empty() -> None:
    # `Never use **mock**` is a CONSTRAINT carrying LITERAL `**`; the rendered-
    # appearance fields must stay empty so no bold/italic check can read them.
    atoms = tokenize("```\nNever use **mock** in the test suite.\n```\n")
    fenced = [a for a in atoms if a.format == "code_block"]
    assert fenced and fenced[0].charge_value == -1
    assert fenced[0].bold_tokens == []
    assert fenced[0].italic_tokens == []
    assert fenced[0].unformatted_code == []


@pytest.mark.unit
@pytest.mark.subsys_map
def test_italic_constraints_skips_fenced_constraint_but_count_holds() -> None:
    rm = _rm("```\nNever use **mock** in the test suite.\n```\n")
    # No italic-constraints violation (the literal `**` is not rendered bold)…
    assert has_non_italic_constraints(rm, "rules.md").found is False
    # …but the charge count still sees the fenced constraint.
    assert has_constraint_atoms(rm, "rules.md").found is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_client_bold_check_skips_fenced_directive_but_count_holds() -> None:
    rm = _rm("```\nAlways run the **full suite** before every commit.\n```\n")
    findings = run_client_checks(rm)
    assert not [f for f in findings if f.rule == "bold"]
    assert has_directive_atoms(rm, "rules.md").found is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_client_unformatted_check_skips_fenced_line() -> None:
    # A bare code-ish token inside a fence is already in a code container, so the
    # "wrap in backticks" appearance check must not fire on it.
    rm = _rm("```\nNever call rm -rf on the cache directory during a build.\n```\n")
    assert not [f for f in run_client_checks(rm) if f.rule == "format"]
