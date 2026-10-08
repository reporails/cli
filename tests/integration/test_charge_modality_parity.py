"""Charge + modality parity fixture — real bundled model, hand-labelled cases.

A per-example regression guard for the charge classifier: a small set of
representative instruction sentences whose correct signed charge and modality
class are hand-labelled, asserted against the real bundled model. It reddens if a
change silently shifts the charge sign or the modality class on a known case,
complementing the aggregate accuracy check.

Real model, no stubs — a parity claim over a mocked classifier means nothing.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.bio_tagger import tag_atom_multislot

# (sentence, expected signed charge, expected modality) — hand-labelled, then
# confirmed against the real decode. Each row is an independent semantic
# expectation, not a frozen snapshot of arbitrary output.
_CASES: list[tuple[str, int, str]] = [
    ("Never push to main.", -1, "absolute"),
    ("Always run the tests before committing.", +1, "absolute"),
    ("Do not use mocks in integration tests.", -1, "imperative"),
    ("You must validate every input.", +1, "absolute"),
    ("Run `uv run poe qa_fast` before committing.", +1, "imperative"),
    ("The pipeline reads markdown files.", 0, "none"),
    ("Avoid global mutable state.", -1, "imperative"),
    ("Consider caching the result when the input is large.", +1, "hedged"),
    ("You should prefer composition over inheritance.", +1, "hedged"),
    ("Delete the temporary directory after the run.", +1, "imperative"),
]

_MODALITY_VALUES = {"imperative", "direct", "absolute", "hedged", "none"}


@pytest.mark.integration
@pytest.mark.subsys_map
@pytest.mark.requires_model
@pytest.mark.parametrize(("text", "charge", "modality"), _CASES)
def test_charge_modality_parity(text: str, charge: int, modality: str) -> None:
    """Real decode reproduces the hand-labelled charge sign + modality class."""
    t = tag_atom_multislot(text)
    assert t.polarity == charge, f"charge regressed on {text!r}: got {t.polarity:+d}, want {charge:+d}"
    assert t.modality == modality, f"modality regressed on {text!r}: got {t.modality!r}, want {modality!r}"


@pytest.mark.integration
@pytest.mark.subsys_map
@pytest.mark.requires_model
@pytest.mark.parametrize(("text", "charge", "modality"), _CASES)
def test_charge_modality_invariants(text: str, charge: int, modality: str) -> None:
    """The charge↔modality invariant holds: a neutral atom carries `none`, a charged one never does."""
    t = tag_atom_multislot(text)
    assert t.modality in _MODALITY_VALUES
    if t.polarity == 0:
        assert t.modality == "none", f"neutral atom must carry modality=none on {text!r}"
    else:
        assert t.modality != "none", f"charged atom must not carry modality=none on {text!r}"


# Shipped-path cases: tokenize without charge splits, then the charge decode with its floors,
# exactly as the mapper runs them. A line that opens with a quoted term is running text, not a
# quotation, so the imperative it carries survives the structural floor.
_SHIPPED_PATH_CASES: list[tuple[str, int, str]] = [
    (
        '"Feature creep" is a known failure mode for this codebase; '
        "flag it early if a new abstraction starts pulling in responsibilities that belong elsewhere.",
        +1,
        "imperative",
    ),
    ('"Never push to main."', 0, "none"),  # a whole-line quotation stays neutral
    ("**Important** — always run `pytest` before pushing.", +1, "absolute"),
    ("**Warning** - do not run migrations on production.", -1, "imperative"),
    ("**Critical**: use `uv run` for every Python invocation.", +1, "imperative"),
    ("**Widget**: a small reusable UI element.", 0, "none"),  # a real definition stays neutral
    ("See docs/testing.md, and never skip the integration tests.", -1, "absolute"),
    ("See docs/testing.md; never skip the integration tests.", -1, "absolute"),
    ("See docs/testing.md.", 0, "none"),  # a bare pointer stays neutral
    ("See the build and deploy guide.", 0, "none"),  # a pointer's object is a title, not a command
    ("See the runbook, which never changes.", 0, "none"),  # a relative clause is not an instruction
    ("No changes needed here; run `pytest` before merging.", +1, "imperative"),
    ("No changes needed here.", 0, "none"),  # a bare status stays neutral
    ("`make test` — run it before every commit.", +1, "imperative"),
    ("`make test` — runs the whole suite.", 0, "none"),  # a command reference stays neutral
    ("Regenerate `dist/` with `make build` after source changes where possible.", +1, "hedged"),
    ("Regenerate `dist/` with `make build` after source changes if possible.", +1, "hedged"),
    ("Regenerate `dist/` with `make build` after source changes whenever possible.", +1, "hedged"),
    ("Regenerate `dist/` with `make build` after source changes when possible.", +1, "hedged"),
    ("Regenerate `dist/` with `make build` as soon as possible.", +1, "imperative"),  # urgency, not a hedge
    ("It's best not to edit files under `dist/` by hand.", -1, "hedged"),
    ("It is best not to edit files under `dist/` by hand.", -1, "hedged"),
    ("It's best to regenerate `dist/` with `make build` after source changes.", +1, "hedged"),
    ("It is best to regenerate `dist/` with `make build` after source changes.", +1, "hedged"),
    ("Set theory underlies the proof in this chapter.", 0, "none"),
    ("Cache misses slow the build down.", 0, "none"),
    ("Build artifacts with `make`.", +1, "imperative"),
]


@pytest.mark.integration
@pytest.mark.subsys_map
@pytest.mark.requires_model
@pytest.mark.parametrize(("text", "charge", "modality"), _SHIPPED_PATH_CASES)
def test_shipped_path_charge(text: str, charge: int, modality: str) -> None:
    from reporails_cli.core.mapper.bio_pipeline import apply_multislot
    from reporails_cli.core.mapper.parse import tokenize

    atoms = apply_multislot(tokenize(text + "\n", "structure"))
    assert len(atoms) == 1, [a.text for a in atoms]
    assert atoms[0].charge_value == charge, f"got {atoms[0].charge} on {text!r}"
    assert atoms[0].modality == modality


# Whole-pipeline cases (structure-aware tokenize, then the charge decode): (line, signed charge, modality).
# A hedge phrase inside a code span is a command's text, not the author's wording; a pronoun or wh-word
# after an ambiguous opening verb ends the subject, so the line is an order.
_PIPELINE_CASES: list[tuple[str, int, str]] = [
    ("- Run `make where possible`.", +1, "imperative"),
    ("- `It's best to` is a phrase we flag.", 0, "none"),
    ("- Regenerate `dist/` with `make build` after source changes where possible.", +1, "hedged"),
    ("- `make test` — fix flaky tests you can reproduce", +1, "imperative"),
    ("- **pytest** — test changes you can reproduce locally", +1, "imperative"),
    ("- `ails check` — remove whatever is unused", +1, "imperative"),
    ("- `make test` — fix the broken tests first", +1, "imperative"),
]


@pytest.mark.integration
@pytest.mark.subsys_map
@pytest.mark.requires_model
@pytest.mark.parametrize(("line", "charge", "modality"), _PIPELINE_CASES)
def test_pipeline_reads_code_span_hedges_and_pronoun_subjects(line: str, charge: int, modality: str) -> None:
    from reporails_cli.core.mapper.bio_pipeline import apply_multislot
    from reporails_cli.core.mapper.parse import tokenize

    atoms = apply_multislot(tokenize(line + "\n", "structure-aware"))
    assert len(atoms) == 1, [a.text for a in atoms]
    assert (atoms[0].charge_value, atoms[0].modality) == (charge, modality), (
        f"{line!r}: got {atoms[0].charge} {atoms[0].modality!r}"
    )
