"""A directive and a prohibition joined in one sentence are two instructions, while one instruction
written with commas or a descriptive negation stays whole; line-level charge of labels and statements."""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper import bio_pipeline
from reporails_cli.core.mapper.classify import classify_charge
from reporails_cli.core.mapper.parse import tokenize

_needs_model = pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")


def _mapped(text: str) -> list:
    return [a for a in bio_pipeline.apply_multislot(list(tokenize(text))) if a.kind != "heading"]


def _signs(text: str) -> list[int]:
    return sorted(a.charge_value for a in _mapped(text))


# A directive joined to a prohibition reads as two instructions, the prohibition keeping its -1.
_SPLIT_CASES = [
    "Only fetch the temperature, do not perform any transformations",
    "Fetch BOTH sources — never skip either",
    "Read the whole file, do not skim it",
    "Prefer composition; avoid deep inheritance",
]

# One instruction written with commas, a neutral lead, or a descriptive negation stays ONE atom.
_WHOLE_CASES = [
    "Write clean, readable, well-tested code",  # commas, one instruction
    "When editing, never commit secrets",  # neutral scope + one -1
    "Engine code should never reference an agent name",  # modal negation, one clause
    "The limitations must describe what checks do vs don't do",  # 'vs' idiom
    "Run the tests before committing your changes",  # single directive
    "This is the reviewer role, focused on correctness",  # neutral
]


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
@pytest.mark.parametrize("text", _SPLIT_CASES)
def test_directive_prohibition_compound_splits(text: str) -> None:
    signs = _signs(text)
    assert len(signs) == 2 and -1 in signs, f"{text!r} -> {signs}"


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
@pytest.mark.parametrize("text", _WHOLE_CASES)
def test_same_charge_or_declarative_stays_whole(text: str) -> None:
    atoms = _mapped(text)
    assert len(atoms) == 1, f"{text!r} fragmented into {[a.text for a in atoms]}"


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_parenthetical_negation_is_not_a_boundary() -> None:
    # A prohibition marker inside parentheses is an inline example, not a cut.
    md = "Only FILE a research observation (never a solo re-implementation) if a gap survives"
    assert len(_mapped(md)) == 1


# Reference/meta-label lines describe or point at a source — never an instruction.
_META_NEUTRAL_CASES = [
    "Knowledge: see `docs/guides/changelog-policy.md` for the policy",
    "Open question: keep as a single doc or split into two",
    "See also: the onboarding guide",
    "Reference: docs/architecture.md",
    "Overview: the pipeline runs in eight stages",
    "Security: see docs/threat-model.md",  # bare noun label fronting a pointer
]

# Colon-led lines that DO carry a charge must stay charged — the meta-label guard
# is scoped to non-instructive label words only.
_META_CONTROL_CASES = [
    "Note: always run the tests before committing",  # Note is not a meta-label
    "When editing: never commit secrets",  # conditional + real -1
]

# Past-tense narration and bare "No <noun>" status fragments command nothing —
# they must resolve neutral instead of being confidently charged.
_NON_INSTRUCTION_NEUTRAL_CASES = [
    "On 2026-05-10 I proposed a rewrite of the module",  # date-led narration
    "I retired the legacy path last week",  # first-person past
    "We shipped the fix",  # first-person-plural past
    "No regressions.",  # bare status fragment
    "No penalty.",  # bare status fragment
    "No open issues",  # named status phrase
    "No known issues",  # named status phrase
    "No cloud dependencies",  # named status phrase
    "No setup required.",  # named status phrase
    "No drift detected on the tracked dimensions",  # named status phrase + complement
]

# Real prohibitions must stay charged. The bare-status guard covers the one-word
# form (`No regressions.`) and the named status phrases (`No open issues`) — a
# `No <thing>` line naming anything else forbids that thing, complement or not.
_REAL_PROHIBITION_CASES = [
    "No blank lines between sections",
    "No hardcoded secrets in code",
    "Never commit secrets",
    "No console.log",
    "No hardcoded secrets",
    "No blank lines",
]

# A `<Label>: see <ref>` cross-reference floors only behind a bare noun label. A
# clause that commands something keeps its charge, colon and pointer notwithstanding.
_LABELLED_CLAUSE_CHARGED_CASES = [
    "Never commit secrets: see security.md",
    "Always run the linter first: see docs/lint.md",
    "Do not skip tests: see CONTRIBUTING.md",
    # A bare noun label, but an instruction rides after the reference — the
    # tokenize-time verdict is final on the model-less path, so it must agree
    # with the post-head floor and keep the charge.
    "Security: see the runbook, and never commit a credential.",
]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("text", _META_NEUTRAL_CASES)
def test_reference_meta_label_is_neutral(text: str) -> None:
    atoms = [a for a in tokenize(text, "legacy") if a.kind != "heading"]
    assert all(a.charge_value == 0 for a in atoms), f"{text!r} -> {[a.charge_value for a in atoms]}"


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("text", _META_CONTROL_CASES)
def test_charged_colon_line_stays_charged(text: str) -> None:
    atoms = [a for a in tokenize(text, "legacy") if a.kind != "heading"]
    assert any(a.charge_value != 0 for a in atoms), f"{text!r} wrongly neutralised"


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("text", _NON_INSTRUCTION_NEUTRAL_CASES)
def test_narration_and_bare_no_are_neutral(text: str) -> None:
    atoms = [a for a in tokenize(text, "legacy") if a.kind != "heading"]
    assert all(a.charge_value == 0 for a in atoms), f"{text!r} -> {[a.charge_value for a in atoms]}"


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("text", _REAL_PROHIBITION_CASES)
def test_real_prohibition_stays_charged(text: str) -> None:
    atoms = [a for a in tokenize(text, "legacy") if a.kind != "heading"]
    assert any(a.charge_value != 0 for a in atoms), f"{text!r} wrongly neutralised"


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("text", _LABELLED_CLAUSE_CHARGED_CASES)
def test_instruction_before_a_see_pointer_stays_charged(text: str) -> None:
    atoms = [a for a in tokenize(text, "legacy") if a.kind != "heading"]
    assert any(a.charge_value != 0 for a in atoms), f"{text!r} wrongly neutralised"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_pointer_reference_title_with_and_is_still_a_pointer() -> None:
    # `and` inside a reference title is not a clause break — the line still points.
    atoms = [a for a in tokenize("Knowledge: see the build and deploy guide", "legacy") if a.kind != "heading"]
    assert all(a.charge_value == 0 for a in atoms), [(a.text, a.charge_value) for a in atoms]


# The deterministic classifier is the discriminator the neutral floor and the map
# validator share, so it is asserted directly, not only through the tokenizer.
_CLASSIFY_STATUS_CASES = ["No regressions.", "No changes.", "None.", "No open issues", "No drift detected —"]
_CLASSIFY_PROHIBITION_CASES = [
    "No console.log",
    "No hardcoded secrets",
    "No blank lines",
    "No console.log in production code",
]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("text", _CLASSIFY_STATUS_CASES)
def test_classify_charge_reads_a_status_line_neutral(text: str) -> None:
    assert classify_charge(text)[1] == 0, f"{text!r} -> {classify_charge(text)}"


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("text", _CLASSIFY_PROHIBITION_CASES)
def test_classify_charge_reads_a_terse_prohibition_constraint(text: str) -> None:
    assert classify_charge(text)[1] == -1, f"{text!r} -> {classify_charge(text)}"


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_colon_label_is_not_a_charge_boundary() -> None:
    # A colon after a label is structural: the label stays with its instruction, the prohibition is its own.
    md = "**How to apply:** always verify claims, never speculate"
    signs = _signs(md)
    assert -1 in signs and 1 in signs
