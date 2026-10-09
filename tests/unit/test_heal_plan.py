"""The plan's scripted edits, the plan builder and the conformance check."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.heal.conformance import check_plan
from reporails_cli.core.heal.plan import apply_edits, build_plan
from reporails_cli.core.heal.transforms import (
    code,
    dedupe,
    direct,
    italic,
    move,
    negation_form,
    split_or_reason,
    unbold,
)
from reporails_cli.core.mapper.annotate import check_specificity
from reporails_cli.core.platform.dto.heal_plan import Edit, Plan, PlanOp, Slot
from reporails_cli.core.platform.dto.ruleset import Atom, AtomSlots


def _split_edit(op: PlanOp, atoms: Any, lines: Any) -> Edit | None:
    """The edit `split_or_reason` makes, or None when it refuses."""
    outcome = split_or_reason(op, atoms, lines)
    return outcome if isinstance(outcome, Edit) else None


F = "a.md"


def _atom(text: str, line: int = 1, charge: int = -1, fmt: str = "prose", pi: int = 0, **kw: object) -> Atom:
    named, tokens, unformatted, _, bold = check_specificity(text)[0], *check_specificity(text)[1:]
    return Atom(
        line=line,
        text=text,
        kind="excitation",
        charge={-1: "CONSTRAINT", 0: "NEUTRAL", 1: "DIRECTIVE"}[charge],
        charge_value=charge,
        modality="direct",
        specificity=named,
        format=fmt,
        file_path=F,
        position_index=pi,
        named_tokens=tokens,
        unformatted_code=unformatted,
        bold_tokens=bold,
        **kw,  # type: ignore[arg-type]
    )


def _op(kind: str, line: int = 1, pi: int | None = None, **expect: object) -> PlanOp:
    return PlanOp("CORE:C:0058", F, line, pi, kind, dict(expect))  # type: ignore[arg-type]


def _lines(*text: str) -> list[str]:
    return [t + "\n" for t in text]


SPLIT_1 = "*Never file a `note` outside `notes/<team>/`; never reintroduce the per-repo `<repo>` segment.*"
SPLIT_2 = "*Do not preload a fixed trinity or walk the whole corpus — resolve only the named entries.*"
TASKCTL_19 = (
    "Invoke `taskctl` to author or mutate any entry and to decide any schema/conformance/roadmap state \u2014 "
    "never hand-author frontmatter, never assert a `taskctl`-decidable state by inspection. `/taskctl` is the "
    "user-invocable surface for the taskctl tool; each intent maps to one command and to the per-capability "
    "workflow whose `## Steps` are authoritative (`taskctl-authoring` / `taskctl-lifecycle` / `taskctl-schema` / "
    "`taskctl-validation` / `taskctl-operational`). It is a **standalone utility skill**, outside the v2 team-roster "
    '\u2014 the roster\'s grain is "skills delegate to taskctl".'
)
TASKCTL_21 = (
    "Run `taskctl <args>` from any cwd under the umbrella \u2014 the PATH shim `scripts/taskctl` walks up to the "
    "root and runs `taskctl` SOURCE via `uv run --directory <root>/taskctl`, so no cwd-relative "
    "root-path guess is needed "
    "(this closes the `root/taskctl` `os error 2` FM, where a wrong relative guess failed and the grounding check "
    "was abandoned). The explicit `uv run --directory <root>/taskctl taskctl <args>` form still works at or near the "
    "root. *Never install `taskctl` into a team venv \u2014 run the PATH shim or `uv run --directory` (unset "
    "`VIRTUAL_ENV`); never abandon a `taskctl` command that errors on a path guess \u2014 re-run it as "
    "`taskctl <args>`.*"
)


def _pieces(*texts: str, fmt: str = "prose", predicate: bool = True, objects: bool = True, **kw: object) -> list[Atom]:
    """One atom per text, as the mapper cuts a packed sentence: each with its own predicate and object span."""
    slots = AtomSlots(predicate_span=(0, 1) if predicate else None, object_span=(1, 3) if objects else None)
    return [_atom(t, fmt=fmt, pi=i, slots=slots, **kw) for i, t in enumerate(texts)]


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    ("line", "texts", "after"),
    [
        (
            SPLIT_1,
            (
                "*Never file a `note` outside `notes/<team>/`;*",
                "*never reintroduce the per-repo `<repo>` segment.*",
            ),
            "*Never file a `note` outside `notes/<team>/`.* *Never reintroduce the per-repo `<repo>` segment.*",
        ),
        (
            SPLIT_2,
            ("*Do not preload a fixed trinity or walk the whole corpus \u2014*", "*resolve only the named entries.*"),
            "*Do not preload a fixed trinity or walk the whole corpus.* *Resolve only the named entries.*",
        ),
        (
            "Run the tests; fix every failure.",
            ("Run the tests;", "fix every failure."),
            "Run the tests. Fix every failure.",
        ),
        (
            "- Run the tests \u2014 fix every failure.",
            ("Run the tests \u2014", "fix every failure."),
            "- Run the tests. Fix every failure.",
        ),
        (
            "Run the tests, and fix every failure.",
            ("Run the tests, and", "fix every failure."),
            "Run the tests. Fix every failure.",
        ),
    ],
)
def test_split_writes_each_instruction_atom_as_its_own_sentence(line: str, texts: tuple[str, ...], after: str) -> None:
    atoms = _pieces(*texts, fmt="list" if line.startswith("- ") else "prose")
    edit = _split_edit(_op("split"), atoms, _lines(line))
    assert edit is not None
    assert (edit.before, edit.after) == (line, after)


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    ("line", "texts", "flags"),
    [
        ("Run the tests; see the guide.", ("Run the tests;", "see the guide."), {"predicate": False}),
        ("Run the tests, then fix every failure.", ("Run the tests,", "fix every failure."), {}),
        ("Do not push keys; or share tokens.", ("Do not push keys;", "share tokens."), {}),
        ("Run `a; b` for the check.", ("Run `a;", "b` for the check."), {}),
    ],
)
def test_split_leaves_a_piece_without_its_own_predicate_or_a_bare_joint_to_a_decision(
    line: str, texts: tuple[str, ...], flags: dict[str, bool]
) -> None:
    assert _split_edit(_op("split"), _pieces(*texts, **flags), _lines(line)) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_split_leaves_a_piece_sharing_its_siblings_object_to_a_decision() -> None:
    line = "Run the tests; fix every failure."
    first, second = _pieces("Run the tests;", "fix every failure.")
    second.slots = AtomSlots(predicate_span=(0, 1))
    assert _split_edit(_op("split"), [first, second], _lines(line)) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_split_leaves_a_neutral_atom_of_the_sentence_to_a_decision() -> None:
    line = "Run the tests; fix every failure."
    atoms = [_atom("Run the tests;", pi=0, slots=_pieces("x")[0].slots), _atom("fix every failure.", charge=0, pi=1)]
    assert _split_edit(_op("split"), atoms, _lines(line)) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_split_refuses_a_lead_in() -> None:
    line = "Run the tests; fix every failure:"
    atoms = _pieces("Run the tests;", "fix every failure:", lead_in=True)
    assert _split_edit(_op("split"), atoms, _lines(line)) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_split_keeps_a_step_that_starts_with_then_with_the_step_before_it() -> None:
    line = "Run the tests, then fix every failure."
    assert _split_edit(_op("split"), _pieces("Run the tests,", "then fix every failure."), _lines(line)) is None
    plan = build_plan([_op("split")], {F: _pieces("Run the tests,", "then fix every failure.")}, {F: _lines(line)})
    assert plan.edits == () and [s.change for s in plan.slots] == ["split-keep-sequence"]


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_split_still_cuts_two_independent_prohibitions_apart() -> None:
    line = "*Never commit generated files; never push to the main branch.*"
    atoms = _pieces("*Never commit generated files;*", "*never push to the main branch.*")
    edit = _split_edit(_op("split"), atoms, _lines(line))
    assert edit is not None
    assert edit.after == "*Never commit generated files.* *Never push to the main branch.*"


def _slot_change(atoms: list[Atom], line: str) -> str:
    plan = build_plan([_op("split")], {F: atoms}, {F: _lines(line)})
    assert plan.edits == ()
    (slot,) = plan.slots
    return slot.change


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_refused_split_of_a_lead_in_allows_keeping_the_lead_in() -> None:
    atoms = _pieces("Run the tests;", "fix every failure:", lead_in=True)
    assert _slot_change(atoms, "Run the tests; fix every failure:") == "split-keep-lead-in"


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_refused_split_of_pieces_sharing_an_object_allows_repeating_it() -> None:
    first, second = _pieces("Run the tests;", "fix every failure.")
    first.slots = AtomSlots(predicate_span=(0, 3), object_span=(1, 3), object="the tests")
    second.slots = AtomSlots(predicate_span=(0, 3))
    assert _slot_change([first, second], "Run the tests; fix every failure.") == "split-repeat:the tests"


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_refused_split_with_an_unreadable_object_allows_no_change() -> None:
    first, second = _pieces("Run the tests;", "fix every failure.")
    second.slots = AtomSlots(predicate_span=(0, 1))
    assert _slot_change([first, second], "Run the tests; fix every failure.") == ""


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_refused_split_inside_a_list_allows_giving_each_item_its_verb() -> None:
    line = "Read the file, sort it, run the tests."
    atoms = _pieces("Read the file, sort it,", "run the tests.")
    assert _slot_change(atoms, line) == "split-series"


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_refused_split_that_drops_a_condition_allows_repeating_it() -> None:
    line = "When the build fails, run the tests; never push."
    first, second = _pieces("When the build fails, run the tests;", "never push.")
    first.charge, first.charge_value, first.scope_conditional = "DIRECTIVE", 1, True
    assert _slot_change([first, second], line) == "split-keep-condition"


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_refused_split_that_drops_only_a_scope_allows_no_change() -> None:
    line = "Review the notes before opinions form; never push."
    first, second = _pieces("Review the notes before opinions form;", "never push.")
    first.slots = AtomSlots(predicate_span=(0, 1), object_span=(1, 3), scope_span=(3, 6))
    assert _slot_change([first, second], line) == ""


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_then_step_after_a_list_allows_keeping_the_step_not_repeating_verbs() -> None:
    line = "Brief each reviewer to load its notes, read the source completely, then apply its bar."
    atoms = _pieces("Brief each reviewer to load its notes,", "read the source completely,", "then apply its bar.")
    assert _slot_change(atoms, line) == "split-keep-sequence"


@pytest.mark.integration
@pytest.mark.subsys_heal
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("line", "change"),
    [
        (
            "Seed that data into a cross-team review before opinions form, and read a failing check as a broken "
            "tool to fix per `check-guide` and `review-guide`.",
            "",
        ),
        (
            "Brief each reviewer to `/load` its notes, read the source completely, then apply its bar to the source.",
            "split-keep-sequence",
        ),
    ],
)
def test_a_refused_real_split_names_only_the_change_that_fits(tmp_path: Path, line: str, change: str) -> None:
    _, atoms, lines, _ = _mapped(tmp_path, f"# Notes\n\n{line}\n")
    name = atoms[0].file_path
    plan = build_plan([PlanOp("CORE:C:0058", name, 3, None, "split", {})], {name: atoms}, {name: lines})
    assert plan.edits == ()
    assert [s.change for s in plan.slots] == [change]


def _mapped(tmp_path: Path, text: str) -> tuple[Path, list[Atom], list[str], Any]:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    path = tmp_path / "SKILL.md"
    path.write_text(text, encoding="utf-8")
    ruleset = map_ruleset([path], models=get_models(), root=tmp_path, cache_dir=None)
    return path, list(ruleset.atoms), _lines(*text.split("\n")[:-1]), ruleset


@pytest.mark.integration
@pytest.mark.subsys_heal
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("line", "lead", "after"),
    [
        (
            TASKCTL_19,
            "Invoke `taskctl`",
            "Invoke `taskctl` to author or mutate any entry and to decide any schema/conformance/roadmap state. "
            "Never hand-author frontmatter. Never assert a `taskctl`-decidable state by inspection. ",
        ),
        (
            TASKCTL_21,
            "*Never install",
            "*Never install `taskctl` into a team venv.* *Run the PATH shim or `uv run --directory` (unset "
            "`VIRTUAL_ENV`).* *Never abandon a `taskctl` command that errors on a path guess \u2014 re-run it as "
            "`taskctl <args>`.*",
        ),
    ],
)
def test_split_cuts_a_real_packed_line_at_its_atoms_and_keeps_every_instruction(
    tmp_path: Path, line: str, lead: str, after: str
) -> None:
    from reporails_cli.core.heal.preservation import compare, take_snapshot

    text = f"# Taskctl\n\n{line}\n"
    path, atoms, lines, ruleset = _mapped(tmp_path, text)
    pi = next(a.position_index for a in atoms if a.line == 3 and a.text.startswith(lead))
    name = atoms[0].file_path
    plan = build_plan([PlanOp("CORE:C:0058", name, 3, pi, "split", {})], {name: atoms}, {name: lines})
    assert [(e.line, e.op) for e in plan.edits] == [(3, "split")]
    assert after in plan.edits[0].after
    new_text = "".join(apply_edits(lines, plan.edits)[0][i] + "\n" for i in range(len(lines)))
    snap = take_snapshot(str(path), text, ruleset, 5.0)
    path.write_text(new_text, encoding="utf-8")
    _, new_atoms, new_lines, new_map = _mapped(tmp_path, new_text)
    assert check_plan(plan, {name: lines}, {name: new_lines}, {name: new_atoms}) == []
    assert compare(snap, new_map, new_text, 5.0)["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_a_refused_split_of_a_real_line_names_the_object_to_repeat(tmp_path: Path) -> None:
    _, atoms, lines, _ = _mapped(tmp_path, "# Loader\n\nRead the config file first; restart afterwards.\n")
    name = atoms[0].file_path
    plan = build_plan([PlanOp("CORE:C:0058", name, 3, None, "split", {})], {name: atoms}, {name: lines})
    assert plan.edits == ()
    assert [s.change for s in plan.slots] == ["split-repeat:the config file first"]


_THEN_LINE = (
    "*Do not silently skip an entry that fails to load \u2014 name the missing key and the paths tried, "
    "then ask the maintainer; do not add a fallback path \u2014 the loader is strict.*"
)


@pytest.mark.integration
@pytest.mark.subsys_heal
@pytest.mark.requires_model
@pytest.mark.parametrize("line", [_THEN_LINE, "Run the tests, then fix every failure."])
def test_split_keeps_a_real_then_step_with_the_step_before_it(tmp_path: Path, line: str) -> None:
    _, atoms, lines, _ = _mapped(tmp_path, f"# Loader\n\n{line}\n")
    name = atoms[0].file_path
    plan = build_plan([PlanOp("CORE:C:0058", name, 3, None, "split", {})], {name: atoms}, {name: lines})
    assert plan.edits == ()
    assert [(s.line, s.op) for s in plan.slots] == [(3, "split")]


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_negation_form_swaps_a_leading_never_even_inside_emphasis() -> None:
    line = "*Never bypass `reviewer` on cross-release work.*"
    edit = negation_form(_op("negation-form"), [_atom(line)], _lines(line))
    assert edit is not None
    assert edit.after == "*Do not bypass `reviewer` on cross-release work.*"
    plain = "Do not bypass `reviewer`."
    assert negation_form(_op("negation-form"), [_atom(plain)], _lines(plain)) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_unbold_turns_a_bold_term_of_a_constraint_into_italic() -> None:
    line = "The mirror view is the **inverse** of this surface and must not be edited."
    edit = unbold(_op("unbold"), [_atom(line)], _lines(line))
    assert edit is not None
    assert edit.after == "The mirror view is the *inverse* of this surface and must not be edited."
    directive = unbold(_op("unbold"), [_atom(line, charge=1)], _lines(line))
    assert directive is not None and directive.after == edit.after


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_italic_and_code_run_the_existing_fixers_on_the_one_atom() -> None:
    line = "Never push to main."
    edit = italic(_op("italic"), [_atom(line)], _lines(line))
    assert edit is not None
    assert edit.after == "*Never push to main.*"
    raw = "Open settings.json and edit it."
    edit = code(_op("code"), [_atom(raw, charge=1)], _lines(raw))
    assert edit is not None
    assert edit.after == "Open `settings.json` and edit it."


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    ("line", "after"),
    [
        ("Try to run the linter first.", "Run the linter first."),
        ("You should run the linter first.", "Run the linter first."),
        ("- Please run the linter first.", "- Run the linter first."),
        ("Perhaps run the linter first.", "Run the linter first."),
    ],
)
def test_direct_drops_a_leading_hedge(line: str, after: str) -> None:
    atom = _atom(line.removeprefix("- "), charge=1, fmt="list" if line.startswith("- ") else "prose")
    edit = direct(_op("direct"), [atom], _lines(line))
    assert edit is not None
    assert edit.after == after


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    "line", ["Prefer real objects over mocks.", "Consider running the linter.", "Try not to mock."]
)
def test_direct_leaves_prefer_consider_and_try_not_to_for_a_rewrite(line: str) -> None:
    assert direct(_op("direct"), [_atom(line, charge=1)], _lines(line)) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_move_places_a_whole_list_item_after_the_anchor_in_the_same_list() -> None:
    lines = _lines("- Run the tests.", "- Lint the code.", "- Tag the release.")
    atoms = [_atom(t.strip("- \n"), line=n, charge=1, fmt="list", list_depth=1) for n, t in enumerate(lines, 1)]
    edit = move(_op("move", line=1, after=[F, 3, 0]), atoms, lines)
    assert edit is not None
    assert apply_edits(lines, [edit])[0] == ["- Lint the code.", "- Tag the release.", "- Run the tests."]
    assert move(_op("move", line=1, after=[F, 2, 0]), atoms[:1] + atoms[2:], lines) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_move_refuses_across_two_paragraphs() -> None:
    lines = _lines("Run the tests.", "", "Lint the code.")
    atoms = [_atom("Run the tests.", charge=1), _atom("Lint the code.", line=3, charge=1)]
    assert move(_op("move", line=1, after=[F, 3, 0]), atoms, lines) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_dedupe_deletes_a_list_line_naming_the_partners_tokens_and_no_others() -> None:
    lines = _lines("- Run `pytest` first.", "- Always run `pytest` before commit.", "- Run `ruff` too.")
    atoms = [_atom(t[2:].strip(), line=n, charge=1, fmt="list", list_depth=1) for n, t in enumerate(lines, 1)]
    edit = dedupe(_op("dedupe", line=2), atoms, lines, atoms[0])
    assert edit is not None
    assert apply_edits(lines, [edit])[0] == ["- Run `pytest` first.", "- Run `ruff` too."]
    assert dedupe(_op("dedupe", line=3), atoms, lines, atoms[0]) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_build_plan_scripts_what_applies_and_slots_the_rest() -> None:
    lines = _lines(SPLIT_2, "Keep notes short.", "Elaborate here.")
    first = _pieces(
        "*Do not preload a fixed trinity or walk the whole corpus \u2014*", "*resolve only the named entries.*"
    )
    atoms = [
        *first,
        _atom("Keep notes short.", line=2, charge=1, pi=2),
        _atom("Elaborate here.", line=3, charge=1, pi=3),
    ]
    ops = [
        _op("split", 1),
        _op("negation-form", 1),
        _op("elaborate", 3),
        _op("charge", 2),
        _op("split", 9),
        _op("together", 1),
    ]
    plan = build_plan(ops, {F: atoms}, {F: lines})
    assert [(e.line, e.op) for e in plan.edits] == [(1, "split")]
    assert [(s.line, s.op, s.bound, s.text) for s in plan.slots] == [
        (1, "negation-form", "line", " ".join(a.text for a in first)),
        (2, "charge", "line", "Keep notes short."),
        (3, "elaborate", "section", "Elaborate here."),
    ]
    assert [(r.op.line, r.reason) for r in plan.refused] == [(9, "stale map")]


def _split_plan() -> tuple[Plan, list[str], Atom]:
    lines = _lines("Run the tests; fix every failure.", "", "Keep notes short.")
    atoms = _pieces("Run the tests;", "fix every failure.")
    plan = build_plan([_op("split")], {F: atoms}, {F: lines})
    assert len(plan.edits) == 1
    return plan, lines, atoms[0]


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_conformance_accepts_a_file_rewritten_as_planned() -> None:
    plan, lines, _ = _split_plan()
    new = ["Run the tests. Fix every failure.", "", "Keep notes short."]
    atoms = [_atom("Run the tests."), _atom("Fix every failure.")]
    assert check_plan(plan, {F: lines}, {F: new}, {F: atoms}) == []


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_conformance_flags_an_edit_that_changes_an_extra_line() -> None:
    plan, lines, _ = _split_plan()
    new = ["Run the tests. Fix every failure.", "", "Keep notes brief."]
    found = check_plan(plan, {F: lines}, {F: new}, {F: [_atom("Run the tests.")]})
    assert [(d.line, d.op, d.expected, d.found) for d in found] == [(3, "outside", "same", "changed")]


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_conformance_flags_a_split_that_leaves_two_instructions_in_one_sentence() -> None:
    plan, lines, _ = _split_plan()
    new = ["Run the tests. Fix every failure.", "", "Keep notes short."]
    packed = [_atom("Run the tests and fix every failure.", charge=1)]
    found = check_plan(plan, {F: lines}, {F: new}, {F: packed})
    assert [(d.op, d.expected, d.found) for d in found] == [("split", "instr:1", "instr:2")]


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_conformance_flags_an_edit_line_not_written_as_planned_and_lets_slot_lines_change() -> None:
    plan, lines, _ = _split_plan()
    plan = Plan(plan.edits, (Slot(F, 3, None, "charge", "r", "Keep notes short.", "line"),), ())
    new = ["Run the tests, fix every failure.", "", "Keep notes brief."]
    found = check_plan(plan, {F: lines}, {F: new}, {F: []})
    assert [(d.line, d.op, d.expected) for d in found] == [(1, "split", "after")]


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_conformance_holds_line_shifts_from_a_move_and_a_dedupe() -> None:
    lines = _lines("- Run `pytest` first.", "- Always run `pytest` before commit.", "- Run `ruff` too.", "- Tag it.")
    atoms = [_atom(t[2:].strip(), line=n, charge=1, fmt="list", list_depth=1) for n, t in enumerate(lines, 1)]
    ops = [_op("dedupe", 2, keep=[F, 1]), _op("move", 4, after=[F, 1, 0])]
    plan = build_plan(ops, {F: atoms}, {F: lines}, partner_atoms={(F, 1): atoms[0]})
    assert [e.op for e in plan.edits] == ["dedupe", "move"]
    new = ["- Run `pytest` first.", "- Tag it.", "- Run `ruff` too."]
    assert check_plan(plan, {F: lines}, {F: new}, {F: atoms}) == []
    wrong = ["- Run `pytest` first.", "- Run `ruff` too.", "- Tag it."]
    assert [d.op for d in check_plan(plan, {F: lines}, {F: wrong}, {F: atoms})] != []


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_edit_dataclass_spans_the_lines_it_covers() -> None:
    assert Edit(F, 2, "a\nb", "c", "italic", "r").span == 2


@pytest.mark.integration
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_mapped_text_is_split_negated_and_conforms(tmp_path: Path) -> None:
    from reporails_cli.core.mapper.pipeline import map_ruleset

    path = tmp_path / "CLAUDE.md"
    text = f"# Rules\n\n{SPLIT_1}\n\n{SPLIT_2}\n\n*Never bypass `reviewer` on cross-release work.*\n"
    path.write_text(text, encoding="utf-8")
    atoms = list(map_ruleset([path]).atoms)
    name = atoms[0].file_path
    lines = _lines(*text.split("\n")[:-1])
    ops = [_op("split", 3), _op("split", 5), _op("negation-form", 7)]
    plan = build_plan([PlanOp(o.rule, name, o.line, o.pi, o.op, o.expect) for o in ops], {name: atoms}, {name: lines})
    assert [(e.line, e.op) for e in plan.edits] == [(3, "split"), (5, "split"), (7, "negation-form")]
    new_text = "".join(apply_edits(lines, plan.edits)[0][i] + "\n" for i in range(len(lines)))
    path.write_text(new_text, encoding="utf-8")
    new_atoms = list(map_ruleset([path]).atoms)
    assert check_plan(plan, {name: lines}, {name: new_text.split("\n")[:-1]}, {name: new_atoms}) == []


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_conformance_accepts_an_italic_fix_on_an_instruction_over_two_lines() -> None:
    lines = _lines("Never commit secrets to the", "repository.")
    edit = Edit(
        F, 1, "Never commit secrets to the\nrepository.", "*Never commit secrets to the\nrepository.*", "italic", "R"
    )
    new = ["*Never commit secrets to the", "repository.*"]
    assert check_plan(Plan(edits=(edit,)), {F: lines}, {F: new}, {F: []}) == []


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_conformance_accepts_a_dedupe_whose_kept_copy_is_in_the_same_file() -> None:
    old = ["# T", "- Run `make test` first.", "- Other", "- Run `make test` first."]
    edit = Edit(F, 4, "- Run `make test` first.", None, "dedupe", "R")
    plan = Plan(edits=(edit,))
    new = ["# T", "- Run `make test` first.", "- Other"]
    assert check_plan(plan, {F: _lines(*old)}, {F: new}, {F: []}) == []
    assert [d.found for d in check_plan(plan, {F: _lines(*old)}, {F: old}, {F: []})] != []
