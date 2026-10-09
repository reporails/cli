"""A scripted split never ends a sentence partway through its series, never detaches a fallback from the
condition it hangs on, and drops the joining `and` of a two-item compound; the keyed heal puts back a file
whose written result fails the rewrite check."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.heal.plan import build_plan
from reporails_cli.core.heal.transforms import split_or_reason
from reporails_cli.core.platform.dto.heal_plan import Edit, PlanOp
from reporails_cli.core.platform.dto.ruleset import Atom, AtomSlots

LINES: dict[str, str] = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "heal_split_defect_lines.json").read_text(encoding="utf-8")
)


def _split_edit(op: PlanOp, atoms: Any, lines: Any) -> Edit | None:
    """The edit `split_or_reason` makes, or None when it refuses."""
    outcome = split_or_reason(op, atoms, lines)
    return outcome if isinstance(outcome, Edit) else None


F = "a.md"


def _mapped(tmp_path: Path, text: str) -> tuple[list[Atom], list[str]]:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    path = tmp_path / "SKILL.md"
    path.write_text(text, encoding="utf-8")
    ruleset = map_ruleset([path], models=get_models(), root=tmp_path, cache_dir=None)
    return list(ruleset.atoms), [t + "\n" for t in text.split("\n")[:-1]]


@pytest.mark.integration
@pytest.mark.subsys_heal
@pytest.mark.requires_model
@pytest.mark.parametrize("name", sorted(LINES))
def test_split_leaves_a_series_cut_or_a_detached_condition_to_a_decision(tmp_path: Path, name: str) -> None:
    atoms, lines = _mapped(tmp_path, f"# T\n\n{LINES[name]}\n")
    op = PlanOp("CORE:C:0058", atoms[0].file_path, 3, None, "split", {})
    assert _split_edit(op, atoms, lines) is None
    plan = build_plan([op], {atoms[0].file_path: atoms}, {atoms[0].file_path: lines})
    assert not plan.edits
    assert [s.op for s in plan.slots] == ["split"]


def _piece(text: str, pi: int, charge: int = 1, slots: AtomSlots | None = None, **kw: Any) -> Atom:
    return Atom(
        line=1,
        text=text,
        kind="excitation",
        charge="DIRECTIVE" if charge > 0 else "CONSTRAINT",
        charge_value=charge,
        modality="direct",
        specificity="abstract",
        file_path=F,
        position_index=pi,
        slots=slots or AtomSlots(predicate_span=(0, 1), object_span=(1, 3)),
        **kw,
    )


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_split_drops_the_joining_and_of_a_two_item_compound() -> None:
    atoms = [_piece("Run the tests,", 0), _piece("and fix every failure.", 1)]
    edit = _split_edit(
        PlanOp("CORE:C:0058", F, 1, None, "split", {}), atoms, ["Run the tests, and fix every failure.\n"]
    )
    assert edit is not None
    assert edit.after == "Run the tests. Fix every failure."


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_split_cuts_a_series_when_every_item_is_its_own_sentence() -> None:
    line = "Read the file, run the tests, and tag the release."
    atoms = [_piece("Read the file,", 0), _piece("run the tests,", 1), _piece("and tag the release.", 2)]
    edit = _split_edit(PlanOp("CORE:C:0058", F, 1, None, "split", {}), atoms, [line + "\n"])
    assert edit is not None
    assert edit.after == "Read the file. Run the tests. Tag the release."


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_split_refuses_a_series_with_two_items_on_one_lead_verb() -> None:
    line = "Read the file, classify it, and tag the release."
    atoms = [_piece("Read the file, classify it,", 0), _piece("and tag the release.", 1)]
    assert _split_edit(PlanOp("CORE:C:0058", F, 1, None, "split", {}), atoms, [line + "\n"]) is None


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_split_refuses_a_piece_cut_off_the_scope_the_sentence_before_it_sets() -> None:
    line = "Never claim fit; mark it outside the circle."
    scoped = AtomSlots(predicate_span=(0, 1), object_span=(1, 3), scope_span=(3, 5))
    atoms = [_piece("Never claim fit;", 0, -1, slots=scoped), _piece("mark it outside the circle.", 1)]
    assert _split_edit(PlanOp("CORE:C:0058", F, 1, None, "split", {}), atoms, [line + "\n"]) is None
