"""An instruction and the list of things it introduces are one instruction.

`Audit these surfaces:` followed by a list of files is one instruction whose object is the list: the
lead-in is not a four-word instruction and the items are not context around it. The items stay lines
of their file, so what is checked line by line (a code name without backticks) is still reported where
it stands. A list that gives commands is left alone: each command is an instruction of its own.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.client_checks import _check_unformatted_code
from reporails_cli.core.mapper import bio_pipeline
from reporails_cli.core.mapper.instructions import fold_lead_ins
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.platform.adapters.payload import project_payload
from reporails_cli.core.platform.dto.ruleset import LIST_OBJECT_ROLE, Atom, FileRecord, RulesetMap

_CHARGE = {1: "DIRECTIVE", -1: "CONSTRAINT", 0: "NEUTRAL"}


def _atom(
    line: int,
    text: str,
    cv: int = 0,
    *,
    fmt: str = "list",
    depth: int = 1,
    named: tuple[str, ...] = (),
    unformatted: tuple[str, ...] = (),
    lead_in: bool = False,
) -> Atom:
    atom = Atom(
        line=line,
        text=text,
        kind="excitation",
        charge=_CHARGE[cv],
        charge_value=cv,
        modality="imperative" if cv else "none",
        specificity="named" if named else "abstract",
        plain_text=text.strip("*"),
        format=fmt,
        list_depth=depth if fmt in ("list", "numbered") else 0,
        named_tokens=list(named),
        unformatted_code=list(unformatted),
        token_count=len(text.split()),
        lead_in=lead_in,
    )
    atom.file_path = "a.md"
    return atom


def _state(atoms: list[Atom]) -> list[tuple[int, int, int, str]]:
    return [(a.line, a.charge_value, a.token_count, a.role) for a in atoms]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_lead_in_takes_a_list_of_things_as_its_object() -> None:
    atoms = fold_lead_ins(
        [
            _atom(18, "Audit these instruction-file surfaces:", 1, fmt="prose", lead_in=True),
            _atom(20, "`README.md` and the version heading", named=("README.md",)),
            _atom(21, "CLAUDE.md at the root", unformatted=("CLAUDE.md",)),
            _atom(22, "the slim auto-loading rules"),
            _atom(24, "Do not audit the source tree.", -1, fmt="prose"),
        ]
    )
    lead = atoms[0]
    assert (lead.charge_value, lead.token_count, lead.specificity) == (1, 4 + 3, "named")
    assert lead.named_tokens == ["README.md"]
    assert [a.role for a in atoms] == ["", LIST_OBJECT_ROLE, LIST_OBJECT_ROLE, LIST_OBJECT_ROLE, ""]
    # The item still reads as its own line: a code name there is reported on that line.
    assert [(f.line, f.message.split("'")[1]) for f in _check_unformatted_code(atoms, "a.md")] == [(21, "CLAUDE.md")]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_only_the_list_nested_under_a_list_item_is_its_object() -> None:
    """A list item introducing a nested list takes the nested items, never the sibling after them."""
    atoms = fold_lead_ins(
        [
            _atom(1, "Never modify these generated files:", -1, lead_in=True),
            _atom(2, "`schema.json`", depth=2, named=("schema.json",)),
            _atom(3, "the lockfile", depth=2),
            _atom(4, "Run the tests before you commit.", 1),
        ]
    )
    assert _state(atoms) == [
        (1, -1, 5 + 2, ""),
        (2, 0, 1, LIST_OBJECT_ROLE),
        (3, 0, 2, LIST_OBJECT_ROLE),
        (4, 1, 6, ""),
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "atoms",
    [
        # a list of commands: each is an instruction of its own, whatever the lead-in says
        [
            _atom(3, "Launch 3 subagents for the target rule:", 1, fmt="prose", lead_in=True),
            _atom(4, "Audit the rule's category.", 1, fmt="numbered"),
            _atom(5, "Tighten its language.", 1, fmt="numbered"),
        ],
        [
            _atom(3, "Do not merge until you:", -1, fmt="prose", lead_in=True),
            _atom(4, "run the tests"),
            _atom(5, "get a review"),
        ],
        # a list mixing things and a command
        [
            _atom(3, "Read these files:", 1, fmt="prose", lead_in=True),
            _atom(4, "`a.md`"),
            _atom(5, "Then run the tests.", 1),
        ],
        # the colon does not end its line
        [_atom(3, "Note:", 1, fmt="prose"), _atom(3, "run the tests", 1, fmt="prose"), _atom(4, "the README")],
        # an uncharged lead-in
        [_atom(3, "The files:", fmt="prose", lead_in=True), _atom(4, "the README")],
        # no list right after it
        [
            _atom(3, "Check these:", 1, fmt="prose", lead_in=True),
            _atom(4, "Some prose.", fmt="prose"),
            _atom(5, "the README"),
        ],
        [_atom(3, "Check these:", 1, fmt="prose", lead_in=True), _atom(7, "the README")],
        [_atom(3, "Run this:", 1, fmt="prose", lead_in=True), _atom(4, "make build", fmt="code_block")],
    ],
)
def test_a_lead_in_that_introduces_no_list_of_things_is_left_alone(atoms: list[Atom]) -> None:
    before = _state(atoms)
    assert _state(fold_lead_ins(atoms)) == before


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_an_unhyphenated_lead_in_is_still_an_instruction_and_folds_its_list() -> None:
    """UNRELEASED's own documented example, verbatim, with no hyphen in the lead-in.

    A hyphenated lead-in (`Audit these instruction-file surfaces:`) never matched
    `_LABEL_ONLY_RE` in the first place, so a test built only from that text would pass
    whether or not the zeroing bug was fixed. This is the plain, unhyphenated shape the
    zeroing regex actually catches.
    """
    text = "Audit these files:\n\n- `CLAUDE.md`\n- `AGENTS.md`\n\nNever skip the version check.\n"
    atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
    lead, *items, last = atoms
    assert lead.line == 1 and lead.charge_value == 1
    assert items and all(a.role == LIST_OBJECT_ROLE for a in items)
    assert last.charge_value == -1


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_the_charge_stage_reads_a_lead_in_and_its_list_as_one_instruction() -> None:
    text = (
        "Audit these instruction-file surfaces:\n"
        "\n"
        "- `README.md` and the per-version heading coupling to `pyproject.toml`\n"
        "- `CLAUDE.md` at the cli root\n"
        "- `.claude/rules/*.md` — slim auto-loading rules\n"
        "\n"
        "Never skip the version check.\n"
    )
    atoms = bio_pipeline.apply_multislot(list(tokenize(text)))
    lead, *items, last = atoms
    assert lead.line == 1 and lead.charge_value == 1 and lead.specificity == "named"
    assert items and all(a.role == LIST_OBJECT_ROLE and a.position_index == -1 for a in items)
    assert (lead.position_index, last.position_index) == (0, 1)
    for a in atoms:
        a.file_path = "/p/a.md"
    ruleset_map = RulesetMap(
        schema_version="4",
        embedding_model="m",
        generated_at="2026-09-28T00:00:00Z",
        files=(FileRecord(path="/p/a.md", content_hash="sha256:x"),),
        atoms=tuple(atoms),
    )
    assert [a["line"] for a in project_payload(ruleset_map, Path("/p"))["atoms"]] == [1, 7]
