"""The preservation check: a rewrite is judged whole, against its snapshot.

Each unit test builds a snapshot and a "new" map/text directly from synthetic content shaped
like a real rewrite's damage (never copied from a real project), pinning
the matching thresholds `preservation/match.py` chose. A block of integration-marked tests runs the
same `compare()` against the real mapper, so the synthetic-atom tests are not the only coverage.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.core.heal.preservation import PRESERVATION_CONTRACT, Snapshot, compare, take_snapshot
from reporails_cli.core.heal.preservation import match as preservation_match
from reporails_cli.core.heal.preservation import named as preservation_named
from reporails_cli.core.heal.preservation import structure as preservation_structure
from reporails_cli.core.heal.preservation.snapshot import SnapshotAtom
from reporails_cli.core.mapper.structure import read_structure
from reporails_cli.core.platform.adapters.project_environment import LocalProjectEnvironment
from reporails_cli.interfaces.mcp import snapshots

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_preservation_contract_is_byte_identical_to_the_plugin_s_quoted_text() -> None:
    """The plugin quotes `PRESERVATION_CONTRACT` verbatim — a paraphrase here silently
    desyncs the plugin's own copy from the server's."""
    assert PRESERVATION_CONTRACT == (
        "Keep every instruction: each keeps its polarity — a prohibition stays a prohibition — its "
        "scope, with no condition or exception added or dropped, and every construct it names. Keep "
        "every table row, list item, heading, fenced block, example and link, each list item in its "
        "own list; delete one only when a relation names it as a true duplicate of its partner. Keep "
        "a bare negative heading such as `## Don'ts` exactly as it is, with its items under it. Keep "
        "each constraint directly after the directive it limits. Add no filler and invent nothing: an "
        "instruction grows only by a construct the file already names or that exists in the project, "
        "or a reason the file already gives — never by repeating one it already names."
    )


_FILE = "/proj/.claude/agents/reviewer.md"


def _atom(
    line: int,
    text: str,
    charge_value: int,
    *,
    named: tuple[str, ...] = (),
    format: str = "prose",
    embedding: tuple[int, ...] | None = None,
    heading_context: str = "",
    scope_conditional: bool = False,
    heading: bool = False,
    modality: str | None = None,
) -> SnapshotAtom:
    return SnapshotAtom(
        line=line,
        text=text,
        charge_value=charge_value,
        named_tokens=named,
        format=format,
        embedding_int8=embedding,
        heading_context=heading_context,
        scope_conditional=scope_conditional,
        heading=heading,
        plain_text=text.replace("`", ""),
        modality=modality or ("direct" if charge_value else "none"),
    )


def _new_atom(
    line: int,
    pi: int,
    text: str,
    charge_value: int,
    named: tuple[str, ...] = (),
    file_path: str = _FILE,
    heading_context: str = "",
    scope_conditional: bool = False,
) -> SimpleNamespace:
    """A stand-in for a mapper `Atom` — `compare()` / `snapshot_file()` only read these fields."""
    return SimpleNamespace(
        line=line,
        position_index=pi,
        text=text,
        charge_value=charge_value,
        named_tokens=list(named),
        embedding_int8=None,
        kind="excitation",
        role="",
        file_path=file_path,
        format="prose",
        heading_context=heading_context,
        scope_conditional=scope_conditional,
        plain_text=text.replace("`", ""),
        modality="direct" if charge_value else "none",
    )


def _new_map(atoms: tuple[SimpleNamespace, ...]) -> SimpleNamespace:
    return SimpleNamespace(atoms=atoms)


def _env(root) -> LocalProjectEnvironment:
    return LocalProjectEnvironment(root, Path(_FILE).parent)


def _snapshot(
    text: str,
    atoms: tuple[SnapshotAtom, ...],
    relation_lines: frozenset[int] = frozenset(),
) -> Snapshot:
    return Snapshot(file_path=_FILE, text=text, atoms=atoms, score=6.0, relation_lines=relation_lines)


# ---------------------------------------------------------------------------
# (a) an agent file whose role table loses 3 rows
# ---------------------------------------------------------------------------

_TABLE_BEFORE = """# Reviewer Agent

You are a reviewer.

| Role | Responsibility |
|------|-----------------|
| architect | Owns architecture |
| planner | Owns scope |
| designer | Owns interface shape |
| reviewer | Reviews PRs |
"""

_TABLE_AFTER = """# Reviewer Agent

You are a reviewer.

| Role | Responsibility |
|------|-----------------|
| reviewer | Reviews PRs |
"""


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_role_table_losing_three_rows_is_not_ok() -> None:
    snap = _snapshot(_TABLE_BEFORE, ())
    result = compare(snap, _new_map(()), _TABLE_AFTER, score_after=6.0)
    assert result["removed_structure"]["table_rows"] == 3
    assert result["ok"] is False


@pytest.mark.unit
@pytest.mark.subsys_server
def test_kept_table_rows_is_the_snapshot_total_minus_what_was_removed() -> None:
    """`kept` is the flip side of `removed_structure`: the snapshot had 4 rows, 3 were removed,
    so `kept.table_rows` is 1 — never the count still in the rewrite read some other way."""
    snap = _snapshot(_TABLE_BEFORE, ())
    result = compare(snap, _new_map(()), _TABLE_AFTER, score_after=6.0)
    assert result["kept"]["table_rows"] == 1
    assert result["kept"]["instructions"] == 0, "no charged atoms in this snapshot"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_kept_instructions_is_the_snapshot_count_minus_lost_not_flipped_or_moved() -> None:
    """A flip or a detach is still present in the file — only a true loss subtracts from
    `kept.instructions`."""
    snap = _snapshot(_REPLACED_BEFORE, (_atom(3, "Never update based on inference or analogy.", -1),))
    new_atoms = (_new_atom(3, 0, "Cite every capability determination to its source.", 1),)
    result = compare(snap, _new_map(new_atoms), _REPLACED_AFTER, score_after=6.0)
    # The instruction is lost-or-flipped (asserted elsewhere); either way it does not count as kept.
    assert result["kept"]["instructions"] == 0


# ---------------------------------------------------------------------------
# (b) a bullet whose directive carries its prohibition on the same line; the rewrite
# moves the prohibition into a list at the end of the file — detached, not lost.
# ---------------------------------------------------------------------------

_DETACH_BEFORE = "# Agent\n\n- Ground every judgment in X. *Do not reason from Y when X covers it.*\n"
_DETACH_AFTER = (
    "# Agent\n\n- Ground every judgment in X.\n\n## Constraints\n\n- Do not reason from Y when X covers it.\n"
)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_prohibition_moved_off_its_directive_s_line_is_detached() -> None:
    directive = _atom(3, "Ground every judgment in X.", 1)
    prohibition = _atom(3, "Do not reason from Y when X covers it.", -1)
    snap = _snapshot(_DETACH_BEFORE, (directive, prohibition))
    new_atoms = (
        _new_atom(3, 0, "Ground every judgment in X.", 1),
        _new_atom(7, 1, "Do not reason from Y when X covers it.", -1),
    )
    result = compare(snap, _new_map(new_atoms), _DETACH_AFTER, score_after=6.0)
    assert result["detached_constraints"] == [{"line": 3, "text": "Do not reason from Y when X covers it."}]
    assert result["lost_instructions"] == [] and result["polarity_flips"] == []
    assert result["ok"] is False


# A packed bullet (two directives and the prohibition that limits them) whose short second
# directive also fits a numbered step elsewhere in the file. The rewrite names more in the
# step and leaves the bullet as it was, or only rewords it: nothing moved.

_TWIN_BEFORE = (
    "# Release agent\n\n## Steps\n\n1. Run the audit script against the output.\n2. Present the result.\n\n"
    "## Constraints\n\n- Present each change for approval before editing files. Run the audit script and "
    "compare the report against the baseline before proposing. *Do not edit files without explicit approval.*\n"
)
_TWIN_SNAP_ATOMS = (
    _atom(5, "Run the audit script against the output.", 1, heading_context="Steps"),
    _atom(6, "Present the result.", 1, heading_context="Steps"),
    _atom(10, "Present each change for approval before editing files.", 1, heading_context="Constraints"),
    _atom(10, "Run the audit script", 1, heading_context="Constraints"),
    _atom(10, "and compare the report against the baseline before proposing.", 1, heading_context="Constraints"),
    _atom(10, "*Do not edit files without explicit approval.*", -1, heading_context="Constraints"),
)
# An example the rewrite adds under Steps: it moves the bullet 7 lines down, further from its
# own old line than the reworded step is.
_TWIN_EXAMPLE = "\n```text\naudit: 0 errors\naudit: 2 warnings\naudit: done\n```\n"


def _twin_after(
    bullet_atoms: tuple[str, ...], bullet: str, *, grown: bool = False
) -> tuple[str, tuple[SimpleNamespace, ...]]:
    head, _ = _TWIN_BEFORE.replace("against the output.", "against the drafted release notes.").split(
        "\n\n## Constraints"
    )
    text = head + (_TWIN_EXAMPLE if grown else "") + "\n\n## Constraints\n\n" + bullet + "\n"
    bullet_line = text.split("\n").index(bullet) + 1
    step_atoms = (
        _new_atom(5, 0, "Run the audit script against the drafted release notes.", 1, heading_context="Steps"),
        _new_atom(6, 1, "Present the result.", 1, heading_context="Steps"),
    )
    charges = (1,) * (len(bullet_atoms) - 1) + (-1,)
    tail = tuple(
        _new_atom(bullet_line, 2 + i, t, c, heading_context="Constraints")
        for i, (t, c) in enumerate(zip(bullet_atoms, charges, strict=True))
    )
    return text, step_atoms + tail


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_unchanged_packed_bullet_keeps_its_constraint_when_a_step_elsewhere_shares_its_words() -> None:
    """The bullet is byte-identical, so its short directive matches its unchanged twin on the
    same line, never the reworded step in another section — and its prohibition is not detached."""
    bullet = _TWIN_BEFORE.split("\n")[9]
    text, new_atoms = _twin_after(tuple(a.text for a in _TWIN_SNAP_ATOMS[2:]), bullet)
    result = compare(_snapshot(_TWIN_BEFORE, _TWIN_SNAP_ATOMS), _new_map(new_atoms), text, score_after=6.0)
    assert result["detached_constraints"] == []
    assert result["moved_list_items"] == []
    assert result["ok"] is True


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_reworded_packed_bullet_keeps_its_constraint_when_a_step_elsewhere_fits_as_well() -> None:
    """The bullet's directives are reworded, so no twin is identical, and its short directive
    fits the reworded step and its own reworded line equally well. The rewrite also added an
    example under Steps, so the step now sits nearer the bullet's old line than the bullet
    does: the candidate under the same heading wins, not the nearer line."""
    bullet_atoms = (
        "Present each change for approval before editing files.",
        "Run the audit script against each change before proposing.",
        "Compare the report against the baseline before proposing.",
        "*Do not edit any files without the user's explicit approval.*",
    )
    text, new_atoms = _twin_after(bullet_atoms, "- " + " ".join(bullet_atoms), grown=True)
    assert new_atoms[3].line - 10 > 10 - new_atoms[0].line, "the fixture must put the step nearer"
    result = compare(_snapshot(_TWIN_BEFORE, _TWIN_SNAP_ATOMS), _new_map(new_atoms), text, score_after=6.0)
    assert result["detached_constraints"] == []
    assert result["moved_list_items"] == []
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# (c) a prohibition replaced by an unrelated directive
# ---------------------------------------------------------------------------

_REPLACED_BEFORE = "# Agent\n\nNever update based on inference or analogy.\n"
_REPLACED_AFTER = "# Agent\n\nCite every capability determination to its source.\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_prohibition_replaced_by_an_unrelated_directive_is_not_ok() -> None:
    snap = _snapshot(_REPLACED_BEFORE, (_atom(3, "Never update based on inference or analogy.", -1),))
    new_atoms = (_new_atom(3, 0, "Cite every capability determination to its source.", 1),)
    result = compare(snap, _new_map(new_atoms), _REPLACED_AFTER, score_after=6.0)
    assert result["lost_instructions"] or result["polarity_flips"]
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# `_added_instructions` — direct unit tests against the matcher's own exclusion sets,
# hand-built rather than relying on `_assign_matches` / `_split_window` to reproduce the exact
# shape: a charged new atom the matcher never claimed and the split path never covered, whose
# content words trace mostly to nothing the file's original instructions ever said.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_added_instruction_with_no_snapshot_counterpart_is_flagged() -> None:
    snapshot_text = "# Agent\n\nRun the linter before every commit.\n"
    added = _new_atom(5, 1, "Rotate the deployment keys every quarter.", -1)
    result = preservation_match.added_instructions(snapshot_text, (added,), {}, {})
    assert result == [{"line": 5, "text": "Rotate the deployment keys every quarter."}]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_new_atom_covering_a_snapshot_instruction_s_split_window_is_not_flagged() -> None:
    """`split_covering_for`'s values are excluded outright, regardless of word overlap — the
    split-coverage decision already happened upstream in `_instruction_diffs`."""
    snapshot_text = "# Agent\n\nRotate the deployment keys and audit access every quarter.\n"
    piece = _new_atom(3, 0, "Rotate the deployment keys every quarter.", 1)
    result = preservation_match.added_instructions(snapshot_text, (piece,), {}, {12345: [piece]})
    assert result == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_directly_matched_instruction_is_not_flagged_even_with_low_word_overlap() -> None:
    """`matched_new_for`'s values are excluded outright — a match the matcher already made
    (even a heavy reword the coverage heuristic alone would not clear) is never an addition."""
    snapshot_text = "# Agent\n\nRun the linter before every commit.\n"
    reworded = _new_atom(3, 0, "Scan the codebase automatically prior to integration.", 1)
    result = preservation_match.added_instructions(snapshot_text, (reworded,), {987: reworded}, {})
    assert result == []


# ---------------------------------------------------------------------------
# (d) a clean ideal rewrite: hedge removed, construct backticked, packed sentence split in
# two, heading renamed to a topic, every row/list/fence/link kept.
# ---------------------------------------------------------------------------

_IDEAL_BEFORE = """# Agent

## Testing

Maybe run the qa suite and check coverage before you push.

| Tool | Purpose |
|------|---------|
| pytest | Runs tests |

- Keep commits small.

```bash
uv run poe qa_fast
```

See [the guide](docs/guide.md) for details.
"""

_IDEAL_AFTER = """# Agent

## qa suite

Run the `qa suite` before you push. Check coverage too.

| Tool | Purpose |
|------|---------|
| pytest | Runs tests |

- Keep commits small.

```bash
uv run poe qa_fast
```

See [the guide](docs/guide.md) for details.
"""


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_clean_ideal_rewrite_is_ok() -> None:
    snap = _snapshot(
        _IDEAL_BEFORE,
        (
            _atom(5, "Maybe run the qa suite and check coverage before you push.", 1, modality="hedged"),
            _atom(11, "Keep commits small.", 1),
        ),
    )
    new_atoms = (
        _new_atom(5, 0, "Run the `qa suite` before you push.", 1),
        _new_atom(6, 1, "Check coverage too.", 1),
        _new_atom(12, 2, "Keep commits small.", 1),
    )
    result = compare(snap, _new_map(new_atoms), _IDEAL_AFTER, score_after=7.9)
    assert result == {
        "ok": True,
        "score_before": 6.0,
        "score_after": 7.9,
        "lost_instructions": [],
        "polarity_flips": [],
        "added_instructions": [],
        "lost_named": [],
        "invented_named": [],
        "repeated_named": [],
        "detached_constraints": [],
        "prohibition_scope_changed": [],
        "added_conditions": [],
        "dropped_conditions": [],
        "narrowed_instructions": [],
        "hedge_made_absolute": [],
        "dangling_fragments": [],
        "padded_lines": [],
        "made_direct": [
            {
                "line": 5,
                "text": "Maybe run the qa suite and check coverage before you push.",
                "new_line": 5,
                "new_text": "Run the `qa suite` before you push.",
            }
        ],
        "made_specific": [],
        "relabelled_negative_headings": [],
        "lost_context": [],
        "moved_list_items": [],
        "removed_structure": {"table_rows": 0, "list_items": 0, "headings": 0, "fences": 0, "links": 0},
        "kept": {"instructions": 2, "table_rows": 1, "list_items": 1, "headings": 2, "fences": 1, "links": 1},
    }


# ---------------------------------------------------------------------------
# (e) a relation-named duplicate line deleted — still ok
# ---------------------------------------------------------------------------

_DUP_BEFORE = "# Agent\n\nRun the tests before committing.\nRun the tests before committing.\n"
_DUP_AFTER = "# Agent\n\nRun the tests before committing.\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_relation_allowed_duplicate_line_deleted_is_still_ok() -> None:
    kept = _atom(3, "Run the tests before committing.", 1)
    duplicate = _atom(4, "Run the tests before committing.", 1)
    snap = _snapshot(_DUP_BEFORE, (kept, duplicate), relation_lines=frozenset({4}))
    new_atoms = (_new_atom(3, 0, "Run the tests before committing.", 1),)
    result = compare(snap, _new_map(new_atoms), _DUP_AFTER, score_after=6.0)
    assert result["ok"] is True


_PROSE_BEFORE = "# Agent\n\nNever push to main directly.\n\nThe api runs on port 8001 and reloads on every edit.\n"
_PROSE_CONTEXT = "The api runs on port 8001 and reloads on every edit."


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_deleted_prose_paragraph_fails_the_check() -> None:
    atoms = (_atom(3, "Never push to main directly.", -1), _atom(5, _PROSE_CONTEXT, 0))
    after = "# Agent\n\nNever push to main directly.\n"
    new_atoms = (_new_atom(3, 0, "Never push to main directly.", -1),)
    result = compare(_snapshot(_PROSE_BEFORE, atoms), _new_map(new_atoms), after, score_after=6.0)
    assert [x["line"] for x in result["lost_context"]] == [5]
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# (f) a fenced example edited or a link target dropped — counted
# ---------------------------------------------------------------------------

_FENCE_LINK_BEFORE = "# Agent\n\n```bash\nuv run poe qa_fast\n```\n\nSee [the guide](docs/guide.md) for details.\n"
_FENCE_LINK_AFTER = "# Agent\n\n```bash\nuv run pytest\n```\n\nSee the guide for details.\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_edited_fence_and_a_dropped_link_are_both_counted() -> None:
    snap = _snapshot(_FENCE_LINK_BEFORE, ())
    result = compare(snap, _new_map(()), _FENCE_LINK_AFTER, score_after=6.0)
    assert result["removed_structure"]["fences"] == 1
    assert result["removed_structure"]["links"] == 1
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# (g) coverage is of the SNAPSHOT instruction's words, never min-normalized: a short
# surviving instruction sharing one word must not stand in for a long lost one.
# ---------------------------------------------------------------------------

_SHORT_SURVIVOR_BEFORE = "# Agent\n\nAlways write integration tests for every new endpoint.\n\nWrite clearly.\n"
_SHORT_SURVIVOR_AFTER = "# Agent\n\nWrite clearly.\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_short_survivor_sharing_one_word_does_not_mask_a_long_lost_instruction() -> None:
    """A short surviving instruction ("Write clearly.", 2 content words) must not satisfy a 0.5
    threshold against the much longer, unrelated "Always write integration tests for every new
    endpoint." on their one shared word ("write"). Coverage of the long (lost) instruction's own
    words must not clear 0.5 on one shared word out of five."""
    lost = _atom(3, "Always write integration tests for every new endpoint.", 1)
    kept = _atom(5, "Write clearly.", 1)
    snap = _snapshot(_SHORT_SURVIVOR_BEFORE, (lost, kept))
    new_atoms = (_new_atom(3, 0, "Write clearly.", 1),)
    result = compare(snap, _new_map(new_atoms), _SHORT_SURVIVOR_AFTER, score_after=6.0)
    assert result["lost_instructions"] == [
        {"line": 3, "text": "Always write integration tests for every new endpoint."}
    ]
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# (h) split coverage counts only new atoms of the SAME polarity: a charged instruction
# whose words happen to scatter across neutral (table-cell) atoms is not "kept".
# ---------------------------------------------------------------------------

_KEPT_TABLE_BEFORE = (
    "# Agent\n\nNever commit temp files without cleanup.\n\n| Step | Note |\n|------|------|\n| a | b |\n"
)
_KEPT_TABLE_AFTER = "# Agent\n\n| Step | Note |\n|------|------|\n| a | b |\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_prohibition_scattered_across_neutral_table_cells_is_not_covered_by_split() -> None:
    """Two neutral (charge 0) new atoms happen to carry every word of the deleted
    prohibition between them (a table cell, an example block) — `_covered_by_split` must not
    count that as the packed sentence being kept split across new instructions of its own
    polarity, since there is no charge -1 new atom at all."""
    prohibition = _atom(3, "Never commit temp files without cleanup.", -1)
    snap = _snapshot(_KEPT_TABLE_BEFORE, (prohibition,))
    new_atoms = (
        _new_atom(5, 0, "Never commit temp files", 0),
        _new_atom(6, 1, "without cleanup", 0),
    )
    result = compare(snap, _new_map(new_atoms), _KEPT_TABLE_AFTER, score_after=6.0)
    assert result["lost_instructions"] == [{"line": 3, "text": "Never commit temp files without cleanup."}]
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# (i) `lost_named` matches whole tokens, never a bare substring of a longer word.
# ---------------------------------------------------------------------------

_NAMED_SUBSTRING_BEFORE = "# Git\n\nNever force-push `main`.\n"
_NAMED_SUBSTRING_AFTER = "# Git\n\nKeep the branch protection settings up to date; maintain them every release.\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_named_token_is_not_falsely_present_as_a_substring_of_a_longer_word() -> None:
    """`main` must not read as present just because "maintain" contains the substring
    "main" — the named token is gone, even though `main` occurs textually."""
    snap = _snapshot(_NAMED_SUBSTRING_BEFORE, (_atom(3, "Never force-push `main`.", -1, named=("`main`",)),))
    result = compare(snap, _new_map(()), _NAMED_SUBSTRING_AFTER, score_after=6.0)
    assert result["lost_named"] == ["`main`"]
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# (i3) `repeated_named` — a construct the file already names that the rewrite mentions more
# often than the original did, beyond one extra mention per instruction that names it.
# ---------------------------------------------------------------------------

_REPEAT_BEFORE = "# Skill\n\nRun `pytest` before you push.\n\nKeep the suite fast.\n\nFix a failure first.\n"


def _repeat_snapshot() -> Snapshot:
    return _snapshot(
        _REPEAT_BEFORE,
        (
            _atom(3, "Run `pytest` before you push.", 1, named=("`pytest`",)),
            _atom(5, "Keep the suite fast.", 1),
            _atom(7, "Fix a failure first.", 1),
        ),
    )


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_construct_repeated_into_other_instructions_is_flagged() -> None:
    """Genuine padding: the three original instructions are kept unchanged (no vague one is
    concretized), and a brand-new fourth instruction — matching none of the originals — pads in
    two more mentions of `pytest`, a construct the file already names once."""
    after = (
        "# Skill\n\nRun `pytest` before you push.\n\nKeep the suite fast.\n\nFix a failure first.\n\n"
        "Also always run `pytest` twice, since `pytest` matters.\n"
    )
    new_atoms = (
        _new_atom(3, 0, "Run `pytest` before you push.", 1, named=("`pytest`",)),
        _new_atom(5, 1, "Keep the suite fast.", 1),
        _new_atom(7, 2, "Fix a failure first.", 1),
        _new_atom(9, 3, "Also always run `pytest` twice, since `pytest` matters.", 1, named=("`pytest`", "`pytest`")),
    )
    result = compare(_repeat_snapshot(), _new_map(new_atoms), after, score_after=6.0)
    assert result["repeated_named"] == [{"token": "`pytest`", "before": 1, "after": 3, "allowed": 2}]
    assert result["ok"] is False


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_vague_instruction_naming_an_already_named_construct_is_not_flagged() -> None:
    """The concretizing case `repeated_named` must not contradict: a vague instruction ("Keep
    the suite fast.", naming nothing) is rewritten to name a construct the file already names
    elsewhere (`pytest`) — that is the vague-instruction remedy working as intended, not
    padding."""
    after = "# Skill\n\nRun `pytest` before you push.\n\nKeep the `pytest` suite fast.\n\nFix a failure first.\n"
    new_atoms = (
        _new_atom(3, 0, "Run `pytest` before you push.", 1, named=("`pytest`",)),
        _new_atom(5, 1, "Keep the `pytest` suite fast.", 1, named=("`pytest`",)),
        _new_atom(7, 2, "Fix a failure first.", 1),
    )
    result = compare(_repeat_snapshot(), _new_map(new_atoms), after, score_after=6.0)
    assert result["repeated_named"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_one_extra_mention_per_instruction_that_names_it_is_kept() -> None:
    """An instruction split in two may name its construct in both halves."""
    after = (
        "# Skill\n\nRun `pytest` before you push. Run `pytest` again after a rebase.\n\n"
        "Keep the suite fast.\n\nFix a failure first.\n"
    )
    new_atoms = (
        _new_atom(3, 0, "Run `pytest` before you push.", 1, named=("`pytest`",)),
        _new_atom(3, 1, "Run `pytest` again after a rebase.", 1, named=("`pytest`",)),
        _new_atom(5, 2, "Keep the suite fast.", 1),
        _new_atom(7, 3, "Fix a failure first.", 1),
    )
    result = compare(_repeat_snapshot(), _new_map(new_atoms), after, score_after=6.0)
    assert result["repeated_named"] == []


# ---------------------------------------------------------------------------
# `_mentions` — direct regex-boundary coverage. A general construct followed by a sentence
# colon or period must still count; a directory construct followed by anything but a path
# continuation must still count.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("See docs/, then continue.", 1),
        ("(docs/) holds the notes.", 1),
        ("Read docs/.", 1),
        ("Read `docs/guides/x.md` instead.", 0),
        ("See `docs/<area>/` for the pattern.", 0),
    ],
)
def test_mentions_of_a_directory_construct(text: str, expected: int) -> None:
    assert preservation_named.mentions("docs/", text) == expected


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("inner", "text", "expected"),
    [
        ("CLAUDE.md", "`CLAUDE.md`: read it first.", 1),
        ("CLAUDE.md", "CLAUDE.md: read it first.", 1),
        ("skills", "Use skills:foo instead.", 0),
    ],
)
def test_mentions_of_a_general_construct(inner: str, text: str, expected: int) -> None:
    assert preservation_named.mentions(inner, text) == expected


_CATEGORY_BEFORE = (
    "# Skill\n\nCheck the `category` field before merging.\n\n"
    "Run `/check-category` to verify.\n\nRun `/check-category` again to confirm.\n"
)


def _category_snapshot() -> Snapshot:
    return _snapshot(
        _CATEGORY_BEFORE,
        (
            _atom(3, "Check the `category` field before merging.", 1, named=("`category`",)),
            _atom(5, "Run `/check-category` to verify.", 1, named=("`/check-category`",)),
            _atom(7, "Run `/check-category` again to confirm.", 1, named=("`/check-category`",)),
        ),
    )


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_construct_joined_into_a_longer_name_is_not_counted_as_its_own_mention() -> None:
    """`category` is joined into `/check-category` in the original twice, and the rewrite adds
    two more `/check-category` mentions (no bare `category` added) — the joined occurrences
    never count toward `category`'s own tally, so it is not flagged as repeated."""
    after = (
        "# Skill\n\nCheck the `category` field before merging.\n\n"
        "Run `/check-category` to verify.\n\nRun `/check-category` again to confirm.\n\n"
        "Also run `/check-category` once more, then `/check-category` finally.\n"
    )
    new_atoms = (
        _new_atom(3, 0, "Check the `category` field before merging.", 1, named=("`category`",)),
        _new_atom(5, 1, "Run `/check-category` to verify.", 1, named=("`/check-category`",)),
        _new_atom(7, 2, "Run `/check-category` again to confirm.", 1, named=("`/check-category`",)),
        _new_atom(
            9,
            3,
            "Also run `/check-category` once more, then `/check-category` finally.",
            1,
            named=("`/check-category`", "`/check-category`"),
        ),
    )
    result = compare(_category_snapshot(), _new_map(new_atoms), after, score_after=6.0)
    assert not any(e["token"] == "`category`" for e in result["repeated_named"])


@pytest.mark.unit
@pytest.mark.subsys_server
def test_two_bare_mentions_of_an_already_named_construct_are_still_flagged() -> None:
    """A rewrite padding two bare mentions of `category` into an unrelated instruction still
    repeats a construct the file already names, even though the file also mentions it joined
    into `/check-category` throughout."""
    after = (
        "# Skill\n\nCheck the `category` field before merging.\n\n"
        "Run `/check-category` to verify.\n\nRun `/check-category` again to confirm.\n\n"
        "Also check the category twice, since category matters.\n"
    )
    new_atoms = (
        _new_atom(3, 0, "Check the `category` field before merging.", 1, named=("`category`",)),
        _new_atom(5, 1, "Run `/check-category` to verify.", 1, named=("`/check-category`",)),
        _new_atom(7, 2, "Run `/check-category` again to confirm.", 1, named=("`/check-category`",)),
        _new_atom(9, 3, "Also check the category twice, since category matters.", 1),
    )
    result = compare(_category_snapshot(), _new_map(new_atoms), after, score_after=6.0)
    entry = next(e for e in result["repeated_named"] if e["token"] == "`category`")
    assert (entry["before"], entry["after"]) == (1, 3)


_DOCS_BEFORE = (
    "# Skill\n\nRead `docs/` for project notes.\n\n"
    "See `docs/<class>/<topic>/<slug>.md` for the pattern.\n\nSee `docs/<class>/<arg>/` too.\n"
)


def _docs_snapshot() -> Snapshot:
    return _snapshot(
        _DOCS_BEFORE,
        (
            _atom(3, "Read `docs/` for project notes.", 1, named=("`docs/`",)),
            _atom(
                5,
                "See `docs/<class>/<topic>/<slug>.md` for the pattern.",
                1,
                named=("`docs/<class>/<topic>/<slug>.md`",),
            ),
            _atom(7, "See `docs/<class>/<arg>/` too.", 1, named=("`docs/<class>/<arg>/`",)),
        ),
    )


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_directory_construct_is_not_counted_inside_a_longer_path_below_it() -> None:
    """`docs/` (a directory) is a different, longer path once anything but whitespace or a
    backtick follows its trailing slash — `docs/<class>/<topic>/<slug>.md` is not a mention of
    `docs/` itself, even though the character right after the slash (`<`) is neither a word
    character nor `/ : -`. A rewrite adding two more such longer paths (no new bare `docs/`)
    is not flagged."""
    after = _DOCS_BEFORE + "\nAlso see `docs/<class>/<other>/<slug>.md` and `docs/<class>/<more>/`.\n"
    new_atoms = (
        _new_atom(3, 0, "Read `docs/` for project notes.", 1, named=("`docs/`",)),
        _new_atom(
            5,
            1,
            "See `docs/<class>/<topic>/<slug>.md` for the pattern.",
            1,
            named=("`docs/<class>/<topic>/<slug>.md`",),
        ),
        _new_atom(7, 2, "See `docs/<class>/<arg>/` too.", 1, named=("`docs/<class>/<arg>/`",)),
        _new_atom(
            9,
            3,
            "Also see `docs/<class>/<other>/<slug>.md` and `docs/<class>/<more>/`.",
            1,
            named=("`docs/<class>/<other>/<slug>.md`", "`docs/<class>/<more>/`"),
        ),
    )
    result = compare(_docs_snapshot(), _new_map(new_atoms), after, score_after=6.0)
    assert not any(e["token"] == "`docs/`" for e in result["repeated_named"])


@pytest.mark.unit
@pytest.mark.subsys_server
def test_two_bare_mentions_of_a_directory_construct_are_still_flagged() -> None:
    """A rewrite padding two bare mentions of `docs/` itself into an unrelated instruction is
    still flagged, even though the file also mentions longer paths below that directory
    throughout."""
    after = _DOCS_BEFORE + "\nAlso check `docs/` again, since `docs/` matters.\n"
    new_atoms = (
        _new_atom(3, 0, "Read `docs/` for project notes.", 1, named=("`docs/`",)),
        _new_atom(
            5,
            1,
            "See `docs/<class>/<topic>/<slug>.md` for the pattern.",
            1,
            named=("`docs/<class>/<topic>/<slug>.md`",),
        ),
        _new_atom(7, 2, "See `docs/<class>/<arg>/` too.", 1, named=("`docs/<class>/<arg>/`",)),
        _new_atom(9, 3, "Also check `docs/` again, since `docs/` matters.", 1, named=("`docs/`", "`docs/`")),
    )
    result = compare(_docs_snapshot(), _new_map(new_atoms), after, score_after=6.0)
    entry = next(e for e in result["repeated_named"] if e["token"] == "`docs/`")
    assert (entry["before"], entry["after"]) == (1, 3)


# ---------------------------------------------------------------------------
# (i2) `invented_named` — a NEW-file named token the snapshot never named and that is not a
# real project path is flagged; a token grounded in the snapshot's own (unbackticked) text, or
# in a real project path, is not.
# ---------------------------------------------------------------------------

_INVENTED_BEFORE = "# Skill\n\nRun the qa suite before you push.\n"
_INVENTED_AFTER = "# Skill\n\nRun `mcp__reporails__score` before you push.\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_invented_tool_name_is_flagged() -> None:
    """The demo case: a rewrite introduces a tool name the original file never mentioned and
    that does not exist on disk — flagged, and `ok` is False."""
    snap = _snapshot(_INVENTED_BEFORE, (_atom(3, "Run the qa suite before you push.", 1),))
    new_atoms = (
        _new_atom(3, 0, "Run `mcp__reporails__score` before you push.", 1, named=("`mcp__reporails__score`",)),
    )
    result = compare(snap, _new_map(new_atoms), _INVENTED_AFTER, score_after=6.0)
    assert result["invented_named"] == [{"line": 3, "token": "`mcp__reporails__score`"}]
    assert result["ok"] is False


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_word_the_original_had_unbackticked_and_the_rewrite_backticked_is_not_invented() -> None:
    """The original already said "qa suite" in prose; the rewrite naming it with backticks is
    concretizing, not inventing — case-insensitive, backticks stripped, on both sides."""
    before = "# Skill\n\nRun the QA Suite before you push.\n"
    after = "# Skill\n\nRun the `qa suite` before you push.\n"
    snap = _snapshot(before, (_atom(3, "Run the QA Suite before you push.", 1),))
    new_atoms = (_new_atom(3, 0, "Run the `qa suite` before you push.", 1, named=("`qa suite`",)),)
    result = compare(snap, _new_map(new_atoms), after, score_after=6.0)
    assert result["invented_named"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_real_project_path_the_original_did_not_mention_is_not_invented(tmp_path) -> None:
    """A named token that resolves to a real file under the project root counts as grounded
    even though the snapshot's own text never wrote it."""
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "release.py").write_text("# release\n")
    before = "# Skill\n\nRun the release helper before you push.\n"
    after = "# Skill\n\nRun `scripts/release.py` before you push.\n"
    snap = _snapshot(before, (_atom(3, "Run the release helper before you push.", 1),))
    new_atoms = (_new_atom(3, 0, "Run `scripts/release.py` before you push.", 1, named=("`scripts/release.py`",)),)
    result = compare(snap, _new_map(new_atoms), after, score_after=6.0, environment=_env(tmp_path))
    assert result["invented_named"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_token_the_original_named_is_not_invented() -> None:
    """A named token the snapshot's own text already carried, kept verbatim in the rewrite, is
    never flagged — the baseline "nothing changed" case."""
    before = "# Git\n\nNever force-push `main`.\n"
    after = "# Git\n\nNever force-push `main` without review.\n"
    snap = _snapshot(before, (_atom(3, "Never force-push `main`.", -1, named=("`main`",)),))
    new_atoms = (_new_atom(3, 0, "Never force-push `main` without review.", -1, named=("`main`",)),)
    result = compare(snap, _new_map(new_atoms), after, score_after=6.0)
    assert result["invented_named"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_language_of_a_newly_added_code_example_is_not_invented() -> None:
    """A rewrite that adds a fenced example tagged `bash` names no construct: the fence
    language is the block's own label, never an invented name."""
    before = "# Skill\n\nRun the qa suite before you push.\n"
    after = "# Skill\n\nRun the qa suite before you push.\n\n```bash\nqa\n```\n"
    snap = _snapshot(before, (_atom(3, "Run the qa suite before you push.", 1),))
    code = _new_atom(5, 1, "qa", 0, named=("bash",))
    code.format = "code_block"
    new_atoms = (_new_atom(3, 0, "Run the qa suite before you push.", 1), code)
    result = compare(snap, _new_map(new_atoms), after, score_after=6.0)
    assert result["invented_named"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_command_the_project_declares_is_not_invented(tmp_path) -> None:
    """A command whose program the project's own manifest declares exists in the project:
    naming it is what a too-brief remedy asks for, never an invention. A name neither the file,
    the project nor the machine knows is still flagged."""
    (tmp_path / "pyproject.toml").write_text('[tool.poe.tasks]\ntest = "pytest -q"\n')
    before = "# Skill\n\nRun the tests before you push.\n"
    after = "# Skill\n\nRun `pytest -q` and `mcp__reporails__score` before you push.\n"
    snap = _snapshot(before, (_atom(3, "Run the tests before you push.", 1),))
    new_atoms = (
        _new_atom(
            3,
            0,
            "Run `pytest -q` and `mcp__reporails__score` before you push.",
            1,
            named=("`pytest -q`", "`mcp__reporails__score`"),
        ),
    )
    result = compare(snap, _new_map(new_atoms), after, score_after=6.0, environment=_env(tmp_path))
    assert result["invented_named"] == [{"line": 3, "token": "`mcp__reporails__score`"}]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_path_relative_to_the_file_itself_is_not_invented(tmp_path) -> None:
    """A nested instruction file names paths relative to its own directory."""
    pkg = tmp_path / "packages" / "web"
    (pkg / "src").mkdir(parents=True)
    (pkg / "src" / "index.ts").write_text("export {}\n")
    before = "# Web\n\nStart from the entry file.\n"
    after = "# Web\n\nStart from `src/index.ts`.\n"
    snap = Snapshot(
        file_path=str(pkg / "CLAUDE.md"),
        text=before,
        atoms=(_atom(3, "Start from the entry file.", 1),),
        score=6.0,
    )
    new_atoms = (
        _new_atom(3, 0, "Start from `src/index.ts`.", 1, named=("`src/index.ts`",), file_path=str(pkg / "CLAUDE.md")),
    )
    result = compare(
        snap, _new_map(new_atoms), after, score_after=6.0, environment=LocalProjectEnvironment(tmp_path, pkg)
    )
    assert result["invented_named"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_home_path_that_exists_is_not_invented(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    (tmp_path / ".config").mkdir()
    (tmp_path / ".config" / "tool.toml").write_text("x = 1\n")
    before = "# Skill\n\nRead the user config first.\n"
    after = "# Skill\n\nRead `~/.config/tool.toml` first.\n"
    snap = _snapshot(before, (_atom(3, "Read the user config first.", 1),))
    new_atoms = (_new_atom(3, 0, "Read `~/.config/tool.toml` first.", 1, named=("`~/.config/tool.toml`",)),)
    result = compare(snap, _new_map(new_atoms), after, score_after=6.0, environment=_env(tmp_path))
    assert result["invented_named"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_construct_moved_in_from_a_sibling_file_of_the_location_is_not_invented(tmp_path) -> None:
    """A relation remedy moves an instruction between two briefed files: the construct it
    carries was named in the sibling's own original, so it is not an invention."""
    sibling_text = "# Agents\n\nRun `repo-lint --fix` before you push.\n"
    before = "# Skill\n\nCheck style before you push.\n"
    after = "# Skill\n\nRun `repo-lint --fix` before you push.\n"
    snap = Snapshot(
        file_path=str(tmp_path / "CLAUDE.md"),
        text=before,
        atoms=(_atom(3, "Check style before you push.", 1),),
        score=6.0,
    )
    new_atoms = (
        _new_atom(
            3,
            0,
            "Run `repo-lint --fix` before you push.",
            1,
            named=("`repo-lint --fix`",),
            file_path=str(tmp_path / "CLAUDE.md"),
        ),
    )
    alone = compare(snap, _new_map(new_atoms), after, score_after=6.0, environment=_env(tmp_path))
    assert [e["token"] for e in alone["invented_named"]] == ["`repo-lint --fix`"]
    result = compare(
        snap, _new_map(new_atoms), after, score_after=6.0, environment=_env(tmp_path), sibling_texts=(sibling_text,)
    )
    assert result["invented_named"] == []


# ---------------------------------------------------------------------------
# (j) fence tracking closes only on a line of the opener's exact character and a run at
# least as long (CommonMark): a bare 3-backtick line inside a 4-backtick fence's example body
# must not close it, and a table row deleted after such a fence must still be caught.
# ---------------------------------------------------------------------------

_NESTED_FENCE_BEFORE = (
    "# Skill\n\n"
    "````markdown\n"
    "```\n"
    "bare fence marker inside the example\n"
    "````\n\n"
    "| Col | Val |\n|-----|-----|\n| a | 1 |\n| b | 2 |\n"
)
_NESTED_FENCE_AFTER = (
    "# Skill\n\n"
    "````markdown\n"
    "```\n"
    "bare fence marker inside the example\n"
    "````\n\n"
    "| Col | Val |\n|-----|-----|\n| a | 1 |\n"
)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_nested_bare_fence_does_not_close_a_4_backtick_fence_early() -> None:
    """The opener's exact length is tracked, so the inner 3-backtick line does not close the
    outer 4-backtick fence early, and the deleted table row after the fence is detected."""
    snap = _snapshot(_NESTED_FENCE_BEFORE, ())
    result = compare(snap, _new_map(()), _NESTED_FENCE_AFTER, score_after=6.0)
    assert result["removed_structure"]["table_rows"] == 1
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# `moved_list_items` — a snapshot list item whose match lands in a different list than the
# majority of its own list's matched siblings. List membership is the contiguous list block a
# line sits in, never its marker glyph.
# ---------------------------------------------------------------------------

_MOVED_POS_BEFORE = """# Agent

## Checks

Run checks C1 through C5 before presenting output.

- **C1**: Verify the first item.
- **C2**: Verify the second item.
- **C3**: Never skip validation on save.
- **C4**: Verify the fourth item.
- **C5**: Verify the fifth item.

## Steps

Do the work.

## Notes

Some notes.

## Report

Write the report.
"""

_MOVED_POS_AFTER = """# Agent

## Checks

Run checks C1 through C5 before presenting output.

- **C1**: Verify the first item.
- **C2**: Verify the second item.
- **C4**: Verify the fourth item.
- **C5**: Verify the fifth item.

## Steps

Do the work.

## Notes

Some notes.

## Report

Write the report.

- *C3: Never skip validation on save, reworded for clarity.*
"""


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_list_item_moved_into_a_different_list_three_headings_later_is_flagged() -> None:
    """A prohibition bullet leaves its own list under `##
    Checks` and reappears, reworded, as a bullet under `## Report` — the majority of its
    snapshot list siblings (`C1`, `C2`, `C4`, `C5`) all still match into the `## Checks` list,
    so `C3` alone lands away from the majority."""
    snap_atoms = (
        _atom(7, "Verify the first item.", 1),
        _atom(8, "Verify the second item.", 1),
        _atom(9, "Never skip validation on save.", -1),
        _atom(10, "Verify the fourth item.", 1),
        _atom(11, "Verify the fifth item.", 1),
    )
    snap = _snapshot(_MOVED_POS_BEFORE, snap_atoms)
    new_atoms = (
        _new_atom(7, 0, "Verify the first item.", 1),
        _new_atom(8, 1, "Verify the second item.", 1),
        _new_atom(9, 2, "Verify the fourth item.", 1),
        _new_atom(10, 3, "Verify the fifth item.", 1),
        _new_atom(24, 4, "Never skip validation on save, reworded for clarity.", -1),
    )
    result = compare(snap, _new_map(new_atoms), _MOVED_POS_AFTER, score_after=6.0)
    assert result["moved_list_items"] == [{"line": 9, "text": "Never skip validation on save."}]
    assert result["ok"] is False


_MOVED_REORDER_BEFORE = "# Agent\n\n## Checks\n\n- C1: Verify a.\n- C2: Verify b.\n- C3: Verify c.\n"
_MOVED_REORDER_AFTER = "# Agent\n\n## Checks\n\n- C3: Verify c.\n- C1: Verify a.\n- C2: Verify b.\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_items_reordered_within_their_own_list_are_not_flagged() -> None:
    snap = _snapshot(
        _MOVED_REORDER_BEFORE,
        (_atom(5, "Verify a.", 1), _atom(6, "Verify b.", 1), _atom(7, "Verify c.", 1)),
    )
    new_atoms = (
        _new_atom(5, 0, "Verify c.", 1),
        _new_atom(6, 1, "Verify a.", 1),
        _new_atom(7, 2, "Verify b.", 1),
    )
    result = compare(snap, _new_map(new_atoms), _MOVED_REORDER_AFTER, score_after=6.0)
    assert result["moved_list_items"] == []
    assert result["added_instructions"] == [], "a reflowed list must not read as new instructions"


_MOVED_SPLIT_BEFORE = (
    "# Agent\n\n## Checks\n\n- C1: Verify a.\n- C2: Verify b and check c thoroughly.\n- C3: Verify d.\n"
)
_MOVED_SPLIT_AFTER = (
    "# Agent\n\n## Checks\n\n- C1: Verify a.\n- C2: Verify b.\n- C2b: Check c thoroughly.\n- C3: Verify d.\n"
)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_item_split_into_two_items_of_the_same_list_is_not_flagged() -> None:
    snap = _snapshot(
        _MOVED_SPLIT_BEFORE,
        (_atom(5, "Verify a.", 1), _atom(6, "Verify b and check c thoroughly.", 1), _atom(7, "Verify d.", 1)),
    )
    new_atoms = (
        _new_atom(5, 0, "Verify a.", 1),
        _new_atom(6, 1, "Verify b.", 1),
        _new_atom(7, 2, "Check c thoroughly.", 1),
        _new_atom(8, 3, "Verify d.", 1),
    )
    result = compare(snap, _new_map(new_atoms), _MOVED_SPLIT_AFTER, score_after=6.0)
    assert result["moved_list_items"] == []


_MOVED_SWAP_BEFORE = (
    "# Agent\n\n## Checks\n\n- C1: Verify a.\n- C2: Verify b.\n- C3: Verify c.\n\n## Report\n\nWrite the report.\n"
)
_MOVED_SWAP_AFTER = (
    "# Agent\n\n## Report\n\nWrite the report.\n\n## Checks\n\n- C1: Verify a.\n- C2: Verify b.\n- C3: Verify c.\n"
)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_whole_list_moving_with_two_sections_swapping_is_not_flagged() -> None:
    snap = _snapshot(
        _MOVED_SWAP_BEFORE,
        (_atom(5, "Verify a.", 1), _atom(6, "Verify b.", 1), _atom(7, "Verify c.", 1)),
    )
    new_atoms = (
        _new_atom(9, 0, "Verify a.", 1),
        _new_atom(10, 1, "Verify b.", 1),
        _new_atom(11, 2, "Verify c.", 1),
    )
    result = compare(snap, _new_map(new_atoms), _MOVED_SWAP_AFTER, score_after=6.0)
    assert result["moved_list_items"] == []


_MOVED_SINGLE_BEFORE = "# Agent\n\n## Checks\n\n- C1: Verify a lone item.\n\n## Report\n\nWrite the report.\n"
_MOVED_SINGLE_AFTER = (
    "# Agent\n\n## Checks\n\nNothing to check here.\n\n## Report\n\nWrite the report.\n\n- C1: Verify a lone item.\n"
)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_list_with_a_single_item_is_not_flagged_even_when_it_moves() -> None:
    snap = _snapshot(_MOVED_SINGLE_BEFORE, (_atom(5, "Verify a lone item.", 1),))
    new_atoms = (_new_atom(11, 0, "Verify a lone item.", 1),)
    result = compare(snap, _new_map(new_atoms), _MOVED_SINGLE_AFTER, score_after=6.0)
    assert result["moved_list_items"] == []


_MOVED_NOSIB_BEFORE = (
    "# Agent\n\n## Checks\n\n- C1: Verify a lone-ish item in a pair.\n"
    "- C2: Verify something entirely different that gets dropped.\n\n## Report\n\nWrite the report.\n"
)
_MOVED_NOSIB_AFTER = (
    "# Agent\n\n## Checks\n\nNothing left here.\n\n## Report\n\nWrite the report.\n\n"
    "- C1: Verify a lone-ish item in a pair.\n"
)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_item_whose_only_sibling_has_no_match_is_not_flagged() -> None:
    """`C2`'s wording never occurs in the after text (no match at all), so `C1`'s single
    sibling carries no landing to form a majority from — `C1` must not be flagged even though
    it did move."""
    snap = _snapshot(
        _MOVED_NOSIB_BEFORE,
        (
            _atom(5, "Verify a lone-ish item in a pair.", 1),
            _atom(6, "Verify something entirely different that gets dropped.", 1),
        ),
    )
    new_atoms = (_new_atom(11, 0, "Verify a lone-ish item in a pair.", 1),)
    result = compare(snap, _new_map(new_atoms), _MOVED_NOSIB_AFTER, score_after=6.0)
    assert result["moved_list_items"] == []


_MOVED_MARKER_BEFORE = (
    "# Agent\n\n## Checks\n\n"
    "- [ ] Verify the environment is clean.\n"
    "- [ ] Verify the config file exists.\n"
    "3. Cross-check the manifest against the lockfile.\n\n"
    "## Report\n\n"
    "1. Gather the check results.\n"
    "2. Summarize the outcome.\n"
    "- [ ] Confirm the summary was written to disk.\n"
    "4. Publish the report.\n"
)
_MOVED_MARKER_AFTER = (
    "# Agent\n\n## Checks\n\n"
    "- [ ] Verify the environment is clean.\n"
    "- [ ] Verify the config file exists.\n"
    "- [ ] Cross-check the manifest against the lockfile.\n\n"
    "## Report\n\n"
    "1. Gather the check results.\n"
    "2. Summarize the outcome.\n"
    "3. Confirm the summary was written to disk.\n"
    "4. Publish the report.\n"
)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_marker_corrected_to_match_its_own_block_is_not_flagged() -> None:
    """The `distribution-auditor` case: a numbered item stuck inside a checklist block, and a
    checklist item stuck inside a numbered block, each stay in their own contiguous block —
    the rewrite only fixed the marker glyph to match. List membership is the block, not the
    glyph, so neither is a list-crossing move."""
    snap_atoms = (
        _atom(5, "Verify the environment is clean.", 1),
        _atom(6, "Verify the config file exists.", 1),
        _atom(7, "Cross-check the manifest against the lockfile.", 1),
        _atom(11, "Gather the check results.", 1),
        _atom(12, "Summarize the outcome.", 1),
        _atom(13, "Confirm the summary was written to disk.", 1),
        _atom(14, "Publish the report.", 1),
    )
    snap = _snapshot(_MOVED_MARKER_BEFORE, snap_atoms)
    new_atoms = (
        _new_atom(5, 0, "Verify the environment is clean.", 1),
        _new_atom(6, 1, "Verify the config file exists.", 1),
        _new_atom(7, 2, "Cross-check the manifest against the lockfile.", 1),
        _new_atom(11, 3, "Gather the check results.", 1),
        _new_atom(12, 4, "Summarize the outcome.", 1),
        _new_atom(13, 5, "Confirm the summary was written to disk.", 1),
        _new_atom(14, 6, "Publish the report.", 1),
    )
    result = compare(snap, _new_map(new_atoms), _MOVED_MARKER_AFTER, score_after=6.0)
    assert result["moved_list_items"] == []
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# Errors and instruction/heading and `no_workflow`/`location_not_found` cases live in
# `test_remedy_brief.py`; snapshot store lifecycle:
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_server
def test_snapshot_persists_until_replaced(tmp_path) -> None:
    target = tmp_path / "CLAUDE.md"
    target.write_text("# Project\n\nNever skip tests.\n", encoding="utf-8")
    atoms = (_new_atom(3, 0, "Never skip tests.", -1, file_path=str(target)),)
    snapshots.snapshot_file(target, _new_map(atoms), 5.0, [])
    assert snapshots.has_snapshot(target)
    snap = snapshots.get_snapshot(target)
    assert snap is not None and snap.score == 5.0

    snapshots.snapshot_file(target, _new_map(()), 8.0, [])
    assert snapshots.get_snapshot(target).score == 8.0


@pytest.mark.unit
@pytest.mark.subsys_server
def test_clear_snapshots_drops_every_baseline(tmp_path) -> None:
    target = tmp_path / "CLAUDE.md"
    target.write_text("# Project\n\nNever skip tests.\n", encoding="utf-8")
    snapshots.snapshot_file(target, _new_map(()), 5.0, [])
    assert snapshots.has_snapshot(target)
    snapshots.clear_snapshots()
    assert not snapshots.has_snapshot(target)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_instruction_atoms_for_file_leaves_out_list_objects() -> None:
    from reporails_cli.core.lint.content_queries import instruction_atoms_for_file
    from reporails_cli.core.platform.dto.ruleset import LIST_OBJECT_ROLE

    def atom(line: int, role: str, path: str = "a.md") -> SimpleNamespace:
        return SimpleNamespace(line=line, role=role, file_path=path)

    rm = _new_map((atom(1, ""), atom(2, LIST_OBJECT_ROLE), atom(3, "", "b.md")))
    assert [a.line for a in instruction_atoms_for_file(rm, "a.md")] == [1]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_unsnapshotted_file_has_no_snapshot(tmp_path) -> None:
    assert not snapshots.has_snapshot(tmp_path / "never-briefed.md")
    assert snapshots.get_snapshot(tmp_path / "never-briefed.md") is None


# ---------------------------------------------------------------------------
# Integration: the real mapper, not synthetic atoms.
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_compare_against_the_real_mapper(tmp_path) -> None:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    before_text = "# Agent\n\nNever commit secrets to the repo.\n"
    target = tmp_path / "CLAUDE.md"
    target.write_text(before_text, encoding="utf-8")
    before_map = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    snap = Snapshot(
        file_path=str(target),
        text=before_text,
        atoms=tuple(
            SnapshotAtom(
                a.line,
                a.text,
                a.charge_value,
                tuple(a.named_tokens),
                a.format,
                a.embedding_int8,
                a.heading_context,
                a.scope_conditional,
            )
            for a in before_map.atoms
            if a.kind != "heading"
        ),
        score=None,
    )

    # A genuine no-op (unchanged content) must be ok.
    same_map = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    result = compare(snap, same_map, before_text, None)
    assert result["ok"] is True

    # Replacing the prohibition with an unrelated directive must not be ok.
    after_text = "# Agent\n\nDocument every endpoint in the API reference.\n"
    target.write_text(after_text, encoding="utf-8")
    after_map = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    result2 = compare(snap, after_map, after_text, None)
    assert result2["ok"] is False
    assert result2["lost_instructions"] or result2["polarity_flips"]


# ---------------------------------------------------------------------------
# Adversarial cases extended into the real-mapper suite. The base document is a git-workflow file with
# two `main`-prohibitions, a packed constraint bullet, neutral prose, a table and a link.
# ---------------------------------------------------------------------------

_ATTACK_BASE = """# Git

Merge pull requests into `main` after review.

- Never force-push `main`.
- Never push to `main` directly.
- Run `pytest` before every commit. *Do not skip `ruff` when it fails.*

The api runs on port 8001 and reloads from the source tree on every edit.

| Role | Owns |
|---|---|
| `planner` | routing |
| `pm` | features |

See [the guide](docs/guide.md) for the full release checklist.
"""

_PROSE_BEFORE = (
    "# Git\n\nNever force-push `main`.\n\nNever push to `main` directly.\n\nRun `pytest` before every commit.\n"
)
_PROSE_AFTER = "# Git\n\nNever force-push `main`.\n\nRun `pytest` before every commit.\n"


def _real_snapshot(target: Any, before_map: Any, before_text: str, score: float | None = None) -> Snapshot:
    """A `Snapshot` built the way `remedy_brief` builds one, from a real mapper map."""
    return take_snapshot(str(target), before_text, before_map, score)


def _compare_edit(tmp_path, before_text: str, after_text: str) -> dict[str, Any]:
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset

    target = tmp_path / "CLAUDE.md"
    target.write_text(before_text, encoding="utf-8")
    before_map = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    snap = _real_snapshot(target, before_map, before_text, score=5.0)

    target.write_text(after_text, encoding="utf-8")
    after_map = map_ruleset([target], models=get_models(), root=tmp_path, cache_dir=None)
    return compare(snap, after_map, after_text, 5.0, LocalProjectEnvironment(tmp_path, target.parent))


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_genuine_no_op_on_the_attack_base_is_ok(tmp_path) -> None:
    result = _compare_edit(tmp_path, _ATTACK_BASE, _ATTACK_BASE)
    assert result["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_deleted_prose_prohibition_sharing_a_named_token_is_lost_not_masked(tmp_path) -> None:
    """In PROSE (no list structure to fall back on) deleting one of two prohibitions that share
    a named token (`main`) must not read as kept just because a differently-worded surviving
    prohibition happens to share that token: the surviving "Never force-push `main`." does not
    stand in for the deleted "Never push to `main` directly."."""
    result = _compare_edit(tmp_path, _PROSE_BEFORE, _PROSE_AFTER)
    assert result["lost_instructions"] == [{"line": 5, "text": "Never push to `main` directly."}]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_prohibition_rewritten_as_a_directive_the_model_reads_as_flipped_is_a_flip(tmp_path) -> None:
    """A prohibition rewritten so the real charge model reads it as a directive (not every
    rephrasing flips polarity under the bundled model — "only through" stays a prohibition, so
    this uses wording the model does classify +1) must report as a `polarity_flips` entry, not
    read as kept via the other `main` prohibition on a different line (the untouched "Never
    force-push `main`." is also charge -1 and also names `main`)."""
    after = _ATTACK_BASE.replace("- Never push to `main` directly.", "- Push to `main` through a pull request.")
    result = _compare_edit(tmp_path, _ATTACK_BASE, after)
    assert result["polarity_flips"] == [
        {
            "line": 6,
            "text": "Never push to `main` directly.",
            "new_line": 6,
            "new_text": "Push to `main` through a pull request.",
        }
    ]
    assert result["lost_instructions"] == []
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_deleted_factual_prose_is_lost_context(tmp_path) -> None:
    """A neutral (charge 0) prose fact the rewrite silently drops is not an "instruction", but
    the drop must still be reported and `ok` must be `False`."""
    after = _ATTACK_BASE.replace("The api runs on port 8001 and reloads from the source tree on every edit.\n\n", "")
    result = _compare_edit(tmp_path, _ATTACK_BASE, after)
    assert result["lost_context"] == [
        {"line": 9, "text": "The api runs on port 8001 and reloads from the source tree on every edit."}
    ]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_constraint_split_into_the_next_bullet_stays_ok(tmp_path) -> None:
    """The packed bullet "Run `pytest` before every commit. *Do not skip `ruff`...*" split
    into two CONSECUTIVE bullets is not detached — its prohibition lands in the block right
    after its directive's block, not merely a different one, so this legitimate split is not a loss."""
    after = _ATTACK_BASE.replace(
        "- Run `pytest` before every commit. *Do not skip `ruff` when it fails.*",
        "- Run `pytest` before every commit.\n- *Do not skip `ruff` when it fails.*",
    )
    result = _compare_edit(tmp_path, _ATTACK_BASE, after)
    assert result["detached_constraints"] == []
    assert result["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_constraint_moved_to_the_end_of_the_file_stays_detached(tmp_path) -> None:
    """A constraint moved far away (not the block right after its
    directive) is still detached."""
    after = (
        _ATTACK_BASE.replace(" *Do not skip `ruff` when it fails.*", "") + "\n- *Do not skip `ruff` when it fails.*\n"
    )
    result = _compare_edit(tmp_path, _ATTACK_BASE, after)
    assert result["detached_constraints"] == [{"line": 7, "text": "*Do not skip `ruff` when it fails.*"}]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_named_token_extended_is_not_lost(tmp_path) -> None:
    """`` `pytest` `` renamed to `` `pytest -q` `` still contains the
    word `pytest` at a word boundary (backtick, not a word character, closes it either side),
    so it is not `lost_named`."""
    after = _ATTACK_BASE.replace("`pytest`", "`pytest -q`")
    result = _compare_edit(tmp_path, _ATTACK_BASE, after)
    assert result["lost_named"] == []


_RESTATED_BASE = """# Reviews

Merge after two approvals.

Note the concern that triggered the review in the first place. *Face it directly — don't dodge. \
If the concern remains after the fix, log it as a followup.*
"""


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_directive_restated_negatively_in_its_own_sentence_reworded_is_not_a_flip(tmp_path) -> None:
    """ "Face it directly — don't dodge." states its instruction once positively and once
    negatively in the same sentence, with no leading prohibition marker on either side; the
    charge model reads the whole sentence as a single scalar, and a reword that only narrows the
    sentence's own emphasis span and fills in the pronoun ("it" -> "that risk", "directly" ->
    "directly in the review") can tip that scalar to the other side of zero without the
    instruction itself flipping — same directive, same negation, on both sides. The rewrite also
    adds a place phrase ("in the review"), which the narrowing check reports, so the verdict as a
    whole is not asserted here."""
    after = _RESTATED_BASE.replace(
        "*Face it directly — don't dodge. If the concern remains after the fix, log it as a followup.*",
        "*Face that risk directly in the review — don't dodge it.* If the concern remains after the fix, "
        "log it as a followup.",
    )
    result = _compare_edit(tmp_path, _RESTATED_BASE, after)
    assert result["polarity_flips"] == []
    assert result["lost_instructions"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before_text", "after_text", "expect_flip"),
    [
        (
            "# Git\n\nNever push to `main` without running the tests.\n",
            "# Git\n\nPush to `main` without running the tests.\n",
            True,
        ),
        (
            "# Reviews\n\nDo not merge a PR that has not been reviewed.\n",
            "# Reviews\n\nMerge a PR that has not been reviewed.\n",
            True,
        ),
        (
            "# Releases\n\nNever deploy on Fridays without approval.\n",
            "# Releases\n\nAlways deploy on Fridays without approval.\n",
            True,
        ),
        (
            "# Reviews\n\nAlways face it directly — don't dodge.\n",
            "# Reviews\n\nFace it directly — don't dodge.\n",
            False,
        ),
        (
            "# Reviews\n\nFace it directly — don't dodge.\n",
            "# Reviews\n\nAlways face it directly — don't dodge.\n",
            False,
        ),
    ],
)
def test_a_leading_polarity_change_is_a_flip_even_when_an_embedded_negation_stays_on_both_sides(
    tmp_path, before_text, after_text, expect_flip
) -> None:
    """Dropping, adding, or swapping an instruction's own leading prohibition marker (`Never`,
    `Do not`) is a real polarity flip even when an unrelated embedded negation cue
    (`without running the tests`, `has not been reviewed`) still appears on both sides — that
    embedded cue alone is not enough to read the pair as a reword. Only a rewrite that keeps the
    same leading marker, has none on either side, or only adds/drops the affirmative intensifier
    (`Always`) — which is not itself a prohibition marker — stays unflagged."""
    result = _compare_edit(tmp_path, before_text, after_text)
    if expect_flip:
        assert len(result["polarity_flips"]) == 1
        assert result["ok"] is False
    else:
        assert result["polarity_flips"] == []
        assert result["ok"] is True


_APPENDED_BASE = """# Working here

## Housekeeping

Add a `## Status` section to the project tracking file (`STATUS.md`) pointing at the latest \
report. This step is required — the tracker is not useful unless the status file references \
it. Replace any existing `## Status` section with the new one.
"""


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_prohibition_silently_appended_to_an_already_kept_instruction_is_added(tmp_path) -> None:
    """The false negative this check closes: a rewrite that keeps the existing instruction word
    for word and tacks on a brand new prohibition the original never had. The appended
    sentence's own words trace only 2/3 to the file, clearing `_ADDED_COVERAGE`."""
    after = _APPENDED_BASE.rstrip("\n") + " Do not edit that tracking file beyond its `## Status` section.\n"
    result = _compare_edit(tmp_path, _APPENDED_BASE, after)
    assert result["added_instructions"] == [
        {"line": 5, "text": "Do not edit that tracking file beyond its `## Status` section."}
    ]
    assert result["lost_instructions"] == []
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# Second set: a packed hedge+prohibition sentence split into a
# same-line directive half and a prohibition half must read as kept; every other ideal
# rewrite stays ok; every subtle-damage rewrite stays not ok.
# ---------------------------------------------------------------------------

_SPLIT_BASE = """# Working here

You should probably try to keep the code clean and tidy.

Maybe run the tests before you push, and never skip the linter.

The build uses a cache under `.cache/` that survives restarts.

## Releases

- Tag releases from `main` only.
- Do not publish from a fork.
"""

# The packed-sentence case gets its own base (rather than `_SPLIT_BASE`) so the specific tool names its packed-
# sentence rewrite names are grounded in the file already — the project's own tool names, not
# an invented construct (`invented_named`, a separate concern these cases do not
# otherwise exercise).
_PACKED_BASE = """# Working here

The project's tools are ruff check, ruff format, and pytest.

You should probably try to keep the code clean and tidy.

Maybe run the tests before you push, and never skip the linter.
"""


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_hedged_packed_sentence_split_into_a_directive_and_a_prohibition_stays_ok(tmp_path) -> None:
    """The hedge "maybe" and the vague "tests"/
    "linter" nouns the rewrite replaces with named constructs must not count against split
    coverage, and the split's two halves carry opposite polarity (a directive half, a
    prohibition half) — `_covered_by_split`'s window must accept a mixed-polarity run that
    holds at least one atom of the snapshot instruction's own polarity. The named constructs
    the rewrite introduces (`ruff check` / `ruff format` / `pytest`) are already the project's
    own tool names (`_PACKED_BASE` names them), so this stays a pure split-coverage exercise and
    never trips `invented_named`."""
    after = _PACKED_BASE.replace(
        "You should probably try to keep the code clean and tidy.",
        "Keep the code clean: run `ruff check` and `ruff format`.",
    ).replace(
        "Maybe run the tests before you push, and never skip the linter.",
        "Run `pytest` before you push. Never skip `ruff check`.",
    )
    result = _compare_edit(tmp_path, _PACKED_BASE, after)
    assert result["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_heading_renamed_to_a_topic_stays_ok(tmp_path) -> None:
    after = _SPLIT_BASE.replace("## Releases", "## Release tagging")
    result = _compare_edit(tmp_path, _SPLIT_BASE, after)
    assert result["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_g2b_a_heading_added_over_a_previously_unheaded_instruction_stays_ok(tmp_path) -> None:
    """A new `## Hygiene` heading placed over the previously unheaded, unchanged directive is
    not read as `added_instructions` — the heading itself is never a charged atom
    `_added_instructions` even sees, and the directive's own text is unchanged so it still
    matches its snapshot counterpart."""
    after = _SPLIT_BASE.replace(
        "You should probably try to keep the code clean and tidy.",
        "## Hygiene\n\nYou should probably try to keep the code clean and tidy.",
    )
    result = _compare_edit(tmp_path, _SPLIT_BASE, after)
    assert result["added_instructions"] == []
    assert result["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_prose_reworded_with_facts_kept_stays_ok(tmp_path) -> None:
    after = _SPLIT_BASE.replace(
        "The build uses a cache under `.cache/` that survives restarts.",
        "Build artifacts are cached under `.cache/`, and the cache survives restarts.",
    )
    result = _compare_edit(tmp_path, _SPLIT_BASE, after)
    assert result["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_prohibition_given_a_reason_stays_ok(tmp_path) -> None:
    after = _SPLIT_BASE.replace(
        "- Do not publish from a fork.", "- Do not publish from a fork, because forks lack the signing key."
    )
    result = _compare_edit(tmp_path, _SPLIT_BASE, after)
    assert result["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_prohibition_merged_away_into_a_directive_is_not_ok(tmp_path) -> None:
    after = _SPLIT_BASE.replace(
        "- Tag releases from `main` only.\n- Do not publish from a fork.\n",
        "- Tag and publish releases from `main`.\n",
    )
    result = _compare_edit(tmp_path, _SPLIT_BASE, after)
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_fact_replaced_by_a_different_fact_is_not_ok(tmp_path) -> None:
    after = _SPLIT_BASE.replace("The build uses a cache under `.cache/` that survives restarts.", "The build is fast.")
    result = _compare_edit(tmp_path, _SPLIT_BASE, after)
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_negation_dropped_in_place_is_not_ok(tmp_path) -> None:
    after = _SPLIT_BASE.replace("never skip the linter", "skip the linter when rushed")
    result = _compare_edit(tmp_path, _SPLIT_BASE, after)
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# `_prohibition_scope_changes` — a matched prohibition (`charge_value < 0`) whose own
# forbidden-object set grew (a new named construct this instruction now bans) or shrank (a
# previously named one it no longer bans) — even when the construct survives, or already
# existed, elsewhere in the file. This is the blind spot `_repeated_named`'s vague-instruction-
# concretized allowance otherwise leaves open for a PROHIBITION specifically: naming what a
# vague DIRECTIVE means is fine, but a prohibition naming something new it now forbids (or
# dropping something it used to forbid) changes what the file bans, independent of the rest of
# the file's own wording.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_prohibition_widened_with_a_new_forbidden_object_is_flagged() -> None:
    """A prohibition that names nothing gains two named constructs — even though both already
    exist elsewhere in the file for a different, permitted purpose, they are new to THIS
    instruction, so its own scope grew."""
    prohibition = _atom(89, "Never walk the whole corpus.", -1)
    widened = _new_atom(
        89,
        0,
        "Never walk the whole `docs/` corpus, by `Glob`, `Grep`, or any other sweep.",
        -1,
        named=("`docs/`", "`Glob`", "`Grep`"),
    )
    result = preservation_named.prohibition_scope_changes([prohibition], {id(prohibition): widened})
    assert result == [
        {
            "line": 89,
            "text": "Never walk the whole corpus.",
            "new_line": 89,
            "new_text": "Never walk the whole `docs/` corpus, by `Glob`, `Grep`, or any other sweep.",
            "added": ["docs/", "glob", "grep"],
            "dropped": [],
        }
    ]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_prohibition_narrowed_by_dropping_a_listed_object_is_flagged() -> None:
    """The mirrored case: a prohibition that named three forbidden constructs drops one — the
    ban on that construct silently disappears even though the other two survive."""
    prohibition = _atom(
        3,
        "Never import `OpenAIClient`, `ClaudeClient`, or `GeminiClient` directly.",
        -1,
        named=("`OpenAIClient`", "`ClaudeClient`", "`GeminiClient`"),
    )
    narrowed = _new_atom(
        3,
        0,
        "Never import `OpenAIClient` or `ClaudeClient` directly.",
        -1,
        named=("`OpenAIClient`", "`ClaudeClient`"),
    )
    result = preservation_named.prohibition_scope_changes([prohibition], {id(prohibition): narrowed})
    assert result == [
        {
            "line": 3,
            "text": "Never import `OpenAIClient`, `ClaudeClient`, or `GeminiClient` directly.",
            "new_line": 3,
            "new_text": "Never import `OpenAIClient` or `ClaudeClient` directly.",
            "added": [],
            "dropped": ["geminiclient"],
        }
    ]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_prohibition_rephrase_keeping_its_named_objects_is_not_flagged() -> None:
    """Guard against over-fire: a pure rephrase that keeps every named object and condition the
    prohibition already had must still pass."""
    prohibition = _atom(
        3, "Never import `OpenAIClient` or `ClaudeClient` directly.", -1, named=("`OpenAIClient`", "`ClaudeClient`")
    )
    reworded = _new_atom(
        3, 0, "Do not directly import `OpenAIClient` or `ClaudeClient`.", -1, named=("`OpenAIClient`", "`ClaudeClient`")
    )
    result = preservation_named.prohibition_scope_changes([prohibition], {id(prohibition): reworded})
    assert result == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_backtick_added_around_a_word_the_prohibition_already_said_is_not_flagged() -> None:
    """Guard against over-fire: a mechanical formatting change — backticking (or emphasising) a
    word the instruction already carried in plain text — must not read as a new forbidden
    object, even though the atom gained a `named_tokens` entry it did not have before."""
    prohibition = _atom(3, "Never force-push main without review.", -1)
    formatted = _new_atom(3, 0, "*Never force-push `main` without review.*", -1, named=("`main`",))
    result = preservation_named.prohibition_scope_changes([prohibition], {id(prohibition): formatted})
    assert result == []


# ---------------------------------------------------------------------------
# A regression pin against a real rewrite of `orient/SKILL.md:89`: `remedy_brief` snapshotted
# this file, a rewrite widened its `## Constraints` prohibition to "by `Glob`, `Grep`, or any
# other sweep" (contradicting the same file's own `help` and prose-resolution steps, which
# require `Glob`/`Grep` for a different, permitted purpose), and the preservation check used to
# report the file `ok: true` anyway. Before this fix, `ok` was `True` here and
# `prohibition_scope_changed` did not exist.
# ---------------------------------------------------------------------------

_ORIENT_WIDEN_BEFORE = (
    "# Orient\n\n## Constraints\n\n"
    "- *Resolve and `Read` only the named (or prose-matched) artifacts — never preload a fixed "
    "trinity, never walk the whole corpus.*\n"
)
_ORIENT_WIDEN_AFTER = (
    "# Orient\n\n## Constraints\n\n"
    "- *Resolve and `Read` only the named (or prose-matched) artifacts — never preload a fixed "
    "trinity.* *Never walk the whole `docs/` corpus, by `Glob`, `Grep`, or any other sweep.*\n"
)


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_the_orient_skill_widened_prohibition_is_not_ok(tmp_path) -> None:
    """The `orient/SKILL.md:89` before/after pair from a real rewrite. A rewrite widened "never
    walk the whole corpus" into a prohibition naming `Glob`/`Grep` as forbidden means —
    constructs the same file requires elsewhere for a different, permitted use — and the
    preservation check used to let it through as preserved."""
    result = _compare_edit(tmp_path, _ORIENT_WIDEN_BEFORE, _ORIENT_WIDEN_AFTER)
    assert result["ok"] is False
    entry = next(e for e in result["prohibition_scope_changed"] if "walk the whole" in e["text"])
    assert entry["line"] == 5, "names the prohibition line, for the caller to quote"
    assert entry["added"] == ["docs/", "glob", "grep"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_mirrored_narrowing_drops_a_listed_forbidden_object_is_not_ok(tmp_path) -> None:
    """Mirrors the widening case above in the opposite direction: a prohibition already naming
    two forbidden means (the `Glob`/`Grep` pair from the rewrite above) drops one — the ban on
    `Grep` silently disappears even though the rest of the bullet is untouched."""
    before = "# Orient\n\n## Constraints\n\n- *Never walk the whole corpus, by `Glob`, `Grep`, or any other sweep.*\n"
    after = "# Orient\n\n## Constraints\n\n- *Never walk the whole corpus, by `Glob` or any other sweep.*\n"
    result = _compare_edit(tmp_path, before, after)
    assert result["ok"] is False
    entry = next(iter(result["prohibition_scope_changed"]))
    assert entry["line"] == 5, "names the prohibition line, for the caller to quote"
    assert entry["dropped"] == ["grep"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_prohibition_rephrased_keeping_its_objects_stays_ok(tmp_path) -> None:
    """Guard against over-fire: a pure rephrase of the prohibition's own named objects and
    conditions must still pass."""
    before = "# Agent\n\nNever import `OpenAIClient` or `ClaudeClient` directly.\n"
    after = "# Agent\n\nDo not directly import `OpenAIClient` or `ClaudeClient`.\n"
    result = _compare_edit(tmp_path, before, after)
    assert result["ok"] is True
    assert result["prohibition_scope_changed"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_prohibition_s_mechanical_formatting_change_stays_ok(tmp_path) -> None:
    """Guard against over-fire: backticking a word the prohibition already said in plain text is
    formatting, not a new forbidden object."""
    before = "# Git\n\nNever force-push main without review.\n"
    after = "# Git\n\n*Never force-push `main` without review.*\n"
    result = _compare_edit(tmp_path, before, after)
    assert result["ok"] is True
    assert result["prohibition_scope_changed"] == []


# ---------------------------------------------------------------------------
# Regression coverage measured against a real corpus of rewritten instruction files: the flags
# a hand-read of that corpus judged correct (each stays flagged after the over-fire fixes
# below), and the over-fire shapes an example or a trailing reason clause produced on that same
# corpus (each must now stay ok).
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_condition_silently_added_before_a_restriction_is_not_ok(tmp_path) -> None:
    """An unconditional "only modify `X`, `Y`, `Z`" restriction gains a
    `During `/refine-rule`,` prefix — outside that command the rewrite no longer restricts
    modification at all, exactly the "condition added" `PRESERVATION_CONTRACT` forbids."""
    before = "# Rule writer\n\n*only modify `patterns`, `message`, and `vocab.yml`.*\n"
    after = (
        "# Rule writer\n\n*During `/refine-rule`, only modify the `patterns` and `message` "
        "fields in `checks.yml`, plus `vocab.yml`.*\n"
    )
    result = _compare_edit(tmp_path, before, after)
    assert result["ok"] is False
    entry = next(iter(result["prohibition_scope_changed"]))
    assert "/refine-rule" in entry["added"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_test_fixtures_narrowed_to_two_named_directories_is_not_ok(tmp_path) -> None:
    """`tighten-language/SKILL.md:46`: "test fixtures" (unqualified) narrows to only fixtures
    under two named directories. Regression pin: an earlier version of the
    referent-concretization guard also cleared "test" (the adjective in "test fixtures") against
    "tests" (the directory name in `tests/pass/`) as the same referent and wrongly suppressed
    this flag — the guard is exact-word-match only now, precisely so this stays caught."""
    before = "# Rules\n\n*Do NOT change `checks.yml`, `vocab.yml`, or test fixtures*\n"
    after = (
        "# Rules\n\n*Do NOT change `checks.yml`, `vocab.yml`, or test fixtures in `tests/pass/` and `tests/fail/`*\n"
    )
    result = _compare_edit(tmp_path, before, after)
    assert result["ok"] is False
    entry = next(iter(result["prohibition_scope_changed"]))
    assert set(entry["added"]) == {"tests/pass/", "tests/fail/"}


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_an_exclusion_narrowed_to_one_named_location_is_not_ok(tmp_path) -> None:
    """`update-public-docs/SKILL.md:76`: an unqualified "EXCLUDE" narrows to excluding only from
    one named location — elsewhere, documenting the same categories is now silently allowed."""
    before = "# Docs\n\n**EXCLUDE:**\n"
    after = "# Docs\n\n*EXCLUDE: Do not document any of these categories in `reflexio/public_docs/`:*\n"
    result = _compare_edit(tmp_path, before, after)
    assert result["ok"] is False
    entry = next(iter(result["prohibition_scope_changed"]))
    assert entry["added"] == ["reflexio/public_docs/"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_an_illustrative_such_as_example_stays_ok(tmp_path) -> None:
    """ "do not write production code" gains "such as `X`", naming one instance of the SAME
    already-forbidden category, not a new one."""
    source = "Production code lives in `src/reporails_cli/**/*.py`.\n"
    before = "# Agent\n\n" + source + "\n*Do not write production code from this role.*\n"
    after = (
        "# Agent\n\n"
        + source
        + "\n*Do not write production code such as `src/reporails_cli/**/*.py` from this role.*\n"
    )
    result = _compare_edit(tmp_path, before, after)
    assert result["ok"] is True
    assert result["prohibition_scope_changed"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_like_the_x_example_below_pointer_stays_ok(tmp_path) -> None:
    """`fastapi/SKILL.md:395` — an over-fire fix: a prohibition gains a "like the `X` example
    below" pointer to an illustration, not a new forbidden object. An earlier version of this
    check flagged this rewrite."""
    example = '\n```python\n@app.api_route("/items", methods=["GET", "POST"])\ndef items(): ...\n```\n'
    before = (
        "# FastAPI\n\nDon't mix HTTP operations in a single function, having one function per "
        "HTTP operation helps separate concerns\n" + example
    )
    after = (
        "# FastAPI\n\n*Don't mix HTTP operations in a single function, like the "
        "`@app.api_route` example below.*\n" + example
    )
    result = _compare_edit(tmp_path, before, after)
    assert result["ok"] is True
    assert result["prohibition_scope_changed"] == []


def _snap_item(line: int, text: str) -> Any:
    return SnapshotAtom(line, text, 1, (), "list", None)


def _new_item(line: int, text: str) -> Any:
    return SimpleNamespace(line=line, text=text, named_tokens=(), embedding_int8=None)


def _moved(snap: list[Any], new: list[Any], pairs: dict[int, int], before: str, after: str) -> list[int]:
    """`_moved_list_items` over hand-placed atoms: `pairs` maps a snapshot line to the new line it matched."""
    new_at = {na.line: na for na in new}
    matched = {id(sa): new_at[pairs[sa.line]] for sa in snap if sa.line in pairs}
    return [
        m["line"]
        for m in preservation_structure.moved_list_items(
            snap, matched, read_structure(before), read_structure(after), new
        )
    ]


def _doc(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def _items(make: Any, *pairs: tuple[int, str]) -> list[Any]:
    return [make(line, text) for line, text in pairs]


_KEEP = "Keep reports free of internal jargon terms."
_WRITE = "Write the report file."
_SORT = "Sort the findings by severity."
_NAME = "Name the output file."


@pytest.mark.unit
@pytest.mark.subsys_server
def test_in_a_two_item_list_only_the_item_that_left_its_section_is_moved() -> None:
    before = _doc("## Checks", f"- {_KEEP}", f"- {_WRITE}", "## Report", f"- {_SORT}", f"- {_NAME}")
    after = _doc(
        "## Checks",
        "- Write the report file to disk.",
        "## Report",
        "- Sort the findings by severity first.",
        f"- {_NAME}",
        "- Keep every report free of internal jargon terms.",
    )
    snap = _items(_snap_item, (2, _KEEP), (3, _WRITE), (5, _SORT), (6, _NAME))
    new = _items(
        _new_item,
        (2, "Write the report file to disk."),
        (4, "Sort the findings by severity first."),
        (5, _NAME),
        (6, "Keep every report free of internal jargon terms."),
    )
    assert _moved(snap, new, {2: 6, 3: 2, 5: 4, 6: 5}, before, after) == [2]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_two_items_that_left_their_section_together_are_moved_and_the_one_that_stayed_is_not() -> None:
    before = _doc("## Checks", f"- {_KEEP}", f"- {_WRITE}", f"- {_SORT}", "## Report", f"- {_NAME}")
    after = _doc(
        "## Checks",
        f"- {_KEEP}",
        "## Report",
        f"- {_NAME}",
        "- Write the report file to disk.",
        "- Sort the findings by severity first.",
    )
    snap = _items(_snap_item, (2, _KEEP), (3, _WRITE), (4, _SORT), (6, _NAME))
    new = _items(
        _new_item,
        (2, _KEEP),
        (4, _NAME),
        (5, "Write the report file to disk."),
        (6, "Sort the findings by severity first."),
    )
    assert _moved(snap, new, {2: 2, 3: 5, 4: 6, 6: 4}, before, after) == [3, 4]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_near_duplicate_paired_with_its_twin_in_another_list_is_not_moved_while_its_own_list_holds_a_match() -> None:
    run_draft = "Run checks C1-C5 against the draft."
    run_output = "Run checks C1-C5 against the draft output."
    run_drafted = "Run checks C1-C5 against the drafted report."
    before = _doc(
        "## Draft", f"- {run_draft}", f"- {_WRITE}", f"- {_SORT}", "## Review", f"- {run_output}", f"- {_NAME}"
    )
    after = _doc(
        "## Draft",
        f"- {run_drafted}",
        "- Write the report file to disk.",
        "- Sort the findings by severity first.",
        "## Review",
        f"- {run_output}",
        f"- {_NAME}",
    )
    snap = _items(_snap_item, (2, run_draft), (3, _WRITE), (4, _SORT), (6, run_output), (7, _NAME))
    new = _items(
        _new_item,
        (2, run_drafted),
        (3, "Write the report file to disk."),
        (4, "Sort the findings by severity first."),
        (6, run_output),
        (7, _NAME),
    )
    # the one-to-one assignment crossed the two near-duplicates
    assert _moved(snap, new, {2: 6, 3: 3, 4: 4, 6: 2, 7: 7}, before, after) == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_dropping_an_example_from_a_prohibition_is_not_a_scope_change() -> None:
    """A construct the original gave only as an example is not something the rewrite stopped
    forbidding: the same prohibition without its example still forbids the same thing."""
    prohibition = _atom(5, "Never commit secrets (e.g. `.env`).", -1, named=("`.env`",))
    rewritten = _new_atom(5, 0, "Never commit secrets.", -1, named=())
    assert preservation_named.prohibition_scope_changes([prohibition], {id(prohibition): rewritten}) == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_dropping_a_governing_construct_from_a_prohibition_is_still_flagged() -> None:
    prohibition = _atom(6, "Never commit `.env` files.", -1, named=("`.env`",))
    rewritten = _new_atom(6, 0, "Never commit files.", -1, named=())
    result = preservation_named.prohibition_scope_changes([prohibition], {id(prohibition): rewritten})
    assert result and result[0]["dropped"] == [".env"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_prohibition_whose_words_are_scattered_over_the_file_is_still_added() -> None:
    """A prohibition appended to a bullet is new when its words trace to several unrelated
    sentences of the original rather than to one sentence that already says it."""
    snapshot_text = (
        "# Agent\n\n- Merge the pull request into main after review.\n"
        "- Teams push release tags from the release branch. Never skip review. CI runs directly on every branch.\n"
    )
    added = _new_atom(3, 1, "Never push to `main` directly.", -1)
    result = preservation_match.added_instructions(snapshot_text, (added,), {}, {})
    assert result == [{"line": 3, "text": "Never push to `main` directly."}]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_prohibition_the_original_line_already_states_is_not_added() -> None:
    snapshot_text = "# Agent\n\n- Never push directly to main.\n"
    restated = _new_atom(3, 1, "Never push to `main` directly.", -1)
    assert preservation_match.added_instructions(snapshot_text, (restated,), {}, {}) == []


# ---------------------------------------------------------------------------
# A bare negative heading keeps its label; an instruction gains no condition.
# ---------------------------------------------------------------------------

_DONTS_BEFORE = """## Don'ts

- Use mock objects in tests.
- Use test doubles in the test suite.

## Testing

Use real objects in tests.
"""


def _dont_items(*texts: str) -> tuple[SimpleNamespace, ...]:
    return tuple(_new_atom(3 + i, i, t, -1, heading_context="Don'ts") for i, t in enumerate(texts))


def _heading_atoms(text: str) -> tuple[SimpleNamespace, ...]:
    """Neutral heading atoms for each `#` heading line of `text`, as the mapper reads them."""
    return tuple(
        SimpleNamespace(
            line=n,
            position_index=0,
            text=line.lstrip("# ").strip(),
            plain_text=line.lstrip("# ").strip(),
            charge_value=0,
            named_tokens=[],
            embedding_int8=None,
            kind="heading",
            role="",
            file_path=_FILE,
            format="heading",
            heading_context="",
            scope_conditional=False,
        )
        for n, line in enumerate(text.split("\n"), start=1)
        if line.startswith("#")
    )


def _dont_snapshot() -> Snapshot:
    atoms = (
        _atom(1, "Don'ts", 0, format="heading", heading=True),
        _atom(3, "Use mock objects in tests.", -1, format="list", heading_context="Don'ts"),
        _atom(4, "Use test doubles in the test suite.", -1, format="list", heading_context="Don'ts"),
    )
    return _snapshot(_DONTS_BEFORE, atoms)


def _relabelled(after_text: str, items: tuple[SimpleNamespace, ...]) -> dict[str, Any]:
    return compare(_dont_snapshot(), _new_map(_heading_atoms(after_text) + items), after_text, score_after=6.0)


_NEGATED = ("Do not use mock objects in tests.", "Do not use test doubles in the test suite.")


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_bare_negative_heading_renamed_over_negated_items_is_not_ok() -> None:
    after = "## Test doubles\n\n- Do not use mock objects in tests.\n- Do not use test doubles in the test suite.\n"
    result = _relabelled(after, _dont_items(*_NEGATED))
    assert result["relabelled_negative_headings"] == [{"line": 1, "text": "## Don'ts"}]
    assert result["ok"] is False


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_bare_negative_heading_replaced_by_another_negative_label_is_listed() -> None:
    after = _DONTS_BEFORE.replace("## Don'ts", "## Never")
    result = _relabelled(after, _dont_items("Use mock objects in tests.", "Use test doubles in the test suite."))
    assert result["relabelled_negative_headings"] == [{"line": 1, "text": "## Don'ts"}]
    assert result["ok"] is False


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_bare_negative_heading_kept_with_its_items_reworded_in_place_is_not_listed() -> None:
    after = _DONTS_BEFORE.replace("- Use mock", "- Do not use mock").replace("- Use test", "- Do not use test")
    result = _relabelled(after, _dont_items(*_NEGATED))
    assert result["relabelled_negative_headings"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("label", ["### Don'ts", "## DON'TS", "## Don\u2019ts"])
def test_a_bare_negative_heading_kept_at_another_level_or_case_is_not_listed(label: str) -> None:
    after = _DONTS_BEFORE.replace("## Don'ts", label)
    result = _relabelled(after, _dont_items("Use mock objects in tests.", "Use test doubles in the test suite."))
    assert result["relabelled_negative_headings"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_file_with_no_bare_negative_heading_lists_no_relabelled_heading() -> None:
    before = "## Never use mocks\n\n- Use real objects.\n"
    snap = _snapshot(before, (_atom(3, "Use real objects.", 1, format="list"),))
    result = compare(
        snap, _new_map((_new_atom(3, 0, "Use real objects.", 1),)), "## Testing\n\n- Use real objects.\n", 6.0
    )
    assert result["relabelled_negative_headings"] == []
    assert result["added_conditions"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_relabelled_heading_on_a_relation_named_line_is_exempt() -> None:
    snap = _snapshot(
        _DONTS_BEFORE, (_atom(1, "Don'ts", 0, format="heading", heading=True),), relation_lines=frozenset({1})
    )
    result = compare(snap, _new_map(_heading_atoms("## Test doubles\n")), "## Test doubles\n", score_after=6.0)
    assert result["relabelled_negative_headings"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("charge", [1, -1])
def test_an_instruction_that_gains_a_condition_is_listed(charge: int) -> None:
    before_text = "# Agent\n\nUse real objects in tests.\n"
    snap = _snapshot(before_text, (_atom(3, "Use real objects in tests.", charge),))
    new = _new_atom(
        3, 0, "Use real objects in tests whenever a test touches the database.", charge, scope_conditional=True
    )
    result = compare(snap, _new_map((new,)), "# Agent\n\nnew\n", score_after=6.0)
    assert result["added_conditions"] == [
        {
            "line": 3,
            "text": "Use real objects in tests.",
            "new_line": 3,
            "new_text": "Use real objects in tests whenever a test touches the database.",
        }
    ]
    assert result["ok"] is False


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_instruction_that_was_conditional_and_stays_conditional_is_not_listed() -> None:
    before_text = "# Agent\n\nUse real objects in tests when a test touches the database.\n"
    snap = _snapshot(
        before_text,
        (_atom(3, "Use real objects in tests when a test touches the database.", 1, scope_conditional=True),),
    )
    new = _new_atom(3, 0, "Use real objects in tests if a test touches the database.", 1, scope_conditional=True)
    result = compare(snap, _new_map((new,)), before_text, score_after=6.0)
    assert result["added_conditions"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_instruction_reworded_with_no_condition_is_not_listed() -> None:
    before_text = "# Agent\n\nUse real objects in tests.\n"
    snap = _snapshot(before_text, (_atom(3, "Use real objects in tests.", 1),))
    new = _new_atom(3, 0, "Use real objects in the tests.", 1)
    result = compare(snap, _new_map((new,)), before_text, score_after=6.0)
    assert result["added_conditions"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_renamed_bare_negative_heading_over_negated_items_is_not_ok_on_the_real_mapper(tmp_path) -> None:
    after = (
        "## Test doubles\n\n- Do not use mock objects in tests.\n"
        "- Do not use test doubles in the test suite.\n\n## Testing\n\nUse real objects in tests.\n"
    )
    result = _compare_edit(tmp_path, _DONTS_BEFORE, after)
    assert result["ok"] is False
    assert result["relabelled_negative_headings"] == [{"line": 1, "text": "## Don'ts"}]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_condition_added_to_a_directive_is_not_ok_on_the_real_mapper(tmp_path) -> None:
    after = _DONTS_BEFORE.replace(
        "Use real objects in tests.", "Use real objects in tests whenever a test touches the database."
    )
    result = _compare_edit(tmp_path, _DONTS_BEFORE, after)
    assert result["ok"] is False
    assert [e["line"] for e in result["added_conditions"]] == [8]
    assert result["relabelled_negative_headings"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_bold_around_a_bare_url_turning_italic_removes_no_link() -> None:
    before = "# Agent\n\nNever skip **https://x.com/docs** first.\n"
    after = "# Agent\n\nNever skip *https://x.com/docs* first.\n"
    result = compare(_snapshot(before, ()), _new_map(()), after, score_after=6.0)
    assert result["removed_structure"]["links"] == 0


@pytest.mark.unit
@pytest.mark.subsys_server
def test_sibling_texts_leave_out_a_project_that_shares_a_name_prefix(tmp_path: Path) -> None:
    """`/x/proj` does not pick up the snapshots of `/x/proj2`."""
    from reporails_cli.core.heal.preservation import Snapshot
    from reporails_cli.interfaces.mcp import snapshots

    def snap(path: Path, text: str) -> Snapshot:
        return Snapshot(file_path=str(path), text=text, atoms=(), score=None)

    snapshots.clear_snapshots()
    try:
        own, mine, other = tmp_path / "proj" / "a.md", tmp_path / "proj" / "b.md", tmp_path / "proj2" / "c.md"
        for path, text in ((own, "own"), (mine, "mine"), (other, "other")):
            snapshots._snapshots[snapshots._key(path)] = snap(path, text)
        assert snapshots.sibling_texts(snapshots._snapshots[snapshots._key(own)], tmp_path / "proj") == ("mine",)
    finally:
        snapshots.clear_snapshots()


_ESCAPED_LINE = "Rewrite hedges as an imperative: `Use \\`ruff\\`` or `run \\`uv run ails check .\\``."
_ESCAPED_NORMALIZED = "Rewrite hedges as an imperative: `Use \\\\`ruff`orrun `uv run ails check .``."
_ESCAPED_TOKENS = ("Use \\\\", "orrun ")


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_line_with_escaped_backticks_in_code_compares_ok_with_itself() -> None:
    """The mapper normalizes escaped backticks inside a code span, so its named tokens never
    occur in the raw text; the same text on both sides is still no loss and no invention."""
    text = f"# Lint\n\n{_ESCAPED_LINE}\n"
    snap = _snapshot(text, (_atom(3, _ESCAPED_NORMALIZED, 1, named=_ESCAPED_TOKENS),))
    new_atoms = (_new_atom(3, 0, _ESCAPED_NORMALIZED, 1, named=_ESCAPED_TOKENS),)
    result = compare(snap, _new_map(new_atoms), text, score_after=6.0)
    assert result["lost_named"] == []
    assert result["invented_named"] == []
    assert result["ok"] is True


@pytest.mark.unit
@pytest.mark.subsys_server
def test_deleting_a_line_with_escaped_backticks_is_still_a_loss() -> None:
    """Deleting the line is reported: its instruction is lost."""
    before = f"# Lint\n\n{_ESCAPED_LINE}\n"
    snap = _snapshot(before, (_atom(3, _ESCAPED_NORMALIZED, 1, named=_ESCAPED_TOKENS),))
    result = compare(snap, _new_map(()), "# Lint\n", score_after=6.0)
    assert result["ok"] is False
    assert result["lost_instructions"]
