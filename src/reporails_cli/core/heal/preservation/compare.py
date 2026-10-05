"""The preservation comparison: a rewrite judged whole against the snapshot taken before it. Runs
every check and builds the `preservation` block a rewrite check returns.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.heal.preservation import conditions, structure
from reporails_cli.core.heal.preservation.match import added_instructions, instruction_diffs, lost_context
from reporails_cli.core.heal.preservation.named import (
    invented_named,
    lost_named_tokens,
    prohibition_scope_changes,
    repeated_named,
)
from reporails_cli.core.heal.preservation.snapshot import (
    Snapshot,
    SnapshotAtom,
    is_hedge_fragment,
    is_instruction_heading,
    rewritten_atoms,
)
from reporails_cli.core.lint.content_queries import atoms_for_file
from reporails_cli.core.mapper.structure import read_structure
from reporails_cli.core.platform.contract.environment import ProjectEnvironment
from reporails_cli.core.platform.dto.structure import DocumentStructure
from reporails_cli.core.platform.policy.negative_headings import is_negative_heading

# The fixed preservation-contract text shown in the `remedy_brief` reply. Byte-identical —
# the plugin quotes it verbatim.
PRESERVATION_CONTRACT = (
    "Keep every instruction: each keeps its polarity — a prohibition stays a prohibition — its scope, "
    "with no condition or exception added or dropped, and every construct it names. Keep every table "
    "row, list item, heading, fenced block, example and link, each list item in its own list; delete "
    "one only when a relation names it as a true duplicate of its partner. Keep a bare negative heading "
    "such as `## Don'ts` exactly as it is, with its items under it. Keep each constraint "
    "directly after the directive it limits. Add no filler and invent nothing: an instruction grows "
    "only by a construct the file already names or that exists in the project, or a reason the file "
    "already gives — never by repeating one it already names."
)

# Findings that are reported but never fail the rewrite.
_LISTED_ONLY = frozenset({"removed_structure", "made_direct"})


def _negative_heading_texts(new_map: Any, file_path: str) -> list[str]:
    """The text of each bare negative heading the mapper reads in `new_map`'s `file_path`,
    whatever its markdown style (`##`, underlined, inside a quote)."""
    atoms = atoms_for_file(new_map, file_path) if new_map is not None else ()
    return [a.text for a in atoms if a.kind == "heading" and is_negative_heading(a.text)]


def _run_checks(
    snapshot: Snapshot,
    snap_atoms: list[SnapshotAtom],
    new: tuple[list[Any], str, list[Any], DocumentStructure],
    grounding: tuple[ProjectEnvironment | None, tuple[str, ...]],
    negative_headings: tuple[list[SnapshotAtom], list[str]],
) -> dict[str, Any]:
    """Every preservation check's finding list/dict, keyed exactly as `compare()`'s reply.
    `new` is the rewrite's instruction atoms, its text and its whole-file atoms; `grounding` is the
    project environment and the original text of the sibling files; `negative_headings` is the snapshot's
    bare negative heading atoms and the rewrite's bare negative heading texts."""
    new_atoms, new_text, new_all, new_structure = new
    lost_instructions, polarity_flips, matched_new_for, split_covering_for = instruction_diffs(snap_atoms, new_atoms)
    sentences = (conditions.by_line(snapshot.atoms), conditions.by_line(new_all))
    pairs = conditions.pair_up(snap_atoms, matched_new_for, *sentences)
    return {
        "lost_instructions": lost_instructions,
        "polarity_flips": polarity_flips,
        "added_instructions": added_instructions(snapshot.text, new_atoms, matched_new_for, split_covering_for),
        "lost_named": lost_named_tokens(snap_atoms, new_text, new_atoms),
        "invented_named": invented_named(snapshot.text, new_atoms, *grounding, snap_atoms),
        "repeated_named": repeated_named(
            snap_atoms, new_atoms, matched_new_for, split_covering_for, snapshot.text, new_text
        ),
        "detached_constraints": structure.detached_constraints(snap_atoms, matched_new_for, new_structure),
        "prohibition_scope_changed": prohibition_scope_changes(snap_atoms, matched_new_for),
        "added_conditions": conditions.added_conditions(snap_atoms, matched_new_for),
        "dropped_conditions": conditions.dropped_conditions(pairs),
        "narrowed_instructions": conditions.narrowed_instructions(pairs, sentences[0]),
        "hedge_made_absolute": conditions.hedge_made_absolute(pairs, sentences[0]),
        "padded_lines": structure.padded_lines(list(snapshot.atoms), new_atoms),
        "made_direct": conditions.made_direct(pairs, snap_atoms, new_atoms, matched_new_for, sentences),
        "relabelled_negative_headings": structure.relabelled_negative_headings(snapshot.text, *negative_headings),
        "lost_context": lost_context(snap_atoms, new_text),
        "moved_list_items": structure.moved_list_items(
            snap_atoms, matched_new_for, snapshot.structure, new_structure, new_atoms
        ),
        "removed_structure": structure.removed_structure(snapshot.structure, new_structure, snapshot.relation_lines),
    }


def _kept_counts(snap_atoms: list[SnapshotAtom], snapshot: Snapshot, checks: dict[str, Any]) -> dict[str, int]:
    """What the rewrite kept, as counts: the snapshot's own totals minus what the checks found
    lost / removed. `instructions` is the snapshot's charged-atom count minus `lost_instructions`
    (a flipped or moved instruction is still present, just changed — only a true loss subtracts);
    the structural counts are each `structure_totals` entry minus its `removed_structure` twin.
    Never negative — `max(0, ...)` guards a check that (in principle) over-counts a removal past
    the snapshot's own total."""
    total_instructions = sum(1 for sa in snap_atoms if sa.charge_value != 0)
    totals = structure.structure_totals(snapshot.structure, snapshot.relation_lines)
    removed = checks["removed_structure"]
    return {
        "instructions": max(0, total_instructions - len(checks["lost_instructions"])),
        **{key: max(0, totals[key] - removed[key]) for key in totals},
    }


def compare(
    snapshot: Snapshot,
    new_map: Any,
    new_text: str,
    score_after: float | None,
    environment: ProjectEnvironment | None = None,
    sibling_texts: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Compare `snapshot` against the file's current map + text; returns the `preservation`
    block a `validate(path=<file>)` reply carries for a snapshotted file.

    Lines a relation names as a true duplicate are dropped from the snapshot before every
    check; no other line is deletion-safe. Prose a rewrite deletes is reported when under half of
    its content words survive anywhere in the rewrite (`lost_context`).
    `kept` reports the flip side of the same checks — what survived, as counts.
    `invented_named` — a new-file named token the snapshot and `sibling_texts` (the original text
    of the other files briefed with it) never named and that is not an existing path or a
    known program according to `environment` — is part of `ok` same as every other check;
    `environment` is `None` for a caller with no project to ask.
    `added_instructions` — a charged new atom with no snapshot counterpart whose content words are
    mostly absent from the snapshot's whole text — is part of `ok` too.
    `prohibition_scope_changed` — a matched prohibition whose own forbidden-object set grew or
    shrank — is part of `ok` too, even when the construct in question survives elsewhere in the file.
    `added_conditions` — a matched instruction that was unconditional and now sits in an if /
    when / unless frame carrying words its original line never had — is part of `ok` too.
    `made_direct` lists each hedged instruction the rewrite made direct (`prefer X` -> `use X`) with its
    sentence before and after; it never fails the rewrite. `hedge_made_absolute` — a hedge turned
    into `Never` / `Always` where the line had neither word — `narrowed_instructions` — words added that
    restrict where, when or to what an instruction applies — `dropped_conditions` — a condition
    the original instruction held that the rewrite no longer holds — and `padded_lines` — atoms
    added that copy an atom the file already has — are part of `ok` too.
    `relabelled_negative_headings` — a bare negative heading (`## Don'ts`) with no heading of the
    same label left in the rewrite — is part of `ok` too: the label is what makes every item
    under it a prohibition.
    """
    live = [a for a in snapshot.atoms if a.line not in snapshot.relation_lines]
    snap_atoms = [a for a in live if (not a.heading or is_instruction_heading(a)) and not is_hedge_fragment(a)]
    new_atoms = rewritten_atoms(new_map, snapshot.file_path)
    new_all = atoms_for_file(new_map, snapshot.file_path) if new_map is not None else []
    negative_headings = (
        [a for a in live if a.heading and is_negative_heading(a.text)],
        _negative_heading_texts(new_map, snapshot.file_path),
    )
    checks = _run_checks(
        snapshot,
        snap_atoms,
        (new_atoms, new_text, sorted(new_all, key=lambda a: (a.line, a.position_index)), read_structure(new_text)),
        (environment, sibling_texts),
        negative_headings,
    )
    ok = not any(v for k, v in checks.items() if k not in _LISTED_ONLY) and all(
        v == 0 for v in checks["removed_structure"].values()
    )
    kept = _kept_counts(snap_atoms, snapshot, checks)
    return {"ok": ok, "score_before": snapshot.score, "score_after": score_after, **checks, "kept": kept}
