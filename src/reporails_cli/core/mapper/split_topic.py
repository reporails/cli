"""Topic split of over-merged atoms into separate instruction atoms.

Acts on the granularity audit: an atom flagged `over_merged` packs
clauses that span unrelated topics into one blurred vector. This pass splits such
atoms at clause boundaries so each resulting atom carries one charge over one
topic, re-classifying and re-embedding each sub-atom.

The split is embedding-*driven* — it runs only where the audit's clause-cosine
measurement flagged the atom, never a blind clause cut. The unit it produces is
one instruction, not one sentence: the sub-atoms are emitted as *separate*
atoms, each with its own position and vector.

Charge for each sub-atom is re-derived through the `recharge` callable the caller
supplies, so sub-atoms carry the caller's charge source. With no recharge, a
sub-atom keeps the charge `build_split_atom` assigned it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from reporails_cli.core.mapper.embed import _embed_atoms_deduped
from reporails_cli.core.mapper.lexical import split_clauses
from reporails_cli.core.mapper.markers import reformat_spans
from reporails_cli.core.mapper.parse import TABLE_HEADER_RULE, build_split_atom, keep_lead_in_on_last, reindex_positions
from reporails_cli.core.platform.dto.ruleset import Atom


def split_over_merged_atoms(
    atoms: list[Atom],
    encoder: Any,
    recharge: Callable[[list[Atom]], None] | None = None,
) -> tuple[list[Atom], int]:
    """Split over-merged atoms into per-clause sub-atoms; re-index positions.

    Returns the rebuilt atom list and the count of parent atoms that were split.
    Sub-atoms are re-classified (`build_split_atom`), re-charged via `recharge`
    (the caller's charge source) when supplied, and re-embedded. Position
    indices are recomputed per `file_path` (document order within each file),
    matching the per-file re-index `_apply_charge_stage` already applied — a
    single counter over the whole atom set would give every file after the
    first a position starting past zero.
    """
    result: list[Atom] = []
    fresh: list[Atom] = []
    n_split = 0
    for atom in atoms:
        # An atom already cut into instructions (`stage == "multislot"`) keeps its
        # subordinate clause as part of the instruction; cutting it again at clause markers
        # would fragment every `when ...` / `— ...` clause into an atom of its own.
        # The split applies only to atoms that were not cut that way. A table header row is a
        # column label, never an instruction, whatever its cells' words are — re-cutting it
        # can charge a fragment of its own label text (`rule == TABLE_HEADER_RULE`). A fenced
        # line was already classified once, as one line, by the fence cascade (`parse.py`'s
        # own "classify each line ONCE" contract) — re-cutting it here re-opens that verdict
        # on a fragment of the same line, so it is excluded too.
        eligible = (
            atom.over_merged
            and atom.stage != "multislot"
            and atom.rule != TABLE_HEADER_RULE
            and atom.format != "code_block"
        )
        clauses = split_clauses(atom.plain_text or atom.text) if eligible else []
        if len(clauses) < 2:
            result.append(atom)
            continue
        # Clauses come from the AST-clean text; put the parent's backticks and
        # emphasis back on each so the sub-atom's specificity reads them (else
        # every backticked name in a split atom comes out `abstract`).
        plains = clauses
        if atom.plain_text:
            clauses = reformat_spans(atom.text, atom.plain_text, clauses)
        subs = [build_split_atom(c, atom, plain_sent=pl) for c, pl in zip(clauses, plains, strict=True)]
        keep_lead_in_on_last(subs)
        result.extend(subs)
        fresh.extend(subs)
        n_split += 1

    if fresh:
        if recharge is not None:
            recharge(fresh)
        _embed_atoms_deduped(fresh, encoder)

    reindex_positions(result)
    return result, n_split
