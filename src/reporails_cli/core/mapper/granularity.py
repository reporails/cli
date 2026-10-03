"""Mapper granularity audit — flag over-merged multi-clause atoms.

Diagnostic-only pass (atom boundaries unchanged): split each eligible atom into
clauses, embed the clauses, and measure the minimum pairwise similarity. An atom
whose clauses sit below the coherence floor is flagged `over_merged`.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.mapper.lexical import split_clauses
from reporails_cli.core.platform.dto.ruleset import Atom

# Clauses of one atom sitting below this similarity count as distinct topics.
_OVER_MERGED_COSINE = 0.5


def _audit_eligible(atom: Atom) -> bool:
    """Non-heading atoms with text are eligible for the clause-coherence audit.

    A unit the classifier already segmented is excluded —
    its subordinate clause is a scope slot, not a lexical over-merge, and
    `split_topic.py` skips it for the same reason: the audit should only flag
    atoms the split can actually act on, or its flags reach no consumer.
    """
    return atom.kind != "heading" and atom.stage != "multislot" and bool((atom.plain_text or atom.text).strip())


def _min_pairwise_cosine(vecs: Any) -> float:
    """Minimum off-diagonal cosine of L2-normalized row vectors (k >= 2)."""
    sims = vecs @ vecs.T
    k = sims.shape[0]
    return min(float(sims[i, j]) for i in range(k) for j in range(i + 1, k))


def audit_over_merged(atoms: list[Atom], encoder: Any) -> int:
    """Flag multi-clause atoms whose clauses are topically incoherent.

    Sets `over_merged` and `min_clause_cosine` in place on each eligible
    multi-clause atom. Clause strings are deduped across atoms into one encode
    call. Returns the number of atoms flagged over-merged.
    """
    targets: list[tuple[Atom, list[str]]] = []
    for atom in atoms:
        if not _audit_eligible(atom):
            continue
        clauses = split_clauses(atom.plain_text or atom.text)
        if len(clauses) >= 2:
            targets.append((atom, clauses))
    if not targets:
        return 0

    index: dict[str, int] = {}
    order: list[str] = []
    for _, clauses in targets:
        for clause in clauses:
            if clause not in index:
                index[clause] = len(order)
                order.append(clause)
    vectors = encoder.encode(order)

    flagged = 0
    for atom, clauses in targets:
        rows = vectors[[index[c] for c in clauses]]
        min_cos = _min_pairwise_cosine(rows)
        atom.min_clause_cosine = min_cos
        if min_cos < _OVER_MERGED_COSINE:
            atom.over_merged = True
            flagged += 1
    return flagged
