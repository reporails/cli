"""Instruction matching for the preservation check: which original instruction a rewritten one
stands in for (a direct match, a polarity flip, or a split into several), which instruction the
rewrite added with no basis in the original, and which prose it dropped.
"""

from __future__ import annotations

import math
import re
from typing import Any

from reporails_cli.core.heal.preservation.snapshot import SnapshotAtom
from reporails_cli.core.heal.preservation.words import NEGATION_RE, content_words, named_key
from reporails_cli.core.mapper.classify import AFFIRMATIVE_ABSOLUTES, leading_prohibition, words_of

# Matching thresholds, pinned by tests.
COSINE_THRESHOLD = 0.75
OVERLAP_THRESHOLD = 0.5
SPLIT_COVERAGE = 0.6
SPLIT_WINDOW = 4
# High enough that a genuinely added instruction (mostly new words, no basis in the original
# file) is flagged, while a reworded, split, or reheaded instruction — which still traces most
# of its words to the original — clears it; see `added_instructions` for the false-positive
# tolerance this threshold implies.
ADDED_COVERAGE = 0.75


def _cosine(a: tuple[int, ...] | None, b: tuple[int, ...] | None) -> float | None:
    if not a or not b or len(a) != len(b):
        return None
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return None
    return dot / (na * nb)


def _leading_polarity_sign(plain_text: str) -> int:
    """-1 when `plain_text` opens on a prohibition marker (`Never`/`Do not`/`Don't`/`No`/`Avoid`), +1
    when it opens on the affirmative intensifier that stands in a prohibition marker's place
    (`Always`), 0 otherwise - the governing imperative's own sign, read off its leading word(s)
    only. Two texts sharing this sign still carry the same imperative even if a negation cue
    appears somewhere inside the sentence; two texts with different signs do not - a prohibition
    marker was added, dropped, or swapped for its intensifier opposite."""
    if leading_prohibition(plain_text):
        return -1
    return 1 if set(words_of(plain_text)[:1]) & AFFIRMATIVE_ABSOLUTES else 0


def _without_leading_marker(plain_text: str) -> str:
    """`plain_text`'s words with its own leading polarity marker (if any) removed, so a negation
    cue search over the remainder reads the instruction's embedded clause, not the marker itself."""
    marker = leading_prohibition(plain_text)
    if marker:
        return marker.string[marker.end() :]
    words = words_of(plain_text)
    return " ".join(words[1:] if set(words[:1]) & AFFIRMATIVE_ABSOLUTES else words)


def _mixed_polarity_restated(sa_text: str, na_text: str) -> bool:
    """Whether `sa_text` and `na_text` — a pair `pair_score` already cleared as the SAME
    instruction — keep the same leading prohibition status AND both still carry a negation cue
    in an embedded clause beyond any leading marker. A sentence that gives its instruction once
    (its governing imperative, read off its leading word(s)) and restates it again negatively in
    an embedded clause in the same breath (`Address it directly — don't sidestep.`) can report as
    flipped on a reword (pronoun/detail changes, not a meaning change) even though the underlying
    instruction never actually flipped — same governing imperative, same embedded negation, both
    still present on both sides. A change in whether the sentence leads with a prohibition marker
    (`Never`/`Do not`/`Don't`/`No`/`Avoid` added, dropped, or swapped for the other side's marker)
    is a real flip regardless of what negation cue an embedded clause still carries on either
    side, so that case is never suppressed; leading on neither side, or adding/dropping only the
    affirmative intensifier (`Always`, which never itself makes a sentence a prohibition), is not
    a change in prohibition status and can still be suppressed. Restricted to a pair the matcher
    already paired as one instruction; negation symmetry alone is too weak a signal to pair on."""
    if (_leading_polarity_sign(sa_text) == -1) != (_leading_polarity_sign(na_text) == -1):
        return False
    return bool(NEGATION_RE.search(_without_leading_marker(sa_text))) and bool(
        NEGATION_RE.search(_without_leading_marker(na_text))
    )


def _content_coverage(sa_text: str, na_text: str) -> float:
    """The fraction of `sa_text`'s content words (stopwords removed) present in `na_text` —
    of the SNAPSHOT side only, never normalized by the shorter of the two word sets, so a
    short survivor sharing one word with a long lost instruction cannot pass the threshold."""
    wa = content_words(sa_text)
    if not wa:
        return 0.0
    return len(wa & content_words(na_text)) / len(wa)


def pair_score(sa: SnapshotAtom, na: Any) -> float | None:
    """A candidate pair's score, or `None` when it clears neither qualifying threshold —
    content-word coverage of the snapshot instruction, or embedding cosine. A shared named
    token raises the score but never qualifies a pair by itself."""
    cos = _cosine(sa.embedding_int8, na.embedding_int8)
    coverage = _content_coverage(sa.text, na.text)
    if coverage < OVERLAP_THRESHOLD and (cos is None or cos < COSINE_THRESHOLD):
        return None
    score = max(coverage, cos or 0.0)
    shared_named = {named_key(t) for t in sa.named_tokens} & {named_key(t) for t in na.named_tokens}
    return score + 1.0 if shared_named else score


def _assign_matches(snap_atoms: list[SnapshotAtom], new_atoms: list[Any]) -> dict[int, tuple[Any, bool]]:
    """One-to-one greedy assignment across every snapshot x new candidate pair: every
    same-polarity pair is assigned before any opposite-polarity (flip) pair; within each group
    an instruction left word for word pairs with its unchanged text first, then pairs go by
    descending score, and a tie goes to a candidate under the same heading, then to the nearer
    line. Returns `{id(sa): (matched_na, flipped)}` for every snapshot atom that found a
    qualifying candidate — a snapshot atom claims at most one new atom, and a new atom is
    claimed by at most one snapshot atom. `flipped` is `False` for an opposite-polarity pair
    that is `_mixed_polarity_restated` — the pairing (and ranking preference for a same-
    polarity candidate first) still runs on the true polarity comparison; only the reported
    flag is suppressed."""
    candidates: list[tuple[tuple[bool, bool, float, bool, int], SnapshotAtom, Any, bool]] = []
    for sa in snap_atoms:
        for na in new_atoms:
            same_polarity = na.charge_value == sa.charge_value
            flipped = na.charge_value != 0 and na.charge_value == -sa.charge_value
            if not same_polarity and not flipped:
                continue
            score = pair_score(sa, na)
            if score is None:
                continue
            unchanged = " ".join(sa.text.split()) == " ".join(na.text.split())
            elsewhere = na.heading_context != sa.heading_context
            rank = (not same_polarity, not unchanged, -score, elsewhere, abs(na.line - sa.line))
            candidates.append((rank, sa, na, flipped))
    candidates.sort(key=lambda c: c[0])

    matched_sa: set[int] = set()
    matched_na: set[int] = set()
    out: dict[int, tuple[Any, bool]] = {}
    for _rank, sa, na, flipped in candidates:
        if id(sa) in matched_sa or id(na) in matched_na:
            continue
        matched_sa.add(id(sa))
        matched_na.add(id(na))
        out[id(sa)] = (na, flipped and not _mixed_polarity_restated(sa.plain_text, na.plain_text))
    return out


def _split_window(sa: SnapshotAtom, new_atoms: list[Any]) -> list[Any] | None:
    """The run of consecutive CHARGED new atoms (charge != 0) that covers `sa`'s content words
    and holds at least one atom of `sa`'s own polarity — a packed sentence split into a
    directive half and a prohibition half still counts as kept. Neutral (table cell / example)
    atoms are never part of the window. Returns the covering window (`sa`'s counterparts for
    `repeated_named`'s vague-instruction-concretized credit), or `None` when no window clears
    the coverage threshold."""
    words = content_words(sa.text)
    if not words:
        return None
    charged = [na for na in new_atoms if na.charge_value != 0]
    for i in range(len(charged)):
        union: set[str] = set()
        has_polarity = False
        for j in range(i, min(i + SPLIT_WINDOW, len(charged))):
            na = charged[j]
            has_polarity = has_polarity or na.charge_value == sa.charge_value
            union |= content_words(na.text)
            if has_polarity and len(words & union) / len(words) >= SPLIT_COVERAGE:
                return charged[i : j + 1]
    return None


def instruction_diffs(
    snap_atoms: list[SnapshotAtom], new_atoms: list[Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[int, Any], dict[int, list[Any]]]:
    """`(lost_instructions, polarity_flips, matched_new_for, split_covering_for)` — each
    snapshot instruction (charge_value != 0) matched, flipped, or lost (unless a
    packed-sentence split covers it). Matching is one-to-one everywhere, split coverage
    included: a new atom `_assign_matches` already gave to one snapshot instruction cannot also
    stand in — even partially, through a split window — for a different, unmatched snapshot
    instruction. `_split_window` draws its window only from new atoms no direct match claimed.
    `split_covering_for` carries, for every split-covered snapshot instruction, the new atoms
    that cover it — `repeated_named`'s counterparts for the vague-instruction-concretized
    credit, the same role `matched_new_for` plays for a direct match."""
    charged = [sa for sa in snap_atoms if sa.charge_value != 0]
    assignment = _assign_matches(charged, new_atoms)
    claimed_na = {id(match) for match, _flipped in assignment.values()}
    unclaimed_new_atoms = [na for na in new_atoms if id(na) not in claimed_na]
    lost: list[dict[str, Any]] = []
    flips: list[dict[str, Any]] = []
    matched_new_for: dict[int, Any] = {}
    split_covering_for: dict[int, list[Any]] = {}
    for sa in charged:
        result = assignment.get(id(sa))
        if result is None:
            window = _split_window(sa, unclaimed_new_atoms)
            if window is None:
                lost.append({"line": sa.line, "text": sa.text})
            else:
                split_covering_for[id(sa)] = window
            continue
        match, flipped = result
        matched_new_for[id(sa)] = match
        if flipped:
            flips.append({"line": sa.line, "text": sa.text, "new_line": match.line, "new_text": match.text})
    return lost, flips, matched_new_for, split_covering_for


def added_instructions(
    snapshot_text: str,
    new_atoms: list[Any],
    matched_new_for: dict[int, Any],
    split_covering_for: dict[int, list[Any]],
) -> list[dict[str, Any]]:
    """Every charged new atom the rewrite carries with no snapshot counterpart at all — not a
    direct or flipped match (`matched_new_for`'s values), not part of a packed-sentence split's
    covering window (`split_covering_for`'s values) — and whose content words are mostly absent
    from every single sentence of `snapshot_text`: an instruction (a prohibition or a directive)
    the rewrite added that the original gave it no basis for. Words scattered over unrelated
    sentences of the original do not make a new instruction a restatement. A reworded, split, or
    reheaded instruction still traces most of its words to one original sentence and clears the
    coverage threshold, so only a genuinely new instruction is flagged. Each entry is
    `{line, text}`, in new-file order.

    `ADDED_COVERAGE` sits just above a genuinely added instruction's word-coverage fraction (an
    instruction silently appended to an already-kept one traces only a minority of its words to
    any one sentence), which is close enough to a handful of legitimate rewordings the matcher's
    own pairing missed (a neutral original clause recharged into a directive, picking up 1-2
    incidental new words) that the threshold also flags those few borderline rewordings — a
    deliberate false-positive tolerance, not an oversight; a tighter threshold would silently
    miss a genuinely added instruction instead."""
    claimed_na = {id(m) for m in matched_new_for.values()}
    used_in_split = {id(x) for window in split_covering_for.values() for x in window}
    orig_sentences = [w for w in (content_words(sn) for sn in re.split(r"(?<=[.!?])\s+|\n", snapshot_text)) if w]
    out: list[dict[str, Any]] = []
    for na in new_atoms:
        if na.charge_value == 0 or id(na) in claimed_na or id(na) in used_in_split:
            continue
        words = content_words(na.text)
        if not words:
            continue
        coverage = max((len(words & sentence) / len(words) for sentence in orig_sentences), default=0.0)
        if coverage < ADDED_COVERAGE:
            out.append({"line": na.line, "text": na.text})
    return out


def lost_context(snap_atoms: list[SnapshotAtom], new_text: str) -> list[dict[str, Any]]:
    """Snapshot neutral prose atoms (charge 0, format `prose`) whose content words are less
    than half present in the new file's text — factual context a rewrite silently dropped.
    Relation-allowed lines are already excluded from `snap_atoms` by the caller, the same as
    every other check."""
    new_words = content_words(new_text)
    out: list[dict[str, Any]] = []
    for a in snap_atoms:
        if a.charge_value != 0 or a.format != "prose":
            continue
        words = content_words(a.text)
        if not words:
            continue
        if len(words & new_words) / len(words) < OVERLAP_THRESHOLD:
            out.append({"line": a.line, "text": a.text})
    return out
