"""Instruction decoding — reads each running-text line into the instructions it gives.

Rebuilds each running-text atom (prose, list/numbered item, blockquote, table
row, a fenced line that reads as an instruction) into one atom per instruction — a sentence
giving several instructions is read as one instruction each — carrying its
charge, modality, and subject/action/object/scope spans.

Headings are re-charged but keep their structural identity: a heading is one
atom, so it is never rebuilt into span atoms — its text is decoded for the
charge, and a heading that names no action titles its section. A fence kept
whole as one block is neutral by structure. When the charge files are not
bundled this step does nothing and every atom keeps its tokenize-time charge.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from reporails_cli.core.mapper.bio_tagger import (
    AtomTuple,
    Span,
    multislot_available,
)
from reporails_cli.core.mapper.classify import (
    _CLASSIFY_WORD_RE,
    is_conditional_frame,
    is_terse_no_prohibition,
    opens_conditional_clause,
)
from reporails_cli.core.mapper.heading_labels import neutralize_paired_label_headings
from reporails_cli.core.mapper.instructions import fold_lead_ins, instruction_texts, without_joining_word
from reporails_cli.core.mapper.markers import reformat_spans
from reporails_cli.core.mapper.multislot_frames import (
    _decode_logits_batch,
    _frames_from_decoded,
    _heading_tuple_from_decoded,
)
from reporails_cli.core.mapper.parse import (
    TABLE_HEADER_RULE,
    _apply_deontic_floor,
    _apply_hedged_should_floor,
    _apply_negation_constraint_floor,
    _apply_structural_neutral_floor,
    _atom_from_sentence,
    inline_plain_text,
    is_fence_block,
    is_quoted_line,
    keep_lead_in_on_last,
    reindex_positions,
)
from reporails_cli.core.mapper.prose_split import split_prose_sentences
from reporails_cli.core.platform.dto.ruleset import Atom, AtomSlots

# Running-text formats this module rebuilds into spans. Headings are read too, but
# re-charged in place. A table row is running text too — its cells are joined into
# one line — and so is a line read out of a fence that reads as an instruction; it
# keeps its `code_block` format.
_HEAD_FORMATS = frozenset({"prose", "list", "numbered", "blockquote", "table", "code_block"})


def _head_eligible(atom: Atom) -> bool:
    """Whether an atom is running text to re-read; a heading, a table's header row, a fence kept whole
    as one block, and a line that is wholly a quotation (a sample, whatever sentences it holds) are not.
    A line read out of a fence is re-read only when it reads as an instruction: the fence's other lines
    (a sample's output, a template's options) stay neutral."""
    if atom.format == "code_block" and (is_fence_block(atom) or atom.charge_value == 0):
        return False
    return (
        atom.kind != "heading"
        and atom.format in _HEAD_FORMATS
        and atom.rule != TABLE_HEADER_RULE
        and not is_quoted_line(atom.text)
    )


def _span_has_content(text: str) -> bool:
    """A span carries an instruction only if it has an alphanumeric token.

    Drops bare-punctuation spans (a lone ``—`` clause separator) the head can
    emit when splitting a list/numbered line, which would otherwise become a
    charged atom with no instructional content.
    """
    return any(ch.isalnum() for ch in text)


# ──────────────────────────────────────────────────────────────────
# MULTI-SLOT PATH — one atom per instruction
# ──────────────────────────────────────────────────────────────────

_POLARITY_CHARGE = {1: ("DIRECTIVE", 1), -1: ("CONSTRAINT", -1), 0: ("NEUTRAL", 0)}


def _slots_from_tuple(t: AtomTuple) -> AtomSlots:
    return AtomSlots(
        subject=t.subject.text,
        predicate=t.predicate.text,
        object=t.object.text,
        scope=t.scope.text,
        subject_span=t.subject.offset,
        predicate_span=t.predicate.offset,
        object_span=t.object.offset,
        scope_span=t.scope.offset,
        subject_conf=t.subject.conf,
        predicate_conf=t.predicate.conf,
        object_conf=t.object.conf,
        scope_conf=t.scope.conf,
    )


def _tuple_scope_conditional(t: AtomTuple) -> bool:
    """Whether the decoded tuple frames its instruction with a condition.

    The head decodes a `scope` axis — the sentence's own condition slot — so an
    accepted scope span whose text opens a conditional frame (`If the tests fail,`,
    `unless it is empty`) settles it — the span IS the condition, so its opener is
    the whole evidence. Its silence is not proof of an unconditional sentence: the
    head declines a scope on a fronted restrictive (`Only for TypeScript files,
    prefer interfaces.`), so the sentence itself is read as the fallback. Read
    WHOLE, a frame marker at the head settles nothing — the same word opens a noun
    phrase (`While loops must be bounded`) or a heading (`When to use`) — so the
    fallback demands a frame that closes before its clause
    (:func:`~reporails_cli.core.mapper.classify.opens_conditional_clause`).
    """
    scope_text = t.scope.text.strip()
    if t.scope.offset is not None and len(scope_text.split()) > 1 and is_conditional_frame(scope_text):
        return True
    return opens_conditional_clause(t.text)


def _atom_from_tuple(t: AtomTuple, parent: Atom, *, already_plain: bool, formatted: str | None = None) -> Atom:
    """Build one per-sentence atom from a decoded tuple, carrying parent context.

    ``formatted`` is the decoded span with the parent's markers put back; it becomes
    the atom's ``text`` while ``plain_text`` stays the span the head decoded (the
    slot offsets index its words; a marker attaches to a word, so the count holds).
    """
    charge, cv = _POLARITY_CHARGE[t.polarity]
    plain_sent = t.text if already_plain else inline_plain_text(t.text)
    sent = formatted if formatted is not None else t.text
    atom = _atom_from_sentence(
        sent,
        parent,
        charge,
        cv,
        t.modality,
        "multislot",
        scope=_tuple_scope_conditional(t),
        plain_sent=plain_sent,
    )
    atom.file_path = parent.file_path
    atom.stage = "multislot"
    atom.slots = _slots_from_tuple(t)
    return atom


def _heading_names_no_action(atom: Atom, t: AtomTuple) -> bool:
    """Whether a heading decodes no action anywhere in its words, so it titles its section.

    `Step 2: PRD Structure`, `Handling Authentication` and `What to avoid` name a topic;
    `Step 3: Count Skills` and `Verify Build` name what to do. A terse `No <what>`
    prohibition (`No Inline Chaining`) forbids without a verb by its shape, so it is not
    read as a title.
    """
    if t.predicate.offset is not None:
        return False
    words = [w.lower() for w in _CLASSIFY_WORD_RE.findall(atom.plain_text or atom.text)]
    return not is_terse_no_prohibition(words)


def _apply_heading_tuple(atom: Atom, t: AtomTuple) -> Atom:
    """Recharge a heading in place from its decoded tuple (stays one atom).

    A heading that decodes no action is a section title and reads neutral, the way a
    charged run with no action of its own folds away in running text.
    """
    polarity = 0 if t.polarity != 0 and _heading_names_no_action(atom, t) else t.polarity
    charge, cv = _POLARITY_CHARGE[polarity]
    atom.charge, atom.charge_value = charge, cv
    atom.modality = t.modality if polarity != 0 else "none"
    atom.rule, atom.stage = "multislot", "multislot"
    atom.scope_conditional = _tuple_scope_conditional(t)
    atom.slots = _slots_from_tuple(t)
    return atom


_CELL_EDGE_RE = re.compile(r"\|\s*$")


def _shift_span(span: Span, n_words: int) -> Span:
    """Rebase a span's word offset forward by ``n_words`` — the merged prefix's word count."""
    if span.offset is None:
        return span
    lo, hi = span.offset
    return Span(span.text, span.conf, (lo + n_words, hi + n_words))


def _merge_cell_edge_frames(frames: list[AtomTuple]) -> list[AtomTuple]:
    """Fold a bare table-cell label back into its neighbour across a `` | `` join.

    A table row is one joined line (`_collect_table_cells`, ``parse.py``), so a
    charge-run boundary can land exactly on the `` | `` a cell join left behind —
    the earlier run then reads as a bare label (`Deploy |`) paired with an orphaned
    clause (`Never deploy on Friday`), splitting one instruction written across two
    cells into two units. Detected by a trailing bare `|` on a run's own text (the
    widened run, see :mod:`multislot_frames`, always carries the join character on
    the EARLIER side, never a leading `|` on the later one). The merged atom keeps
    the neighbour's charge/modality/slots — the label side carries none of its own
    — with the neighbour's span offsets rebased to the merged text's word count.
    """
    if len(frames) < 2:
        return frames
    merged: list[AtomTuple] = []
    i = 0
    while i < len(frames):
        left = frames[i]
        if i + 1 < len(frames) and _CELL_EDGE_RE.search(left.text):
            right = frames[i + 1]
            prefix_words = len(left.text.split())
            merged_text = f"{left.text.rstrip()} {right.text.lstrip()}"
            merged.append(
                AtomTuple(
                    right.polarity,
                    right.modality,
                    _shift_span(right.subject, prefix_words),
                    _shift_span(right.predicate, prefix_words),
                    _shift_span(right.object, prefix_words),
                    _shift_span(right.scope, prefix_words),
                    right.compound_prob,
                    right.compound_candidate,
                    merged_text,
                )
            )
            i += 2
        else:
            merged.append(left)
            i += 1
    return merged


def _span_atoms(atom: Atom, frames: list[list[AtomTuple]], *, plain: bool) -> list[Atom]:
    """The span atoms of one parent, each built from its formatted text.

    The head decoded the parent's AST-clean ``plain_text``, so each frame's text is
    plain; the parent's markers are projected back onto it (:mod:`markers`) and the
    atom is built from that formatted span — ``text`` formatted, ``plain_text`` the
    decoded span — the same contract the legacy sentence split honours, so the specificity
    fields (named / unformatted / italic / bold / specificity) read the author's
    backticks and emphasis instead of losing them.

    A table row folds any cell-edge cut back together first (:func:`_merge_cell_edge_frames`),
    per sentence — the sentence-level split (a genuine sentence boundary inside a row)
    already ran upstream and stays untouched; only a run boundary WITHIN one decoded
    sentence that lands on a cell join is repaired here.
    """
    if atom.format == "table":
        frames = [_merge_cell_edge_frames(sent) for sent in frames]
    tuples = [t for sent in frames for t in sent]
    if not plain:  # decoded from the formatted text itself — the sentence already carries its markers
        spans = [_atom_from_tuple(t, atom, already_plain=False) for t in tuples]
    else:
        formatted = reformat_spans(atom.text, atom.plain_text, [t.text for t in tuples])
        spans = [
            _atom_from_tuple(t, atom, already_plain=True, formatted=f) for t, f in zip(tuples, formatted, strict=True)
        ]
    keep_lead_in_on_last(spans)
    return spans


def _instruction_units(atom: Atom, sents: list[str]) -> list[str]:
    """Each sentence of ``atom`` cut into its instructions, as in-order slices of the decoded text."""
    written = reformat_spans(atom.text, atom.plain_text, sents) if atom.plain_text else sents
    return [
        unit
        for sent, md in zip(sents, written, strict=True)
        for unit in instruction_texts(sent, md)
        if _span_has_content(unit)
    ]


def _with_joining_word(frames: list[AtomTuple], unit: str) -> list[AtomTuple]:
    """The frames of an instruction read without its joining `and`, with the `and` put back on the first."""
    prefix = unit[: len(unit) - len(without_joining_word(unit))]
    if not prefix or not frames:
        return frames
    first, n = frames[0], len(prefix.split())
    restored = AtomTuple(
        first.polarity,
        first.modality,
        _shift_span(first.subject, n),
        _shift_span(first.predicate, n),
        _shift_span(first.object, n),
        _shift_span(first.scope, n),
        first.compound_prob,
        first.compound_candidate,
        prefix + first.text,
    )
    return [restored, *frames[1:]]


def _decode_plan(atoms: list[Atom]) -> tuple[list[str], list[tuple[Any, ...]]]:
    """Every text to decode, plus the plan that reconstructs atom order from the batch."""
    texts: list[str] = []
    plan: list[tuple[Any, ...]] = []
    for atom in atoms:
        if atom.kind == "heading":
            plan.append(("head", atom, len(texts)))
            texts.append(atom.plain_text or atom.text)
        elif not _head_eligible(atom):
            plan.append(("pass", atom))
        else:
            text = atom.plain_text or atom.text
            sents = [s for s in (split_prose_sentences(text, atom.named_tokens) or [text]) if _span_has_content(s)]
            units = _instruction_units(atom, sents)
            plan.append(("sent", atom, bool(atom.plain_text), len(texts), units))
            texts.extend(without_joining_word(u) for u in units)
    return texts, plan


def _reconstruct_atoms(texts: list[str], plan: list[tuple[Any, ...]], decoded: list[Any]) -> list[Atom]:
    """Rebuild one atom list from its decode plan and the decoded logits for its texts.

    ``decoded`` is 0-indexed against ``texts``, exactly as ``plan`` addresses it, so a
    caller may decode a larger batch and pass in only this plan's own slice. The
    structural/deontic floors and the position re-index run over this plan's atoms
    only, so a caller that decodes several plans in one batch gets the same atoms it
    would from decoding each separately.
    """
    result: list[Atom] = []
    for entry in plan:
        if entry[0] == "pass":
            result.append(entry[1])
        elif entry[0] == "head":
            _, atom, i = entry
            result.append(_apply_heading_tuple(atom, _heading_tuple_from_decoded(decoded[i], texts[i])))
        else:
            _, atom, plain, start, units = entry
            frames = [
                _with_joining_word(_frames_from_decoded(decoded[start + j], texts[start + j]), unit)
                for j, unit in enumerate(units)
            ]
            result.extend(_span_atoms(atom, frames, plain=plain))

    # Deterministic charge floors, in the regex path's own order. The terse-prohibition
    # floor runs first (a verbless `No <what> <where>` the head read as a statement is
    # re-charged to CONSTRAINT), then the structural-NEUTRAL floor (a determined
    # non-instruction → 0, which also re-zeroes anything the first floor promoted on a
    # quoted or otherwise structural line), then the deontic prohibition floor — so a
    # bare-negative item under `## Don'ts` (`No mocks.`) ends CONSTRAINT rather than NEUTRAL.
    # Last, an instruction given with `should` reads hedged once its charge is final.
    _apply_negation_constraint_floor(result)
    _apply_structural_neutral_floor(result)
    _apply_deontic_floor(result)
    _apply_hedged_should_floor(result)
    # A category-label heading beside a sibling label gives no instruction; decided last so no
    # decode charges it back.
    neutralize_paired_label_headings(result)
    # An instruction that introduces a list is read together with it, once every charge is final;
    # the list's items then take no place of their own.
    result = fold_lead_ins(result)
    reindex_positions(result)
    return result


def apply_multislot(atoms: list[Atom]) -> list[Atom]:
    """Rebuild the atom list into one atom per instruction via the charge-run decode.

    Each running-text atom's text splits into whole sentences; each sentence's charge
    segments into one atom per charge run, each with its polarity, modality, and
    slot spans. Headings are re-charged in place; ineligible atoms (code blocks) pass
    through. Every sentence + heading is decoded in ONE batched pass (once over the
    whole batch, not once per sentence). No-ops (returns the input) when the charge
    model is not bundled.
    """
    if not multislot_available():
        return atoms
    texts, plan = _decode_plan(atoms)
    decoded = _decode_logits_batch(texts)
    return _reconstruct_atoms(texts, plan, decoded)


def apply_multislot_groups(
    groups: list[list[Atom]], progress: Callable[[int, int], None] | None = None
) -> list[list[Atom]]:
    """Charge-decode several atom groups in ONE batch, each group rebuilt on its own.

    Same result as calling :func:`apply_multislot` on each group in turn, but the
    dominant encoder forward runs once over every group's sentences at once — a
    batch large enough to fill the encode thread pool — instead of once per group
    with only a few buckets. Each group's reconstruction (frames, floors, position
    re-index) still runs over its own atoms alone, and the decode is per-text and
    order-preserving (padding is attention-masked), so each group's output is
    byte-identical to the per-group call. ``progress(done, total)`` counts the
    distinct texts done so far. No-ops (returns the input) when the charge
    model is not bundled.
    """
    if not multislot_available():
        return groups
    plans: list[tuple[list[str], list[tuple[Any, ...]], int]] = []
    all_texts: list[str] = []
    for group in groups:
        texts, plan = _decode_plan(group)
        plans.append((texts, plan, len(all_texts)))
        all_texts.extend(texts)
    decoded = _decode_logits_batch(all_texts, progress)
    return [_reconstruct_atoms(texts, plan, decoded[offset : offset + len(texts)]) for texts, plan, offset in plans]
