"""Rule-based charge classification (no embedding model).

Deterministic steps classify each atom's charge into CONSTRAINT (-1),
DIRECTIVE (+1), IMPERATIVE (+1), or NEUTRAL (0), from the wording of the
atom alone.

Public entry point: `classify_charge(md_text, plain_text=...)`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Protocol

from reporails_cli.core.mapper.classify_lexicon import (
    ADDRESSEE_SUBJECTS,
    ALL_VERBS,
    CONDITION_OPENERS,
    CONDITIONAL_MARKERS,
    HEDGE_POSSIBLE_LEADS,
    IT_IS,
    MODAL_ABSOLUTE,
    MODAL_HEDGED,
    RESTRICTOR_BLOCKERS,
    SCOPE_RESTRICTORS,
    WORD_RE,
    words_of,
)
from reporails_cli.core.mapper.classify_no import starts_bare_no_status, starts_descriptive_no
from reporails_cli.core.mapper.classify_phases import (
    SUBJECT_ENDS,
    ChargeVerdict,
    classify_phase3_lexicon,
)
from reporails_cli.core.mapper.markers import strip_markdown_inline, without_list_marker
from reporails_cli.core.mapper.md_parser import leading_bold_run, replace_code_spans
from reporails_cli.core.mapper.word_spans import words_between
from reporails_cli.core.platform.dto.ruleset import AtomSlots, Modality

# ──────────────────────────────────────────────────────────────────
# RULE-BASED CHARGE CLASSIFIER
# Verb lexicon. Three phases: negation → modal → imperative
# verb detection. No spaCy dependency, no embedding.
# ──────────────────────────────────────────────────────────────────

# Phase 1: Negation / Prohibition
_NEGATION_PHRASES_RE = re.compile(
    r"^(do not|don't|must not|shall not|should not|will not|cannot|can not|can't)\b",
    re.IGNORECASE,
)
_PROHIBITION_START_RE = re.compile(
    r"^(never|no|don't|cannot|can't|won't|avoid|refrain|prevent|prohibit|forbid)\b",
    re.IGNORECASE,
)
_MID_NEGATION_RE = re.compile(
    r"\b(is|are|does|do|did|has|have|was|were)\s+(NOT|not|n't)\b",
)
_LATE_DONOT_RE = re.compile(r"\bdo not\b|\bdon't\b|\bdo NOT\b", re.IGNORECASE)


# The hedge leads that can be dropped alone, leaving the instruction (`Perhaps run the linter`).
HEDGE_ADVERB_LEADS: frozenset[str] = frozenset({"perhaps", "maybe", "possibly", "ideally"})
# The words that can be dropped alone from the front of an instruction: the hedge adverbs and `please`.
DROPPABLE_LEADS: frozenset[str] = HEDGE_ADVERB_LEADS | {"please"}
# The hedge words that, opening an instruction (after `you` / `we` / `please`), make all of it a
# suggestion (`Prefer real objects`, `Try not to mock`, `Perhaps run the linter`).
HEDGE_LEADS: frozenset[str] = HEDGE_ADVERB_LEADS | {"prefer", "preferably", "consider", "try"}
_HEDGE_LEAD_SKIP = ADDRESSEE_SUBJECTS | {"please"}
# Words that give an instruction as an order that admits no exception. `must` and `shall` read as
# absolute modality in the classifier but are not among these cues.
ABSOLUTE_CUES: frozenset[str] = frozenset({"never", "always", "exclusively"})
# The absolute cues that affirm (`Always run the tests`) rather than prohibit.
AFFIRMATIVE_ABSOLUTES: frozenset[str] = ABSOLUTE_CUES - {"never"}
# Capitalised words that mark a line as a hard constraint.
CONSTRAINT_WORDS: frozenset[str] = frozenset({"MUST", "NEVER", "ALWAYS", "IMPORTANT"})
_ABSOLUTE_ADVERBS: frozenset[str] = AFFIRMATIVE_ABSOLUTES | {"only"}


def _strip_md_for_classify(text: str) -> str:
    """Strip markdown markers for charge classification. Keeps content."""
    return without_list_marker(strip_markdown_inline(text))


# What sits between a bold label and the text it introduces: a colon, a dash, a slash or a sentence
# mark, or only space.
_AFTER_BOLD_LABEL_RE = re.compile(r"\s*[:\u2014\u2013.!?/-]\s*|\s+")


def _after_bold_label(md_text: str) -> str | None:
    """Return text after **Label**: / **Label** — patterns, or None."""
    raw = without_list_marker(md_text)
    run = leading_bold_run(raw)
    if run is None:
        return None
    m = _AFTER_BOLD_LABEL_RE.match(raw, run.end)
    return raw[m.end() :] if m else None


def _find_verb_idx(lowers: list[str]) -> int:
    """Index of first known verb in word list, or -1."""
    for i, w in enumerate(lowers):
        if w in ALL_VERBS:
            return i
    return -1


# Limiting adverbs that may sit in front of a frame marker without breaking the
# frame (`Only for TypeScript files, …`, `Just when the build fails, …`).
_COND_FRAME_LEADS = frozenset({"only", "just", "strictly", "solely", "even"})


def is_conditional_frame(text: str) -> bool:
    """True when ``text`` opens a conditional / restrictive frame.

    Reads the frame marker at the head of the text — `if`, `when`, `unless`,
    `before`, `while`, … — allowing a limiting adverb in front of it. A bare `for`
    opener counts only behind such an adverb (`Only for TypeScript files`), because
    an unqualified `For example, …` names no condition.
    """
    lowers = [w.lower() for w in WORD_RE.findall(text)]
    i = 0
    while i < len(lowers) and lowers[i] in _COND_FRAME_LEADS:
        i += 1
    if i >= len(lowers):
        return False
    head = lowers[i]
    if head in CONDITION_OPENERS:
        return True
    return head == "for" and i > 0


# A frame CLOSES before the clause it governs: `If X, Y` / `When X, do Y` /
# `Unless X, then Y`. The comma (or `then`) is what makes the opener a frame at
# all — without it the word is the sentence's own subject or a section label
# (`While loops must be bounded`, `Before hooks run on every commit`, `When to use`).
# A comma inside a number (`1,000`) closes nothing.
_COND_CLAUSE_CLOSE_RE = re.compile(r"(?:,(?!\d)|;)\s*\S|\s+then\s+\S", re.IGNORECASE)
# The governing clause is short; past that the comma belongs to the main clause.
_COND_CLAUSE_MAX_WORDS = 12


def conditional_clause(text: str) -> str | None:
    """The conditional frame ``text`` opens, from its start through the word before the
    comma or `then` that closes it; None when no frame closes before its clause.

    A frame marker at the head settles nothing on its own, because the same words
    open a noun phrase (`While loops …`) or a heading (`When to use`). A real frame
    hands off to the clause it governs at a comma or a `then`.
    """
    if not is_conditional_frame(text):
        return None
    head = " ".join(text.split()[:_COND_CLAUSE_MAX_WORDS])
    close = _COND_CLAUSE_CLOSE_RE.search(head)
    return head[: close.start()] if close else None


# A restricting phrase runs on through its commas (`only modify a, b and c`); a semicolon or a `then` ends it.
_RESTRICTOR_CLOSE_RE = re.compile(r";\s*\S|\s+then\s+\S", re.IGNORECASE)


def _named_char_mask(text: str, named_tokens: Sequence[str]) -> list[bool]:
    """Per character of ``text``, whether it lies inside one of the named tokens."""
    mask = [False] * len(text)
    for token in named_tokens:
        start = text.find(token) if token else -1
        while start >= 0:
            mask[start : start + len(token)] = [True] * len(token)
            start = text.find(token, start + len(token))
    return mask


def restrictor_clause(
    plain_text: str, named_tokens: Sequence[str], aside_spans: Sequence[tuple[int, int]]
) -> str | None:
    """The phrase a restricting word opens (`only on main`, `except integration tests`), from the
    word through the word before the comma that closes it; None when the text has none.

    A word inside a named token (`try`/`except` in backticks) restricts nothing, nor does one
    used as an adjective or a correlative (`the only option`, `not only X`), nor one inside an aside
    (word spans `aside_spans`), which illustrates the instruction and restricts nothing.
    """
    mask = _named_char_mask(plain_text, named_tokens)
    tokens = [(m.start(), m.group()) for m in re.finditer(r"\S+", plain_text)]
    previous = ""
    for i, (start, token) in enumerate(tokens):
        word = (WORD_RE.findall(token) or [""])[0].lower()
        blocked = previous in RESTRICTOR_BLOCKERS
        previous = word
        if word not in SCOPE_RESTRICTORS or blocked or mask[start] or any(a <= i < b for a, b in aside_spans):
            continue
        head = " ".join(t for _s, t in tokens[i : i + _COND_CLAUSE_MAX_WORDS])
        close = _RESTRICTOR_CLOSE_RE.search(head)
        return head[: close.start()] if close else head
    return None


class ConditionRead(Protocol):
    """The fields `condition_text` reads, shared by a mapper atom and a snapshotted one."""

    @property
    def scope_conditional(self) -> bool:
        """Whether a conditional frame governs the atom."""

    @property
    def plain_text(self) -> str:
        """The text with its markup read away."""

    @property
    def named_tokens(self) -> Sequence[str]:
        """The backticked constructs it names."""

    @property
    def slots(self) -> AtomSlots | None:
        """The slots the mapper read, as word spans of `plain_text`."""

    @property
    def aside_spans(self) -> tuple[tuple[int, int], ...]:
        """The word spans of `plain_text` that illustrate the instruction."""


def condition_text(atom: ConditionRead) -> str | None:
    """The condition the mapper read on a conditional atom: its decoded scope when that scope
    opens a conditional frame, else the frame that closes the sentence's opening; None when the
    atom is not conditional. A phrase a restricting word (`only`, `except`) opens is part of the
    condition too."""
    if not atom.scope_conditional:
        return None
    frame = conditional_clause(atom.plain_text)
    if atom.slots is not None and atom.slots.scope_span is not None:
        scope = words_between(atom.plain_text, *atom.slots.scope_span)
        if is_conditional_frame(scope):
            frame = scope
    restriction = restrictor_clause(atom.plain_text, atom.named_tokens, atom.aside_spans)
    return " ".join(part for part in (frame, restriction) if part) or None


def opens_conditional_clause(text: str) -> bool:
    """True when ``text`` opens a conditional frame AND closes it before its clause.

    The stricter reading of :func:`is_conditional_frame`, for the case where the
    whole sentence is the evidence (see :func:`conditional_clause`).
    """
    return conditional_clause(text) is not None


def _classify_phase1(
    clean: str,
    words: list[str],
    lowers: list[str],
    has_cond_prefix: bool,
) -> ChargeVerdict | None:
    """Phase 1: Negation/prohibition patterns → CONSTRAINT."""
    if _NEGATION_PHRASES_RE.match(clean):
        return "CONSTRAINT", -1, "direct", "p1_negation_phrase", False
    if _PROHIBITION_START_RE.match(clean):
        # "No X is/are/was/were Y" is descriptive and a bare "No <noun phrase>" is a
        # status report — neither prohibits anything.
        if starts_descriptive_no(lowers) or starts_bare_no_status(lowers):
            pass  # fall through — descriptive "No X is Y" / bare status pattern
        else:
            return "CONSTRAINT", -1, "absolute" if lowers[0] == "never" else "direct", "p1_prohibition_start", False
    if words[0] in ("NOT", "NO", "NEVER"):
        return "CONSTRAINT", -1, "absolute", "p1_caps_negation", False
    # Main-clause only: split at STRONG markers (em/en-dash, ; : , .) so a
    # trailing prohibition in a compound ("Read X — do not skim") does not
    # invert the affirmative main clause. The trailing clause becomes its own
    # atom via the granularity split in parse.
    first_clause = re.split(r"\s+[\u2014\u2013]\s+|[,;:.]", clean, maxsplit=1)[0]
    if _MID_NEGATION_RE.search(first_clause):
        return "CONSTRAINT", -1, "direct", "p1_mid_negation", has_cond_prefix
    if _LATE_DONOT_RE.search(first_clause):
        return "CONSTRAINT", -1, "direct", "p1_late_donot", has_cond_prefix
    return None


# Words that negate the word before them (`should not`, `must never`, `would n't`, `must cannot`).
NEGATION_WORDS: frozenset[str] = frozenset({"not", "never", "n't", "cannot"})
# Prepositions that negate what follows them (`run it without flags`).
NEGATING_PREPOSITIONS: frozenset[str] = frozenset({"without"})
# Lowered words whose presence as a line's first word gives it as an order: absolute and negation
# cues, constraint words and the modals the classifier reads as a directive.
DIRECTIVE_CUES: frozenset[str] = (
    ABSOLUTE_CUES
    | NEGATION_WORDS
    | frozenset(w.lower() for w in CONSTRAINT_WORDS)
    | MODAL_ABSOLUTE
    | MODAL_HEDGED
    | {"only"}
)


def _modal_result(
    next_negated: bool,
    modality: Modality,
    directive_trace: str,
    negated_trace: str,
) -> ChargeVerdict:
    """Return CONSTRAINT if negated, DIRECTIVE otherwise."""
    if next_negated:
        return "CONSTRAINT", -1, modality, negated_trace, False
    return "DIRECTIVE", 1, modality, directive_trace, False


def _check_modal_word(
    w: str,
    i: int,
    lowers: list[str],
) -> ChargeVerdict | None:
    """Check a single word for modal/hedged/you-will patterns. Returns result or None."""
    next_negated = i + 1 < len(lowers) and lowers[i + 1] in NEGATION_WORDS
    if w in MODAL_ABSOLUTE:
        return _modal_result(next_negated, "absolute", f"p2_modal_{w}", "p2_modal_negated")
    if w in MODAL_HEDGED:
        if next_negated:
            return "CONSTRAINT", -1, "hedged", f"p2_hedged_{w}_negated", False
        is_positioned = (
            w == "should"
            or i == 0
            or (i > 0 and lowers[i - 1] in ADDRESSEE_SUBJECTS)
            or (i > 0 and lowers[i - 1] in CONDITIONAL_MARKERS)
        )
        return ("DIRECTIVE", 1, "hedged", f"p2_hedged_{w}", False) if is_positioned else None
    if w == "will" and i > 0 and lowers[i - 1] == "you":
        return _modal_result(next_negated, "absolute", "p2_you_will", "p2_you_will_not")
    return None


def _classify_phase2(
    lowers: list[str],
) -> ChargeVerdict | None:
    """Phase 2: Modal verbs and absolute adverbs → DIRECTIVE."""
    for i, w in enumerate(lowers):
        result = _check_modal_word(w, i, lowers)
        if result is not None:
            return result
    for w in lowers[:6]:
        if w in _ABSOLUTE_ADVERBS:
            if w == "only" and not any(v in ALL_VERBS for v in lowers):
                continue
            return "DIRECTIVE", 1, "absolute", f"p2_adverb_{w}", False
    return None


_NEUTRAL_RESULT: ChargeVerdict = ("NEUTRAL", 0, "none", "fallthrough", False)


def _classify_phase3b_bold(md_text: str) -> ChargeVerdict | None:
    """Phase 3b: Bold label + verb after it — shallow recursive call."""
    after = _after_bold_label(md_text)
    if after is None:
        return None
    after_clean = _strip_md_for_classify(after)
    if not after_clean:
        return None
    sub_c, sub_cv, sub_m, _sub_trace, sub_sc = classify_charge(
        after,
        plain_text=after_clean,
        _shallow=True,
    )
    if sub_cv != 0:
        return sub_c, sub_cv, sub_m, "p3b_bold_label", sub_sc
    return None


def _classify_phase3(
    clean: str,
    md_text: str,
    lowers: list[str],
    *,
    shallow: bool,
) -> ChargeVerdict:
    """Phase 3: Imperative verb detection (embedding-free / spaCy-free lexicon)."""
    # 3b: Bold label recursive
    if not shallow:
        p3b = _classify_phase3b_bold(md_text)
        if p3b is not None:
            return p3b

    # 3c-3g: verb lexicon (primary path)
    verb_idx = _find_verb_idx(lowers)
    if verb_idx != -1:
        return classify_phase3_lexicon(clean, lowers, verb_idx, shallow=shallow)

    # Lexicon miss: no verb found (`ALL_VERBS` is the sole verb source).
    return "NEUTRAL", 0, "none", "p3_no_verb", False


def hedge_cue_words(text: str) -> int:
    """How many words open `text` as a hedge cue a reader can drop (`You should`, `Try to`, `Perhaps`,
    `Please`), 0 when it opens with none. `You should` counts only when the classifier reads the text
    as hedged with it."""
    lowers = words_of(text)
    if lowers[:2] == ["you", "should"]:
        return 2 if hedges_with_should(text) else 0
    if lowers[:2] == ["try", "to"]:
        return 2
    return 1 if lowers[:1] and lowers[0] in DROPPABLE_LEADS else 0


def hedges_with_should(text: str) -> bool:
    """True when `text` gives its instruction with `should` (`You should run the linter`).

    Reads the same modal the classifier itself settles on: a prohibition opener
    (`Never …`) or an absolute modal met first keeps the line from reading hedged, and
    only `should` counts — `might` and `could` do not.
    """
    if "should" not in text.lower():
        return False
    _charge, _cv, _mod, trace, _scope = classify_charge(text, plain_text=text)
    return trace.startswith("p2_hedged_should")


def predicate_opens_hedge(predicate: str) -> bool:
    """True when a predicate (`might want to run`, `consider running`) opens with a hedge: a hedged modal
    (`should`, `could`, `might`) or one of `HEDGE_LEADS`."""
    lowers = words_of(predicate)
    return bool(lowers) and (lowers[0] in MODAL_HEDGED or lowers[0] in HEDGE_LEADS)


def hedges_with_lead(text: str) -> bool:
    """True when `text` opens with a hedge word (`Prefer …`, `Try not to …`, `Perhaps …`): after
    `you` / `we` / `please`, its first word is one of `HEDGE_LEADS`."""
    lowers = words_of(text)
    start = 0
    while start < len(lowers) and lowers[start] in _HEDGE_LEAD_SKIP:
        start += 1
    return start < len(lowers) and lowers[start] in HEDGE_LEADS


# `as soon as possible` is urgency and `if possible duplicates exist` uses the adjective; only a
# `HEDGE_POSSIBLE_LEADS` word followed by `possible` ending its clause hedges.
_HEDGE_POSSIBLE_RE = re.compile(
    rf"\b(?:{'|'.join(sorted(HEDGE_POSSIBLE_LEADS))})\s+possible\s*(?:$|[.,;:!?)\]\u2014])",
    re.IGNORECASE,
)
# `it's` / `it is` / `it s` (a curly apostrophe splits the word) in front of `best`.
_IT_IS_FORMS: tuple[tuple[str, ...], ...] = (("it's",), IT_IS, (IT_IS[0], "s"))


def _prose(text: str) -> str:
    """`text` with each code span replaced by a placeholder word, so what a command or path contains
    is not read as the author's wording."""
    return replace_code_spans(text, "x")


def hedges_with_possible(text: str) -> bool:
    """True when `text` carries `where possible`, `wherever possible`, `if possible`, `when possible`
    or `whenever possible` as a closing phrase, outside code spans. Takes the markdown, so a code
    span is still marked when it is masked."""
    return _HEDGE_POSSIBLE_RE.search(_strip_md_for_classify(_prose(text))) is not None


def best_to_sign(text: str) -> int:
    """`+1` for `It's best to <verb> …`, `-1` for `It's best not to <verb> …` or `It's best to
    avoid / never / not <verb> …`, else `0`: the lead is a suggestion, and the sign is the direction
    of the instruction it gives."""
    lowers = words_of(_prose(text))
    for form in _IT_IS_FORMS:
        if tuple(lowers[: len(form)]) != form:
            continue
        rest = lowers[len(form) :]
        if rest[:1] != ["best"]:
            return 0
        negated = rest[1:2] == ["not"]
        after = rest[2:] if negated else rest[1:]
        if after[:1] != ["to"] or not after[1:] or after[1] in SUBJECT_ENDS:
            return 0
        act = after[1:]
        return -1 if negated or act[0] == "not" or leading_prohibition(" ".join(act)) else 1
    return 0


def hedges_with_phrase(text: str) -> bool:
    """True when markdown `text` gives its instruction as `where possible` (and its kin) or `It's best (not) to …`."""
    return hedges_with_possible(text) or best_to_sign(text) != 0


def has_negation_cue(text: str) -> bool:
    """True when `text` holds a negation cue: a negation word, a word ending in the `n't` contraction
    suffix, or a negating preposition."""
    return any(w in NEGATION_WORDS or w in NEGATING_PREPOSITIONS or w.endswith("n't") for w in words_of(text))


def leading_prohibition(text: str) -> re.Match[str] | None:
    """The prohibition marker (`Never`, `Do not`, `Avoid`, ...) that opens `text`, read off its words;
    the match's `string` is the words rejoined, so `string[end():]` is what follows the marker."""
    clean = " ".join(words_of(text))
    return _NEGATION_PHRASES_RE.match(clean) or _PROHIBITION_START_RE.match(clean)


def classify_charge(
    md_text: str,
    *,
    plain_text: str | None = None,
    _shallow: bool = False,
) -> ChargeVerdict:
    """Classify an atom's charge and modality using deterministic rules (:func:`_classify_lexical`),
    then read `where possible` (and its kin) and `It's best (not) to …` as the hedges they are."""
    result = _classify_lexical(md_text, plain_text=plain_text, _shallow=_shallow)
    low = md_text.lower()
    if "possible" not in low and "best" not in low:
        return result
    charge, charge_value, modality, trace, scope = result
    sign = best_to_sign(md_text)
    if sign:
        return ("DIRECTIVE" if sign > 0 else "CONSTRAINT"), sign, "hedged", "p2_hedged_best_to", scope
    if charge_value != 0 and modality != "hedged" and hedges_with_possible(md_text):
        return charge, charge_value, "hedged", trace, scope
    return result


def _classify_lexical(
    md_text: str,
    *,
    plain_text: str | None = None,
    _shallow: bool = False,
) -> ChargeVerdict:
    """Classify an atom's charge and modality using deterministic rules.

    Input: raw markdown text (with formatting markers intact).
    Returns: (charge, charge_value, modality, rule_trace, scope_conditional)

    rule_trace identifies which rule fired (e.g. "p1_negation_phrase",
    "p3c_verb0_use"). Traces ending with "!amb" indicate the classification
    depends on a verb-noun interpretation (ambiguous charge).

    Three-phase classification:
      Phase 1 — Negation/prohibition patterns → CONSTRAINT
      Phase 2 — Modal verbs and absolute adverbs → DIRECTIVE
      Phase 3 — Imperative verb detection (verb lexicon) → IMPERATIVE

    When _shallow=True (recursive from Phase 3b), only high-precision
    phases fire: Phase 1, Phase 2, Phase 3a, Phase 3c. Phases 3d-3g
    (deep mid-sentence detection) are skipped to avoid noise from
    descriptive text after bold labels.
    """
    clean = without_list_marker(plain_text) if plain_text is not None else _strip_md_for_classify(md_text)
    if len(clean) < 3:
        return "NEUTRAL", 0, "none", "short_text", False

    words = WORD_RE.findall(clean)
    if not words:
        return "NEUTRAL", 0, "none", "no_words", False
    lowers = [w.lower() for w in words]
    has_cond_prefix = lowers[0] in CONDITIONAL_MARKERS

    p1 = _classify_phase1(clean, words, lowers, has_cond_prefix)
    if p1 is not None:
        return p1

    p2 = _classify_phase2(lowers)
    if p2 is not None:
        return p2

    return _classify_phase3(
        clean,
        md_text,
        lowers,
        shallow=_shallow,
    )
