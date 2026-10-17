"""Verb-position phases of the rule-based charge classifier.

Reads an atom's charge from where its first verb sits (phases 3c to 3g), and tells a
statement that opens on a verb-shaped noun (`Set theory underlies the proof`) from an order.
"""

from __future__ import annotations

import re

from reporails_cli.core.mapper.classify_lexicon import (
    ALL_VERBS,
    CONDITION_CONJUNCTIONS,
    CONDITION_OPENERS,
    CONDITIONAL_MARKERS,
    CONTEXT_WORDS,
    DETERMINERS,
    MODAL_ABSOLUTE,
    MODAL_HEDGED,
    PHRASE_PREPOSITIONS,
    SUBJECT_PRONOUNS,
    VERBS_AMBIGUOUS,
    WORD_RE,
    words_of,
)
from reporails_cli.core.mapper.classify_no import DESCRIPTIVE_NO_COPULAS
from reporails_cli.core.platform.dto.ruleset import Charge, Modality

# One classifier verdict: (charge, charge value, modality, rule trace, scope conditional).
type ChargeVerdict = tuple[Charge, int, Modality, str, bool]

# Probable sentence subjects — block mid-sentence verb promotion
_PROBABLE_SUBJECTS = {
    "it",
    "this",
    "that",
    "they",
    "we",
    "he",
    "she",
    "everything",
    "nothing",
    "something",
    "anything",
}


# Determiners for verb-noun disambiguation in Phase 3c: the noun-phrase openers plus articles,
# possessives and quantifiers.
_VERB_NOUN_DETERMINERS: frozenset[str] = DETERMINERS | {
    "a",
    "an",
    "your",
    "our",
    "my",
    "its",
    "their",
    "his",
    "her",
    "no",
    "some",
    "both",
    "either",
    "neither",
}

# Declarative sentence starters for Phase 3g
_DECLARATIVE_STARTS: frozenset[str] = frozenset(
    _PROBABLE_SUBJECTS
    | {
        "the",
        "a",
        "an",
        "its",
        "their",
        "our",
        "your",
        "my",
        "his",
        "her",
    }
)


# Verbs that read as a noun at the head of a subject (`Set theory underlies …`): the ambiguous verbs
# and `set`, which stays among the core verbs so `Set NODE_ENV to production` reads as an order.
_SUBJECT_HOMOGRAPHS: frozenset[str] = frozenset(VERBS_AMBIGUOUS | {"set"})
# Finite verbs that follow a subject noun phrase (`Build artifacts live under …`): the modals, the
# auxiliaries and the plain and `-s` forms of verbs that describe rather than order.
_FINITE_AFTER_SUBJECT: frozenset[str] = (
    MODAL_HEDGED
    | DESCRIPTIVE_NO_COPULAS
    | frozenset(MODAL_ABSOLUTE)
    | frozenset(
        {
            "can", "will", "may", "would", "need", "needs",
            "live", "lives", "underlie", "underlies", "slow", "slows", "exist", "exists", "reside",
            "resides", "contain", "contains", "cause", "causes", "depend", "depends", "belong",
            "belongs", "appear", "appears", "remain", "remains", "mean", "means",
        }
    )
)  # fmt: skip
# Words that end a subject noun phrase before any verb: determiners, prepositions, conjunctions,
# pronouns and the words that open a condition or a relative clause (`once tests exist`, `whose names`).
SUBJECT_ENDS: frozenset[str] = (
    _VERB_NOUN_DETERMINERS
    | PHRASE_PREPOSITIONS
    | CONDITIONAL_MARKERS
    | CONDITION_CONJUNCTIONS
    | _DECLARATIVE_STARTS
    | SUBJECT_PRONOUNS
    | frozenset({"but", "then", "as", "whose", "which", "who", "what", "whatever", "whoever", "whichever", "how"})
)
_SUBJECT_REACH = 5  # a subject noun phrase of up to three words before its finite verb


def starts_noun_subject(text: str) -> bool:
    """True when `text` opens with a word that is also a noun and that starts the subject of a
    later finite verb (`Set theory underlies the proof`, `Cache misses slow the build`, `Build
    artifacts live under dist/`) -- a statement, not an order."""
    lowers = words_of(text)
    if len(lowers) < 3 or lowers[0] not in _SUBJECT_HOMOGRAPHS or lowers[1] in SUBJECT_ENDS:
        return False
    for i in range(2, min(len(lowers), _SUBJECT_REACH)):
        word = lowers[i]
        if word in _FINITE_AFTER_SUBJECT:
            return True
        if word in SUBJECT_ENDS:
            return False
    return False


def _classify_phase3e_break(
    clean: str,
) -> ChargeVerdict | None:
    """Phase 3e: verb after sentence/clause break."""
    sentences = re.split(r"(?<=[.!?:;])\s+", clean)
    for sent in sentences[1:]:
        sw = WORD_RE.findall(sent)
        if not sw:
            continue
        sl = [w.lower() for w in sw]
        if sl[0] in ALL_VERBS:
            has_cond = any(w in CONDITIONAL_MARKERS for w in sl[:6])
            amb = "!amb" if sl[0] in VERBS_AMBIGUOUS else ""
            return "IMPERATIVE", 1, "imperative", f"p3e_break_{sl[0]}{amb}", has_cond
        if sl[0] in CONDITIONAL_MARKERS:
            return "IMPERATIVE", 1, "imperative", "p3e_break_cond", True
    return None


def _classify_phase3d_context(
    lowers: list[str],
    verb_idx: int,
    pre: set[str],
) -> ChargeVerdict | None:
    """Phase 3d: verb after context words only."""
    if not pre <= CONTEXT_WORDS:
        return None
    has_cond = bool(pre & CONDITIONAL_MARKERS)
    if "not" in pre:
        return "CONSTRAINT", -1, "direct", "p3d_context_not", has_cond
    verb = lowers[verb_idx]
    amb = "!amb" if verb in VERBS_AMBIGUOUS else ""
    return "IMPERATIVE", 1, "imperative", f"p3d_context_{verb}{amb}", has_cond


def _classify_phase3_deep(
    clean: str,
    lowers: list[str],
    verb_idx: int,
    pre: set[str],
) -> ChargeVerdict:
    """Phase 3 deep detection: sub-phases 3d-3g (mid-sentence verb detection)."""
    # 3d: Verb after context words only
    p3d = _classify_phase3d_context(lowers, verb_idx, pre)
    if p3d is not None:
        return p3d

    # 3e: Verb after sentence/clause break
    p3e = _classify_phase3e_break(clean)
    if p3e is not None:
        return p3e

    # 3f: Conditional marker at sentence start
    if lowers[0] in CONDITIONAL_MARKERS:
        return "IMPERATIVE", 1, "imperative", f"p3f_cond_{lowers[0]}", True

    # 3g: Mid-sentence verb with conditional marker before it
    if lowers[0] not in _DECLARATIVE_STARTS and verb_idx <= 7 and pre & CONDITIONAL_MARKERS:
        verb = lowers[verb_idx]
        amb = "!amb" if verb in VERBS_AMBIGUOUS else ""
        if "not" in pre:
            return "CONSTRAINT", -1, "direct", f"p3g_mid_not{amb}", True
        return "IMPERATIVE", 1, "imperative", f"p3g_mid_{verb}{amb}", True

    return "NEUTRAL", 0, "none", "fallthrough", False


def classify_phase3_lexicon(
    clean: str,
    lowers: list[str],
    verb_idx: int,
    *,
    shallow: bool,
) -> ChargeVerdict:
    """Phase 3 fallback: verb lexicon detection (when spaCy unavailable or returns None).

    Covers sub-phases 3c through 3g.
    """
    # 3c: Verb at position 0
    if verb_idx == 0:
        if starts_noun_subject(clean):
            return "NEUTRAL", 0, "none", "p3c_noun_subject", False
        verb = lowers[0]
        amb = ""
        if verb in VERBS_AMBIGUOUS:
            pos1 = lowers[1] if len(lowers) > 1 else ""
            if pos1 not in _VERB_NOUN_DETERMINERS:
                amb = "!amb"
        has_cond = any(w in CONDITION_OPENERS for w in lowers[1:8])
        return "IMPERATIVE", 1, "imperative", f"p3c_verb0_{verb}{amb}", has_cond

    if shallow:
        return "NEUTRAL", 0, "none", "p3_shallow_stop", False

    return _classify_phase3_deep(clean, lowers, verb_idx, set(lowers[:verb_idx]))
