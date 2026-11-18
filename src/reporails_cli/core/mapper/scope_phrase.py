"""The phrase that says where, when or to what an instruction applies, recorded as the atom's scope.

The decoded scope axis names a condition (`If the tests fail,`). A place, time or target phrase
(`In CI,` before the clause, `in staging` or `for src/` after its object) is left in no slot, or
inside the object; this reads it into `scope`. A means phrase (`with pytest`) and a word inside a
backticked construct are not scope.
"""

from __future__ import annotations

from reporails_cli.core.mapper.classify_lexicon import (
    CLAUSE_JOINERS,
    MEANS_PREPOSITIONS,
    SCOPE_PHRASE_PREPOSITIONS,
    words_of,
)
from reporails_cli.core.mapper.lexical import DASH_MARKS
from reporails_cli.core.mapper.md_parser import code_spans
from reporails_cli.core.mapper.word_spans import word_offsets
from reporails_cli.core.platform.dto.mapping import AtomTuple, Span

_FRONTED_REACH = 6  # a fronted phrase of up to six words before its comma
_BREAKS = (",", ";", ":", *DASH_MARKS)


def _in_code(text: str) -> list[bool]:
    """Per word of ``text``: whether it overlaps a code span the markdown parse reads."""
    spans = code_spans(text)
    return [any(lo < span.end and hi > span.start for span in spans) for lo, hi in word_offsets(text)]


def _is_preposition(word: str) -> bool:
    letters = words_of(word)
    return len(letters) == 1 and letters[0] in SCOPE_PHRASE_PREPOSITIONS


def _is_means(word: str) -> bool:
    letters = words_of(word)
    return len(letters) == 1 and letters[0] in MEANS_PREPOSITIONS


def _means_start(words: list[str], flags: list[bool], start: int, end: int) -> int:
    """Index of the first means preposition (`by hand`) in ``words[start:end]``, else ``end``."""
    return next((i for i in range(start, end) if _is_means(words[i]) and not flags[i]), end)


def _span(text: str, offsets: list[tuple[int, int]], lo: int, hi: int, conf: float) -> Span:
    return Span(text[offsets[lo][0] : offsets[hi - 1][1]], conf, (lo, hi))


def _fronted_end(words: list[str], flags: list[bool], t: AtomTuple) -> int | None:
    """Word count of a fronted preposition phrase closed by a comma, when the clause opens after it."""
    if not _is_preposition(words[0]) or flags[0]:
        return None
    reach = min(len(words) - 1, _FRONTED_REACH)
    end = next((i + 1 for i in range(1, reach) if words[i].endswith(",")), None)
    if end is None:
        return None
    if any(s.offset is not None and s.offset[0] < end for s in (t.subject, t.predicate, t.object)):
        return None
    return end


def _trailing_start(words: list[str], flags: list[bool], obj: tuple[int, int]) -> int | None:
    """Index of the preposition opening a place, time or target phrase that ends the object."""
    for j in range(obj[0] + 1, obj[1] - 1):
        if _is_preposition(words[j]) and not flags[j]:
            tail = words[j : obj[1] - 1]
            return None if any(w.endswith(_BREAKS) for w in tail) else j
    return None


def _after_object_end(words: list[str], flags: list[bool], obj: tuple[int, int]) -> int | None:
    """Word count of a place, time or target phrase left in no slot right after the object, to the end."""
    if obj[1] >= len(words) - 1 or not _is_preposition(words[obj[1]]) or flags[obj[1]]:
        return None
    if any(w.endswith(_BREAKS) for w in words[obj[1] : -1]):
        return None
    return len(words)


def _with(t: AtomTuple, object_: Span, scope: Span, subject: Span | None = None) -> AtomTuple:
    return AtomTuple(t.polarity, t.modality, subject or t.subject, t.predicate, object_, scope, t.text)


def _trailing(t: AtomTuple, words: list[str], flags: list[bool], offsets: list[tuple[int, int]]) -> AtomTuple:
    """``t`` with the phrase after its object read as scope, else ``t``."""
    obj = t.object.offset
    if obj is None or obj[1] > len(words):
        return t
    start = _trailing_start(words, flags, obj)
    if start is not None:
        subject = t.subject
        if subject.offset is not None and subject.offset[0] >= start:
            subject = Span("", 0.0, None)
        object_ = _span(t.text, offsets, obj[0], start, t.object.conf)
        stop = _means_start(words, flags, start, obj[1])
        return _with(t, object_, _span(t.text, offsets, start, stop, t.object.conf), subject)
    left_out = _after_object_end(words, flags, obj)
    if left_out is None:
        return t
    return _with(t, t.object, _span(t.text, offsets, obj[1], left_out, t.object.conf))


def _ends_in_preposition(words: list[str], flags: list[bool], t: AtomTuple) -> bool:
    """Whether the predicate runs into a preposition (`Run at`): its verb took no object, and the
    preposition opens a phrase naming where or when."""
    pred = t.predicate.offset
    if pred is None or pred[1] - pred[0] < 2 or pred[1] > len(words) or t.scope.offset is not None:
        return False
    return _is_preposition(words[pred[1] - 1]) and not flags[pred[1] - 1] and not words[pred[1] - 1].endswith(_BREAKS)


def _object_is_scope(t: AtomTuple, words: list[str], flags: list[bool], offsets: list[tuple[int, int]]) -> AtomTuple:
    """``t`` with the preposition its predicate ends in, and what follows it to the end of the
    sentence, read as scope; the verb has no object."""
    pred = t.predicate.offset
    if pred is None or not _ends_in_preposition(words, flags, t):
        return t
    tail = words[pred[1] :]
    if not tail or any(w.endswith(_BREAKS) for w in tail[:-1]):
        return t
    start = pred[1] - 1
    predicate = _span(t.text, offsets, pred[0], start, t.predicate.conf)
    scope = _span(t.text, offsets, start, len(words), t.predicate.conf)
    return AtomTuple(t.polarity, t.modality, t.subject, predicate, Span("", 0.0, None), scope, t.text)


def _extend_scope(t: AtomTuple, words: list[str], offsets: list[tuple[int, int]]) -> AtomTuple:
    """``t`` with a trailing scope run over the words after it that sit in no slot, to the end of the
    sentence: the decoded scope stops short of the sentence's last words (`before committing on this`
    of `before committing on this branch.`)."""
    scope = t.scope.offset
    if scope is None or scope[1] >= len(words):
        return t
    others = [s.offset for s in (t.subject, t.predicate, t.object) if s.offset is not None]
    if any(o[1] > scope[0] for o in others):
        return t
    tail = words[scope[1] :]
    if words[scope[1] - 1].endswith(_BREAKS) or any(w.endswith(_BREAKS) for w in tail[:-1]):
        return t
    if not CLAUSE_JOINERS.isdisjoint(words_of(" ".join(tail))):
        return t  # a joiner opens a clause of its own, which the scope does not cover
    return _with(t, t.object, _span(t.text, offsets, scope[0], len(words), t.scope.conf))


def record_scope_phrase(t: AtomTuple) -> AtomTuple:
    """``t`` with its scope set to the fronted or trailing place/time/target phrase, when it has none,
    and a trailing scope run to the end of the sentence."""
    words = t.text.split()
    if t.polarity == 0 or t.predicate.offset is None or len(words) < 3:
        return t
    flags = _in_code(t.text)
    offsets = word_offsets(t.text)
    if t.scope.offset is not None:
        return _extend_scope(t, words, offsets)
    moved = _object_is_scope(t, words, flags, offsets)
    if moved is not t:
        return moved
    end = _fronted_end(words, flags, t)
    if end is None:
        return _trailing(t, words, flags, offsets)
    return _with(t, t.object, _span(t.text, offsets, 0, end, t.predicate.conf))
