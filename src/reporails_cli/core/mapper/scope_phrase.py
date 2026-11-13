"""The phrase that says where, when or to what an instruction applies, recorded as the atom's scope.

The decoded scope axis names a condition (`If the tests fail,`). A place, time or target phrase
(`In CI,` before the clause, `in staging` or `for src/` after its object) is left in no slot, or
inside the object; this reads it into `scope`. A means phrase (`with pytest`) and a word inside a
backticked construct are not scope.
"""

from __future__ import annotations

from reporails_cli.core.mapper.classify_lexicon import SCOPE_PHRASE_PREPOSITIONS, words_of
from reporails_cli.core.mapper.lexical import DASH_MARKS
from reporails_cli.core.mapper.word_spans import word_offsets
from reporails_cli.core.platform.dto.mapping import AtomTuple, Span

_FRONTED_REACH = 6  # a fronted phrase of up to six words before its comma
_BREAKS = (",", ";", ":", *DASH_MARKS)


def _in_code(text: str) -> list[bool]:
    """Per word of ``text``: whether it sits inside a backticked construct."""
    flags: list[bool] = []
    inside = False
    for lo, hi in word_offsets(text):
        word = text[lo:hi]
        flags.append(inside or word.startswith("`"))
        if word.count("`") % 2 == 1:
            inside = not inside
    return flags


def _is_preposition(word: str) -> bool:
    letters = words_of(word)
    return len(letters) == 1 and letters[0] in SCOPE_PHRASE_PREPOSITIONS


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
        return _with(t, object_, _span(t.text, offsets, start, obj[1], t.object.conf), subject)
    left_out = _after_object_end(words, flags, obj)
    if left_out is None:
        return t
    return _with(t, t.object, _span(t.text, offsets, obj[1], left_out, t.object.conf))


def record_scope_phrase(t: AtomTuple) -> AtomTuple:
    """``t`` with its scope set to the fronted or trailing place/time/target phrase, when it has none."""
    words = t.text.split()
    if t.polarity == 0 or t.scope.offset is not None or t.predicate.offset is None or len(words) < 3:
        return t
    flags = _in_code(t.text)
    offsets = word_offsets(t.text)
    end = _fronted_end(words, flags, t)
    if end is None:
        return _trailing(t, words, flags, offsets)
    return _with(t, t.object, _span(t.text, offsets, 0, end, t.predicate.conf))
