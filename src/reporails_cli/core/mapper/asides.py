"""Asides: the word spans of an atom's plain text that illustrate or list members of what the
instruction is about (`(see the guide)`, `such as tokens or passwords`, `, e.g. X`), as opposed
to the words that say what it asks or forbids.
"""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.mapper.classify_lexicon import CONDITION_CONJUNCTIONS, DEFINITE_DETERMINERS, INDEFINITE_ARTICLES
from reporails_cli.core.mapper.parse import _build_scope_mask
from reporails_cli.core.mapper.word_spans import word_offsets

# Cues that open an example or a list of members wherever they stand.
_OPEN_CUES: tuple[tuple[str, ...], ...] = (
    ("such", "as"),
    ("e.g.",),
    ("e.g",),
    ("i.e.",),
    ("i.e",),
    ("for", "example"),
    ("for", "instance"),
)
# Cues that open one only after a comma (`, like the X below`, `, because X`); bare they are ordinary words.
_SET_OFF_CUES: tuple[tuple[str, ...], ...] = (("like",), ("including",), ("because",))
_PARENTHESIS_CUES: tuple[tuple[str, ...], ...] = (("see",), ("cf.",), ("cf",))
_ARTICLES = INDEFINITE_ARTICLES | DEFINITE_DETERMINERS
_EDGE_PUNCT = ",;:!?()[]\"'"


def _norm(token: str) -> str:
    """A token lowered, without the punctuation around it (`e.g.` keeps its dots)."""
    return token.lower().strip(_EDGE_PUNCT)


def _cue_len(tokens: list[str], i: int) -> int:
    """How many words the example cue opening at word `i` takes; 0 when none opens there."""
    cues = _OPEN_CUES + (_SET_OFF_CUES if i > 0 and tokens[i - 1].endswith(",") else ())
    ahead = [_norm(t) for t in tokens[i : i + 2]]
    return next((len(cue) for cue in cues if tuple(ahead[: len(cue)]) == cue), 0)


def _list_goes_on(tokens: list[str], j: int) -> bool:
    """Whether the list a comma-ended word `j - 1` closes continues with word `j`."""
    return j < len(tokens) and (_norm(tokens[j]) in CONDITION_CONJUNCTIONS or tokens[j].endswith(","))


def _set_off_end(tokens: list[str], start: int) -> int:
    """Where an aside a comma set off, opening its items at `start`, ends: past the comma that closes
    it, else the end of the text."""
    for j in range(start, len(tokens)):
        if tokens[j].endswith(",") and not _list_goes_on(tokens, j + 1):
            return j + 1
    return len(tokens)


def _items_end(tokens: list[str], start: int) -> int:
    """Where the items an unset-off cue lists, from `start`, end: each is one word, joined by `and` / `or`."""
    j = start
    while j < len(tokens):
        j += _norm(tokens[j]) in _ARTICLES
        j += 1
        if j <= len(tokens) and tokens[j - 1].endswith(",") and not _list_goes_on(tokens, j):
            break
        if j < len(tokens) and _norm(tokens[j]) in CONDITION_CONJUNCTIONS:
            j += 1
            continue
        if j < len(tokens) and tokens[j - 1].endswith(","):
            continue
        break
    return min(j, len(tokens))


def _is_illustration(tokens: list[str], named_tokens: Sequence[str]) -> bool:
    """Whether a parenthesised run illustrates rather than enumerates new kinds: it opens with a cue
    (`see`, `e.g.`, `cf.`) or holds nothing but named constructs and the words that list them."""
    words = [_norm(t) for t in tokens]
    if tuple(words[:1]) in _PARENTHESIS_CUES or any(tuple(words[: len(c)]) == c for c in _OPEN_CUES):
        return True
    named = {_norm(w) for token in named_tokens for w in token.split()}
    return bool(words) and all(w in named or w in CONDITION_CONJUNCTIONS for w in words)


def aside_spans(plain_text: str, named_tokens: Sequence[str]) -> tuple[tuple[int, int], ...]:
    """The word spans `[start, end)` of `plain_text` that are asides: an example or list of members a
    cue opens (`such as`, `e.g.`, `for example`, and after a comma `like` or `including`) through the end
    of its items or, set off by a comma, the comma that closes it; and a parenthesised run that opens with
    a cue or lists only named constructs (`(see the guide)`, `(`a`, `b` or `c`)`). A parenthesised run that
    lists kinds in plain words is no aside: it says what the instruction covers."""
    offsets = word_offsets(plain_text)
    tokens = [plain_text[s:e] for s, e in offsets]
    mask = _build_scope_mask(plain_text, quotes=False)
    covered = [False] * len(tokens)
    k = 0
    while k < len(tokens):
        if not mask[offsets[k][0]]:
            k += 1
            continue
        stop = k
        while stop < len(tokens) and mask[offsets[stop][0]]:
            stop += 1
        if _is_illustration(tokens[k:stop], named_tokens):
            covered[k:stop] = [True] * (stop - k)
        k = stop
    i = 0
    while i < len(tokens):
        cue = _cue_len(tokens, i) if i > 0 else 0
        if not cue:
            i += 1
            continue
        end = _set_off_end(tokens, i + cue) if tokens[i - 1].endswith(",") else _items_end(tokens, i + cue)
        covered[i:end] = [True] * (end - i)
        i = max(end, i + 1)
    spans: list[tuple[int, int]] = []
    for k, is_aside in enumerate(covered):
        if not is_aside:
            continue
        if spans and spans[-1][1] == k:
            spans[-1] = (spans[-1][0], k + 1)
        else:
            spans.append((k, k + 1))
    return tuple(spans)
