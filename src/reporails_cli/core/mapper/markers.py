"""Formatting-marker projection — put a parent line's markers back onto a span.

A stage that rebuilds atoms from a parent's AST-clean ``plain_text`` has no backticks
or emphasis to read specificity from, so every backticked name in the rebuilt atom
would read ``abstract``. The parent still holds the formatted ``text``, and every
code span / emphasis run in it is a verbatim substring of ``plain_text``; each run is
located there once and re-wrapped around whatever part of it falls inside a span.
The span's atom is then built from that formatted text exactly as the legacy
per-sentence split builds its atoms.
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from itertools import accumulate, pairwise

from reporails_cli.core.mapper.md_parser import code_spans, emphasis_runs, replace_spans

# Markdown inline markers are read from the markdown parse: the code spans and the emphasis runs
# it pairs (a `_` or `*` inside backticks - `__init__.py`, `notes-*.md` - never pairs, nor does
# a lone glob star or an in-word underscore).

# A list item's marker (`-`, `*`, `+`, `1.`, `1)`) and a task item's checkbox (`[ ]`, `[x]`).
_LIST_MARKER_RE = re.compile(r"^(?:(?:[-*+]|\d+[.)])\s+)?(?:\[[ xX]\]\s+)?")

# (plain_start, plain_end, marker) - one located formatting run.
Marker = tuple[int, int, str]


def without_list_marker(text: str) -> str:
    """`text` without its list marker and task checkbox, and without the space around it.

    A unit read from the markdown parse carries no marker; a fenced line and a numbered heading's
    text can.
    """
    return _LIST_MARKER_RE.sub("", text.strip())


def strip_markdown_inline(text: str, *, keep_code: bool = False) -> str:
    """Drop emphasis delimiters and code fences, keeping every character they wrap.

    Unpaired markers stay: `*.pem` is a glob, `snake_case` is an identifier, and
    both must survive into the analysed text and into the stored map. Code-span
    content is verbatim - an underscore or star inside backticks is never a marker.
    With `keep_code` a code span keeps its backticks and only the emphasis is dropped.
    """
    return replace_spans(text, _strip_edits(text, keep_code=keep_code), lambda edit: edit[2])


def _strip_edits(text: str, *, keep_code: bool = False) -> list[tuple[int, int, str]]:
    """The edits that strip ``text``'s inline markers: each code span becomes its content (unless
    ``keep_code``) and each emphasis delimiter is dropped."""
    edits = [] if keep_code else [(span.start, span.end, span.content) for span in code_spans(text)]
    for run in emphasis_runs(text):
        edits += [(run.start, run.content_start, ""), (run.content_end, run.end, "")]
    return edits


def _runs(md_text: str) -> list[tuple[int, int, str, str]]:
    """Every formatting run of ``md_text`` as (md_start, md_end, marker, plain content).

    Each run's content is cut from one stripped copy of ``md_text`` at the positions its content edges
    map to, so the text is parsed once however deep its runs nest.
    """
    kept: list[tuple[int, int, str]] = []
    cursor = 0
    for edit in sorted(_strip_edits(md_text), key=lambda e: (e[0], -e[1])):
        if edit[0] >= cursor:
            kept.append(edit)
            cursor = edit[1]
    plain = replace_spans(md_text, kept, lambda edit: edit[2])
    ends = [edit[1] for edit in kept]
    shifts = list(accumulate(len(edit[2]) - (edit[1] - edit[0]) for edit in kept))

    def plain_at(pos: int) -> int:
        n = bisect_right(ends, pos)
        return pos + (shifts[n - 1] if n else 0)

    runs = [(span.start, span.end, "`", span.content) for span in code_spans(md_text)]
    runs += [
        (run.start, run.end, run.marker, plain[plain_at(run.content_start) : plain_at(run.content_end)])
        for run in emphasis_runs(md_text)
    ]
    return sorted(runs, key=lambda r: (r[0], -r[1]))


def project_markers(md_text: str, plain_text: str) -> list[Marker]:
    """Locate each formatting run of ``md_text`` inside ``plain_text``.

    Each run's plain position is derived from its markdown position: the plain text
    is the markdown minus the marker characters before that point (both delimiters
    of every run that closed earlier, the opener of every run still open). So a bare
    earlier mention of the same word never captures a later run. The derived
    position is checked against the plain text with a small tolerance (the AST may
    have collapsed whitespace); a run whose content is not there is skipped.
    """
    runs = _runs(md_text)
    out: list[Marker] = []
    for (md_start, _md_end, marker, needle), removed in zip(runs, _markers_before(runs), strict=True):
        if not needle:
            continue
        hint = md_start + len(marker) - removed
        idx = _nearest(plain_text, needle, hint)
        if idx is None:
            continue
        out.append((idx, idx + len(needle), marker))
    return out


def _markers_before(runs: list[tuple[int, int, str, str]]) -> list[int]:
    """For each run (in start order), the marker characters the markdown before it holds: the opener of
    every run that began earlier, and the closer too of every run that closed by then."""
    by_end = sorted(runs, key=lambda r: r[1])
    ends = [r[1] for r in by_end]
    closed = list(accumulate(len(r[2]) for r in by_end))
    starts = [r[0] for r in runs]
    opened = list(accumulate(len(r[2]) for r in runs))
    counts = []
    for md_start, *_ in runs:
        n_open, n_closed = bisect_left(starts, md_start), bisect_right(ends, md_start)
        counts.append((opened[n_open - 1] if n_open else 0) + (closed[n_closed - 1] if n_closed else 0))
    return counts


def _nearest(haystack: str, needle: str, hint: int, tolerance: int = 3) -> int | None:
    """The occurrence of ``needle`` closest to ``hint``, or None when none lies within ``tolerance``."""
    best: int | None = None
    start = max(0, hint - tolerance)
    stop = max(0, hint + tolerance) + len(needle)
    while (idx := haystack.find(needle, start, stop)) >= 0:
        if best is None or abs(idx - hint) < abs(best - hint):
            best = idx
        if idx >= hint:
            break
        start = idx + 1
    return best if best is not None and abs(best - hint) <= tolerance else None


def reformat_span(span: str, start: int, markers: list[Marker]) -> str:
    """Put the markers overlapping ``[start, start + len(span))`` back around the span's text."""
    end = start + len(span)
    clipped = [(max(ps, start) - start, min(pe, end) - start, mk) for ps, pe, mk in markers if ps < end and pe > start]
    if not clipped:
        return span
    opens: dict[int, list[str]] = {}
    closes: dict[int, list[str]] = {}
    for ps, pe, mk in sorted(clipped, key=lambda c: (c[0], -c[1])):
        opens.setdefault(ps, []).append(mk)
        closes.setdefault(pe, []).insert(0, mk)  # inner runs close first
    cuts = sorted({0, len(span), *opens, *closes})
    parts: list[str] = []
    for a, b in pairwise(cuts):
        parts.extend(closes.get(a, ()))
        parts.extend(opens.get(a, ()))
        parts.append(span[a:b])
    parts.extend(closes.get(len(span), ()))
    return "".join(parts)


def reformat_spans(md_text: str, plain_text: str, spans: list[str]) -> list[str]:
    """The formatted form of each span, walked in order through ``plain_text``.

    ``spans`` are in-order substrings of ``plain_text`` (sentence frames, clauses).
    A parent with no markers, or a span not found from the running cursor, comes
    back unchanged — it is already the best text available.
    """
    if md_text == plain_text:
        return list(spans)
    markers = project_markers(md_text, plain_text)
    if not markers:
        return list(spans)
    out: list[str] = []
    cursor = 0
    for span in spans:
        idx = plain_text.find(span, cursor)
        if idx < 0:
            out.append(span)
            continue
        cursor = idx + len(span)
        out.append(reformat_span(span, idx, markers))
    return out
