"""The one path-glob matcher: `**` spans directories, `{a,b}` expands, `*` and `?` stay in one segment."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from functools import lru_cache
from pathlib import PurePosixPath
from typing import NamedTuple

# A segment holding one of these is a pattern, not a plain name.
GLOB_CHARS = frozenset("*?[{")

_ESCAPES = {"*": "[*]", "?": "[?]", "[": "[[]", "{": "[{]"}


def escape_glob(text: str) -> str:
    """`text` as a glob that matches only `text` itself.

    Pure function. `*`, `?` and `[` are written as one-character classes (`[*]`, `[?]`, `[[]`),
    and `{` as `[{]`, which does not open a brace group.
    """
    return "".join(_ESCAPES.get(char, char) for char in text)


class _Segment(NamedTuple):
    """One glob segment: its text, and a matcher for a path segment."""

    text: str
    matches: Callable[[str], object]
    literal: bool


class _Shape(NamedTuple):
    """A glob split at its `**` segments: the runs of segments between them, and whether it opens or ends with one."""

    chunks: tuple[tuple[_Segment, ...], ...]
    opens: bool
    ends: bool
    has_star: bool


def _segment(text: str) -> _Segment:
    """A glob segment; one with no glob character is compared as text."""
    if GLOB_CHARS.isdisjoint(text):
        return _Segment(text, text.__eq__, True)
    return _Segment(text, re.compile(fnmatch.translate(text)).match, False)


def _shape(segments: tuple[str, ...]) -> _Shape:
    """`segments` split at their `**` segments."""
    chunks: list[tuple[_Segment, ...]] = []
    run: list[_Segment] = []
    for text in segments:
        if text == "**":
            if run:
                chunks.append(tuple(run))
                run = []
        else:
            run.append(_segment(text))
    if run:
        chunks.append(tuple(run))
    return _Shape(tuple(chunks), segments[0] == "**", segments[-1] == "**", "**" in segments)


def _chunk_at(parts: tuple[str, ...], at: int, chunk: tuple[_Segment, ...]) -> bool:
    """Whether the segments of `chunk` match the path segments starting at `at`."""
    if len(chunk) == 1:
        return at < len(parts) and bool(chunk[0].matches(parts[at]))
    if at + len(chunk) > len(parts):
        return False
    return all(seg.matches(parts[at + offset]) for offset, seg in enumerate(chunk))


def _find_chunk(parts: tuple[str, ...], chunk: tuple[_Segment, ...], start: int, end: int) -> int:
    """The first position in `start..end` where `chunk` matches `parts` and ends by `end`; -1 when none."""
    size = len(chunk)
    if size == 1:
        only = chunk[0]
        if only.literal:
            text = only.text
            return next((at for at in range(start, end) if parts[at] == text), -1)
        matches = only.matches
        for at in range(start, end):
            if matches(parts[at]):
                return at
        return -1
    for at in range(start, end - size + 1):
        if _chunk_at(parts, at, chunk):
            return at
    return -1


def _inner_span(
    parts: tuple[str, ...], shape: _Shape, prefix: bool
) -> tuple[int, int, tuple[tuple[_Segment, ...], ...]] | None:
    """The part of `parts` left between the glob's fixed first and last runs, and the runs still to place.

    `None` when the first run (unless the glob opens with `**`) or the last run (unless it ends
    with `**`, or `prefix` lets the match stop early) does not match where it must.
    """
    chunks, opens, ends, _ = shape
    size = len(parts)
    start, end = 0, size
    if not opens:
        first = chunks[0]
        if len(first) > size or not _chunk_at(parts, 0, first):
            return None
        start, chunks = len(first), chunks[1:]
    if not ends and not prefix and chunks:
        last = chunks[-1]
        end -= len(last)
        if end < start or not _chunk_at(parts, end, last):
            return None
        chunks = chunks[:-1]
    return start, end, chunks


def _shape_matches(parts: tuple[str, ...], shape: _Shape, prefix: bool = False) -> bool:
    """Whether path segments match a glob; a `**` segment spans zero or more directories.

    A trailing `**` needs at least one more path segment. Each run of segments between `**`
    segments is placed at its earliest position, which leaves the most room for the rest.
    With `prefix`, the glob may match the segments or any leading part of them: the runs are
    placed as for a trailing `**`, and the match may end before the last segment.
    """
    if prefix and not parts:
        return False
    if not shape.has_star:
        size = len(shape.chunks[0])
        if prefix:
            return size <= len(parts) and _chunk_at(parts, 0, shape.chunks[0])
        return size == len(parts) and _chunk_at(parts, 0, shape.chunks[0])
    if shape.opens and (shape.ends or prefix):
        start, end, chunks = 0, len(parts), shape.chunks
    else:
        span = _inner_span(parts, shape, prefix)
        if span is None:
            return False
        start, end, chunks = span
    for chunk in chunks:
        at = _find_chunk(parts, chunk, start, end)
        if at < 0:
            return False
        start = at + len(chunk)
    return start < len(parts) if shape.ends else True


# A comma group opens at a `{` that is not the `[{]` escape.
_BRACE_GROUP = re.compile(r"(?<!\[)\{(?!\])([^{}]*,[^{}]*)\}")


@lru_cache(maxsize=1024)
def brace_alternatives(glob: str) -> tuple[str, ...]:
    """The globs a `{a,b}` group stands for (`*.{ts,tsx}` -> `*.ts`, `*.tsx`); the glob itself without one.

    Pure function, cached. Only a group holding a comma expands: `{x}` and `{{x}}` stay literal,
    and so does a `{` written as `[{]`.
    """
    group = _BRACE_GROUP.search(glob)
    if group is None:
        return (glob,)
    head, tail = glob[: group.start()], glob[group.end() :]
    return tuple(alt for option in group.group(1).split(",") for alt in brace_alternatives(head + option + tail))


@lru_cache(maxsize=1024)
def _alternative_shapes(pattern: str, anchored: bool) -> tuple[_Shape, ...]:
    """The shape of each brace alternative of `pattern`; an unanchored relative one starts with `**`."""
    out: list[_Shape] = []
    for alternative in brace_alternatives(pattern):
        glob = PurePosixPath(alternative)
        if glob.parts:
            out.append(_shape(glob.parts if anchored or glob.is_absolute() else ("**", *glob.parts)))
    return tuple(out)


# A path with a leading, trailing or doubled slash, or a `.` segment, is normalized before it is split.
_NEEDS_NORMALIZING = re.compile(r"^/|^\./|/$|/\.$|//|/\./|^\.$")


@lru_cache(maxsize=8192)
def _path_parts(path: str) -> tuple[str, ...]:
    """The segments of a posix path."""
    if _NEEDS_NORMALIZING.search(path):
        return PurePosixPath(path).parts
    return tuple(path.split("/")) if path else ()


def glob_matches(path: str, pattern: str, *, anchored: bool = False, prefix: bool = False) -> bool:
    """Whether a posix path matches a glob pattern, one path segment at a time.

    Pure function. `*` and `?` stay inside one segment; a `**` segment spans zero or more
    directories (`a/**/b.md` matches `a/b.md` and `a/x/y/b.md`), and a trailing `**` needs
    at least one more segment. A `{a,b}` group matches any of its alternatives. An anchored or
    absolute pattern must match the whole path;
    any other matches the path's trailing segments (`AGENTS.md` matches `pkg/AGENTS.md`).
    With `prefix`, a path also matches when a folder above it does (`docs` matches `docs/a/b.md`).
    """
    parts = _path_parts(path)
    return any(_shape_matches(parts, shape, prefix) for shape in _alternative_shapes(pattern, anchored))
