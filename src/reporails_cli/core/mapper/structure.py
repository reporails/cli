"""Block structure of a markdown file, read from the same markdown parse the atoms come from.

Atoms are instruction-level (a list item can yield several, a short one none), so the block
counts a rewrite check needs - list items, table rows, headings, fences, links, which list an
item belongs to - are read here from the parse tokens instead.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from functools import lru_cache
from typing import Any, NamedTuple

import mdurl

from reporails_cli.core.mapper.markdown_extract import _extract_texts
from reporails_cli.core.mapper.md_parser import (
    EmphasisRun,
    code_spans,
    definition_ranges,
    emphasis_runs,
    html_spans,
    line_offsets,
    link_spans,
    recorded_spans,
)
from reporails_cli.core.mapper.parse import _tok_line, inline_line, parse_blocks
from reporails_cli.core.platform.dto.structure import DocumentStructure

_LEAF_BLOCKS = frozenset({"paragraph_open", "heading_open", "fence", "code_block", "table_open", "html_block", "hr"})

# A URL written in running text rather than as a markdown link.
_BARE_URL_RE = re.compile(r"https?://\S+")
_SCHEME_RE = re.compile(r"https?://")


def _written(href: str) -> str:
    """A link destination the way its author wrote it: the parser percent-encodes spaces and
    non-ASCII characters, and a path on disk is spelled with them."""
    return mdurl.decode(href.strip())


def _inline_links(tok: Any, offset: int, *, written_only: bool = False) -> list[tuple[int, str]]:
    """`(line, target)` of each link, image and bare URL in the inline token `tok`, in source order; a
    line is the file line the link's own source position falls on. With `written_only`, a bare URL and
    a link written as a reference to a definition elsewhere are left out."""
    found: list[tuple[int, str]] = []
    for child in tok.children or []:
        span = child.meta.get("span")
        if span is None or (written_only and child.meta.get("reference")):
            continue
        if child.type == "link_open":
            found.append((span[0], _written(str(child.attrGet("href") or ""))))
        elif child.type == "image":
            found.append((span[0], _written(str(child.attrGet("src") or ""))))
    if not written_only:
        found.extend(_bare_urls(tok))
    return [(inline_line(tok, offset, pos), target) for pos, target in sorted(found, key=lambda f: f[0])]


def _bare_urls(tok: Any) -> list[tuple[int, str]]:
    """`(source position, target)` of each URL written in the running text of the inline token `tok`:
    the target is the URL as the parse reads its text, the position is where it starts in the source."""
    recorded = recorded_spans(tok)
    taken = [*recorded.links, *recorded.html, *((c.start, c.end) for c in recorded.code)]
    found: list[tuple[int, str]] = []
    cursor = 0
    in_link = False
    run = ""
    for child in [*(tok.children or []), None]:
        if child is not None and child.type == "text":
            run += child.content
            continue
        if not in_link:
            for m in _BARE_URL_RE.finditer(run):
                start = _scheme_position(tok.content, cursor, taken)
                cursor = start + 1
                found.append((start, m.group(0).rstrip(").,;:")))
        run = ""
        if child is not None and child.type in ("link_open", "link_close"):
            in_link = child.type == "link_open"
    return found


def _scheme_position(source: str, cursor: int, taken: Sequence[tuple[int, int]]) -> int:
    """Where the next `http(s)://` outside the `taken` spans starts in `source` at or after `cursor`;
    `cursor` when the source spells it some other way (an escape)."""
    for m in _SCHEME_RE.finditer(source, cursor):
        if not in_any_span(m.start(), taken):
            return m.start()
    return cursor


def _is_list(tok: Any, nesting: int) -> bool:
    """Whether `tok` opens (`nesting` 1) or closes (-1) a bullet or ordered list."""
    return tok.tag in ("ul", "ol") and tok.nesting == nesting


def _is_after_list(tokens: list[Any], i: int) -> bool:
    """Whether the list opening at `i` directly follows a list closed at the same level; a code
    fence between the two does not split them."""
    j = i - 1
    while j >= 0 and tokens[j].type == "fence":
        j -= 1
    return j >= 0 and _is_list(tokens[j], -1) and tokens[j].level == tokens[i].level


@dataclass
class _Reading:
    """What the walk over the parse tokens has found so far."""

    offset: int
    headings: list[int] = field(default_factory=list)
    items: list[tuple[int, int]] = field(default_factory=list)
    rows: list[tuple[int, str]] = field(default_factory=list)
    fences: list[tuple[int, str]] = field(default_factory=list)
    links: list[tuple[int, str]] = field(default_factory=list)
    block_of: dict[int, int] = field(default_factory=dict)
    lists: list[int] = field(default_factory=list)
    group: int = 0
    block: int = 0
    item_just_opened: bool = False

    def line(self, tok: Any) -> int:
        return _tok_line(tok, self.offset)

    def open_list(self, tokens: list[Any], i: int) -> None:
        if not self.lists and not _is_after_list(tokens, i):
            self.group += 1
        self.lists.append(self.group)

    def open_item(self, tok: Any) -> None:
        self.items.append((self.line(tok), self.lists[-1] if self.lists else self.group))
        self.block += 1
        self.item_just_opened = True

    def leaf(self, tok: Any) -> None:
        """A leaf block's lines join the current block, or a new one; the first leaf of a list
        item belongs to the item's own block."""
        self.block += not self.item_just_opened
        self.item_just_opened = False
        first = self.line(tok)
        self.block_of.update(dict.fromkeys(range(first, first + tok.map[1] - tok.map[0]), self.block))

    def visit(self, tokens: list[Any], i: int) -> None:
        tok = tokens[i]
        if _is_list(tok, 1):
            self.open_list(tokens, i)
        elif _is_list(tok, -1) and self.lists:
            self.lists.pop()
        elif tok.type == "list_item_open":
            self.open_item(tok)
        elif tok.type == "tr_open" and tokens[i + 1].type == "td_open" and tokens[i + 2].type == "inline":
            self.rows.append((self.line(tok), _extract_texts(tokens[i + 2].children or [])[1]))
        elif tok.type == "inline":
            self.links.extend(_inline_links(tok, self.offset))
        elif tok.type == "heading_open":
            self.headings.append(self.line(tok))
        elif tok.type == "fence":
            self.fences.append((self.line(tok), tok.content))
        if tok.type in _LEAF_BLOCKS and tok.map:
            self.leaf(tok)


def read_structure(content: str) -> DocumentStructure:
    """The headings, list items, table rows, fenced blocks, links and block numbering of `content`."""
    tokens, offset = parse_blocks(content)
    reading = _Reading(offset)
    for i in range(len(tokens)):
        reading.visit(tokens, i)
    return DocumentStructure(
        tuple(reading.headings),
        tuple(reading.items),
        tuple(reading.rows),
        tuple(reading.fences),
        tuple(reading.links),
        reading.block_of,
    )


def section_span(content: str, heading: str) -> tuple[int, int] | None:
    """File lines of the `## <heading>` or `### <heading>` section of `content`: the 1-based line of
    its heading and the line (exclusive) where it ends, the next heading of the same or a higher
    level or the line after the last. A heading inside a fenced block is not a heading. None when
    no such heading exists."""
    tokens, offset = parse_blocks(content)
    depth = start = 0
    for i, tok in enumerate(tokens):
        if tok.type != "heading_open" or tok.level or not tok.map:
            continue
        level = int(tok.tag[1:])
        if depth:
            if level <= depth:
                return start, _tok_line(tok, offset)
        elif level in (2, 3) and tokens[i + 1].content.strip() == heading:
            depth, start = level, _tok_line(tok, offset)
    return (start, content.count("\n") + 2) if depth else None


@lru_cache(maxsize=64)
def _link_targets(content: str) -> tuple[tuple[int, str], ...]:
    env: dict[str, Any] = {}
    tokens, offset = parse_blocks(content, env)
    found = [link for tok in tokens if tok.type == "inline" for link in _inline_links(tok, offset, written_only=True)]
    found.extend((ref["map"][0] + offset + 1, _written(str(ref["href"]))) for ref in env.get("references", {}).values())
    return tuple(sorted(found, key=lambda link: link[0]))


def link_targets(content: str) -> list[tuple[int, str]]:
    """`(line, target)` of every link and image written in `content` (`[text](path)`, `![alt](path)`)
    and every link reference definition (`[ref]: path`), outside code, in source order. A bare URL
    and a link that only points at a definition are not listed."""
    return list(_link_targets(content))


def strip_anchor(target: str) -> str:
    """A link target without its trailing `#anchor` and surrounding whitespace."""
    return target.split("#", 1)[0].strip()


def in_any_span(pos: int, spans: Sequence[tuple[int, int]]) -> bool:
    """Whether `pos` falls inside one of the `[start, end)` spans."""
    return any(start <= pos < end for start, end in spans)


def _unescaped(line: str) -> tuple[str, list[int]]:
    """`line` with each `\\|` reduced to `|` (a table cell's text is read that way), and for each
    char of the result, the column in `line` it came from (one more entry marks the end)."""
    out: list[str] = []
    column: list[int] = []
    i = 0
    while i < len(line):
        skip = line.startswith("\\|", i)
        out.append("|" if skip else line[i])
        column.append(i + skip)
        i += 1 + skip
    column.append(len(line))
    return "".join(out), column


def _source_columns(piece: str, line: str, after: int) -> list[int] | None:
    """The column in the file `line` of each char of `piece` and of the char after it, where `piece`
    is a line of an inline token's text: it ends the line, or else is the first match at or after
    column `after`. None when the line does not hold it."""
    plain, source_col = _unescaped(line.rstrip())
    at = len(plain) - len(piece)
    if at < 0 or source_col[at] < after or plain[at : at + len(piece)] != piece:
        at = plain.find(piece, next((k for k, c in enumerate(source_col) if c >= after), len(plain)))
    return None if at < 0 else source_col[at : at + len(piece) + 1]


def _token_columns(tok: Any, lines: list[str], first_line: int, cursor: dict[int, int]) -> list[list[int]] | None:
    """For each line of the inline token `tok`'s text, the column in its file line of each char and of
    the char after it; None when a line of the file does not hold the text.

    The parse places a span within the token's own text; each line of that text sits at the end of
    its file line (a container's marker or a table's pipes come before it), which puts the text, and
    any span in it, in the file.
    """
    columns: list[list[int]] = []
    for j, text_line in enumerate(tok.content.split("\n")):
        n = first_line + j
        if n >= len(lines):
            return None
        found = _source_columns(text_line.rstrip(), lines[n], cursor.get(n, 0))
        if found is None:
            return None
        columns.append(found)
        cursor[n] = found[-1]
    return columns


def _text_starts(tok: Any, columns: list[list[int]], first_line: int) -> list[tuple[int, int]]:
    """`(file line, column)` where each line of the inline token `tok`'s text starts, after its
    container's markers and any indent."""
    out = []
    for j, (text_line, column) in enumerate(zip(tok.content.split("\n"), columns, strict=True)):
        text = text_line.rstrip()
        out.append((first_line + j, column[len(text) - len(text.lstrip())]))
    return out


def _inline_span_ranges(
    tok: Any, columns: list[list[int]], starts: list[int], first_line: int
) -> tuple[list[tuple[int, int]], list[tuple[int, int]], list[EmphasisRun], list[tuple[int, int]]]:
    """Char ranges, in the whole file, of each code span, of each link or image and of each inline HTML
    tag the inline token `tok` holds, and its emphasis runs placed the same way (every position a file
    char offset), given where its text sits (`_token_columns`)."""
    found = recorded_spans(tok)
    if not found.code and not found.links and not found.emphasis and not found.html:
        return [], [], [], []
    text_lines = tok.content.split("\n")
    text_starts = line_offsets(text_lines)

    def to_file(pos: int) -> int:
        j = max(k for k in range(len(text_lines)) if text_starts[k] <= pos)
        return starts[first_line + j] + columns[j][min(pos - text_starts[j], len(columns[j]) - 1)]

    return (
        [(to_file(span.start), to_file(span.end - 1) + 1) for span in found.code],
        [(to_file(begin), to_file(end - 1) + 1) for begin, end in found.links],
        [
            EmphasisRun(
                to_file(run.start),
                to_file(run.end - 1) + 1,
                to_file(run.content_start),
                to_file(run.content_end),
                run.marker,
            )
            for run in found.emphasis
        ],
        [(to_file(begin), to_file(end - 1) + 1) for begin, end in found.html],
    )


def code_ranges(content: str) -> list[tuple[int, int]]:
    """Char ranges of `content` that are code: fenced blocks, indented code blocks and code spans,
    as the markdown parse reads them (an unclosed fence runs to the end of the file)."""
    return list(_source_ranges(content).code)


def _moved(pos: int, at: int, removed: int, inserted: int, *, opens: bool) -> int:
    """Where column `pos` lands when `removed` characters at `at` become `inserted` ones. A column that
    opens something (a range start) at the edit point moves with the inserted text; one that closes
    something (a range end) stays before it. A column inside the removed characters falls to `at`."""
    if pos >= at + removed and (opens or pos > at):
        return pos + inserted - removed
    return min(pos, at)


def _moved_ranges(
    ranges: tuple[tuple[int, int], ...], at: int, removed: int, inserted: int
) -> tuple[tuple[int, int], ...]:
    return tuple(
        (_moved(lo, at, removed, inserted, opens=True), _moved(hi, at, removed, inserted, opens=False))
        for lo, hi in ranges
    )


@dataclass(frozen=True)
class LineSpans:
    """The `[start, end)` columns of a line that a code span (or code block), a link, image or
    link reference definition and an inline HTML tag occupy, the column where the line's inline text
    starts after a blockquote's `>` markers or a list item's marker (None for a line with no inline
    text: a fenced or markup block, a blank line, a rule), and the emphasis runs that sit wholly on the
    line (their positions are columns; a run that runs over a line break is not listed)."""

    code: tuple[tuple[int, int], ...] = ()
    links: tuple[tuple[int, int], ...] = ()
    text: int | None = None
    emphasis: tuple[EmphasisRun, ...] = ()
    html: tuple[tuple[int, int], ...] = ()

    @classmethod
    def of_fragment(cls, text: str) -> LineSpans:
        """The columns of `text`, read as one inline fragment."""
        return cls(
            tuple((span.start, span.end) for span in code_spans(text)),
            link_spans(text),
            0,
            emphasis_runs(text),
            html_spans(text),
        )

    def spliced(self, at: int, removed: int, inserted: int) -> LineSpans:
        """These columns after `removed` characters of the line at column `at` are replaced by
        `inserted` new ones: every column after the edit moves with it, so the line need not be read
        again."""

        def move(pos: int, *, opens: bool) -> int:
            return _moved(pos, at, removed, inserted, opens=opens)

        return LineSpans(
            _moved_ranges(self.code, at, removed, inserted),
            _moved_ranges(self.links, at, removed, inserted),
            None if self.text is None else move(self.text, opens=False),
            tuple(
                EmphasisRun(
                    move(run.start, opens=True),
                    move(run.end, opens=False),
                    move(run.content_start, opens=False),
                    move(run.content_end, opens=True),
                    run.marker,
                )
                for run in self.emphasis
            ),
            _moved_ranges(self.html, at, removed, inserted),
        )

    def with_code(self, span: tuple[int, int]) -> LineSpans:
        """These columns with one more code span."""
        return replace(self, code=tuple(sorted((*self.code, span))))

    def softened(self, run: EmphasisRun) -> LineSpans:
        """These columns after the bold `run` becomes italic: one delimiter character is dropped on each
        side of its content."""
        italic = replace(self, emphasis=tuple(r._replace(marker="*") if r == run else r for r in self.emphasis))
        return italic.spliced(run.content_end, 1, 0).spliced(run.start, 1, 0)


def _spread(
    ranges: tuple[tuple[int, int], ...], lines: list[str], starts: list[int]
) -> dict[int, list[tuple[int, int]]]:
    """Each file-wide char range cut into the columns it covers on each line it touches."""
    by_line: dict[int, list[tuple[int, int]]] = {}
    for begin, end in ranges:
        n = max(bisect_right(starts, begin) - 1, 0)
        while n < len(lines) and starts[n] < end:
            lo, hi = max(begin, starts[n]) - starts[n], min(end, starts[n] + len(lines[n])) - starts[n]
            if hi > lo:
                by_line.setdefault(n, []).append((lo, hi))
            n += 1
    return by_line


def line_spans(content: str) -> list[LineSpans]:
    """For each line of `content` (split on newlines), the columns inside code and inside links and
    the column where its inline text starts, read from the markdown parse: a fenced or indented code
    block is code on every line it covers."""
    lines = content.split("\n")
    starts = line_offsets(lines)
    read = _source_ranges(content)
    in_code, in_links, in_html = (_spread(ranges, lines, starts) for ranges in (read.code, read.links, read.html))
    text = dict(read.text)
    runs: dict[int, list[EmphasisRun]] = {}
    for run in read.emphasis:
        n = max(bisect_right(starts, run.start) - 1, 0)
        if run.end <= starts[n] + len(lines[n]):
            runs.setdefault(n, []).append(run.shifted(-starts[n]))
    return [
        LineSpans(
            tuple(in_code.get(n, ())),
            tuple(in_links.get(n, ())),
            text.get(n),
            tuple(runs.get(n, ())),
            tuple(in_html.get(n, ())),
        )
        for n in range(len(lines))
    ]


def paragraph_lines(content: str) -> list[tuple[int, int]]:
    """`(first, last)` 0-based file lines of each paragraph that is not inside a list item: a plain
    block of prose (a blockquote's paragraph counts), never a heading, list item, table row, fence,
    indented code block, rule or markup block."""
    tokens, offset = parse_blocks(content)
    out: list[tuple[int, int]] = []
    in_item = 0
    for tok in tokens:
        if tok.type == "list_item_open":
            in_item += 1
        elif tok.type == "list_item_close":
            in_item -= 1
        elif tok.type == "paragraph_open" and tok.map and not in_item:
            out.append((tok.map[0] + offset, tok.map[1] + offset - 1))
    return out


class _SourceRanges(NamedTuple):
    """What the parse places in the file: code, link and inline HTML char ranges, `(line, column)` where
    the inline text of each file line starts, and the emphasis runs (positions are file char offsets)."""

    code: tuple[tuple[int, int], ...]
    links: tuple[tuple[int, int], ...]
    text: tuple[tuple[int, int], ...]
    emphasis: tuple[EmphasisRun, ...]
    html: tuple[tuple[int, int], ...]


def _place_inline(
    tok: Any, lines: list[str], starts: list[int], first: int, cursor: dict[int, int]
) -> _SourceRanges | None:
    """Where the inline token `tok` puts its text, code spans and links in the file; None when the
    file's lines do not hold its text."""
    columns = _token_columns(tok, lines, first, cursor)
    if columns is None:
        return None
    code, links, emphasis, html = _inline_span_ranges(tok, columns, starts, first)
    return _SourceRanges(
        tuple(code), tuple(links), tuple(_text_starts(tok, columns, first)), tuple(emphasis), tuple(html)
    )


@lru_cache(maxsize=64)
def _source_ranges(content: str) -> _SourceRanges:
    """The code, link and inline HTML ranges, the text starts and the emphasis runs of `content`, placed in the file."""
    env: dict[str, Any] = {}
    tokens, offset = parse_blocks(content, env)
    lines = content.split("\n")
    starts = line_offsets(lines)
    starts.append(len(content) + 1)
    parts: list[_SourceRanges] = []
    cursor: dict[int, int] = {}
    for tok in tokens:
        if tok.type in ("fence", "code_block") and tok.map:
            block = (starts[tok.map[0] + offset], min(starts[tok.map[1] + offset], len(content)))
            parts.append(_SourceRanges((block,), (), (), (), ()))
        elif tok.type == "inline" and tok.map:
            placed = _place_inline(tok, lines, starts, tok.map[0] + offset, cursor)
            if placed is not None:
                parts.append(placed)
    text: dict[int, int] = {}
    for n, col in (start for part in parts for start in part.text):
        text.setdefault(n, col)
    return _SourceRanges(
        tuple(span for part in parts for span in part.code),
        (*(span for part in parts for span in part.links), *definition_ranges(env, starts, offset)),
        tuple(sorted(text.items())),
        tuple(run for part in parts for run in part.emphasis),
        tuple(span for part in parts for span in part.html),
    )
