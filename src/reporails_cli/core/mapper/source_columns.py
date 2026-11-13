"""Where inline text sits in its file: the column of each character of an inline token's text, and of each
character of the plain text read from it.

The one reader of source columns. The whole-file readers (`structure`) and the parse that builds each
atom both take their columns from here, so an atom's position is read once, where its text is.
"""

from __future__ import annotations

from collections.abc import Sequence

from markdown_it.token import Token

from reporails_cli.core.mapper.md_parser import line_offsets, recorded_spans
from reporails_cli.core.platform.dto.ruleset import PlainPlacement


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


def token_columns(tok: Token, lines: list[str], first_line: int, cursor: dict[int, int]) -> list[list[int]] | None:
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


def _aligned(
    plain: str,
    source: str,
    columns: list[int],
    left_out: Sequence[tuple[int, int]],
    code: Sequence[tuple[int, int]],
) -> tuple[int, ...] | None:
    """The file column of each char of `plain`, which the parse read from `source` by dropping markup
    (emphasis marks, a link's brackets and target, an escape's backslash, extra spaces, an emoji).

    Each char sits at the first equal char of `source` after the one before it; the first char of a
    code span's words sits at the span's opening backtick. None when a word char of `source` is passed
    over that is not inside a span the plain text leaves out (a link or an image target, an HTML tag):
    the plain text is then not a plain subsequence of the source, and no column is claimed for it.
    """
    out: list[int] = []
    entered: set[int] = set()
    at = 0
    for ch in plain:
        start = at
        while at < len(source) and source[at] != ch:
            at += 1
        if at == len(source):
            return None
        if any(source[k].isalnum() and not any(lo <= k < hi for lo, hi in left_out) for k in range(start, at)):
            return None
        opening = next((lo for lo, hi in code if lo < at < hi and lo not in entered), None)
        if opening is not None:
            entered.add(opening)
        out.append(columns[at if opening is None else opening])
        at += 1
    return tuple(out)


def plain_placement(
    tok: Token, columns: list[list[int]], line_in_token: int, file_line: str, plain: str
) -> PlainPlacement | None:
    """Where each char of `plain`, the plain text of the line `line_in_token` of the inline token `tok`,
    sits in `file_line`; None when the token's line does not hold it as a plain subsequence."""
    text_lines = tok.content.split("\n")
    if not 0 <= line_in_token < len(columns) or not plain:
        return None
    base = line_offsets(text_lines)[line_in_token]
    found = recorded_spans(tok)
    left_out = [(lo - base, hi - base) for lo, hi in (*found.links, *found.html)]
    code = [(span.start - base, span.end - base) for span in found.code]
    placed = _aligned(plain, text_lines[line_in_token].rstrip(), columns[line_in_token], left_out, code)
    return None if placed is None else PlainPlacement(line=file_line, columns=placed)
