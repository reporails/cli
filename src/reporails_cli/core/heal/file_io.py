"""Reading and writing a heal target file: lines kept with their own line endings."""

from __future__ import annotations

import re
from pathlib import Path

_LINE_BREAK = re.compile(r"(\r\n|\r|\n)")


def split_lines(text: str) -> tuple[list[str], list[str]]:
    """The text's lines as the parse numbers them (each ends in `\\n` where the parse breaks a line; a form
    feed, NEL or Unicode line separator is no break) and the ending each was written with."""
    pieces = _LINE_BREAK.split(text)
    lines = [f"{piece}\n" for piece in pieces[0:-1:2]] + ([pieces[-1]] if pieces[-1] else [])
    return lines, pieces[1::2]


def read_lines(path: Path) -> tuple[list[str], list[str]]:
    """The file's lines and the ending each was written with (see `split_lines`)."""
    with path.open(encoding="utf-8", newline="") as handle:
        return split_lines(handle.read())


def write_lines(path: Path, lines: list[str], endings: list[str]) -> None:
    """Write `lines` back, each with the ending it was read with."""
    out = "".join(line.removesuffix("\n") + endings[i] if i < len(endings) else line for i, line in enumerate(lines))
    path.write_text(out, encoding="utf-8", newline="")
