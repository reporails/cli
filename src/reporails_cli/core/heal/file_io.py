"""Reading and writing a heal target file: lines kept with their own line endings, import-expanded files skipped."""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_LINE_BREAK = re.compile(r"(\r\n|\r|\n)")


def read_lines(path: Path) -> tuple[list[str], list[str]]:
    """The file's lines (each ends in `\\n` where the parse breaks a line) and the ending each was written with."""
    with path.open(encoding="utf-8", newline="") as handle:
        pieces = _LINE_BREAK.split(handle.read())
    lines = [f"{text}\n" for text in pieces[0:-1:2]] + ([pieces[-1]] if pieces[-1] else [])
    return lines, pieces[1::2]


def write_lines(path: Path, lines: list[str], endings: list[str]) -> None:
    """Write `lines` back, each with the ending it was read with."""
    out = "".join(line.removesuffix("\n") + endings[i] if i < len(endings) else line for i, line in enumerate(lines))
    path.write_text(out, encoding="utf-8", newline="")


def imports_expand(path: Path, content: str) -> bool:
    """Whether the file's `@import`s expand (atom lines are then import-expanded, a write would mis-target),
    or the expansion fails; either way heal leaves the file alone."""
    from reporails_cli.core.mapper.imports import expand_imports

    try:
        return expand_imports(content, path) != content
    except Exception as exc:  # any import-resolution error: skip this file, never abort the heal pass
        logger.warning("Skipping heal of %s: import-expansion failed: %s", path, exc)
        return True
