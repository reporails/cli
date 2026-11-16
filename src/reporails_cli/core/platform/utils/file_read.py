"""The one reader of a file's text, bytes or head."""

from __future__ import annotations

from pathlib import Path
from typing import Literal


def read_file_text(
    path: Path,
    *,
    encoding: Literal["utf-8", "utf-8-sig"] = "utf-8",
    errors: Literal["strict", "replace"] = "strict",
    limit: int | None = None,
) -> str:
    """The text of `path` decoded with `encoding`; `errors="strict"` raises `UnicodeDecodeError` on bad bytes.
    With `limit`, at most that many characters are read."""
    if limit is None:
        return path.read_text(encoding=encoding, errors=errors)
    with path.open(encoding=encoding, errors=errors) as handle:
        return handle.read(limit)


def read_file_bytes(path: Path) -> bytes:
    """The raw bytes of `path`."""
    return path.read_bytes()


def read_file_head(path: Path, limit: int) -> bytes:
    """At most the first `limit` bytes of `path`."""
    with path.open("rb") as handle:
        return handle.read(limit)
