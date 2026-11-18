"""Read the complete lines appended to a file since a byte offset."""

from __future__ import annotations

from pathlib import Path


def read_appended_lines(path: Path, offset: int, until: int | None = None) -> tuple[list[bytes], int]:
    """The complete lines from byte `offset` on (with `until`, no further than byte `until`), and the offset just
    past the last of them.

    A torn last line (no newline yet) is left for the next read. A missing or unreadable file
    reads as no lines at `offset`. Raises `ValueError` on a negative offset."""
    if offset < 0:
        raise ValueError(f"offset must be 0 or more, got {offset}")
    try:
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read() if until is None else handle.read(max(0, until - offset))
    except OSError:
        return [], offset
    end = data.rfind(b"\n")
    if end < 0:
        return [], offset
    return data[:end].split(b"\n"), offset + end + 1
