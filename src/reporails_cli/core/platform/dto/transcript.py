"""What the transcript reader returns for one tool call and for one compaction summary."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CallDetail:
    """What one tool call said when asked for: its tool, the shell command (None for a call that is not a shell
    one), its input as indented JSON, an excerpt of its result (None without one) and whether any of the three
    was cut."""

    tool: str
    text: str | None
    input: str
    result: str | None
    truncated: bool


@dataclass(frozen=True)
class SummarySpan:
    """Where one compaction summary row sits in its transcript file: the id of the boundary row it follows and
    the byte range of its line, with the summary's size in characters. Never the text."""

    link: str
    chars: int
    start: int
    end: int
