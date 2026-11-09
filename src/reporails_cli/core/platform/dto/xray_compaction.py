"""What a compaction did to the instruction files an agent had loaded before it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

CompactionTrigger = Literal["manual", "auto"]
# What a compaction did to an instruction file loaded before it: its read result is still in the first request after
# it, the file loaded again, it is gone, no request has been sent since the compaction to say, or the transcript cannot
# tell.
FileState = Literal["kept", "reloaded", "dropped", "pending", "unknown"]
# The states in which a file stays in the context after a compaction: every state but dropped. A file the rows cannot
# settle yet, or at all, stays held.
HELD_FILE_STATES: frozenset[FileState] = frozenset({"kept", "reloaded", "pending", "unknown"})


@dataclass(frozen=True)
class XrayFileState:
    """One instruction file loaded before a compaction and what the compaction did to it."""

    source: str
    state: FileState

    def to_json(self) -> JsonObject:
        """The file state as a JSON object."""
        return {"source": self.source, "state": self.state}


@dataclass(frozen=True)
class XrayCompaction:
    """One compaction of a node's context: when, what started it, the context before and after and each instruction
    file loaded before it with its state after it."""

    t: float
    trigger: CompactionTrigger | None
    before: int | None
    after: int | None
    files: tuple[XrayFileState, ...]
    # The key the summary route takes and the summary's size in tokens; None when the transcript holds no summary.
    summary_id: str | None = None
    summary_tokens: int | None = None

    def to_json(self) -> JsonObject:
        """The compaction as a JSON object."""
        files: list[JsonValue] = [item.to_json() for item in self.files]
        return {
            "t": self.t,
            "trigger": self.trigger,
            "before": self.before,
            "after": self.after,
            "files": files,
            "summary_id": self.summary_id,
            "summary_tokens": self.summary_tokens,
        }
