"""What a compaction did to the instruction files an agent had loaded before it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

CompactionTrigger = Literal["manual", "auto"]
# What a compaction left of an instruction file loaded before it: the file loaded again after it, the whole file put
# back after the summary, only its name put back, nothing of it but what the summary says, or (while the agent has not
# replied since the compaction) not settled yet.
FileState = Literal["reloaded", "restored", "named", "summarized", "pending"]
# The states in which a file's content is in the context after a compaction. A file not settled yet stays held.
IN_CONTEXT_FILE_STATES: frozenset[FileState] = frozenset({"reloaded", "restored", "pending"})


@dataclass(frozen=True)
class XrayFileState:
    """One instruction file loaded before a compaction and what the compaction did to it."""

    source: str
    state: FileState
    # Whether the file's content is in the context after the compaction: its state is in IN_CONTEXT_FILE_STATES.
    in_context: bool

    def to_json(self) -> JsonObject:
        """The file state as a JSON object."""
        return {"source": self.source, "state": self.state, "in_context": self.in_context}


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
