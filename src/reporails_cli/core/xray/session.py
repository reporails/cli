"""One session followed as it grows: new records are read from where the last read stopped."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from reporails_cli.core.eventbus.query import read_events
from reporails_cli.core.eventbus.transcript import read_transcript, subagent_brief
from reporails_cli.core.pipeline.expected_loads import AGENT
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.dto.events import EventRecord, TranscriptCursor
from reporails_cli.core.platform.dto.xray import XraySpan, XrayView
from reporails_cli.core.xray.artifacts import (
    ArtifactFile,
    artifact_files,
    build_artifacts,
    in_context_turns,
    is_actionable,
    peek_text,
)
from reporails_cli.core.xray.derive import (
    Frame,
    build_harness,
    build_subagents,
    build_turns,
    epoch,
    loads_of,
    main_replies,
    real_path,
    start_loads,
    turn_end_times,
)

_NOT_KNOWN = ("stop hook blocks", "hook notes", "prompts", "context window")
_NO_BUS = "reads and compactions"


class XraySession:
    """The records of one session of a project and the view built from them."""

    def __init__(self, project_root: Path, session_file: Path) -> None:
        self._root = project_root
        self._file = session_file
        self._cursor = TranscriptCursor()
        self._offset = 0
        self._transcript: list[EventRecord] = []
        self._bus: list[EventRecord] = []
        self._files: tuple[ArtifactFile, ...] | None = None
        self._findings: dict[str, int] = {}
        self.version = 0

    def refresh(self) -> bool:
        """Read what the transcript and the event log gained since the last read; True when anything new arrived."""
        records, self._cursor = read_transcript(AGENT, self._file, self._cursor)
        events, self._offset = read_events(self._file.stem, self._offset)
        if not (records or events):
            return False
        self._transcript.extend(records)
        self._bus.extend(events)
        self._files = None
        self.version += 1
        return True

    def _listed(self, path: str) -> ArtifactFile | None:
        """The listed file the page shows as `path`, or None when the page lists none."""
        if self._files is None:
            self._files = artifact_files(self._root)
        return next((item for item in self._files if relative_wire_path(item.path, self._root) == path), None)

    def acts_on(self, path: str) -> bool:
        """True when the page lists `path` (project-relative) as a file it may check or fix."""
        item = self._listed(path)
        return item is not None and is_actionable(item, self._root)

    def peek(self, path: str) -> tuple[str, bool] | None:
        """The text of the listed file shown as `path` and whether it was cut; None unless the page lists it
        as an instruction, memory, skill or agent file that exists. The text is not kept."""
        item = self._listed(path)
        return None if item is None or item.kind == "hook" else peek_text(item, self._root)

    def brief(self, subagent_id: str) -> str | None:
        """The brief of a subagent the records name; None for any other id. Raises `PayloadRefused` when the
        subagent file does not open as the adapter is pinned to. The text is not kept."""
        if not any(record.subagent_id == subagent_id for record in self._transcript):
            return None
        return subagent_brief(AGENT, self._file, subagent_id)

    def view(self, findings: Mapping[str, int]) -> XrayView:
        """The view of the records read so far; `findings` maps a file path to its finding count."""
        if dict(findings) != self._findings:
            self._findings = dict(findings)
            self.version += 1
        if self._files is None:
            self._files = artifact_files(self._root)
        records = [record for record in self._transcript if record.event != "refusal"]
        timed = sorted((moment, record.time) for record in records if (moment := epoch(record.time)) is not None)
        frame = Frame(timed[0][0] if timed else 0.0, self._root, self._findings)
        replies = main_replies(records)
        start = loads_of(start_loads(records, replies), frame)
        turns = build_turns(records, self._bus or None, frame)
        loaded = {real_path(load.path, self._root) for load in loads_of(records, frame)}
        return XrayView(
            version=self.version,
            session=self._file.stem,
            project=self._root.name,
            span=XraySpan(timed[0][1], timed[-1][0] - timed[0][0]) if timed else XraySpan(None, None),
            first_context=replies.points[0][1] if replies.points else None,
            start=start,
            turns=turns,
            subagents=build_subagents(records, turn_end_times(records), frame),
            artifacts=build_artifacts(
                self._files, loaded, in_context_turns(start, turns, self._root), self._findings, self._root
            ),
            refusals=tuple(dict.fromkeys(r.refusal for r in self._transcript if r.event == "refusal" and r.refusal)),
            not_known=_NOT_KNOWN if self._bus else (*_NOT_KNOWN, _NO_BUS),
            harness=build_harness(records, replies),
        )
