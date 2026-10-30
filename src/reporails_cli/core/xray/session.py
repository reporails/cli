"""One session followed as it grows: new records are read from where the last read stopped."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from reporails_cli.core.eventbus.query import read_events
from reporails_cli.core.eventbus.transcript import read_transcript
from reporails_cli.core.pipeline.expected_loads import AGENT
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.dto.events import EventRecord, TranscriptCursor
from reporails_cli.core.platform.dto.xray import XrayView
from reporails_cli.core.xray.artifacts import (
    ArtifactFile,
    artifact_files,
    build_artifacts,
    in_context_turns,
    is_actionable,
)
from reporails_cli.core.xray.derive import (
    Frame,
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

    def acts_on(self, path: str) -> bool:
        """True when the page lists `path` (project-relative) as a file it may check or fix."""
        if self._files is None:
            self._files = artifact_files(self._root)
        return any(
            relative_wire_path(item.path, self._root) == path and is_actionable(item, self._root)
            for item in self._files
        )

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
            started_at=timed[0][1] if timed else None,
            length_s=timed[-1][0] - timed[0][0] if timed else None,
            first_context=replies.points[0][1] if replies.points else None,
            start=start,
            turns=turns,
            subagents=build_subagents(records, turn_end_times(records), frame),
            artifacts=build_artifacts(
                self._files, loaded, in_context_turns(start, turns, self._root), self._findings, self._root
            ),
            refusals=tuple(dict.fromkeys(r.refusal for r in self._transcript if r.event == "refusal" and r.refusal)),
            not_known=_NOT_KNOWN if self._bus else (*_NOT_KNOWN, _NO_BUS),
        )
