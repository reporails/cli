"""One session followed as it grows: new records are read from where the last read stopped."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from reporails_cli.core.discovery.plugin_roots import installed_plugin_roots
from reporails_cli.core.discovery.project_root import resolve_project_root
from reporails_cli.core.eventbus.query import read_events
from reporails_cli.core.eventbus.transcript import prompt_text, read_transcript, subagent_brief
from reporails_cli.core.pipeline.expected_loads import AGENT
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.contract.errors import InstalledPluginsUnreadableError
from reporails_cli.core.platform.dto.events import EventRecord, TranscriptCursor
from reporails_cli.core.platform.dto.xray import ArtifactFile, FindingTally, XrayCheck, XraySpan, XrayView
from reporails_cli.core.xray.artifacts import (
    advertised_files,
    agent_run_turns,
    artifact_files,
    build_artifacts,
    context_counts,
    in_context_turns,
    is_actionable,
    merged_turns,
    peek_text,
    run_paths,
    runnable_paths,
)
from reporails_cli.core.xray.derive import (
    Frame,
    build_compactions,
    build_harness,
    build_subagents,
    build_turns,
    epoch,
    latest_model,
    loads_of,
    main_replies,
    peak_context,
    preload_tokens,
    real_path,
    start_loads,
    turn_end_times,
    window_of,
)
from reporails_cli.core.xray.funnel import build_funnel

_NO_WINDOW = "context window"
_NO_BUS = "reads"


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
        self._plugin_problem: str | None = None
        self._findings: dict[str, FindingTally] = {}
        self._check = XrayCheck("running", None)
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

    def _listing(self) -> tuple[ArtifactFile, ...]:
        """The files the page lists; with the installed plugins' record unreadable, none of their files, and the
        problem kept for the refusals."""
        if self._files is None:
            try:
                plugins = installed_plugin_roots(resolve_project_root(self._root))
                self._plugin_problem = None
            except InstalledPluginsUnreadableError as exc:
                plugins = []
                self._plugin_problem = str(exc)
            self._files = artifact_files(self._root, plugins)
        return self._files

    def _listed(self, path: str) -> ArtifactFile | None:
        """The listed file the page shows as `path`, or None when the page lists none."""
        return next((item for item in self._listing() if relative_wire_path(item.path, self._root) == path), None)

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

    def prompt(self, prompt_id: str) -> str | None:
        """The text of a typed prompt the records name; None for any other id. Raises `PayloadRefused` when the
        row is not the shape the adapter is pinned to. The text is not kept."""
        if not any(
            record.subagent_id is None and record.prompt is not None and record.prompt.id == prompt_id
            for record in self._transcript
        ):
            return None
        return prompt_text(AGENT, self._file, prompt_id)

    def view(self, findings: Mapping[str, FindingTally], check: XrayCheck) -> XrayView:
        """The view of the records read so far; `findings` maps a file path to its finding tally and `check` is
        the state of the launch check."""
        if dict(findings) != self._findings or check != self._check:
            self._findings = dict(findings)
            self._check = check
            self.version += 1
        files = self._listing()
        records = [record for record in self._transcript if record.event != "refusal"]
        timed = sorted((moment, record.time) for record in records if (moment := epoch(record.time)) is not None)
        frame = Frame(timed[0][0] if timed else 0.0, self._root, self._findings, runnable_paths(files))
        replies = main_replies(records)
        start = loads_of(start_loads(records, replies), frame)
        turns = build_turns(records, self._bus or None, frame)
        length = timed[-1][0] - timed[0][0] if timed else None
        compactions = build_compactions(records, replies, turn_end_times(records), frame, length)
        harness = build_harness(records, replies)
        subagents = build_subagents(records, turn_end_times(records), frame)
        agent_turns = agent_run_turns(subagents, files, self._root)
        main_context = in_context_turns(start, turns, compactions, self._root)
        in_context = merged_turns(main_context, agent_turns)
        loaded = {real_path(load.path, self._root) for load in loads_of(records, frame)}
        loaded |= run_paths(turns, self._root) | set(agent_turns)
        window = window_of(replies)
        artifacts = build_artifacts(
            files,
            loaded,
            in_context,
            self._findings,
            self._root,
            advertised_files(files, records),
            context_counts(main_context, subagents, files, self._root),
        )
        return XrayView(
            version=self.version,
            session=self._file.stem,
            project=self._root.name,
            span=XraySpan(timed[0][1], length) if timed else XraySpan(None, None),
            first_context=replies.points[0][1] if replies.points else None,
            peak=peak_context(replies, compactions),
            preload_tokens_est=preload_tokens(harness, start),
            start=start,
            turns=turns,
            compactions=compactions,
            subagents=subagents,
            artifacts=artifacts,
            refusals=tuple(
                dict.fromkeys(
                    [r.refusal for r in self._transcript if r.event == "refusal" and r.refusal]
                    + ([self._plugin_problem] if self._plugin_problem else [])
                )
            ),
            not_known=(*((_NO_WINDOW,) if window is None else ()), *(() if self._bus else (_NO_BUS,))),
            harness=harness,
            model=latest_model(records),
            window=window,
            funnel=build_funnel(artifacts, turns, subagents),
            check=self._check,
        )
