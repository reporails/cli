"""One session followed as it grows: new records are read from where the last read stopped."""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path

from reporails_cli.core.discovery.plugin_roots import installed_plugin_roots
from reporails_cli.core.discovery.project_root import resolve_project_root
from reporails_cli.core.eventbus.transcript import (
    call_detail,
    compact_summaries,
    compact_summary_sizes,
    first_prompt_text,
    hook_output_text,
    last_write,
    prompt_text,
    read_transcript,
    subagent_brief,
    subagent_system,
)
from reporails_cli.core.pipeline.expected_loads import AGENT
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.config.claude_settings import (
    claude_settings_files,
    leaving_out_unreadable_cache,
    mcp_declarations,
    mcp_turned_off,
)
from reporails_cli.core.platform.contract.errors import InstalledPluginsUnreadableError
from reporails_cli.core.platform.dto.events import CallDetail, EventRecord, TranscriptCursor
from reporails_cli.core.platform.dto.xray import (
    AdapterVocabulary,
    Graph,
    SessionPick,
    XrayCheck,
    XrayGaps,
    XraySessionInfo,
    XrayVerdict,
    XrayView,
    XrayWindow,
)
from reporails_cli.core.platform.dto.xray_build import Frame, SourceTable
from reporails_cli.core.platform.dto.xray_sources import ArtifactFile, FindingTally, XrayPeek
from reporails_cli.core.xray.artifacts import (
    advertised_files,
    agent_file_tokens,
    artifact_files,
    build_artifacts,
    is_actionable,
    peek_text,
    runnable_paths,
    unlisted_loads,
)
from reporails_cli.core.xray.cost import load_price_list
from reporails_cli.core.xray.derive import epoch, latest_model, real_path, replies_of, window_of
from reporails_cli.core.xray.facts import build_facts
from reporails_cli.core.xray.funnel import build_funnel
from reporails_cli.core.xray.graph.agents import main_records
from reporails_cli.core.xray.graph.build import build_graph
from reporails_cli.core.xray.graph.shapes import first_launch, first_requests
from reporails_cli.core.xray.graph.sources import build_sources, ran_sources
from reporails_cli.core.xray.vocabulary import vocabulary_for

_CACHE_MAY_DIFFER = (
    "which AGENTS.md files and plugins Claude Code loads may differ from what is shown, since the cache is left out"
)
_NO_WINDOW = "context window"

# A session whose transcript was written this many seconds ago or less is taken to be still going.
LIVE_WINDOW_S = 300.0

# The most characters of one hook firing's output the page is sent.
HOOK_OUTPUT_CHARS = 20_000


class _FileReads:
    """Where the reads of one session's transcript files stopped: the cursor of the record read and, per file (a
    subagent id, None for the main one), the byte offset scanned for compaction summaries and the sizes in
    characters found so far."""

    def __init__(self) -> None:
        self._cursor = TranscriptCursor()
        self._found: dict[str | None, tuple[int, list[int]]] = {}

    def records(self, file: Path) -> list[EventRecord]:
        """The records the transcript gained since the last read."""
        records, self._cursor = read_transcript(AGENT, file, self._cursor)
        return records

    def sizes(self, file: Path, owner: str | None) -> tuple[int, ...]:
        """The sizes of every summary of the file, reading it from where the last read stopped."""
        offset, found = self._found.get(owner, (0, []))
        more, offset = compact_summary_sizes(AGENT, file, owner, offset)
        found = [*found, *more]
        self._found[owner] = (offset, found)
        return tuple(found)


class XraySession:
    """The records of one session of a project and the view built from them."""

    def __init__(self, project_root: Path, session_file: Path) -> None:
        self._root = project_root
        self._file = session_file
        self._transcript: list[EventRecord] = []
        self._reads = _FileReads()
        self._files: tuple[ArtifactFile, ...] | None = None
        self._shown: dict[str, ArtifactFile] | None = None
        self._problems: tuple[str, ...] = ()
        self._settings: tuple[Path, ...] = ()
        self._plugins: list[tuple[str, Path]] = []
        self._findings: dict[str, FindingTally] = {}
        self._check = XrayCheck("running", None)
        self.version = 0

    def refresh(self) -> bool:
        """Read what the transcript gained since the last read; True when anything new arrived."""
        records = self._reads.records(self._file)
        if not records:
            return False
        self._transcript.extend(records)
        self._files = None
        self._shown = None
        self.version += 1
        return True

    def _listing(self) -> tuple[ArtifactFile, ...]:
        """The files the page lists; with the installed plugins' record unreadable, none of their files, and with
        the server-managed settings cache unreadable, the files as if it were absent. Every problem is kept for
        the refusals."""
        if self._files is None:
            problems: list[str] = []
            with leaving_out_unreadable_cache() as cache_problems:
                try:
                    plugins = installed_plugin_roots(resolve_project_root(self._root))
                except InstalledPluginsUnreadableError as exc:
                    plugins = []
                    problems.append(str(exc))
                self._plugins = plugins
                self._files = artifact_files(self._root, plugins)
                self._settings = claude_settings_files(self._root)
            problems.extend(f"{problem}; {_CACHE_MAY_DIFFER}" for problem in dict.fromkeys(cache_problems))
            self._problems = tuple(problems)
        return self._files

    def _shown_as(self, path: str) -> ArtifactFile | None:
        """The listed file the page shows as `path`, else the instruction or memory file the transcript recorded as
        loaded that the listing leaves out and the page shows as `path`; None when the page shows none. The shown
        names are worked out once per listing and kept until the transcript grows."""
        if self._shown is None:
            listing = self._listing()
            known = {real_path(item.path, self._root) for item in listing}
            loads = unlisted_loads(self._transcript, known, self._root)
            self._shown = {}
            for item in (*listing, *loads):
                self._shown.setdefault(relative_wire_path(item.path, self._root), item)
        return self._shown.get(path)

    def acts_on(self, path: str) -> bool:
        """True when the page lists `path` (project-relative), or the session recorded it as loaded, as a file it may
        check or fix."""
        item = self._shown_as(path)
        return item is not None and is_actionable(item, self._root)

    def peek(self, path: str) -> XrayPeek | None:
        """The text of the file shown as `path`, whether it was cut and its frontmatter split from its body; None
        unless the page lists it as an instruction, memory, skill or agent file that exists, or the session
        recorded it as loaded. The text is not kept."""
        item = self._shown_as(path)
        return None if item is None or item.kind == "hook" else peek_text(item, self._root)

    def brief(self, subagent_id: str) -> str | None:
        """The brief of a subagent the records name; None for any other id. Raises `PayloadRefused` when the
        subagent file does not open as the adapter is pinned to. The text is not kept."""
        if not any(record.subagent_id == subagent_id for record in self._transcript):
            return None
        return subagent_brief(AGENT, self._file, subagent_id)

    def system_prompt(self, agent_type: str) -> str | None:
        """The system prompt the first launch of an agent type that recorded a request was sent with; None when the
        session launched no such type or none of its launches recorded one. Raises `PayloadRefused` when the
        subagent file does not record it as the adapter is pinned to. The text is not kept.

        The empty type is the main agent: the system prompt of the last request the main transcript recorded, None
        when it recorded none."""
        if not agent_type:
            return subagent_system(AGENT, self._file, None)
        launched = {
            record.subagent_id
            for record in self._transcript
            if record.event == "subagent_run" and record.subagent_type == agent_type and record.subagent_id
        }
        chosen = first_launch(launched, first_requests(self._transcript))
        return None if chosen is None else subagent_system(AGENT, self._file, chosen)

    def prompt(self, prompt_id: str) -> str | None:
        """The text of a typed prompt the records name; None for any other id. Raises `PayloadRefused` when the
        row is not the shape the adapter is pinned to. The text is not kept."""
        if not any(
            record.subagent_id is None and record.prompt is not None and record.prompt.id == prompt_id
            for record in self._transcript
        ):
            return None
        return prompt_text(AGENT, self._file, prompt_id)

    def summary(self, summary_id: str) -> str | None:
        """The compaction summary a compaction record names by `<subagent id>:<index>` (the main session's subagent
        id is empty); None for any other id. Raises `PayloadRefused` when the agent is unknown. The text is not
        kept."""
        node, _, position = summary_id.rpartition(":")
        if not (position.isascii() and position.isdigit()):
            return None
        owner = node or None
        if not any(r.event == "post_compact" and r.subagent_id == owner for r in self._transcript):
            return None
        found = compact_summaries(AGENT, self._file, owner)
        return found[int(position)] if int(position) < len(found) else None

    def hook_output(self, row_id: str) -> tuple[str, bool] | None:
        """The text one hook firing the records name left in the transcript, cut at `HOOK_OUTPUT_CHARS`, and whether
        it was cut; None for any other id. Raises `PayloadRefused` when the row is not the shape the adapter is pinned
        to. The text is not kept."""
        named = next(
            (record for record in self._transcript if record.hook is not None and record.hook.id == row_id), None
        )
        if named is None:
            return None
        text = hook_output_text(AGENT, self._file, named.subagent_id, row_id)
        return None if text is None else (text[:HOOK_OUTPUT_CHARS], len(text) > HOOK_OUTPUT_CHARS)

    def first_prompt(self) -> str | None:
        """The text of the first typed prompt of the session; None when it has none. The text is not kept."""
        return first_prompt_text(AGENT, self._file)

    def call(self, use_id: str) -> CallDetail | None:
        """What a call the records name said: its tool, its shell command, its input and an excerpt of its
        result; None for any other id. Raises `PayloadRefused` when the call is not the shape the adapter is
        pinned to. The text is not kept."""
        named = next(
            (
                record
                for record in self._transcript
                if record.event == "tool_call" and record.tool is not None and record.tool.use_id == use_id
            ),
            None,
        )
        if named is None or named.tool is None:
            return None
        return call_detail(
            AGENT,
            self._file,
            named.subagent_id,
            use_id,
            named.tool.name or "tool",
            shell=named.tool.category == "run",
        )

    def view(self, findings: Mapping[str, FindingTally], check: XrayCheck, picked: SessionPick) -> XrayView:
        """The view of the records read so far; `findings` maps a file path to its finding tally and `check` is
        the state of the launch check; `picked` is how the session was chosen."""
        if dict(findings) != self._findings or check != self._check:
            self._findings = dict(findings)
            self._check = check
            self.version += 1
        files = self._listing()
        records = [record for record in self._transcript if record.event != "refusal"]
        frame = self._frame(files, records)
        vocabulary = vocabulary_for(AGENT, [item.label for item in files if item.kind == "agent"])
        artifacts = build_artifacts(files, self._findings, self._root, advertised=advertised_files(files, records))
        table = build_sources(artifacts, records, frame)
        prices = load_price_list()
        graph = build_graph(records, frame, table, vocabulary, prices)
        window = window_of(replies_of(main_records(records)))
        return XrayView(
            version=self.version,
            info=self._info(records, picked),
            model=latest_model(records),
            window=window,
            adapter=vocabulary,
            price_list=prices.info,
            nodes=graph.nodes,
            edges=graph.edges,
            sources=graph.sources,
            stations=graph.stations,
            tracks=graph.tracks,
            builtin=graph.builtin,
            session_cost=graph.session_cost,
            gaps=self._gaps(window),
            verdict=self._verdict(table, graph, records, vocabulary),
        )

    def _frame(self, files: tuple[ArtifactFile, ...], records: list[EventRecord]) -> Frame:
        """The clock zero, project root, finding tallies and runnable paths the derivations read."""
        timed = _timed(records)
        written = last_write(self._file)
        live = written is not None and time.time() - written <= LIVE_WINDOW_S
        return Frame(
            timed[0][0] if timed else 0.0,
            self._root,
            self._findings,
            runnable_paths(files),
            agent_file_tokens(files, self._root),
            live,
            mcp_declarations(self._root, self._plugins),
            mcp_turned_off(self._root),
            self._settings,
            self._summary_chars(records),
        )

    def _summary_chars(self, records: list[EventRecord]) -> dict[str, tuple[int, ...]]:
        """The size in characters of each compaction summary of every transcript file that records a compaction,
        by subagent id (empty for the main session); each file is read from where the last read stopped. The
        texts are not kept."""
        owners = {record.subagent_id for record in records if record.event == "post_compact"}
        sizes: dict[str, tuple[int, ...]] = {}
        for owner in owners:
            sizes[owner or ""] = self._reads.sizes(self._file, owner)
        return sizes

    def _verdict(
        self, table: SourceTable, graph: Graph, records: list[EventRecord], vocabulary: AdapterVocabulary
    ) -> XrayVerdict:
        """The funnel and headline facts over the sources and the graph, with the state of the launch check."""
        kinds = [item.key for item in vocabulary.source_kinds]
        funnel = build_funnel(table, graph.sources, kinds, ran_sources(records, table))
        definitions = frozenset(item.key for item in vocabulary.source_kinds if item.definitions)
        facts = build_facts(table.entries, graph.sources, funnel, kinds, definitions)
        return XrayVerdict(funnel, facts, self._check)

    def _info(self, records: list[EventRecord], picked: SessionPick) -> XraySessionInfo:
        """The session and project names, when the first record was written and how long the records span."""
        timed = _timed(records)
        if not timed:
            return XraySessionInfo(self._file.stem, self._root.name, None, None, picked)
        return XraySessionInfo(self._file.stem, self._root.name, timed[0][1], timed[-1][0] - timed[0][0], picked)

    def _gaps(self, window: XrayWindow | None) -> XrayGaps:
        """The refusals the records and the plugin listing hold, and what the view could not read."""
        refusals = [r.refusal for r in self._transcript if r.event == "refusal" and r.refusal]
        refusals.extend(self._problems)
        return XrayGaps(
            refusals=tuple(dict.fromkeys(refusals)),
            not_known=(_NO_WINDOW,) if window is None else (),
        )


def _timed(records: list[EventRecord]) -> list[tuple[float, str]]:
    """Each timed record's moment in seconds and its written time, earliest first."""
    return sorted((moment, record.time) for record in records if (moment := epoch(record.time)) is not None)
