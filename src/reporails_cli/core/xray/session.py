"""One session followed as it grows: new records are read from where the last read stopped."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path

from reporails_cli.core.discovery.plugin_roots import installed_plugin_roots
from reporails_cli.core.discovery.project_root import resolve_project_root
from reporails_cli.core.eventbus.context_text import context_text
from reporails_cli.core.eventbus.transcript import (
    call_detail,
    compact_summary,
    first_prompt_text,
    hook_output_text,
    last_write,
    prompt_text,
    read_transcript,
    recent_sessions,
    scan_compact_summaries,
    subagent_brief,
    subagent_output,
    workflow_runs,
)
from reporails_cli.core.pipeline.expected_loads import AGENT
from reporails_cli.core.platform.config.bootstrap import (
    claude_plugins_dir,
    get_global_config_path,
    get_local_config_path,
    get_project_config_path,
)
from reporails_cli.core.platform.config.claude_settings import (
    claude_settings_files,
    leaving_out_unreadable_cache,
    mcp_declarations,
    mcp_turned_off,
)
from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.contract.errors import InstalledPluginsUnreadableError
from reporails_cli.core.platform.dto.events import EventRecord, TranscriptCursor
from reporails_cli.core.platform.dto.transcript import CallDetail, SummarySpan
from reporails_cli.core.platform.dto.workflows import WorkflowRefused, WorkflowRun
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
from reporails_cli.core.platform.dto.xray_build import Frame, SourceTable, WorkflowReading
from reporails_cli.core.platform.dto.xray_graph import OutputSource
from reporails_cli.core.platform.dto.xray_own import ContextKey, XrayOwnContext, XrayOwnItem
from reporails_cli.core.platform.dto.xray_sources import (
    ArtifactFile,
    EarlierFiring,
    EarlierFirings,
    FindingTally,
    XrayPeek,
)
from reporails_cli.core.platform.utils.utils import relative_wire_path
from reporails_cli.core.xray.artifacts import (
    advertised_files,
    agent_file_sizes,
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
from reporails_cli.core.xray.graph.agents import MAIN_ID, main_records
from reporails_cli.core.xray.graph.build import build_graph
from reporails_cli.core.xray.graph.hook_sources import with_earlier_firings
from reporails_cli.core.xray.graph.sources import build_sources, ran_sources
from reporails_cli.core.xray.vocabulary import vocabulary_for

logger = logging.getLogger(__name__)

_CACHE_MAY_DIFFER = (
    "which AGENTS.md files and plugins Claude Code loads may differ from what is shown, since the cache is left out"
)
_NO_WINDOW = "context window"

# A session whose transcript was written this many seconds ago or less is taken to be still going.
LIVE_WINDOW_S = 300.0

# A listing is walked again after this many seconds even when its stamp holds, so a file added deeper in the tree
# than the stamp looks shows within that time.
LISTING_MAX_AGE_S = 30.0

# The most characters of one hook firing's output the page is sent.
HOOK_OUTPUT_CHARS = 20_000

# The project's session list is looked at again for sessions to read after this many seconds.
EARLIER_MAX_AGE_S = 30.0


def _stat_of(path: Path) -> tuple[int, int] | None:
    """The change time and size of `path`; None when it does not exist or cannot be read (a best-effort stamp: a
    missing file is the stamp's own reading, and an unreadable one reads the same until it changes)."""
    try:
        found = path.stat()
    except OSError:
        return None
    return found.st_mtime_ns, found.st_size


def _listing_stamp(root: Path) -> tuple[tuple[int, int] | None, ...]:
    """What the listing reads, cheaply: the change time of the three config files, the settings files, the plugin
    record, the project folder and each `.claude` folder's own listing folders, in the project and in the home."""
    claude = (root / ".claude", Path.home() / ".claude")
    paths = [
        get_project_config_path(root),
        get_local_config_path(root),
        get_global_config_path(),
        claude_plugins_dir() / "installed_plugins.json",
        *claude_settings_files(root),
        root,
        *(folder for base in claude for folder in (base, base / "rules", base / "skills", base / "agents")),
    ]
    return tuple(_stat_of(path) for path in paths)


class _FileReads:
    """Where the reads of one session's transcript files stopped: the cursor of the record read and, per file (a
    subagent id, None for the main one), the byte offset scanned for compaction summaries and the summaries
    found so far by the id of the boundary row each follows, and the source each subagent's output text is read from
    as the last view sized it, and each agent's own context as the last view held it, and the hook firings of the
    project's other sessions."""

    def __init__(self, project_root: Path, session_file: Path) -> None:
        self.earlier = _EarlierSessions(project_root, session_file)
        self.outputs: dict[str, OutputSource] = {}
        self.own: dict[str, XrayOwnContext] = {}
        self._cursor = TranscriptCursor()
        self._found: dict[str | None, tuple[int, dict[str, SummarySpan]]] = {}

    def records(self, file: Path) -> list[EventRecord]:
        """The records the transcript gained since the last read."""
        records, self._cursor = read_transcript(AGENT, file, self._cursor)
        return records

    def summaries(self, file: Path, owner: str | None) -> Mapping[str, SummarySpan]:
        """Every summary of the file by the id of the boundary row it follows, reading it from where the last read
        stopped."""
        offset, found = self._found.get(owner, (0, {}))
        more, offset = scan_compact_summaries(AGENT, file, owner, offset)
        found = {**found, **{span.link: span for span in more}}
        self._found[owner] = (offset, found)
        return found


def _in_background(job: Callable[[], None]) -> None:
    """Run `job` on a thread of its own, off the request that asked for it."""
    threading.Thread(target=job, daemon=True).start()


def _latest_firings(session_file: Path) -> tuple[EarlierFiring, ...]:
    """The latest firing of each hook name and command a session's transcript records, read with the one transcript
    reader."""
    records, _ = read_transcript(AGENT, session_file, TranscriptCursor())
    latest: dict[tuple[str, str, str | None], EarlierFiring] = {}
    for record in records:
        moment = epoch(record.time)
        if record.hook is None or moment is None:
            continue
        key = (record.hook.event, record.hook.label, record.hook.command)
        held = latest.get(key)
        if held is None or moment >= held.moment:
            latest[key] = EarlierFiring(session_file.stem, record.time, moment, record.hook)
    return tuple(latest.values())


class _EarlierSessions:
    """The hook firings of the project's other recent sessions, the ones the session switcher lists. Reading them is
    slow, so a view only asks for what has been read so far: the first request starts one background read of every
    other session, a later request after `EARLIER_MAX_AGE_S` looks at the session list again and reads the sessions it
    gained, and a session already read is not read again."""

    def __init__(self, project_root: Path, session_file: Path) -> None:
        self._root = project_root
        self._own = session_file.stem
        self._lock = threading.Lock()
        self._read: dict[str, tuple[EarlierFiring, ...]] = {}
        self._held = EarlierFirings(checking=True)
        self._running = False
        self._checked: float | None = None

    def request(self) -> None:
        """Start a background read when none is going and none has run for `EARLIER_MAX_AGE_S`."""
        with self._lock:
            due = not self._running and (self._checked is None or time.monotonic() - self._checked >= EARLIER_MAX_AGE_S)
            self._running = self._running or due
        if due:
            _in_background(self._read_gained)

    def found(self) -> EarlierFirings:
        """What has been read so far, and whether the reading goes on."""
        with self._lock:
            return self._held

    def _publish(self, *, checking: bool) -> None:
        firings = tuple(item for found in self._read.values() for item in found)
        with self._lock:
            self._held = EarlierFirings(checking, firings)

    def _read_gained(self) -> None:
        """Read each listed session not read yet and forget the ones the list lost; a session folder that cannot be
        read leaves what was read."""
        try:
            listed = [path for path in recent_sessions(self._root) if path.stem != self._own]
            names = {path.stem for path in listed}
            fresh = [path for path in listed if path.stem not in self._read]
            if fresh:
                self._publish(checking=True)
            for path in fresh:
                self._read[path.stem] = _latest_firings(path)
            self._read = {name: found for name, found in self._read.items() if name in names}
        except OSError:
            logger.warning("the earlier sessions of %s could not all be read", self._root, exc_info=True)
        finally:
            with self._lock:
                self._running = False
                self._checked = time.monotonic()
            self._publish(checking=False)


class XraySession:
    """The records of one session of a project and the view built from them."""

    def __init__(self, project_root: Path, session_file: Path) -> None:
        self._root = project_root
        self._file = session_file
        self._transcript: list[EventRecord] = []
        self._reads = _FileReads(project_root, session_file)
        self._content: XrayView | None = None
        self._shown: dict[str, ArtifactFile] | None = None
        self._walked: (
            tuple[tuple[tuple[int, int] | None, ...], float, tuple[ArtifactFile, ...], tuple[str, ...]] | None
        ) = None
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
        self._shown = None
        return True

    def _listing(self, run: RunContext) -> tuple[ArtifactFile, ...]:
        """The files the page lists; with the installed plugins' record unreadable, none of their files, and with
        the server-managed settings cache unreadable, the files as if it were absent. Every problem is kept for
        the refusals. The files are walked again only when the config files, the settings files or the folders the
        stamp reads changed, or after `LISTING_MAX_AGE_S`."""
        with leaving_out_unreadable_cache():
            stamp = _listing_stamp(self._root)
        now = time.monotonic()
        if self._walked is not None and self._walked[0] == stamp and now - self._walked[1] < LISTING_MAX_AGE_S:
            return self._walked[2]
        problems: list[str] = []
        with leaving_out_unreadable_cache() as cache_problems:
            try:
                plugins = installed_plugin_roots(resolve_project_root(self._root))
            except InstalledPluginsUnreadableError as exc:
                plugins = []
                problems.append(str(exc))
            self._plugins = plugins
            files = artifact_files(run, self._root, plugins)
            self._settings = claude_settings_files(self._root)
        problems.extend(f"{problem}; {_CACHE_MAY_DIFFER}" for problem in dict.fromkeys(cache_problems))
        self._walked = (stamp, now, files, tuple(problems))
        return files

    def _shown_as(self, run: RunContext, path: str) -> ArtifactFile | None:
        """The listed file the page shows as `path`, else the instruction or memory file the transcript recorded as
        loaded that the listing leaves out and the page shows as `path`; None when the page shows none. The shown
        names are worked out once per listing and kept until the transcript grows."""
        if self._shown is None:
            listing = self._listing(run)
            known = {real_path(item.path, self._root) for item in listing}
            loads = unlisted_loads(self._transcript, known, self._root)
            self._shown = {}
            for item in (*listing, *loads):
                self._shown.setdefault(relative_wire_path(item.path, self._root), item)
        return self._shown.get(path)

    def acts_on(self, run: RunContext, path: str) -> bool:
        """True when the page lists `path` (project-relative), or the session recorded it as loaded, as a file it may
        check or fix."""
        item = self._shown_as(run, path)
        return item is not None and is_actionable(item, self._root)

    def peek(self, run: RunContext, path: str) -> XrayPeek | None:
        """The text of the file shown as `path`, whether it was cut and its frontmatter split from its body; None
        unless the page lists it as an instruction, memory, skill or agent file that exists, or the session
        recorded it as loaded. The text is not kept."""
        item = self._shown_as(run, path)
        return None if item is None or item.kind == "hook" else peek_text(item, self._root)

    def brief(self, subagent_id: str) -> str | None:
        """The brief of a subagent the records name; None for any other id. Raises `PayloadRefused` when the
        subagent file does not open as the adapter is pinned to. The text is not kept."""
        if not any(record.subagent_id == subagent_id for record in self._transcript):
            return None
        return subagent_brief(AGENT, self._file, subagent_id)

    def output(self, subagent_id: str) -> str | None:
        """The text a subagent handed back, read from the source the last view sized its hand-back from; None for
        any other id and for a subagent the view found no output text for. For `reply` a row the adapter refuses
        is skipped (the last readable reply counts); for `handback` and `result` an unpinned row raises
        `PayloadRefused`. The text is not kept."""
        source = self._reads.outputs.get(subagent_id)
        if source is None:
            return None
        run = next((r for r in self._transcript if r.event == "subagent_run" and r.subagent_id == subagent_id), None)
        use_id = None if run is None or run.launch is None else run.launch.tool_use_id
        return subagent_output(AGENT, self._file, subagent_id, source, use_id)

    def workflows(self) -> tuple[WorkflowRun | WorkflowRefused, ...]:
        """The session's workflow runs; a run whose record file is not the shape the adapter is pinned to is a
        refusal naming what was wrong, and the other runs are still read."""
        return workflow_runs(AGENT, self._file)

    def context_text(self, agent: str, item: ContextKey) -> list[str] | None:
        """The texts of one item of an agent's own context, read from the request the last view sized the item from:
        `agent` is a node id, empty for the main agent. None for an agent or item the last view holds no recorded
        request for. Raises `PayloadRefused` when a row read is not the shape the adapter is pinned to. The text is
        not kept."""
        own = self._reads.own.get(agent or MAIN_ID)
        if own is None or own.request_id is None or self.own_item(agent, item) is None:
            return None
        return context_text(AGENT, self._file, agent or None, own.request_id, item)

    def own_item(self, agent: str, item: ContextKey) -> XrayOwnItem | None:
        """The item of an agent's own context the last view built; None for an agent or item it holds none of."""
        own = self._reads.own.get(agent or MAIN_ID)
        return None if own is None else next((row for row in own.rows if row.key == item), None)

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
        """The compaction summary a compaction record names by `<subagent id>:<boundary row id>` (the main
        session's subagent id is empty); None for any other id. Reads only the summary's line. Raises
        `PayloadRefused` when the agent is unknown. The text is not kept."""
        node, _, link = summary_id.rpartition(":")
        owner = node or None
        if not any(
            r.event == "post_compact" and r.subagent_id == owner and r.boundary and r.boundary.id == link
            for r in self._transcript
        ):
            return None
        span = self._reads.summaries(self._file, owner).get(link)
        return None if span is None else compact_summary(AGENT, self._file, owner, span)

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

    def view(
        self, run: RunContext, findings: Mapping[str, FindingTally], check: XrayCheck, picked: SessionPick
    ) -> XrayView:
        """The view of the records read so far, listing the files under the config `run` read; `findings` maps a
        file path to its finding tally and `check` is the state of the launch check; `picked` is how the session
        was chosen. The version rises whenever the view built differs from the one built before it."""
        self._findings = dict(findings)
        self._check = check
        self._shown = None
        files = self._listing(run)
        records = [record for record in self._transcript if record.event != "refusal"]
        frame = self._frame(files, records)
        vocabulary = vocabulary_for(AGENT, [item.label for item in files if item.kind == "agent"])
        artifacts = build_artifacts(run, files, self._findings, self._root, advertised=advertised_files(files, records))
        table = build_sources(run, artifacts, records, frame)
        self._reads.earlier.request()
        table = replace(table, entries=with_earlier_firings(table.entries, self._reads.earlier.found()))
        prices = load_price_list()
        graph = build_graph(records, frame, table, vocabulary, prices, workflows=WorkflowReading(self.workflows()))
        self._reads.outputs = {
            node.id: node.detail.back.source for node in graph.nodes if node.detail.back.source is not None
        }
        self._reads.own = {
            node.id: node.detail.in_context.own for node in graph.nodes if node.detail.in_context is not None
        }
        window = window_of(replies_of(main_records(records)))
        content = XrayView(
            version=0,
            info=self._info(records, picked),
            model=latest_model(records),
            window=window,
            adapter=vocabulary,
            price_list=prices.info,
            nodes=graph.nodes,
            workflows=graph.workflows,
            edges=graph.edges,
            sources=graph.sources,
            stations=graph.stations,
            tracks=graph.tracks,
            session_cost=graph.session_cost,
            gaps=self._gaps(window),
            verdict=self._verdict(table, graph, records, vocabulary),
        )
        if content != self._content:
            self.version += 1
        self._content = content
        return replace(content, version=self.version)

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
            agent_file_sizes(files, self._root),
            live,
            mcp_declarations(self._root, self._plugins),
            mcp_turned_off(self._root),
            self._settings,
            self._summaries(records),
        )

    def _summaries(self, records: list[EventRecord]) -> dict[str, Mapping[str, SummarySpan]]:
        """The compaction summaries of every transcript file that records a compaction, by subagent id (empty for
        the main session); each file is read from where the last read stopped. The texts are not kept."""
        owners = {record.subagent_id for record in records if record.event == "post_compact"}
        return {owner or "": self._reads.summaries(self._file, owner) for owner in owners}

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
        refusals.extend(() if self._walked is None else self._walked[3])
        return XrayGaps(
            refusals=tuple(dict.fromkeys(refusals)),
            not_known=(_NO_WINDOW,) if window is None else (),
        )


def _timed(records: list[EventRecord]) -> list[tuple[float, str]]:
    """Each timed record's moment in seconds and its written time, earliest first."""
    return sorted((moment, record.time) for record in records if (moment := epoch(record.time)) is not None)
