"""The agent producer: the main agent and every subagent as nodes, with what each was handed, what it handed back and
how it ended."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.dto.events import EventRecord, SubagentMeta, is_note_kind
from reporails_cli.core.platform.dto.xray import (
    AgentOutcome,
    LoadTrigger,
    NodeKind,
    XrayAgentDetail,
    XrayCompaction,
    XrayDown,
    XrayEdge,
    XrayGiven,
    XrayPrompt,
)
from reporails_cli.core.xray.derive import (
    BYTES_PER_TOKEN,
    Frame,
    Replies,
    build_compactions,
    build_harness,
    epoch,
    peak_context,
    replies_of,
    start_loads,
)
from reporails_cli.core.xray.graph.port import (
    Produced,
    ProducedCall,
    ProducedLoad,
    ProducedNode,
    ProducerContext,
    register,
)
from reporails_cli.core.xray.graph.sources import SourceTable, hook_id, mcp_id

# The id of the main agent's node.
MAIN_ID = "main"

# A subagent whose last record is this close to the session's last record is taken to still be running.
RUNNING_WINDOW_S = 120.0


@dataclass(frozen=True)
class _Result:
    """The result of a call: when it came, how big it was and whether it reported an error."""

    t: float
    chars: int | None
    error: bool


@dataclass(frozen=True)
class _Own:
    """What one agent's own records hold."""

    key: str
    records: list[EventRecord]
    replies: Replies
    results: dict[str, _Result]
    calls: tuple[ProducedCall, ...]
    loads: tuple[ProducedLoad, ...]
    compactions: tuple[XrayCompaction, ...]
    times: tuple[float, ...]

    @property
    def start(self) -> float:
        """When the agent's first record came; 0 when none is timed."""
        return self.times[0] if self.times else 0.0

    @property
    def end(self) -> float:
        """When the agent's last record came; 0 when none is timed."""
        return self.times[-1] if self.times else 0.0

    @property
    def handback(self) -> ProducedCall | None:
        """The agent's first call that hands its result back."""
        return next((call for call in self.calls if call.category == "handback"), None)


def _tokens(chars: int | None) -> int | None:
    return None if chars is None else chars // BYTES_PER_TOKEN


def _results(group: Sequence[EventRecord], frame: Frame) -> dict[str, _Result]:
    """The result of each call among `group`, by the call's id."""
    return {
        record.tool.use_id: _Result(frame.at(record) or 0.0, record.tool.chars, record.tool.error is True)
        for record in group
        if record.event == "tool_result" and record.tool is not None and record.tool.use_id is not None
    }


def _calls(
    group: Sequence[EventRecord], frame: Frame, sources: SourceTable, results: dict[str, _Result]
) -> tuple[ProducedCall, ...]:
    """Each tool call among `group` with its result joined by id."""
    found: list[ProducedCall] = []
    for record in group:
        tool = record.tool
        if record.event != "tool_call" or tool is None or tool.use_id is None:
            continue
        category = tool.category or "other"
        path = relative_wire_path(tool.path, frame.root) if tool.path else None
        result = results.get(tool.use_id)
        chars = tool.chars if category == "handback" else None if result is None else result.chars
        found.append(
            ProducedCall(
                t=frame.at(record) or 0.0,
                category=category,
                label=f"{tool.name or 'tool'} · {path}" if path else tool.name or "tool",
                source=sources.for_path(tool.path) if tool.path else None,
                mcp_source=mcp_id(tool.server) if tool.server else None,
                failed=result is not None and result.error,
                use_id=tool.use_id,
                fingerprint=tool.fingerprint,
                back_tokens_est=_tokens(chars),
            )
        )
    return tuple(found)


@dataclass(frozen=True)
class _Reading:
    """What loads are read against: the frame, the sources, the time of the agent's first reply and whether the agent
    is the main one."""

    frame: Frame
    sources: SourceTable
    first: float
    is_main: bool

    def at_start(self, record: EventRecord) -> bool:
        """Whether a record came before the agent's first reply."""
        moment = epoch(record.time)
        return moment is not None and moment < self.first


def _source_load(sid: str | None, t: float | None, reading: _Reading) -> list[ProducedLoad]:
    """A load by the agent's own doing (a run, a read) of the source `sid`; none when `sid` is no source."""
    entry = reading.sources.get(sid) if sid else None
    return [] if entry is None else [ProducedLoad(entry.id, t, entry.tokens_est, "agent", None, True)]


def _harness_loads(record: EventRecord, reading: _Reading) -> list[ProducedLoad]:
    """The MCP servers and the hook a harness record puts into the agent's context."""
    entry = record.harness
    if entry is None:
        return []
    t = reading.frame.at(record)
    if entry.kind == "mcp_instructions":
        trigger: LoadTrigger = "session_start" if reading.is_main else "inherited"
        return [
            ProducedLoad(mcp_id(name), t, chars // BYTES_PER_TOKEN, trigger, None, True) for name, chars in entry.added
        ]
    if is_note_kind(entry.kind) and entry.event is not None:
        return [ProducedLoad(hook_id(entry.label), t, entry.chars // BYTES_PER_TOKEN, "hook", entry.event, True)]
    return []


def _record_loads(record: EventRecord, reading: _Reading) -> list[ProducedLoad]:
    """The sources one record puts into the agent's context."""
    if record.event == "instruction_load":
        return _instruction_load(record, reading)
    if record.event == "harness":
        return _harness_loads(record, reading)
    t = reading.frame.at(record)
    if record.event == "skill_run" and record.skill is not None and not record.skill.forked:
        return _source_load(reading.sources.by_run.get(record.skill.name), t, reading)
    if record.event == "tool_call" and record.tool is not None and record.tool.category == "read" and record.tool.path:
        return _source_load(reading.sources.for_path(record.tool.path), t, reading)
    return []


def _instruction_load(record: EventRecord, reading: _Reading) -> list[ProducedLoad]:
    load = record.load
    if load is None:
        return []
    sid = reading.sources.for_path(load.path)
    entry = reading.sources.get(sid) if sid else None
    if entry is None:
        return []
    t = reading.frame.at(record)
    if load.memory_type == "nested":
        return [ProducedLoad(entry.id, t, entry.tokens_est, "path_match", None, True)]
    early = reading.at_start(record)
    trigger: LoadTrigger = "session_start" if reading.is_main else "inherited" if early else "agent"
    return [ProducedLoad(entry.id, t, entry.tokens_est, trigger, None, not (early and entry.kind == "instructions"))]


def _own(key: str, group: list[EventRecord], frame: Frame, sources: SourceTable) -> _Own:
    replies = replies_of(group)
    results = _results(group, frame)
    reading = _Reading(frame, sources, replies.points[0][0] if replies.points else float("inf"), key == MAIN_ID)
    return _Own(
        key=key,
        records=group,
        replies=replies,
        results=results,
        calls=_calls(group, frame, sources, results),
        loads=tuple(load for record in group for load in _record_loads(record, reading)),
        compactions=build_compactions(group, replies, frame),
        times=tuple(sorted(moment for record in group if (moment := frame.at(record)) is not None)),
    )


def _given(own: _Own, sources: SourceTable) -> tuple[list[XrayGiven], list[XrayGiven]]:
    """What the agent started with besides its task prompt: its harness items, and the instruction files it loaded
    before its first reply."""
    harness = [XrayGiven(item.label, item.tokens_est, None) for item in build_harness(own.records, own.replies) or ()]
    loaded: list[XrayGiven] = []
    for record in start_loads(own.records, own.replies):
        entry = sources.get(sources.for_path(record.load.path) or "") if record.load is not None else None
        if entry is not None:
            loaded.append(XrayGiven(entry.name, entry.tokens_est, entry.id))
    return harness, loaded


def _prompts(own: _Own, frame: Frame) -> tuple[XrayPrompt, ...]:
    typed = [
        XrayPrompt(record.prompt.id, frame.at(record) or 0.0, record.prompt.chars // BYTES_PER_TOKEN)
        for record in own.records
        if record.event == "prompt_submit" and record.prompt is not None
    ]
    return tuple(sorted(typed, key=lambda item: item.t))


def _detail(
    own: _Own, given: Sequence[XrayGiven], handoff: tuple[XrayDown, int | None, AgentOutcome | None], frame: Frame
) -> XrayAgentDetail:
    down, back, outcome = handoff
    series = tuple((moment - frame.t0, context) for moment, context in own.replies.points)
    return XrayAgentDetail(
        context_start=series[0][1] if series else None,
        peak=peak_context(own.replies, own.compactions),
        series=series,
        down=down,
        back_tokens_est=back,
        outcome=outcome,
        given=tuple(given),
        prompts=_prompts(own, frame) if own.key == MAIN_ID else (),
        brief=own.key != MAIN_ID,
    )


def _launch(group: Sequence[EventRecord]) -> SubagentMeta | None:
    run = next((record for record in group if record.event == "subagent_run"), None)
    return None if run is None else run.launch


def _parent_of(key: str, metas: dict[str, SubagentMeta | None]) -> str:
    """The node a subagent hangs under: its launching subagent when the records hold one whose own launchers do not
    lead back to it, else the main agent."""
    meta = metas[key]
    parent = None if meta is None else meta.parent_id
    seen = {key}
    current = parent
    while current is not None and current in metas:
        if current in seen:
            return MAIN_ID
        seen.add(current)
        above = metas[current]
        current = None if above is None else above.parent_id
    return parent if parent is not None and parent in metas else MAIN_ID


def _outcome(meta: SubagentMeta | None, own: _Own, result: _Result | None, running: bool) -> AgentOutcome:
    if own.handback is not None:
        return "returned"
    if meta is not None and meta.stopped:
        return "stopped"
    if result is not None and result.error:
        return "failed"
    if result is not None and not (meta is not None and meta.background):
        return "returned"
    return "running" if running else "no_handback"


def main_records(records: Sequence[EventRecord]) -> list[EventRecord]:
    """The records of the main agent's own file."""
    return [record for record in records if record.subagent_id is None]


class AgentProducer:
    """Makes the main agent's node and one node per subagent run."""

    kind: NodeKind = "agent"

    def produce(self, records: Sequence[EventRecord], frame: Frame, context: ProducerContext) -> Produced:
        """The agent nodes of `records`, the main agent first and the subagents in launch order, and one edge from
        each subagent's parent to it."""
        groups: dict[str, list[EventRecord]] = {MAIN_ID: main_records(records)}
        for record in records:
            if record.subagent_id is not None:
                groups.setdefault(record.subagent_id, []).append(record)
        owns = {key: _own(key, group, frame, context.sources) for key, group in groups.items()}
        times = sorted(moment for record in records if (moment := frame.at(record)) is not None)
        session_end = times[-1] if times else 0.0
        metas = {key: _launch(group) for key, group in groups.items() if key != MAIN_ID}
        order = sorted(metas, key=lambda key: (owns[key].start, key))
        nodes = [self._main(owns[MAIN_ID], frame, context, session_end)]
        edges: list[XrayEdge] = []
        for key in order:
            parent = _parent_of(key, metas)
            node, edge = self._sub(owns[key], owns[parent], metas[key], (frame, context), session_end)
            nodes.append(node)
            edges.append(edge)
        return Produced(tuple(nodes), tuple(edges))

    def _main(self, own: _Own, frame: Frame, context: ProducerContext, session_end: float) -> ProducedNode:
        harness, loaded = _given(own, context.sources)
        given = [*harness, *loaded]
        down = XrayDown(None, sum(item.tokens_est or 0 for item in given))
        detail = _detail(own, given, (down, None, None), frame)
        return ProducedNode(
            id=MAIN_ID,
            kind=self.kind,
            parent=None,
            name=context.vocabulary.root.name,
            type=context.vocabulary.root.type,
            start=0.0,
            end=session_end,
            detail=detail,
            series=detail.series,
            loads=own.loads,
            calls=own.calls,
            compactions=own.compactions,
            activity=own.times,
        )

    def _sub(
        self,
        own: _Own,
        parent: _Own,
        meta: SubagentMeta | None,
        world: tuple[Frame, ProducerContext],
        session_end: float,
    ) -> tuple[ProducedNode, XrayEdge]:
        frame, context = world
        harness, loaded = _given(own, context.sources)
        task = None if meta is None else meta.brief_chars // BYTES_PER_TOKEN
        given = [*([] if task is None else [XrayGiven("task prompt", task, None)]), *loaded, *harness]
        down = XrayDown(task, sum(item.tokens_est or 0 for item in (*loaded, *harness)))
        use_id = None if meta is None else meta.tool_use_id
        result = parent.results.get(use_id) if use_id is not None else None
        launch = next((call for call in parent.calls if call.use_id == use_id), None) if use_id is not None else None
        outcome = _outcome(meta, own, result, own.end >= session_end - RUNNING_WINDOW_S)
        handback = own.handback
        back_t = handback.t if handback is not None else None if result is None else result.t
        back = handback.back_tokens_est if handback is not None else None if result is None else _tokens(result.chars)
        detail = _detail(own, given, (down, back, outcome), frame)
        run_type = next((r.subagent_type for r in own.records if r.event == "subagent_run"), None)
        node = ProducedNode(
            id=own.key,
            kind=self.kind,
            parent=parent.key,
            name=((None if meta is None else meta.description) or run_type or own.key),
            type=run_type,
            start=own.start,
            end=own.end,
            detail=detail,
            series=detail.series,
            loads=own.loads,
            calls=own.calls,
            compactions=own.compactions,
            activity=own.times,
        )
        edge = XrayEdge(
            parent.key,
            own.key,
            (task or 0) + down.inherited_tokens_est,
            back,
            own.start if launch is None else launch.t,
            back_t,
            outcome,
        )
        return node, edge


register(AgentProducer())
