"""The agent producer: the main agent and every subagent as nodes, with what each was handed, what it handed back and
how it ended."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.dto.events import ASSISTANT_ROW_KINDS, EventRecord, SubagentMeta, is_note_kind
from reporails_cli.core.platform.dto.xray_build import (
    AgentRecords,
    AgentReply,
    AgentWorld,
    CallResult,
    Frame,
    Handoff,
    LoadReading,
    NodeProducer,
    Produced,
    ProducedCall,
    ProducedNode,
    ProducedSpine,
    ProducerContext,
    SourceTable,
)
from reporails_cli.core.platform.dto.xray_graph import (
    HANDED_BACK_OUTCOMES,
    AgentOutcome,
    LoadEvent,
    LoadTrigger,
    NodeKind,
    XrayAgentDetail,
    XrayBack,
    XrayDown,
    XrayEdge,
    XrayGiven,
    XrayPrompt,
    XrayUsage,
)
from reporails_cli.core.xray.cost import agent_cost
from reporails_cli.core.xray.derive import (
    build_compactions,
    build_harness,
    epoch,
    frame_time,
    peak_context,
    replies_of,
    start_loads,
    tokens_of,
)
from reporails_cli.core.xray.graph.composition import build_in_context, composition_series
from reporails_cli.core.xray.graph.port import register
from reporails_cli.core.xray.graph.sources import for_path, hook_id, mcp_id

# The id of the main agent's node.
MAIN_ID = "main"

_KIND: NodeKind = "agent"


def _results(group: Sequence[EventRecord], frame: Frame) -> dict[str, CallResult]:
    """The result of each call among `group`, by the call's id."""
    return {
        record.tool.use_id: CallResult(frame_time(frame, record) or 0.0, record.tool.chars, record.tool.error is True)
        for record in group
        if record.event == "tool_result" and record.tool is not None and record.tool.use_id is not None
    }


def _calls(
    group: Sequence[EventRecord], frame: Frame, sources: SourceTable, results: dict[str, CallResult]
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
                t=frame_time(frame, record) or 0.0,
                category=category,
                tool=tool.name or "tool",
                label=f"{tool.name or 'tool'} · {path}" if path else tool.name or "tool",
                source=for_path(sources, tool.path) if tool.path else None,
                mcp_source=mcp_id(tool.server) if tool.server else None,
                failed=result is not None and result.error,
                use_id=tool.use_id,
                fingerprint=tool.fingerprint,
                back_tokens_est=None if chars is None else tokens_of(chars),
                duration_s=None if result is None else result.t - (frame_time(frame, record) or 0.0),
            )
        )
    return tuple(found)


def _at_start(reading: LoadReading, record: EventRecord) -> bool:
    """Whether a record came before the agent's first reply."""
    moment = epoch(record.time)
    return moment is not None and moment < reading.first


def _source_load(sid: str | None, t: float | None, reading: LoadReading) -> list[LoadEvent]:
    """A load by the agent's own doing (a run, a read) of the source `sid`; none when `sid` is no source."""
    entry = reading.sources.get(sid) if sid else None
    return [] if entry is None else [LoadEvent(entry.id, t, entry.tokens_est, "agent", None, True)]


def _harness_loads(record: EventRecord, reading: LoadReading) -> list[LoadEvent]:
    """The MCP servers and the hook a harness record puts into the agent's context."""
    entry = record.harness
    if entry is None:
        return []
    t = frame_time(reading.frame, record)
    if entry.kind == "mcp_instructions":
        trigger: LoadTrigger = "session_start" if reading.is_main else "inherited"
        return [LoadEvent(mcp_id(name), t, tokens_of(chars), trigger, None, True) for name, chars in entry.added]
    if is_note_kind(entry.kind) and entry.event is not None:
        return [LoadEvent(hook_id(entry.label), t, tokens_of(entry.chars), "hook", entry.event, True)]
    return []


def _record_loads(record: EventRecord, reading: LoadReading) -> list[LoadEvent]:
    """The sources one record puts into the agent's context."""
    if record.event == "instruction_load":
        return _instruction_load(record, reading)
    if record.event == "harness":
        return _harness_loads(record, reading)
    t = frame_time(reading.frame, record)
    if record.event == "skill_run" and record.skill is not None and not record.skill.forked:
        return _source_load(reading.sources.by_run.get(record.skill.name), t, reading)
    if record.event == "tool_call" and record.tool is not None and record.tool.category == "read" and record.tool.path:
        return _source_load(for_path(reading.sources, record.tool.path), t, reading)
    return []


def _instruction_load(record: EventRecord, reading: LoadReading) -> list[LoadEvent]:
    load = record.load
    if load is None:
        return []
    sid = for_path(reading.sources, load.path)
    entry = reading.sources.get(sid) if sid else None
    if entry is None:
        return []
    t = frame_time(reading.frame, record)
    if load.memory_type == "nested":
        return [LoadEvent(entry.id, t, entry.tokens_est, "path_match", None, True)]
    early = _at_start(reading, record)
    trigger: LoadTrigger = "session_start" if reading.is_main else "inherited" if early else "agent"
    return [LoadEvent(entry.id, t, entry.tokens_est, trigger, None, not (early and entry.kind == "instructions"))]


def _final_reply(group: Sequence[EventRecord], frame: Frame) -> AgentReply | None:
    """The text the agent's last assistant record carries; None when that record is a tool call or the agent never
    replied."""
    last = next(
        (record for record in reversed(group) if record.event in ASSISTANT_ROW_KINDS),
        None,
    )
    if last is None or last.reply is None:
        return None
    return AgentReply(frame_time(frame, last) or 0.0, last.reply.chars, last.reply.synthetic)


def _own(key: str, group: list[EventRecord], frame: Frame, sources: SourceTable) -> AgentRecords:
    replies = replies_of(group)
    results = _results(group, frame)
    reading = LoadReading(frame, sources, replies.points[0][0] if replies.points else float("inf"), key == MAIN_ID)
    return AgentRecords(
        key=key,
        records=group,
        replies=replies,
        results=results,
        calls=_calls(group, frame, sources, results),
        loads=tuple(load for record in group for load in _record_loads(record, reading)),
        compactions=build_compactions(group, replies, frame),
        times=tuple(sorted(moment for record in group if (moment := frame_time(frame, record)) is not None)),
        reply=_final_reply(group, frame),
    )


def _given(own: AgentRecords, sources: SourceTable) -> tuple[list[XrayGiven], list[XrayGiven]]:
    """What the agent started with besides its task prompt: its harness items, and the instruction files it loaded
    before its first reply."""
    harness = [XrayGiven(item.label, item.tokens_est, None) for item in build_harness(own.records, own.replies) or ()]
    loaded: list[XrayGiven] = []
    for record in start_loads(own.records, own.replies):
        entry = sources.get(for_path(sources, record.load.path) or "") if record.load is not None else None
        if entry is not None:
            loaded.append(XrayGiven(entry.name, entry.tokens_est, entry.id))
    return harness, loaded


def _prompts(own: AgentRecords, frame: Frame) -> tuple[XrayPrompt, ...]:
    typed = [
        XrayPrompt(record.prompt.id, frame_time(frame, record) or 0.0, tokens_of(record.prompt.chars))
        for record in own.records
        if record.event == "prompt_submit" and record.prompt is not None
    ]
    return tuple(sorted(typed, key=lambda item: item.t))


def _detail(
    own: AgentRecords,
    given: Sequence[XrayGiven],
    handoff: tuple[XrayDown, int | None, AgentOutcome | None],
    world: AgentWorld,
    run_type: str | None,
) -> XrayAgentDetail:
    down, back, outcome = handoff
    frame = world.frame
    brief_chars = None if own.key == MAIN_ID else _brief_chars(own)
    series = tuple((moment - frame.t0, context) for moment, context in own.replies.points)
    peak = peak_context(own.replies, own.compactions)
    series_of = composition_series(own, world.context.sources, frame, brief_chars)
    composition, carried = series_of
    return XrayAgentDetail(
        context_start=series[0][1] if series else None,
        peak=peak,
        series=series,
        down=down,
        back=XrayBack(back, peak // back if outcome == "returned" and peak is not None and back else None),
        outcome=outcome,
        given=tuple(given),
        prompts=_prompts(own, frame) if own.key == MAIN_ID else (),
        brief=down.task_tokens_est is not None,
        usage=XrayUsage(
            agent_cost(own.records, world.context.prices, frame.t0, carried, world.context.sources),
            composition,
        ),
        in_context=build_in_context(own, run_type, down, series_of, world),
    )


def _brief_chars(own: AgentRecords) -> int | None:
    """The size in characters of the task brief a subagent was launched with; None when its records hold none."""
    meta = _launch(own.records)
    return None if meta is None else meta.brief_chars


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


def _answered(meta: SubagentMeta | None, result: CallResult | None) -> bool:
    """Whether the parent's call for the subagent came back without an error and without the launch of a background
    run."""
    return result is not None and not result.error and not (meta is not None and meta.background)


def _outcome(meta: SubagentMeta | None, own: AgentRecords, result: CallResult | None, live: bool) -> AgentOutcome:
    if own.handback is not None:
        return "returned"
    if meta is not None and meta.stopped:
        return "stopped"
    if (result is not None and result.error) or (own.reply is not None and own.reply.synthetic):
        return "failed"
    if _answered(meta, result) or (own.reply is not None and not live):
        return "returned"
    return "running" if live else "no_handback"


def _back(
    meta: SubagentMeta | None, own: AgentRecords, result: CallResult | None, outcome: AgentOutcome
) -> tuple[int | None, float | None]:
    """The size in tokens of what came back to the parent and when, known only for a subagent that returned or
    failed: its hand-back, else the text it ended on, else the parent's result unless that result only acknowledged
    a background launch."""
    if outcome not in HANDED_BACK_OUTCOMES:
        return None, None
    handback = own.handback
    if handback is not None:
        return handback.back_tokens_est, handback.t
    if outcome == "returned" and own.reply is not None and not _answered(meta, result):
        return tokens_of(own.reply.chars), own.reply.t
    if result is not None and result.chars is not None and not (meta is not None and meta.background):
        return tokens_of(result.chars), result.t
    return None, None


def main_records(records: Sequence[EventRecord]) -> list[EventRecord]:
    """The records of the main agent's own file."""
    return [record for record in records if record.subagent_id is None]


def _spine(own: AgentRecords, detail: XrayAgentDetail) -> ProducedSpine:
    return ProducedSpine(detail.series, own.loads, own.calls, own.compactions, own.times)


def _main_node(own: AgentRecords, world: AgentWorld) -> ProducedNode:
    harness, loaded = _given(own, world.context.sources)
    given = [*harness, *loaded]
    down = XrayDown(None, sum(item.tokens_est or 0 for item in given))
    detail = _detail(own, given, (down, None, None), world, None)
    return ProducedNode(
        id=MAIN_ID,
        kind=_KIND,
        parent=None,
        name=world.context.vocabulary.root.name,
        type=world.context.vocabulary.root.type,
        start=0.0,
        end=world.session_end,
        detail=detail,
        spine=_spine(own, detail),
    )


def _handoff(own: AgentRecords, parent: AgentRecords, meta: SubagentMeta | None, down: XrayDown, live: bool) -> Handoff:
    use_id = None if meta is None else meta.tool_use_id
    result = parent.results.get(use_id) if use_id is not None else None
    launch = next((call for call in parent.calls if call.use_id == use_id), None) if use_id is not None else None
    outcome = _outcome(meta, own, result, live)
    back, back_t = _back(meta, own, result, outcome)
    return Handoff(down, back, own.start if launch is None else launch.t, back_t, outcome)


def _subagent_given(
    own: AgentRecords, meta: SubagentMeta | None, run_type: str | None, world: AgentWorld
) -> tuple[int | None, list[XrayGiven], XrayDown]:
    """A subagent's task prompt size, everything it was given in order (the task prompt, its agent definition file,
    the instruction files it loaded, its harness items) and what went down."""
    harness, loaded = _given(own, world.context.sources)
    task = None if meta is None or meta.brief_chars is None else tokens_of(meta.brief_chars)
    definition = world.frame.agent_files.get(run_type or "")
    inherited = [*([] if definition is None else [XrayGiven(run_type or "", definition, None)]), *loaded, *harness]
    given = [*([] if task is None else [XrayGiven("task prompt", task, None)]), *inherited]
    return task, given, XrayDown(task, sum(item.tokens_est or 0 for item in inherited))


def _sub_node(
    own: AgentRecords, parent: AgentRecords, meta: SubagentMeta | None, world: AgentWorld
) -> tuple[ProducedNode, XrayEdge]:
    run_type = next((r.subagent_type for r in own.records if r.event == "subagent_run"), None)
    task, given, down = _subagent_given(own, meta, run_type, world)
    handoff = _handoff(own, parent, meta, down, world.frame.live)
    detail = _detail(own, given, (down, handoff.back, handoff.outcome), world, run_type)
    node = ProducedNode(
        id=own.key,
        kind=_KIND,
        parent=parent.key,
        name=(None if meta is None else meta.description) or run_type or own.key,
        type=run_type,
        start=own.start,
        end=own.end,
        detail=detail,
        spine=_spine(own, detail),
    )
    edge = XrayEdge(
        parent.key,
        own.key,
        (task or 0) + down.inherited_tokens_est,
        handoff.back,
        handoff.out_t,
        handoff.back_t,
        handoff.outcome,
    )
    return node, edge


def _groups(records: Sequence[EventRecord]) -> dict[str, list[EventRecord]]:
    """The records of each agent by its key: the main agent's, then each subagent's."""
    groups: dict[str, list[EventRecord]] = {MAIN_ID: main_records(records)}
    for record in records:
        if record.subagent_id is not None:
            groups.setdefault(record.subagent_id, []).append(record)
    return groups


def produce_agents(records: Sequence[EventRecord], frame: Frame, context: ProducerContext) -> Produced:
    """The agent nodes of `records`, the main agent first and the subagents in launch order, and one edge from each
    subagent's parent to it."""
    owns = {key: _own(key, group, frame, context.sources) for key, group in _groups(records).items()}
    times = sorted(moment for record in records if (moment := frame_time(frame, record)) is not None)
    world = AgentWorld(frame, context, times[-1] if times else 0.0)
    metas = {key: _launch(own.records) for key, own in owns.items() if key != MAIN_ID}
    nodes = [_main_node(owns[MAIN_ID], world)]
    edges: list[XrayEdge] = []
    for key in sorted(metas, key=lambda item: (owns[item].start, item)):
        node, edge = _sub_node(owns[key], owns[_parent_of(key, metas)], metas[key], world)
        nodes.append(node)
        edges.append(edge)
    return Produced(tuple(nodes), tuple(edges))


register(NodeProducer(_KIND, produce_agents))
