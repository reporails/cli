"""What an agent's context is made of at each of its replies.

A reply's total and cache split are exact. The loaded files, hook notes, skills listing, typed prompts, the agent's
own text and the tool results before the reply are estimated from the sizes its records hold; what the estimates
leave of the total is the system prompt and tool definitions.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

from reporails_cli.core.platform.dto.events import EventRecord, HarnessKind, TokenUsage, is_note_kind
from reporails_cli.core.platform.dto.xray import AdapterVocabulary
from reporails_cli.core.platform.dto.xray_build import (
    AgentRecords,
    AgentWorld,
    Frame,
    HarnessSlot,
    ProducedNode,
    SourceTable,
)
from reporails_cli.core.platform.dto.xray_composition import (
    COMPOSITION_KEYS,
    ESTIMATED_KEYS,
    REMAINDER_KEY,
    CarriedReply,
    CompositionKey,
    ReplyComposition,
    XrayComposition,
)
from reporails_cli.core.platform.dto.xray_graph import (
    ContextKey,
    LoadEvent,
    SourceKind,
    XrayContextRow,
    XrayDown,
    XrayInContext,
)
from reporails_cli.core.platform.dto.xray_sources import SourceEntry, XrayBuiltin, XrayContextText
from reporails_cli.core.xray.derive import build_harness, context_of, frame_time, replies_of, tokens_of
from reporails_cli.core.xray.graph.sources import source_label

# The category each source kind's loads count in; a kind not listed (an MCP server) falls in the remainder.
_LOAD_CATEGORY: dict[SourceKind, CompositionKey] = {
    "instructions": "instructions",
    "rule": "rules_skills",
    "skill": "rules_skills",
    "memory": "memory",
    "hook": "hook_notes",
}

# The one harness kind a composition estimates as its own category; every other builtin kind is inside the remainder.
_LISTED_KIND: HarnessKind = "skill_list"

# (time, category, tokens, source id or None): a size that enters the context at a time and stays.
type Added = tuple[float, CompositionKey, int, str | None]
# (time, category, tokens): conversation and tool-result sizes; a category of None is a compaction.
type Spoken = tuple[float, CompositionKey | None, int]


def _load_deltas(own: AgentRecords, sources: SourceTable) -> list[Added]:
    """The loads of the agent in time order: a file counts once however often it loads, a hook firing each time."""
    found: list[Added] = []
    seen: set[str] = set()
    for load in sorted((item for item in own.loads if item.t is not None), key=lambda item: item.t or 0.0):
        entry = sources.get(load.source)
        category = None if entry is None else _LOAD_CATEGORY.get(entry.kind)
        if category is None or load.t is None:
            continue
        if category != "hook_notes":
            if load.source in seen:
                continue
            seen.add(load.source)
        found.append((load.t, category, load.tokens_est or 0, load.source))
    return found


def _skill_listing_deltas(own: AgentRecords, frame: Frame) -> list[Added]:
    """The change in the skills listing's size at each of its records: the first row, then the delta rows up to the
    first compaction, summed as the harness items are."""
    found: list[Added] = []
    slot: HarnessSlot | None = None
    compacted = False
    held = 0
    for record in own.records:
        entry = record.harness
        moment = frame_time(frame, record)
        if record.event == "post_compact":
            compacted = True
        if record.event != "harness" or entry is None or entry.kind != "skill_list" or moment is None:
            continue
        if slot is None:
            slot = HarnessSlot.of(entry)
        elif compacted:
            continue
        else:
            slot.add(entry)
        size = tokens_of(slot.chars)
        found.append((moment, "skill_listing", size - held, None))
        held = size
    return found


def _spoken_deltas(own: AgentRecords, frame: Frame, brief_chars: int | None) -> list[Spoken]:
    """What the conversation and the tool results grew by at each record, and every compaction."""
    found: list[Spoken] = []
    if brief_chars is not None:
        found.append((float("-inf"), "conversation", tokens_of(brief_chars)))
    for record in own.records:
        moment = frame_time(frame, record)
        if moment is None:
            continue
        if record.event == "post_compact":
            found.append((moment, None, 0))
        elif record.event == "prompt_submit" and record.prompt is not None:
            found.append((moment, "conversation", tokens_of(record.prompt.chars)))
        elif record.event == "assistant_text" and record.reply is not None:
            found.append((moment, "conversation", tokens_of(record.reply.chars)))
        elif record.event == "tool_result" and record.tool is not None and record.tool.chars is not None:
            found.append((moment, "tool_results", tokens_of(record.tool.chars)))
    return found


def _usages(records: Sequence[EventRecord], frame: Frame) -> list[tuple[float, TokenUsage]]:
    """The replies among `records` with their usage, in time order."""
    found = [
        (moment, record.usage)
        for record in records
        if record.event == "assistant_usage" and record.usage is not None
        if (moment := frame_time(frame, record)) is not None
    ]
    return sorted(found, key=lambda item: item[0])


def _take_load(held: dict[CompositionKey, int], carried: dict[str, int], hooks: set[str], load: Added) -> None:
    """Apply one load: its tokens join its category and, with an id, its source's carried tokens."""
    _, category, tokens, source = load
    held[category] += tokens
    if source is None:
        return
    carried[source] = carried.get(source, 0) + tokens
    if category == "hook_notes":
        hooks.add(source)


def _take_spoken(
    held: dict[CompositionKey, int], carried: dict[str, int], hooks: set[str], item: Spoken
) -> dict[str, int]:
    """Apply one conversation, tool result or compaction entry; returns the carried tokens after it."""
    _, grown, size = item
    if grown is not None:
        held[grown] += size
        return carried
    held["conversation"] = held["tool_results"] = held["hook_notes"] = 0
    kept = {source: tokens for source, tokens in carried.items() if source not in hooks}
    hooks.clear()
    return kept


def _sweep(
    added: Sequence[Added], spoken: Sequence[Spoken], usages: Sequence[tuple[float, TokenUsage]]
) -> Iterator[tuple[float, TokenUsage, dict[CompositionKey, int], dict[str, int]]]:
    """For each reply, what each estimated category holds at it: loads, hook notes and the skills
    listing up to and including the reply's time, conversation and tool results strictly before it; and the tokens
    each source that has an id contributed. A compaction empties the conversation, the tool results and the hook
    notes with the hook sources' tokens; loaded files stay. The two streams are applied in time order, so a hook
    note landing after a compaction survives it; at equal times the compaction goes first, because a note stamped
    with the compaction's own instant is what the compaction's aftermath loads."""
    held: dict[CompositionKey, int] = dict.fromkeys(ESTIMATED_KEYS, 0)
    carried: dict[str, int] = {}
    hooks: set[str] = set()
    ahead = 0
    behind = 0
    for moment, usage in usages:
        while True:
            load_due = ahead < len(added) and added[ahead][0] <= moment
            spoken_due = behind < len(spoken) and spoken[behind][0] < moment
            if not (load_due or spoken_due):
                break
            if spoken_due and not (load_due and added[ahead][0] < spoken[behind][0]):
                carried = _take_spoken(held, carried, hooks, spoken[behind])
                behind += 1
            else:
                _take_load(held, carried, hooks, added[ahead])
                ahead += 1
        yield moment, usage, held, dict(carried)


def _timeline(
    own: AgentRecords, sources: SourceTable, frame: Frame, brief_chars: int | None
) -> tuple[list[Added], list[Spoken]]:
    added = sorted([*_load_deltas(own, sources), *_skill_listing_deltas(own, frame)], key=lambda item: item[0])
    spoken = sorted(_spoken_deltas(own, frame, brief_chars), key=lambda item: item[0])
    return added, spoken


def _reply_row(moment: float, usage: TokenUsage, held: dict[CompositionKey, int]) -> ReplyComposition:
    """One reply's row: its exact total and cache split, and the categories with the remainder in its own."""
    total = context_of(usage)
    remainder = total - sum(held.values())
    parts = tuple(remainder if key == REMAINDER_KEY else held[key] for key in COMPOSITION_KEYS)
    return ReplyComposition(
        moment,
        total,
        usage.input_tokens,
        usage.cache_creation_input_tokens,
        usage.cache_read_input_tokens,
        parts,
        remainder < 0,
    )


def composition_series(
    own: AgentRecords, sources: SourceTable, frame: Frame, brief_chars: int | None
) -> tuple[XrayComposition, tuple[CarriedReply, ...]]:
    """The composition of the agent's context at each of its replies, and for each reply the tokens each source
    carried in it; `brief_chars` is the size of the task brief a subagent was launched with (None for the main
    agent)."""
    added, spoken = _timeline(own, sources, frame, brief_chars)
    replies: list[ReplyComposition] = []
    carried: list[CarriedReply] = []
    for moment, usage, held, by_source in _sweep(added, spoken, _usages(own.records, frame)):
        carried.append(CarriedReply(usage, by_source))
        replies.append(_reply_row(moment, usage, held))
    peak = max(range(len(replies)), key=lambda index: replies[index].total) if replies else None
    return XrayComposition(tuple(replies), peak), tuple(carried)


def _count_note(template: str | None, count: int | None) -> str | None:
    """The note `template` gives for an item of `count` entries; None when it needs a count the item lacks."""
    if template is None or "{count}" not in template:
        return template
    return None if count is None else template.format(count=count)


def _in_remainder(kind: HarnessKind) -> bool:
    """Whether a harness item's size sits in the remainder category: every kind except the skills listing and the
    hook notes, which have categories of their own, and the system prompt itself."""
    return kind not in (_LISTED_KIND, "system_prompt") and not is_note_kind(kind)


def builtin_items(
    main: ProducedNode, records: Sequence[EventRecord], vocabulary: AdapterVocabulary
) -> tuple[XrayBuiltin, ...]:
    """The coding agent's own context in the vocabulary's order. A harness item's size is read from its records;
    the system prompt is in no record, so its size is what the main agent's remainder category holds at its peak
    reply after the other harness items inside that category, never below 0."""
    composition = main.detail.usage.composition
    held = {item.kind: item for item in build_harness(records, replies_of(records)) or ()}
    system: int | None = None
    if composition.peak is not None:
        reply = composition.replies[composition.peak]
        inside = sum((item.tokens_est or 0) for kind, item in held.items() if _in_remainder(kind))
        system = max(0, reply.parts[COMPOSITION_KEYS.index(REMAINDER_KEY)] - inside)
    found: list[XrayBuiltin] = []
    for info in vocabulary.context.builtin:
        item = held.get(info.key)
        if info.key == "system_prompt":
            if system is not None:
                found.append(XrayBuiltin(info.key, info.label, system, info.note, info.visible, True))
        elif item is not None:
            note = _count_note(info.note, item.count)
            found.append(XrayBuiltin(info.key, info.label, item.tokens_est or 0, note, info.visible, False))
    return tuple(found)


def _row(key: ContextKey, entry: SourceEntry, load: LoadEvent, tokens: int, reason: str) -> XrayContextRow:
    findings = None if entry.findings is None else entry.findings.count
    return XrayContextRow(key, entry.id, entry.kind, source_label(entry), reason, tokens, load.t, findings)


def _first_loads(
    own: AgentRecords, reply_t: float, carried: dict[str, int], sources: SourceTable
) -> list[tuple[LoadEvent, SourceEntry]]:
    """The first load by `reply_t` of each source that was in the agent's context at the reply: a carried source
    or an MCP server."""
    seen: set[str] = set()
    found: list[tuple[LoadEvent, SourceEntry]] = []
    for load in sorted(
        (item for item in own.loads if item.t is not None and item.t <= reply_t), key=lambda i: i.t or 0
    ):
        entry = sources.get(load.source)
        if entry is None or load.source in seen or not (entry.kind == "mcp" or load.source in carried):
            continue
        seen.add(load.source)
        found.append((load, entry))
    return found


def _source_rows(
    own: AgentRecords, reply_t: float, carried: dict[str, int], world: AgentWorld
) -> tuple[list[XrayContextRow], list[XrayContextRow], int]:
    """The rows of the sources the agent had loaded by `reply_t`, inherited ones first then by time, the rows of
    the hooks among them, and the tokens of the MCP servers among the first."""
    vocabulary = world.context.vocabulary
    triggers = {item.key: item.label for item in vocabulary.triggers}
    hook_reason = next(item.reason for item in vocabulary.context.texts if item.key == "hooks")
    dropped = max((item.t for item in own.compactions if item.t < reply_t), default=float("-inf"))
    fires: dict[str, int] = {}
    for load in own.loads:
        if load.t is not None and dropped < load.t <= reply_t:
            fires[load.source] = fires.get(load.source, 0) + 1
    loaded: list[tuple[LoadEvent, XrayContextRow]] = []
    hooks: list[XrayContextRow] = []
    mcp = 0
    for load, entry in _first_loads(own, reply_t, carried, world.context.sources):
        tokens = (load.tokens_est or 0) if entry.kind == "mcp" else carried[entry.id]
        if entry.kind == "mcp":
            mcp += tokens
        if entry.kind == "hook":
            hooks.append(_row("hooks", entry, load, tokens, hook_reason.format(count=fires[entry.id])))
        else:
            loaded.append((load, _row("source", entry, load, tokens, triggers.get(load.trigger, ""))))
    loaded.sort(key=lambda item: (item[0].trigger != "inherited", item[0].t or 0.0))
    return [row for _, row in loaded], hooks, mcp


def _definition_row(run_type: str | None, own: AgentRecords, world: AgentWorld) -> XrayContextRow | None:
    """The row of the agent definition a subagent was launched from; None for the main agent and for a type with
    no readable definition file."""
    size = world.frame.agent_files.get(run_type or "")
    entry = next(
        (item for item in world.context.sources.entries if item.kind == "agent" and item.name == run_type), None
    )
    if size is None or entry is None:
        return None
    reason = next((item.label for item in world.context.vocabulary.triggers if item.key == "inherited"), "")
    return XrayContextRow("source", entry.id, entry.kind, source_label(entry), reason, size, own.start, None)


def _opening_rows(
    own: AgentRecords,
    run_type: str | None,
    task_tokens: int | None,
    *,
    reply_t: float,
    by_source: dict[str, int],
    texts: dict[ContextKey, XrayContextText],
    world: AgentWorld,
) -> tuple[list[XrayContextRow], int, int]:
    """The rows before the coding agent's own context: the task prompt (a subagent), the agent definition, the
    sources loaded by the reply (inherited first, then by time) and the hooks that fired; with the tokens of the MCP
    servers among the sources and of the definition."""
    sources, hooks, mcp = _source_rows(own, reply_t, by_source, world)
    definition = _definition_row(run_type, own, world)
    rows: list[XrayContextRow] = []
    if task_tokens is not None:
        task = texts["task"]
        rows.append(XrayContextRow("task", None, None, task.label, task.reason, task_tokens, own.start, None))
    rows.extend([] if definition is None else [definition])
    rows.extend([*sources, *hooks])
    return rows, mcp, 0 if definition is None else definition.tokens_est


def _closing_rows(
    reply: ReplyComposition,
    opening: Sequence[XrayContextRow],
    taken: tuple[int, int],
    texts: dict[ContextKey, XrayContextText],
) -> list[XrayContextRow]:
    """The coding agent's own context and the conversation with the tool results, which take what the estimates
    leave of the measured total, the conversation row at 0 when the estimates overshoot it. `taken` is the tokens
    of the MCP servers and of the definition, which the coding agent's own context does not count."""
    built = reply.parts[COMPOSITION_KEYS.index(REMAINDER_KEY)] + reply.parts[COMPOSITION_KEYS.index("skill_listing")]
    builtin = texts["builtin"]
    own_row = XrayContextRow(
        "builtin", None, None, builtin.label, builtin.reason, max(0, built - sum(taken)), None, None
    )
    left = reply.total - sum(row.tokens_est for row in opening) - own_row.tokens_est
    rest = texts["rest"]
    return [own_row, XrayContextRow("rest", None, None, rest.label, rest.reason, max(0, left), None, None)]


def build_in_context(
    own: AgentRecords,
    run_type: str | None,
    down: XrayDown,
    series: tuple[XrayComposition, tuple[CarriedReply, ...]],
    world: AgentWorld,
) -> XrayInContext | None:
    """What the agent's context held at its peak reply: its task prompt (a subagent), its definition, the sources
    loaded by then (inherited first, then by time), the hooks that fired, the coding agent's own context and the
    conversation and tool results, which take what the estimates leave of the measured total. The estimates may
    overshoot the total; the last row is then 0 and `over` is set. None when the agent has no reply."""
    composition, carried = series
    if composition.peak is None:
        return None
    reply = composition.replies[composition.peak]
    texts = {item.key: item for item in world.context.vocabulary.context.texts}
    rows, mcp, defined = _opening_rows(
        own,
        run_type,
        down.task_tokens_est,
        reply_t=reply.t,
        by_source=carried[composition.peak].by_source,
        texts=texts,
        world=world,
    )
    closing = _closing_rows(reply, rows, (mcp, defined), texts)
    shown = (*rows, *closing)
    return XrayInContext(reply.total, shown, sum(row.tokens_est for row in shown) != reply.total)
