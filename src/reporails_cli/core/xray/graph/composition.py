"""What an agent's context is made of at each of its replies.

A reply's total and cache split are exact. When the request the reply answered was recorded, the exact total is
split by that request's measured sizes: system prompt, tool definitions, and tool calls and results are shares of
it, the loaded files, hook notes and skills listing stay estimated, and the conversation takes what is left. When
the request was not recorded, the loaded files, hook notes, skills listing, typed prompts, the agent's own text and
the tool results before the reply are estimated from the sizes its records hold; what the estimates leave of the
total is the system prompt and tool definitions.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence

from reporails_cli.core.platform.dto.events import (
    EventRecord,
    RequestSize,
    TokenUsage,
)
from reporails_cli.core.platform.dto.xray import AdapterVocabulary
from reporails_cli.core.platform.dto.xray_build import (
    AgentRecords,
    AgentWorld,
    Frame,
    HarnessSlot,
    SourceTable,
)
from reporails_cli.core.platform.dto.xray_compaction import HELD_FILE_STATES, XrayCompaction
from reporails_cli.core.platform.dto.xray_composition import (
    COMPOSITION_KEYS,
    ESTIMATED_KEYS,
    REMAINDER_KEY,
    SPOKEN_KEYS,
    CarriedReply,
    CompositionKey,
    ReplyComposition,
    RequestMeasure,
    XrayComposition,
)
from reporails_cli.core.platform.dto.xray_graph import (
    ContextKey,
    LoadEvent,
    SourceKind,
    XrayContextRow,
    XrayDown,
    XrayInContext,
    XrayRowMeasure,
)
from reporails_cli.core.platform.dto.xray_sources import SourceEntry, XrayContextText
from reporails_cli.core.xray.derive import context_of, frame_time, tokens_of
from reporails_cli.core.xray.graph.sources import source_label

# The category each source kind's loads count in; a kind not listed (an MCP server) falls in the remainder.
_LOAD_CATEGORY: dict[SourceKind, CompositionKey] = {
    "instructions": "instructions",
    "rule": "rules_skills",
    "skill": "rules_skills",
    "memory": "memory",
    "hook": "hook_notes",
}

# (time, category, tokens, source id or None): a size that enters the context at a time and stays.
type Added = tuple[float, CompositionKey, int, str | None]
# (time, category, tokens, left): conversation and tool-result sizes; a category of None is a compaction, and `left`
# holds the sources it takes out of the context (loaded files that did not survive it).
type Spoken = tuple[float, CompositionKey | None, int, frozenset[str]]


def _left(compaction: XrayCompaction) -> frozenset[str]:
    """The sources `compaction` took out of the agent's context: its files that are dropped."""
    return frozenset(item.source for item in compaction.files if item.state not in HELD_FILE_STATES)


def _left_between(own: AgentRecords, source: str, after: float, before: float) -> bool:
    """Whether a compaction between the two times took `source` out of the agent's context."""
    return any(after < item.t < before and source in _left(item) for item in own.compactions)


def _load_deltas(own: AgentRecords, sources: SourceTable) -> list[Added]:
    """The loads of the agent in time order: a file counts once however often it loads, a hook firing each time."""
    found: list[Added] = []
    seen: dict[str, float] = {}
    for load in sorted((item for item in own.loads if item.t is not None), key=lambda item: item.t or 0.0):
        entry = sources.get(load.source)
        category = None if entry is None else _LOAD_CATEGORY.get(entry.kind)
        if category is None or load.t is None:
            continue
        if category != "hook_notes":
            if load.source in seen and not _left_between(own, load.source, seen[load.source], load.t):
                continue
            seen[load.source] = load.t
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
    none: frozenset[str] = frozenset()
    left = {item.t: _left(item) for item in own.compactions}
    if brief_chars is not None:
        found.append((float("-inf"), "conversation", tokens_of(brief_chars), none))
    for record in own.records:
        moment = frame_time(frame, record)
        if moment is None:
            continue
        if record.event == "post_compact":
            found.append((moment, None, 0, left.get(moment, none)))
        elif record.event == "prompt_submit" and record.prompt is not None:
            found.append((moment, "conversation", tokens_of(record.prompt.chars), none))
        elif record.event == "assistant_text" and record.reply is not None:
            found.append((moment, "conversation", tokens_of(record.reply.chars), none))
        elif record.event == "tool_result" and record.tool is not None and record.tool.chars is not None:
            found.append((moment, "tool_results", tokens_of(record.tool.chars), none))
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


def _take_load(
    held: dict[CompositionKey, int],
    carried: dict[str, int],
    homes: dict[str, CompositionKey],
    hooks: set[str],
    load: Added,
) -> None:
    """Apply one load: its tokens join its category and, with an id, its source's carried tokens."""
    _, category, tokens, source = load
    held[category] += tokens
    if source is None:
        return
    homes[source] = category
    carried[source] = carried.get(source, 0) + tokens
    if category == "hook_notes":
        hooks.add(source)


def _take_spoken(
    held: dict[CompositionKey, int],
    carried: dict[str, int],
    homes: dict[str, CompositionKey],
    hooks: set[str],
    item: Spoken,
) -> dict[str, int]:
    """Apply one conversation, tool result or compaction entry; returns the carried tokens after it."""
    _, grown, size, left = item
    if grown is not None:
        held[grown] += size
        return carried
    held["conversation"] = held["tool_results"] = held["hook_notes"] = 0
    for source in left & carried.keys():
        held[homes[source]] -= carried[source]
    kept = {source: tokens for source, tokens in carried.items() if source not in hooks and source not in left}
    hooks.clear()
    return kept


def _sweep(
    added: Sequence[Added], spoken: Sequence[Spoken], usages: Sequence[tuple[float, TokenUsage]]
) -> Iterator[tuple[float, TokenUsage, dict[CompositionKey, int], dict[str, int]]]:
    """For each reply, what each estimated category holds at it: loads, hook notes and the skills
    listing up to and including the reply's time, conversation and tool results strictly before it; and the tokens
    each source that has an id contributed. A compaction empties the conversation, the tool results and the hook
    notes with the hook sources' tokens, and takes out the loaded files that were neither kept nor reloaded. The two
    streams are applied in time order, so a hook note landing after a compaction survives it; at equal times the
    compaction goes first, because a note stamped with the compaction's own instant is what the compaction's
    aftermath loads."""
    held: dict[CompositionKey, int] = dict.fromkeys(ESTIMATED_KEYS, 0)
    carried: dict[str, int] = {}
    homes: dict[str, CompositionKey] = {}
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
                carried = _take_spoken(held, carried, homes, hooks, spoken[behind])
                behind += 1
            else:
                _take_load(held, carried, homes, hooks, added[ahead])
                ahead += 1
        yield moment, usage, held, dict(carried)


def _timeline(
    own: AgentRecords, sources: SourceTable, frame: Frame, brief_chars: int | None
) -> tuple[list[Added], list[Spoken]]:
    added = sorted([*_load_deltas(own, sources), *_skill_listing_deltas(own, frame)], key=lambda item: item[0])
    spoken = sorted(_spoken_deltas(own, frame, brief_chars), key=lambda item: item[0])
    return added, spoken


def _request_sizes(records: Sequence[EventRecord]) -> dict[str, RequestSize]:
    """The sizes of each request among `records`, by request id."""
    return {record.request.request_id: record.request for record in records if record.request is not None}


def _measure(usage: TokenUsage, sizes: dict[str, RequestSize]) -> RequestMeasure | None:
    """The recorded request `usage` answered, with the tokens per character of its text and its images priced at
    its model's tier. The images take their own tokens off the reply's exact total before the text is scaled to
    the rest. None when the request was not recorded, names a message the file never recorded, holds an image that
    could not be priced or one whose model's tier is unknown, or measured no characters."""
    size = None if usage.request_ref is None else sizes.get(usage.request_ref)
    if size is None or size.unresolved or size.parts.unpriced_images:
        return None
    parts = size.parts
    held = parts.images + parts.result_images
    if size.high_resolution is None and (held.standard or held.high):
        return None
    high = bool(size.high_resolution)
    images, result_images = parts.images.at(high_resolution=high), parts.result_images.at(high_resolution=high)
    chars = size.system_chars + size.tools_chars + parts.text_chars
    text_tokens = context_of(usage) - images - result_images
    if chars <= 0 or text_tokens <= 0:
        return None
    return RequestMeasure(size, text_tokens / chars, result_images)


def share(chars: int, scale: float) -> int:
    """`chars` characters of a measured request as tokens of the reply's total."""
    return round(chars * scale)


def _tool_share(measured: RequestMeasure) -> int:
    """The tool calls and results of a measured request as tokens: their characters at its scale, with the
    images of the tool results added."""
    size = measured.size
    return share(size.parts.tool_calls + size.parts.tool_results, measured.scale) + measured.result_images


def _reply_row(
    moment: float,
    usage: TokenUsage,
    held: dict[CompositionKey, int],
    measured: RequestMeasure | None,
    sized: RequestMeasure | None,
) -> ReplyComposition:
    """One reply's row: its exact total and cache split and its categories. A reply whose request was recorded takes
    its system, tools and tool-result shares from the request and the conversation from what the rest leave. Any
    other keeps the remainder in its own category, except that when an earlier request sizes it (`sized`) the
    remainder category holds only that request's system and tool share and the conversation takes the rest."""
    total = context_of(usage)
    if measured is None:
        remainder = total - sum(held.values())
        kept = remainder
        if sized is not None and remainder > 0:
            kept = min(remainder, share(sized.size.system_chars + sized.size.tools_chars, sized.scale))
        parts = {**held, REMAINDER_KEY: kept}
        parts["conversation"] += max(0, remainder - kept)
        return ReplyComposition(
            moment,
            total,
            usage.input_tokens,
            usage.cache_creation_input_tokens,
            usage.cache_read_input_tokens,
            tuple(parts[key] for key in COMPOSITION_KEYS),
            remainder < 0,
            None,
            sized,
        )
    size, scale = measured.size, measured.scale
    fixed: dict[CompositionKey, int] = {
        **{key: held[key] for key in ESTIMATED_KEYS if key not in SPOKEN_KEYS},
        REMAINDER_KEY: share(size.system_chars + size.tools_chars, scale),
        "tool_results": _tool_share(measured),
    }
    conversation = total - sum(fixed.values())
    fixed["conversation"] = max(0, conversation)
    return ReplyComposition(
        moment,
        total,
        usage.input_tokens,
        usage.cache_creation_input_tokens,
        usage.cache_read_input_tokens,
        tuple(fixed[key] for key in COMPOSITION_KEYS),
        conversation < 0,
        measured,
        measured,
    )


def _sized_by(measures: Sequence[RequestMeasure | None]) -> list[RequestMeasure | None]:
    """The request each reply is sized by: its own complete request, else the newest complete one before it."""
    sized: list[RequestMeasure | None] = []
    for measure in measures:
        sized.append(measure or (sized[-1] if sized else None))
    return sized


def composition_series(
    own: AgentRecords, sources: SourceTable, frame: Frame, brief_chars: int | None
) -> tuple[XrayComposition, tuple[CarriedReply, ...]]:
    """The composition of the agent's context at each of its replies, and for each reply the tokens each source
    carried in it; `brief_chars` is the size of the task brief a subagent was launched with (None for the main
    agent)."""
    added, spoken = _timeline(own, sources, frame, brief_chars)
    sizes = _request_sizes(own.records)
    # the sweep reuses one table of held tokens, so each reply keeps its own copy
    swept = [
        (moment, usage, dict(held), by_source)
        for moment, usage, held, by_source in _sweep(added, spoken, _usages(own.records, frame))
    ]
    measures = [_measure(usage, sizes) for _, usage, _, _ in swept]
    sized = _sized_by(measures)
    replies = tuple(
        _reply_row(moment, usage, held, measure, size)
        for (moment, usage, held, _), measure, size in zip(swept, measures, sized, strict=True)
    )
    carried = tuple(CarriedReply(usage, by_source) for _, usage, _, by_source in swept)
    peak = max(range(len(replies)), key=lambda index: replies[index].total) if replies else None
    return XrayComposition(replies, peak), carried


def count_text(many: str | None, once: str | None, count: int | None) -> str | None:
    """The wording of a vocabulary entry for `count` entries: `once` for a count of one when the entry has one,
    else `many`, with `{count}` filled in; None when the wording needs a count that is missing."""
    template = once if count == 1 and once is not None else many
    if template is None or "{count}" not in template:
        return template
    return None if count is None else template.format(count=count)


def _row(key: ContextKey, entry: SourceEntry, load: LoadEvent, tokens: int, reason: str) -> XrayContextRow:
    findings = None if entry.findings is None else entry.findings.count
    return XrayContextRow(key, entry.id, entry.kind, source_label(entry), reason, tokens, load.t, findings)


def _dropped_at(own: AgentRecords, reply_t: float) -> float:
    """The time of the last compaction before `reply_t`, which empties the hook notes; a load stamped with that
    very instant is what the compaction's aftermath loads, so it is carried."""
    return max((item.t for item in own.compactions if item.t < reply_t), default=float("-inf"))


def _first_loads(
    own: AgentRecords, reply_t: float, carried: dict[str, int], sources: SourceTable
) -> list[tuple[LoadEvent, SourceEntry]]:
    """The first load by `reply_t` of each source that was in the agent's context at the reply: a carried source
    or an MCP server. A hook counts from its first firing after the last compaction."""
    dropped = _dropped_at(own, reply_t)
    seen: set[str] = set()
    found: list[tuple[LoadEvent, SourceEntry]] = []
    for load in sorted(
        (item for item in own.loads if item.t is not None and item.t <= reply_t), key=lambda i: i.t or 0
    ):
        entry = sources.get(load.source)
        if entry is None or load.source in seen or not (entry.kind == "mcp" or load.source in carried):
            continue
        if entry.kind == "hook" and (load.t or 0.0) < dropped:
            continue
        seen.add(load.source)
        found.append((load, entry))
    return found


def _hook_reason(vocabulary: AdapterVocabulary) -> Callable[[int], str]:
    """The reason a hook row gives for a number of firings, in the vocabulary's wording for one firing or several."""
    text = next(item for item in vocabulary.context.texts if item.key == "hooks")
    return lambda count: count_text(text.reason, text.reason_once, count) or text.reason


def _source_rows(
    own: AgentRecords, reply_t: float, carried: dict[str, int], world: AgentWorld
) -> tuple[list[XrayContextRow], list[XrayContextRow], int]:
    """The rows of the sources the agent had loaded by `reply_t`, inherited ones first then by time, the rows of
    the hooks among them, and the tokens of the MCP servers among the first."""
    vocabulary = world.context.vocabulary
    triggers = {item.key: item.label for item in vocabulary.triggers}
    dropped = _dropped_at(own, reply_t)
    reason = _hook_reason(vocabulary)
    fires: dict[str, int] = {}
    for load in own.loads:
        if load.t is not None and dropped <= load.t <= reply_t:
            fires[load.source] = fires.get(load.source, 0) + 1
    loaded: list[tuple[LoadEvent, XrayContextRow]] = []
    hooks: list[XrayContextRow] = []
    mcp = 0
    for load, entry in _first_loads(own, reply_t, carried, world.context.sources):
        tokens = (load.tokens_est or 0) if entry.kind == "mcp" else carried[entry.id]
        if entry.kind == "mcp":
            mcp += tokens
        if entry.kind == "hook":
            hooks.append(_row("hooks", entry, load, tokens, reason(fires[entry.id])))
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


def _measured_shares(
    measured: RequestMeasure, taken: tuple[int, int]
) -> list[tuple[ContextKey, int, XrayRowMeasure | None]]:
    """The system prompt, tool definitions and tool calls and results of a measured request as rows: each share
    of the request's characters at its scale, the system prompt and tool definitions less what an earlier row
    already lists, the tool row with the images of the tool results added."""
    size, scale = measured.size, measured.scale
    mcp, defined = taken
    system, tools = share(size.system_chars, scale), share(size.tools_chars, scale)
    io_chars = size.parts.tool_calls + size.parts.tool_results
    return [
        ("system_prompt", max(0, system - defined), XrayRowMeasure(size.system_chars, 0, min(defined, system))),
        ("tool_definitions", max(0, tools - mcp), XrayRowMeasure(size.tools_chars, 0, min(mcp, tools))),
        (
            "tool_io",
            _tool_share(measured),
            XrayRowMeasure(io_chars, measured.result_images, 0),
        ),
    ]


def _reason(text: XrayContextText, own_request: bool) -> str:
    """The reason a measured row gives: the one for a share of the reply's own request, or the one for a share of an
    earlier request when the row has it."""
    return text.reason if own_request else text.reason_earlier or text.reason


def _measured_rows(
    measured: RequestMeasure,
    reply: ReplyComposition,
    opening: Sequence[XrayContextRow],
    taken: tuple[int, int],
    texts: dict[ContextKey, XrayContextText],
    *,
    own_request: bool = True,
) -> list[XrayContextRow]:
    """The rows after the opening ones for a measured peak: the system prompt without the agent definition, the tool
    definitions without the MCP servers (both already listed above), the tool calls and results, the skills listing
    when the reply held one (the composition's estimate, not part of the request's measured shares), and the
    conversation, which takes what is left of the total, at 0 when the rest overshoots it. A reply whose own request
    was not recorded (`own_request` False) takes the sizes of the newest earlier measured request for the system
    prompt and the tool definitions only, and its conversation row keeps the tool calls and results."""
    shares = _measured_shares(measured, taken)
    shares = shares if own_request else [item for item in shares if item[0] != "tool_io"]
    listing = reply.parts[COMPOSITION_KEYS.index("skill_listing")]
    if listing > 0:
        shares.append(("skill_listing", listing, None))
    rows = [
        XrayContextRow(
            key, None, None, texts[key].label, _reason(texts[key], own_request), tokens, None, None, row_measure
        )
        for key, tokens, row_measure in shares
    ]
    left = reply.total - sum(row.tokens_est for row in (*opening, *rows))
    rest = texts["conversation" if own_request else "rest"]
    return [*rows, XrayContextRow("rest", None, None, rest.label, rest.reason, max(0, left), None, None)]


def _tail_rows(
    reply: ReplyComposition,
    opening: Sequence[XrayContextRow],
    taken: tuple[int, int],
    texts: dict[ContextKey, XrayContextText],
) -> list[XrayContextRow]:
    """The rows after the opening ones: the shares of the request the reply is sized from (its own, else the latest
    complete one before it), or the estimated closing rows when none sizes it."""
    if reply.sized is None:
        return _closing_rows(reply, opening, taken, texts)
    return _measured_rows(reply.sized, reply, opening, taken, texts, own_request=reply.measured)


def build_in_context(
    own: AgentRecords,
    run_type: str | None,
    down: XrayDown,
    series: tuple[XrayComposition, tuple[CarriedReply, ...]],
    world: AgentWorld,
) -> XrayInContext | None:
    """What the agent's context held at its peak reply: its task prompt (a subagent), its definition, the sources
    loaded by then (inherited first, then by time), the hooks that fired, then one of three tails. A reply whose
    request was recorded shows the measured shares of that request (system prompt, tool definitions, tool calls
    and results, and the conversation as what is left). A reply whose request was not recorded, after a complete
    one, shows that earlier request's system prompt and tool definitions (the request and its tokens per character
    are named) and the conversation and tool results as what is left, labelled an estimate. With no complete request
    before it, the reply shows the coding agent's own context and the conversation and tool results, which take
    what the estimates leave. The rows may overshoot the total; the last row is then 0 and `over` is set. None when
    the agent has no reply."""
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
    shown = (*rows, *_tail_rows(reply, rows, (mcp, defined), texts))
    sized = reply.sized
    return XrayInContext(
        reply.total,
        shown,
        sum(row.tokens_est for row in shown) != reply.total,
        reply.measured,
        None if reply.measured else texts["estimated"].reason,
        None if sized is None else sized.size.request_id,
        None if sized is None else sized.scale,
    )
