"""The rows of what an agent's context held at its peak reply: the task prompt, the agent definition, the sources
and hooks loaded by then, and the tail of measured or estimated shares that makes up the rest of its total.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace

from reporails_cli.core.platform.dto.xray import AdapterVocabulary
from reporails_cli.core.platform.dto.xray_build import AgentRecords, AgentWorld, Frame, SourceTable
from reporails_cli.core.platform.dto.xray_composition import (
    COMPOSITION_KEYS,
    REMAINDER_KEY,
    CarriedReply,
    ReplyComposition,
    RequestMeasure,
    XrayComposition,
)
from reporails_cli.core.platform.dto.xray_graph import (
    INJECTED_TRIGGERS,
    LoadEvent,
    XrayContextRow,
    XrayInContext,
)
from reporails_cli.core.platform.dto.xray_own import LISTING_KEYS, ContextKey, XrayOwnContext, XrayRowMeasure
from reporails_cli.core.platform.dto.xray_sources import SourceEntry, XrayContextText
from reporails_cli.core.xray.graph.builtin import LISTED, own_context
from reporails_cli.core.xray.graph.composition import count_text, listing_chars, share, tokens_at, tool_share
from reporails_cli.core.xray.graph.sources import source_label


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


def _fire_counts(own: AgentRecords, reply_t: float) -> dict[str, int]:
    """How many times each source loaded by `reply_t`, counting from the last compaction before it."""
    dropped = _dropped_at(own, reply_t)
    fires: dict[str, int] = {}
    for load in own.loads:
        if load.t is not None and dropped <= load.t <= reply_t:
            fires[load.source] = fires.get(load.source, 0) + 1
    return fires


def _source_rows(
    own: AgentRecords, reply_t: float, carried: dict[str, int], world: AgentWorld, measured: RequestMeasure | None
) -> tuple[list[XrayContextRow], list[XrayContextRow], int, int]:
    """The rows of the sources the agent had loaded by `reply_t`, inherited ones first then by time, the rows of
    the hooks among them, the tokens of the MCP servers among the first, and the tokens of the rows whose text
    Claude Code sent as a message of its own (the MCP servers, the hooks, and the files loaded by a trigger that
    injects them). The carried characters become tokens at the scale of `measured`, or at the estimate's four
    characters to a token when it is None."""
    triggers = {item.key: item.label for item in world.context.vocabulary.triggers}
    reason = _hook_reason(world.context.vocabulary)
    fires = _fire_counts(own, reply_t)
    loaded: list[tuple[LoadEvent, XrayContextRow]] = []
    hooks: list[XrayContextRow] = []
    mcp = 0
    injected = 0
    for load, entry in _first_loads(own, reply_t, carried, world.context.sources):
        tokens = tokens_at((load.chars or 0) if entry.kind == "mcp" else carried[entry.id], measured)
        if entry.kind == "mcp":
            mcp += tokens
        if entry.kind == "hook" or load.trigger in INJECTED_TRIGGERS or entry.kind == "mcp":
            injected += tokens
        if entry.kind == "hook":
            hooks.append(_row("hooks", entry, load, tokens, reason(fires[entry.id])))
        else:
            loaded.append((load, _row("source", entry, load, tokens, triggers.get(load.trigger, ""))))
    loaded.sort(key=lambda item: (item[0].trigger != "inherited", item[0].t or 0.0))
    return [row for _, row in loaded], hooks, mcp, injected


def _definition_row(
    run_type: str | None, own: AgentRecords, world: AgentWorld, measured: RequestMeasure | None
) -> XrayContextRow | None:
    """The row of the agent definition a subagent was launched from, its file size in tokens at the scale of
    `measured` (four bytes to a token when None); None for the main agent and for a type with no readable
    definition file."""
    size = world.frame.agent_files.get(run_type or "")
    entry = next(
        (item for item in world.context.sources.entries if item.kind == "agent" and item.name == run_type), None
    )
    if size is None or entry is None:
        return None
    reason = next((item.label for item in world.context.vocabulary.triggers if item.key == "inherited"), "")
    return XrayContextRow(
        "source", entry.id, entry.kind, source_label(entry), reason, tokens_at(size, measured), own.start, None
    )


def _opening_rows(
    own: AgentRecords,
    run_type: str | None,
    brief_chars: int | None,
    *,
    reply_t: float,
    carried: CarriedReply,
    texts: dict[ContextKey, XrayContextText],
    world: AgentWorld,
) -> tuple[list[XrayContextRow], int, int, int]:
    """The rows before the coding agent's own context: the task prompt (a subagent), the agent definition, the
    sources loaded by the reply (inherited first, then by time) and the hooks that fired, sized from the characters
    `carried` holds; with the tokens of the MCP servers among the sources, of the definition, and of the rows Claude
    Code sent as messages of its own."""
    sources, hooks, mcp, injected = _source_rows(own, reply_t, carried.by_source, world, carried.measured)
    definition = _definition_row(run_type, own, world, carried.measured)
    rows: list[XrayContextRow] = []
    if brief_chars is not None:
        task = texts["task"]
        rows.append(
            XrayContextRow(
                "task", None, None, task.label, task.reason, tokens_at(brief_chars, carried.measured), own.start, None
            )
        )
    rows.extend([] if definition is None else [definition])
    rows.extend([*sources, *hooks])
    return rows, mcp, 0 if definition is None else definition.tokens_est, injected


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


def _measured_shares(measured: RequestMeasure, defined: int) -> list[tuple[ContextKey, int, XrayRowMeasure | None]]:
    """The system prompt, tool definitions and tool calls and results of a measured request as rows: each share
    of the request's characters at its scale, the system prompt less what an earlier row already lists (`defined`,
    the agent definition), the tool row with the images of the tool results added."""
    size, scale = measured.size, measured.scale
    system, tools = share(size.system_chars, scale), share(size.tools_chars, scale)
    io_chars = size.parts.tool_calls + size.parts.tool_results
    return [
        ("system_prompt", max(0, system - defined), XrayRowMeasure(size.system_chars, 0, min(defined, system))),
        ("tool_definitions", tools, XrayRowMeasure(size.tools_chars, 0, 0)),
        (
            "tool_io",
            tool_share(measured),
            XrayRowMeasure(io_chars, measured.result_images, 0),
        ),
    ]


def _harness_row(
    key: ContextKey, chars: int, names: dict[ContextKey, str], scale: float, *, taken: int = 0
) -> XrayContextRow:
    """The row of `chars` characters of a measured request at its `scale`, less the `taken` tokens an earlier row
    already lists."""
    tokens = share(chars, scale)
    return XrayContextRow(
        key,
        None,
        None,
        names[key],
        "",
        max(0, tokens - taken),
        None,
        None,
        XrayRowMeasure(chars, 0, min(taken, tokens)),
    )


def _listing_rows(
    own: AgentRecords, frame: Frame, reply: ReplyComposition, scale: float, names: dict[ContextKey, str]
) -> list[XrayContextRow]:
    """The rows of the agent listing, the deferred tools and the session context at the characters each held by
    the reply; a listing of no characters is left out."""
    sized = ((key, listing_chars(own, frame, LISTED[key], reply.t)) for key in LISTING_KEYS)
    return [_harness_row(key, chars, names, scale) for key, chars in sized if chars > 0]


def _harness_shares(
    own: AgentRecords, frame: Frame, reply: ReplyComposition, injected: int, names: dict[ContextKey, str]
) -> list[XrayContextRow]:
    """The rows of a reply's own measured request beyond the system prompt, tool definitions and tool calls: the
    agent listing, the deferred tools and the session context at the characters each held by the reply, the
    agent's thinking, and the other messages Claude Code sent (the share of the request's message notes that no
    row above lists: `injected` tokens of sources, the skills listing and the three listings). A row of no
    characters is left out."""
    measured = reply.measure
    if measured is None:
        return []
    size, scale = measured.size, measured.scale
    rows = _listing_rows(own, frame, reply, scale, names)
    listed = reply.parts[COMPOSITION_KEYS.index("skill_listing")] + injected + sum(row.tokens_est for row in rows)
    if size.parts.thinking > 0:
        rows.append(_harness_row("thinking", size.parts.thinking, names, scale))
    if size.parts.notes > 0:
        rows.append(_harness_row("harness_other", size.parts.notes, names, scale, taken=listed))
    return rows


def _absorb_rounding(rows: list[XrayContextRow], surplus: int) -> list[XrayContextRow]:
    """`rows` with a negative `surplus` (the rounding of each row to whole tokens) taken off the largest one."""
    big = max(range(len(rows)), key=lambda i: rows[i].tokens_est)
    return [replace(row, tokens_est=row.tokens_est + surplus) if i == big else row for i, row in enumerate(rows)]


def _measured_rows(
    measured: RequestMeasure,
    reply: ReplyComposition,
    opening: Sequence[XrayContextRow],
    defined: int,
    *,
    texts: dict[ContextKey, XrayContextText],
    names: dict[ContextKey, str],
    extra: Sequence[XrayContextRow],
    own_request: bool = True,
) -> list[XrayContextRow]:
    """The rows after the opening ones for a measured peak: the system prompt without the agent definition (already
    listed above), the tool definitions, the tool calls and results, the skills listing when the reply held one,
    the `extra` rows of the reply's own request, and the conversation, which takes what is left of the total, at 0
    when the rest overshoots it. A reply whose own request was not recorded (`own_request` False) takes the sizes
    of the newest earlier measured request for the system prompt and the tool definitions only, and its
    conversation row keeps the tool calls and results."""
    shares = _measured_shares(measured, defined)
    shares = shares if own_request else [item for item in shares if item[0] != "tool_io"]
    listing = reply.parts[COMPOSITION_KEYS.index("skill_listing")]
    if listing > 0:
        shares.append(("skill_listing", listing, None))
    rows = [
        XrayContextRow(key, None, None, names[key], "", tokens, None, None, row_measure)
        for key, tokens, row_measure in shares
    ]
    rows.extend(extra)
    left = reply.total - sum(row.tokens_est for row in (*opening, *rows))
    if own_request and -len(rows) - len(opening) <= left < 0:
        rows, left = _absorb_rounding(rows, left), 0
    rest = texts["conversation" if own_request else "rest"]
    return [*rows, XrayContextRow("rest", None, None, rest.label, rest.reason, max(0, left), None, None)]


def _tail_rows(
    reply: ReplyComposition,
    opening: Sequence[XrayContextRow],
    taken: tuple[int, int],
    *,
    texts: dict[ContextKey, XrayContextText],
    names: dict[ContextKey, str],
    extra: Sequence[XrayContextRow],
) -> list[XrayContextRow]:
    """The rows after the opening ones: the shares of the request the reply is sized from (its own, else the latest
    complete one before it), or the estimated closing rows when none sizes it."""
    if reply.sized is None:
        return _closing_rows(reply, opening, taken, texts)
    return _measured_rows(
        reply.sized, reply, opening, taken[1], texts=texts, names=names, extra=extra, own_request=reply.measured
    )


def _row_names(vocabulary: AdapterVocabulary) -> dict[ContextKey, str]:
    """The label of each kind of "in context" row, as the vocabulary words it."""
    context = vocabulary.context
    return {item.key: item.label for item in context.texts} | {item.key: item.label for item in context.builtin}


def _own_and_rows(
    own: AgentRecords,
    world: AgentWorld,
    reply: ReplyComposition,
    opening: Sequence[XrayContextRow],
    *,
    taken: tuple[int, int],
    injected: int,
    texts: dict[ContextKey, XrayContextText],
) -> tuple[XrayOwnContext, tuple[XrayContextRow, ...]]:
    """The coding agent's own context as one group, and the rows that stay: the `opening` rows, then the tail."""
    names = _row_names(world.context.vocabulary)
    extra = _harness_shares(own, world.frame, reply, injected, names)
    tail = _tail_rows(reply, opening, taken, texts=texts, names=names, extra=extra)
    group, kept = own_context(tail, own, world.frame, reply, world.context.vocabulary)
    return group, (*opening, *kept)


def build_in_context(
    own: AgentRecords,
    run_type: str | None,
    series: tuple[XrayComposition, tuple[CarriedReply, ...]],
    world: AgentWorld,
    brief_chars: int | None,
) -> XrayInContext | None:
    """What the agent's context held at its peak reply: its task prompt (a subagent), its definition, the sources
    loaded by then (inherited first, then by time), the hooks that fired, the tool calls and results, and the
    conversation as what is left, with the coding agent's own context as one group beside them. A reply whose
    request was recorded holds the group's items as measured shares of that request. A reply whose request was not
    recorded, after a complete one, holds that earlier request's system prompt, tool definitions and skills listing
    (the request and its tokens per character are named), and the conversation and tool results as what is left,
    labelled an estimate. With no complete request before it, the group is the estimated system prompt and
    listings, and the conversation and tool results take what the estimates leave. The rows and the group may
    overshoot the total; the last row is then 0 and `over` is set. None when the agent has no reply."""
    composition, carried = series
    if composition.peak is None:
        return None
    reply = composition.replies[composition.peak]
    texts = {item.key: item for item in world.context.vocabulary.context.texts}
    rows, mcp, defined, injected = _opening_rows(
        own,
        run_type,
        brief_chars,
        reply_t=reply.t,
        carried=carried[composition.peak],
        texts=texts,
        world=world,
    )
    group, shown = _own_and_rows(own, world, reply, rows, taken=(mcp, defined), injected=injected, texts=texts)
    return XrayInContext(
        reply.total,
        shown,
        group,
        sum(row.tokens_est for row in shown) + group.tokens_est != reply.total,
        reply.measured,
        None if reply.measured else texts["estimated"].reason,
        None if reply.sized is None else reply.sized.size.request_id,
        None if reply.sized is None else reply.sized.scale,
    )
