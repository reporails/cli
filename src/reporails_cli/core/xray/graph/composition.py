"""What an agent's context is made of at each of its replies.

A reply's total and cache split are exact. Every size the records hold is kept in characters. When the request the
reply answered was recorded, the exact total is split by that request's measured sizes, and the characters of the
loaded files, hook notes, skills listing and the other listings become tokens at that request's tokens per
character: system prompt, tool definitions, tool calls and results, thinking and the harness's own messages are
shares of it, and the conversation takes what is left, which is what the user and the agent wrote. When the request
was not recorded, the characters become tokens at four characters to a token: the loaded files, hook notes, skills
listing, typed prompts, the agent's own text and the tool results before the reply are estimated from the sizes
its records hold; what the estimates leave of the total is the system prompt and tool definitions.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

from reporails_cli.core.platform.dto.events import (
    DELTA_KINDS,
    EventRecord,
    HarnessKind,
    RequestSize,
    TokenUsage,
)
from reporails_cli.core.platform.dto.xray_build import (
    AgentRecords,
    Frame,
    HarnessSlot,
    SourceTable,
)
from reporails_cli.core.platform.dto.xray_compaction import IN_CONTEXT_FILE_STATES, XrayCompaction
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
    SourceKind,
)
from reporails_cli.core.xray.derive import context_of, frame_time, tokens_of

# The category each source kind's loads count in; a kind not listed (an MCP server) falls in the remainder.
_LOAD_CATEGORY: dict[SourceKind, CompositionKey] = {
    "instructions": "instructions",
    "rule": "rules_skills",
    "skill": "rules_skills",
    "memory": "memory",
    "hook": "hook_notes",
}

# (time, category, characters, source id or None): a size that enters the context at a time and stays.
type Added = tuple[float, CompositionKey, int, str | None]
# (time, category, characters, left): conversation and tool-result sizes; a category of None is a compaction, and
# `left` holds the sources it takes out of the context (loaded files it did not put back).
type Spoken = tuple[float, CompositionKey | None, int, frozenset[str]]


def _left(compaction: XrayCompaction) -> frozenset[str]:
    """The sources `compaction` took out of the agent's context: its files whose content it did not put back."""
    return frozenset(item.source for item in compaction.files if item.state not in IN_CONTEXT_FILE_STATES)


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
        if category is None or load.t is None or load.chars is None:
            continue
        if category != "hook_notes":
            if load.source in seen and not _left_between(own, load.source, seen[load.source], load.t):
                continue
            seen[load.source] = load.t
        found.append((load.t, category, load.chars, load.source))
    return found


def _listing_sizes(own: AgentRecords, frame: Frame, kind: HarnessKind) -> list[tuple[float, int]]:
    """The size in characters of the `kind` harness item at each of its records: the first row, then the delta rows
    of a list kind up to the first compaction, summed as the harness items are."""
    found: list[tuple[float, int]] = []
    slot: HarnessSlot | None = None
    compacted = False
    for record in own.records:
        entry = record.harness
        moment = frame_time(frame, record)
        if record.event == "post_compact":
            compacted = True
        if record.event != "harness" or entry is None or entry.kind != kind or moment is None:
            continue
        if slot is None:
            slot = HarnessSlot.of(entry)
        elif compacted or kind not in DELTA_KINDS:
            continue
        else:
            slot.add(entry)
        found.append((moment, slot.chars))
    return found


def _skill_listing_deltas(own: AgentRecords, frame: Frame) -> list[Added]:
    """The change in the skills listing's characters at each of its records."""
    found: list[Added] = []
    held = 0
    for moment, size in _listing_sizes(own, frame, "skill_list"):
        found.append((moment, "skill_listing", size - held, None))
        held = size
    return found


def listing_chars(own: AgentRecords, frame: Frame, kind: HarnessKind, reply_t: float) -> int:
    """The characters the `kind` harness item held at `reply_t`; 0 when none of its records came by then."""
    return next((size for moment, size in reversed(_listing_sizes(own, frame, kind)) if moment <= reply_t), 0)


def _spoken_deltas(own: AgentRecords, frame: Frame, brief_chars: int | None) -> list[Spoken]:
    """What the conversation and the tool results grew by in characters at each record, and every compaction."""
    found: list[Spoken] = []
    none: frozenset[str] = frozenset()
    left = {item.t: _left(item) for item in own.compactions}
    if brief_chars is not None:
        found.append((float("-inf"), "conversation", brief_chars, none))
    for record in own.records:
        moment = frame_time(frame, record)
        if moment is None:
            continue
        if record.event == "post_compact":
            found.append((moment, None, 0, left.get(moment, none)))
        elif record.event == "prompt_submit" and record.prompt is not None:
            found.append((moment, "conversation", record.prompt.chars, none))
        elif record.event == "assistant_text" and record.reply is not None:
            found.append((moment, "conversation", record.reply.chars, none))
        elif record.event == "tool_result" and record.tool is not None and record.tool.chars is not None:
            found.append((moment, "tool_results", record.tool.chars, none))
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
    """Apply one load: its characters join its category and, with an id, its source's carried characters."""
    _, category, chars, source = load
    held[category] += chars
    if source is None:
        return
    homes[source] = category
    carried[source] = carried.get(source, 0) + chars
    if category == "hook_notes":
        hooks.add(source)


def _take_spoken(
    held: dict[CompositionKey, int],
    carried: dict[str, int],
    homes: dict[str, CompositionKey],
    hooks: set[str],
    item: Spoken,
) -> dict[str, int]:
    """Apply one conversation, tool result or compaction entry; returns the carried characters after it."""
    _, grown, size, left = item
    if grown is not None:
        held[grown] += size
        return carried
    held["conversation"] = held["tool_results"] = held["hook_notes"] = 0
    for source in left & carried.keys():
        held[homes[source]] -= carried[source]
    kept = {source: chars for source, chars in carried.items() if source not in hooks and source not in left}
    hooks.clear()
    return kept


def _sweep(
    added: Sequence[Added], spoken: Sequence[Spoken], usages: Sequence[tuple[float, TokenUsage]]
) -> Iterator[tuple[float, TokenUsage, dict[CompositionKey, int], dict[str, int]]]:
    """For each reply, the characters each estimated category holds at it: loads, hook notes and the skills
    listing up to and including the reply's time, conversation and tool results strictly before it; and the
    characters each source that has an id contributed. A compaction empties the conversation, the tool results and
    the hook notes with the hook sources' characters, and takes out the loaded files that were neither kept nor
    reloaded. The two streams are applied in time order, so a hook note landing after a compaction survives it; at
    equal times the compaction goes first, because a note stamped with the compaction's own instant is what the
    compaction's aftermath loads."""
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


def tokens_at(chars: int, measured: RequestMeasure | None) -> int:
    """`chars` characters as tokens of a reply: at the tokens per character of its measured request, else at the
    estimate's four characters to a token."""
    return tokens_of(chars) if measured is None else share(chars, measured.scale)


def tool_share(measured: RequestMeasure) -> int:
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
    """One reply's row: its exact total and cache split and its categories, `held` characters turned into tokens at
    the measured request's scale. A reply whose request was recorded takes its system, tools and tool-result shares
    from the request and the conversation from what the rest leave. Any other keeps the remainder in its own
    category, except that when an earlier request sizes it (`sized`) the remainder category holds only that
    request's system and tool share and the conversation takes the rest."""
    total = context_of(usage)
    held = {key: tokens_at(chars, measured) for key, chars in held.items()}
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
        "tool_results": tool_share(measured),
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
    """The composition of the agent's context at each of its replies, and for each reply the characters each source
    carried in it; `brief_chars` is the size of the task brief a subagent was launched with (None for the main
    agent)."""
    added, spoken = _timeline(own, sources, frame, brief_chars)
    sizes = _request_sizes(own.records)
    # the sweep reuses one table of held characters, so each reply keeps its own copy
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
    carried = tuple(
        CarriedReply(usage, measure, by_source)
        for (_, usage, _, by_source), measure in zip(swept, measures, strict=True)
    )
    peak = max(range(len(replies)), key=lambda index: replies[index].total) if replies else None
    return XrayComposition(replies, peak), carried


def count_text(many: str | None, once: str | None, count: int | None) -> str | None:
    """The wording of a vocabulary entry for `count` entries: `once` for a count of one when the entry has one,
    else `many`, with `{count}` filled in; None when the wording needs a count that is missing."""
    template = once if count == 1 and once is not None else many
    if template is None or "{count}" not in template:
        return template
    return None if count is None else template.format(count=count)
