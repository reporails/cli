"""What an agent's context is made of at each of its replies.

A reply's total and cache split are exact. The loaded files, hook notes, skills listing, typed prompts, the agent's
own text and the tool results before the reply are estimated from the sizes its records hold; what the estimates
leave of the total is the system prompt and tool definitions.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

from reporails_cli.core.platform.dto.events import EventRecord, TokenUsage
from reporails_cli.core.platform.dto.xray_build import AgentRecords, Frame, HarnessSlot, SourceTable
from reporails_cli.core.platform.dto.xray_composition import (
    COMPOSITION_KEYS,
    ESTIMATED_KEYS,
    REMAINDER_KEY,
    CompositionKey,
    ReplyComposition,
    XrayComposition,
)
from reporails_cli.core.platform.dto.xray_graph import SourceKind
from reporails_cli.core.xray.derive import context_of, frame_time, tokens_of

# The category each source kind's loads count in; a kind not listed (an MCP server) falls in the remainder.
_LOAD_CATEGORY: dict[SourceKind, CompositionKey] = {
    "instructions": "instructions",
    "rule": "rules_skills",
    "skill": "rules_skills",
    "memory": "memory",
    "hook": "hook_notes",
}

# (time, category, tokens): a size that enters the context at a time and stays.
type Added = tuple[float, CompositionKey, int]
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
        found.append((load.t, category, load.tokens_est or 0))
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
        found.append((moment, "skill_listing", size - held))
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


def _sweep(
    added: Sequence[Added], spoken: Sequence[Spoken], usages: Sequence[tuple[float, TokenUsage]]
) -> Iterator[tuple[float, TokenUsage, dict[CompositionKey, int]]]:
    """For each reply, what each estimated category holds at it: loads, hook notes and the skills
    listing up to and including the reply's time, conversation and tool results strictly before it."""
    held: dict[CompositionKey, int] = dict.fromkeys(ESTIMATED_KEYS, 0)
    ahead = 0
    behind = 0
    for moment, usage in usages:
        while ahead < len(added) and added[ahead][0] <= moment:
            _, category, tokens = added[ahead]
            held[category] += tokens
            ahead += 1
        while behind < len(spoken) and spoken[behind][0] < moment:
            _, grown, size = spoken[behind]
            if grown is None:
                held["conversation"] = held["tool_results"] = 0
            else:
                held[grown] += size
            behind += 1
        yield moment, usage, held


def _timeline(
    own: AgentRecords, sources: SourceTable, frame: Frame, brief_chars: int | None
) -> tuple[list[Added], list[Spoken]]:
    added = sorted([*_load_deltas(own, sources), *_skill_listing_deltas(own, frame)], key=lambda item: item[0])
    spoken = sorted(_spoken_deltas(own, frame, brief_chars), key=lambda item: item[0])
    return added, spoken


def composition_series(
    own: AgentRecords, sources: SourceTable, frame: Frame, brief_chars: int | None
) -> XrayComposition:
    """The composition of the agent's context at each of its replies; `brief_chars` is the size of the task brief a
    subagent was launched with (None for the main agent)."""
    added, spoken = _timeline(own, sources, frame, brief_chars)
    replies: list[ReplyComposition] = []
    for moment, usage, held in _sweep(added, spoken, _usages(own.records, frame)):
        total = context_of(usage)
        remainder = total - sum(held.values())
        parts = tuple(remainder if key == REMAINDER_KEY else held[key] for key in COMPOSITION_KEYS)
        replies.append(
            ReplyComposition(
                moment,
                total,
                usage.input_tokens,
                usage.cache_creation_input_tokens,
                usage.cache_read_input_tokens,
                parts,
                remainder < 0,
            )
        )
    peak = max(range(len(replies)), key=lambda index: replies[index].total) if replies else None
    return XrayComposition(tuple(replies), peak)
