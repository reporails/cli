"""The coding agent's own built-in context items: the system prompt, the tool definitions and the harness items
whose sizes sit in the remainder category of its replies."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from reporails_cli.core.platform.dto.events import EventRecord, HarnessKind, is_note_kind
from reporails_cli.core.platform.dto.xray import AdapterVocabulary, XrayHarnessItem
from reporails_cli.core.platform.dto.xray_build import ProducedNode
from reporails_cli.core.platform.dto.xray_composition import (
    COMPOSITION_KEYS,
    REMAINDER_KEY,
    ReplyComposition,
    RequestMeasure,
    XrayComposition,
)
from reporails_cli.core.platform.dto.xray_sources import XrayBuiltin, XrayBuiltinInfo
from reporails_cli.core.xray.derive import build_harness, replies_of
from reporails_cli.core.xray.graph.composition import count_text, share

# The one harness kind a composition estimates as its own category; every other builtin kind is inside the remainder.
_LISTED_KIND: HarnessKind = "skill_list"


def _in_remainder(kind: HarnessKind) -> bool:
    """Whether a harness item's size sits in the remainder category: every kind except the skills listing and the
    hook notes, which have categories of their own, and the system prompt itself."""
    return kind not in (_LISTED_KIND, "system_prompt") and not is_note_kind(kind)


def _main_system_shapes(records: Sequence[EventRecord]) -> int:
    """How many different system prompts the main agent's recorded requests were sent with."""
    return len({record.request.system_digest for record in records if record.subagent_id is None and record.request})


def _estimated_system(composition: XrayComposition, held: Mapping[HarnessKind, XrayHarnessItem]) -> int | None:
    """The system prompt's estimated size: what the peak reply's remainder category holds after the other harness
    items inside it, never below 0; None when no reply was recorded."""
    if composition.peak is None:
        return None
    reply = composition.replies[composition.peak]
    inside = sum((item.tokens_est or 0) for kind, item in held.items() if _in_remainder(kind))
    return max(0, reply.parts[COMPOSITION_KEYS.index(REMAINDER_KEY)] - inside)


def _sized_note(own: str | None, info: XrayBuiltinInfo, reply: ReplyComposition, sized: RequestMeasure) -> str | None:
    """The note of a size measured from `sized`: `own` when it is the reply's own request, else the item's note that
    names the earlier request it was measured from."""
    if reply.measured or info.earlier_note is None:
        return own
    return info.earlier_note.replace("{request}", sized.size.request_id)


def builtin_items(
    main: ProducedNode, records: Sequence[EventRecord], vocabulary: AdapterVocabulary
) -> tuple[XrayBuiltin, ...]:
    """The coding agent's own context in the vocabulary's order. A harness item's size is read from its records.
    The system prompt and the tool definitions are in no record: they are shares of the request the main agent's peak
    reply is sized from (its own recorded request, else the latest complete one before it, which the note names);
    with none, the system prompt is what the main agent's remainder category holds at its peak reply after the
    other harness items inside that category, never below 0, and there is no tool definitions item."""
    composition = main.detail.usage.composition
    held = {item.kind: item for item in build_harness(records, replies_of(records)) or ()}
    reply = None if composition.peak is None else composition.replies[composition.peak]
    sized = None if reply is None else reply.sized
    system = _estimated_system(composition, held) if sized is None else None
    shapes = _main_system_shapes(records)
    found: list[XrayBuiltin] = []
    for info in vocabulary.context.builtin:
        item = held.get(info.key)
        if info.key == "system_prompt" and reply is not None and sized is not None:
            note = _sized_note(info.measured_note, info, reply, sized) or info.note
            tokens = share(sized.size.system_chars, sized.scale)
            found.append(XrayBuiltin(info.key, info.label, tokens, note, info.visible, False, shapes))
        elif info.key == "system_prompt":
            if system is not None:
                found.append(XrayBuiltin(info.key, info.label, system, info.note, info.visible, True, shapes))
        elif info.key == "tool_definitions":
            if reply is not None and sized is not None:
                counted = count_text(info.note, info.note_once, sized.size.tool_count)
                tokens = share(sized.size.tools_chars, sized.scale)
                note = _sized_note(counted, info, reply, sized)
                found.append(XrayBuiltin(info.key, info.label, tokens, note, info.visible, False))
        elif item is not None:
            note = count_text(info.note, info.note_once, item.count)
            found.append(XrayBuiltin(info.key, info.label, item.tokens_est or 0, note, info.visible, False))
    return tuple(found)
