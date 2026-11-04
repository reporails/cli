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
    RequestMeasure,
    XrayComposition,
)
from reporails_cli.core.platform.dto.xray_sources import XrayBuiltin
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


def _earlier_note(note: str | None, measured: RequestMeasure) -> str:
    """`note` with the request the size was measured from, when the newest reply's own request was not recorded
    yet."""
    return f"{note or ''} Sized from the earlier request {measured.size.request_id}.".strip()


def builtin_items(
    main: ProducedNode, records: Sequence[EventRecord], vocabulary: AdapterVocabulary
) -> tuple[XrayBuiltin, ...]:
    """The coding agent's own context in the vocabulary's order. A harness item's size is read from its records.
    The system prompt and the tool definitions are in no record: when the main agent's peak reply was measured they
    are shares of the request recorded for it, and when it was not, of the request of the newest reply that was
    measured; otherwise the system prompt is what the main agent's remainder
    category holds at its peak reply after the other harness items inside that category, never below 0, and there
    is no tool definitions item."""
    composition = main.detail.usage.composition
    held = {item.kind: item for item in build_harness(records, replies_of(records)) or ()}
    measured = None if composition.peak is None else composition.replies[composition.peak].measure
    from_earlier = measured is None and composition.latest_measure is not None
    measured = composition.latest_measure if measured is None else measured
    system = _estimated_system(composition, held) if measured is None else None
    shapes = _main_system_shapes(records)
    found: list[XrayBuiltin] = []
    for info in vocabulary.context.builtin:
        item = held.get(info.key)
        if info.key == "system_prompt" and measured is not None:
            size, scale = measured.size, measured.scale
            note = info.measured_note or info.note
            note = _earlier_note(note, measured) if from_earlier else note
            found.append(
                XrayBuiltin(info.key, info.label, share(size.system_chars, scale), note, info.visible, False, shapes)
            )
        elif info.key == "system_prompt":
            if system is not None:
                found.append(XrayBuiltin(info.key, info.label, system, info.note, info.visible, True, shapes))
        elif info.key == "tool_definitions":
            if measured is not None:
                size, scale = measured.size, measured.scale
                note = count_text(info.note, info.note_once, size.tool_count)
                note = _earlier_note(note, measured) if from_earlier else note
                found.append(
                    XrayBuiltin(info.key, info.label, share(size.tools_chars, scale), note, info.visible, False)
                )
        elif item is not None:
            note = count_text(info.note, info.note_once, item.count)
            found.append(XrayBuiltin(info.key, info.label, item.tokens_est or 0, note, info.visible, False))
    return tuple(found)
