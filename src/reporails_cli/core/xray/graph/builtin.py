"""The coding agent's own context as one group: the system prompt, the tool definitions, the listings, the
thinking and the other messages the coding agent sent, split off the rows of an agent's "in context" list."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from reporails_cli.core.platform.dto.events import HarnessKind
from reporails_cli.core.platform.dto.xray import AdapterVocabulary, XrayHarnessItem
from reporails_cli.core.platform.dto.xray_build import AgentRecords, Frame
from reporails_cli.core.platform.dto.xray_composition import COMPOSITION_KEYS, ReplyComposition, RequestMeasure
from reporails_cli.core.platform.dto.xray_graph import XrayContextRow
from reporails_cli.core.platform.dto.xray_own import (
    LISTED,
    LISTING_KEYS,
    OWN_KEYS,
    ContextKey,
    OwnBasis,
    XrayOwnContext,
    XrayOwnItem,
    XrayRowMeasure,
)
from reporails_cli.core.platform.dto.xray_sources import XrayBuiltinInfo
from reporails_cli.core.xray.derive import build_harness, frame_time, replies_of
from reporails_cli.core.xray.graph.composition import count_text, listing_chars, tokens_at

Share = tuple[ContextKey, int, XrayRowMeasure | None]


def _unsized_kinds(own: AgentRecords, frame: Frame, reply_t: float) -> list[str]:
    """The names of the attachment kinds that only named themselves by `reply_t`, in the order first seen."""
    found: dict[str, None] = {}
    for record in own.records:
        entry = record.harness
        moment = frame_time(frame, record)
        if record.event != "harness" or entry is None or entry.kind != "unsized":
            continue
        if moment is not None and moment <= reply_t:
            found[entry.label.replace("_", " ")] = None
    return list(found)


def _described(info: XrayBuiltinInfo, count: int | None, kinds: Sequence[str]) -> str | None:
    """What an item holds, in the vocabulary's words for its count, or for the kinds of message it lists."""
    if info.note_none is None:
        return count_text(info.note, info.note_once, count)
    return info.note.format(kinds=", ".join(kinds)) if kinds and info.note else info.note_none


def _count(key: ContextKey, sized: RequestMeasure | None, held: Mapping[HarnessKind, XrayHarnessItem]) -> int | None:
    """How many things an item lists: the tools of the request, or the entries of its recorded listing."""
    if key == "tool_definitions":
        return None if sized is None else sized.size.tool_count
    item = held.get(LISTED[key]) if key in LISTED else None
    return None if item is None else item.count


def _basis(reply: ReplyComposition) -> OwnBasis:
    if reply.measure is not None:
        return "measured"
    return "estimate" if reply.sized is None else "measured_earlier"


def _estimated(group: XrayContextRow | None, own: AgentRecords, frame: Frame, reply: ReplyComposition) -> list[Share]:
    """The items of a context no recorded request sizes: each listing at four characters to a token, the skills
    listing from the reply's categories, and everything else as what the group row leaves of them, never below
    0 (the system prompt, the tool definitions and the rest are not told apart without a request)."""
    listed: list[Share] = []
    for key in LISTING_KEYS:
        chars = listing_chars(own, frame, LISTED[key], reply.t)
        if chars > 0:
            listed.append((key, tokens_at(chars, None), None))
    skills = reply.parts[COMPOSITION_KEYS.index("skill_listing")]
    if skills > 0:
        listed.append(("skill_listing", skills, None))
    system = max(0, (0 if group is None else group.tokens_est) - sum(tokens for _, tokens, _ in listed))
    return [("built_in_rest", system, None), *listed]


def _items(
    shares: list[Share],
    infos: Mapping[ContextKey, XrayBuiltinInfo],
    own: AgentRecords,
    frame: Frame,
    reply: ReplyComposition,
) -> tuple[XrayOwnItem, ...]:
    """The items of the own context, one per share in display order, each with what it holds and whether a recorded
    request holds its text."""
    sized = reply.sized
    group_basis = _basis(reply)
    held = {item.kind: item for item in build_harness(own.records, replies_of(own.records)) or ()}
    kinds = _unsized_kinds(own, frame, reply.t)
    shapes = len({record.request.system_digest for record in own.records if record.request})
    return tuple(
        XrayOwnItem(
            key,
            infos[key].label,
            _described(infos[key], _count(key, sized, held), kinds),
            tokens,
            measure,
            infos[key].visible,
            sized is not None,
            shapes if key == "system_prompt" else 0,
            group_basis if measure is not None else "estimate",
            tokens + (0 if measure is None else measure.listed_above),
            infos[key].unread,
        )
        for key, tokens, measure in sorted(shares, key=lambda share: OWN_KEYS.index(share[0]))
    )


def own_context(
    tail: Sequence[XrayContextRow],
    own: AgentRecords,
    frame: Frame,
    reply: ReplyComposition,
    vocabulary: AdapterVocabulary,
) -> tuple[XrayOwnContext, list[XrayContextRow]]:
    """The coding agent's own context taken out of `tail`, the rows after the opening ones, and the rows that stay.
    A reply whose request was recorded (its own, else the latest complete one before it) holds the items as
    measured shares of that request; with none, the group's single row is split into items estimated from the
    recorded listings. The group's size is the sum of its items, or the group row's size for an estimate."""
    infos = {item.key: item for item in vocabulary.context.builtin}
    text = next(item for item in vocabulary.context.texts if item.key == "builtin")
    group = next((row for row in tail if row.key == "builtin"), None)
    taken = {row.key: row for row in tail if row.key in OWN_KEYS}
    kept = [row for row in tail if row.key not in OWN_KEYS and row.key != "builtin"]
    sized = reply.sized
    shares: list[Share] = (
        _estimated(group, own, frame, reply)
        if sized is None
        else [(key, taken[key].tokens_est, taken[key].measure) for key in OWN_KEYS if key in taken]
    )
    items = _items(shares, infos, own, frame, reply)
    total = sum(item.tokens_est for item in items) if sized is not None or group is None else group.tokens_est
    return (
        XrayOwnContext(
            text.label,
            text.reason,
            total,
            _basis(reply),
            None if sized is None else sized.size.request_id,
            None if sized is None else sized.scale,
            items,
        ),
        kept,
    )
