"""What each agent type was launched with, read from the first request each subagent's file records."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence

from reporails_cli.core.platform.dto.events import EventRecord, RequestSize, SubagentMeta
from reporails_cli.core.platform.dto.xray_sources import AgentLaunch
from reporails_cli.core.xray.derive import tokens_of


def first_requests(records: Sequence[EventRecord]) -> dict[str, RequestSize]:
    """The first request each subagent's file records, by subagent id."""
    first: dict[str, RequestSize] = {}
    for record in records:
        if record.subagent_id is not None and record.request is not None:
            first.setdefault(record.subagent_id, record.request)
    return first


def launch_metas(records: Sequence[EventRecord]) -> dict[str, SubagentMeta]:
    """What each subagent's meta file says about its launch, by subagent id."""
    return {
        record.subagent_id: record.launch
        for record in records
        if record.event == "subagent_run" and record.subagent_id is not None and record.launch is not None
    }


def _grouped(values: list[str]) -> str | None:
    """The one value every launch agrees on, else each value with its launch count, most launches first then by
    name; None when no launch has a value."""
    if not values:
        return None
    counts = Counter(values)
    if len(counts) == 1:
        return values[0]
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return "; ".join(f"{value} · {count} launch{'' if count == 1 else 'es'}" for value, count in ordered)


def _yes_no(flag: bool | None) -> str:
    return "not recorded" if flag is None else "yes" if flag else "no"


def _settings(
    ids: list[str], first: dict[str, RequestSize], metas: dict[str, SubagentMeta]
) -> tuple[tuple[str, str], ...]:
    """The launch settings of the launches `ids`, each as one line grouped over the launches that carry it."""
    ran = [metas[node_id] for node_id in ids if node_id in metas]
    configs = [first[node_id].config for node_id in ids if node_id in first]
    rows = (
        ("Model asked for", [meta.asked_model or "default" for meta in ran]),
        ("Model in requests", [config.model for config in configs if config.model is not None]),
        (
            "Launched with defaults",
            [_yes_no(metas[node_id].with_defaults if node_id in metas else None) for node_id in ids],
        ),
        ("Background", [_yes_no(meta.background) for meta in ran]),
        ("Thinking", [config.thinking for config in configs if config.thinking is not None]),
        ("Effort", [config.effort for config in configs if config.effort is not None]),
        ("Max tokens", [str(config.max_tokens) for config in configs if config.max_tokens is not None]),
    )
    return tuple((label, text) for label, values in rows if (text := _grouped(values)) is not None)


def first_launch(launch_ids: Iterable[str], first: dict[str, RequestSize]) -> str | None:
    """The lowest id among `launch_ids` whose file recorded a request; None when none did."""
    return next((node_id for node_id in sorted(launch_ids) if node_id in first), None)


def launched_with(
    launch_ids: Iterable[str], first: dict[str, RequestSize], metas: dict[str, SubagentMeta]
) -> AgentLaunch | None:
    """The system prompt size in tokens of the first launch (lowest id) that recorded a request (None when none
    did), each tool the launches were sent with and how many launches had it, most launches first then by name, and
    the launch settings; None when no launch recorded a request or a launch setting."""
    ids = list(launch_ids)
    chosen = first_launch(ids, first)
    if chosen is None and not any(node_id in metas for node_id in ids):
        return None
    counts = Counter(name for node_id in ids if node_id in first for name in set(first[node_id].tool_names))
    return AgentLaunch(
        tokens_of(first[chosen].system_chars) if chosen is not None else None,
        tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0]))),
        _settings(ids, first, metas),
    )
