"""How many artifacts of each kind sit on disk, are advertised, load and are used."""

from __future__ import annotations

from collections.abc import Sequence
from typing import get_args

from reporails_cli.core.platform.dto.xray import (
    RUNNABLE_ARTIFACT_KINDS,
    ArtifactKind,
    XrayArtifact,
    XrayFunnelRow,
    XraySubagent,
    XrayTurn,
)
from reporails_cli.core.xray.artifacts import winners


def _run_paths(turns: Sequence[XrayTurn], subagents: Sequence[XraySubagent]) -> set[str]:
    """The paths of the skill and command files that ran anywhere, a forked run included."""
    runs = [run for turn in turns for run in turn.skill_runs] + [run for sub in subagents for run in sub.skill_runs]
    return {run.path for run in runs if run.path is not None}


def _agent_run_paths(artifacts: Sequence[XrayArtifact], subagents: Sequence[XraySubagent]) -> set[str]:
    """The paths of the agent files a subagent ran as."""
    agents = winners(artifacts, frozenset({"agent"}))
    return {agents[run.type].path for run in subagents if run.type in agents}


def _used(kind: ArtifactKind, items: Sequence[XrayArtifact], ran: set[str], agents: set[str]) -> int | None:
    if kind in RUNNABLE_ARTIFACT_KINDS:
        return sum(1 for item in items if item.path in ran)
    if kind == "agent":
        return sum(1 for item in items if item.path in agents)
    if kind == "memory":
        return sum(1 for item in items if item.linked is True and item.loaded)
    return None


def build_funnel(
    artifacts: Sequence[XrayArtifact], turns: Sequence[XrayTurn], subagents: Sequence[XraySubagent]
) -> tuple[XrayFunnelRow, ...]:
    """One row per kind that has an artifact on disk, in the kind vocabulary's order."""
    ran = _run_paths(turns, subagents)
    agents = _agent_run_paths(artifacts, subagents)
    rows: list[XrayFunnelRow] = []
    for kind in get_args(ArtifactKind):
        items = [item for item in artifacts if item.kind == kind]
        if not items:
            continue
        marks = [item.advertised for item in items if item.advertised is not None]
        rows.append(
            XrayFunnelRow(
                kind=kind,
                on_disk=len(items),
                advertised=sum(marks) if marks else None,
                loaded=None if kind == "hook" else sum(1 for item in items if item.loaded),
                used=_used(kind, items, ran, agents),
            )
        )
    return tuple(rows)
