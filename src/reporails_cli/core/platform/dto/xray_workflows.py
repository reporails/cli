"""The workflow runs of a session as numbers, names and phases: each run's phases with the nodes of the agents
that ran in them.

A value with no source is `None`, which reads as "not known here".
"""

from __future__ import annotations

from dataclasses import dataclass

from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.xray_graph import objects


@dataclass(frozen=True)
class XrayWorkflowPhase:
    """One phase of a workflow run: its title and the nodes of the agents that ran in it."""

    title: str
    agents: tuple[str, ...]

    def to_json(self) -> JsonObject:
        """The phase as a JSON object."""
        return {"title": self.title, "agents": list(self.agents)}


@dataclass(frozen=True)
class XrayWorkflow:
    """One workflow run of a session: its id, name (None while the run has no record file or when the record is not
    readable), status, phases with their agents, how many agents it has, when its first agent started in seconds on the
    session's clock (None when the run has no agent and no start time), its duration and its token total. A run whose
    record file is not the shape the adapter is pinned to has `refusal` set to what was wrong and no name, duration
    or token total."""

    run_id: str
    name: str | None
    status: str
    phases: tuple[XrayWorkflowPhase, ...]
    agent_count: int
    start: float | None
    duration_ms: int | None
    total_tokens: int | None
    refusal: str | None

    def to_json(self) -> JsonObject:
        """The run as a JSON object."""
        return {
            "run_id": self.run_id,
            "name": self.name,
            "status": self.status,
            "phases": objects(phase.to_json() for phase in self.phases),
            "agent_count": self.agent_count,
            "start": self.start,
            "duration_ms": self.duration_ms,
            "total_tokens": self.total_tokens,
            "refusal": self.refusal,
        }
