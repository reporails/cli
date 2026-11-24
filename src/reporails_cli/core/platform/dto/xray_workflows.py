"""The workflow runs of a session as numbers, names and phases: each run's phases with the nodes of the agents
that ran in them.

A value with no source is `None`, which reads as "not known here".
"""

from __future__ import annotations

from dataclasses import dataclass

from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.workflows import WorkflowStatus
from reporails_cli.core.platform.dto.xray_graph import objects


@dataclass(frozen=True)
class XrayWorkflowPhase:
    """One phase of a workflow run, in the place the record gives it (two phases may share a title): its title and the
    nodes of the agents that ran in it."""

    title: str
    agents: tuple[str, ...]

    def to_json(self) -> JsonObject:
        """The phase as a JSON object."""
        return {"title": self.title, "agents": list(self.agents)}


@dataclass(frozen=True)
class XrayWorkflow:
    """One workflow run of a session: its id, name (None while the run has no record file or when the record is not
    readable), its status as a closed word and the phrase the page shows for it, phases with their agents, the nodes
    of the agents that are in no known phase, how many agents it lists (those in a phase and those in none), when its
    first agent started in seconds on the session's clock (None when the run has no agent and no start time), the
    segment of the main agent's context it started in, its duration and its token total. A run whose record file is
    not JSON or not the shape the adapter is pinned to has `refusal` set to what was wrong and no name, duration or
    token total."""

    run_id: str
    name: str | None
    status: WorkflowStatus
    status_text: str
    phases: tuple[XrayWorkflowPhase, ...]
    unphased: tuple[str, ...]
    agent_count: int
    start: float | None
    segment: int
    duration_ms: int | None
    total_tokens: int | None
    refusal: str | None

    def to_json(self) -> JsonObject:
        """The run as a JSON object."""
        return {
            "run_id": self.run_id,
            "name": self.name,
            "status": self.status,
            "status_text": self.status_text,
            "phases": objects(phase.to_json() for phase in self.phases),
            "unphased": list(self.unphased),
            "agent_count": self.agent_count,
            "start": self.start,
            "segment": self.segment,
            "duration_ms": self.duration_ms,
            "total_tokens": self.total_tokens,
            "refusal": self.refusal,
        }
