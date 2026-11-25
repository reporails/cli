"""Workflow runs of an agent session: ids, titles, labels and counts; never prompt or result text."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# The state of a workflow run: `running` (no record file yet, or the record says so), a state a record file names, or
# `unreadable` (the record file is not JSON or not the shape the adapter is pinned to).
WorkflowStatus = Literal["running", "completed", "failed", "killed", "unreadable"]
# The states a record file may name.
RECORDED_STATUSES: tuple[WorkflowStatus, ...] = ("running", "completed", "failed", "killed")


@dataclass(frozen=True)
class WorkflowAgent:
    """One agent of a workflow run: its id, the index and title of its phase, its label and the size in characters
    of the output the run accepted from it (None while the run has accepted none). `phase_index` is the place of the
    agent's phase among the run's phases. While the run has no record file, a phase title or label the agent's files
    do not state is None, and so is the index of an agent with no phase title."""

    agent_id: str
    phase_index: int | None
    phase_title: str | None
    label: str | None
    result_chars: int | None


@dataclass(frozen=True)
class WorkflowRun:
    """One workflow run of a session: its id, name and status (`running` while the run has no record file), the
    titles of its phases, its duration in milliseconds, its token total and its start time in milliseconds since 1970
    (None while the run has no record file), and its agents."""

    run_id: str
    name: str | None
    status: WorkflowStatus
    phases: tuple[str, ...]
    duration_ms: int | None
    total_tokens: int | None
    start_time: int | None
    agents: tuple[WorkflowAgent, ...]


@dataclass(frozen=True)
class WorkflowRefused:
    """A workflow run whose record file is not JSON or not the shape the adapter is pinned to: its id and what was
    wrong."""

    run_id: str
    reason: str
