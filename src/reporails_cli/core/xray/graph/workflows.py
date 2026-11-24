"""The workflow runs of a session as nodes of the graph: each run with its phases and the agents that ran in them."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.events import EventRecord
from reporails_cli.core.platform.dto.workflows import WorkflowAgent, WorkflowRefused, WorkflowRun
from reporails_cli.core.platform.dto.xray_build import Frame, ProducedNode, WorkflowReading
from reporails_cli.core.platform.dto.xray_workflows import XrayWorkflow, XrayWorkflowPhase

# The status of a run whose record file the adapter refused.
UNREADABLE = "not readable"


def _start(run_start: int | None, agents: Sequence[str], nodes: dict[str, ProducedNode], frame: Frame) -> float | None:
    """When the run began on the session's clock: its first agent's start, else its recorded start time."""
    started = [nodes[agent].start for agent in agents if agent in nodes]
    if started:
        return min(started)
    return None if run_start is None else run_start / 1000.0 - frame.t0


def _phases(
    titles: Sequence[str], agents: Sequence[WorkflowAgent], nodes: dict[str, ProducedNode]
) -> tuple[XrayWorkflowPhase, ...]:
    """The run's phases in order, each with the nodes of the agents of that phase that the graph holds."""
    return tuple(
        XrayWorkflowPhase(
            title,
            tuple(agent.agent_id for agent in agents if agent.phase_title == title and agent.agent_id in nodes),
        )
        for title in titles
    )


def _read_run(run: WorkflowRun, nodes: dict[str, ProducedNode], frame: Frame) -> XrayWorkflow:
    return XrayWorkflow(
        run.run_id,
        run.name,
        run.status,
        _phases(run.phases, run.agents, nodes),
        run.agent_count,
        _start(run.start_time, [agent.agent_id for agent in run.agents], nodes, frame),
        run.duration_ms,
        run.total_tokens,
        None,
    )


def _unreadable(
    refused: WorkflowRefused, records: Sequence[EventRecord], nodes: dict[str, ProducedNode], frame: Frame
) -> XrayWorkflow:
    """The run shown as not readable: its phases and agents are the ones the subagent records name for it."""
    members = [
        WorkflowAgent(record.subagent_id, None, record.launch.workflow_phase, None)
        for record in records
        if record.event == "subagent_run"
        and record.launch is not None
        and record.launch.workflow_run == refused.run_id
        and record.subagent_id is not None
    ]
    titles = list(dict.fromkeys(agent.phase_title for agent in members if agent.phase_title is not None))
    ids = [agent.agent_id for agent in members]
    return XrayWorkflow(
        refused.run_id,
        None,
        UNREADABLE,
        _phases(titles, members, nodes),
        len(members),
        _start(None, ids, nodes, frame),
        None,
        None,
        refused.reason,
    )


def workflow_nodes(
    reading: WorkflowReading, records: Sequence[EventRecord], pnodes: Sequence[ProducedNode], frame: Frame
) -> tuple[XrayWorkflow, ...]:
    """The session's workflow runs, earliest first; a run whose record was refused is shown as not readable."""
    nodes = {node.id: node for node in pnodes}
    runs = [
        _unreadable(run, records, nodes, frame) if isinstance(run, WorkflowRefused) else _read_run(run, nodes, frame)
        for run in reading.runs
    ]
    return tuple(sorted(runs, key=lambda run: (run.start is None, run.start or 0.0, run.run_id)))
