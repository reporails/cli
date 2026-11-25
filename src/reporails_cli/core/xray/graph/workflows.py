"""The workflow runs of a session as nodes of the graph: each run with its phases and the agents that ran in them."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.events import EventRecord
from reporails_cli.core.platform.dto.workflows import WorkflowAgent, WorkflowRefused, WorkflowRun
from reporails_cli.core.platform.dto.xray_build import Frame, ProducedNode, WorkflowReading
from reporails_cli.core.platform.dto.xray_workflows import XrayWorkflow, XrayWorkflowPhase
from reporails_cli.core.xray.graph.spine import cuts_of, segment_of
from reporails_cli.core.xray.vocabulary import WORKFLOW_STATUS_TEXT


def _start(run_start: int | None, agents: Sequence[str], nodes: dict[str, ProducedNode], frame: Frame) -> float | None:
    """When the run began on the session's clock: its first agent's start, else its recorded start time."""
    started = [nodes[agent].start for agent in agents if agent in nodes]
    if started:
        return min(started)
    return None if run_start is None else run_start / 1000.0 - frame.t0


def _phases(
    titles: Sequence[str], agents: Sequence[WorkflowAgent], nodes: dict[str, ProducedNode]
) -> tuple[tuple[XrayWorkflowPhase, ...], tuple[str, ...]]:
    """The run's phases in order, each with the nodes of the agents whose phase index is its place that the graph
    holds, and the nodes of the agents whose phase index is none of the phases' places."""
    listed = [agent.agent_id for agent in agents if agent.agent_id in nodes]
    phases = tuple(
        XrayWorkflowPhase(
            title,
            tuple(
                dict.fromkeys(
                    agent.agent_id for agent in agents if agent.phase_index == place and agent.agent_id in nodes
                )
            ),
        )
        for place, title in enumerate(titles)
    )
    placed = {agent for phase in phases for agent in phase.agents}
    return phases, tuple(agent for agent in dict.fromkeys(listed) if agent not in placed)


def _segment(root: ProducedNode | None, start: float | None) -> int:
    """The segment of the main agent's context the run started in; a run with no start is at the agent's start."""
    return 0 if root is None else segment_of(cuts_of(root), root.start if start is None else start)


def _read_run(
    run: WorkflowRun, nodes: dict[str, ProducedNode], frame: Frame, root: ProducedNode | None
) -> XrayWorkflow:
    phases, unphased = _phases(run.phases, run.agents, nodes)
    start = _start(run.start_time, [agent.agent_id for agent in run.agents], nodes, frame)
    return XrayWorkflow(
        run.run_id,
        run.name,
        run.status,
        WORKFLOW_STATUS_TEXT[run.status],
        phases,
        unphased,
        sum(len(phase.agents) for phase in phases) + len(unphased),
        start,
        _segment(root, start),
        run.duration_ms,
        run.total_tokens,
        None,
    )


def _unreadable(
    refused: WorkflowRefused,
    records: Sequence[EventRecord],
    nodes: dict[str, ProducedNode],
    frame: Frame,
    root: ProducedNode | None,
) -> XrayWorkflow:
    """The run shown as not readable: its phases and agents are the ones the subagent records name for it."""
    named = [
        (record.subagent_id, record.launch.workflow_phase)
        for record in records
        if record.event == "subagent_run"
        and record.launch is not None
        and record.launch.workflow_run == refused.run_id
        and record.subagent_id is not None
    ]
    titles = list(dict.fromkeys(title for _, title in named if title is not None))
    members = [
        WorkflowAgent(agent_id, None if title is None else titles.index(title), title, None, None)
        for agent_id, title in named
    ]
    phases, unphased = _phases(titles, members, nodes)
    start = _start(None, [agent.agent_id for agent in members], nodes, frame)
    return XrayWorkflow(
        refused.run_id,
        None,
        "unreadable",
        WORKFLOW_STATUS_TEXT["unreadable"],
        phases,
        unphased,
        sum(len(phase.agents) for phase in phases) + len(unphased),
        start,
        _segment(root, start),
        None,
        None,
        refused.reason,
    )


def workflow_nodes(
    reading: WorkflowReading,
    records: Sequence[EventRecord],
    pnodes: Sequence[ProducedNode],
    frame: Frame,
    root: ProducedNode | None,
) -> tuple[XrayWorkflow, ...]:
    """The session's workflow runs, earliest first, each placed in a segment of the main agent `root`'s context; a
    run whose record was refused is shown as not readable."""
    nodes = {node.id: node for node in pnodes}
    runs = [
        _unreadable(run, records, nodes, frame, root)
        if isinstance(run, WorkflowRefused)
        else _read_run(run, nodes, frame, root)
        for run in reading.runs
    ]
    return tuple(sorted(runs, key=lambda run: (run.start is None, run.start or 0.0, run.run_id)))
