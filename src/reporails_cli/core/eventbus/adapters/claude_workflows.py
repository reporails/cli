"""Claude Code workflow runs: the run record file and, while it is not written yet, the run's agent files.

A run record is the JSON object `<session>/workflows/<runId>.json`. Pinned keys: `runId` (a string equal to the
file's run id), `status` (a string), `phases` (a list of objects with a string `title`) and `workflowProgress` (a
list); when present, `workflowName` (a string), `durationMs`, `totalTokens` and `startTime` (whole
numbers). The `workflowProgress` entries that carry an `agentId` are the run's agents, each with a string `agentId`,
`phaseIndex` (a whole number), `phaseTitle` and `label` (strings). A `journal.jsonl` row of type `started` carries
`agentId`, `label` and `phase` (strings). An agent's meta file carries `workflowPhase` (a string). Anything else is
ignored; a field of another shape refuses the record."""

from __future__ import annotations

from reporails_cli.core.eventbus.adapters.claude_rows import meta_field
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_list, as_object
from reporails_cli.core.platform.dto.workflows import RECORDED_STATUSES, WorkflowAgent, WorkflowRun, WorkflowStatus


def _required[Field: (str, int)](record: JsonObject, key: str, kind: type[Field]) -> Field:
    value = _optional(record, key, kind)
    if value is None:
        raise PayloadRefused(f"workflow run record has no {key}")
    return value


def _optional[Field: (str, int)](record: JsonObject, key: str, kind: type[Field]) -> Field | None:
    value: JsonValue = record.get(key)
    if value is None:
        return None
    if not isinstance(value, kind) or isinstance(value, bool):
        raise PayloadRefused(f"workflow run record {key} is not a {kind.__name__}")
    return value


def _status(record: JsonObject) -> WorkflowStatus:
    """The run's status the record names; refuses a word outside `RECORDED_STATUSES`."""
    word = _required(record, "status", str)
    for known in RECORDED_STATUSES:
        if word == known:
            return known
    raise PayloadRefused(f"workflow run record status {word!r} is none of {', '.join(RECORDED_STATUSES)}")


def _recorded_agent(entry: JsonObject) -> WorkflowAgent:
    return WorkflowAgent(
        _required(entry, "agentId", str),
        _required(entry, "phaseIndex", int),
        _required(entry, "phaseTitle", str),
        _required(entry, "label", str),
    )


def _resolve_recorded_run(run_id: str, record: JsonObject) -> WorkflowRun:
    """The run a record file holds; refuses a record that is not the pinned shape."""
    if _required(record, "runId", str) != run_id:
        raise PayloadRefused(f"workflow run record names a run other than {run_id}")
    if not isinstance(record.get("phases"), list) or not isinstance(record.get("workflowProgress"), list):
        raise PayloadRefused("workflow run record phases or workflowProgress is not a list")
    phases = tuple(_required(as_object(phase), "title", str) for phase in as_list(record["phases"]))
    entries = [as_object(entry) for entry in as_list(record["workflowProgress"])]
    agents = tuple(_recorded_agent(entry) for entry in entries if "agentId" in entry)
    return WorkflowRun(
        run_id=run_id,
        name=_optional(record, "workflowName", str),
        status=_status(record),
        phases=phases,
        duration_ms=_optional(record, "durationMs", int),
        total_tokens=_optional(record, "totalTokens", int),
        start_time=_optional(record, "startTime", int),
        agents=agents,
    )


def _resolve_running_run(run_id: str, journal: list[JsonObject], metas: dict[str, JsonObject]) -> WorkflowRun:
    """The run that has no record file yet, from its agents' meta files (their phase) and its journal (their
    label and start order). The run's name, duration, token total and start time are not known."""
    labels: dict[str, str | None] = {}
    for row in journal:
        agent_id = row.get("agentId")
        if row.get("type") == "started" and isinstance(agent_id, str):
            label = row.get("label")
            labels[agent_id] = label if isinstance(label, str) else None
    ordered = [
        *(agent for agent in labels if agent in metas),
        *(agent for agent in sorted(metas) if agent not in labels),
    ]
    phases: list[str] = []
    agents: list[WorkflowAgent] = []
    for agent_id in ordered:
        phase = meta_field(metas[agent_id], "workflowPhase", str)
        if phase is not None and phase not in phases:
            phases.append(phase)
        index = None if phase is None else phases.index(phase)
        agents.append(WorkflowAgent(agent_id, index, phase, labels.get(agent_id)))
    return WorkflowRun(run_id, None, "running", tuple(phases), None, None, None, tuple(agents))


def resolve_workflow_run(
    run_id: str, record: JsonObject | None, journal: list[JsonObject], metas: dict[str, JsonObject]
) -> WorkflowRun:
    """The run its record file holds; with no record file (`record` None), the running run its journal rows and
    agent meta files show. Refuses a record that is not the pinned shape."""
    if record is None:
        return _resolve_running_run(run_id, journal, metas)
    return _resolve_recorded_run(run_id, record)
