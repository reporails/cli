"""The launch a subagent's meta file records: its task, parent, nesting, model and, for a workflow run's agent,
the run and the phase it ran in. Each field that is present must be the type it is pinned to."""

from __future__ import annotations

from reporails_cli.core.eventbus.adapters.claude_rows import meta_field
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.events import SubagentMeta

BACKGROUND_SHAPE = "background"


def subagent_launch(meta: JsonObject, brief: str | None, workflow_run: str | None) -> SubagentMeta:
    """The launch a subagent's meta file records, with the size of its brief (None when it has no text) and, for an
    agent a workflow run started, the id of the run. Refuses a field of another type."""
    return SubagentMeta(
        description=meta_field(meta, "description", str),
        parent_id=meta_field(meta, "parentAgentId", str),
        tool_use_id=meta_field(meta, "toolUseId", str),
        depth=meta_field(meta, "spawnDepth", int),
        brief_chars=None if brief is None else len(brief),
        stopped=meta_field(meta, "stoppedByUser", bool) is True,
        background=meta_field(meta, "requestShape", str) == BACKGROUND_SHAPE,
        asked_model=meta_field(meta, "model", str),
        with_defaults=meta_field(meta, "launchedWithDefaults", bool),
        workflow_run=workflow_run,
        workflow_phase=meta_field(meta, "workflowPhase", str),
    )
