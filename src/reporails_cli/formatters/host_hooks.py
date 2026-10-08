"""The `host_hooks` reply entries: the project's hooks that can intercept heal's file reads and writes."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from reporails_cli.core.platform.config.config import get_agent_config
from reporails_cli.core.platform.dto.results import AgentConfig, HookEntry
from reporails_cli.core.platform.policy.host_hooks import intercepted_tools


def host_hooks_field(hooks: Iterable[HookEntry]) -> dict[str, Any]:
    """`{"host_hooks": [...]}` for the reply, or nothing when no hook can intercept."""
    entries = _entries(hooks)
    return {"host_hooks": entries} if entries else {}


def _entries(hooks: Iterable[HookEntry]) -> list[dict[str, Any]]:
    """One entry per hook that intercepts Read, Edit or Write, with what its agent's docs say about sub-agents."""
    entries: list[dict[str, Any]] = []
    configs: dict[str, AgentConfig] = {}
    for hook in hooks:
        if hook.agent not in configs:
            configs[hook.agent] = get_agent_config(hook.agent)
        tools = intercepted_tools(hook, configs[hook.agent])
        if not tools:
            continue
        facts = configs[hook.agent].subagent_hooks
        entries.append(
            {
                "agent": hook.agent,
                "event": hook.event,
                "matcher": hook.matcher,
                "scope": hook.scope,
                "file": hook.file,
                "tools": list(tools),
                "identity_fields": list(facts.identifies_agent.fields),
                "fires_in_subagents": facts.fire_in_subagents.value,
                "opt_out": facts.extension_opt_out.value,
            }
        )
    return entries
