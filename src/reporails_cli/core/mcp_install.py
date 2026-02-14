"""MCP server registration — detect agents and write MCP config files."""

from __future__ import annotations

import json
from pathlib import Path

from reporails_cli.core.agents import detect_agents

# Agent ID → project-level MCP config file path
MCP_PROJECT_CONFIGS: dict[str, str] = {
    "claude": ".mcp.json",
    "copilot": ".vscode/mcp.json",
    "codex": ".codex/mcp.json",
}

MCP_SERVER_ENTRY: dict[str, str | list[str]] = {
    "command": "uvx",
    "args": ["--refresh", "--from", "reporails-cli", "reporails-mcp"],
}


def detect_mcp_targets(project_root: Path) -> list[tuple[str, Path]]:
    """Detect agents in the project and return MCP config targets.

    Returns:
        List of (agent_id, absolute_config_path) for agents with known MCP configs.
    """
    agents = detect_agents(project_root)
    targets: list[tuple[str, Path]] = []

    for agent in agents:
        agent_id = agent.agent_type.id
        config_rel = MCP_PROJECT_CONFIGS.get(agent_id)
        if config_rel is not None:
            targets.append((agent_id, project_root / config_rel))

    return targets


def write_mcp_config(config_path: Path) -> bool:
    """Write or merge the reporails MCP server entry into a config file.

    - If the file exists: loads JSON, merges ``mcpServers.reporails``, writes back.
    - If the file is missing: creates parent dirs and writes a fresh config.
    - If an existing entry has ``ails-mcp`` in args, silently migrates to ``reporails-mcp``.

    Returns:
        True if the file was written successfully.
    """
    args = MCP_SERVER_ENTRY["args"]
    entry: dict[str, str | list[str]] = {
        "command": str(MCP_SERVER_ENTRY["command"]),
        "args": list(args) if isinstance(args, list) else [str(args)],
    }

    if config_path.exists():
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
    else:
        data = {}

    if "mcpServers" not in data:
        data["mcpServers"] = {}

    data["mcpServers"]["reporails"] = entry

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return True
