"""The one owner of the folder an MCP tool works in.

An agent starts the server in a folder that is not always the project (the home folder, the plugin's
own folder), so the server never reads its working folder. Each tool that takes `path` resolves the
project folder here, in this order: the `path` the agent passed, the first `file://` root the agent
lists, the absolute `AILS_PROJECT_DIR` value; with none of them the tool refuses.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from mcp.server.mcpserver import Context

from reporails_cli.core.platform.config.bootstrap import env_text
from reporails_cli.core.platform.contract.json_value import JsonObject

ToolContext = Context[None, object]

PROJECT_DIR_ENV = "AILS_PROJECT_DIR"

NO_PROJECT: JsonObject = {
    "error": "no_project",
    "message": "Pass the project folder as path; this agent did not say which folder it is working in.",
}


@dataclass(frozen=True)
class ProjectFolder:
    """`target` is what the tool checks; `root` is the project folder a file target is read against."""

    target: Path
    root: Path


async def _first_root(ctx: ToolContext | None) -> Path | None:
    """The first `file://` root the agent lists, or None when it lists none or cannot be asked.

    Asking is best-effort: an agent without the roots capability, a closed channel or a call outside a
    request all mean "no root", never a failed tool call."""
    if ctx is None:
        return None
    try:
        capabilities = ctx.session.client_capabilities
        if capabilities is None or capabilities.roots is None:
            return None
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # the SDK marks roots/list deprecated; agents still answer it
            listed = await ctx.session.list_roots()
    except Exception:  # pylint: disable=broad-exception-caught  # best-effort: any SDK or transport failure is "no root"
        return None
    for root in listed.roots:
        parsed = urlparse(str(root.uri))
        if parsed.scheme == "file" and parsed.path:
            return Path(unquote(parsed.path)).resolve()
    return None


async def _agent_folder(ctx: ToolContext | None) -> Path | None:
    """The folder the agent says it works in: its first root, else `AILS_PROJECT_DIR`."""
    root = await _first_root(ctx)
    if root is not None:
        return root
    from_env = Path(env_text(PROJECT_DIR_ENV))
    # An unexpanded `${...}` or a relative value names no folder: never read it against the working folder.
    return from_env.resolve() if from_env.is_absolute() else None


async def resolve_project_folder(path: str, ctx: ToolContext | None) -> ProjectFolder | JsonObject:
    """The target and project folder for a tool call, or the `no_project` refusal.

    A `path` that is neither empty nor `.` is the target; a relative one is read against the agent's
    folder and refused when there is none. With no `path` the agent's folder is the target. The project
    folder is the agent's folder when it gave one, else the target's own folder."""
    agent_folder = await _agent_folder(ctx)
    given = path.strip()
    requested = Path(given) if given and given != "." else None
    if requested is not None and requested.is_absolute():
        target = requested.resolve()
        return ProjectFolder(target, agent_folder or (target if target.is_dir() else target.parent))
    if agent_folder is None:
        return dict(NO_PROJECT)
    target = (agent_folder / requested).resolve() if requested is not None else agent_folder
    return ProjectFolder(target, agent_folder)
