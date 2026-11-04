"""The one owner of the folder an MCP tool works in.

An agent starts the server in a folder that is not always the project (the home folder, the plugin's
own folder), so the server never reads its working folder. Each tool that takes `path` resolves the
project folder here, in this order: the `path` the agent passed, the `file://` root the agent lists (the
one holding an absolute `path`, else the first), the absolute `AILS_PROJECT_DIR` value; with none of them
the tool refuses.
"""

from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname

import anyio
from mcp.server.mcpserver import Context

from reporails_cli.core.platform.config.bootstrap import env_text
from reporails_cli.core.platform.contract.json_value import JsonObject

ToolContext = Context[None, object]

PROJECT_DIR_ENV = "AILS_PROJECT_DIR"
ROOTS_TIMEOUT_S = 2

logger = logging.getLogger(__name__)

NO_PROJECT: JsonObject = {
    "error": "no_project",
    "message": (
        "Pass the project folder as path and the file in targets; this agent did not say which folder it is working in."
    ),
}


@dataclass(frozen=True)
class ProjectFolder:
    """`target` is what the tool checks; `root` is the project folder a file target is read against."""

    target: Path
    root: Path


def _root_path(uri: str) -> Path | None:
    """The local folder a `file://` root names, or None for any other root. A host in the URI is a network share."""
    parsed = urlparse(uri)
    if parsed.scheme != "file" or not parsed.path:
        return None
    share = parsed.netloc not in ("", "localhost")
    return Path(url2pathname(f"//{parsed.netloc}{parsed.path}" if share else parsed.path)).resolve()


async def _listed_roots(ctx: ToolContext | None) -> list[Path]:
    """The `file://` roots the agent lists, in its order; none when it lists none or cannot be asked.

    Asking is best-effort: an agent without the roots capability, a closed channel, an agent that does not
    answer within `ROOTS_TIMEOUT_S` or a call outside a request all mean "no root", never a failed tool call."""
    if ctx is None:
        return []
    try:
        capabilities = ctx.session.client_capabilities
        if capabilities is None or capabilities.roots is None:
            return []
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # the SDK marks roots/list deprecated; agents still answer it
            with anyio.fail_after(ROOTS_TIMEOUT_S):
                listed = await ctx.session.list_roots()
    except Exception as err:  # pylint: disable=broad-exception-caught  # best-effort: any SDK or transport failure is "no root"
        logger.debug("roots/list failed, so the agent names no root: %s", err)
        return []
    found = (_root_path(str(root.uri)) for root in listed.roots)
    return [root for root in found if root is not None]


async def _agent_folder(ctx: ToolContext | None, target: Path | None) -> Path | None:
    """The folder the agent says it works in: the root holding `target`, else its first root, else the env value."""
    roots = await _listed_roots(ctx)
    if roots:
        holding = next((root for root in roots if target is not None and target.is_relative_to(root)), None)
        return holding or roots[0]
    from_env = Path(env_text(PROJECT_DIR_ENV))
    # An unexpanded `${...}` or a relative value names no folder: never read it against the working folder.
    return from_env.resolve() if from_env.is_absolute() else None


async def resolve_project_folder(path: str, ctx: ToolContext | None) -> ProjectFolder | JsonObject:
    """The target and project folder for a tool call, or the `no_project` refusal.

    A `path` that is neither empty nor `.` is the target; a relative one is read against the agent's
    folder and refused when there is none. With no `path` the agent's folder is the target. The project
    folder is the agent's folder when it gave one; an absolute folder `path` is its own project folder
    when the agent gave none, and an absolute file `path` is refused then, since its own folder is not known
    to be the project."""
    given = path.strip()
    requested = Path(given) if given and given != "." else None
    absolute = requested.resolve() if requested is not None and requested.is_absolute() else None
    agent_folder = await _agent_folder(ctx, absolute)
    if absolute is not None:
        if agent_folder is not None:
            return ProjectFolder(absolute, agent_folder)
        return ProjectFolder(absolute, absolute) if absolute.is_dir() else dict(NO_PROJECT)
    if agent_folder is None:
        return dict(NO_PROJECT)
    target = (agent_folder / requested).resolve() if requested is not None else agent_folder
    return ProjectFolder(target, agent_folder)
