"""The name a file is shown by: a skill, agent or command by its frontmatter `name` (a skill's folder, an agent's or
command's file when it has none), a memory topic by what follows its type."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import MEMORY_INDEX_FILENAME, MEMORY_SURFACES
from reporails_cli.core.discovery.external_patterns import SYNCED_SCOPE
from reporails_cli.core.mapper.inspect import STEM_LABELLED_TYPES
from reporails_cli.core.platform.utils.utils import read_frontmatter_file

# How the session names a skill synced from claude.ai: `anthropic-skills:<folder>`. Observed on Claude Code 2.1.308,
# 2026-10-31; the skills page does not document it.
SYNCED_SKILL_PREFIX = "anthropic-skills"


def skill_name(folder: str | Path) -> str:
    """A skill's name: its folder's name."""
    return Path(folder).name


def _declared_name(path: Path, default: str) -> str:
    """The `name` the file's frontmatter declares, which is the identity Claude Code knows a skill, agent or
    command by (https://code.claude.com/docs/en/skills, https://code.claude.com/docs/en/sub-agents); `default`
    when it declares none."""
    block = read_frontmatter_file(path)
    declared = block.data.get("name") if block is not None and block.data is not None else None
    return declared if isinstance(declared, str) and declared else default


def _plugin_scoped(name: str, plugin: str | None) -> str:
    """`name` as Claude Code names a plugin's component: `<plugin name>:<name>`."""
    return f"{plugin.split('@', 1)[0]}:{name}" if plugin else name


def file_label(
    file_type: str,
    path: Path,
    fallback: str,
    *,
    plugin: str | None = None,
    memory_type: str | None = None,
    scope: str | None = None,
) -> str:
    """The display name of the file at `path` of the config file type `file_type`; `fallback` names any other
    file. A skill, agent or command is its frontmatter `name`, else its folder's name for a skill and its file name
    for an agent or command (after `<plugin>:` for a file of plugin `plugin`, an `name@marketplace` id), and a
    memory topic file its name without a leading
    `<memory_type>_`; a skill of the `synced` scope is `anthropic-skills:<folder>`."""
    if file_type == "skills":
        name = _declared_name(path, skill_name(path.parent))
        return f"{SYNCED_SKILL_PREFIX}:{name}" if scope == SYNCED_SCOPE else _plugin_scoped(name, plugin)
    if file_type in STEM_LABELLED_TYPES:
        return _plugin_scoped(_declared_name(path, path.stem), plugin)
    if file_type in MEMORY_SURFACES:
        if path.name == MEMORY_INDEX_FILENAME:
            return path.name
        return path.stem.removeprefix(f"{memory_type}_") if memory_type else path.stem
    return fallback
