"""The name a file is shown by: a skill by its folder, an agent or command by its file, a memory topic by what
follows its type."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import MEMORY_INDEX_FILENAME, MEMORY_SURFACES
from reporails_cli.core.mapper.inspect import STEM_LABELLED_TYPES


def skill_name(folder: str | Path) -> str:
    """A skill's name: its folder's name."""
    return Path(folder).name


def _plugin_scoped(name: str, plugin: str | None) -> str:
    """`name` as Claude Code names a plugin's component: `<plugin name>:<name>`."""
    return f"{plugin.split('@', 1)[0]}:{name}" if plugin else name


def file_label(
    file_type: str, path: Path, fallback: str, *, plugin: str | None = None, memory_type: str | None = None
) -> str:
    """The display name of the file at `path` of the config file type `file_type`; `fallback` names any other
    file. A skill entry file is its folder's name, an agent or command its file name (after `<plugin>:` for a
    file of plugin `plugin`, an `name@marketplace` id) and a memory topic file its name without a leading
    `<memory_type>_`."""
    if file_type == "skills":
        return _plugin_scoped(skill_name(path.parent), plugin)
    if file_type in STEM_LABELLED_TYPES:
        return _plugin_scoped(path.stem, plugin)
    if file_type in MEMORY_SURFACES:
        if path.name == MEMORY_INDEX_FILENAME:
            return path.name
        return path.stem.removeprefix(f"{memory_type}_") if memory_type else path.stem
    return fallback
