"""Claude Code's own setting for which project instruction files it loads.

Claude Code reads `AGENTS.md` through a built-in plugin. The value at
`pluginConfigs["cc-plugin-agents-md@builtin"].options.instructionFiles` picks what loads;
before Claude Code 2.1.285 the plugin's ID was `agents-md@builtin`, and both IDs are read:

- `claude-md-or-agents-md` (the default): `CLAUDE.md` files, or `AGENTS.md` files when
  no `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` sits in the working directory
  or above it.
- `claude-md-and-agents-md`: both, each directory's `CLAUDE.md` first.
- `claude-md`: `CLAUDE.md` files only.
- `managed-only`: the organization's managed `CLAUDE.md` only; every `AGENTS.md` is left out.

Claude Code honours the value in the user's settings and in managed settings (managed
wins) and ignores it in a project's own settings files. A plugin turned off through
`enabledPlugins` leaves `CLAUDE.md` files only. The settings files are the ones Claude's
`config` file type declares, so this reader and discovery name the same files.
"""

from __future__ import annotations

import glob
import json
import logging
from collections.abc import Callable
from pathlib import Path

from reporails_cli.core.platform.config.config import get_agent_config_path, read_agent_config
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_object, pattern_list
from reporails_cli.core.platform.utils.utils import is_rooted_pattern

logger = logging.getLogger(__name__)

# The built-in plugin's ID since Claude Code 2.1.285, then its earlier one. When one file sets
# both, the current ID wins.
AGENTS_MD_PLUGINS = ("cc-plugin-agents-md@builtin", "agents-md@builtin")
MODE_CLAUDE_MD_OR_AGENTS_MD = "claude-md-or-agents-md"
MODE_CLAUDE_MD_AND_AGENTS_MD = "claude-md-and-agents-md"
MODE_CLAUDE_MD = "claude-md"
MODE_MANAGED_ONLY = "managed-only"
_MODES = frozenset({MODE_CLAUDE_MD_OR_AGENTS_MD, MODE_CLAUDE_MD_AND_AGENTS_MD, MODE_CLAUDE_MD, MODE_MANAGED_ONLY})

# Modes under which Claude Code reads no AGENTS.md at all.
MODES_WITHOUT_AGENTS_MD = frozenset({MODE_CLAUDE_MD, MODE_MANAGED_ONLY})

# Modes under which Claude Code leaves out every project, local and user `CLAUDE.md` and rules file
# that loads at launch, keeping the managed `CLAUDE.md` and everything that loads on demand.
MODES_WITHOUT_LAUNCH_INSTRUCTIONS = frozenset({MODE_MANAGED_ONLY})

# The file types of Claude's `CLAUDE.md` and rules files, the ones those modes switch off at launch.
LAUNCH_INSTRUCTION_FILE_TYPES = frozenset({"main", "override", "rules"})


def _scope_patterns(file_type: str) -> dict[str, list[str]]:
    """Scope name -> file patterns, from Claude's `file_type` file type."""
    data = read_agent_config(get_agent_config_path("claude"))
    if data is None:
        return {}
    scopes = as_object(as_object(as_object(data.get("file_types")).get(file_type)).get("scopes"))
    return {str(name): pattern_list(as_object(spec).get("patterns")) for name, spec in scopes.items()}


def _settings_patterns() -> dict[str, list[str]]:
    """Scope name -> settings-file patterns, from Claude's `config` file type."""
    return _scope_patterns("config")


def _expand(patterns: list[str], project_root: Path | None) -> list[Path]:
    """Existing files for `patterns`; relative ones resolve against `project_root`."""
    files: list[Path] = []
    for pattern in patterns:
        if is_rooted_pattern(pattern):
            expanded = str(Path(pattern).expanduser())
        elif project_root is not None:
            expanded = str(project_root / pattern)
        else:
            continue
        if "*" in expanded:
            files.extend(Path(p) for p in sorted(glob.glob(expanded)) if not Path(p).name.startswith("."))
        else:
            files.append(Path(expanded))
    return [f for f in files if _is_readable_file(f)]


def _is_readable_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:  # a settings path under a folder the user cannot read counts as absent
        return False


def _read_json(path: Path) -> JsonObject:
    try:
        data: JsonValue = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.debug("Claude settings file unreadable: %s", path, exc_info=True)
        return {}
    return as_object(data)


def _managed_files(scopes: dict[str, list[str]]) -> list[Path]:
    """Managed settings in merge order: `managed-settings.json`, then drop-ins alphabetically."""
    return _expand(scopes.get("managed", []), None) + _expand(scopes.get("managed_dropin", []), None)


def _mode_value(data: JsonObject) -> str | None:
    configs = data.get("pluginConfigs")
    if not isinstance(configs, dict):
        return None
    for plugin in AGENTS_MD_PLUGINS:
        entry = configs.get(plugin)
        options = entry.get("options") if isinstance(entry, dict) else None
        value = options.get("instructionFiles") if isinstance(options, dict) else None
        if isinstance(value, str):
            return value
    return None


def _enabled_value(data: JsonObject) -> bool | None:
    enabled = data.get("enabledPlugins")
    if not isinstance(enabled, dict):
        return None
    for plugin in AGENTS_MD_PLUGINS:
        value = enabled.get(plugin)
        if isinstance(value, bool):
            return value
    return None


def _last_set[T](files: list[Path], read: Callable[[JsonObject], T | None]) -> T | None:
    """The value the last file in `files` sets (later files override earlier ones), else None."""
    found: T | None = None
    for path in files:
        value = read(_read_json(path))
        if value is not None:
            found = value
    return found


def claude_instruction_files_mode(project_root: Path | None = None) -> str:
    """The Claude Code `instructionFiles` mode in effect for a session in `project_root`.

    Managed settings outrank the user's settings. A missing or unknown value is the
    default mode. When the built-in `AGENTS.md` plugin is turned off, the mode is `claude-md`:
    `enabledPlugins` is read from every scope, managed first, then the project's local
    and shared settings, then the user's.
    """
    scopes = _settings_patterns()
    managed = _managed_files(scopes)
    user = _expand(scopes.get("user", []), None)
    local = _expand(scopes.get("local", []), project_root)
    project = _expand(scopes.get("project", []), project_root)

    for files in (managed, local, project, user):
        enabled = _last_set(files, _enabled_value)
        if enabled is not None:
            if not enabled:
                return MODE_CLAUDE_MD
            break

    for files in (managed, user):
        value = _last_set(files, _mode_value)
        if value is not None:
            return value if value in _MODES else MODE_CLAUDE_MD_OR_AGENTS_MD
    return MODE_CLAUDE_MD_OR_AGENTS_MD


def _cleanup_days_value(data: JsonObject) -> int | None:
    value = data.get("cleanupPeriodDays")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _precedence_files(scopes: dict[str, list[str]], project_root: Path | None) -> list[Path]:
    """Claude Code's settings files from lowest to highest precedence: user, project, local, managed."""
    return (
        _expand(scopes.get("user", []), None)
        + _expand(scopes.get("project", []), project_root)
        + _expand(scopes.get("local", []), project_root)
        + _managed_files(scopes)
    )


def enabled_plugins(project_root: Path | None = None) -> dict[str, bool]:
    """Each plugin id the settings files turn on or off, merged key by key: the highest source that names
    an id decides it. An id no file names is absent (the plugin's own `defaultEnabled` applies)."""
    merged: dict[str, bool] = {}
    for path in _precedence_files(_settings_patterns(), project_root):
        enabled = _read_json(path).get("enabledPlugins")
        if isinstance(enabled, dict):
            merged.update({str(plugin): value for plugin, value in enabled.items() if isinstance(value, bool)})
    return merged


def claude_cleanup_period_days(project_root: Path | None = None) -> int | None:
    """Days Claude Code keeps a session, from its `cleanupPeriodDays` setting, or None when no
    settings file sets a positive whole number. Files are read in Claude Code's precedence: the
    user's, then the project's shared and local ones, then managed settings, the last to set it
    winning. It is Claude Code's setting, so an invalid value reads as unset."""
    return _last_set(_precedence_files(_settings_patterns(), project_root), _cleanup_days_value)


def claude_synced_account_folder() -> str | None:
    """The name of the folder under `~/.claude/skills/synced/` that holds the skills synced from the signed-in
    claude.ai account, `<organizationUuid>_<accountUuid>`; None when `~/.claude.json` names no signed-in account.

    https://code.claude.com/docs/en/skills documents `~/.claude/skills/synced/` for skills downloaded from
    claude.ai. The per-account folder below it and its name are not documented: observed on Claude Code 2.1.308,
    2026-10-31, where the folder of the account `~/.claude.json` names under `oauthAccount` is the one whose skills
    the session lists.
    """
    for path in _expand(_scope_patterns("mcp").get("user", []), None):
        folder = _account_folder(path)
        if folder is not None:
            return folder
    return None


# The account folder each `~/.claude.json` named when last read, with the file's modification time and size then.
_account_folders: dict[str, tuple[tuple[int, int], str | None]] = {}


def _account_folder(path: Path) -> str | None:
    """The account folder the file at `path` names; the file is parsed again only when its modification time or
    size changed."""
    stat = path.stat()
    stamp = (stat.st_mtime_ns, stat.st_size)
    cached = _account_folders.get(str(path))
    if cached is not None and cached[0] == stamp:
        return cached[1]
    account = as_object(_read_json(path).get("oauthAccount"))
    organization, uuid = account.get("organizationUuid"), account.get("accountUuid")
    named = isinstance(organization, str) and isinstance(uuid, str) and organization and uuid
    folder = f"{organization}_{uuid}" if named else None
    _account_folders[str(path)] = (stamp, folder)
    return folder
