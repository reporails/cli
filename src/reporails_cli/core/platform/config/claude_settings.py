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
wins; the cache of the organization's server-managed settings, `~/.claude/remote-settings.json`,
ranks first) and ignores it in a project's own settings files. A plugin turned off through
`enabledPlugins` leaves `CLAUDE.md` files only. The settings files are the ones Claude's
`config` file type declares, so this reader and discovery name the same files.
"""

from __future__ import annotations

import glob
import json
import logging
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from reporails_cli.core.platform.config.config import get_agent_config_path, read_agent_config
from reporails_cli.core.platform.contract.errors import ClaudeSettingsUnreadableError
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_object, pattern_list
from reporails_cli.core.platform.dto.mcp import McpDeclaration
from reporails_cli.core.platform.dto.xray_sources import ArtifactScope
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

# The two keys of a managed source that are not policy: a source holding only these delivers no policy.
# https://code.claude.com/docs/en/managed-settings#how-claude-code-combines-managed-sources
_CONTROL_KEYS = frozenset({"wslInheritsWindowsSettings", "managedSourcesBehavior"})

# The problems of an unreadable server-managed cache, collected inside `leaving_out_unreadable_cache`.
_CACHE_PROBLEMS: ContextVar[list[str] | None] = ContextVar("claude_cache_problems", default=None)

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


def _read_json(path: Path, *, strict: bool = False) -> JsonObject:
    """A settings file's object; an unreadable or non-object file reads as empty, or with `strict` (the
    server-managed cache) raises `ClaudeSettingsUnreadableError`."""
    try:
        data: JsonValue = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        if strict:
            raise ClaudeSettingsUnreadableError(f"{path}: cannot be read as JSON ({exc})") from exc
        logger.debug("Claude settings file unreadable: %s", path, exc_info=True)
        return {}
    if strict and not isinstance(data, dict):
        raise ClaudeSettingsUnreadableError(f"{path}: not a JSON object")
    return as_object(data)


@contextmanager
def leaving_out_unreadable_cache() -> Iterator[list[str]]:
    """Within the block an unreadable server-managed cache is left out instead of raising; each problem is
    appended to the yielded list, for a caller that shows the problem and keeps listing."""
    problems: list[str] = []
    token = _CACHE_PROBLEMS.set(problems)
    try:
        yield problems
    finally:
        _CACHE_PROBLEMS.reset(token)


def _remote_cache(scopes: dict[str, list[str]]) -> dict[Path, JsonObject]:
    """The server-managed cache files that deliver a policy key, each with its settings."""
    cache: dict[Path, JsonObject] = {}
    for path in _expand(scopes.get("remote", []), None):
        try:
            data = _read_json(path, strict=True)
        except ClaudeSettingsUnreadableError as exc:
            problems = _CACHE_PROBLEMS.get()
            if problems is None:
                raise
            problems.append(str(exc))
            continue
        if _holds_policy(data):
            cache[path] = data
    return cache


def _holds_policy(data: JsonObject) -> bool:
    return any(key not in _CONTROL_KEYS for key in data)


def _managed_files(scopes: dict[str, list[str]]) -> list[Path]:
    """Managed settings in merge order, lowest first. Claude Code's managed tier uses the first source that
    delivers a policy key, server-managed settings (the `remote` scope's cache) before the files:
    `managed-settings.json`, then drop-ins alphabetically. With `managedSourcesBehavior` `"merge"` on the
    selected source, every source that delivers one is used, the server-managed one ranked highest. A
    malformed cache raises `ClaudeSettingsUnreadableError`."""
    files = _expand(scopes.get("managed", []), None) + _expand(scopes.get("managed_dropin", []), None)
    remote = _remote_cache(scopes)
    if not remote:
        return files
    if not any(data.get("managedSourcesBehavior") == "merge" for data in remote.values()):
        return list(remote)
    return [path for path in files if _holds_policy(_read_json(path))] + list(remote)


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


def claude_settings_files(project_root: Path) -> tuple[Path, ...]:
    """Claude Code's settings files that exist for a session in `project_root`, lowest precedence first: the
    user's, the project's shared and local ones, then managed settings."""
    return tuple(_precedence_files(_settings_patterns(), project_root))


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


def _declared_in(data: JsonObject, *, wrapped: bool) -> list[str]:
    """The server names an `mcpServers` map names; the map is the object's `mcpServers` value, or the object
    itself when `wrapped` is false."""
    servers = data.get("mcpServers") if wrapped else data
    return [name for name, spec in as_object(servers).items() if isinstance(spec, dict)]


def _plugin_mcp_files(plugin_root: Path) -> list[tuple[Path, JsonObject, bool]]:
    """The files a plugin declares servers in: its `.mcp.json` and, when it carries an inline `mcpServers` map, its
    manifest. A `.mcp.json` is read with or without an `mcpServers` wrapper."""
    files: list[tuple[Path, JsonObject, bool]] = []
    mcp_file = plugin_root / ".mcp.json"
    if _is_readable_file(mcp_file):
        data = _read_json(mcp_file)
        files.append((mcp_file, data, isinstance(data.get("mcpServers"), dict)))
    manifest = plugin_root / ".claude-plugin" / "plugin.json"
    if _is_readable_file(manifest):
        data = _read_json(manifest)
        if isinstance(data.get("mcpServers"), dict):
            files.append((manifest, data, True))
    return files


def _project_entry(project_root: Path) -> JsonObject:
    """What the user's `~/.claude.json` records for the project at `project_root`; empty when it records none."""
    for path in _expand(_scope_patterns("mcp").get("user", []), None):
        projects = as_object(_read_json(path).get("projects"))
        for key in (str(project_root), str(project_root.resolve())):
            if key in projects:
                return as_object(projects[key])
    return {}


def mcp_declarations(project_root: Path, plugins: Sequence[tuple[str, Path]]) -> tuple[McpDeclaration, ...]:
    """Every MCP server the configuration declares for a session in `project_root`, the one Claude Code connects
    first: the managed file, the project's own entry in `~/.claude.json`, the project's `.mcp.json`, the user's
    entry in `~/.claude.json` and each of `plugins`' servers, with the file each is declared in. A plugin is named
    by its id before the `@`."""
    scopes = _scope_patterns("mcp")
    found: list[McpDeclaration] = []
    claude_json = _expand(scopes.get("user", []), None)
    sources: list[tuple[ArtifactScope, Path, JsonObject, bool]] = [
        ("managed", path, _read_json(path), True) for path in _managed_files(scopes)
    ]
    sources += [("local", path, _project_entry(project_root), True) for path in claude_json]
    sources += [("project", path, _read_json(path), True) for path in _expand(scopes.get("project", []), project_root)]
    sources += [("user", path, _read_json(path), True) for path in claude_json]
    found.extend(
        McpDeclaration(name, scope, None, str(path))
        for scope, path, data, wrapped in sources
        for name in _declared_in(data, wrapped=wrapped)
    )
    for plugin_id, plugin_root in plugins:
        plugin = plugin_id.split("@", 1)[0]
        found.extend(
            McpDeclaration(name, "plugin", plugin, str(path))
            for path, data, wrapped in _plugin_mcp_files(plugin_root)
            for name in _declared_in(data, wrapped=wrapped)
        )
    return tuple(found)


def mcp_turned_off(project_root: Path) -> frozenset[str]:
    """The servers `~/.claude.json` turns off for the project at `project_root`: its `disabledMcpServers` (a user,
    managed or claude.ai server by name, a plugin's as `plugin:<plugin>:<server>`) and the `.mcp.json` servers it
    rejects in `disabledMcpjsonServers`."""
    entry = _project_entry(project_root)
    off: set[str] = set()
    for key in ("disabledMcpServers", "disabledMcpjsonServers"):
        listed = entry.get(key)
        if isinstance(listed, list):
            off.update(item for item in listed if isinstance(item, str))
    return frozenset(off)
