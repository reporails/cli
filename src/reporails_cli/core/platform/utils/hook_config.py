"""Where the hooks sit in a parsed hook config, as plain data.

A hook config nests its handlers in a known place: a block of events, each event a
list, each list entry a handler or a group of handlers sharing a matcher. This module
walks that shape over already-parsed data and nowhere else; reading and parsing the
file goes through `read_hook_config`, the one reader.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import tomllib
from collections.abc import Iterator
from pathlib import Path

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.hooks import CannotFire, HookConfig, HookPath, HookSite
from reporails_cli.core.platform.utils.file_read import read_file_text

# A config file larger than this is not read.
MAX_HOOK_CONFIG_BYTES = 1_048_576


def value_at(data: JsonValue, path: HookPath) -> JsonValue:
    """The value at ``path`` in parsed data, or None when the path does not exist."""
    for step in path:
        if isinstance(step, int) and isinstance(data, list):
            if not -len(data) <= step < len(data):
                return None
            data = data[step]
        elif isinstance(step, str) and isinstance(data, dict):
            if step not in data:
                return None
            data = data[step]
        else:
            return None
    return data


def _matcher_of(holder: JsonObject) -> str:
    """The matcher an entry or group carries; empty when it has none or it is not text."""
    matcher = holder.get("matcher")
    return matcher if isinstance(matcher, str) else ""


def _event_sites(event: str, entries: list[JsonValue], where: HookPath, grouped: bool) -> Iterator[HookSite]:
    """The handlers one event lists: its entries, or the members of each entry's ``hooks`` list."""
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        members = entry.get("hooks") if grouped else None
        if not isinstance(members, list):
            yield HookSite(event, _matcher_of(entry), entry, (*where, index))
            continue
        for position, member in enumerate(members):
            if isinstance(member, dict):
                yield HookSite(event, _matcher_of(entry), member, (*where, index, "hooks", position))


def walk_hooks(
    data: JsonValue, *, block: str = "", named_hooks: bool = False, grouped: bool = False
) -> Iterator[HookSite]:
    """Each hook handler the parsed file declares.

    ``block`` is the top-level key holding the hooks (empty: the top-level object is the
    block). ``named_hooks``: the block maps a hook name to that hook's own events.
    ``grouped``: an entry holding a ``hooks`` list is a matcher group and that list holds
    the handlers; any other entry is itself a handler.
    """
    where: HookPath = (block,) if block else ()
    block_data = value_at(data, where)
    if not isinstance(block_data, dict):
        return
    if named_hooks:
        event_maps = [((*where, name), events) for name, events in block_data.items()]
    else:
        event_maps = [(where, block_data)]
    for map_path, events in event_maps:
        if not isinstance(events, dict):
            continue
        for event, entries in events.items():
            if isinstance(entries, list):
                yield from _event_sites(str(event), entries, (*map_path, event), grouped)


def hook_sites(data: JsonValue) -> Iterator[HookSite]:
    """Every hook handler in a hook config of any agent, whichever shape it is written in.

    The hooks sit under a top-level ``hooks`` key when there is one, else the top-level
    object is the block. A block whose values are objects names its hooks; one whose values
    are lists maps events directly. A matcher group's ``hooks`` list is read as handlers.
    """
    if not isinstance(data, dict):
        return
    hooks = data.get("hooks")
    block = "hooks" if isinstance(hooks, dict) else ""
    members = hooks if isinstance(hooks, dict) else data
    named = any(isinstance(value, dict) for value in members.values())
    yield from walk_hooks(data, block=block, named_hooks=named, grouped=True)


class _Located(dict[str, JsonValue]):
    """A parsed JSON object that remembers the line its opening brace is on."""

    line: int = 0


_JSON_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\n]')


def _object_lines(text: str) -> Iterator[int]:
    """The line of each JSON object's opening brace, in the order the objects close."""
    line = 1
    open_lines: list[int] = []
    for token in _JSON_TOKEN_RE.finditer(text):
        char = token.group()
        if char == "\n":
            line += 1
        elif char == "{":
            open_lines.append(line)
        elif char == "}" and open_lines:
            yield open_lines.pop()


def _load_json(text: str) -> JsonValue:
    """Parse JSON; every object in the result knows the line it starts on."""
    lines = _object_lines(text)

    def located(pairs: list[tuple[str, JsonValue]]) -> _Located:
        # The decoder completes objects in the order their closing braces appear.
        obj = _Located(pairs)
        obj.line = next(lines, 0)
        return obj

    data: JsonValue = json.loads(text, object_pairs_hook=located)
    return data


def read_hook_config(path: Path) -> HookConfig | None:
    """The hook config at ``path`` parsed (TOML by its suffix, else JSON, every JSON object knowing its line).

    None when the file is unreadable, larger than ``MAX_HOOK_CONFIG_BYTES``, or not valid JSON / TOML.
    """
    try:
        if path.stat().st_size > MAX_HOOK_CONFIG_BYTES:
            return None
        text = read_file_text(path, encoding="utf-8-sig")
        return HookConfig(text, tomllib.loads(text) if path.suffix == ".toml" else _load_json(text))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


# A command that starts with one of these runs the script it is given, which then needs no executable bit.
_INTERPRETERS = frozenset(
    {"bash", "sh", "zsh", "dash", "fish", "python", "python3", "node", "deno", "bun", "ruby", "perl", "php", "pwsh"}
)
_VARIABLE_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# The folder variables Claude Code expands in a hook command, braced or not.
FOLDER_VARIABLE_RE = re.compile(
    r"\$\{(CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA|CLAUDE_PROJECT_DIR)\}"
    r"|\$(CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA|CLAUDE_PROJECT_DIR)\b"
)
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "fish"})
_SHELL_BODY_RE = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")
_VERSION_SUFFIX_RE = re.compile(r"[\d.]+$")
# The arguments after which an interpreter runs the text it is given instead of a script file.
_INLINE_ARGUMENTS: dict[str, frozenset[str]] = {
    "python": frozenset({"-c"}),
    "node": frozenset({"-e", "-p", "--eval", "--print"}),
    "bun": frozenset({"-e", "-p", "--eval", "--print"}),
    "deno": frozenset({"eval"}),
    "ruby": frozenset({"-e"}),
    "perl": frozenset({"-e", "-E"}),
    "php": frozenset({"-r"}),
    "pwsh": frozenset({"-c", "-Command", "-command"}),
}


# The interpreter options that take the next argument as their value; that value is never the script.
_VALUE_OPTIONS = frozenset(
    {
        "-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--config",
        "--env-file", "-W", "-X", "-Q", "-I", "-o", "-O", "--rcfile", "--init-file", "--preload",
    }
)  # fmt: skip
# The option after which a python interpreter runs a module instead of a script file.
_MODULE_OPTION = "-m"


def _script_token(interpreter: str, arguments: list[str]) -> str | None:
    """The first positional argument that is a path, after the interpreter options and their values; None when the
    interpreter runs a module or names no path."""
    family = _VERSION_SUFFIX_RE.sub("", interpreter)
    skip = False
    for argument in arguments:
        if skip:
            skip = False
        elif family == "python" and argument == _MODULE_OPTION:
            return None
        elif argument.startswith("-"):
            skip = argument in _VALUE_OPTIONS
        elif _is_path(argument):
            return argument
    return None


def _expand_folders(token: str, project_root: Path, plugin_root: Path | None) -> str | None:
    """The token with the folder variables put in: the project folder, and the folder of the plugin that declares
    the hook; None when it names a variable whose value is not known here."""
    values = {"CLAUDE_PROJECT_DIR": project_root, "CLAUDE_PLUGIN_ROOT": plugin_root}

    def value(match: re.Match[str]) -> str:
        folder = values.get(match.group(1) or match.group(2))
        return "$" if folder is None else str(folder)

    text = os.path.expanduser(FOLDER_VARIABLE_RE.sub(value, token))
    return None if "$" in text else text


def _runs_inline(interpreter: str, arguments: list[str]) -> bool:
    """Whether the interpreter is given a script body instead of a script file."""
    family = _VERSION_SUFFIX_RE.sub("", interpreter)
    for argument in arguments:
        if argument in _INLINE_ARGUMENTS.get(family, frozenset()):
            return True
        if family in _SHELLS and _SHELL_BODY_RE.match(argument):
            return True
        if not argument.startswith("-"):
            return False
    return False


def _is_path(token: str) -> bool:
    return "/" in token and not token.startswith("-")


def hook_script(command: str, project_root: Path, plugin_root: Path | None = None) -> tuple[Path, bool] | None:
    """The script path a hook command runs and whether an interpreter runs it, folder variables expanded; a relative
    path stands for the project root. None when the command names no script path (a bare command, a shell line that
    starts with another command, an inline script body, a variable whose value is not known)."""
    try:
        tokens = [token for token in shlex.split(command) if not _VARIABLE_ASSIGNMENT_RE.match(token)]
    except ValueError:
        return None
    if not tokens:
        return None
    interpreter = os.path.basename(tokens[0])
    interpreted = interpreter in _INTERPRETERS
    if interpreted and _runs_inline(interpreter, tokens[1:]):
        return None
    token = _script_token(interpreter, tokens[1:]) if interpreted else tokens[0]
    if token is None or not _is_path(token):
        return None
    expanded = _expand_folders(token, project_root, plugin_root)
    if expanded is None:
        return None
    path = Path(expanded)
    return (path if path.is_absolute() else project_root / path), interpreted


def cannot_fire(command: str, project_root: Path, plugin_root: Path | None = None) -> CannotFire | None:
    """Why the hook command cannot fire, or None when nothing shows it cannot: the folder of its script is missing,
    the script is missing from its folder, or the script exists, runs directly and lacks the executable bit."""
    found = hook_script(command, project_root, plugin_root)
    if found is None:
        return None
    path, interpreted = found
    if not path.parent.is_dir():
        return "folder_missing"
    if not path.is_file():
        return "script_missing"
    if interpreted:
        return None
    return None if os.access(path, os.X_OK) else "not_executable"
