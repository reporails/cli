"""Hook handler check — reads a hook config file and judges the handlers it declares.

A hook config nests its handlers in a known place: a block of events, each event a
list, each list entry a handler or a group of handlers. This check parses the file,
walks to those handlers and nowhere else, and reports each handler that does not meet
the rule's requirement on the line where that handler starts.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from reporails_cli.core.lint.mechanical.checks import _resolve_glob_targets, get_target_files
from reporails_cli.core.platform.dto.checks import CheckResult
from reporails_cli.core.platform.dto.models import ClassifiedFile
from reporails_cli.core.platform.utils.hook_config import HookPath, read_hook_config, value_at, walk_hooks

_REQUIRE_FORMS = ("type", "non_empty", "matches", "not_matches")


_LINE_RE = re.compile(r"[^\n]*\n|[^\n]+")


def _toml_line(text: str, path: HookPath) -> int:
    """The line where the TOML table at ``path`` starts.

    That is the first line by which the table exists: its ``[[...]]`` header, or the
    line that completes it when the table is written inline.
    """
    lines = _LINE_RE.findall(text)

    def exists_by(count: int) -> bool | None:
        """Whether the first ``count`` lines define the table; None when they do not parse alone."""
        try:
            return value_at(tomllib.loads("".join(lines[:count])), path) is not None
        except tomllib.TOMLDecodeError:
            return None

    low, high = 1, len(lines)
    while low < high:
        middle = (low + high) // 2
        probe, state = middle, exists_by(middle)
        # A cut inside a multi-line value does not parse: step back to the last line that does.
        while state is None and probe > low:
            probe -= 1
            state = exists_by(probe)
        if state:
            high = probe
        else:
            low = middle + 1
    return low


def _parse(path: Path) -> tuple[Any, Callable[[dict[str, Any], HookPath], int]] | None:
    """Parse a config file; return its data and a function giving a handler's line.

    None when the file is unreadable, too large, or not valid JSON / TOML.
    """
    config = read_hook_config(path)
    if config is None:
        return None
    if path.suffix == ".toml":
        return config.data, lambda _handler, where: _toml_line(config.text, where)
    return config.data, lambda handler, _where: getattr(handler, "line", 0)


def _handlers(data: Any, args: dict[str, Any]) -> Iterator[tuple[dict[str, Any], HookPath]]:
    """Each hook handler the file declares, with its data path."""
    sites = walk_hooks(
        data,
        block=str(args.get("block") or ""),
        named_hooks=bool(args.get("named_hooks")),
        grouped=args.get("handlers") == "grouped",
    )
    for site in sites:
        yield site.handler, site.path


def _type_of(handler: dict[str, Any], args: dict[str, Any]) -> Any:
    """The handler's type: its own ``type``, else the type an untyped handler runs as."""
    return handler["type"] if "type" in handler else args.get("default_type")


def _listed(value: Any) -> list[Any]:
    """An ``args`` value written as one item or as a list, as a list."""
    return value if isinstance(value, list) else [value]


def _is_selected(handler: dict[str, Any], args: dict[str, Any]) -> bool:
    """Whether the rule judges this handler."""
    select = args.get("select") or {}
    if "type" in select and _type_of(handler, args) not in _listed(select["type"]):
        return False
    return "has" not in select or any(key in handler for key in _listed(select["has"]))


def _has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _verdict(handler: dict[str, Any], args: dict[str, Any]) -> bool | None:
    """True when the handler meets the requirement, False when it does not, None when it is not judged."""
    require = args["require"]
    if "type" in require:
        return _type_of(handler, args) in _listed(require["type"])
    if "non_empty" in require:
        return any(_has_text(handler.get(key)) for key in _listed(require["non_empty"]))
    wanted = "matches" in require
    ((key, pattern),) = require["matches" if wanted else "not_matches"].items()
    value = handler.get(key)
    if not isinstance(value, str) or not value.strip():
        return None
    return bool(re.search(str(pattern), value)) is wanted


def _failing_lines(path: Path, args: dict[str, Any]) -> list[int]:
    """The line of each handler in one file that fails the rule."""
    parsed = _parse(path)
    if parsed is None:
        return []
    data, line_of = parsed
    judged = [
        (handler, where, verdict)
        for handler, where in _handlers(data, args)
        if _is_selected(handler, args) and (verdict := _verdict(handler, args)) is not None
    ]
    if args.get("any_handler"):
        if not judged or any(verdict for _, _, verdict in judged):
            return []
        first, where, _ = judged[0]
        return [line_of(first, where)]
    return [line_of(handler, where) for handler, where, verdict in judged if not verdict]


def _target_files(root: Path, args: dict[str, Any], classified_files: list[ClassifiedFile]) -> list[Path]:
    """The files to read: the rule's own files, or every JSON / TOML file under ``root`` when none is classified."""
    if classified_files or args.get("path"):
        return get_target_files(args, classified_files, root)
    found = {path for pattern in ("**/*.json", "**/*.toml") for path in _resolve_glob_targets(pattern, root)}
    return sorted(path for path in found if path.is_file())


def _args_problem(args: dict[str, Any]) -> str:
    """What is wrong with the check's ``args``, or an empty string when they are usable."""
    if not args.get("message"):
        return "no message specified"
    if args.get("handlers") not in ("direct", "grouped"):
        return "handlers must be 'direct' or 'grouped'"
    require = args.get("require")
    forms = [form for form in _REQUIRE_FORMS if form in require] if isinstance(require, dict) else []
    if not isinstance(require, dict) or len(forms) != 1:
        return f"require must hold exactly one of {', '.join(_REQUIRE_FORMS)}"
    if forms[0] in ("matches", "not_matches"):
        value = require[forms[0]]
        if not isinstance(value, dict) or len(value) != 1:
            return f"require.{forms[0]} must map one key to one pattern"
        try:
            re.compile(str(next(iter(value.values()))))
        except re.error as exc:
            return f"invalid pattern: {exc}"
    return ""


def hook_handlers(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check the hook handlers a JSON or TOML config file declares.

    The file is parsed, never pattern-matched: only objects in a handler position are
    judged, so an unrelated object elsewhere in the file is not read as a handler. A file
    that does not parse, has no hook block, or lists no handlers draws no finding here.
    A ``.toml`` file is read as TOML, any other file as JSON. The files read are the
    ones the rule targets (narrowed by a ``path`` glob when given); a directory with no
    classified file at all has every JSON and TOML file under it read instead.
    Where an arg takes a list, a single value means a one-item list.

    Args — where the handlers are:
        block: top-level key whose object holds the hooks. Omit when the file's top-level
            object is itself that block.
        named_hooks: true when the block maps a hook name to that hook's own events
            (``{"my-hook": {"<event>": [...]}}``). Default: the block maps events directly
            (``{"<event>": [...]}``).
        handlers: ``direct`` — every object an event lists is a handler.
            ``grouped`` — an object holding a ``hooks`` list is a matcher group and the
            objects in that list are the handlers; an object without one is itself a handler.
        default_type: the type a handler with no ``type`` runs as. Omit when a handler
            must name its type.

    Args — which handlers the rule judges (``select``, optional; default every handler):
        select.type: handlers whose type (after ``default_type``) is one of these.
        select.has: handlers carrying at least one of these keys.

    Args — what a judged handler must meet (``require``, exactly one form):
        require.type: its type (after ``default_type``) is one of these.
        require.non_empty: at least one of these keys holds a non-blank string.
        require.matches: ``{key: pattern}`` — the key's value matches the pattern.
        require.not_matches: ``{key: pattern}`` — the key's value does not match it.
            Both pattern forms judge only handlers where the key holds a non-blank string.

    Args — how findings are reported:
        message: the finding text.
        any_handler: false (default) — one finding per failing handler, each on the line
            where that handler starts. true — the file passes when at least one judged
            handler meets the requirement; otherwise one finding on the first judged handler.
    """
    problem = _args_problem(args)
    if problem:
        return CheckResult(passed=False, message=f"hook_handlers: {problem}")
    message = str(args["message"])
    occurrences: list[tuple[str, str]] = []
    for target in _target_files(root, args, classified_files):
        rel = target.relative_to(root).as_posix() if target.is_relative_to(root) else str(target)
        occurrences.extend((f"{rel}:{line}", message) for line in _failing_lines(target, args))
    if occurrences:
        return CheckResult(passed=False, message=message, occurrences=occurrences)
    return CheckResult(passed=True, message="Hook handlers meet the requirement")
