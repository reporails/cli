"""Shared utility functions used across modules.

All functions are pure (no I/O) except where noted.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from collections.abc import Hashable
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import ClassVar, NamedTuple

import yaml
from yaml.constructor import SafeConstructor
from yaml.resolver import Resolver

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

logger = logging.getLogger(__name__)

_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"
# Explicit tags whose constructors build values JSON cannot hold (bytes, sets, tuples, dates).
_NON_JSON_TAGS = frozenset(f"tag:yaml.org,2002:{name}" for name in ("binary", "set", "omap", "pairs", "timestamp"))


class _JsonConstruction(SafeConstructor):
    """The constructor changes that make a safe-loaded document JSON by construction: a timestamp-looking
    scalar stays a string, every mapping key is a string and a tag for bytes, sets, pairs or dates is a
    `yaml.YAMLError`. The tables are copies; PyYAML's own classes are left as they are."""

    yaml_implicit_resolvers: ClassVar[dict[str | None, list[tuple[str, re.Pattern[str]]]]] = {
        first: [(tag, regexp) for tag, regexp in resolvers if tag != _TIMESTAMP_TAG]
        for first, resolvers in Resolver.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Hashable, object]:
        self.flatten_mapping(node)
        mapping: dict[Hashable, object] = {}
        for pair in node.value:  # one pair at a time, so keys that differ only before `str` stay apart
            single = yaml.MappingNode(node.tag, [pair], node.start_mark, node.end_mark, node.flow_style)
            mapping.update((str(key), value) for key, value in super().construct_mapping(single, deep=deep).items())
        return mapping


_JsonConstruction.yaml_constructors = {
    tag: constructor for tag, constructor in SafeConstructor.yaml_constructors.items() if tag not in _NON_JSON_TAGS
}


class _PureYamlLoader(_JsonConstruction, yaml.SafeLoader):  # pylint: disable=too-many-ancestors  # PyYAML's loader chain
    """The pure-Python safe loader with the JSON changes; its errors name the problem and its line."""


_YamlLoader: type[yaml.SafeLoader] | type[yaml.CSafeLoader] = _PureYamlLoader
if hasattr(yaml, "CSafeLoader"):  # the C loader is faster

    class _CYamlLoader(_JsonConstruction, yaml.CSafeLoader):  # pylint: disable=too-many-ancestors  # PyYAML's loader chain
        """The C safe loader with the JSON changes."""

    _YamlLoader = _CYamlLoader


def fast_yaml_load(content: str) -> JsonValue:
    """Load YAML content as JSON values using fastest available loader."""
    loaded: JsonValue = yaml.load(content, Loader=_YamlLoader)
    return loaded


# File-level YAML cache — avoids re-parsing the same file from multiple call sites
# (e.g., registry loads checks.yml for Rule construction, compiler re-reads for regex).
_yaml_file_cache: dict[str, tuple[tuple[int, int], JsonValue]] = {}


def load_yaml_file(path: Path) -> JsonValue:
    """Load and cache a YAML file using the fastest available loader; a cached read is reused only
    while the file's modification time and size are unchanged, so an edited file is read again."""
    key = str(path)
    stat = path.stat()
    stamp = (stat.st_mtime_ns, stat.st_size)
    cached = _yaml_file_cache.get(key)
    if cached is not None and cached[0] == stamp and cached[1] is not None:
        return cached[1]
    data = fast_yaml_load(path.read_text(encoding="utf-8"))
    _yaml_file_cache[key] = (stamp, data)
    return data


def forget_yaml_file(path: Path) -> None:
    """Drop the cached read of a YAML file this process just rewrote, so the next read parses the new content."""
    _yaml_file_cache.pop(str(path), None)


def yaml_error_line(exc: Exception) -> str:
    """One line naming what is wrong in a YAML read: the parser's problem and its line, when it gives them."""
    problem = getattr(exc, "problem", None)
    if not problem:
        return (str(exc).splitlines() or [type(exc).__name__])[0]
    mark = getattr(exc, "problem_mark", None)
    return f"{problem} (line {mark.line + 1})" if mark is not None else str(problem)


def unreadable_file_problem(exc: OSError | UnicodeDecodeError | yaml.YAMLError) -> str:
    """What is wrong with a file whose read or parse raised `exc`, as text that follows the file's path."""
    if isinstance(exc, UnicodeDecodeError):
        return "is not UTF-8 text"
    if isinstance(exc, yaml.YAMLError):
        return f"is not valid YAML ({yaml_error_line(exc)})"
    return f"cannot be read ({exc.strerror or exc})"


def value_reading(value: JsonValue) -> str:
    """What YAML read a value as, as a clause that follows the setting or item it belongs to."""
    if value is None:
        return "is empty"
    if isinstance(value, bool):
        return "reads as true/false (yes, no, on, off, true and false all do)"
    if isinstance(value, float) and not math.isfinite(value):
        return "reads as a special number (.nan or .inf)"
    if isinstance(value, (int, float)):
        return f"reads as the number {value}"
    if isinstance(value, str):
        return f"reads as the text {value!r}"
    return f"is a nested {'list' if isinstance(value, list) else 'mapping'}"


def non_text_reading(position: int, item: JsonValue) -> str:
    """What YAML read the non-text item at 1-based `position` of a list as, and what to do about it."""
    reading = f"item {position} {value_reading(item)}"
    if item is None:
        return f"{reading}; remove it"
    if isinstance(item, (list, dict)):
        return f"{reading}, not text"
    return f"{reading}, not text; quote it"


def non_text_items(values: list[JsonValue]) -> list[tuple[int, str]]:
    """`(1-based position, reading)` of each item of `values` that is not text."""
    return [
        (position, non_text_reading(position, item))
        for position, item in enumerate(values, start=1)
        if not isinstance(item, str)
    ]


# A frontmatter delimiter: a whole `---` line (trailing whitespace allowed). A longer dash run,
# or `---` inside a line, is not one.
_DELIMITER_RE = re.compile(r"^---\s*$")
# A top-level `key: value` line whose value is not already quoted, a flow list, or a
# block scalar; a trailing ` # comment` is left out of the value.
_BARE_SCALAR_LINE = re.compile(r"^([A-Za-z_][\w-]*):[ \t]+(?![\"'\[|>#])(.+?)(?:[ \t]+#.*)?[ \t]*$")
# YAML null / bool / number tokens keep their meaning when a block is re-read.
_PLAIN_TOKEN = re.compile(r"^(?:~|null|true|false|[-+]?\d+(?:\.\d+)?)$", re.IGNORECASE)
_UNCLOSED = "the frontmatter block is not closed"


class FrontmatterBlock(NamedTuple):
    """Where a file's leading frontmatter block is: its YAML text and the lines it occupies."""

    text: str  # the YAML between the two delimiter lines
    first_line: int  # 1-based file line of `text`'s first line
    body_line: int  # 0-based index of the first line after the closing delimiter


NOT_A_MAPPING = "the block is not a YAML mapping"


class FrontmatterProblem(NamedTuple):
    """Why a frontmatter block cannot be read: the 1-based file line of the problem and one line of text."""

    line: int
    message: str


class Frontmatter(NamedTuple):
    """What a file's leading frontmatter block holds: the mapping, or the problem that stops it reading."""

    block: FrontmatterBlock | None  # None when the file has no closed block (an opened one is the problem)
    data: JsonObject | None  # None when there is no block, it is empty, or it does not read
    problem: FrontmatterProblem | None


def frontmatter_block(content: str) -> FrontmatterBlock | None:
    """The leading frontmatter block of `content`, or None.

    The first line must be a `---` line (a leading byte-order mark is not part of it) and the
    block ends at the next `---` line; a block that is never closed is not a block. Pure function.
    """
    lines = content.removeprefix("\ufeff").split("\n")
    if not _DELIMITER_RE.match(lines[0]):
        return None
    for index in range(1, len(lines)):
        if _DELIMITER_RE.match(lines[index]):
            return FrontmatterBlock("\n".join(lines[1:index]), 2, index + 1)
    return None


def strip_frontmatter(content: str) -> str:
    """`content` without its leading frontmatter block. Pure function."""
    block = frontmatter_block(content)
    if block is None:
        return content
    return "\n".join(content.split("\n")[block.body_line :])


_CONTROL_CHAR = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _quote_bare_scalars(raw: str) -> str:
    """Wrap the value of each top-level one-line `key: value` in double quotes."""
    lines = []
    for line in raw.split("\n"):
        m = _BARE_SCALAR_LINE.match(line)
        if m and not _PLAIN_TOKEN.match(m.group(2)):
            value = m.group(2).replace("\\", "\\\\").replace('"', '\\"')
            value = _CONTROL_CHAR.sub(lambda c: f"\\x{ord(c.group()):02x}", value)
            line = f'{m.group(1)}: "{value}"'
        lines.append(line)
    return "\n".join(lines)


def _load_block(text: str) -> JsonValue:
    """Load a block's YAML with the fast loader; one that fails is loaded again with the pure-Python
    loader, whose error names the problem and its line."""
    try:
        return fast_yaml_load(text)
    except yaml.YAMLError:
        loaded: JsonValue = yaml.load(text, Loader=_PureYamlLoader)
        return loaded


def _problem(exc: yaml.YAMLError, block: FrontmatterBlock) -> FrontmatterProblem:
    mark = getattr(exc, "problem_mark", None)
    detail = getattr(exc, "problem", None)
    if mark is None or not detail:
        return FrontmatterProblem(block.first_line, yaml_error_line(exc))
    line = block.first_line + mark.line
    return FrontmatterProblem(line, f"{detail} (line {line})")


def read_frontmatter(content: str, *, lenient: bool = False) -> Frontmatter:
    """Read the leading frontmatter block of `content` as a YAML mapping.

    With `lenient` a block that does not parse is read again with every one-line `key: value`
    quoted, which is how an agent reads a rule's path filter; without it the block must parse
    as written. A block that holds something other than a mapping is a problem. Pure function.
    """
    block = frontmatter_block(content)
    if block is None:
        opened = _DELIMITER_RE.match(content.removeprefix("\ufeff").split("\n", 1)[0])
        return Frontmatter(None, None, FrontmatterProblem(1, _UNCLOSED) if opened else None)
    try:
        data = _load_block(block.text)
    except yaml.YAMLError as exc:
        if not lenient:
            return Frontmatter(block, None, _problem(exc, block))
        try:
            data = _load_block(_quote_bare_scalars(block.text))
        except yaml.YAMLError as retry_exc:
            return Frontmatter(block, None, _problem(retry_exc, block))
    if data is None:
        return Frontmatter(block, None, None)
    if not isinstance(data, dict):
        return Frontmatter(block, None, FrontmatterProblem(block.first_line, NOT_A_MAPPING))
    return Frontmatter(block, data, None)


def read_frontmatter_file(path: Path, *, lenient: bool = False) -> Frontmatter | None:
    """`read_frontmatter` of the file at `path`, or None when the file cannot be read. I/O function."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return read_frontmatter(text, lenient=lenient)


def _segments_match(parts: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    """Whether path segments match glob segments; a `**` segment spans zero or more directories."""
    if not pattern:
        return not parts
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        if not rest:
            return bool(parts)
        return any(_segments_match(parts[skip:], rest) for skip in range(len(parts) + 1))
    return bool(parts) and fnmatchcase(parts[0], head) and _segments_match(parts[1:], rest)


_BRACE_GROUP = re.compile(r"\{([^{}]*,[^{}]*)\}")


@lru_cache(maxsize=1024)
def brace_alternatives(glob: str) -> tuple[str, ...]:
    """The globs a `{a,b}` group stands for (`*.{ts,tsx}` -> `*.ts`, `*.tsx`); the glob itself without one.

    Pure function, cached. Only a group holding a comma expands: `{x}` and `{{x}}` stay literal.
    """
    group = _BRACE_GROUP.search(glob)
    if group is None:
        return (glob,)
    head, tail = glob[: group.start()], glob[group.end() :]
    return tuple(alt for option in group.group(1).split(",") for alt in brace_alternatives(head + option + tail))


def glob_matches(path: str, pattern: str, *, anchored: bool = False) -> bool:
    """Whether a posix path matches a glob pattern, one path segment at a time.

    Pure function. `*` and `?` stay inside one segment; a `**` segment spans zero or more
    directories (`a/**/b.md` matches `a/b.md` and `a/x/y/b.md`), and a trailing `**` needs
    at least one more segment. A `{a,b}` group matches any of its alternatives. An anchored or
    absolute pattern must match the whole path;
    any other matches the path's trailing segments (`AGENTS.md` matches `pkg/AGENTS.md`).
    """
    parts = PurePosixPath(path).parts
    for alternative in brace_alternatives(pattern):
        glob = PurePosixPath(alternative)
        if not glob.parts:
            continue
        segments = glob.parts if anchored or glob.is_absolute() else ("**", *glob.parts)
        if _segments_match(parts, segments):
            return True
    return False


def expand_home_pattern(pattern: str) -> str:
    """A `~`-rooted glob pattern with `~` resolved to the user's home directory.

    Lets a pattern be compared against a file outside the scan root, whose relative path falls
    back to its absolute path string. A pattern with no leading `~` is returned unchanged.
    """
    return Path(pattern).expanduser().as_posix() if pattern.startswith("~") else pattern


def is_rooted_pattern(pattern: str) -> bool:
    """Whether a pattern is rooted outside the project: the home folder (`~/...`), the filesystem
    root (`/abs`) or a Windows drive (`C:/...`).

    Pure function. A drive is a single character followed by `:` at the start of the pattern.
    """
    return pattern.startswith(("~", "/")) or pattern[1:2] == ":"


def is_loose_leaf_pattern(pattern: str) -> bool:
    """Whether a pattern can match a file at any directory depth.

    Pure function. True for a bare filename (`CLAUDE.md`) or a `**/`-prefixed glob; a
    path-prefixed pattern (`.claude/rules/**/*.md`) pins the file's location and is not loose.
    """
    return pattern.startswith("**/") or ("/" not in pattern and "**" not in pattern)


def config_pattern_matches(
    rel: str,
    pattern: str,
    *,
    full_path: str | None = None,
    ignore_case: bool = False,
    anchor_loose_leaf: bool = False,
) -> bool:
    """Whether a pattern declared in an agent config matches a file.

    A leading `./` is dropped; a trailing-slash directory
    pattern (`.claude/agent-memory/*/`) matches the `.md` files inside the directories it
    matches; a `~` pattern is resolved to the home directory and matched against `full_path`
    (a file outside the scan root has no useful relative path) when given. The pattern is
    anchored at the scan root unless it is a loose leaf and `anchor_loose_leaf` is False.
    `ignore_case` lower-cases both sides.
    """
    clean = pattern.removeprefix("./")
    expanded = expand_home_pattern(clean + "**/*.md" if clean.endswith("/") else clean)
    subject = full_path if full_path is not None and clean.startswith("~") else rel
    if ignore_case:
        subject, expanded = subject.lower(), expanded.lower()
    return glob_matches(subject, expanded, anchored=anchor_loose_leaf or not is_loose_leaf_pattern(clean))


def matches_any_glob(path: Path, patterns: list[str], target: Path) -> bool:
    """Check whether path matches any glob pattern relative to target.

    Pure function. Tries the target-relative path first, then the absolute
    path, so patterns may include or omit the project-root prefix.
    """
    if not patterns:
        return False
    try:
        rel = path.relative_to(target).as_posix()
    except ValueError:
        rel = path.as_posix()
    return any(glob_matches(rel, pattern) or glob_matches(path.as_posix(), pattern) for pattern in patterns)


def json_object(text: str) -> JsonObject:
    """The JSON object `text` holds; empty when it is not JSON or not an object.

    For a reply body read by its fields: a body without them (a proxy's HTML page, a bare
    list) names nothing, and the caller classifies the reply by its status.
    """
    body: JsonValue = None
    try:
        body = json.loads(text)
    except (ValueError, TypeError):
        logger.debug("Not a JSON body: %r", text[:200])
    return body if isinstance(body, dict) else {}


def write_json_atomic(path: Path, data: JsonValue) -> None:
    """Write `data` as JSON to `path` in one step (I/O).

    The JSON goes to a temp file beside `path` and `os.replace` swaps it in, so a
    reader sees the old file or the new one, never a half-written one. Creates the
    parent directory. Raises `OSError` when the write fails; the temp file is removed.
    """
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def compact_json(value: JsonValue, *, ensure_ascii: bool = True) -> str:
    """`value` as JSON text with no whitespace between items.

    Non-ASCII characters are written as `\\uXXXX` escapes unless `ensure_ascii` is False.
    """
    return json.dumps(value, separators=(",", ":"), ensure_ascii=ensure_ascii)
