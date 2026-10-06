"""Shared utility functions used across modules.

All functions are pure (no I/O) except where noted.
"""

from __future__ import annotations

import hashlib
import re
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple

import yaml

# Use the C YAML loader when available (faster than the pure Python loader)
try:
    from yaml import CSafeLoader as _YamlLoader
except ImportError:
    from yaml import SafeLoader as _YamlLoader  # type: ignore[assignment]


def fast_yaml_load(content: str) -> Any:
    """Load YAML content using fastest available loader."""
    return yaml.load(content, Loader=_YamlLoader)


# File-level YAML cache — avoids re-parsing the same file from multiple call sites
# (e.g., registry loads checks.yml for Rule construction, compiler re-reads for regex).
_yaml_file_cache: dict[str, tuple[tuple[int, int], Any]] = {}


def load_yaml_file(path: Path) -> Any:
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


def yaml_error_line(exc: Exception) -> str:
    """One line naming what is wrong in a YAML read: the parser's problem and its line, when it gives them."""
    problem = getattr(exc, "problem", None)
    if not problem:
        return (str(exc).splitlines() or [type(exc).__name__])[0]
    mark = getattr(exc, "problem_mark", None)
    return f"{problem} (line {mark.line + 1})" if mark is not None else str(problem)


# Paths whose unreadable YAML was already reported, so one broken file is reported once per run.
_yaml_failures_reported: set[str] = set()


def is_first_yaml_failure(path: Path) -> bool:
    """True the first time `path` is reported as unreadable YAML since the cache was last cleared."""
    key = str(path)
    if key in _yaml_failures_reported:
        return False
    _yaml_failures_reported.add(key)
    return True


def clear_yaml_cache() -> None:
    """Clear the YAML file cache and the reported-failure memory. Called alongside rule cache clearing."""
    _yaml_file_cache.clear()
    _yaml_failures_reported.clear()


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
    data: dict[str, Any] | None  # None when there is no block, it is empty, or it does not read
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


def strip_frontmatter(content: str, *, keep_lines: bool = False) -> str:
    """`content` without its leading frontmatter block; with `keep_lines` the block becomes blank lines.

    Pure function.
    """
    block = frontmatter_block(content)
    if block is None:
        return content
    rest = content.split("\n")[block.body_line :]
    return "\n".join([""] * block.body_line + rest if keep_lines else rest)


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


def _load_block(text: str) -> Any:
    """Load a block's YAML with the fast loader; one that fails is loaded again with the pure-Python
    loader, whose error names the problem and its line."""
    try:
        return fast_yaml_load(text)
    except yaml.YAMLError:
        return yaml.safe_load(text)


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


def compute_content_hash(file_path: Path) -> str:
    """Compute SHA256 hash of file content.

    I/O function — reads file.

    Args:
        file_path: Path to file

    Returns:
        Hash string in format "sha256:{hash16}"
    """
    content = file_path.read_bytes()
    return f"sha256:{hashlib.sha256(content).hexdigest()[:16]}"


def is_valid_path_reference(path: str) -> bool:
    """Check if a string looks like a valid file path reference.

    Pure function.

    Args:
        path: Potential path string

    Returns:
        True if it looks like a valid path reference
    """
    # Must have at least one slash or dot
    if "/" not in path and "." not in path:
        return False

    # Filter out URLs
    if path.startswith("http://") or path.startswith("https://"):
        return False

    # Reject path traversal attempts (../../../etc)
    if path.count("..") > 2:
        return False

    # Reject absolute paths outside project
    if path.startswith("/") and not path.startswith("./"):
        return False

    # Filter out common false positives
    false_positives = {"e.g.", "i.e.", "etc.", "vs.", "v1", "v2"}
    return path.lower() not in false_positives


def relative_to_safe(path: Path, base: Path) -> str:
    """Get relative path safely, with fallback to absolute.

    Pure function.

    Args:
        path: Path to convert
        base: Base directory

    Returns:
        Relative path string, or absolute if not relative to base
    """
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


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


def normalize_rule_id(rule_id: str) -> str:
    """Normalize rule ID to uppercase.

    Pure function.

    Args:
        rule_id: Raw rule ID

    Returns:
        Uppercase rule ID
    """
    return rule_id.upper()
