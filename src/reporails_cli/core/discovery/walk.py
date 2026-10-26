"""Symlink-following file walkers for instruction discovery.

`Path.rglob` on Python 3.12 does not descend into symlinked directories
(`recurse_symlinks=True` is 3.13-only). The project pins `>=3.12,<3.14`,
so bulk-discovery sites use these helpers instead — they list each directory
with `os.scandir`, follow directory symlinks and track canonical paths to break
symlink cycles.

Inside `shared_dir_listings()` every walker reads a directory once and replays
the listing to each later walk of the same tree, so the many file-name walks of
one discovery pass cost one scan of the disk.
"""

from __future__ import annotations

import contextlib
import contextvars
import errno
import logging
import os
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import NamedTuple, Protocol

from reporails_cli.core.platform.contract.glob_pattern import GLOB_CHARS, brace_alternatives, glob_matches

logger = logging.getLogger(__name__)


_WINDOWS_LOOP_ERRORS = frozenset({1920, 1921})


def safe_resolve(path: Path) -> Path:
    """`path.resolve()`, or `path` unchanged when a symlink loop or an unreadable link stops it."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


def is_symlink_loop_error(exc: BaseException) -> bool:
    """True when `exc` from `Path.resolve(strict=True)` reports a symlink loop.

    Python 3.12 raises `RuntimeError`; 3.13 raises `OSError` with `errno.ELOOP` on POSIX and
    with Windows error 1920 or 1921 (`ERROR_CANT_ACCESS_FILE`, `ERROR_CANT_RESOLVE_FILENAME`:
    an unfollowable symlink) on Windows. A missing file (Windows error 2 or 3) is not a loop.
    """
    if isinstance(exc, RuntimeError) or getattr(exc, "errno", None) == errno.ELOOP:
        return True
    return getattr(exc, "winerror", None) in _WINDOWS_LOOP_ERRORS


def has_symlink_loop(path: Path) -> bool:
    """True when following `path`'s symlinks never ends, so the path names no file.

    Resolves strictly: Python 3.13's non-strict `resolve()` no longer raises on a loop.
    A merely missing path is not a loop.
    """
    try:
        path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return is_symlink_loop_error(exc)
    except ValueError:
        return False
    return False


def is_under(path: Path, root: Path) -> bool:
    """True when `path` resolves to a location under `root` (a looping link is under nothing)."""
    if has_symlink_loop(path):
        return False
    try:
        return path.resolve().is_relative_to(safe_resolve(root))
    except (OSError, RuntimeError, ValueError):
        return False


class Pruner(Protocol):  # pylint: disable=too-few-public-methods  # a protocol of one question
    """Which folders a walk skips."""

    def prunes(self, path: str, name: str, real: str) -> bool:
        """True when the listed folder `path` named `name` (canonical path `real`) is skipped."""


class ListedEntry(NamedTuple):
    """One directory entry, resolved once: name, path, whether it resolves to a regular file
    or to a directory (symlinks followed), and whether it is itself a symlink."""

    name: str
    path: str
    is_file: bool
    is_dir: bool
    is_symlink: bool


# While set, `list_dir` reads each directory once and replays it for every later walk.
_shared_listings: contextvars.ContextVar[dict[str, list[ListedEntry] | None] | None] = contextvars.ContextVar(
    "shared_listings", default=None
)


@contextlib.contextmanager
def shared_dir_listings() -> Iterator[None]:
    """Make every walk inside the block share one scan of each directory.

    A block entered inside another one keeps sharing the outer block's listings.
    """
    if _shared_listings.get() is not None:
        yield
        return
    token = _shared_listings.set({})
    try:
        yield
    finally:
        _shared_listings.reset(token)


def _entry_is_file(entry: os.DirEntry[str]) -> bool:
    """Whether a scandir entry resolves to a regular file (follows symlinks).

    Broken/circular symlinks raise `OSError`; surface them anyway so
    downstream code can report the error properly.
    """
    try:
        return entry.is_file(follow_symlinks=True)
    except OSError:
        return entry.is_symlink()


def _entry_is_dir(entry: os.DirEntry[str]) -> bool:
    """Whether a scandir entry resolves to a directory (symlinks followed)."""
    try:
        return entry.is_dir(follow_symlinks=True)
    except OSError:
        return False


def list_dir(path: str) -> list[ListedEntry] | None:
    """The entries of `path` in scan order (`None` when it cannot be read), shared across the
    walks of a `shared_dir_listings` block."""
    shared = _shared_listings.get()
    if shared is not None and path in shared:
        return shared[path]
    listed: list[ListedEntry] | None
    try:
        with os.scandir(path) as scanner:
            listed = [ListedEntry(e.name, e.path, _entry_is_file(e), _entry_is_dir(e), e.is_symlink()) for e in scanner]
    except OSError:
        listed = None
    if shared is not None:
        shared[path] = listed
    return listed


def child_real(path: str, name: str, parent_real: str, is_symlink: bool) -> str:
    """The canonical path of the listed child `name` at `path` of a folder whose canonical path is `parent_real`.

    A plain folder's canonical path is its parent's plus its name; a symlink or a Windows
    junction is resolved.
    """
    return os.path.realpath(path) if is_symlink or os.path.isjunction(path) else os.path.join(parent_real, name)


def _descend_real(entry: ListedEntry, skip: Pruner, visited_real: set[str], parent_real: str) -> str | None:
    """The canonical path of a listed entry worth descending into, else `None`.

    Follows directory symlinks (so symlinked skills/rules surface) and
    tracks canonical paths in `visited_real` to break cycles —
    each physical directory is entered at most once across the walk.
    """
    if not entry.is_dir:
        return None
    try:
        real = child_real(entry.path, entry.name, parent_real, entry.is_symlink)
    except OSError:
        return None
    if skip.prunes(entry.path, entry.name, real) or real in visited_real:
        return None
    visited_real.add(real)
    return real


def documented_path(path: Path, documented: str) -> Path | None:
    """The path to report for `path` when the agent would open it by the documented name `documented`.

    The listed path when its name equals `documented` exactly. The documented spelling in the
    same folder when the listed name differs only in case and the filesystem resolves
    `documented` there to that same file (a case-insensitive filesystem). None otherwise: on a
    case-sensitive filesystem a differently-cased file is a different file.
    """
    if path.name == documented:
        return path
    if path.name.lower() != documented.lower():
        return None
    named = path.parent / documented
    return named if _same_file(named, path) else None


def _same_file(first: Path, second: Path) -> bool:
    """Whether two paths resolve to one existing file."""
    try:
        return first.samefile(second)
    except OSError:
        return False


def walk_glob(root: Path, filename: str, skip: Pruner) -> list[Path]:
    """Every regular file under root that answers to the documented name `filename`, skipping
    the folders `skip` prunes.

    Much faster than Path.glob("**/name") because it prunes skipped
    subtrees during traversal instead of filtering afterwards.

    A file is found by its exact name, or by a differently-cased name only when the filesystem
    resolves `filename` in that folder to the same file (see `documented_path`), reported under
    the documented spelling; on a case-sensitive filesystem a lowercase `agents.md` is not
    `AGENTS.md`.
    """
    found = _walk(root, skip, lambda path: documented_path(path, filename) is not None)
    return [named for path in found if (named := documented_path(path, filename)) is not None]


def walk_markdown(root: Path, skip: Pruner) -> Iterator[Path]:
    """Yield every regular `.md` file under root, following symlinks safely and not
    entering a folder `skip` prunes."""
    yield from _walk(root, skip, lambda p: p.suffix == ".md")


def walk_files(root: Path, skip: Pruner, predicate: Callable[[Path], bool] | None = None) -> Iterator[Path]:
    """Yield every regular file under root, following symlinks safely and not entering a
    folder `skip` prunes.

    Optional `predicate` further filters the yielded files (e.g. text-file
    detection for the regex runner's catch-all fallback).
    """
    yield from _walk(root, skip, predicate)


def glob_prefix_dir(pattern: str) -> str:
    """The folder a root-anchored glob can match under: its leading segments without glob
    characters, leaving the last segment (a file name or a glob) out. `.claude/skills/*/SKILL.md`
    gives `.claude/skills`; `CLAUDE.md` and `**/x.md` give `""`."""
    prefix: list[str] = []
    for segment in pattern.lstrip("/").split("/")[:-1]:
        if segment in ("", ".", "..") or GLOB_CHARS & set(segment):
            break
        prefix.append(segment)
    return "/".join(prefix)


def _blocked_prefix(root: str, glob: str, skip: Pruner) -> bool:
    """Whether a pattern's leading folders include a pruned folder or a `..` step, so it
    matches nothing."""
    parts = PurePosixPath(glob).parts
    if ".." in parts:
        return True
    literal = _literal_folders(parts[:-1])
    folder, real = root, os.path.realpath(root)
    for name in literal:
        folder = os.path.join(folder, name)
        real = child_real(folder, name, real, os.path.islink(folder))
        if skip.prunes(folder, name, real):
            return True
    return False


def _literal_folders(folders: tuple[str, ...]) -> tuple[str, ...]:
    """The leading folders of a pattern up to its first glob segment."""
    out: list[str] = []
    for segment in folders:
        if GLOB_CHARS & set(segment):
            break
        out.append(segment)
    return tuple(out)


def _folders_ignoring_case(root: Path, prefix: str) -> list[Path]:
    """The folders under `root` whose names equal the `/`-separated `prefix` segments, compared
    without regard to case (every differently-cased folder is kept)."""
    folders = [root]
    for segment in prefix.split("/") if prefix else ():
        wanted = segment.lower()
        folders = [
            Path(entry.path)
            for folder in folders
            for entry in list_dir(str(folder)) or ()
            if entry.is_dir and entry.name.lower() == wanted
        ]
    return folders


def _literal_matches(root: Path, glob: str, ignore_case: bool) -> Iterator[Path]:
    """The regular file a glob-free pattern names (every differently-cased spelling when
    `ignore_case`), checked without a walk."""
    if not ignore_case:
        literal = root / glob
        if literal.is_file():
            yield literal
        return
    prefix, _, leaf = glob.rpartition("/")
    for folder in _folders_ignoring_case(root, prefix):
        for entry in list_dir(str(folder)) or ():
            if entry.is_file and entry.name.lower() == leaf.lower():
                yield Path(entry.path)


def walk_glob_matches(root: Path, pattern: str, skip: Pruner, *, ignore_case: bool = False) -> Iterator[Path]:
    """Yield every regular file under `root` matching `pattern` anchored at `root` (a leading `/`
    is dropped), walking only the pattern's literal prefix folder. A symlinked prefix folder is
    entered; folders `skip` prunes are skipped below it. A pattern with no glob character is checked as
    one path, without a walk. With `ignore_case` the pattern matches names and prefix folders
    without regard to case."""
    glob = pattern.lstrip("/")
    if _blocked_prefix(str(root), glob, skip):
        return
    if not GLOB_CHARS & set(glob):
        yield from _literal_matches(root, glob, ignore_case)
        return
    prefix = glob_prefix_dir(glob)
    if ignore_case:
        starts = _folders_ignoring_case(root, prefix)
        glob = glob.lower()
    else:
        starts = [root / prefix if prefix else root]
    leaves = _leaf_globs(glob)
    for start in starts:
        if not start.is_dir():
            continue
        start_prefix = str(start)
        start_rel = os.path.relpath(start, root).replace(os.sep, "/")
        base = "" if start_rel == "." else start_rel + "/"
        for entry in _walk_files(start, skip, report_loops=False):
            name = entry.name.lower() if ignore_case else entry.name
            if leaves is not None and not any(glob_matches(name, leaf, anchored=True) for leaf in leaves):
                continue
            rel = base + entry.path[len(start_prefix) :].lstrip(os.sep).replace(os.sep, "/")
            if glob_matches(rel.lower() if ignore_case else rel, glob, anchored=True):
                yield Path(entry.path)


def _leaf_globs(glob: str) -> tuple[str, ...] | None:
    """The last path segment of each brace alternative of `glob`: a file name must match one of
    them. `None` when an alternative ends in `**`, which lets any name through."""
    leaves = tuple(PurePosixPath(alt).name for alt in brace_alternatives(glob))
    return None if "**" in leaves or "" in leaves else leaves


def _walk(root: Path, skip: Pruner, predicate: Callable[[Path], bool] | None) -> Iterator[Path]:
    """Every regular file under `root` (see `_walk_files`), as a `Path` that passes `predicate`."""
    for entry in _walk_files(root, skip):
        full_path = Path(entry.path)
        if predicate is None or predicate(full_path):
            yield full_path


def _walk_files(root: Path, skip: Pruner, *, report_loops: bool = True) -> Iterator[ListedEntry]:
    """Shared walker — top-down over listed directories with canonical-path cycle tracking.

    Yields each listed regular file. A plain file is taken from the listing as it stands; a
    symlink is confirmed to resolve to a file, and a circular one is skipped (and logged unless
    `report_loops` is False).
    """
    try:
        root_real = os.path.realpath(root)
    except OSError:
        return
    visited_real = {root_real}
    stack = [(str(root), root_real)]
    while stack:
        current, current_real = stack.pop()
        kept: list[tuple[str, str]] = []
        for entry in list_dir(current) or ():
            if entry.is_dir:
                real = _descend_real(entry, skip, visited_real, current_real)
                if real is not None:
                    kept.append((entry.path, real))
            elif not entry.is_symlink:
                if entry.is_file:
                    yield entry
            elif Path(entry.path).is_file():
                yield entry
            elif report_loops and has_symlink_loop(Path(entry.path)):
                logger.warning("Circular symlink detected: %s — file will be skipped", entry.path)
        stack.extend(reversed(kept))
