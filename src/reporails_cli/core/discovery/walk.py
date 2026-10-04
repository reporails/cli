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
from typing import NamedTuple

from reporails_cli.core.platform.utils.utils import glob_matches

logger = logging.getLogger(__name__)


def safe_resolve(path: Path) -> Path:
    """`path.resolve()`, or `path` unchanged when a symlink loop or an unreadable link stops it."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


def has_symlink_loop(path: Path) -> bool:
    """True when following `path`'s symlinks never ends, so the path names no file."""
    try:
        path.resolve()
    except RuntimeError:
        return True
    except OSError as exc:
        return exc.errno == errno.ELOOP
    return False


def is_under(path: Path, root: Path) -> bool:
    """True when `path` resolves to a location under `root` (a looping link is under nothing)."""
    try:
        return path.resolve().is_relative_to(safe_resolve(root))
    except (OSError, RuntimeError, ValueError):
        return False


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


def _descend_real(
    entry: ListedEntry, exclude_dirs: frozenset[str], visited_real: set[str], parent_real: str
) -> str | None:
    """The canonical path of a listed entry worth descending into, else `None`.

    Follows directory symlinks (so symlinked skills/rules surface) and
    tracks canonical paths in `visited_real` to break cycles —
    each physical directory is entered at most once across the walk.

    A plain directory's canonical path is its parent's canonical path plus its name, so
    only a symlink pays for a path resolution; resolving every directory on a large tree
    cost seconds per walk.
    """
    if entry.name in exclude_dirs or not entry.is_dir:
        return None
    try:
        real = os.path.realpath(entry.path) if entry.is_symlink else os.path.join(parent_real, entry.name)
    except OSError:
        return None
    if real in visited_real:
        return None
    visited_real.add(real)
    return real


def walk_glob(root: Path, filename: str, exclude_dirs: frozenset[str]) -> list[Path]:
    """Every regular file under root named `filename`, skipping excluded dirs.

    Much faster than Path.glob("**/name") because it prunes excluded
    subtrees during traversal instead of filtering afterwards.

    Match is case-INSENSITIVE (`agents.md` == `AGENTS.md`). Repos in the wild
    use mixed casing and the agent specs do not mandate exact case (the
    AGENTS.md spec is silent on casing), so a lowercase copy is a real
    instruction file.
    """
    filename_lower = filename.lower()
    return list(_walk(root, exclude_dirs, lambda path: path.name.lower() == filename_lower))


def walk_markdown(root: Path, exclude_dirs: frozenset[str]) -> Iterator[Path]:
    """Yield every regular `.md` file under root, following symlinks safely and not
    entering a directory named in `exclude_dirs`."""
    yield from _walk(root, exclude_dirs, lambda p: p.suffix == ".md")


def walk_files(
    root: Path, exclude_dirs: frozenset[str], predicate: Callable[[Path], bool] | None = None
) -> Iterator[Path]:
    """Yield every regular file under root, following symlinks safely and not entering a
    directory named in `exclude_dirs`.

    Optional `predicate` further filters the yielded files (e.g. text-file
    detection for the regex runner's catch-all fallback).
    """
    yield from _walk(root, exclude_dirs, predicate)


_GLOB_CHARS = frozenset("*?[{")


def glob_prefix_dir(pattern: str) -> str:
    """The folder a root-anchored glob can match under: its leading segments without glob
    characters, leaving the last segment (a file name or a glob) out. `.claude/skills/*/SKILL.md`
    gives `.claude/skills`; `CLAUDE.md` and `**/x.md` give `""`."""
    prefix: list[str] = []
    for segment in pattern.lstrip("/").split("/")[:-1]:
        if segment in ("", ".", "..") or _GLOB_CHARS & set(segment):
            break
        prefix.append(segment)
    return "/".join(prefix)


def _blocked_prefix(glob: str, exclude_dirs: frozenset[str]) -> bool:
    """Whether a pattern's leading folders include an excluded folder or a `..` step, so it
    matches nothing."""
    folders = PurePosixPath(glob).parts[:-1]
    return ".." in PurePosixPath(glob).parts or bool(exclude_dirs.intersection(_literal_folders(folders)))


def _literal_folders(folders: tuple[str, ...]) -> tuple[str, ...]:
    """The leading folders of a pattern up to its first glob segment."""
    out: list[str] = []
    for segment in folders:
        if _GLOB_CHARS & set(segment):
            break
        out.append(segment)
    return tuple(out)


def walk_glob_matches(root: Path, pattern: str, exclude_dirs: frozenset[str]) -> Iterator[Path]:
    """Yield every regular file under `root` matching `pattern` anchored at `root` (a leading `/`
    is dropped), walking only the pattern's literal prefix folder. A symlinked prefix folder is
    entered; excluded folders are skipped below it. A pattern with no glob character is checked as
    one path, without a walk."""
    glob = pattern.lstrip("/")
    if _blocked_prefix(glob, exclude_dirs):
        return
    if not _GLOB_CHARS & set(glob):
        literal = root / glob
        if literal.is_file():
            yield literal
        return
    prefix = glob_prefix_dir(glob)
    start = root / prefix if prefix else root
    if not start.is_dir():
        return
    for path in _walk(start, exclude_dirs, None):
        if glob_matches(path.relative_to(root).as_posix(), glob, anchored=True):
            yield path


def _walk(root: Path, exclude_dirs: frozenset[str], predicate: Callable[[Path], bool] | None) -> Iterator[Path]:
    """Shared walker — top-down over listed directories with canonical-path cycle tracking."""
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
                real = _descend_real(entry, exclude_dirs, visited_real, current_real)
                if real is not None:
                    kept.append((entry.path, real))
                continue
            full_path = Path(entry.path)
            if predicate is not None and not predicate(full_path):
                continue
            if full_path.is_file():
                yield full_path
            elif entry.is_symlink and has_symlink_loop(full_path):
                logger.warning("Circular symlink detected: %s — file will be skipped", full_path)
        stack.extend(reversed(kept))
