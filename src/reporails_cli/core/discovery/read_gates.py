"""Files an agent reads only under a condition its own settings decide.

Claude Code reads `AGENTS.md` through a built-in plugin, so a project's
`AGENTS.md` belongs to a Claude check only when Claude would load it:

- With the default setting, only when no `CLAUDE.md`, `.claude/CLAUDE.md` or
  `CLAUDE.local.md` sits in the project root or any directory above it (the user's own
  `~/.claude/CLAUDE.md` does not count). Then the root `AGENTS.md` and
  `.claude/AGENTS.md` load at session start, and a subdirectory's `AGENTS.md` loads on
  demand when that subdirectory has none of those three files of its own.
- With `claude-md-and-agents-md`, every `AGENTS.md` loads alongside the `CLAUDE.md` files.
- With `claude-md`, `managed-only`, or the plugin turned off, no `AGENTS.md` loads.

Anything under a `.agents/` directory is never read.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from reporails_cli.core.discovery.file_aliases import AliasHow, has_same_text
from reporails_cli.core.discovery.project_root import resolve_project_root
from reporails_cli.core.discovery.walk import list_dir, safe_resolve
from reporails_cli.core.platform.config.claude_settings import (
    MODE_CLAUDE_MD_AND_AGENTS_MD,
    MODE_CLAUDE_MD_OR_AGENTS_MD,
    MODES_WITHOUT_AGENTS_MD,
    MODES_WITHOUT_LAUNCH_INSTRUCTIONS,
    claude_instruction_files_mode,
)

_AGENTS_MD = "agents.md"
_CLAUDE_FAMILY = ("claude.md", "claude.local.md")


def _file_named(directory: Path, name: str) -> Path | None:
    """The file in `directory` called `name` (any case), or None."""
    for entry in list_dir(str(directory)) or ():
        if entry.name.lower() == name and entry.is_file:
            return Path(entry.path)
    return None


def _claude_file_in(directory: Path, user_file: Path) -> Path | None:
    """The `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` in `directory`, in that order, or None."""
    plain = _file_named(directory, "claude.md")
    if plain is not None:
        return plain
    dot = _file_named(directory / ".claude", "claude.md")
    if dot is not None and safe_resolve(dot) != user_file:
        return dot
    return _file_named(directory, "claude.local.md")


def _claude_file_folder(claude_file: Path) -> Path:
    """The folder a `CLAUDE.md`-family file belongs to: the one holding `.claude/` for a `.claude/CLAUDE.md`."""
    parent = claude_file.parent
    return parent.parent if parent.name.lower() == ".claude" else parent


def _user_claude_md() -> Path:
    return safe_resolve(Path.home() / ".claude" / "CLAUDE.md")


def claude_file_at_or_above(root: Path) -> Path | None:
    """The `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` nearest `root`, looking in `root`
    and then each directory above it, other than the user's own `~/.claude/CLAUDE.md`; None when there is none."""
    user_file = _user_claude_md()
    start = safe_resolve(root)
    for directory in (start, *start.parents):
        found = _claude_file_in(directory, user_file)
        if found is not None:
            return found
    return None


def _never_read(path: Path, root: Path) -> bool:
    """Anything under a `.agents/` directory, and a `.claude/AGENTS.md` below the root."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    dirs = [part.lower() for part in parts[:-1]]
    return ".agents" in dirs or (len(dirs) > 1 and dirs[-1] == ".claude")


def _loads_at_session_start(path: Path, root: Path) -> bool:
    return path.parent in (root, root / ".claude")


SkipReason = Literal["claude_md_present", "subdir_has_claude_md", "setting_off", "never_read"]


@dataclass(frozen=True)
class SkippedFile:
    """An `AGENTS.md` Claude Code does not read, and why; `cause` is the `CLAUDE.md`-family file that made
    it skip the file (`claude_md_present`, `subdir_has_claude_md`), None for the other reasons."""

    path: Path
    reason: SkipReason
    cause: Path | None


@dataclass(frozen=True)
class AliasFile:
    """An `AGENTS.md` whose text reaches Claude through a `CLAUDE.md` it reads: `link` when it is the
    same file under another name, `copy` when it is a separate file with exactly the same text."""

    path: Path
    same_as: Path
    how: AliasHow


@dataclass(frozen=True)
class AgentsMdReads:
    """The `AGENTS.md` files Claude Code loads, the ones it skips, the ones that are a `CLAUDE.md`
    it reads under another name, and the setting that decided."""

    kept: list[Path]
    skipped: list[SkippedFile]
    mode: str
    aliases: list[AliasFile]


def claude_agents_md_reads(found: list[Path], target: Path, read: Iterable[Path] = ()) -> AgentsMdReads:
    """Split the `AGENTS.md` files among `found` into those Claude Code loads for a session in
    `target` and those it skips, each skipped file with its reason. A skipped file that is the same
    file as, or holds exactly the text of, a `CLAUDE.md`-family file among `read` (the instruction
    files the session reads) is reported as an alias of it instead."""
    if not found:
        return AgentsMdReads([], [], "", [])
    root = resolve_project_root(target)
    mode = claude_instruction_files_mode(root)
    kept: list[Path] = []
    skipped: list[SkippedFile] = []
    aliases: list[AliasFile] = []
    claude_above = claude_file_at_or_above(root) if mode == MODE_CLAUDE_MD_OR_AGENTS_MD else None
    user_file = _user_claude_md()
    claude_files = {} if mode in MODES_WITHOUT_LAUNCH_INSTRUCTIONS else _claude_files_by_identity(read, root)
    for path in found:
        skip = _skip_reason(path, root, mode, claude_above=claude_above, user_file=user_file)
        if skip is None:
            kept.append(path)
            continue
        same_as = claude_files.get(safe_resolve(path))
        if same_as is not None:
            aliases.append(AliasFile(path, same_as, "link"))
            continue
        twin = _file_with_same_text(path, list(claude_files.items()), prefer=skip[1], user_file=user_file)
        if twin is not None:
            aliases.append(AliasFile(path, twin, "copy"))
            continue
        skipped.append(SkippedFile(path, *skip))
    return AgentsMdReads(kept, skipped, mode, aliases)


def _file_with_same_text(
    path: Path, candidates: list[tuple[Path, Path]], *, prefer: Path | None, user_file: Path
) -> Path | None:
    """The `CLAUDE.md`-family file among `candidates` (resolved path, path) that holds exactly the text
    of `path` and is read in every session that reads `path`, the one at `prefer` first."""
    folder = safe_resolve(path.parent)
    wanted = safe_resolve(prefer) if prefer is not None else None
    ordered = [pair for pair in candidates if pair[0] == wanted] + [pair for pair in candidates if pair[0] != wanted]
    return next(
        (
            file
            for resolved, file in ordered
            if _read_wherever_read(resolved, file, folder, user_file) and has_same_text(path, file)
        ),
        None,
    )


def _read_wherever_read(resolved: Path, claude_file: Path, folder: Path, user_file: Path) -> bool:
    """True when `claude_file` is the user's own `~/.claude/CLAUDE.md`, or sits in `folder` or a folder above it;
    for a `.claude/CLAUDE.md` the folder that counts is the one holding `.claude/`."""
    if resolved == user_file:
        return True
    owner = safe_resolve(_claude_file_folder(claude_file))
    return owner == folder or owner in folder.parents


def _claude_files_by_identity(read: Iterable[Path], root: Path) -> dict[Path, Path]:
    """The `CLAUDE.md`-family files among `read`, each under the resolved path it is the same file as.
    A file under a `.agents/` directory of the project is not one Claude Code reads. The dict is ordered by path."""
    return {
        safe_resolve(path): path
        for path in sorted(read, key=str)
        if path.name.lower() in _CLAUDE_FAMILY and not _in_agents_dir(path, root)
    }


def _in_agents_dir(path: Path, root: Path) -> bool:
    try:
        return ".agents" in (part.lower() for part in path.relative_to(root).parts[:-1])
    except ValueError:
        return False


def _skip_reason(
    path: Path, root: Path, mode: str, *, claude_above: Path | None, user_file: Path
) -> tuple[SkipReason, Path | None] | None:
    """Why Claude Code skips `path` and the `CLAUDE.md`-family file that made it, None when it loads it."""
    if _never_read(path, root):
        return "never_read", None
    if mode in MODES_WITHOUT_AGENTS_MD:
        return "setting_off", None
    if mode == MODE_CLAUDE_MD_AND_AGENTS_MD:
        return None
    if claude_above is not None:
        return "claude_md_present", claude_above
    if _loads_at_session_start(path, root):
        return None
    beside = _claude_file_in(path.parent, user_file)
    return None if beside is None else ("subdir_has_claude_md", beside)


def claude_agents_md_files(found: list[Path], target: Path) -> list[Path]:
    """The `AGENTS.md` files among `found` that Claude Code loads for a session in `target`."""
    return claude_agents_md_reads(found, target).kept


# (agent, file type) -> the files among a discovered list that the agent really reads.
_GATES: dict[tuple[str, str], Callable[[list[Path], Path], list[Path]]] = {
    ("claude", "agents_md"): claude_agents_md_files,
    ("claude", "nested_context"): claude_agents_md_files,
}

# Agent -> file names it reads only in place of its own main file.
_FALLBACK_READS: dict[str, frozenset[str]] = {"claude": frozenset({_AGENTS_MD})}


def gated_file_types(agent_id: str) -> tuple[str, ...]:
    """The file types of `agent_id` whose files a read gate narrows."""
    return tuple(file_type for agent, file_type in _GATES if agent == agent_id)


def apply_read_gate(agent_id: str, file_type: str, found: list[Path], target: Path) -> list[Path]:
    """`found`, narrowed to the files `agent_id` reads for `file_type` in a session at `target`."""
    gate = _GATES.get((agent_id, file_type))
    return found if gate is None else gate(found, target)


def reads_as_fallback(agent_id: str, path: Path) -> bool:
    """True when `agent_id` reads `path` only in place of its own main file (Claude and
    `AGENTS.md`), so another agent that reads the same file natively keeps it."""
    return path.name.lower() in _FALLBACK_READS.get(agent_id, frozenset())
