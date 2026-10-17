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


def _names_in(directory: Path) -> set[str]:
    return {entry.name.lower() for entry in list_dir(str(directory)) or () if entry.is_file}


def _dot_claude_md(directory: Path) -> Path | None:
    """`directory/.claude/CLAUDE.md` (any case), or None."""
    dot_claude = directory / ".claude"
    for entry in list_dir(str(dot_claude)) or ():
        if entry.name.lower() == "claude.md" and entry.is_file:
            return Path(entry.path)
    return None


def _has_claude_file(directory: Path, user_file: Path) -> bool:
    """Whether `directory` holds a `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md`."""
    if _names_in(directory) & set(_CLAUDE_FAMILY):
        return True
    dot = _dot_claude_md(directory)
    if dot is None:
        return False
    return safe_resolve(dot) != user_file


def _user_claude_md() -> Path:
    return safe_resolve(Path.home() / ".claude" / "CLAUDE.md")


def claude_file_at_or_above(root: Path) -> bool:
    """Whether a `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` sits in `root` or
    any directory above it, other than the user's own `~/.claude/CLAUDE.md`."""
    user_file = _user_claude_md()
    start = safe_resolve(root)
    return any(_has_claude_file(directory, user_file) for directory in (start, *start.parents))


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
    """An `AGENTS.md` Claude Code does not read, and why."""

    path: Path
    reason: SkipReason


@dataclass(frozen=True)
class AliasFile:
    """An `AGENTS.md` that links to a `CLAUDE.md` Claude Code reads: the same file under another name."""

    path: Path
    same_as: Path


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
    file as a `CLAUDE.md`-family file among `read` (the instruction files the session reads) is
    reported as an alias of it instead."""
    if not found:
        return AgentsMdReads([], [], "", [])
    root = resolve_project_root(target)
    mode = claude_instruction_files_mode(root)
    kept: list[Path] = []
    skipped: list[SkippedFile] = []
    aliases: list[AliasFile] = []
    claude_above = mode == MODE_CLAUDE_MD_OR_AGENTS_MD and claude_file_at_or_above(root)
    user_file = _user_claude_md()
    claude_files = {} if mode in MODES_WITHOUT_LAUNCH_INSTRUCTIONS else _claude_files_by_identity(read, root)
    for path in found:
        reason = _skip_reason(path, root, mode, claude_above=claude_above, user_file=user_file)
        if reason is None:
            kept.append(path)
            continue
        same_as = claude_files.get(safe_resolve(path))
        if same_as is None:
            skipped.append(SkippedFile(path, reason))
        else:
            aliases.append(AliasFile(path, same_as))
    return AgentsMdReads(kept, skipped, mode, aliases)


def _claude_files_by_identity(read: Iterable[Path], root: Path) -> dict[Path, Path]:
    """The `CLAUDE.md`-family files among `read`, each under the resolved path it is the same file as.
    A file under a `.agents/` directory of the project is not one Claude Code reads."""
    return {
        safe_resolve(path): path
        for path in read
        if path.name.lower() in _CLAUDE_FAMILY and not _in_agents_dir(path, root)
    }


def _in_agents_dir(path: Path, root: Path) -> bool:
    try:
        return ".agents" in (part.lower() for part in path.relative_to(root).parts[:-1])
    except ValueError:
        return False


def _skip_reason(path: Path, root: Path, mode: str, *, claude_above: bool, user_file: Path) -> SkipReason | None:
    """Why Claude Code skips `path`, None when it loads it."""
    if _never_read(path, root):
        return "never_read"
    if mode in MODES_WITHOUT_AGENTS_MD:
        return "setting_off"
    if mode == MODE_CLAUDE_MD_AND_AGENTS_MD:
        return None
    if claude_above:
        return "claude_md_present"
    if _loads_at_session_start(path, root) or not _has_claude_file(path.parent, user_file):
        return None
    return "subdir_has_claude_md"


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
