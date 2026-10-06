"""Files an agent reads only under a condition its own settings decide.

Claude Code reads `AGENTS.md` through its built-in `agents-md` plugin, so a project's
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

from collections.abc import Callable
from pathlib import Path

from reporails_cli.core.discovery.walk import list_dir, safe_resolve

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
    return path.parent == root or path.parent == root / ".claude"


def claude_agents_md_files(found: list[Path], target: Path) -> list[Path]:
    """The `AGENTS.md` files among `found` that Claude Code loads for a session in `target`."""
    from reporails_cli.core.discovery.agent_discovery import resolve_project_root
    from reporails_cli.core.platform.config.claude_settings import (
        MODE_CLAUDE_MD_AND_AGENTS_MD,
        MODES_WITHOUT_AGENTS_MD,
        claude_instruction_files_mode,
    )

    if not found:
        return []
    root = resolve_project_root(target)
    mode = claude_instruction_files_mode(root)
    if mode in MODES_WITHOUT_AGENTS_MD:
        return []
    readable = [f for f in found if not _never_read(f, root)]
    if mode == MODE_CLAUDE_MD_AND_AGENTS_MD:
        return readable
    if claude_file_at_or_above(root):
        return []
    user_file = _user_claude_md()
    return [f for f in readable if _loads_at_session_start(f, root) or not _has_claude_file(f.parent, user_file)]


# (agent, file type) -> the files among a discovered list that the agent really reads.
_GATES: dict[tuple[str, str], Callable[[list[Path], Path], list[Path]]] = {
    ("claude", "agents_md"): claude_agents_md_files,
    ("claude", "nested_context"): claude_agents_md_files,
}

# Agent -> file names it reads only in place of its own main file.
_FALLBACK_READS: dict[str, frozenset[str]] = {"claude": frozenset({_AGENTS_MD})}


def apply_read_gate(agent_id: str, file_type: str, found: list[Path], target: Path) -> list[Path]:
    """`found`, narrowed to the files `agent_id` reads for `file_type` in a session at `target`."""
    gate = _GATES.get((agent_id, file_type))
    return found if gate is None else gate(found, target)


def reads_as_fallback(agent_id: str, path: Path) -> bool:
    """True when `agent_id` reads `path` only in place of its own main file (Claude and
    `AGENTS.md`), so another agent that reads the same file natively keeps it."""
    return path.name.lower() in _FALLBACK_READS.get(agent_id, frozenset())
