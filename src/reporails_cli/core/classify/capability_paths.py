"""Capability path resolver — reverse lookup from (agent, capability, name) to path.

Per-capability targeting (`ails check skill backlog`) needs the inverse of
file classification: given a capability keyword from the agent's
``file_types:`` config and an optional name, resolve to the canonical file
path(s) under the project.

The capability vocabulary is whatever the detected agent's
``framework/rules/<agent>/config.yml`` declares — no Claude-specific labels
in this module.
"""

from __future__ import annotations

import glob
from collections.abc import Callable
from pathlib import Path

from reporails_cli.core.classify import load_file_types
from reporails_cli.core.platform.dto.models import FileTypeDeclaration

_CAPABILITY_SINGULAR_TO_PLURAL: dict[str, str] = {
    "skill": "skills",
    "rule": "rules",
    "agent": "agents",
    "command": "commands",
}


def available_capabilities(agent: str, project_root: Path | None = None) -> list[str]:
    """Return capability names the given agent declares in its config.yml."""
    return [decl.name for decl in load_file_types(agent, project_root=project_root)]


def canonicalize_capability(arg: str, agent: str, project_root: Path | None = None) -> str | None:
    """Map a user-facing capability keyword (singular or plural) to the agent's config key, or None."""
    if not arg:
        return None
    decls = available_capabilities(agent, project_root)
    if arg in decls:
        return arg
    plural = _CAPABILITY_SINGULAR_TO_PLURAL.get(arg)
    if plural and plural in decls:
        return plural
    return None


def is_capability_keyword(arg: str, agent: str, project_root: Path | None = None) -> bool:
    """Sniff helper: does `arg` match a capability name for `agent`?

    Accepts singular (`skill`) or plural (`skills`) forms. Used by
    `ails check` to decide whether the first positional argument is a
    capability keyword (route to focus / listing) or a filesystem path
    (existing behavior).
    """
    if not arg or "/" in arg or arg.startswith("."):
        return False
    return canonicalize_capability(arg, agent, project_root) is not None


def list_capability_targets(
    agent: str,
    capability: str,
    project_root: Path,
) -> list[Path]:
    """Enumerate files matching `capability` for `agent` under `project_root`.

    Globs the project-scope patterns from the agent's ``file_types:``
    declaration. Returns absolute paths. Returns an empty list when the
    agent has no `capability` declared.
    """
    decl = _find_declaration(agent, capability, project_root)
    if decl is None:
        return []
    return _glob_patterns(decl.patterns, project_root)


def resolve_capability(
    agent: str,
    capability: str,
    name: str,
    project_root: Path,
) -> Path | None:
    """Resolve `(agent, capability, name)` to a canonical file path.

    Lists all targets for the capability, then filters by `name` using a
    capability-aware extractor:

    - `skills` / `nested_context` / `child_instruction`: parent directory name
      (e.g. `.claude/skills/backlog/SKILL.md` → `backlog`).
    - `rules` / `agents` / `commands` / `config`: file stem
      (`.claude/rules/git.md` → `git`).
    - `main` / `override`: filename match against `name` (rarely used
      with an explicit name).

    Returns the first match, or None when no candidate matches.
    """
    candidates = list_capability_targets(agent, capability, project_root)
    extractor = _name_extractor_for(capability)
    for candidate in candidates:
        if extractor(candidate) == name:
            return candidate
    return None


def _find_declaration(
    agent: str,
    capability: str,
    project_root: Path,
) -> FileTypeDeclaration | None:
    for decl in load_file_types(agent, project_root=project_root):
        if decl.name == capability:
            return decl
    return None


def _glob_patterns(patterns: tuple[str, ...], project_root: Path) -> list[Path]:
    """Expand glob patterns under project_root. Skips user/managed-scope patterns.

    The `FileTypeDeclaration.patterns` tuple comes from `_extract_patterns`
    in `core/discovery/agents.py`, which collects project + user + managed
    scope patterns. For per-capability targeting we only want files inside
    the project tree — drop patterns that start with `~/`, an absolute
    path outside `project_root`, or `/etc/`-style managed locations.

    Symlink handling: paths are kept in their pre-resolve form so a project
    symlink (e.g. `.claude/` linked to a hub directory) surfaces files
    under the project's path even though the underlying inode is
    elsewhere. Duplicate physical files (same inode reached via multiple
    symlinks) are deduped via the resolved path.
    """
    seen_resolved: set[Path] = set()
    out: list[Path] = []
    for pattern in patterns:
        if _is_external_pattern(pattern):
            continue
        for match in glob.glob(str(project_root / pattern), recursive=True):
            path = Path(match)
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen_resolved:
                continue
            seen_resolved.add(resolved)
            out.append(path)
    return out


def _is_external_pattern(pattern: str) -> bool:
    if pattern.startswith(("~", "/")):
        return True
    return len(pattern) >= 2 and pattern[1] == ":"


def _name_extractor_for(capability: str) -> Callable[[Path], str]:
    """Return a function path → name appropriate for the capability shape."""
    parent_dir_caps = {"skills", "nested_context", "child_instruction"}
    if capability in parent_dir_caps:
        return _parent_dir_name
    return _file_stem


def _parent_dir_name(path: Path) -> str:
    return path.parent.name


def _file_stem(path: Path) -> str:
    return path.stem
