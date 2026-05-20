"""Capability path resolver — reverse lookup from (agent, capability, name) to path.

Per-capability targeting (`ails check skills:backlog`) needs the inverse of
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
    "memory": "memories",
    "subagent_memory": "subagent_memories",
    "nested_context": "nested_contexts",
    "referenced": "references",
}

# Capabilities that fold into a primary bucket for the redesigned display.
# `ails check main` resolves to root-level family only (main + override).
# Nested CLAUDE.md / nested_context / child_instruction files have their own
# capability and are NOT folded under `main`. `ails check memories` enumerates
# both memory and subagent_memory entries.
_CAPABILITY_FOLD: dict[str, tuple[str, ...]] = {
    "main": ("main", "override"),
    "memories": ("memory", "subagent_memory"),
    "memory": ("memory", "subagent_memory"),
}

# Capabilities not declared in any agent's `config.yml` — they're synthesized
# by the classifier at scan time. `referenced` enumerates `[text](path)`-reached
# files (`file_type: referenced` per the carve-out in
# `cli/specs/plans/0.5.11-referenced-capability-carve-out.md`) and works across
# all agents since markdown links are universal. Requires `generic_scanning:
# true` in `.ails/config.yml` for results to be non-empty.
_VIRTUAL_CAPABILITIES: frozenset[str] = frozenset({"referenced", "references"})


def available_capabilities(agent: str, project_root: Path | None = None) -> list[str]:
    """Return capability names the given agent declares in its config.yml."""
    return [decl.name for decl in load_file_types(agent, project_root=project_root)]


def canonicalize_capability(arg: str, agent: str, project_root: Path | None = None) -> str | None:
    """Map a user-facing capability keyword (singular or plural) to the agent's config key, or None.

    For fold-source aliases (`memories`, `memory`), returns the alias itself
    when any member of the fold tuple is declared by the agent — the
    listing path walks the fold tuple. For non-fold aliases, returns the
    singular config key declared by the agent.

    Virtual capabilities (`referenced` / `references`) are synthesized by
    the classifier and don't appear in any agent config; they canonicalize
    to the singular `referenced` regardless of agent.
    """
    if not arg:
        return None
    if arg in _VIRTUAL_CAPABILITIES:
        return "referenced"
    decls = available_capabilities(agent, project_root)
    if arg in decls:
        return arg
    fold = _CAPABILITY_FOLD.get(arg)
    if fold and any(f in decls for f in fold):
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
    exclude_dirs: list[str] | tuple[str, ...] | None = None,
) -> list[Path]:
    """Enumerate files matching `capability` for `agent` under `project_root`.

    Globs the project-scope patterns from the agent's ``file_types:``
    declaration, honoring `.ails/config.yml: exclude_dirs` via
    `exclude_dirs`. Returns absolute paths. Returns an empty list when
    the agent has no `capability` declared.

    Fold-source aliases (``main``, ``memories``, ``memory``) union the
    enumeration of every member declared by the agent. Memory file_types
    whose patterns target ``~/.claude/...`` delegate to
    `memory_locator.memory_entries_for_agent` so user-scope entries
    surface in the listing.
    """
    if capability == "referenced":
        return _list_referenced_targets(agent, project_root)

    out: list[Path] = []
    seen: set[Path] = set()
    for ft_name in _resolve_fold(agent, capability, project_root):
        decl = _find_declaration(agent, ft_name, project_root)
        if decl is None:
            continue
        if _is_user_scope_memory(ft_name, decl.patterns):
            paths = _user_scope_memory_paths(agent, project_root)
        else:
            paths = _glob_patterns(decl.patterns, project_root, exclude_dirs, decl=decl)
        for path in paths:
            resolved = _safe_resolve(path)
            if resolved in seen:
                continue
            seen.add(resolved)
            out.append(path)
    return out


def _list_referenced_targets(agent: str, project_root: Path) -> list[Path]:
    """Enumerate `[text](path)`-reached files via classifier output.

    Runs link-walker discovery (`generic_scanning: true`) against the
    detected agent's surfaces and returns paths whose synthesized
    `file_type == "referenced"`. Requires `generic_scanning` to be enabled
    in the project — if disabled, returns an empty list (classifier won't
    walk).
    """
    from reporails_cli.core.classify import classify_files, load_file_types
    from reporails_cli.core.discovery.agent_discovery import discover_from_config

    discovered = discover_from_config(project_root, agent)
    if discovered is None:
        return []
    instruction_files, _rule_files, _config_files = discovered
    file_types = load_file_types(agent, project_root=project_root)
    classified = classify_files(
        project_root,
        instruction_files,
        file_types,
        generic_scanning=True,
    )
    return [cf.path for cf in classified if cf.file_type == "referenced"]


def _resolve_fold(agent: str, capability: str, project_root: Path) -> tuple[str, ...]:
    """Return the fold tuple for `capability`, restricted to declared types."""
    decls = available_capabilities(agent, project_root)
    fold = _CAPABILITY_FOLD.get(capability)
    if fold is None:
        return (capability,) if capability in decls else ()
    return tuple(f for f in fold if f in decls)


def _is_user_scope_memory(ft_name: str, patterns: tuple[str, ...]) -> bool:
    """True when the declared file_type names a user-scope memory directory.

    The capability-listing path can't reach `~/.claude/projects/*/memory/`
    via `glob.glob(project_root / pattern)` because the pattern is absolute
    once expanded. `memory_locator` already knows how to walk the
    per-project memory directory — delegate when the file_type name is
    `memory` or `subagent_memory` AND any pattern starts with `~/`.
    """
    if ft_name not in ("memory", "subagent_memory"):
        return False
    return any(p.startswith("~/") for p in patterns)


def _user_scope_memory_paths(agent: str, project_root: Path) -> list[Path]:
    """Resolve user-scope memory entries via memory_locator."""
    from reporails_cli.core.discovery.memory_locator import memory_entries_for_agent

    return [entry.path for entry in memory_entries_for_agent(agent, project_root)]


def _safe_resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def resolve_capability(
    agent: str,
    capability: str,
    name: str,
    project_root: Path,
    exclude_dirs: list[str] | tuple[str, ...] | None = None,
) -> Path | None:
    """Resolve `(agent, capability, name)` to a canonical file path.

    Lists all targets for the capability, then filters by `name` using a
    capability-aware extractor:

    - `skills` / `nested_context` / `child_instruction`: parent directory name
      (e.g. `.claude/skills/backlog/SKILL.md` → `backlog`).
    - `rules` / `agents` / `commands` / `config`: file stem
      (`.claude/rules/git.md` → `git`).
    - `memory` / `memories`: file stem (memory entry filename minus `.md`).
    - `main` / `override`: filename match against `name` (rarely used
      with an explicit name).

    Returns the first match, or None when no candidate matches.
    """
    candidates = list_capability_targets(agent, capability, project_root, exclude_dirs)
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


def _glob_patterns(
    patterns: tuple[str, ...],
    project_root: Path,
    exclude_dirs: list[str] | tuple[str, ...] | None = None,
    decl: FileTypeDeclaration | None = None,
) -> list[Path]:
    """Expand glob patterns under project_root. Skips user/managed-scope patterns.

    The `FileTypeDeclaration.patterns` tuple comes from `_extract_patterns`
    in `core/discovery/agents.py`, which collects project + user + managed
    scope patterns. For per-capability targeting we only want files inside
    the project tree — drop patterns that start with `~/`, an absolute
    path outside `project_root`, or `/etc/`-style managed locations.

    `exclude_dirs` mirrors `.ails/config.yml: exclude_dirs` — any matched
    path whose ancestor-chain (relative to project_root) contains a
    directory name in the set is filtered out so listing-mode matches
    full-project discovery.

    `decl` carries the file_type semantics — when provided, files matched
    via a loose-leaf pattern (`**/X.md` or bare `X.md`) are filtered by the
    declaration's `scope` + `loading` properties (global+session_start →
    cwd-level only; nested → descendants only), mirroring `classify_files`
    so `ails check main` and `ails check child_instruction` partition
    shared `**/CLAUDE.md` matches the same way the classifier does.

    Symlink handling: paths are kept in their pre-resolve form so a project
    symlink (e.g. `.claude/` linked to a hub directory) surfaces files
    under the project's path even though the underlying inode is
    elsewhere. Duplicate physical files (same inode reached via multiple
    symlinks) are deduped via the resolved path.
    """
    seen_resolved: set[Path] = set()
    excl_set = set(exclude_dirs or ())
    out: list[Path] = []
    for pattern in patterns:
        if _is_external_pattern(pattern):
            continue
        for match in glob.glob(str(project_root / pattern), recursive=True):
            path = Path(match)
            if not path.is_file():
                continue
            if _is_under_excluded_dir(path, project_root, excl_set):
                continue
            if decl is not None and not _decl_location_matches(path, decl, pattern, project_root):
                continue
            resolved = path.resolve()
            if resolved in seen_resolved:
                continue
            seen_resolved.add(resolved)
            out.append(path)
    return out


def _decl_location_matches(
    file_path: Path,
    decl: FileTypeDeclaration,
    matched_pattern: str,
    project_root: Path,
) -> bool:
    """Apply the classify-level `scope`/`loading` filter to a listing-path match.

    Mirrors `core.classify._location_matches_mode` for the listing case
    where `project_root` doubles as scan_root and the ancestor chain
    reduces to `{project_root}` (the listing path is invoked at the
    project root, not at an arbitrary cwd).
    """
    scope = decl.properties.get("scope")
    loading = decl.properties.get("loading")
    parent = file_path.parent
    in_ancestor_chain = parent == project_root

    if scope == "global" and loading == "session_start":
        if _is_loose_leaf_pattern(matched_pattern):
            return in_ancestor_chain
        return True
    if scope == "nested":
        return not in_ancestor_chain
    return True


def _is_loose_leaf_pattern(pattern: str) -> bool:
    """Pattern that can match a file at any directory depth.

    Mirrors `core.classify._is_loose_leaf_pattern`.
    """
    if pattern.startswith("**/"):
        return True
    return "/" not in pattern and "**" not in pattern


def _is_under_excluded_dir(path: Path, project_root: Path, excl: set[str]) -> bool:
    """True when any ancestor dir name (relative to project_root) is in `excl`."""
    if not excl:
        return False
    try:
        rel = path.relative_to(project_root)
    except ValueError:
        return False
    return any(part in excl for part in rel.parts[:-1])


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
