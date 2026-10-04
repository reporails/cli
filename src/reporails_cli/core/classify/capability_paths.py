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

from collections.abc import Callable
from pathlib import Path
from typing import Any

from reporails_cli.core.classify import load_file_types
from reporails_cli.core.discovery.agent_discovery import _is_external_pattern
from reporails_cli.core.discovery.plugin_roots import expand_plugin_patterns
from reporails_cli.core.discovery.read_gates import apply_read_gate
from reporails_cli.core.discovery.walk import safe_resolve, walk_glob_matches
from reporails_cli.core.platform.config.vocabulary import load_capability_vocabulary
from reporails_cli.core.platform.dto.models import FileTypeDeclaration


def available_capabilities(agent: str, project_root: Path | None = None) -> list[str]:
    """Return capability names the given agent declares in its config.yml."""
    return [decl.name for decl in load_file_types(agent, project_root=project_root)]


def canonicalize_capability(arg: str, agent: str, project_root: Path | None = None) -> str | None:
    """Map a user-facing capability keyword to the agent's config key, or None.

    A config key the agent declares maps to itself; a word a user may type for it (`skill`,
    `agent`) maps to the config key it names. For fold-source aliases (`memories`, `memory`),
    returns the alias itself when any member of the fold tuple is declared by the agent — the
    listing path walks the fold tuple.

    Virtual capabilities (`referenced` / `references`) are synthesized by
    the classifier and don't appear in any agent config; they canonicalize
    to the singular `referenced` regardless of agent.
    """
    if not arg:
        return None
    vocab = load_capability_vocabulary()
    if arg in vocab.virtual:
        return "referenced"
    decls = available_capabilities(agent, project_root)
    if arg in decls:
        return arg
    fold = vocab.fold.get(arg)
    if fold and any(f in decls for f in fold):
        return arg
    key = vocab.input_forms.get(arg)
    if key and key in decls:
        return key
    return None


class TargetError(ValueError):
    """A target token that names no file for the agent.

    `reason` is `undeclared` (the agent declares no such capability; `available` lists the ones
    it does) or `unnamed` (no instance of the capability carries that name; `available` lists
    the instances it has).
    """

    def __init__(
        self,
        reason: str,
        capability: str,
        agent: str,
        project_root: Path,
        name: str = "",
        available: tuple[str, ...] = (),
    ) -> None:
        self.reason = reason
        self.capability = capability
        self.agent = agent
        self.project_root = project_root
        self.name = name
        self.available = available
        super().__init__(self.message())

    def message(self) -> str:
        """The plain-text explanation."""
        if self.reason == "undeclared":
            return (
                f"capability {self.capability} is not declared for agent {self.agent}. "
                f"Available: {', '.join(self.available) or '(none)'}"
            )
        return f"no {self.capability} named {self.name} for agent {self.agent} under {self.project_root}."


def looks_like_windows_path(token: str) -> bool:
    """True for a Windows drive-letter path (`C:\\...`, `C:/...`, `C:`) so it isn't read as `capability:name`."""
    return len(token) >= 2 and token[0].isalpha() and token[1] == ":" and (len(token) == 2 or token[2] in ("\\", "/"))


def classify_target_token(
    token: str, sniff_agent: str, project_root: Path, base: Path | None = None
) -> tuple[str, tuple[str, str] | Path]:
    """Classify one target token as a capability spec or a path.

    Returns ("capability", (cap, name)), ("capability", (cap, "")), or ("path", Path).
    A bare capability noun (`skills`) targets every instance; `capability:name`
    (`skills:backlog`) targets one; `@capability` forces the capability reading. Tokens
    are canonicalized through the agent vocabulary, so a typed word (`skill:backlog`)
    reads as its config key. A leading drive letter (`C:\\...`) routes to path, not
    capability. The explicit `file:<path>` scheme forces path interpretation — the
    inverse of `capability:name` — so a path that shares a name with a capability still
    scans as a file. A relative path resolves against `base` (the working directory when
    None).
    """

    def _path(raw: str) -> Path:
        p = Path(raw)
        return safe_resolve(p if p.is_absolute() or base is None else base / p)

    if token.startswith("file:"):
        return "path", _path(token[len("file:") :])
    if token.startswith("@"):
        cap = token[1:]
        canonical = canonicalize_capability(cap, sniff_agent, project_root) if sniff_agent else None
        return "capability", (canonical if canonical is not None else cap, "")
    if ":" in token and not looks_like_windows_path(token):
        cap, name = token.split(":", 1)
        canonical = canonicalize_capability(cap, sniff_agent, project_root) if sniff_agent else None
        return "capability", (canonical if canonical is not None else cap, name)
    if sniff_agent and is_capability_keyword(token, sniff_agent, project_root):
        canonical = canonicalize_capability(token, sniff_agent, project_root)
        if canonical is not None:
            return "capability", (canonical, "")
    return "path", _path(token)


def sniff_agent(agent: str, project_root: Path) -> str:
    """The agent whose vocabulary reads target tokens: `agent` when given, else the project's
    configured default agent, else the first agent detected under `project_root` (`""` when
    none is)."""
    from reporails_cli.core.discovery.agents import detect_agents
    from reporails_cli.core.platform.config.config import get_project_config

    if agent:
        return agent
    try:
        cfg = get_project_config(project_root)
        if cfg.default_agent:
            return cfg.default_agent
    except (OSError, ValueError):
        pass
    for det in detect_agents(project_root):
        return det.agent_type.id
    return ""


def capability_declared(capability: str, agent: str, project_root: Path) -> bool:
    """True when `capability` is declared (config) or virtual (synthesized) for the agent.

    Virtual capabilities — `referenced` — are agent-agnostic; they're
    synthesized by the classifier rather than declared in any agent config.
    """
    vocab = load_capability_vocabulary()
    if capability in vocab.virtual:
        return True
    decls = available_capabilities(agent, project_root)
    if capability in decls:
        return True
    fold = vocab.fold.get(capability)
    return bool(fold and any(f in decls for f in fold))


def resolve_capability_spec(
    capability: str,
    name: str,
    agent: str,
    project_root: Path,
    exclude_dirs: list[str] | tuple[str, ...] | None = None,
) -> tuple[set[Path], list[Any]]:
    """Resolve one (capability, name) spec to its file set + the skills an agent preloads that
    did not resolve. An empty `name` targets every instance; a named subagent brings the skills
    it preloads. Raises `TargetError` when the spec names no file."""
    from reporails_cli.core.classify.focus_expansion import expand_focus

    if not capability_declared(capability, agent, project_root):
        raise TargetError(
            "undeclared", capability, agent, project_root, name, tuple(available_capabilities(agent, project_root))
        )
    if not name:
        return set(list_capability_targets(agent, capability, project_root, exclude_dirs)), []
    resolved = resolve_capability(agent, capability, name, project_root)
    if resolved is None:
        available = list_capability_targets(agent, capability, project_root, exclude_dirs)
        raise TargetError("unnamed", capability, agent, project_root, name, tuple(str(p) for p in available))
    paths = {resolved}
    unresolved: list[Any] = []
    if capability == "agents":
        paths, unresolved = expand_focus(paths, agent, project_root)
    return paths, unresolved


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
            paths = _glob_patterns(decl.patterns, project_root, frozenset(exclude_dirs or ()), decl=decl)
            # A file the agent reads only under a condition is its target only then.
            paths = apply_read_gate(agent, ft_name, paths, project_root)
        for path in paths:
            resolved = safe_resolve(path)
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
    fold = load_capability_vocabulary().fold.get(capability)
    if fold is None:
        return (capability,) if capability in decls else ()
    return tuple(f for f in fold if f in decls)


def _is_user_scope_memory(ft_name: str, patterns: tuple[str, ...]) -> bool:
    """True when the declared file_type names a user-scope memory directory.

    The capability-listing path can't reach `~/.claude/projects/*/memory/`
    via the project file walk because the pattern is absolute
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
    exclude_dirs: frozenset[str] = frozenset(),
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
    symlink (e.g. `.claude/` linked to a directory elsewhere) surfaces files
    under the project's path even though the underlying inode is
    elsewhere. Duplicate physical files (same inode reached via multiple
    symlinks) are deduped via the resolved path.
    """
    from reporails_cli.core.discovery.agents import load_project_exclude_dirs

    skip_dirs = load_project_exclude_dirs(project_root) | exclude_dirs
    # A plugin component pattern resolves against each plugin root under the project.
    expanded = [
        pattern
        for pattern in expand_plugin_patterns(list(patterns), project_root, skip_dirs)
        if not _is_external_pattern(pattern)
    ]
    if not expanded:
        return []
    seen_resolved: set[Path] = set()
    out: list[Path] = []
    for pattern in expanded:
        for path in sorted(walk_glob_matches(project_root, pattern, skip_dirs)):
            if decl is not None and not _decl_location_matches(path, decl, pattern, project_root):
                continue
            resolved = safe_resolve(path)
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
