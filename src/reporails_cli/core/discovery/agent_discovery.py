"""Agent file discovery — config-driven file globbing and path matching.

All functions here are internal to the agent subsystem.
"""

from __future__ import annotations

import glob
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.discovery.agent_config import (
    SURFACE_BUCKETS,
    SurfaceBucket,
    categorize_file_type,
    extract_patterns,
    extract_properties,
    load_config_file_types,
)
from reporails_cli.core.discovery.exclusions import load_project_exclude_dirs
from reporails_cli.core.discovery.plugin_roots import expand_plugin_patterns
from reporails_cli.core.discovery.project_root import resolve_project_root, user_level_agent_dir
from reporails_cli.core.discovery.read_gates import apply_read_gate
from reporails_cli.core.discovery.surface_config import (
    drop_shadowed_fallbacks,
    surface_exclude_patterns,
    surface_include_patterns,
)
from reporails_cli.core.discovery.walk import (
    documented_path,
    list_dir,
    walk_glob,
    walk_glob_matches,
    walk_markdown,
)
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.policy.exclusion import excluded_by_name
from reporails_cli.core.platform.utils.utils import config_pattern_matches, is_rooted_pattern, matches_any_glob

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.results import ProjectConfig

# Capabilities whose user-scope (home / absolute) patterns are NOT auto-pulled
# into a repo-scoped check — they enumerate cross-project surfaces reachable
# only via an explicit capability target (e.g. `ails check subagent_memory`).
# Filtered via `is_rooted_pattern`.
_USER_SCOPE_OPT_IN_CAPABILITIES = frozenset({"subagent_memory"})

# Capabilities whose user-scope patterns are project-specific despite the `~`
# prefix — the `~/.claude/projects/*/memory/` glob is slug-keyed to the current
# project in `_glob_directory_entries`, so it surfaces only THIS project's
# auto-memory and survives a repo-scoped scan (it does not drive agent detection,
# so it cannot reintroduce the home-config hijack the external-drop guards against).
_PROJECT_SCOPED_HOME_CAPABILITIES = frozenset({"memory"})


def ci_glob(target: Path, pattern: str, exclude_dirs: frozenset[str] = frozenset()) -> list[Path]:
    """Case-insensitive glob (`claude.md` == `CLAUDE.md`).

    Repos in the wild use mixed filename casing and the agent specs do not
    mandate exact case (the AGENTS.md spec is silent on casing), so a
    lowercase copy is a real instruction file and must be collected. The walk
    does not enter a folder named in `exclude_dirs`.
    """
    return list(walk_glob_matches(target, pattern, exclude_dirs, ignore_case=True))


def is_excluded(path: Path, target: Path, exclude_dirs: frozenset[str]) -> bool:
    """Check if any path component is in the exclusion set."""
    if not exclude_dirs:
        return False
    try:
        rel = path.relative_to(target)
    except ValueError:
        return False
    return excluded_by_name(rel.parts, exclude_dirs)


def walk_ancestors(start: Path, filename: str, stop: Path) -> list[Path]:
    """Walk up from start, collecting filename matches at each ancestor.

    Returns paths in walked order (closest first). A file matches by the rule
    of `documented_path`.
    """
    results: list[Path] = []
    current = start if start.is_dir() else start.parent
    while True:
        for entry in list_dir(str(current)) or ():
            named = documented_path(Path(entry.path), filename) if entry.is_file else None
            if named is not None:
                results.append(named)
                break
        if current in (stop, current.parent):
            break
        current = current.parent
    return results


def is_eager_global(properties: Mapping[str, str | list[str]]) -> bool:
    """File_type loads at session start with global scope (e.g., main, override).

    These files are loaded by the agent from the cwd ancestor chain — not
    via descendant traversal. Validator must mirror that: ancestor walk for
    files-at-cwd-and-above, descendant walk for nested per-subdirectory files.
    """
    return properties.get("scope") == "global" and properties.get("loading") == "session_start"


def is_nested(properties: Mapping[str, str | list[str]]) -> bool:
    """File_type whose subtree applicability comes from file LOCATION, not frontmatter.

    `scope: nested` declares: this surface applies to a subdirectory subtree
    by virtue of where the file lives (no frontmatter filter). Maps to
    nested_context / child_instruction declarations — files below cwd that
    the agent loads only when descending into those subdirectories.
    """
    return properties.get("scope") == "nested"


# Memory surfaces share an index-and-recall shape across agents (claude +
# antigravity, source-verified): MEMORY.md is the eager index, sibling entries
# are recalled on-demand.
MEMORY_SURFACES = frozenset({"memory", "subagent_memory"})
MEMORY_INDEX_FILENAME = "MEMORY.md"


def claude_project_folder_name(project_root: Path) -> str:
    """The folder name under `~/.claude/projects/` that holds a project's memory.

    Claude Code names it after the project's real path with every character that is not an
    ASCII letter or digit replaced by `-`.
    """
    return re.sub(r"[^A-Za-z0-9]", "-", os.path.realpath(project_root))


def is_memory_recall_entry(file_type: str, filename: str) -> bool:
    """Whether `filename` is a memory surface's on-demand sibling entry.

    True for any file named something other than `MEMORY.md` under a `memory`
    or `subagent_memory` file_type — the eager index is excluded, everything
    else in the surface is recalled on-demand rather than loaded eagerly.
    """
    return file_type in MEMORY_SURFACES and filename != MEMORY_INDEX_FILENAME


def _is_separate_repository(folder: Path, cache: dict[Path, bool]) -> bool:
    """Whether a folder is a clone or a git worktree (a submodule is part of its project)."""
    cached = cache.get(folder)
    if cached is not None:
        return cached
    marker = folder / ".git"
    separate = False
    if marker.is_dir():
        separate = True
    elif marker.is_file():
        try:
            text = marker.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for line in text.splitlines():
            if line.startswith("gitdir:"):
                gitdir = line[len("gitdir:") :].strip().replace("\\", "/")
                separate = "/worktrees/" in f"/{gitdir}/"
                break
    cache[folder] = separate
    return separate


def _inside_git_repository(target: Path) -> bool:
    """Whether the target or any folder above it holds a `.git`."""
    try:
        target = target.resolve()
    except OSError:
        return False
    return any((folder / ".git").exists() for folder in (target, *target.parents))


def in_nested_repository(path: Path, target: Path, pattern: str, cache: dict[Path, bool]) -> bool:
    """Whether a file the `**/` part of a pattern reached sits in a separate repository.

    A separate repository below a git project is not part of it. Only the folders
    the leading `**/` covered count, so a clone inside the project's own
    `.claude/skills/` is still found by the `.claude/skills/**` pattern.
    """
    if not pattern.startswith("**/"):
        return False
    try:
        parts = path.relative_to(target).parts
    except ValueError:
        return False
    rest = pattern[3:]
    for depth in range(1, len(parts)):
        if config_pattern_matches("/".join(parts[depth:]), rest, ignore_case=True, anchor_loose_leaf=True):
            folder = target
            for part in parts[:depth]:
                folder = folder / part
                if _is_separate_repository(folder, cache):
                    return True
            return False
    return False


def _run_descendant_recursive(
    target: Path,
    pattern: str,
    nested: bool,
    exclude_dirs: frozenset[str],
    repo_cache: dict[Path, bool] | None = None,
) -> list[Path]:
    """Descendant walk for **/<leaf> patterns.

    `nested` (scope: nested) excludes cwd itself — those files belong to the
    eager file_type (main) discovered via ancestor walk. The walk finds the leaf name;
    only files whose path matches the whole pattern are kept.
    """
    parts = Path(pattern).parts
    filename = parts[-1] if parts else ""
    prefix_parts: list[str] = []
    for p in parts:
        if "**" in p:
            break
        prefix_parts.append(p)
    walk_root = target / Path(*prefix_parts) if prefix_parts else target
    if not walk_root.is_dir():
        return []
    results = walk_glob(walk_root, filename, exclude_dirs)
    if nested:
        results = [m for m in results if m.parent != target]
    return [
        m
        for m in results
        if not is_excluded(m, target, exclude_dirs)
        and config_pattern_matches(m.relative_to(target).as_posix(), pattern, ignore_case=True)
        and not (repo_cache is not None and in_nested_repository(m, target, pattern, repo_cache))
    ]


def glob_file_type_patterns(
    target: Path,
    patterns: list[str],
    properties: Mapping[str, str | list[str]] | None,
    exclude_dirs: frozenset[str],
) -> list[Path]:
    """Glob file_type patterns against target directory.

    Dispatch by file_type properties:
      - external (~/..., /abs, C:/...)               -> _glob_external
      - bare leaf or **/<leaf> + eager global        -> walk_ancestors from cwd
      - .../<file> (no **/) + global scope           -> resolve relative to project_root
      - **/<leaf> + scope: nested                    -> walk_glob descendant from cwd, exclude cwd
      - everything else                              -> walk_glob descendant from cwd

    Properties drive the dispatch so a pattern like **/CLAUDE.md can mean
    "ancestor walk" under file_types.main (scope: global) and "descendant walk"
    under file_types.nested_context (scope: nested) — same regex, different
    loading model.
    """
    props = properties or {}
    eager_global = is_eager_global(props)
    nested = is_nested(props)
    project_root: Path | None = None
    repo_cache: dict[Path, bool] = {}
    cache = repo_cache if _inside_git_repository(target) else None

    found: list[Path] = []
    for pattern in patterns:
        if pattern.endswith("/"):
            # Directory glob (`.claude/agent-memory/*/`, `~/.claude/projects/*/memory/`)
            # -> enumerate `*.md` files inside the matched directories.
            _glob_directory_entries(pattern, target, found, exclude_dirs)
            continue
        if is_rooted_pattern(pattern):
            _glob_external(pattern, target, found)
            continue

        filename = Path(pattern).parts[-1] if Path(pattern).parts else ""
        is_recursive_leaf = "**" in pattern and "*" not in filename
        is_bare_leaf = len(Path(pattern).parts) == 1 and "*" not in pattern

        if eager_global and (is_recursive_leaf or is_bare_leaf):
            if project_root is None:
                project_root = resolve_project_root(target)
            found.extend(
                m for m in walk_ancestors(target, filename, project_root) if not is_excluded(m, target, exclude_dirs)
            )
        elif eager_global and "**" not in pattern:
            if project_root is None:
                project_root = resolve_project_root(target)
            found.extend(
                m for m in ci_glob(project_root, pattern, exclude_dirs) if not is_excluded(m, target, exclude_dirs)
            )
        elif is_recursive_leaf:
            found.extend(_run_descendant_recursive(target, pattern, nested, exclude_dirs, cache))
        else:
            found.extend(
                m
                for m in ci_glob(target, pattern, exclude_dirs)
                if not is_excluded(m, target, exclude_dirs)
                and not (cache is not None and in_nested_repository(m, target, pattern, cache))
            )
    return found


def _glob_external(pattern: str, target: Path, found: list[Path]) -> None:
    """Resolve an external path pattern (~/... or /absolute/...)."""
    expanded = Path(pattern).expanduser()
    if "*" in pattern:
        expanded_str = expanded.as_posix()
        if "/projects/*/" in expanded_str:
            expanded_str = expanded_str.replace("/projects/*/", f"/projects/{claude_project_folder_name(target)}/")
        found.extend(Path(p) for p in glob.glob(expanded_str) if Path(p).is_file())
    elif expanded.is_file():
        found.append(expanded)


def _glob_directory_entries(
    pattern: str,
    target: Path,
    found: list[Path],
    exclude_dirs: frozenset[str],
) -> None:
    """Enumerate `*.md` files inside directories matching a trailing-slash pattern.

    Trailing-slash patterns in agent configs (e.g. `.claude/agent-memory/*/`,
    `~/.claude/projects/*/memory/`) describe a directory glob; the files
    inside those directories are the file_type's instances. This helper
    resolves the directory glob then walks `*.md` files inside each match.

    Used by `memory` and `subagent_memory` capabilities — the only file_types
    declared with directory-only patterns. Older releases bucketed these as
    `"skip"`, which left the files unclassified and the `link_walker` then
    mis-tagged them `generic`.
    """
    dir_pattern = pattern.rstrip("/")
    if is_rooted_pattern(dir_pattern):
        expanded_str = Path(dir_pattern).expanduser().as_posix()
        if "/projects/*/" in expanded_str:
            expanded_str = expanded_str.replace("/projects/*/", f"/projects/{claude_project_folder_name(target)}/")
        for d in glob.glob(expanded_str):
            base = Path(d)
            if base.is_dir():
                found.extend(walk_markdown(base, exclude_dirs))
        return

    # In-tree pattern: resolve glob relative to target, enumerate .md inside each dir
    for base in _resolve_in_tree_dirs(dir_pattern, target, exclude_dirs):
        found.extend(
            entry for entry in walk_markdown(base, exclude_dirs) if not is_excluded(entry, target, exclude_dirs)
        )


def _resolve_in_tree_dirs(
    dir_pattern: str,
    target: Path,
    exclude_dirs: frozenset[str],
) -> list[Path]:
    """Resolve an in-tree directory glob (no trailing slash) to existing directories."""
    candidates = [Path(p) for p in glob.glob(str(target / dir_pattern))]
    return [p for p in candidates if p.is_dir() and not is_excluded(p, target, exclude_dirs)]


def _repo_scoped_patterns(
    patterns: list[str], ft_name: str, repo_scoped: bool, user_dir: Path | None = None
) -> list[str]:
    """Drop cross-project user-scope (~/..., absolute) patterns from a repo-scoped scan.

    Resolving them against the developer's HOME falsely marks an agent present — a
    global ~/.codex/config.toml makes codex look distinctive, collapsing a shared
    AGENTS.md to that agent and dropping the generic core findings. Home-scope
    surfaces stay reachable via an explicit capability target, which resolves them
    through classify.capability_paths / memory_locator, not this path. The project-scoped
    auto-memory (`memory`) is exempt — its `~/.claude/projects/*/memory/` glob slug-keys to the
    current project, so it is project-specific, not a cross-project hijack surface.

    When the scan root is itself the user's agent folder (`user_dir`, e.g. `~/.claude`),
    the user-scope patterns that name that folder stay, rewritten relative to it, so the
    folder's own files are found and nothing outside it is.
    """
    if ft_name in _PROJECT_SCOPED_HOME_CAPABILITIES:
        return patterns
    if repo_scoped or ft_name in _USER_SCOPE_OPT_IN_CAPABILITIES:
        if user_dir is not None:
            prefix = f"~/{user_dir.name}/"
            return [
                p.removeprefix(prefix) if p.startswith(prefix) else p
                for p in patterns
                if p.startswith(prefix) or not is_rooted_pattern(p)
            ]
        return [p for p in patterns if not is_rooted_pattern(p)]
    return patterns


@dataclass
class _AgentScope:
    """What one agent's discovery run shares across its file types."""

    target: Path
    agent_id: str
    project_config: ProjectConfig | None
    excluded: frozenset[str]
    repo_scoped: bool
    user_dir: Path | None
    exclude_globs: list[str]
    plugin_roots: dict[str, list[Path]] = field(default_factory=dict)


def _discover_surface(
    scope: _AgentScope, ft_name: str, spec: JsonObject, *, gated: bool = True
) -> tuple[SurfaceBucket, list[Path]] | None:
    """The bucket and files of one file type, None when the file type contributes nothing.
    With `gated` false the agent's read gate leaves the files unnarrowed."""
    target = scope.target
    patterns = _repo_scoped_patterns(extract_patterns(spec), ft_name, scope.repo_scoped, scope.user_dir)
    # A plugin component pattern resolves against each plugin root found here.
    patterns = expand_plugin_patterns(patterns, target, scope.excluded, scope.plugin_roots)
    if not patterns:
        return None
    properties = extract_properties(spec)

    bucket = categorize_file_type(patterns, properties)
    if bucket == "skip":
        return None

    # Inject per-surface include patterns from .ails/config.yml
    patterns = patterns + surface_include_patterns(scope.agent_id, ft_name, scope.project_config)

    found = glob_file_type_patterns(target, patterns, properties, scope.excluded)

    if scope.exclude_globs:
        found = [p for p in found if not matches_any_glob(p, scope.exclude_globs, target)]
    # A file type the agent reads only under a condition keeps just the files it reads.
    if gated:
        found = apply_read_gate(scope.agent_id, ft_name, found, target)
    return bucket, drop_shadowed_fallbacks(found, scope.agent_id, ft_name, scope.project_config)


def _agent_scope(
    target: Path,
    agent_id: str,
    file_types: JsonObject,
    extra_exclude_dirs: frozenset[str] | None,
    *,
    project_config: ProjectConfig | None,
    repo_scoped: bool,
) -> _AgentScope:
    """The scope one agent's discovery run shares across its file types."""
    # Union of every per-surface exclude declared for this agent. Some agents
    # have multiple surfaces that match the same paths (e.g. cursor.rules and
    # cursor.bugbot_rules both match `.cursor/rules/**/*.mdc`). Applying each
    # surface's exclude only within its own loop iteration leaves the file
    # surfaced from the other surface — counter to the user's mental model
    # ("I excluded draft, draft should be gone"). The union closes the gap.
    return _AgentScope(
        target=target,
        agent_id=agent_id,
        project_config=project_config,
        excluded=extra_exclude_dirs or load_project_exclude_dirs(target),
        repo_scoped=repo_scoped,
        user_dir=target if repo_scoped and user_level_agent_dir(target) == target else None,
        exclude_globs=[
            g for ft_name in file_types for g in surface_exclude_patterns(agent_id, ft_name, project_config)
        ],
    )


def discover_ungated(
    target: Path,
    agent_id: str,
    file_type_names: tuple[str, ...],
    extra_exclude_dirs: frozenset[str],
    *,
    project_config: ProjectConfig | None,
) -> list[Path]:
    """The files the named file types of `agent_id` match under `target` in a repo-scoped run,
    found as discovery finds them but before the agent's read gate narrows them. Every path is
    kept under its own name, whatever it links to."""
    file_types = load_config_file_types(agent_id) or {}
    scope = _agent_scope(
        target, agent_id, file_types, extra_exclude_dirs, project_config=project_config, repo_scoped=True
    )
    found: set[Path] = set()
    for name in file_type_names:
        spec = file_types.get(name)
        surface = _discover_surface(scope, name, spec, gated=False) if isinstance(spec, dict) else None
        if surface is not None:
            found.update(surface[1])
    return sorted(found)


def discover_from_config(
    target: Path,
    agent_id: str,
    extra_exclude_dirs: frozenset[str] | None = None,
    *,
    project_config: ProjectConfig | None = None,
    repo_scoped: bool = False,
) -> tuple[list[Path], list[Path], list[Path]] | None:
    """Discover files using config.yml file_types.

    Optionally consults `project_config` (a `ProjectConfig`) for per-surface
    include/exclude pattern adjustments and Codex fallback filenames declared
    in `.ails/config.yml` (or `.ails/config.local.yml`).

    Returns (instruction_files, rule_files, config_files) or None if
    no config.yml is available for this agent.
    """
    file_types = load_config_file_types(agent_id)
    if file_types is None:
        return None

    scope = _agent_scope(
        target, agent_id, file_types, extra_exclude_dirs, project_config=project_config, repo_scoped=repo_scoped
    )
    buckets: dict[SurfaceBucket, list[Path]] = {bucket: [] for bucket in SURFACE_BUCKETS}
    for ft_name, spec in file_types.items():
        if not isinstance(spec, dict):
            continue
        surface = _discover_surface(scope, ft_name, spec)
        if surface is not None:
            buckets[surface[0]].extend(surface[1])

    return (
        _dedupe_by_canonical(buckets["instruction"], target),
        _dedupe_by_canonical(buckets["rule"], target),
        _dedupe_by_canonical(buckets["config"], target),
    )


def _canonical_path(path: Path) -> Path:
    """Return path's canonical (symlink-resolved) form, or the original on error.

    Mirrors the error handling in `applicability.resolve_symlinked_files`:
    `Path.resolve(strict=True)` raises `OSError` (broken symlink, errno
    `ELOOP`) or `RuntimeError` (Python's symlink-loop guard) on bad
    symlinks. Treat unresolvable paths as canonical-to-themselves so they
    are still surfaced for downstream error reporting.
    """
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError):
        return path


def _dedupe_by_canonical(paths: list[Path], root: Path) -> list[Path]:
    """Dedupe paths by their canonical (symlink-resolved) target, sorted.

    Two surface paths can refer to the same underlying file when one or
    both are symlinks (common pattern: `.claude/skills -> ../.agents/skills`).
    Naive `set(paths)` keeps both because path equality compares strings.
    Canonicalizing via `Path.resolve(strict=True)` collapses symlinks; of the
    paths that share a target, one inside `root` stands for it over one outside,
    then the one with the fewest path parts below `root`, then the first in sort order.
    """
    best: dict[Path, tuple[bool, int, Path]] = {}
    for p in sorted(set(paths)):
        canonical = _canonical_path(p)
        inside = p.is_relative_to(root)
        rank = (not inside, len(p.relative_to(root).parts) if inside else len(p.parts), p)
        kept = best.get(canonical)
        if kept is None or rank[:2] < kept[:2]:
            best[canonical] = rank
    return sorted(rank[2] for rank in best.values())
