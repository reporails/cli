"""Agent file discovery — config-driven file globbing and path matching.

All functions here are internal to the agent subsystem.
"""

from __future__ import annotations

import functools
import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from reporails_cli.core.discovery.walk import documented_path, list_dir, walk_glob, walk_markdown
from reporails_cli.core.platform.utils.utils import config_pattern_matches
from reporails_cli.core.platform.utils.utils import matches_any_glob as _matches_any_glob

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.results import ProjectConfig

logger = logging.getLogger(__name__)

# Capabilities whose user-scope (home / absolute) patterns are NOT auto-pulled
# into a repo-scoped check — they enumerate cross-project surfaces reachable
# only via an explicit capability target (e.g. `ails check subagent_memory`).
# Filtered via `_is_external_pattern` (defined below).
_USER_SCOPE_OPT_IN_CAPABILITIES = frozenset({"subagent_memory"})

# Capabilities whose user-scope patterns are project-specific despite the `~`
# prefix — the `~/.claude/projects/*/memory/` glob is slug-keyed to the current
# project in `_glob_directory_entries`, so it surfaces only THIS project's
# auto-memory and survives a repo-scoped scan (it does not drive agent detection,
# so it cannot reintroduce the home-config hijack the external-drop guards against).
_PROJECT_SCOPED_HOME_CAPABILITIES = frozenset({"memory"})


def ci_glob(target: Path, pattern: str) -> list[Path]:
    """Case-insensitive glob (`claude.md` == `CLAUDE.md`).

    Repos in the wild use mixed filename casing and the agent specs do not
    mandate exact case (the AGENTS.md spec is silent on casing), so a
    lowercase copy is a real instruction file and must be collected.
    """
    parts = Path(pattern).parts
    if len(parts) == 1 and "*" not in pattern:
        pat_lower = pattern.lower()
        try:
            # is_file() (not `not is_dir()`) so dangling symlinks are excluded.
            return [p for p in target.iterdir() if p.name.lower() == pat_lower and p.is_file()]
        except OSError:
            return []
    return [p for p in target.glob(pattern, case_sensitive=False) if p.is_file()]


def categorize_file_type(patterns: list[str], properties: dict[str, str]) -> str:
    """Categorize a file_type entry as instruction/rule/config/skip.

    Uses file_type properties from config.yml:
    - format: schema_validated -> config
    - scope: path_scoped -> rule (scoped rule files)
    - absolute system paths only -> skip
    - directory-only patterns -> instruction (memory / subagent_memory:
      `glob_file_type_patterns` enumerates `*.md` files inside the matched
      directories so `match: {type: memory}` rules can target them)
    - everything else -> instruction
    """
    # Skip absolute system paths (managed configs)
    if all(p.startswith(("/", "C:")) for p in patterns):
        return "skip"
    # Schema-validated files -> config bucket
    if properties.get("format") == "schema_validated":
        return "config"
    # Path-scoped markdown -> rule files bucket
    if properties.get("scope") == "path_scoped":
        return "rule"
    # Everything else (main, skill, override, memory/subagent_memory) -> instruction
    return "instruction"


def is_excluded(path: Path, target: Path, exclude_dirs: frozenset[str]) -> bool:
    """Check if any path component is in the exclusion set."""
    if not exclude_dirs:
        return False
    try:
        rel = path.relative_to(target)
    except ValueError:
        return False
    return bool(exclude_dirs & set(rel.parts))


# Coding-agent home directories whose name differs from the agent's own id
# (Copilot's is `.github/`, Antigravity's is `.gemini/`) plus the Agent Skills
# standard's shared `.agents/` home, which is `generic`'s own namespace, not any
# one coding agent's — a project with nothing but `.agents/skills/**` cross-reads
# has no single specific owner among the coding agents.
_NAMESPACE_ALIASES = {"github": "copilot", "gemini": "antigravity", "agents": "generic"}


def _agent_namespace(path: Path, target: Path) -> str | None:
    """The agent id that natively owns the on-disk namespace `path` sits under
    (`.claude/x` -> `"claude"`, `.github/x` -> `"copilot"` via `_NAMESPACE_ALIASES`),
    or `None` for a root-level file (no dot-directory) or a path outside `target` —
    neither carries a namespace to attribute a cross-read to."""
    try:
        parts = path.relative_to(target).parts
    except ValueError:
        return None
    if not parts or not (parts[0].startswith(".") and len(parts[0]) > 1):
        return None
    dirname = parts[0][1:]
    return _NAMESPACE_ALIASES.get(dirname, dirname)


def _is_project_root_file(path: Path, target: Path) -> bool:
    """True for a file directly at `target`'s root (no dot-directory, no subdirectory) —
    real native evidence for whichever agent's own pattern matched it (`CLAUDE.md`,
    root `AGENTS.md`), unlike a NESTED un-namespaced file reached only through a
    recursive `**/AGENTS.md`-style cross-agent-standard glob."""
    try:
        parts = path.relative_to(target).parts
    except ValueError:
        return False
    return len(parts) == 1


def _all_cross_read(
    files: set[Path], own_id: str, other_ids: set[str], target: Path, shared: frozenset[Path] = frozenset()
) -> bool:
    """True when `files` establishes no distinctiveness of `own_id`'s own: none sits in
    `own_id`'s own namespace or at a project-root main-file path, and at least one sits in
    another DETECTED agent's own namespace. A nobody's-specific shared surface
    (`.agents/skills/**`, which resolves to `generic` — not itself a distinctive candidate
    in this loop) is neutral: it neither grants nor costs distinctiveness by itself, so it
    alone can never block the exclusion the way requiring EVERY file to positively
    cross-read someone else would (a Copilot project cross-reading both Claude's
    `.claude/**` and the shared `.agents/skills/**`, with nothing of its own, must still
    exclude Copilot). A project-root file in `shared` (one another detected agent also
    reads, like a root `AGENTS.md` Claude reads when the project has no `CLAUDE.md`) is
    neutral the same way. Empty `files` is never cross-read (there is nothing to read)."""
    if not files:
        return False
    if any(
        _agent_namespace(f, target) == own_id or (_is_project_root_file(f, target) and f not in shared) for f in files
    ):
        return False
    return any((ns := _agent_namespace(f, target)) is not None and ns != own_id and ns in other_ids for f in files)


def _reads_nothing_of_its_own(agent: Any, other_ids: set[str], target: Path, shared: frozenset[Path]) -> bool:
    """True when `agent` is no distinctive agent of its own: its files are all cross-reads
    (`_all_cross_read`), or every instruction and rule file it claims is one it reads only
    in place of its own main file (Claude and `AGENTS.md`) that another detected agent
    also claims -- a Codex project's `AGENTS.md` does not make Claude a second agent."""
    from reporails_cli.core.discovery.agents import _own_files
    from reporails_cli.core.discovery.read_gates import reads_as_fallback

    own_id = agent.agent_type.id
    content = [*agent.instruction_files, *agent.rule_files]
    if content and all(f in shared and reads_as_fallback(own_id, f) for f in content):
        return True
    return _all_cross_read(_own_files(agent), own_id, other_ids, target, shared)


def partition_by_native_owner(detected_agents: list[Any], target: Path) -> dict[str, str]:
    """Map every file a non-generic detected agent claims to its rule-running attribution:
    the DISTINCTIVE agent that natively owns it (its own on-disk namespace, or a
    project-root main-file path), or `"generic"` when no currently-distinctive agent
    natively owns it -- a shared cross-agent standard (`.agents/skills/**`) or a nested
    `AGENTS.md` no agent's own namespace claims runs the core rule set only, exactly as a
    plain single-agent project's own unclaimed files would. This never drops a file from
    the map -- it only routes each one to the right ruleset. Keyed by `str(path)` to match
    `FileRecord.path` and `Path` instruction-file entries directly."""
    from reporails_cli.core.discovery.agents import _distinctive_agents, _own_files
    from reporails_cli.core.discovery.read_gates import reads_as_fallback

    distinctive_ids = {a.agent_type.id for a in _distinctive_agents(detected_agents, target)}
    claimants: dict[Path, list[str]] = {}
    for detected in detected_agents:
        if detected.agent_type.id == "generic":
            continue
        for f in _own_files(detected):
            claimants.setdefault(f, []).append(detected.agent_type.id)

    owner_by_path: dict[str, str] = {}
    for f, claimant_ids in claimants.items():
        # A file only ONE detected agent claims at all (its filename/pattern isn't a
        # cross-agent standard several registries share) is unambiguous native evidence
        # for that agent the moment it stays distinctive -- a nested `CLAUDE.md` under a
        # subproject (`packages/web/CLAUDE.md`) is real claude ownership even though it
        # sits neither at the project root nor inside claude's own `.claude/` namespace.
        # The namespace/root-file tie-break below is only needed once MULTIPLE agents
        # claim the same path (a shared standard like root `AGENTS.md`), where the
        # claim alone can't say which detected agent, if any, really owns it here.
        if len(claimant_ids) == 1 and claimant_ids[0] in distinctive_ids:
            owner_by_path[str(f)] = claimant_ids[0]
            continue
        owner = "generic"
        # An agent that reads the file only in place of its own main file (Claude and a
        # root `AGENTS.md`) yields it to an agent that reads it natively.
        fallback = {cid: reads_as_fallback(cid, f) for cid in claimant_ids}
        for cid in sorted(claimant_ids, key=fallback.__getitem__):
            if cid in distinctive_ids and (_agent_namespace(f, target) == cid or _is_project_root_file(f, target)):
                owner = cid
                break
        owner_by_path[str(f)] = owner
    return owner_by_path


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
        if current == stop or current == current.parent:
            break
        current = current.parent
    return results


def resolve_project_root(target: Path) -> Path:
    """Project root for discovery — the directory `ails check` was pointed at.

    Discovery never walks above this directory. Whoever runs `ails check`
    chooses the scope — `target` IS the project root, regardless of what
    `.git` / `.ails/backbone.yml` / IDE config dirs may exist above it.

    Files outside `target`'s subtree are out of scope. This bounds the scan
    strictly to what the user pointed at and avoids leaking files from a
    surrounding repo into a fixture/subdirectory check.

    For cache-key derivation and mapper coordination (which need a stable
    repo-wide identifier even when running from a subdirectory), see
    `engine_helpers._find_project_root` — that function continues to walk up
    looking for project markers and is unaffected by this change.
    """
    return target if target.is_dir() else target.parent


@functools.lru_cache(maxsize=1)
def root_markers() -> tuple[tuple[tuple[str, ...], frozenset[str]], ...]:
    """Per supported agent: `(main-instruction relative paths, config directory names)`.

    Derived from the bundled `framework/rules/*/config.yml` so the marker set covers
    every shipped agent and follows config rather than a hand-kept list: the `main`
    file_type's project-scope patterns (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
    `.github/copilot-instructions.md`, …) paired with the dot-directories that agent
    declares surfaces in (`.claude/`, `.codex/`, `.cursor/`, `.gemini/`, `.github/`,
    `.agents/`, …). User-scope (`~/…`) and absolute managed patterns are dropped —
    they say nothing about the directory under test.
    """
    from reporails_cli.core.platform.config.bundled import get_bundled_rules_path
    from reporails_cli.core.platform.utils.utils import load_yaml_file

    rules_dir = get_bundled_rules_path()
    if rules_dir is None:
        return ()

    markers: list[tuple[tuple[str, ...], frozenset[str]]] = []
    for config_path in sorted(rules_dir.glob("*/config.yml")):
        try:
            data = load_yaml_file(config_path)
        except (OSError, ValueError, yaml.YAMLError) as exc:  # unreadable or non-YAML agent config
            logger.warning("Skipping agent config %s: %s", config_path, exc)
            continue
        file_types = (data or {}).get("file_types") or {}
        if not isinstance(file_types, dict):
            continue
        mains, dirs = _markers_from_file_types(file_types)
        if mains and dirs:
            markers.append((tuple(sorted(mains)), frozenset(dirs)))
    return tuple(markers)


def _repo_relative_pattern(pattern: str) -> str:
    """Strip a scope pattern to its repo-relative form, or `` for a non-repo one."""
    text = str(pattern)
    if text.startswith(("~", "/")) or ":" in text.split("/", 1)[0]:
        return ""
    return text.removeprefix("**/")


def _markers_from_file_types(file_types: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Split one agent's `file_types` into its main-file names and its config dir names."""
    mains: set[str] = set()
    dirs: set[str] = set()
    for ft_name, ft in file_types.items():
        if not isinstance(ft, dict):
            continue
        for scope in (ft.get("scopes") or {}).values():
            for pattern in (scope or {}).get("patterns", []) or []:
                rel = _repo_relative_pattern(pattern)
                if not rel:
                    continue
                if ft_name == "main" and "*" not in rel:
                    mains.add(rel)
                head = rel.split("/", 1)[0]
                if "/" in rel and head.startswith(".") and "*" not in head:
                    dirs.add(head)
    return mains, dirs


def agent_dir_names() -> frozenset[str]:
    """Every dot-directory a shipped agent declares surfaces in (`.claude`, `.codex`, …)."""
    return frozenset().union(*(dirs for _, dirs in root_markers())) if root_markers() else frozenset()


# Marker directories a project-boundary walk-up recognizes for
# `resolve_project_root_for_file` — mirrors `engine_helpers._PROJECT_MARKER_DIRS`
# (kept as a separate copy rather than an import: that module's walk-up is scoped
# to cache/mapper identity, not discovery, per `resolve_project_root`'s own
# docstring, and the two must stay free to diverge independently).
_FILE_ROOT_MARKER_DIRS: frozenset[str] = frozenset({".vscode", ".idea", ".github"})


def resolve_project_root_for_file(target: Path) -> Path:
    """Project root for a bare FILE target with no invoking cwd to anchor on.

    `resolve_project_root` is right for `ails check <dir>` / `ails check` (no
    target): whoever ran the command chose the scope, and for the CLI's own
    single-FILE case the effective root is the invoking terminal's `cwd` (set in
    `main.py`), never `target.parent` — a human runs `ails check .claude/rules/x.md`
    FROM the project root, not from inside `.claude/rules/`. An MCP-style caller
    passes only the file path with no cwd to read, so `target.parent` under-roots a
    nested file: `.claude/rules/style.md` resolved at `.claude/rules` instead of the
    project root, which misclassifies the file's `loading`/`scope`
    (`core/mapper/inspect.py::_detect_file_loading`) and computes a cache identity
    (`core/cache/full_map_cache.py::compute_identity`) that never matches the CLI's
    same-file run, so the two surfaces never share a whole-map cache entry.

    Walks up from the file looking for a project marker — `.ails/backbone.yml`,
    `.git`, then an IDE/CI config directory — falling back to the file's own
    directory when the walk finds nothing, exactly like a human `cd`-ing to the
    project root before invoking the CLI would resolve.

    A weaker fallback sits below those: the parent of the OUTERMOST agent config
    directory (`.claude`, `.cursor`, `.codex`, ... — the names the agents declare)
    enclosing the file. Such a directory groups one agent's own files under one
    project, so a config file living inside it with no `.git` / `.ails` / IDE marker
    above (`.claude/settings.json` in a project that has never been git-initialized,
    say) still resolves one level up. Any other hidden folder is no boundary, and a
    hidden folder inside an agent directory does not end the walk early.

    An agent directory that sits directly in the user's home (`~/.claude`) is the
    user's own configuration, not a project: the file roots on that directory
    itself, so nothing else under the home directory is ever scanned.

    An IDE/CI folder in the home directory, or in a directory above it, is not a
    project marker: the file roots as if it were absent. `.ails/backbone.yml` and
    `.git` count wherever they are.
    """
    user_dir = user_level_agent_dir(target)
    if user_dir is not None:
        return user_dir
    current = target if target.is_dir() else target.parent
    start = current
    first_git: Path | None = None
    first_marker: Path | None = None
    outermost_agent_dir: Path | None = None
    agent_dirs = agent_dir_names()
    try:
        home: Path | None = Path.home().resolve()
    except (RuntimeError, OSError):
        home = None
    while current != current.parent:
        if (current / ".ails" / "backbone.yml").exists():
            return current
        if first_git is None and (current / ".git").exists():
            first_git = current
        # An editor/host folder in the home directory (or above it) is shared by every
        # project below, so it never decides one project's root.
        if first_marker is None and not (home is not None and (current == home or home.is_relative_to(current))):
            for marker in _FILE_ROOT_MARKER_DIRS:
                if (current / marker).is_dir():
                    first_marker = current
                    break
        if current.name in agent_dirs:
            outermost_agent_dir = current
        current = current.parent
    return first_git or first_marker or (outermost_agent_dir.parent if outermost_agent_dir else None) or start


def user_level_agent_dir(target: Path) -> Path | None:
    """The agent config directory directly in the user's home that holds `target`, if any.

    Only the outermost agent directory above the target counts, and only when its parent
    is the home directory. Returns `None` for every project-level file.
    """
    agent_dirs = agent_dir_names()
    start = target if target.is_dir() else target.parent
    outermost: Path | None = None
    for ancestor in (start, *start.parents):
        if ancestor.name in agent_dirs:
            outermost = ancestor
    if outermost is None:
        return None
    try:
        home = Path.home().resolve()
    except (RuntimeError, OSError):
        return None
    return outermost if outermost.parent.resolve() == home else None


def _is_eager_global(properties: dict[str, str]) -> bool:
    """File_type loads at session start with global scope (e.g., main, override).

    These files are loaded by the agent from the cwd ancestor chain — not
    via descendant traversal. Validator must mirror that: ancestor walk for
    files-at-cwd-and-above, descendant walk for nested per-subdirectory files.
    """
    return properties.get("scope") == "global" and properties.get("loading") == "session_start"


def _is_nested(properties: dict[str, str]) -> bool:
    """File_type whose subtree applicability comes from file LOCATION, not frontmatter.

    `scope: nested` declares: this surface applies to a subdirectory subtree
    by virtue of where the file lives (no frontmatter filter). Maps to
    nested_context / child_instruction declarations — files below cwd that
    the agent loads only when descending into those subdirectories.
    """
    return properties.get("scope") == "nested"


def _is_external_pattern(pattern: str) -> bool:
    """Pattern resolves outside project (~/..., /abs, C:/...)."""
    return pattern.startswith("~") or pattern.startswith("/") or (len(pattern) > 1 and pattern[1] == ":")


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


def _run_descendant_recursive(target: Path, pattern: str, nested: bool, exclude_dirs: frozenset[str]) -> list[Path]:
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
    ]


def glob_file_type_patterns(
    target: Path,
    patterns: list[str],
    properties: dict[str, str] | None,
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
    eager_global = _is_eager_global(props)
    nested = _is_nested(props)
    project_root: Path | None = None

    found: list[Path] = []
    for pattern in patterns:
        if pattern.endswith("/"):
            # Directory glob (`.claude/agent-memory/*/`, `~/.claude/projects/*/memory/`)
            # -> enumerate `*.md` files inside the matched directories.
            _glob_directory_entries(pattern, target, found, exclude_dirs)
            continue
        if _is_external_pattern(pattern):
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
            found.extend(m for m in ci_glob(project_root, pattern) if not is_excluded(m, target, exclude_dirs))
        elif is_recursive_leaf:
            found.extend(_run_descendant_recursive(target, pattern, nested, exclude_dirs))
        else:
            found.extend(m for m in ci_glob(target, pattern) if not is_excluded(m, target, exclude_dirs))
    return found


def _glob_external(pattern: str, target: Path, found: list[Path]) -> None:
    """Resolve an external path pattern (~/... or /absolute/...)."""
    expanded = Path(pattern).expanduser()
    if "*" in pattern:
        expanded_str = str(expanded)
        if "/projects/*/" in expanded_str:
            expanded_str = expanded_str.replace("/projects/*/", f"/projects/{claude_project_folder_name(target)}/")
        import glob as _glob

        found.extend(Path(p) for p in _glob.glob(expanded_str) if Path(p).is_file())
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
    if _is_external_pattern(dir_pattern):
        expanded_str = str(Path(dir_pattern).expanduser())
        if "/projects/*/" in expanded_str:
            expanded_str = expanded_str.replace("/projects/*/", f"/projects/{claude_project_folder_name(target)}/")
        import glob as _glob

        for d in _glob.glob(expanded_str):
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
    import glob as _glob

    candidates = [Path(p) for p in _glob.glob(str(target / dir_pattern))]
    return [p for p in candidates if p.is_dir() and not is_excluded(p, target, exclude_dirs)]


def load_config_file_types(
    agent_id: str,
    rules_paths: list[Path] | None = None,
) -> dict[str, Any] | None:
    """Load file_types section from agent config.yml.

    Searches rules_paths first, then falls back to the default config path.
    Returns the file_types dict or None if not found.
    """

    from reporails_cli.core.platform.config.bootstrap import get_agent_config_path

    candidates: list[Path] = []
    if rules_paths:
        candidates.extend(rp / agent_id / "config.yml" for rp in rules_paths)
    candidates.append(get_agent_config_path(agent_id))

    for path in candidates:
        if not path.exists():
            continue
        try:
            from reporails_cli.core.platform.utils.utils import load_yaml_file

            data = load_yaml_file(path)
            if not data:
                logger.warning("Agent config is empty: %s", path)
                continue
            ft = data.get("file_types")
            if ft and isinstance(ft, dict):
                return dict(ft)
        except Exception:  # agent config parsing; skip broken configs
            logger.debug("Failed to load agent config %s", path, exc_info=True)
            continue
    return None


# File types a declared fallback filename is added to: `main` covers the directories
# from the project root down to the run's directory, `nested_context` the
# subdirectories below it (the same split a plain `AGENTS.md` uses).
_FALLBACK_FILE_TYPES = frozenset({"main", "nested_context"})

# Names an agent reads before it tries any fallback name in the same directory.
_PRIMARY_NAMES: dict[str, frozenset[str]] = {"codex": frozenset({"agents.override.md", "agents.md"})}


def _fallback_names(project_config: ProjectConfig | None, agent_id: str) -> list[str]:
    """The `agents.<agent>.fallback_filenames` entries of the project config."""
    agent_cfg = (getattr(project_config, "agents", {}) or {}).get(agent_id)
    fallbacks = agent_cfg.get("fallback_filenames", []) if isinstance(agent_cfg, dict) else []
    if not isinstance(fallbacks, list):
        return []
    return [name for name in fallbacks if isinstance(name, str)]


def _dir_has_primary(directory: Path, agent_id: str) -> bool:
    """Whether `directory` holds a file the agent reads before any fallback name."""
    primary = _PRIMARY_NAMES.get(agent_id, frozenset())
    return any(entry.name.lower() in primary for entry in list_dir(str(directory)) or ())


def drop_shadowed_fallbacks(
    found: list[Path], agent_id: str, file_type_name: str, project_config: ProjectConfig | None
) -> list[Path]:
    """`found` without the fallback files the agent skips.

    The agent tries its own names in each directory first and reads a fallback
    name only when none of them is there, so a fallback file beside an
    `AGENTS.md` (or `AGENTS.override.md`) is never loaded.
    """
    if file_type_name not in _FALLBACK_FILE_TYPES or agent_id not in _PRIMARY_NAMES:
        return found
    names = {n.lower() for n in _fallback_names(project_config, agent_id)} - _PRIMARY_NAMES[agent_id]
    if not names:
        return found
    return [p for p in found if p.name.lower() not in names or not _dir_has_primary(p.parent, agent_id)]


def _surface_include_patterns(agent_id: str, file_type_name: str, project_config: ProjectConfig | None) -> list[str]:
    """Patterns to ADD to a file_type's declared list, sourced from project config.

    Reads `surfaces.<agent>.<file_type>.include` from `.ails/config.yml`.
    Special case: for `<agent>.main` and `<agent>.nested_context`, also injects
    `**/<filename>` for each entry in `agents.<agent>.fallback_filenames` so
    user-declared alternative instruction filenames (e.g., Codex
    `project_doc_fallback_filenames`) are found at the root, in the directories
    down to the run's directory and in subdirectories.
    """
    if project_config is None:
        return []
    extra: list[str] = []
    surfaces = getattr(project_config, "surfaces", {}) or {}
    surface_key = f"{agent_id}.{file_type_name}"
    surface_cfg = surfaces.get(surface_key, {})
    if isinstance(surface_cfg, dict):
        include = surface_cfg.get("include", [])
        if isinstance(include, list):
            extra.extend(str(p) for p in include)

    if file_type_name in _FALLBACK_FILE_TYPES:
        extra.extend(f"**/{name}" for name in _fallback_names(project_config, agent_id))
    return extra


def config_names_agent(agent_id: str, project_config: ProjectConfig | None) -> bool:
    """True when the project's own config declares `agents.<agent>.fallback_filenames`.

    Declaring alternative instruction filenames for an agent is the project saying which
    agent reads them, so that agent is detected even when its fallback files sit only in
    subfolders (or beside the agent's own main file, where they are skipped).
    """
    return bool(_fallback_names(project_config, agent_id))


def _surface_exclude_patterns(agent_id: str, file_type_name: str, project_config: ProjectConfig | None) -> list[str]:
    """Glob patterns whose matches should be DROPPED from a surface's results."""
    if project_config is None:
        return []
    surfaces = getattr(project_config, "surfaces", {}) or {}
    surface_key = f"{agent_id}.{file_type_name}"
    surface_cfg = surfaces.get(surface_key, {})
    if not isinstance(surface_cfg, dict):
        return []
    exclude = surface_cfg.get("exclude", [])
    if not isinstance(exclude, list):
        return []
    return [str(p) for p in exclude]


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
                if p.startswith(prefix) or not _is_external_pattern(p)
            ]
        return [p for p in patterns if not _is_external_pattern(p)]
    return patterns


def discover_from_config(
    target: Path,
    agent_id: str,
    rules_paths: list[Path] | None = None,
    extra_exclude_dirs: frozenset[str] | None = None,
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
    from reporails_cli.core.discovery.agents import _extract_patterns, _extract_properties, load_project_exclude_dirs
    from reporails_cli.core.discovery.plugin_roots import expand_plugin_patterns
    from reporails_cli.core.discovery.read_gates import apply_read_gate

    file_types = load_config_file_types(agent_id, rules_paths)
    if file_types is None:
        return None
    excluded = extra_exclude_dirs or load_project_exclude_dirs(target)

    instruction_files: list[Path] = []
    rule_files: list[Path] = []
    config_files: list[Path] = []

    # Union of every per-surface exclude declared for this agent. Some agents
    # have multiple surfaces that match the same paths (e.g. cursor.rules and
    # cursor.bugbot_rules both match `.cursor/rules/**/*.mdc`). Applying each
    # surface's exclude only within its own loop iteration leaves the file
    # surfaced from the other surface — counter to the user's mental model
    # ("I excluded draft, draft should be gone"). The union closes the gap.
    agent_exclude_globs: list[str] = []
    for ft_name in file_types:
        agent_exclude_globs.extend(_surface_exclude_patterns(agent_id, ft_name, project_config))

    user_dir = target if repo_scoped and user_level_agent_dir(target) == target else None
    plugin_roots: dict[str, list[Path]] = {}
    for ft_name, spec in file_types.items():
        if not isinstance(spec, dict):
            continue
        patterns = _repo_scoped_patterns(list(_extract_patterns(spec)), ft_name, repo_scoped, user_dir)
        # A plugin component pattern resolves against each plugin root found here.
        patterns = expand_plugin_patterns(patterns, target, excluded, plugin_roots)
        if not patterns:
            continue
        properties = _extract_properties(spec)

        bucket = categorize_file_type(patterns, properties)
        if bucket == "skip":
            continue

        # Inject per-surface include patterns from .ails/config.yml
        extra_include = _surface_include_patterns(agent_id, ft_name, project_config)
        if extra_include:
            patterns = patterns + extra_include

        found = glob_file_type_patterns(target, patterns, properties, excluded)

        if agent_exclude_globs:
            found = [p for p in found if not _matches_any_glob(p, agent_exclude_globs, target)]
        # A file type the agent reads only under a condition keeps just the files it reads.
        found = apply_read_gate(agent_id, ft_name, found, target)
        found = drop_shadowed_fallbacks(found, agent_id, ft_name, project_config)

        if bucket == "instruction":
            instruction_files.extend(found)
        elif bucket == "rule":
            rule_files.extend(found)
        elif bucket == "config":
            config_files.extend(found)

    return (
        _dedupe_by_canonical(instruction_files),
        _dedupe_by_canonical(rule_files),
        _dedupe_by_canonical(config_files),
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


def _dedupe_by_canonical(paths: list[Path]) -> list[Path]:
    """Sort and dedupe paths by their canonical (symlink-resolved) target.

    Two surface paths can refer to the same underlying file when one or
    both are symlinks (common pattern: `.claude/skills -> ../.agents/skills`).
    Naive `set(paths)` keeps both because path equality compares strings.
    Canonicalizing via `Path.resolve(strict=True)` collapses symlinks; the
    first surface path encountered for a canonical target wins.
    """
    seen_canonical: set[Path] = set()
    out: list[Path] = []
    for p in sorted(set(paths)):
        canonical = _canonical_path(p)
        if canonical in seen_canonical:
            continue
        seen_canonical.add(canonical)
        out.append(p)
    return out
