"""Agent file discovery — config-driven file globbing and path matching.

Extracted from agents.py to keep that module under the 600-line limit.
All functions here are internal to the agent subsystem.
"""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reporails_cli.core.discovery.walk import walk_markdown

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.results import ProjectConfig

logger = logging.getLogger(__name__)

# Directories that never contain instruction files — skipped unconditionally.
# Project-specific exclusions come from .ails/config.yml exclude_dirs.
_ALWAYS_SKIP = frozenset({".git", "__pycache__", "node_modules"})


def ci_glob(target: Path, pattern: str) -> list[Path]:
    """Case-sensitive glob — agent specs treat filename casing as authoritative.

    Name retained from the previous case-insensitive implementation; behavior
    is now case-sensitive per the agents.md spec ("Filenames not on this list
    are ignored for instruction discovery.").
    """
    parts = Path(pattern).parts
    if len(parts) == 1 and "*" not in pattern:
        try:
            return [p for p in target.iterdir() if p.name == pattern and not p.is_dir()]
        except OSError:
            return []
    return list(target.glob(pattern))


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


def walk_glob(root: Path, filename: str, exclude_dirs: frozenset[str]) -> list[Path]:
    """Walk directory tree matching a filename exactly, skipping excluded dirs.

    Much faster than Path.glob("**/name") because it prunes excluded
    subtrees during traversal instead of filtering afterwards.
    Uses os.scandir for efficient directory traversal.

    Follows symlinked directories; canonical inode paths in `visited_real`
    break cycles so each physical directory is entered at most once.

    Match is case-SENSITIVE per agent implementations. The OpenAI Codex
    source (`codex-rs/core/src/agents_md.rs`) declares:

        pub const DEFAULT_AGENTS_MD_FILENAME: &str = "AGENTS.md";
        pub const LOCAL_AGENTS_MD_FILENAME: &str = "AGENTS.override.md";

    and looks them up via exact `path.join(filename)` + `std::fs::read_to_string`
    — case-sensitive on Linux, exact-case lookup on macOS/Windows. The
    agents.md spec is consistent: discovery list is "AGENTS.override.md,
    AGENTS.md, TEAM_GUIDE.md, .agents.md. Filenames not on this list are
    ignored." A file named `agents.md` (lowercase, no leading dot) is NOT
    the same as `AGENTS.md` and must not be matched. Same convention applies
    to `CLAUDE.md` and `GEMINI.md`.
    """
    skip = exclude_dirs | _ALWAYS_SKIP
    results: list[Path] = []
    stack = [str(root)]
    visited_real: set[str] = set()
    with contextlib.suppress(OSError):
        visited_real.add(os.path.realpath(root))
    while stack:
        current = stack.pop()
        try:
            scanner = os.scandir(current)
        except OSError:
            continue
        with scanner:
            for entry in scanner:
                if entry.name == filename:
                    if _walk_entry_is_file(entry):
                        results.append(Path(entry.path))
                elif _walk_should_descend(entry, skip, visited_real):
                    stack.append(entry.path)
    return results


def _walk_entry_is_file(entry: os.DirEntry[str]) -> bool:
    """Whether a scandir entry resolves to a regular file (follows symlinks).

    Broken/circular symlinks raise `OSError`; surface them anyway so
    downstream code can report the error properly.
    """
    try:
        return entry.is_file(follow_symlinks=True)
    except OSError:
        return entry.is_symlink()


def _walk_should_descend(entry: os.DirEntry[str], skip: frozenset[str], visited_real: set[str]) -> bool:
    """Whether a scandir entry is a directory worth descending into.

    Follows directory symlinks (so hub-adopted skills/rules surface) and
    tracks canonical inode paths in `visited_real` to break cycles —
    each physical directory is entered at most once across the walk.
    """
    if entry.name in skip:
        return False
    try:
        if not entry.is_dir(follow_symlinks=True):
            return False
    except OSError:
        return False
    try:
        real = os.path.realpath(entry.path)
    except OSError:
        return False
    if real in visited_real:
        return False
    visited_real.add(real)
    return True


def walk_ancestors(start: Path, filename: str, stop: Path) -> list[Path]:
    """Walk up from start, collecting filename matches at each ancestor.

    Returns paths in walked order (closest first). Match is case-SENSITIVE
    per agent specs (see walk_glob docstring for citation).
    """
    results: list[Path] = []
    current = start if start.is_dir() else start.parent
    while True:
        try:
            for entry in os.scandir(current):
                if entry.name == filename:
                    try:
                        is_match = entry.is_file(follow_symlinks=True)
                    except OSError:
                        is_match = entry.is_symlink()
                    if is_match:
                        results.append(Path(entry.path))
                        break
        except OSError:
            pass
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


def _run_descendant_recursive(target: Path, pattern: str, nested: bool, exclude_dirs: frozenset[str]) -> list[Path]:
    """Descendant walk for **/<leaf> patterns.

    `nested` (scope: nested) excludes cwd itself — those files belong to the
    eager file_type (main) discovered via ancestor walk.
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
    return [m for m in results if not is_excluded(m, target, exclude_dirs)]


def glob_file_type_patterns(
    target: Path,
    patterns: list[str],
    properties: dict[str, str] | None = None,
    exclude_dirs: frozenset[str] = frozenset(),
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
            project_key = str(target.resolve()).replace("/", "-")
            expanded_str = expanded_str.replace("/projects/*/", f"/projects/{project_key}/")
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
            project_key = str(target.resolve()).replace("/", "-")
            expanded_str = expanded_str.replace("/projects/*/", f"/projects/{project_key}/")
        import glob as _glob

        for d in _glob.glob(expanded_str):
            base = Path(d)
            if base.is_dir():
                found.extend(walk_markdown(base))
        return

    # In-tree pattern: resolve glob relative to target, enumerate .md inside each dir
    for base in _resolve_in_tree_dirs(dir_pattern, target, exclude_dirs):
        found.extend(entry for entry in walk_markdown(base) if not is_excluded(entry, target, exclude_dirs))


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


def _surface_include_patterns(agent_id: str, file_type_name: str, project_config: ProjectConfig | None) -> list[str]:
    """Patterns to ADD to a file_type's declared list, sourced from project config.

    Reads `surfaces.<agent>.<file_type>.include` from `.ails/config.yml`.
    Special case: for `<agent>.main`, also injects `**/<filename>` for each
    entry in `agents.<agent>.fallback_filenames` so user-declared alternative
    instruction filenames (e.g., Codex `project_doc_fallback_filenames`) are
    treated as main candidates.
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

    if file_type_name == "main":
        agents_cfg = getattr(project_config, "agents", {}) or {}
        agent_cfg = agents_cfg.get(agent_id, {})
        if isinstance(agent_cfg, dict):
            fallbacks = agent_cfg.get("fallback_filenames", [])
            if isinstance(fallbacks, list):
                extra.extend(f"**/{name}" for name in fallbacks if isinstance(name, str))
    return extra


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


def _matches_any_glob(path: Path, patterns: list[str], target: Path) -> bool:
    """Check whether path matches any of the glob patterns relative to target."""
    if not patterns:
        return False
    try:
        rel = path.relative_to(target).as_posix()
    except ValueError:
        rel = str(path)
    for pattern in patterns:
        # PurePath.match supports glob-style; **/ wildcards may need normalization
        try:
            if Path(rel).match(pattern):
                return True
            # Also try absolute match for patterns that include the full prefix
            if path.match(pattern):
                return True
        except ValueError:
            continue
    return False


def discover_from_config(
    target: Path,
    agent_id: str,
    rules_paths: list[Path] | None = None,
    extra_exclude_dirs: frozenset[str] = frozenset(),
    project_config: ProjectConfig | None = None,
) -> tuple[list[Path], list[Path], list[Path]] | None:
    """Discover files using config.yml file_types.

    Optionally consults `project_config` (a `ProjectConfig`) for per-surface
    include/exclude pattern adjustments and Codex fallback filenames declared
    in `.ails/config.yml` (or `.ails/config.local.yml`).

    Returns (instruction_files, rule_files, config_files) or None if
    no config.yml is available for this agent.
    """
    from reporails_cli.core.discovery.agents import _extract_patterns, _extract_properties

    file_types = load_config_file_types(agent_id, rules_paths)
    if file_types is None:
        return None

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

    for ft_name, spec in file_types.items():
        if not isinstance(spec, dict):
            continue
        patterns = list(_extract_patterns(spec))
        properties = _extract_properties(spec)

        bucket = categorize_file_type(patterns, properties)
        if bucket == "skip":
            continue

        # Inject per-surface include patterns from .ails/config.yml
        extra_include = _surface_include_patterns(agent_id, ft_name, project_config)
        if extra_include:
            patterns = patterns + extra_include

        found = glob_file_type_patterns(target, patterns, properties, extra_exclude_dirs)

        if agent_exclude_globs:
            found = [p for p in found if not _matches_any_glob(p, agent_exclude_globs, target)]

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
