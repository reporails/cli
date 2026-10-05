"""File classification engine — typed file targeting for rules.

Replaces the template variable system. Agent configs declare file_types
with glob patterns and properties. Rules declare match criteria. The
classification engine resolves files to types and matches rules to files.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path

import yaml

from reporails_cli.core.classify.content_format import detect_content_format
from reporails_cli.core.discovery.agent_discovery import is_memory_recall_entry
from reporails_cli.core.discovery.plugin_roots import matches_plugin_pattern
from reporails_cli.core.platform.dto.models import ClassifiedFile, FileMatch, FileTypeDeclaration
from reporails_cli.core.platform.policy.matching import match_files
from reporails_cli.core.platform.utils.utils import glob_matches, load_yaml_file

logger = logging.getLogger(__name__)


def load_file_types(
    agent: str,
    rules_paths: list[Path] | None = None,
    project_root: Path | None = None,
) -> list[FileTypeDeclaration]:
    """Load file_types from agent config.yml, with optional project overrides.

    Searches rules_paths first, then falls back to default config path. When
    `project_root` is provided, reads `.ails/config.yml` (+ `.ails/config.local.yml`)
    and merges per-surface `include` / `exclude` patterns plus
    `agents.<id>.fallback_filenames` into the matching FileTypeDeclarations.

    Args:
        agent: Agent identifier (e.g., "claude")
        rules_paths: Optional rules directories to search first
        project_root: Optional project root for reading `.ails/config.yml`

    Returns:
        List of FileTypeDeclaration, empty if no config found
    """
    from reporails_cli.core.platform.config.bootstrap import get_agent_config_path

    candidates: list[Path] = []
    if rules_paths:
        candidates.extend(rules_dir / agent / "config.yml" for rules_dir in rules_paths)
    candidates.append(get_agent_config_path(agent))

    for config_path in candidates:
        if not config_path.exists():
            continue
        try:
            data = load_yaml_file(config_path)
            if not data:
                logger.warning("Agent config is empty: %s", config_path)
                continue
            file_types_data = data.get("file_types", {})
            if not file_types_data:
                continue
            decls = _parse_file_types(file_types_data)
            if project_root is not None:
                decls = _apply_project_overrides(decls, agent, project_root)
            return decls
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("Failed to parse agent file_types %s: %s", config_path, exc)
            continue
    return []


def _apply_project_overrides(
    declarations: list[FileTypeDeclaration],
    agent: str,
    project_root: Path,
) -> list[FileTypeDeclaration]:
    """Merge project config overrides into FileTypeDeclarations.

    Adds patterns from `surfaces.<agent>.<file_type>.include` and Codex
    `agents.<agent>.fallback_filenames` (for `main`) so classification can
    match user-configured fallback instruction files.
    """
    from reporails_cli.core.platform.config.config import get_project_config

    project_config = get_project_config(project_root)

    surfaces = getattr(project_config, "surfaces", {}) or {}
    agents_cfg = getattr(project_config, "agents", {}) or {}

    out: list[FileTypeDeclaration] = []
    for decl in declarations:
        extra: list[str] = []
        surface_cfg = surfaces.get(f"{agent}.{decl.name}", {})
        if isinstance(surface_cfg, dict):
            include = surface_cfg.get("include", [])
            if isinstance(include, list):
                extra.extend(str(p) for p in include)
        if decl.name in ("main", "nested_context"):
            agent_cfg = agents_cfg.get(agent, {})
            if isinstance(agent_cfg, dict):
                fallbacks = agent_cfg.get("fallback_filenames", [])
                if isinstance(fallbacks, list):
                    extra.extend(f"**/{name}" for name in fallbacks if isinstance(name, str))
        if extra:
            out.append(
                FileTypeDeclaration(
                    name=decl.name,
                    patterns=decl.patterns + tuple(extra),
                    required=decl.required,
                    properties=decl.properties,
                )
            )
        else:
            out.append(decl)
    return out


def _parse_file_types(data: dict[str, object]) -> list[FileTypeDeclaration]:
    """Parse file_types dict from agent config into FileTypeDeclaration list.

    Supports both v0.3.0 (patterns + properties nested) and v0.5.0
    (scopes with patterns, properties flattened) schema versions.
    """
    from reporails_cli.core.discovery.agents import _extract_patterns
    from reporails_cli.core.discovery.agents import _extract_properties as _agent_props

    declarations: list[FileTypeDeclaration] = []
    for name, spec in data.items():
        if not isinstance(spec, dict):
            continue
        patterns = _extract_patterns(spec)
        # v0.3.0: properties nested; v0.5.0: flattened at file type level
        raw_props = spec.get("properties")
        if isinstance(raw_props, dict):
            props = _extract_properties(raw_props)
        else:
            props = _extract_properties(_agent_props(spec))
        declarations.append(
            FileTypeDeclaration(
                name=name,
                patterns=tuple(str(p) for p in patterns),
                required=spec.get("required", False),
                properties=props,
            )
        )
    return declarations


def _extract_properties(props: dict[str, object] | None) -> dict[str, str | list[str]]:
    """Extract properties from config. Preserves lists for multi-valued properties."""
    if not props:
        return {}
    result: dict[str, str | list[str]] = {}
    for k, v in props.items():
        if v is None:
            continue
        if isinstance(v, list):
            result[k] = [str(item) for item in v]
        else:
            result[k] = str(v)
    return result


def _compute_ancestor_chain(scan_root: Path) -> set[Path]:
    """Directories from scan_root UP to the project root, inclusive.

    Used by classify_files to distinguish files loaded eagerly by the agent
    (in cwd's ancestor chain) from files loaded on-demand (in descendant
    subdirectories). Mirrors the agent's actual loading model.
    """
    from reporails_cli.core.discovery.agent_discovery import resolve_project_root

    root = resolve_project_root(scan_root)
    chain: set[Path] = set()
    current = scan_root if scan_root.is_dir() else scan_root.parent
    while True:
        chain.add(current)
        if current == root or current == current.parent:
            break
        current = current.parent
    return chain


def _is_loose_leaf_pattern(pattern: str) -> bool:
    """Pattern that can match a file at ANY directory depth.

    A "loose" pattern is either a bare filename (e.g. `CLAUDE.md`) or starts
    with `**/` (e.g. `**/CLAUDE.md`). Such patterns are location-ambiguous —
    the same file matches them whether it lives at cwd, an ancestor, or a
    descendant. These need ancestor-chain disambiguation to distinguish
    `main` (eager) from `nested_context` (on-demand).

    Path-prefixed patterns (e.g. `.github/copilot-instructions.md`,
    `.claude/rules/**/*.md`) are NOT loose — the path prefix already
    constrains where the file lives, so no further disambiguation is
    needed.
    """
    if pattern.startswith("**/"):
        return True
    # Bare leaf with no path separators
    return "/" not in pattern and "**" not in pattern


def _location_matches_mode(
    file_path: Path,
    ft: FileTypeDeclaration,
    ancestor_chain: set[Path],
    matched_pattern: str,
) -> bool:
    """Check whether file's location fits the file_type's loading model.

    Eager global file_types (scope=global, loading=session_start) — like
    `main`, `override`, `agents_md`, `cross_read` — match only files in cwd's
    ancestor chain WHEN the matched pattern is a loose leaf glob (`**/X.md`
    or bare `X.md`). For path-prefixed patterns like `.github/X.md` the
    pattern itself constrains location, so the ancestor-chain check is
    skipped.

    Nested file_types (scope=nested) match only files OUTSIDE the ancestor
    chain (descendants of cwd). Subtree applicability comes from file location
    (no frontmatter); the agent loads these when descending into subdirs.

    Other file_types (path_scoped rules, skills, agents, configs, etc.)
    match anywhere their patterns find them.
    """
    scope = ft.properties.get("scope")
    loading = ft.properties.get("loading")
    parent = file_path.parent
    in_ancestor_chain = parent in ancestor_chain

    if scope == "global" and loading == "session_start":
        # Only enforce ancestor-chain for loose leaf patterns; path-prefixed
        # patterns already pin the file's location via the pattern itself.
        if _is_loose_leaf_pattern(matched_pattern):
            return in_ancestor_chain
        return True
    if scope == "nested":
        return not in_ancestor_chain
    return True


def _pattern_hits(file_path: Path, rel: str, pattern: str, scan_root: Path) -> bool:
    """`_pattern_matches_one` for `rel`; a plugin component pattern instead matches the
    file's path from the plugin root it sits under (see `core.discovery.plugin_roots`)."""
    plugin_hit = matches_plugin_pattern(file_path, scan_root, pattern, _pattern_matches_one)
    if plugin_hit is not None:
        return plugin_hit
    if pattern.startswith("~"):
        # A user-level pattern names a place under the home directory, so it matches the
        # file's full path even when the scan root is that user-level folder itself.
        return _pattern_matches_one(file_path.as_posix(), pattern)
    return _pattern_matches_one(rel, pattern)


def _with_skill_folder(
    ft: FileTypeDeclaration, file_path: Path, skills: Mapping[str, str] | None
) -> dict[str, str | list[str]]:
    """The declaration's properties; a `skills` file also carries its skill folder as `skill`."""
    props = dict(ft.properties)
    if ft.name == "skills" and skills is not None:
        props["skill"] = skills[str(file_path)]
    return props


def _classify_one(
    file_path: Path,
    scan_root: Path,
    file_types: list[FileTypeDeclaration],
    ancestor_chain: set[Path],
    skills: Mapping[str, str] | None,
) -> ClassifiedFile | None:
    """The first file type `file_path` matches as a ClassifiedFile, None when it matches none."""
    try:
        rel = file_path.relative_to(scan_root).as_posix()
    except ValueError:
        rel = str(file_path)

    for ft in file_types:
        # A pattern that matches but fails the location check (e.g. a shared
        # loose leaf like `**/CLAUDE.md`) does not block a later, more
        # specific pattern of the SAME file_type (e.g. `~/.claude/CLAUDE.md`)
        # from getting a turn — each matching pattern is tried in order.
        matched_pattern = next(
            (
                pattern
                for pattern in ft.patterns
                if _pattern_hits(file_path, rel, pattern, scan_root)
                and _location_matches_mode(file_path, ft, ancestor_chain, pattern)
            ),
            None,
        )
        if matched_pattern is None:
            continue
        if ft.name == "skills" and skills is not None and str(file_path) not in skills:
            continue
        props = _with_skill_folder(ft, file_path, skills)
        # Per-entry memory loading: only MEMORY.md is the eager index;
        # sibling entries are recalled on-demand.
        if is_memory_recall_entry(ft.name, file_path.name):
            props["loading"] = "on_demand"
        # Detect content_format for freeform files
        fmt = props.get("format")
        is_freeform = fmt == "freeform" or (isinstance(fmt, list) and "freeform" in fmt)
        if is_freeform and "content_format" not in props:
            try:
                cf = detect_content_format(file_path.read_text(encoding="utf-8", errors="replace"))
                if cf:
                    props["content_format"] = cf
            except OSError:
                pass
        return ClassifiedFile(path=file_path, file_type=ft.name, properties=props)  # first valid match wins
    return None


def classify_files(
    scan_root: Path,
    files: list[Path],
    file_types: list[FileTypeDeclaration],
    generic_scanning: bool = False,
    skills: Mapping[str, str] | None = None,
) -> list[ClassifiedFile]:
    """Classify files against type declarations. First pattern match wins.

    File_type semantics drive ancestor-vs-descendant disambiguation: when
    two file_types share a pattern (e.g. main and nested_context both use
    **/CLAUDE.md), the file's location relative to scan_root's ancestor
    chain decides which declaration wins.

    For freeform files, content_format is detected from file content.

    When `generic_scanning` is True, after pattern-based classification
    the classifier walks Markdown links from each classified file and
    assigns `file_type: "generic"` to any in-tree `.md` files reachable
    via those links that aren't already classified. See `link_walker.py`
    for the walk implementation.

    Args:
        scan_root: Project root / cwd-equivalent for relative paths and
            ancestor-chain anchoring.
        files: Files to classify
        file_types: Type declarations from agent config
        generic_scanning: When True, extend with link-reachability pass
        skills: Skill folder of each file that sits in a skill, keyed by file path.
            When given, a file is typed `skills` only if it is a key, and carries its
            folder as the `skill` property. None leaves the `skills` type to the pattern.

    Returns:
        List of ClassifiedFile for matched files
    """
    # A file target (e.g. `ails check ./CLAUDE.md`) arrives as scan_root;
    # normalize to its parent dir so relative paths and the ancestor chain
    # reproduce the whole-project result instead of yielding empty matches.
    if not scan_root.is_dir():
        scan_root = scan_root.parent

    ancestor_chain = _compute_ancestor_chain(scan_root)

    classified: list[ClassifiedFile] = []
    for file_path in files:
        cf = _classify_one(file_path, scan_root, file_types, ancestor_chain, skills)
        if cf is not None:
            classified.append(cf)

    if generic_scanning:
        classified.extend(_classify_generic_via_links(scan_root, classified))

    return classified


def _classify_generic_via_links(
    scan_root: Path,
    classified: list[ClassifiedFile],
) -> list[ClassifiedFile]:
    """BFS Markdown links + `@<path>` imports from classified files.

    Reachable `.md` files are classified as `file_type: generic` with
    edge-attribution properties — `link_source_type`, `link_source_path`,
    `link_depth`, `loading_verb` — set from the incoming `LinkEdge` set.

    Lazy-imported to avoid pulling the walker module when generic scanning
    is off (the default).
    """
    from reporails_cli.core.classify.generic_type import make_generic_classified
    from reporails_cli.core.classify.link_walker import LinkEdge, walk_markdown_links

    seed_map: dict[Path, str] = {cf.path: cf.file_type for cf in classified}
    classified_paths = set(seed_map.keys())
    edges = walk_markdown_links(seed_map, scan_root, classified_paths)

    by_target: dict[Path, list[LinkEdge]] = {}
    for edge in edges:
        by_target.setdefault(edge.target, []).append(edge)

    return [
        make_generic_classified(target, target_edges, scan_root) for target, target_edges in sorted(by_target.items())
    ]


def resolve_match_to_paths(
    classified: list[ClassifiedFile],
    match: FileMatch | None,
    scan_root: Path,
) -> list[str]:
    """Resolve match criteria to relative path strings for the regex runner.

    Args:
        classified: Previously classified files
        match: Match criteria, or None for all files
        scan_root: Project root for relative paths

    Returns:
        List of relative path strings
    """
    targets = classified if match is None else match_files(classified, match)

    paths: list[str] = []
    for cf in targets:
        try:
            paths.append(cf.path.relative_to(scan_root).as_posix())
        except ValueError:
            paths.append(str(cf.path))
    return paths


def _matches_any_pattern(rel_path: str, patterns: tuple[str, ...]) -> bool:
    """Check if a relative path matches any glob pattern.

    Glob matching is `glob_matches`: ``**`` spans zero or more directory components
    (``a/**/b`` matches ``a/b`` and ``a/x/b``).
    """
    return _first_matching_pattern(rel_path, patterns) is not None


def _first_matching_pattern(rel_path: str, patterns: tuple[str, ...]) -> str | None:
    """Return the first pattern that matches `rel_path`, or None.

    Used by `_matches_any_pattern` and by callers that only need "does any
    pattern match", with no location-mode disambiguation. `classify_files`
    itself calls `_pattern_matches_one` directly so a pattern that matches
    but fails the location check does not block a later pattern of the
    same file_type from getting a turn.
    """
    return next((pattern for pattern in patterns if _pattern_matches_one(rel_path, pattern)), None)


def _pattern_matches_one(rel_path: str, pattern: str) -> bool:
    """Whether `pattern` matches `rel_path`.

    Trailing-slash patterns (`.claude/agent-memory/*/`) name a directory
    glob whose contents are the file_type's instances; they expand to
    `<dir>**/*.md` for match purposes so memory entry files inside the
    directory tag with the capability's file_type.

    A `~`-rooted pattern (`~/.claude/CLAUDE.md`, `~/.claude/projects/*/memory/`)
    is resolved to an absolute path before matching — `rel_path` for a file
    outside the scan root is already its absolute path string, so the raw
    `~` component never matches it without expansion.

    A location-pinned pattern (one that names a path, i.e. is not a loose
    leaf — see `_is_loose_leaf_pattern`) is anchored at the scan root: it
    must match `rel_path` in full, never just its trailing components, so
    `.claude/CLAUDE.md` does not match a deeper file like `pkg/.claude/CLAUDE.md`.
    An already-absolute pattern (a resolved `~`-pattern) always matches the whole path.
    """
    from reporails_cli.core.discovery.agent_discovery import expand_home_pattern

    clean = pattern.removeprefix("./")
    expanded = expand_home_pattern(clean + "**/*.md" if clean.endswith("/") else clean)
    return glob_matches(rel_path, expanded, anchored=not _is_loose_leaf_pattern(clean))
