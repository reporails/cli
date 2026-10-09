"""Filesystem feature detection for capability gates and symlink resolution.

Populates DetectedFeatures by inspecting the project layout: instruction
files, abstracted-rules directories, backbone manifest, shared files, and
content-level signals on the root instruction file. Also resolves
instruction-file symlinks that point outside the scan directory so the
regex engine can scan them as extra targets.
"""

from __future__ import annotations

import functools
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.discovery.agent_discovery import (
    claude_project_folder_name,
    glob_file_type_patterns,
    load_config_file_types,
)
from reporails_cli.core.discovery.agents import (
    DetectedAgent,
    _extract_patterns,
    _extract_properties,
    detect_agents,
    get_all_instruction_files,
    get_known_agents,
)
from reporails_cli.core.discovery.walk import is_symlink_loop_error, is_under, safe_resolve
from reporails_cli.core.mapper.classify import CONSTRAINT_WORDS
from reporails_cli.core.mapper.imports import import_refs
from reporails_cli.core.platform.dto.results import DetectedFeatures, HookEntry
from reporails_cli.core.platform.utils.hook_config import HookConfig, hook_sites, read_hook_config
from reporails_cli.core.platform.utils.utils import matches_any_glob

logger = logging.getLogger(__name__)


_CONSTRAINT_RE = re.compile(r"\b(" + "|".join(sorted(CONSTRAINT_WORDS)) + r")\b")
_SIZE_THRESHOLD = 500  # lines


def resolve_symlinked_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """Find instruction files that are symlinks pointing outside the scan directory."""
    resolved: list[Path] = []
    real_target = safe_resolve(target)

    for path in get_all_instruction_files(target, agents=agents):
        if not path.is_symlink():
            continue
        try:
            real_path = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            if is_symlink_loop_error(exc):
                logger.warning(
                    "Circular symlink detected: %s — file will be skipped",
                    path,
                )
            continue
        # Only include if resolved path is outside the scan directory
        try:
            real_path.relative_to(real_target)
        except ValueError:
            # Outside the scan directory — regex engine scans as extra target
            resolved.append(real_path)

    return resolved


def _has_hierarchy(target: Path, agents: list[DetectedAgent] | None) -> bool:
    """Check if any agent has both root-level and nested instruction files."""
    if agents is None:
        return False
    for detected in agents:
        names_at_root: set[str] = set()
        has_nested = False
        for f in detected.instruction_files:
            if f.parent == target:
                names_at_root.add(f.name)
            else:
                has_nested = True
        if names_at_root and has_nested:
            return True
    return False


def _detect_path_scoped_rules(
    target: Path, resolved_agents: list[DetectedAgent], scan: _SurfaceScan | None = None
) -> bool:
    """L3 capability — path-scoped rules.

    For an agent whose own config.yml declares a `scope: path_scoped` type
    (Claude, Cursor, Copilot), `rule_files` is already scoped to it
    (agent_discovery.py's `categorize_file_type`) — Copilot's `applyTo`
    instructions and Cursor's `.mdc` rules land here exactly like Claude's
    `.claude/rules/*.md`. An agent with no `path_scoped` type (Codex,
    Antigravity — they scope instructions per directory through a nested
    on-demand instruction type instead) gets L3 credit from a real instance of
    that type actually present below the project root.
    """
    for detected in resolved_agents:
        agent_id = detected.agent_type.id
        if _agent_declares_path_scoped(agent_id):
            if detected.rule_files:
                return True
        elif _agent_nested_instruction_files(target, agent_id, scan):
            return True
    return False


def detect_features_filesystem(target: Path, agents: list[DetectedAgent] | None = None) -> DetectedFeatures:
    """Detect project features from file structure and content.

    Populates DetectedFeatures for capability-gate level detection,
    display summaries, and symlink resolution.

    Args:
        target: Project root path
        agents: Pre-detected agents (avoids redundant filesystem scan)

    Returns:
        DetectedFeatures with all capability fields populated
    """
    features = DetectedFeatures()

    # Agents already detected for this target, if the caller ran discovery once —
    # avoids a redundant filesystem scan. Every capability-gate field below is
    # computed per detected agent, from that agent's own config.yml, rather than
    # a fixed Claude-path list, so a Copilot, Codex, Cursor or Antigravity project
    # gates on its own declared surfaces.
    resolved_agents = agents if agents is not None else detect_agents(target)
    agent_ids = {a.agent_type.id for a in resolved_agents}
    scan = _SurfaceScan.for_target(target)

    # Check for CLAUDE.md at root
    root_claude = target / "CLAUDE.md"
    features.has_claude_md = root_claude.exists()
    features.has_instruction_file = features.has_claude_md

    # Check for backbone.yml
    backbone_path = target / ".ails" / "backbone.yml"
    features.has_backbone = backbone_path.exists()
    if features.has_backbone:
        features.component_count = _count_components(backbone_path)

    # Count instruction files (all agents, not just CLAUDE.md).
    # Scope the count to files under `target` — user-level memories like
    # `~/.claude/CLAUDE.md` get pulled in by claude's user-scope patterns,
    # but they are not part of the project's instruction-file inventory and
    # would inflate L-level capability gating (`has_multiple_instruction_files`
    # drives the `multiple_files` / `external_references` capability flags
    # in `policy/levels.py`).
    all_instruction_files = get_all_instruction_files(target, agents=resolved_agents)
    project_instruction_files = [f for f in all_instruction_files if is_under(f, target)]
    features.instruction_file_count = len(project_instruction_files)
    features.has_multiple_instruction_files = len(project_instruction_files) > 1

    if features.instruction_file_count > 0:
        features.has_instruction_file = True

    # Check for hierarchical structure
    features.has_hierarchical_structure = _has_hierarchy(target, resolved_agents)

    # Check for shared files
    shared_patterns = [".shared", "shared", ".ai/shared"]
    for pattern in shared_patterns:
        if (target / pattern).exists():
            features.has_shared_files = True
            break

    # L2 capabilities — content analysis on root instruction file
    root_file = _find_root_instruction(target, all_instruction_files)
    if root_file is not None:
        _detect_content_features(root_file, features)

    # L3 capabilities — path-scoped rules (or, for an agent with no such type
    # of its own, a real nested instruction file below root).
    features.has_path_scoped_rules = _detect_path_scoped_rules(target, resolved_agents, scan)

    # L4/L5 capabilities — skills / sub-agents, per detected agent's own config.yml
    features.has_skills_dir = any(_agent_has_surface(target, agent_id, "skills", scan) for agent_id in agent_ids)
    features.has_subagents = any(_agent_has_surface(target, agent_id, "agents", scan) for agent_id in agent_ids)

    # Directory structure — broadened beyond path-scoped rules to any abstracted
    # surface (skills, sub-agents) a detected agent declares.
    features.is_abstracted = features.has_path_scoped_rules or features.has_skills_dir or features.has_subagents

    # L6 capability — hooks, per detected agent's own config.yml. A folder of
    # plain git hooks is not an agent surface and adds no level.
    features.hook_files = tuple(f for agent_id in sorted(agent_ids) for f in _agent_hook_files(target, agent_id, scan))
    features.hooks = tuple(e for agent_id in sorted(agent_ids) for e in _agent_hook_entries(target, agent_id, scan))

    # L7 capabilities — adaptive: each detected agent's own repo-scoped memory
    # surfaces, plus Claude's user-scope auto-memory when Claude is detected.
    features.has_memory_dir = any(
        _agent_has_surface(target, agent_id, surface, scan)
        for agent_id in agent_ids
        for surface in ("memory", "subagent_memory")
    )
    features.has_auto_memory = "claude" in agent_ids and _detect_auto_memory(target)

    # Resolve symlinked instruction files (for regex engine extra targets)
    features.resolved_symlinks = resolve_symlinked_files(target, agents=resolved_agents)

    return features


def _hooks_key_is_set(settings_path: Path, scan: _SurfaceScan) -> bool:
    """True when the file declares a non-empty `hooks` block."""
    config = scan.hook_config(settings_path)
    return config is not None and isinstance(config.data, dict) and bool(config.data.get("hooks"))


def _repo_scoped_patterns(patterns: list[str]) -> list[str]:
    """Drop user-scope (`~/...`) and absolute patterns — a project-level gate checks
    the project's own files only; a home-directory surface reaches no further than
    the developer who ran the scan."""
    return [p for p in patterns if not p.startswith(("~", "/")) and not (len(p) > 1 and p[1] == ":")]


@dataclass
class _SurfaceScan:
    """What one feature detection shares: the project's excluded folders and the plugin
    roots already found, so each plugin marker is searched for once."""

    exclude_dirs: frozenset[str]
    roots_by_marker: dict[str, list[Path]] = field(default_factory=dict)
    hook_configs: dict[Path, HookConfig | None] = field(default_factory=dict)

    def hook_config(self, path: Path) -> HookConfig | None:
        """The hook config at `path`, read the first time it is asked for and kept for this detection."""
        if path not in self.hook_configs:
            self.hook_configs[path] = read_hook_config(path)
        return self.hook_configs[path]

    @classmethod
    def for_target(cls, target: Path) -> _SurfaceScan:
        from reporails_cli.core.discovery.agents import load_project_exclude_dirs

        return cls(exclude_dirs=load_project_exclude_dirs(target))


def _scan_for(target: Path, scan: _SurfaceScan | None) -> _SurfaceScan:
    """`scan` when given, else the project's own."""
    return scan if scan is not None else _SurfaceScan.for_target(target)


def _surface_patterns(
    target: Path, spec: dict[str, Any], scan: _SurfaceScan | None = None, *, repo_only: bool = True
) -> list[str]:
    """A file type's project-level patterns, with plugin-root patterns expanded against the
    plugin roots found under `target` exactly as discovery expands them (excluded folders
    are not searched). `repo_only=False` keeps the user-scope (`~/...`) and absolute patterns too."""
    from reporails_cli.core.discovery.plugin_roots import expand_plugin_patterns

    scan = _scan_for(target, scan)
    patterns = _extract_patterns(spec)
    return expand_plugin_patterns(
        _repo_scoped_patterns(patterns) if repo_only else patterns, target, scan.exclude_dirs, scan.roots_by_marker
    )


def _agent_surface_files(
    target: Path, agent_id: str, surface_name: str, scan: _SurfaceScan | None = None
) -> list[Path]:
    """Files matching `agent_id`'s declared `surface_name` file type under `target`.

    Reads the file type straight from the agent's own `config.yml` — a `skills`,
    `agents`, `hooks` or `mcp` surface is wherever that agent's own docs say it is,
    not a fixed Claude path.
    """
    scan = _scan_for(target, scan)
    file_types = load_config_file_types(agent_id)
    if not file_types:
        return []
    spec = file_types.get(surface_name)
    if not isinstance(spec, dict):
        return []
    patterns = _surface_patterns(target, spec, scan)
    if not patterns:
        return []
    return glob_file_type_patterns(target, patterns, _extract_properties(spec), scan.exclude_dirs)


def _agent_has_surface(target: Path, agent_id: str, surface_name: str, scan: _SurfaceScan | None = None) -> bool:
    """True when `agent_id` declares `surface_name` and a file matches it under `target`."""
    return bool(_agent_surface_files(target, agent_id, surface_name, scan))


def _hooks_spec(agent_id: str) -> dict[str, Any] | None:
    """`agent_id`'s `hooks` file type from its own `config.yml`; None when it declares none."""
    file_types = load_config_file_types(agent_id)
    spec = file_types.get("hooks") if file_types else None
    return spec if isinstance(spec, dict) else None


def _hook_scope_matches(target: Path, agent_id: str, scan: _SurfaceScan, *, repo_only: bool) -> list[tuple[str, Path]]:
    """Each file of `agent_id`'s hooks surface with the scope of that surface it sits in.

    Every scope the surface models is read (project, local, user, plugin, managed), or only
    the repo-scoped patterns when `repo_only`. A file two scopes both match is listed once,
    under the first.
    """
    spec = _hooks_spec(agent_id)
    if spec is None:
        return []
    scopes = spec.get("scopes")
    by_scope = scopes if isinstance(scopes, dict) else {"project": spec}
    props = _extract_properties(spec)
    seen: set[Path] = set()
    found: list[tuple[str, Path]] = []
    for scope, scope_spec in by_scope.items():
        if not isinstance(scope_spec, dict):
            continue
        patterns = _surface_patterns(
            target, {"scopes": {scope: scope_spec}} if scopes else spec, scan, repo_only=repo_only
        )
        for match in glob_file_type_patterns(target, patterns, props, scan.exclude_dirs):
            if match not in seen:
                seen.add(match)
                found.append((scope, match))
    return found


def _agent_hook_files(target: Path, agent_id: str, scan: _SurfaceScan | None = None) -> list[Path]:
    """The repo-scoped files of `agent_id`'s hooks surface that carry a real hook entry.

    A hooks surface that shares its file with the agent's general config file
    (Claude nests hooks inside `.claude/settings.json`, which also carries
    `permissions` and other settings) only counts when that file's `hooks` key is
    non-empty — the file's mere existence says nothing about hooks. A surface with
    its own dedicated file (Cursor's `.cursor/hooks.json`, Copilot's
    `.github/hooks/*.json`, Codex's `.codex/hooks.json`, Antigravity's
    `.agents/hooks.json`) counts on existence, matching every other surface check.
    """
    scan = _scan_for(target, scan)
    spec = _hooks_spec(agent_id)
    if spec is None:
        return []
    file_types = load_config_file_types(agent_id) or {}
    config_spec = file_types.get("config")
    config_patterns = _extract_patterns(config_spec) if isinstance(config_spec, dict) else []
    shared_patterns = list(set(_repo_scoped_patterns(_extract_patterns(spec))) & set(config_patterns))
    counted: list[Path] = []
    for _scope, match in _hook_scope_matches(target, agent_id, scan, repo_only=True):
        dedicated = not shared_patterns or not matches_any_glob(match, shared_patterns, target)
        if dedicated or _hooks_key_is_set(match, scan):
            counted.append(match)
    return counted


def _hook_file_label(path: Path, target: Path) -> str:
    """A hook file as shown to the user: project-relative, `~/`-relative in the home folder, else absolute."""
    resolved = path.resolve()
    for base, prefix in ((target, ""), (Path.home(), "~/")):
        if resolved.is_relative_to(safe_resolve(base)):
            return prefix + resolved.relative_to(safe_resolve(base)).as_posix()
    return path.as_posix()


def _agent_hook_entries(target: Path, agent_id: str, scan: _SurfaceScan | None = None) -> list[HookEntry]:
    """Every hook handler in every file of `agent_id`'s hooks surface, in every scope it models."""
    scan = _scan_for(target, scan)
    entries: list[HookEntry] = []
    for scope, path in _hook_scope_matches(target, agent_id, scan, repo_only=False):
        label = _hook_file_label(path, target)
        config = scan.hook_config(path)
        entries.extend(
            HookEntry(agent_id, site.event, site.matcher, scope, label)
            for site in hook_sites(config.data if config else None)
        )
    return entries


def _agent_declares_path_scoped(agent_id: str) -> bool:
    """True when `agent_id`'s config.yml declares any `scope: path_scoped` file type."""
    file_types = load_config_file_types(agent_id)
    if not file_types:
        return False
    return any(isinstance(ft, dict) and ft.get("scope") == "path_scoped" for ft in file_types.values())


def _agent_nested_instruction_files(target: Path, agent_id: str, scan: _SurfaceScan | None = None) -> list[Path]:
    """Real nested on-demand instruction files below `target` for `agent_id`.

    Codex and Antigravity scope instructions per directory through a nested
    on-demand instruction type (`scope: nested, loading: on_demand` —
    `nested_context`) rather than a frontmatter path-scoped rule file. That type
    is their own equivalent of Claude/Cursor/Copilot's `scope: path_scoped`
    surface, so an agent with no `path_scoped` type reads L3 from here instead —
    only counted when at least one such file genuinely exists below the project
    root (the type's own `scope: nested` glob already excludes the root file
    itself, which belongs to `main`).
    """
    scan = _scan_for(target, scan)
    file_types = load_config_file_types(agent_id)
    if not file_types:
        return []
    found: list[Path] = []
    for ft in file_types.values():
        if not isinstance(ft, dict) or ft.get("scope") != "nested" or ft.get("loading") != "on_demand":
            continue
        patterns = _surface_patterns(target, ft, scan)
        if not patterns:
            continue
        found.extend(glob_file_type_patterns(target, patterns, _extract_properties(ft), scan.exclude_dirs))
    return found


def _detect_auto_memory(target: Path) -> bool:
    """True when the user-scope auto-memory dir for this project exists."""
    auto_memory_root = Path.home() / ".claude" / "projects" / claude_project_folder_name(target) / "memory"
    if not auto_memory_root.exists():
        return False
    try:
        return any(auto_memory_root.iterdir())
    except OSError:
        return False


def _find_root_instruction(target: Path, instruction_files: list[Path]) -> Path | None:
    """Find the root-level instruction file for content analysis."""
    for f in instruction_files:
        if f.parent == target:
            return f
    return None


def _detect_content_features(root_file: Path, features: DetectedFeatures) -> None:
    """Detect content-based features from the root instruction file."""
    try:
        content = root_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    line_count = content.count("\n")
    features.is_size_controlled = line_count < _SIZE_THRESHOLD
    features.has_explicit_constraints = bool(_CONSTRAINT_RE.search(content))
    features.has_imports = bool(import_refs(content))


@functools.lru_cache(maxsize=1)
def agent_main_literal_paths() -> frozenset[str]:
    """Relative paths every agent's `main` file type pins to one fixed location.

    A `main` scope pattern with no wildcard segment (Copilot's fixed
    `.github/copilot-instructions.md`) names an exact file, not a root-vs-nested
    choice — a path-depth heuristic tuned for Claude's bare-root `CLAUDE.md`
    otherwise reads that fixed, one-directory-deep location as a nested copy.
    Derived once from the bundled `framework/rules/*/config.yml` so an agent
    whose main file lives one directory in is recognized without a second edit.
    """
    literal: set[str] = set()
    for agent_id in get_known_agents():
        file_types = load_config_file_types(agent_id) or {}
        main_spec = file_types.get("main")
        if not isinstance(main_spec, dict):
            continue
        for pattern in _extract_patterns(main_spec):
            if "*" not in pattern and not pattern.startswith("~") and not pattern.startswith("/"):
                literal.add(pattern)
    return frozenset(literal)


# Main-file names that no agent's `main` file type declares: the legacy single-file
# rule files of Cursor and Windsurf.
_LEGACY_MAIN_NAMES = frozenset((".cursorrules", ".windsurfrules"))

# Used only when the bundled configs cannot be read (a broken install).
_MAIN_NAMES_FALLBACK = frozenset(("CLAUDE.md", "AGENTS.md", "GEMINI.md", "copilot-instructions.md"))


@functools.lru_cache(maxsize=1)
def agent_main_names() -> frozenset[str]:
    """The file names every agent's `main` file type reads, wherever the file sits.

    Derived once from the bundled `framework/rules/*/config.yml` `main` scope patterns
    (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `copilot-instructions.md`, ...), so an agent whose
    main file is named differently is recognized without a second edit. Case-sensitive:
    wrong-case copies are not instruction files. User-scope (`~`) and absolute patterns sit
    outside the project and are skipped, as are names with a wildcard.
    """
    names: set[str] = set()
    for agent_id in get_known_agents():
        main_spec = (load_config_file_types(agent_id) or {}).get("main")
        if not isinstance(main_spec, dict):
            continue
        for pattern in _extract_patterns(main_spec):
            if pattern.startswith(("~", "/")) or pattern[1:2] == ":":
                continue
            name = pattern.rsplit("/", 1)[-1]
            if name and "*" not in name:
                names.add(name)
    return frozenset(names or _MAIN_NAMES_FALLBACK) | _LEGACY_MAIN_NAMES


@functools.lru_cache(maxsize=1)
def agent_rule_surface_markers() -> tuple[frozenset[str], tuple[str, ...]]:
    """Directory basenames and filename globs that mark a path-scoped rule file.

    A path-only classifier that only recognizes a literal `rules` directory with
    a `.md` file only covers Claude and Cursor's own convention — Copilot's
    path-scoped surface lives under `.github/instructions/` and Cursor's own
    rule files use the `.mdc` extension, so both would otherwise go unrecognized.
    Derived once from every agent's own `scope: path_scoped` file type in the
    bundled config, so a rule surface named or extended differently from
    Claude's is still recognized the same way.
    """
    dir_names: set[str] = set()
    filename_globs: set[str] = set()
    for agent_id in get_known_agents():
        file_types = load_config_file_types(agent_id) or {}
        for ft in file_types.values():
            if not isinstance(ft, dict) or ft.get("scope") != "path_scoped":
                continue
            for pattern in _extract_patterns(ft):
                segs = [seg for seg in str(pattern).split("/") if seg]
                dir_segs: list[str] = []
                for seg in segs:
                    if "*" in seg:
                        break
                    dir_segs.append(seg)
                if dir_segs:
                    dir_names.add(dir_segs[-1])
                if segs and "*" in segs[-1]:
                    filename_globs.add(segs[-1])
    return frozenset(dir_names), tuple(sorted(filename_globs))


def _count_components(backbone_path: Path) -> int:
    """Count components declared in backbone.yml."""
    from reporails_cli.core.platform.utils.utils import load_yaml_file, yaml_error_line

    try:
        data = load_yaml_file(backbone_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        logger.warning("Backbone %s is not read: %s", backbone_path, yaml_error_line(exc))
        return 0
    if not isinstance(data, dict):
        return 0
    components = data.get("components", {})
    return len(components) if isinstance(components, dict) else 0
