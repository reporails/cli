"""Agent file discovery — config-driven file globbing and path matching.

Extracted from agents.py to keep that module under the 600-line limit.
All functions here are internal to the agent subsystem.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Directories that never contain instruction files — skipped unconditionally.
# Project-specific exclusions come from .ails/config.yml exclude_dirs.
_ALWAYS_SKIP = frozenset({".git", "__pycache__", "node_modules"})


def ci_glob(target: Path, pattern: str) -> list[Path]:
    """Case-insensitive glob for root-level filenames, standard glob for nested."""
    parts = Path(pattern).parts
    if len(parts) == 1 and "*" not in pattern:
        # Root-level exact filename — match case-insensitively
        lower = pattern.lower()
        try:
            return [p for p in target.iterdir() if p.name.lower() == lower and not p.is_dir()]
        except OSError:
            return []
    return list(target.glob(pattern))


def categorize_file_type(patterns: list[str], properties: dict[str, str]) -> str:
    """Categorize a file_type entry as instruction/rule/config/skip.

    Uses file_type properties from config.yml:
    - format: schema_validated -> config
    - scope: path_scoped -> rule (scoped rule files)
    - directory-only or system paths -> skip
    - everything else -> instruction
    """
    # Skip directory-only patterns (e.g., ".claude/memory/")
    if all(p.endswith("/") for p in patterns):
        return "skip"
    # Skip absolute system paths (managed configs)
    if all(p.startswith(("/", "C:")) for p in patterns):
        return "skip"
    # Schema-validated files -> config bucket
    if properties.get("format") == "schema_validated":
        return "config"
    # Path-scoped markdown -> rule files bucket
    if properties.get("scope") == "path_scoped":
        return "rule"
    # Everything else (main, skill, override) -> instruction bucket
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
    """Walk directory tree matching a filename, skipping excluded dirs.

    Much faster than Path.glob("**/name") because it prunes excluded
    subtrees during traversal instead of filtering afterwards.
    Uses os.scandir for efficient directory traversal.
    """
    skip = exclude_dirs | _ALWAYS_SKIP
    lower_name = filename.lower()
    results: list[Path] = []
    stack = [str(root)]
    while stack:
        current = stack.pop()
        try:
            scanner = os.scandir(current)
        except OSError:
            continue
        with scanner:
            for entry in scanner:
                name = entry.name
                if name.lower() == lower_name:
                    try:
                        is_match = entry.is_file(follow_symlinks=True)
                    except OSError:
                        # Broken/circular symlink — include it so downstream
                        # code can report the error properly
                        is_match = entry.is_symlink()
                    if is_match:
                        results.append(Path(entry.path))
                elif entry.is_dir(follow_symlinks=False) and name not in skip:
                    stack.append(entry.path)
    return results


def glob_file_type_patterns(
    target: Path,
    patterns: list[str],
    exclude_dirs: frozenset[str] = frozenset(),
) -> list[Path]:
    """Glob file_type patterns against target directory.

    For recursive (**/) patterns with a literal filename (e.g., **/CLAUDE.md),
    uses pruning walk to avoid traversing excluded directory trees.
    Falls back to Path.glob for wildcard filenames (e.g., **/*.md).

    External paths (~/... and /absolute/...) are resolved outside the project
    directory. These are part of the instruction surface (user-level config,
    managed policies, auto-memory) even though they live outside the repo.
    """
    found: list[Path] = []
    for pattern in patterns:
        # Skip directory-only patterns
        if pattern.endswith("/"):
            continue

        # External paths: ~/... or /absolute/... or C:/...
        if pattern.startswith("~") or pattern.startswith("/") or (len(pattern) > 1 and pattern[1] == ":"):
            _glob_external(pattern, target, found)
            continue

        parts = Path(pattern).parts
        filename = parts[-1] if parts else ""

        # Use pruning walk only for recursive patterns with literal filenames
        if "**" in pattern and "*" not in filename:
            # Extract prefix before ** (e.g., ".claude/skills/**/SKILL.md" -> ".claude/skills")
            prefix_parts = []
            for p in parts:
                if "**" in p:
                    break
                prefix_parts.append(p)
            walk_root = target / Path(*prefix_parts) if prefix_parts else target
            if walk_root.is_dir():
                found.extend(
                    m for m in walk_glob(walk_root, filename, exclude_dirs) if not is_excluded(m, target, exclude_dirs)
                )
        else:
            # Non-recursive or wildcard filename — use standard glob
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


def load_config_file_types(
    agent_id: str,
    rules_paths: list[Path] | None = None,
) -> dict[str, Any] | None:
    """Load file_types section from agent config.yml.

    Searches rules_paths first, then falls back to the default config path.
    Returns the file_types dict or None if not found.
    """

    from reporails_cli.core.bootstrap import get_agent_config_path

    candidates: list[Path] = []
    if rules_paths:
        candidates.extend(rp / agent_id / "config.yml" for rp in rules_paths)
    candidates.append(get_agent_config_path(agent_id))

    for path in candidates:
        if not path.exists():
            continue
        try:
            from reporails_cli.core.utils import load_yaml_file

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


def discover_from_config(
    target: Path,
    agent_id: str,
    rules_paths: list[Path] | None = None,
    extra_exclude_dirs: frozenset[str] = frozenset(),
) -> tuple[list[Path], list[Path], list[Path]] | None:
    """Discover files using config.yml file_types.

    Returns (instruction_files, rule_files, config_files) or None if
    no config.yml is available for this agent.
    """
    from reporails_cli.core.agents import _extract_patterns, _extract_properties

    file_types = load_config_file_types(agent_id, rules_paths)
    if file_types is None:
        return None

    instruction_files: list[Path] = []
    rule_files: list[Path] = []
    config_files: list[Path] = []

    for spec in file_types.values():
        if not isinstance(spec, dict):
            continue
        patterns = _extract_patterns(spec)
        properties = _extract_properties(spec)

        bucket = categorize_file_type(patterns, properties)
        if bucket == "skip":
            continue

        found = glob_file_type_patterns(target, patterns, extra_exclude_dirs)

        if bucket == "instruction":
            instruction_files.extend(found)
        elif bucket == "rule":
            rule_files.extend(found)
        elif bucket == "config":
            config_files.extend(found)

    return (
        sorted(set(instruction_files)),
        sorted(set(rule_files)),
        sorted(set(config_files)),
    )
