"""Agent config.yml reading — the `file_types` section and the bundled agent configs.

One owner for how an agent's config is located, read and interpreted: which patterns and
properties a file type declares, which discovery bucket it falls in, and how the bundled
`framework/rules/*/config.yml` files are walked.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.discovery import plugin_roots
from reporails_cli.core.platform.config.bundled import get_bundled_rules_path
from reporails_cli.core.platform.config.config import get_agent_config_path
from reporails_cli.core.platform.utils.utils import load_yaml_file

logger = logging.getLogger(__name__)


def extract_patterns(spec: dict[str, Any], key: str = "patterns") -> list[str]:
    """Extract all file patterns from a file type spec (`key` names the pattern list: `patterns`, or
    `entry_patterns` for where an instance's entry file sits).

    Supports both v0.3.0 (patterns at top level) and v0.5.0 (patterns
    inside scopes). Returns a flat list of all patterns across all scopes; a `plugin`
    scope's patterns come back as `<marker>/pattern` (see `plugin_roots`).
    """
    # v0.3.0: patterns at top level
    patterns = spec.get(key, [])
    if isinstance(patterns, str):
        patterns = [patterns]
    if patterns:
        return list(patterns)

    # v0.5.0: patterns inside scopes
    scopes = spec.get("scopes", {})
    if not isinstance(scopes, dict):
        return []
    all_patterns: list[str] = []
    for scope_name, scope_spec in scopes.items():
        if not isinstance(scope_spec, dict):
            continue
        if scope_name == plugin_roots.PLUGIN_SCOPE:
            all_patterns.extend(plugin_roots.plugin_scope_patterns(scope_spec, key))
            continue
        scope_patterns = scope_spec.get(key, [])
        if isinstance(scope_patterns, str):
            scope_patterns = [scope_patterns]
        all_patterns.extend(scope_patterns)
    return all_patterns


def extract_properties(spec: dict[str, Any]) -> dict[str, Any]:
    """Extract properties from a file type spec.

    Supports both v0.3.0 (properties nested) and v0.5.0 (flattened).
    """
    # v0.3.0: properties in a nested dict
    props = spec.get("properties")
    if isinstance(props, dict):
        return props

    # v0.5.0: properties flattened at file type level
    prop_keys = {"format", "scope", "cardinality", "lifecycle", "maintainer", "vcs", "loading", "precedence"}
    return {k: v for k, v in spec.items() if k in prop_keys and v is not None}


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


def iter_agent_configs(rules_dir: Path) -> Iterator[dict[str, Any]]:
    """Each readable `*/config.yml` under `rules_dir`, in path order, as its parsed mapping.

    A config that cannot be read, or that is empty or not a mapping, is logged and skipped.
    """
    for config_path in sorted(rules_dir.glob("*/config.yml")):
        try:
            data = load_yaml_file(config_path)
        except (OSError, ValueError, yaml.YAMLError) as exc:  # unreadable or non-YAML agent config
            logger.warning("Skipping agent config %s: %s", config_path, exc)
            continue
        if not data or not isinstance(data, dict):
            logger.warning("Agent config is empty or malformed: %s — agent skipped", config_path)
            continue
        yield data


def bundled_file_types() -> Iterator[dict[str, Any]]:
    """The `file_types` mapping of every bundled agent config that declares one."""
    rules_dir = get_bundled_rules_path()
    if rules_dir is None:
        return
    for data in iter_agent_configs(rules_dir):
        file_types = data.get("file_types")
        if isinstance(file_types, dict):
            yield file_types


def load_config_file_types(
    agent_id: str,
    rules_paths: list[Path] | None = None,
) -> dict[str, Any] | None:
    """Load file_types section from agent config.yml.

    Searches rules_paths first, then falls back to the default config path.
    Returns the file_types dict or None if not found.
    """
    candidates: list[Path] = []
    if rules_paths:
        candidates.extend(rp / agent_id / "config.yml" for rp in rules_paths)
    candidates.append(get_agent_config_path(agent_id))

    for path in candidates:
        if not path.exists():
            continue
        try:
            data = load_yaml_file(path)
        except (OSError, ValueError, yaml.YAMLError) as exc:  # agent config parsing; skip broken configs
            logger.warning("Failed to parse agent file_types %s: %s", path, exc)
            continue
        if not data or not isinstance(data, dict):
            logger.warning("Agent config is empty: %s", path)
            continue
        file_types = data.get("file_types")
        if file_types and isinstance(file_types, dict):
            return dict(file_types)
    return None
