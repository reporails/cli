"""Agent config.yml reading — the `file_types` section and the bundled agent configs.

One owner for how an agent's config is located, read and interpreted: which patterns and
properties a file type declares, which discovery bucket it falls in, and how the bundled
`framework/rules/*/config.yml` files are walked.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Literal

from reporails_cli.core.discovery import plugin_roots
from reporails_cli.core.platform.config.bundled import get_bundled_rules_path
from reporails_cli.core.platform.config.config import get_agent_config_path, iter_agent_configs, read_agent_config
from reporails_cli.core.platform.contract.json_value import JsonObject, pattern_list
from reporails_cli.core.platform.policy.matching import DECLARED_PROPERTIES
from reporails_cli.core.platform.utils.utils import is_rooted_pattern

# The discovery bucket a file type's files are collected into.
SurfaceBucket = Literal["instruction", "rule", "config"]
SURFACE_BUCKETS: tuple[SurfaceBucket, ...] = ("instruction", "rule", "config")


def extract_patterns(spec: JsonObject, key: str = "patterns") -> list[str]:
    """Extract all file patterns from a file type spec (`key` names the pattern list: `patterns`, or
    `entry_patterns` for where an instance's entry file sits).

    Supports both v0.3.0 (patterns at top level) and v0.5.0 (patterns
    inside scopes). Returns a flat list of all patterns across all scopes; a `plugin`
    scope's patterns come back as `<marker>/pattern` (see `plugin_roots`).
    """
    # v0.3.0: patterns at top level
    patterns = pattern_list(spec.get(key, []))
    if patterns:
        return patterns

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
        all_patterns.extend(pattern_list(scope_spec.get(key, [])))
    return all_patterns


def extract_properties(spec: JsonObject) -> dict[str, str | list[str]]:
    """Extract properties from a file type spec as text, a multi-valued property as a list of text.

    Supports both v0.3.0 (properties nested) and v0.5.0 (flattened). A property set to null is left out.
    """
    # v0.3.0: properties in a nested dict
    props = spec.get("properties")
    declared = props if isinstance(props, dict) else {k: v for k, v in spec.items() if k in DECLARED_PROPERTIES}
    result: dict[str, str | list[str]] = {}
    for key, value in declared.items():
        if value is None:
            continue
        result[key] = [str(item) for item in value] if isinstance(value, list) else str(value)
    return result


def categorize_file_type(
    patterns: list[str], properties: Mapping[str, str | list[str]]
) -> SurfaceBucket | Literal["skip"]:
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
    if all(is_rooted_pattern(p) and not p.startswith("~") for p in patterns):
        return "skip"
    # Schema-validated files -> config bucket
    if properties.get("format") == "schema_validated":
        return "config"
    # Path-scoped markdown -> rule files bucket
    if properties.get("scope") == "path_scoped":
        return "rule"
    # Everything else (main, skill, override, memory/subagent_memory) -> instruction
    return "instruction"


def bundled_file_types() -> Iterator[JsonObject]:
    """The `file_types` mapping of every bundled agent config that declares one."""
    rules_dir = get_bundled_rules_path()
    if rules_dir is None:
        return
    for _, data in iter_agent_configs(rules_dir):
        file_types = data.get("file_types")
        if isinstance(file_types, dict):
            yield file_types


def load_config_file_types(
    agent_id: str,
    rules_paths: list[Path] | None = None,
) -> JsonObject | None:
    """Load file_types section from agent config.yml.

    Searches rules_paths first, then falls back to the default config path.
    Returns the file_types dict or None if not found.
    """
    candidates: list[Path] = []
    if rules_paths:
        candidates.extend(rp / agent_id / "config.yml" for rp in rules_paths)
    candidates.append(get_agent_config_path(agent_id))

    for path in candidates:
        data = read_agent_config(path)
        if data is None:
            continue
        file_types = data.get("file_types")
        if file_types and isinstance(file_types, dict):
            return dict(file_types)
    return None
