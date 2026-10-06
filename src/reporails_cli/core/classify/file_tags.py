"""Path-based file-type tagging — the single source for `path -> surface tag`.

Distinct from `classify_files` (config-driven, returns `ClassifiedFile` with a resolved
`file_type`): this is the lightweight path-shape classifier used where only the path is in
hand — the formatter's surface grouping and the lint suppressor's surface resolution both call
`classify_file`, so the structural-directory precedence lives in ONE place and cannot drift
between them.
"""

from __future__ import annotations

import functools
import logging
from pathlib import Path, PurePosixPath

import yaml

from reporails_cli.core.discovery.features import agent_main_names
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.utils.utils import glob_matches

logger = logging.getLogger(__name__)

_CONFIG_NAMES = frozenset(("settings.json", ".mcp.json", "config.yml", "settings.local.json"))

# The config `file_type` property that marks a machine-config surface: these files
# carry no authored prose, so the prose-quality rules declare
# `surface_mutations: {config: {applies: false}}` and the `config` tag is what
# routes them there. The surfaces themselves are derived from the bundled agent
# configs — see `_config_surface_patterns`.
_SCHEMA_VALIDATED = "schema_validated"

# Fallback used only when the bundled configs cannot be read (a broken install —
# the configs ship in the wheel). A suffix guess, which is what the derivation
# replaces: it covers the JSON/TOML surfaces but misses the declared ones that are
# neither (`.codex/rules/*.rules`, `**/agents/openai.yaml`, `.gemini/extensions/**`).
_CONFIG_SUFFIXES_FALLBACK = frozenset((".json", ".toml"))
# The config `file_types` whose contents are agent-maintained memory surfaces
# (an index `MEMORY.md` plus recalled sibling entries, not authored instruction
# prose). Their directory names are derived from config, never hardcoded here —
# see `_memory_surface_dirs`.
_MEMORY_SURFACE_FILE_TYPES = frozenset(("memory", "subagent_memory"))

# Fallback used only when the bundled configs cannot be read (a broken install —
# the configs ship in the wheel). Mirrors the live config so the memory surface
# never silently regresses to `file`; kept in lockstep by the drift-guard test
# `test_memory_surface_dirs_match_config`.
_MEMORY_SURFACE_DIRS_FALLBACK = frozenset(("memory", "agent-memory", "agent-memory-local"))


def _dir_name_from_pattern(pattern: str) -> str | None:
    """Return the terminal literal directory segment of a directory-glob pattern.

    `~/.claude/projects/*/memory/` -> `memory`; `.claude/agent-memory-local/*/`
    -> `agent-memory-local`. Returns None for a non-directory pattern (no trailing
    `/`) or one with no literal segment.
    """
    if not pattern.endswith("/"):
        return None
    literals = [seg for seg in pattern.strip("/").split("/") if seg and seg not in ("*", "**", "~")]
    return literals[-1] if literals else None


@functools.lru_cache(maxsize=1)
def _memory_surface_dirs() -> frozenset[str]:
    """Return the set of directory names that mark a memory surface.

    Derived once from the bundled `framework/rules/*/config.yml` `memory` +
    `subagent_memory` file_type scope patterns, so a memory scope added to config
    is recognized here without a second edit and every declared scope is covered.
    Falls back to `_MEMORY_SURFACE_DIRS_FALLBACK` when the bundled configs are
    unreadable.
    """
    from reporails_cli.core.platform.config.bundled import get_bundled_rules_path
    from reporails_cli.core.platform.utils.utils import load_yaml_file

    rules_dir = get_bundled_rules_path()
    if rules_dir is None:
        return _MEMORY_SURFACE_DIRS_FALLBACK

    names: set[str] = set()
    for config_path in sorted(rules_dir.glob("*/config.yml")):
        try:
            data = load_yaml_file(config_path)
        except (OSError, ValueError, yaml.YAMLError) as exc:  # unreadable or non-YAML agent config
            logger.warning("Skipping agent config %s: %s", config_path, exc)
            continue
        file_types = (data or {}).get("file_types") or {}
        if not isinstance(file_types, dict):
            continue
        for ft_name, ft in file_types.items():
            if ft_name not in _MEMORY_SURFACE_FILE_TYPES or not isinstance(ft, dict):
                continue
            for scope in (ft.get("scopes") or {}).values():
                for pattern in (scope or {}).get("patterns", []) or []:
                    name = _dir_name_from_pattern(str(pattern))
                    if name:
                        names.add(name)
    return frozenset(names) or _MEMORY_SURFACE_DIRS_FALLBACK


@functools.lru_cache(maxsize=1)
def _config_surface_patterns() -> tuple[str, ...]:
    """Lowercased glob patterns for every declared machine-config surface.

    Derived once from the bundled `framework/rules/*/config.yml`: every file_type
    whose `format` is `schema_validated`, over all of its scope patterns. Same shape
    as `_memory_surface_dirs` — config is the source, so a surface added there is
    recognized here without a second edit.

    A suffix guess (`.json` / `.toml`) cannot stand in for this: the shipped set
    includes `.codex/rules/*.rules`, `**/agents/openai.yaml` and
    `.gemini/extensions/**`, which a suffix test tags as prose and so leaves the
    prose-quality rules firing on machine config. Patterns are lowercased, with the
    home and any-depth prefixes dropped, for `_matches_config_surface`. Empty on an unreadable
    install, which sends `_classify_by_name` to the suffix fallback.
    """
    from reporails_cli.core.platform.config.bundled import get_bundled_rules_path
    from reporails_cli.core.platform.utils.utils import load_yaml_file

    rules_dir = get_bundled_rules_path()
    if rules_dir is None:
        return ()

    patterns: set[str] = set()
    for config_path in sorted(rules_dir.glob("*/config.yml")):
        try:
            data = load_yaml_file(config_path)
        except (OSError, ValueError, yaml.YAMLError) as exc:  # unreadable or non-YAML agent config
            logger.warning("Skipping agent config %s: %s", config_path, exc)
            continue
        file_types = (data or {}).get("file_types") or {}
        if not isinstance(file_types, dict):
            continue
        for ft in file_types.values():
            if not isinstance(ft, dict) or ft.get("format") != _SCHEMA_VALIDATED:
                continue
            for scope in (ft.get("scopes") or {}).values():
                for pattern in (scope or {}).get("patterns", []) or []:
                    segs = tuple(
                        seg for seg in str(pattern).strip("/").lower().split("/") if seg and seg not in ("~", "**")
                    ) + (("**",) if str(pattern).rstrip("/").endswith("**") else ())
                    if segs and segs != ("**",):
                        patterns.add("/".join(segs))
    return tuple(sorted(patterns))


def _matches_config_surface(path: str) -> bool:
    """True when the lowercased posix path matches a declared machine-config surface pattern.

    The patterns are project-root-relative while the caller holds a path of unknown anchoring
    (project-relative from the formatter, absolute from discovery), so each pattern matches the
    path's trailing segments. A pattern ending in `**` (a whole config directory, e.g.
    `.gemini/extensions/**`) matches any file inside that directory.
    """
    return any(glob_matches(path, pattern) for pattern in _config_surface_patterns())


def classify_file(filepath: str, root: Path | None = None) -> str:
    """Classify a file path into a surface tag: a config file-type key (`main`, `memory`,
    `skills:<dir>`, `agents:<stem>`, `rules:<stem>`) or a display grouping (`nested`, `config`,
    `file`).

    When ``root`` is given, the main-vs-nested decision compares the file's parent
    against that scan root, so a top-level instruction file classifies as ``main``
    for an ABSOLUTE path too. With ``root`` omitted the legacy path-part heuristic
    (root file has <= 1 parts) applies, which only holds for relative paths.
    """
    p = Path(filepath)
    name = p.name
    parts = p.parts

    # Check structural directories first
    if "skills" in parts and name == "SKILL.md":
        idx = parts.index("skills")
        return f"skills:{parts[idx + 1]}" if idx + 1 < len(parts) - 1 else "skills"
    if "agents" in parts and name.endswith(".md"):
        return f"agents:{p.stem}"
    if "rules" in parts and name.endswith(".md"):
        return f"rules:{p.stem}"

    # Check name-based and directory-based categories
    tag = _classify_by_name(name, parts, p, root)
    return tag if tag else "file"


def _classify_by_name(name: str, parts: tuple[str, ...], p: Path | None = None, root: Path | None = None) -> str:
    """Classify by filename or directory membership. Returns empty string if unrecognized."""
    if name in _CONFIG_NAMES:
        return "config"
    if _memory_surface_dirs() & set(parts):
        return "memory"
    # A declared machine-config surface wins over a main-file name inside it.
    if _matches_config_surface(PurePosixPath(*parts).as_posix().lower()) or (
        not _config_surface_patterns() and p is not None and p.suffix.lower() in _CONFIG_SUFFIXES_FALLBACK
    ):
        return "config"
    # Case-sensitive — matches discovery (walk_glob) and agent specs.
    # Wrong-case copies (e.g. `agents.md` lowercase) are not instruction files.
    if name in agent_main_names():
        # Files at the project root are `main`; subdirectory copies of the
        # same filename are `nested` (per scope: nested in agent.schema.yml).
        # With a scan `root`, compare parents directly so an ABSOLUTE path
        # (what discovery actually yields) classifies correctly; without it,
        # fall back to the path-part heuristic (a relative `tests/CLAUDE.md`
        # has length 2, a root-level `CLAUDE.md` length 1).
        if root is not None and p is not None:
            try:
                return "main" if safe_resolve(p).parent == safe_resolve(root) else "nested"
            except OSError:
                pass
        return "main" if len(parts) <= 1 else "nested"
    return ""
