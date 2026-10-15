"""Agent surface markers read from the bundled agent configs.

The file names, fixed paths, directory names and filename globs that mark an agent's main
instruction file or path-scoped rule file, for path-only classifiers that hold no project scan.
"""

from __future__ import annotations

import functools

from reporails_cli.core.discovery.agent_config import extract_patterns, load_config_file_types
from reporails_cli.core.discovery.agents import get_known_agents
from reporails_cli.core.platform.config.capabilities import legacy_main_files
from reporails_cli.core.platform.contract.errors import BundledConfigMissingError
from reporails_cli.core.platform.utils.utils import is_rooted_pattern


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
        for pattern in extract_patterns(main_spec):
            if "*" not in pattern and not pattern.startswith("~") and not pattern.startswith("/"):
                literal.add(pattern)
    return frozenset(literal)


@functools.lru_cache(maxsize=1)
def agent_main_names() -> frozenset[str]:
    """The file names every agent's `main` file type reads, wherever the file sits.

    Derived once from the bundled `framework/rules/*/config.yml` scope patterns of each `main`
    file type and of each `deprecated` single-file type (`.cursorrules`), plus the root files
    the capability matrix lists for cataloged agents (`.windsurfrules`), e.g. `CLAUDE.md`,
    `AGENTS.md`, `GEMINI.md`, `copilot-instructions.md`, so an agent whose main file is named
    differently is recognized without a second edit. Case-sensitive: wrong-case copies are not
    instruction files. User-scope (`~`) and absolute patterns sit outside the project and are
    skipped, as are names with a wildcard. Raises `BundledConfigMissingError` when no bundled
    config declares a main file.
    """
    names: set[str] = set()
    for agent_id in get_known_agents():
        for ft_name, spec in (load_config_file_types(agent_id) or {}).items():
            if not isinstance(spec, dict) or not (ft_name == "main" or spec.get("deprecated") is True):
                continue
            for pattern in extract_patterns(spec):
                if is_rooted_pattern(pattern):
                    continue
                name = pattern.rsplit("/", 1)[-1]
                if name and "*" not in name:
                    names.add(name)
    for file_names in legacy_main_files().values():
        names |= file_names
    if not names:
        raise BundledConfigMissingError("no bundled agent config declares a main instruction file")
    return frozenset(names)


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
            for pattern in extract_patterns(ft):
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
