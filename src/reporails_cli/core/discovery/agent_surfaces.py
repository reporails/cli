"""Agent surface markers read from the bundled agent configs.

The file names, fixed paths, directory names and filename globs that mark an agent's main
instruction file or path-scoped rule file, for path-only classifiers that hold no project scan.
"""

from __future__ import annotations

import functools

from reporails_cli.core.discovery.agent_config import extract_patterns, load_config_file_types
from reporails_cli.core.discovery.agents import get_known_agents


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
        for pattern in extract_patterns(main_spec):
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
