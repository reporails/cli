"""Synthesizer for the `generic` and `referenced` file classes (link-reached files).

The two classes describe different harness loading models:

- `generic` — reached via `@<path>` import in a Claude/Antigravity surface. The
  harness auto-loads the imported content alongside its parent, so the
  file is genuinely present in the agent's context budget.
- `referenced` — reached only via `[text](path)` / `[ref]: path` markdown
  link. The harness does NOT auto-load these; the agent only sees them if
  it explicitly issues a `Read` tool call. From a rule-pressure standpoint
  these files are discoverable, not loaded.

A file reached via BOTH import and link is classified `generic` — the
import path's auto-load guarantee dominates the link-only path's
discoverability.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.classify.link_walker import LinkEdge
from reporails_cli.core.platform.dto.models import ClassifiedFile

GENERIC_TYPE_NAME = "generic"
REFERENCED_TYPE_NAME = "referenced"

# Source surfaces whose files load eagerly when in context. A generic
# file pointed at by any of these inherits `loading: session_start`.
_EAGER_SOURCES: frozenset[str] = frozenset({"main", "memory", "subagent_memory"})


def make_generic_classified(
    path: Path,
    edges: list[LinkEdge],
    project_root: Path | None = None,
) -> ClassifiedFile:
    """Build a `ClassifiedFile` for `path` with `link_*` properties aggregated from `edges`.

    Routes to `file_type: generic` when any edge is an `@<path>` import
    (harness auto-loads it), `file_type: referenced` when only
    `[text](path)` markdown links reach it (discoverable, not loaded).
    """
    source_types = sorted({edge.source_type for edge in edges})
    source_paths = sorted({_rel_or_str(edge.source, project_root) for edge in edges})
    verbs = sorted({edge.verb for edge in edges})
    min_depth = min((edge.depth for edge in edges), default=0)

    is_imported = "imported" in verbs

    if is_imported:
        loading = "session_start" if any(st in _EAGER_SOURCES for st in source_types) else "on_demand"
        file_type = GENERIC_TYPE_NAME
    else:
        # Only `read` verbs reached this file — markdown-link only.
        # The harness does not auto-load; this is discoverable content.
        loading = "discoverable"
        file_type = REFERENCED_TYPE_NAME

    properties: dict[str, str | list[str]] = {
        "format": "freeform",
        "scope": "path_scoped",
        "loading": loading,
        "lifecycle": "static",
        "maintainer": "human",
        "link_source_type": source_types,
        "link_source_path": source_paths,
        "link_depth": str(min_depth),
        "loading_verb": verbs,
    }

    return ClassifiedFile(
        path=path,
        file_type=file_type,
        properties=properties,
    )


def _rel_or_str(source: Path, project_root: Path | None) -> str:
    """Project-relative POSIX string when possible, absolute POSIX otherwise."""
    if project_root is not None:
        try:
            return source.relative_to(project_root.resolve()).as_posix()
        except ValueError:
            pass
    return source.as_posix()
