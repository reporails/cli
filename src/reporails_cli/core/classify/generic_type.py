"""Synthesizer for the `generic` file class (link-reached files)."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.classify.link_walker import LinkEdge
from reporails_cli.core.platform.dto.models import ClassifiedFile

GENERIC_TYPE_NAME = "generic"

# Source surfaces whose files load eagerly when in context. A generic
# file pointed at by any of these inherits `loading: session_start`.
_EAGER_SOURCES: frozenset[str] = frozenset({"main", "memory", "subagent_memory"})


def make_generic_classified(
    path: Path,
    edges: list[LinkEdge],
    project_root: Path | None = None,
) -> ClassifiedFile:
    """Build a `ClassifiedFile` for `path` with `link_*` properties aggregated from `edges`."""
    source_types = sorted({edge.source_type for edge in edges})
    source_paths = sorted({_rel_or_str(edge.source, project_root) for edge in edges})
    verbs = sorted({edge.verb for edge in edges})
    min_depth = min((edge.depth for edge in edges), default=0)

    loading = "session_start" if any(st in _EAGER_SOURCES for st in source_types) else "on_demand"

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
        file_type=GENERIC_TYPE_NAME,
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
