"""Synthesizer for the `generic` file class — link-reached files (REQ-025 Phase C).

The `generic` class is not declared in any agent config (it's not
agent-specific). When `generic_scanning: true` is set, the classifier
walks Markdown links from already-classified files and assigns `generic`
to the reached `.md` files. This module supplies the synthetic
`FileTypeDeclaration` and the `ClassifiedFile` constructor for those
hits.

`loading: on_demand` is the load mode: linked files are not always-in-context
(link presence does not imply the agent eagerly loads them), so they
default out of `base` cross-file analysis. Operators that want a linked
file treated as base context can override per-project.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.platform.dto.models import ClassifiedFile

GENERIC_TYPE_NAME = "generic"


def make_generic_classified(path: Path) -> ClassifiedFile:
    """Return a `ClassifiedFile` with `file_type: generic` and on-demand loading."""
    return ClassifiedFile(
        path=path,
        file_type=GENERIC_TYPE_NAME,
        properties={
            "format": "freeform",
            "scope": "path_scoped",
            "loading": "on_demand",
            "lifecycle": "static",
            "maintainer": "human",
        },
    )
