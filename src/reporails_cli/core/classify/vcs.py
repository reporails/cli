"""Where a file sits decides its `vcs` when its file type declares none."""

from __future__ import annotations

from pathlib import Path


def default_vcs(path: Path, project_root: Path) -> str:
    """`committed` for a file under the project root, `external` for one outside it (the user home folder included)."""
    if path.is_relative_to(project_root) or path.is_relative_to(project_root.resolve()):
        return "committed"
    return "external"


def with_default_vcs(
    properties: dict[str, str | list[str]], path: Path, project_root: Path
) -> dict[str, str | list[str]]:
    """`properties` with `vcs` set from where `path` sits when none is declared."""
    if "vcs" in properties:
        return properties
    return {**properties, "vcs": default_vcs(path, project_root)}
