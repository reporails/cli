"""Hatch build hook to bundle framework content, excluding test fixtures."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# Framework content to bundle into the wheel.
# Source paths are relative to repo root; destinations are inside the wheel.
FRAMEWORK_INCLUDES = {
    "framework/rules": "reporails_cli/rules",
    "framework/registry/levels.yml": "reporails_cli/registry/levels.yml",
    "framework/sources.yml": "reporails_cli/sources.yml",
}

# Directory names to skip when bundling (rule test fixtures are dev-only)
SKIP_DIRS = {"tests"}


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        root = Path(self.root)
        force_include = build_data["force_include"]

        for src_rel, dest_rel in FRAMEWORK_INCLUDES.items():
            src = root / src_rel
            if src.is_file():
                force_include[str(src)] = dest_rel
            elif src.is_dir():
                for path in src.rglob("*"):
                    if path.is_file() and not _in_skip_dir(path, src):
                        rel = path.relative_to(src)
                        force_include[str(path)] = f"{dest_rel}/{rel}"

        # Remove the pyproject.toml force-include entries (they'd double-include)
        # — handled by clearing them from config before this hook, or by
        #   removing them from pyproject.toml entirely.


def _in_skip_dir(path: Path, base: Path) -> bool:
    """Check if any parent directory between base and path is in SKIP_DIRS."""
    rel = path.relative_to(base)
    return any(part in SKIP_DIRS for part in rel.parts)
