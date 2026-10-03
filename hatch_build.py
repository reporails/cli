"""Hatch build hook to bundle framework content, excluding test fixtures.

The wheel is lean: it carries code + rules + small data files, but NOT the ML
model set. End users fetch the model once, on first use, into the persistent
user cache (see ``src/reporails_cli/core/mapper/model_fetch.py``), so the wheel
stays small for `pip`/`npx` and the model version decouples from the CLI version.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# Framework content to bundle into the wheel.
# Source paths are relative to repo root; destinations are inside the wheel.
FRAMEWORK_INCLUDES = {
    "framework/rules": "reporails_cli/rules",
    "framework/sources.yml": "reporails_cli/sources.yml",
    # Consumed at runtime by the capability-gating rule filter.
    "framework/capabilities_matrix.yml": "reporails_cli/capabilities_matrix.yml",
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


def _in_skip_dir(path: Path, base: Path) -> bool:
    """Check if any parent directory between base and path is in SKIP_DIRS."""
    rel = path.relative_to(base)
    return any(part in SKIP_DIRS for part in rel.parts)
