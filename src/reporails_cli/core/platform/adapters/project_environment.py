"""Disk and environment reads for the rewrite check: existing paths, programs on `PATH`, and the
project's manifests. Implements `contract.environment.ProjectEnvironment`.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

_MANIFESTS = (
    "pyproject.toml",
    "package.json",
    "Makefile",
    "justfile",
    "Taskfile.yml",
    "Cargo.toml",
    "go.mod",
    "setup.cfg",
    "tox.ini",
)

_MANIFEST_MAX_BYTES = 200_000


class LocalProjectEnvironment:
    """The local machine as seen from one project root and one file's directory."""

    def __init__(self, scan_root: Path | None, file_dir: Path | None = None) -> None:
        self._bases = tuple(b for b in (scan_root, file_dir) if b is not None)
        self._scan_root = scan_root
        self._manifests: str | None = None

    def path_exists(self, candidate: str) -> bool:
        if candidate.startswith("~"):
            return os.path.exists(os.path.expanduser(candidate))
        return any(os.path.exists(base / candidate) for base in self._bases)

    def on_path(self, program: str) -> bool:
        return shutil.which(program) is not None

    def manifest_text(self) -> str:
        if self._manifests is None:
            self._manifests = self._read_manifests()
        return self._manifests

    def _read_manifests(self) -> str:
        if self._scan_root is None:
            return ""
        paths = [self._scan_root / name for name in _MANIFESTS]
        paths += sorted((self._scan_root / ".github" / "workflows").glob("*.y*ml"))
        parts: list[str] = []
        for path in paths:
            try:
                if path.is_file() and path.stat().st_size <= _MANIFEST_MAX_BYTES:
                    parts.append(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
        return "\n".join(parts)
