"""The records a cache sweep holds."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SweepUnit:
    """The files of one sweep unit: the newest modification time among them, their total size and their paths."""

    mtime: float = 0.0
    size: int = 0
    files: list[Path] = field(default_factory=list)
