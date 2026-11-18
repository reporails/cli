"""Starting a program detached from the caller, as a typed contract."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol


class Launcher(Protocol):  # pylint: disable=too-few-public-methods  # a port that is called, not a class with methods
    """Starts a command as a detached child."""

    def __call__(self, cmd: list[str], *, cwd: Path | None) -> int:
        """Start `cmd` in `cwd` detached from the caller's streams; the child's pid."""
