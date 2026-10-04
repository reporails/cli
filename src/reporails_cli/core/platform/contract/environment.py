"""The reads of the machine and the project a rewrite check needs, as a typed contract.

A check holds its decisions; what lives on disk or in the environment is asked through this
contract, and an adapter answers it.
"""

from __future__ import annotations

from typing import Protocol


class ProjectEnvironment(Protocol):
    """What the machine and the project can confirm about a name a rewrite uses."""

    def path_exists(self, candidate: str) -> bool:
        """Whether `candidate` is an existing path: `~`-expanded, else under the project root or
        the file's own directory."""
        ...

    def on_path(self, program: str) -> bool:
        """Whether `program` is an executable on the machine's `PATH`."""
        ...

    def manifest_text(self) -> str:
        """The project's own manifests and CI workflow files, concatenated."""
        ...
