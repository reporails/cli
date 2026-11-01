"""The excluded-folder record."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from reporails_cli.core.platform.contract.glob_pattern import escape_glob, glob_matches


@dataclass(frozen=True)
class FolderValue:
    """One excluded folder: a name matched at any depth, or a path anchored at the project root."""

    parts: tuple[str, ...]
    anchored: bool = False

    def __post_init__(self) -> None:
        if not self.parts or not all(self.parts):
            raise ValueError("a folder value holds at least one part, and no part is empty")
        if not self.anchored and len(self.parts) > 1:
            raise ValueError("a folder name holds one part; a folder path is anchored")

    @cached_property
    def glob(self) -> str:
        """The folder as a glob that matches only that folder: any depth for a name, from the root for a path."""
        if not self.anchored:
            return "**/" + escape_glob(self.parts[0])
        return "/".join(escape_glob(part) for part in self.parts)

    def holds(self, rel: str) -> bool:
        """True when the root-relative posix path `rel` is this folder or lies under it."""
        if not rel:
            return False
        return glob_matches(rel, self.glob, anchored=True, prefix=True)

    @property
    def text(self) -> str:
        """The folder as reported: `docs`, `pkg/docs`, or `./docs` for a single anchored folder."""
        if not self.anchored:
            return self.parts[0]
        joined = "/".join(self.parts)
        return joined if len(self.parts) > 1 else "./" + joined
