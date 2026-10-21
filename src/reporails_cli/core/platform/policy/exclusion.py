"""Which folders a folder exclusion leaves out: a folder name, or a folder path from the project root."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import cached_property
from pathlib import PurePath

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


_REFUSED_CHARS = (("*", "it holds '*'"), ("?", "it holds '?'"), ("\\", "it holds a backslash"))


def folder_value_problem(value: str) -> str | None:
    """Why `value` is not a folder name or a folder path, or `None` when it is one."""
    value = value.strip()
    reason = next((why for char, why in _REFUSED_CHARS if char in value), None)
    if reason is None and ".." in value.split("/"):
        reason = "it steps up with '..'"
    if reason is None:
        return None
    return f"'{value}' is not a folder name or a folder path: {reason}"


def parse_folder_value(value: str, roots: Sequence[PurePath]) -> FolderValue | None:
    """The folder `value` names, or `None` when it names no folder (empty, `/`, `.`, the root itself).

    A value that is, or starts with, one of `roots` is read as the path below that root. A leading
    `./` or `/`, or a `/` before the last character, makes the value a path from the root; a
    trailing `/` is ignored. Raises `ValueError` for a value `folder_value_problem` refuses.
    """
    value = value.strip()
    problem = folder_value_problem(value)
    if problem is not None:
        raise ValueError(problem)
    anchored = value.startswith(("./", "/")) or "/" in value.rstrip("/")
    for root in roots:
        prefix = root.as_posix().rstrip("/")
        if value == prefix or value.startswith(prefix + "/"):
            value, anchored = value[len(prefix) :], True
            break
    parts = tuple(p for p in value.split("/") if p and p != ".")
    return FolderValue(parts, anchored) if parts else None


def first_folder_value_problem(values: Iterable[object]) -> str | None:
    """The `folder_value_problem` text of the first text item in `values` that is refused, or `None`."""
    for item in values:
        problem = folder_value_problem(item) if isinstance(item, str) else None
        if problem is not None:
            return problem
    return None
