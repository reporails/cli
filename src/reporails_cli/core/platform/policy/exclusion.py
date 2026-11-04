"""Which folders a folder exclusion leaves out: a folder name, or a folder path from the project root."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import PurePath

from reporails_cli.core.platform.dto.exclusion import FolderValue

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
