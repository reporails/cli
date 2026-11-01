"""A file's leading frontmatter block, what it holds and why it cannot be read."""

from __future__ import annotations

from typing import NamedTuple

from reporails_cli.core.platform.contract.json_value import JsonObject


class FrontmatterBlock(NamedTuple):
    """Where a file's leading frontmatter block is: its YAML text and the lines it occupies."""

    text: str  # the YAML between the two delimiter lines
    first_line: int  # 1-based file line of `text`'s first line
    body_line: int  # 0-based index of the first line after the closing delimiter


class FrontmatterProblem(NamedTuple):
    """Why a frontmatter block cannot be read: the 1-based file line of the problem and one line of text."""

    line: int
    message: str


class Frontmatter(NamedTuple):
    """What a file's leading frontmatter block holds: the mapping, or the problem that stops it reading."""

    block: FrontmatterBlock | None  # None when the file has no closed block (an opened one is the problem)
    data: JsonObject | None  # None when there is no block, it is empty, or it does not read
    problem: FrontmatterProblem | None
