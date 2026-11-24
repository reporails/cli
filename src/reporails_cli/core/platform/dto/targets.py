"""Command-line targets the run did not check, and why."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.diagnostics import Notice

NotEvaluatedReason = Literal["no_markdown", "not_markdown", "unknown_capability"]


@dataclass(frozen=True)
class UnevaluatedTarget:
    """A target named on the command line that no file of the run came from."""

    target: str
    reason: NotEvaluatedReason


@dataclass(frozen=True)
class TargetReport:
    """How the run read the targets named on the command line: those nothing was checked for, and notices on them."""

    unevaluated: tuple[UnevaluatedTarget, ...] = ()
    notices: tuple[Notice, ...] = ()
