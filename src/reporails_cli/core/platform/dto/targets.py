"""Command-line targets the run did not check, and why."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.diagnostics import Notice

NotEvaluatedReason = Literal[
    "no_markdown", "not_markdown", "other_project", "unknown_capability", "excluded", "no_files"
]


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


@dataclass(frozen=True)
class MissingTarget:
    """A path target that names nothing on disk; `capability_hint` says the word is also a capability of the agent."""

    token: str
    path: Path
    capability_hint: bool


@dataclass(frozen=True)
class TargetReading:
    """The targets read against the agent's vocabulary: what each names and what is already known unchecked."""

    capability_specs: tuple[tuple[str, str], ...] = ()
    capability_words: tuple[str, ...] = ()
    path_targets: frozenset[Path] = frozenset()
    missing: tuple[MissingTarget, ...] = ()
    unevaluated: tuple[UnevaluatedTarget, ...] = ()
    notices: tuple[Notice, ...] = ()
