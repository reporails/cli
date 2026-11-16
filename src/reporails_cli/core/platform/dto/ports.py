"""The calls a core function makes out to the server, as typed contracts a caller supplies."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from reporails_cli.core.platform.dto.diagnostics import LintResponse, Notice
from reporails_cli.core.platform.dto.models import LocalEntry
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.dto.sign_in import Handshake, Surface

# Asks the server whether it serves a caller on `Surface`: its verdict, or why there is none.
Handshaker = Callable[[Surface], Handshake]


class LintService(Protocol):
    """The server lint of one run's local findings, and the notices a user is shown."""

    def lint(
        self,
        ruleset_map: RulesetMap,
        local: Sequence[LocalEntry],
        structural_required: int,
        *,
        root: Path,
    ) -> LintResponse:
        """The server's reply to `ruleset_map` and the reported `local` findings, paths relative to `root`."""

    def visible_notices(self, notices: tuple[Notice, ...]) -> tuple[Notice, ...]:
        """`notices` without the ones a user opted out of seeing."""
