"""The server lint and the notice filter, answered by the reporails server client."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reporails_cli.core.platform.adapters.api_client import AilsClient
from reporails_cli.core.platform.adapters.notices_seen import visible_notices
from reporails_cli.core.platform.dto.diagnostics import LintResponse, Notice
from reporails_cli.core.platform.dto.models import LocalEntry
from reporails_cli.core.platform.dto.ruleset import RulesetMap


class ServerLint:
    """Lints through the server and hides the notices the user opted out of."""

    def __init__(self, tier: str) -> None:
        self._tier = tier

    def lint(
        self,
        ruleset_map: RulesetMap,
        local: Sequence[LocalEntry],
        structural_required: int,
        *,
        root: Path,
    ) -> LintResponse:
        """The server's reply to `ruleset_map` and the reported `local` findings, paths relative to `root`."""
        return AilsClient(self._tier).lint(ruleset_map, local, structural_required, root=root)

    def visible_notices(self, notices: tuple[Notice, ...]) -> tuple[Notice, ...]:
        """`notices` without the ones a user opted out of seeing."""
        return visible_notices(notices)
