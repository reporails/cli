"""Arguments of a mechanical check called on its own: the run's exclusions are part of them."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from reporails_cli.core.discovery.exclusions import load_run_exclusions
from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.contract.json_value import JsonValue
from reporails_cli.core.platform.dto.discovery import RunExclusions


def with_run_exclusions(root: Path, args: Mapping[str, JsonValue]) -> dict[str, JsonValue | RunExclusions]:
    """`args` plus the exclusions the config at `root` sets, as `run_mechanical_check` hands them to a check."""
    return {"_exclusions": load_run_exclusions(RunContext(), root), **args}
