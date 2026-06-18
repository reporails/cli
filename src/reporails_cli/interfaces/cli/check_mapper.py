"""Daemon attach + ruleset-map build glue for `ails check`.

Extracted from `interfaces/cli/main.py` to keep that module within the
`pyproject.toml` `max-module-lines` budget. The two helpers here drive
user-visible messaging off the daemon's actual status (rather than
emitting "Starting…" + "unavailable" lines that contradict each other)
and pick the daemon-vs-in-process path up-front.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any


def resolve_daemon_status(progress: Callable[[str], None]) -> Any:
    """Eagerly attach to (or start) the global mapper daemon, return its status."""
    from reporails_cli.core.mapper.daemon_client import DaemonStatus, ensure_daemon

    try:
        status = ensure_daemon()
    except (ImportError, OSError):
        return DaemonStatus.UNAVAILABLE

    if status == DaemonStatus.STARTED:
        progress("Started mapper daemon.")
    elif status == DaemonStatus.STARTING:
        progress("Mapper daemon warming up, mapping in-process this run...")
    elif status == DaemonStatus.UNAVAILABLE:
        progress("Mapper daemon unavailable, mapping in-process...")
    return status


def build_ruleset_map(
    daemon_status: Any,
    instruction_files: list[Path],
    target: Path,
    spinner: Any,
    show_progress: bool,
    progress: Callable[[str], None],
    map_in_process: Callable[[list[Path]], Any],
) -> Any:
    """Map instruction files via daemon or in-process per resolved status."""
    from reporails_cli.core.mapper.daemon_client import DaemonStatus, map_ruleset_via_daemon

    if daemon_status in (DaemonStatus.ATTACHED, DaemonStatus.STARTED):
        ruleset_map = map_ruleset_via_daemon(list(instruction_files), target)
        if ruleset_map is not None:
            return ruleset_map
        progress("Daemon stopped responding, falling back to in-process...")

    if show_progress:
        spinner.update("[bold]Loading models...[/bold]")
    return map_in_process(instruction_files)
