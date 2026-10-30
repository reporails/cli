"""The `ails` console entry: starts light for `ails hook`, hands every other command to the Typer app."""

from __future__ import annotations

import sys

HOOK_COMMAND = "hook"
DEFAULT_HOOK_AGENT = "claude"


def _hook_agent(args: list[str]) -> str:
    """The agent named by `--agent <name>` or `--agent=<name>` in `args`, else the default."""
    for index, arg in enumerate(args):
        if arg == "--agent" and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("--agent="):
            return arg.removeprefix("--agent=")
    return DEFAULT_HOOK_AGENT


HOOK_USAGE = "usage: ails hook [--agent NAME] < payload.json — records one agent hook payload from stdin"


def _run_hook(args: list[str]) -> None:
    """Record the payload on stdin as event records. Exits 0 on every path, prints nothing."""
    if sys.stdin.isatty():
        sys.stderr.write(HOOK_USAGE + "\n")
        sys.exit(0)
    try:
        # pylint: disable-next=import-outside-toplevel  # startup: the hook path must not load the CLI
        from reporails_cli.core.eventbus.dispatcher import record_payload

        # pylint: disable-next=import-outside-toplevel  # startup: the hook path must not load the CLI
        from reporails_cli.core.eventbus.port import subscribe

        # pylint: disable-next=import-outside-toplevel  # startup: the hook path must not load the CLI
        from reporails_cli.core.platform.observability.log_levels import configure_logging

        # pylint: disable-next=import-outside-toplevel  # startup: the hook path must not load the CLI
        from reporails_cli.core.platform.observability.stage_timer import get_stage_timer, mark_event

        configure_logging()
        agent = _hook_agent(args)
        subscribe(mark_event)
        with get_stage_timer().run(f"hook {agent}"):
            record_payload(agent, sys.stdin.buffer.read())
    except BaseException:  # pylint: disable=broad-exception-caught  # the hook must never fail or print into the agent's session
        pass
    sys.exit(0)


def run() -> None:
    """Console entry point of `ails` and `reporails-cli`."""
    if sys.argv[1:2] == [HOOK_COMMAND]:
        _run_hook(sys.argv[2:])
    from reporails_cli.interfaces.cli.main import (  # pylint: disable=import-outside-toplevel  # startup: the entry boundary that must start light
        main,
    )

    main()
