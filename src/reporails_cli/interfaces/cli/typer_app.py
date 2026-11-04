"""The root Typer application every ``ails`` command registers on.

The module imports no command module; each command module imports ``app`` from here and
``main.py`` imports the command modules so their commands register.
"""

from __future__ import annotations

import click
import typer
from typer.core import TyperGroup

from reporails_cli.core.platform.config.bootstrap import consume_npm_launch
from reporails_cli.core.platform.contract.errors import ConfigUnreadableError
from reporails_cli.core.platform.observability.log_levels import configure_logging


class _AilsGroup(TyperGroup):
    """Root command group: an unreadable config file ends any command with one error line and exit code 2."""

    def invoke(self, ctx: click.Context) -> object:
        consume_npm_launch()
        configure_logging()
        try:
            return super().invoke(ctx)
        except ConfigUnreadableError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(2) from exc


# Click context settings that give every command and sub-app both `-h` and `--help`.
HELP_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

app = typer.Typer(
    cls=_AilsGroup,
    name="ails",
    help=("what ails your repo? Let's find out!\n\nrun `ails check` to diagnose your project's instructions"),
    no_args_is_help=True,
    context_settings=HELP_CONTEXT_SETTINGS,
)
