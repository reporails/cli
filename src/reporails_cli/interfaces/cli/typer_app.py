"""The root Typer application every ``ails`` command registers on.

Importing this module installs the torch import blocker, so it is in place before any
other CLI module loads: nothing the commands import can pull torch in. The module
imports no command module; each command module imports ``app`` from here and
``main.py`` imports the command modules so their commands register.
"""

from __future__ import annotations

from typing import Any

import click
import typer
from typer.core import TyperGroup

from reporails_cli.core.platform.contract.errors import ConfigUnreadableError
from reporails_cli.core.platform.runtime import _torch_blocker

_torch_blocker.install()


class _AilsGroup(TyperGroup):
    """Root command group: an unreadable config file ends any command with one error line and exit code 2."""

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except ConfigUnreadableError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(2) from exc


app = typer.Typer(
    cls=_AilsGroup,
    name="ails",
    help=("what ails your repo? Let's find out!\n\nrun `ails check` to diagnose your project's instructions"),
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
