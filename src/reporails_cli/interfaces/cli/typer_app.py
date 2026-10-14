"""The root Typer application every ``ails`` command registers on.

Importing this module installs the torch import blocker, so it is in place before any
other CLI module loads: nothing the commands import can pull torch in. The module
imports no command module; each command module imports ``app`` from here and
``main.py`` imports the command modules so their commands register.
"""

from __future__ import annotations

import typer

from reporails_cli.core.platform.runtime import _torch_blocker

_torch_blocker.install()

app = typer.Typer(
    name="ails",
    help=("what ails your repo? Let's find out!\n\nrun `ails check` to diagnose your project's instructions"),
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
