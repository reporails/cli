"""Typer CLI for reporails - validate and score AI instruction files.

Importing a command module registers its commands on the shared ``app``; this module imports them all,
``check_command`` first, so ``ails -h`` lists the commands in the same order.
"""

from __future__ import annotations

import logging
import sys

from reporails_cli.interfaces.cli import check_command, commands, install, login_command, rules_command, test_command
from reporails_cli.interfaces.cli.config_command import config_app
from reporails_cli.interfaces.cli.daemon_cmd import daemon_app
from reporails_cli.interfaces.cli.stopwords_command import stopwords_app
from reporails_cli.interfaces.cli.typer_app import app

logger = logging.getLogger(__name__)

# The modules whose commands register on `app` when they are imported.
COMMAND_MODULES = (check_command, commands, install, login_command, rules_command, test_command)

# Force UTF-8 on stdout/stderr so the box-drawing and arrow glyphs in the rich
# scorecard and the `-f md` output do not crash on consoles whose default
# encoding (e.g. Windows cp1252) cannot encode them. The CLI ships to Windows
# via npx; cp1252 raises UnicodeEncodeError on `→`/`—`/box-drawing characters.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except (ValueError, OSError) as exc:  # io.UnsupportedOperation on a detached/replaced stream
            logger.debug("Could not set UTF-8 on output stream: %s", exc)


def main() -> None:
    """Entry point for CLI."""
    app()


app.add_typer(config_app, rich_help_panel="Account & setup")
app.add_typer(daemon_app, hidden=True)
app.add_typer(stopwords_app, hidden=True)

if __name__ == "__main__":
    main()
