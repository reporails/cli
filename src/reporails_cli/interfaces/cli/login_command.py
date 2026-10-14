"""ails login / ails logout: sign this machine in to, or out of, your account."""

from __future__ import annotations

from reporails_cli.interfaces.cli.typer_app import app


@app.command("login", rich_help_panel="Account & setup")
def login() -> None:
    """Sign this machine in to your account through the browser."""
    from reporails_cli.interfaces.cli.login_flow import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        run_login,
    )

    run_login()


@app.command("logout", rich_help_panel="Account & setup")
def logout() -> None:
    """Sign this machine out."""
    from reporails_cli.interfaces.cli.login_flow import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        run_logout,
    )

    run_logout()
