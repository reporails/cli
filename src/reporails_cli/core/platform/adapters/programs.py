"""The one process runner: run a program, start a detached one, open a page in the browser."""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

from reporails_cli.core.platform.config.bootstrap import env_text, running_in_ci

logger = logging.getLogger(__name__)


type ProgramRun = subprocess.CompletedProcess[str]


def run_program(
    cmd: list[str], *, timeout: float, env: dict[str, str] | None = None, cwd: Path | None = None
) -> ProgramRun | None:
    """Run a program and capture its text output; None when it cannot start or runs out of time."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False, env=env, cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("%s failed: %s", cmd[0], exc)
        return None


def run_uv_tool(uv: str, *args: str) -> ProgramRun | None:
    """Run `uv tool <args>` and capture its output; None when uv cannot start or runs out of time."""
    return run_program([uv, "tool", *args], timeout=120)


def launch_detached(cmd: list[str], *, cwd: Path | None) -> int:
    """Start `cmd` in `cwd` as a detached child that holds none of the caller's streams and outlives this call.

    Returns the child's pid.
    """
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    child = subprocess.Popen(  # pylint: disable=consider-using-with  # detached child outlives this call
        cmd,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=sys.platform != "win32",
        creationflags=creationflags,
    )
    return child.pid


def _can_show_browser() -> bool:
    """True when this machine can show a page.

    Never in CI. Otherwise a non-blank `BROWSER` setting says how to open one. Without it, macOS and
    Windows can unless the session is over SSH, and every other system needs `DISPLAY` or `WAYLAND_DISPLAY`.
    """
    if running_in_ci():
        return False
    if env_text("BROWSER"):
        return True
    if sys.platform == "darwin" or sys.platform.startswith("win"):
        return not any(env_text(name) for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"))
    return bool(env_text("DISPLAY") or env_text("WAYLAND_DISPLAY"))


def open_in_browser(url: str) -> None:
    """Open `url` from a detached child that ignores the working directory and holds none of the caller's
    streams; nothing starts where no screen can show a page, and a browser that cannot start logs one
    warning and returns."""
    if not sys.executable or not _can_show_browser():
        return
    try:
        launch_detached([sys.executable, "-I", "-m", "webbrowser", "-t", url], cwd=None)
    except OSError as exc:
        logger.warning("Could not open the browser: %s", exc)
