"""Support helpers for the ``ails check`` / ``ails explain`` commands.

Rule-token resolution, heal-authorization, model availability, and the wall-clock timeout backstop.
"""

from __future__ import annotations

import logging
import signal
import sys

import typer

from reporails_cli.core.heal.apply import heal_signed_in
from reporails_cli.core.mapper.model_manifest import ModelFetchError
from reporails_cli.core.mapper.model_store import ensure_models_available
from reporails_cli.core.platform.config.bootstrap import env_int
from reporails_cli.core.platform.dto.diagnostics import FunnelError
from reporails_cli.interfaces.cli.helpers import console

logger = logging.getLogger(__name__)


def _heal_authed(funnel_error: object) -> bool:
    """True when `--heal` may write fixes this run.

    A key string being present is not enough on its own: when the server rejected
    that key in this SAME run (an auth-rejection `funnel_error`), the write gate
    stays shut even though `has_api_key()` reads true. Any other outcome — no
    server reached, a non-auth funnel error, or a normal lint response — leaves a
    present key authed, exactly as before.
    """

    return heal_signed_in(funnel_error.error if isinstance(funnel_error, FunnelError) else None)


def _ensure_model_or_exit() -> bool:
    """Make the model set available before the files are mapped; exit 2 if that fails.

    Returns whether the model is on disk (false only when it is not and the run goes on without it).

    The wall-clock limit is paused while this runs, so a slow first download is not
    cut off by it. With ``AILS_MODEL_OFFLINE`` set and no model on disk (whether
    nothing was ever fetched, or a prior run left only a partial set), the check
    runs without the content checks (the opt-in the variable documents) and says
    so on stderr, rather than scoring on with no notice.
    """

    remaining = _pause_check_timeout()
    try:
        model_dir = ensure_models_available()
        if model_dir is None:
            print(
                "AILS_MODEL_OFFLINE is set and no model is on disk; content checks were skipped.",
                file=sys.stderr,
            )
        return model_dir is not None
    except ModelFetchError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise typer.Exit(2) from exc
    finally:
        _resume_check_timeout(remaining)


def _pause_check_timeout() -> float:
    """Stop the wall-clock timer; return the seconds it had left (0 when none was armed)."""
    if sys.platform == "win32":
        return 0.0

    remaining, _interval = signal.setitimer(signal.ITIMER_REAL, 0)
    return remaining


def _resume_check_timeout(remaining: float) -> None:
    """Re-arm the wall-clock timer with the seconds it had left."""
    if sys.platform == "win32":
        return
    if remaining > 0:
        signal.setitimer(signal.ITIMER_REAL, remaining)


def _check_timeout_ceiling() -> int:
    """Wall-clock ceiling (seconds) for a single `ails check`; 0 disables. Default 600."""

    timeout = env_int("AILS_CHECK_TIMEOUT_S")
    return 600 if timeout is None else timeout


def _arm_check_timeout() -> None:
    """Backstop a runaway check with a SIGALRM wall-clock kill (POSIX-only; no-op on Windows)."""

    if sys.platform == "win32":  # no SIGALRM/setitimer on Windows
        return
    ceiling = _check_timeout_ceiling()
    if ceiling <= 0:
        return

    def _on_timeout(_signum: int, _frame: object) -> None:
        console.print(
            f"[red]Error:[/red] ails check exceeded its {ceiling}s wall-clock limit and was aborted "
            "(set AILS_CHECK_TIMEOUT_S to adjust, 0 to disable)."
        )
        raise SystemExit(124)

    signal.signal(signal.SIGALRM, _on_timeout)
    signal.setitimer(signal.ITIMER_REAL, ceiling)
