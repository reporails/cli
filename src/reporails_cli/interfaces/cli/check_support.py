"""Support helpers for the ``ails check`` / ``ails explain`` commands.

Autocompletion shims, rule-token resolution, match serialization, structural
finding rollup, generic-scan classification, and the wall-clock timeout backstop.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from reporails_cli.core.platform.dto.models import FileMatch
from reporails_cli.core.platform.policy.matching import MATCH_PROPERTIES
from reporails_cli.interfaces.cli.helpers import console

logger = logging.getLogger(__name__)


def _autocomplete_target_token(incomplete: str) -> list[str]:
    """Typer autocompletion shim for `ails check <TARGET>`."""
    from reporails_cli.interfaces.cli.completion import complete_target_token

    return complete_target_token(incomplete)


def _autocomplete_agent(incomplete: str) -> list[str]:
    """Typer autocompletion shim for `--agent`."""
    from reporails_cli.interfaces.cli.completion import complete_agent

    return complete_agent(incomplete)


def _autocomplete_rule_token(incomplete: str) -> list[str]:
    """Typer autocompletion shim for `ails explain <ID-or-slug>`."""
    from reporails_cli.interfaces.cli.completion import complete_rule_token

    return complete_rule_token(incomplete)


def _serialize_match(match: FileMatch | None) -> dict[str, object]:
    """Serialize FileMatch to dict, including all non-None properties."""
    if match is None:
        return {}
    result: dict[str, object] = {}
    if match.type is not None:
        result["type"] = match.type
    for prop in MATCH_PROPERTIES:
        val = getattr(match, prop)
        if val is not None:
            result[prop] = val
    return result


def _explain_rules_paths(rules: list[str] | None) -> list[Path] | None:
    """Resolve rules paths for explain command."""
    if rules:
        return [Path(r).resolve() for r in rules]
    return None


def _generic_scan_file_types(
    target: Path,
    instruction_files: list[Path],
    agent: str,
    generic_scanning: bool,
) -> tuple[list[Path], dict[str, str]]:
    """Classify generic-scanned (link / import-reached) files at the composition root.

    Returns `(import_extra, file_type_by_path)`:
      - `import_extra` — `@`-import-reached files (`file_type == "generic"`, eagerly auto-loaded)
        to ADD to the mapped + server-scored set so they earn an Imported quality score.
        Markdown-`referenced` files are deliberately excluded: the harness never loads them, so
        folding them into the score would be a false signal — they stay lint-only.
      - `file_type_by_path` — normalized path -> file_type for ALL generic-scanned files (generic +
        referenced), so the display routes them to the Imported surface / Referenced panel.
    No-op (`([], {})`) when generic scanning is off.
    """
    if not generic_scanning:
        return [], {}
    from reporails_cli.core.classify import classify_files, load_file_types
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    try:
        file_types = load_file_types(agent, project_root=target)
        classified = classify_files(target, list(instruction_files), file_types, generic_scanning=True)
    except (OSError, ValueError) as exc:
        logger.warning("generic-scan classification skipped: %s", exc)
        return [], {}

    ft_by_path = {normalize_finding_path(str(cf.path), target): cf.file_type for cf in classified}
    seen = {normalize_finding_path(str(p), target) for p in instruction_files}
    import_extra = [
        cf.path
        for cf in classified
        if cf.file_type == "generic" and normalize_finding_path(str(cf.path), target) not in seen
    ]
    return import_extra, ft_by_path


def _heal_authed(funnel_error: object) -> bool:
    """True when `--heal` may write fixes this run.

    A key string being present is not enough on its own: when the server rejected
    that key in this SAME run (an auth-rejection `funnel_error`), the write gate
    stays shut even though `has_api_key()` reads true. Any other outcome — no
    server reached, a non-auth funnel error, or a normal lint response — leaves a
    present key authed, exactly as before.
    """
    from reporails_cli.core.platform.adapters.api_client import has_api_key
    from reporails_cli.core.platform.dto.diagnostics import FunnelError
    from reporails_cli.interfaces.cli.check_orchestration import _AUTH_REJECTED_ERRORS

    if not has_api_key():
        return False
    return not (isinstance(funnel_error, FunnelError) and funnel_error.error in _AUTH_REJECTED_ERRORS)


def _resolve_rule_token(token: str) -> str:
    """Map either a rule ID or a rule slug to a canonical ID."""
    if ":" in token:
        return token.upper()
    from reporails_cli.core.platform.adapters.rules_query import load_all_rules

    for rule in load_all_rules():
        if rule.slug == token:
            return rule.id
    return token


def _ensure_model_or_exit() -> bool:
    """Make the model set available before the files are mapped; exit 2 if that fails.

    Returns whether the model is on disk (false only when it is not and the run goes on without it).

    The wall-clock limit is paused while this runs, so a slow first download is not
    cut off by it. With ``AILS_MODEL_OFFLINE`` set and no model on disk (whether
    nothing was ever fetched, or a prior run left only a partial set), the check
    runs without the content checks (the opt-in the variable documents) and says
    so on stderr, rather than scoring on with no notice.
    """
    import typer

    from reporails_cli.bundled import ensure_models_available
    from reporails_cli.core.mapper.model_fetch import ModelFetchError

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
    import signal

    remaining, _interval = signal.setitimer(signal.ITIMER_REAL, 0)
    return remaining


def _resume_check_timeout(remaining: float) -> None:
    """Re-arm the wall-clock timer with the seconds it had left."""
    if sys.platform == "win32":
        return
    if remaining > 0:
        import signal

        signal.setitimer(signal.ITIMER_REAL, remaining)


def _check_timeout_ceiling() -> int:
    """Wall-clock ceiling (seconds) for a single `ails check`; 0 disables. Default 600."""
    import os

    raw = os.environ.get("AILS_CHECK_TIMEOUT_S", "").strip()
    if not raw:
        return 600
    try:
        return int(raw)
    except ValueError:
        return 600


def _arm_check_timeout() -> None:
    """Backstop a runaway check with a SIGALRM wall-clock kill (POSIX-only; no-op on Windows)."""
    import signal

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
