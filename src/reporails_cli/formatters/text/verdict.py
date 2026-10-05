"""Verdict block of the text scorecard — the three lines a user reads first.

`Quality` (the state), `Fix now` (the next action), `Findings` (the size of the
rest), and the caption that reconciles a low score with a must-fix list. The
console here is the one the whole scorecard prints through.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from rich.console import Console

from reporails_cli.formatters.text.display_constants import (
    conventions_phrase,
    display_rule_id,
    get_term_width,
    rule_docs_url,
)
from reporails_cli.formatters.text.funnel_cta import no_score_reason
from reporails_cli.formatters.text.score import score_color
from reporails_cli.formatters.triage import split_conventions

console = Console()


def compute_score(result: Any, has_quality: bool, n_atoms: int = 0) -> float | None:  # noqa: ARG001
    """Return the reported whole-project display score verbatim.

    The CLI renders it without re-deriving. Falls back to 0.0 when offline (no server quality).
    Returns `None` when the project has quality data but no scorable content (the
    reported `display_score` is itself `None` — no file had any charged atoms), so the
    caller renders "n/a (no scorable content)" rather than raising or fabricating 0.0.
    `n_atoms` is retained for call-signature stability.
    """
    if has_quality and result.quality is not None:
        score = result.quality.display_score
        return float(score) if score is not None else None
    return 0.0


def _plural(n: int, noun: str) -> str:
    """`1 error` / `2 errors`, thousands grouped."""
    return f"{n:,} {noun}{'' if n == 1 else 's'}"


def _score_bar(score: float, bar_width: int, color: str) -> str:
    """Render a score bar with colored fill + dim gray empty.

    Splitting the markup at the fill boundary gives every bar a
    consistent gray baseline so the colored fill is the only visual
    variable that changes across rows.
    """
    filled = round(bar_width * score / 10)
    fill = "\u2593" * filled
    empty = "\u2591" * (bar_width - filled)
    return f"[{color}]{fill}[/{color}][dim]{empty}[/dim]"


# ── Scorecard sub-renderers ───────────────────────────────────────────


_VERDICT_LABEL_W = 10  # widest label is "Findings" plus two spaces


def _render_verdict_block(
    result: Any,
    has_quality: bool,
    n_atoms: int,
    elapsed_ms: float,
    hint_errors: int = 0,
    verbose: bool = False,
) -> None:
    """Render the three-line verdict: Quality, Fix now, Findings.

    Line one is the state — the single reported verdict, which already covers
    completeness and truncation, so a structurally incomplete or truncated
    file cannot read as high quality. Line two is the next action. Line three is the
    size of the rest. A caption beneath reconciles a low score with a must-fix list.
    """
    tw = get_term_width()
    bar_width = min(20, max(10, tw - 48))
    elapsed_s = f"  [dim]({elapsed_ms / 1000:.1f}s)[/dim]" if elapsed_ms else ""

    score: float | None = None
    has_quality_obj = has_quality and result.quality is not None
    if has_quality_obj:
        score = compute_score(result, has_quality, n_atoms)
    if score is not None:
        color = score_color(score)
        bar = _score_bar(score, bar_width, color)
        value = f"[{color} bold]{score:>4.1f}[/{color} bold] / 10"
        console.print(f"  {'Quality':<{_VERDICT_LABEL_W - 1}}{value}  {bar}{elapsed_s}")
    elif has_quality_obj:
        # Quality data exists but no file had any scorable content (display_score
        # is `None`, not a fabricated floor) — never raise, render the n/a line.
        console.print(f"  {'Quality':<{_VERDICT_LABEL_W}}[dim]n/a (no scorable content)[/dim]{elapsed_s}")
    else:
        reason = no_score_reason(getattr(result, "server_error", None))
        console.print(f"  {'Quality':<{_VERDICT_LABEL_W}}[dim]n/a ({reason})[/dim]{elapsed_s}")

    findings = list(result.findings or [])
    visible_errors = [f for f in findings if f.severity == "error"]

    _render_fix_now(visible_errors, hint_errors)
    listed, conventions = split_conventions(findings, verbose)
    _render_findings_line(len(listed), verbose, len(conventions))


def _top_error_rule(errors: list[Any]) -> tuple[str, int]:
    """The rule id with the most error findings and its count; ties break on rule id."""
    counts: Counter[str] = Counter(display_rule_id(f.rule or "") for f in errors)
    rule, n = min(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return rule, n


def _render_fix_now(errors: list[Any], hint_errors: int) -> None:
    """The next action: the error count and one entry point. Omitted when nothing is listed.

    On the free tier the errors held back as Pro diagnostics are named beside the visible
    count, so the number a user reads as "my errors" is not an under-count they discover
    after upgrading.
    """
    if not errors:
        return
    gated = f" [dim]({hint_errors:,} more in Pro)[/dim]" if hint_errors else ""
    rule, n = _top_error_rule(errors)
    url = rule_docs_url(rule)
    rule_cell = f"[link={url}]{rule}[/link]" if url else rule
    count = f" ({_plural(n, 'error')})" if n > 1 else ""
    console.print(
        f"  {'Fix now':<{_VERDICT_LABEL_W}}[red]{_plural(len(errors), 'error')}[/red]{gated}. "
        f"Start with {rule_cell}{count}."
    )


def _render_findings_line(total: int, verbose: bool, conventions: int = 0) -> None:
    """One total, plus the documentation conventions listed as one line apart from it.

    The `-v` hint is dropped once verbose, where every convention is listed and counted.
    """
    note = f" · {conventions_phrase(conventions)}" if conventions else ""
    hint = (
        ""
        if verbose or not (total or conventions)
        else f" [dim]· -v to list {'them' if conventions else 'every one'}[/dim]"
    )
    console.print(f"  {'Findings':<{_VERDICT_LABEL_W}}{total:,} total{note}{hint}")
