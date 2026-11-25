"""The lines that name the checks that did not finish."""

from __future__ import annotations

from collections.abc import Iterable

from rich.console import Console
from rich.markup import escape

from reporails_cli.core.platform.dto.targets import NotEvaluatedReason, UnevaluatedTarget

RUN_IN_ITS_PROJECT = "run ails check in that project's folder"

_REASON_TEXT: dict[NotEvaluatedReason, str] = {
    "no_markdown": "the folder holds no markdown file",
    "not_markdown": "it is not a markdown file",
    "other_project": f"it is a file of another project; {RUN_IN_ITS_PROJECT}",
    "unknown_capability": "the agent has no such capability",
    "excluded": "its markdown files are left out by exclude_dirs or exclude_files",
    "no_files": "the project has no files for it",
}


def group_not_evaluated(pairs: Iterable[tuple[str, str]]) -> list[tuple[str, list[str]]]:
    """The `(rule id, file)` pairs as `(file, [rule ids])`, files and rules in first-seen order."""
    by_file: dict[str, list[str]] = {}
    for rule, file in pairs:
        rules = by_file.setdefault(file, [])
        if rule not in rules:
            rules.append(rule)
    return list(by_file.items())


def not_evaluated_sentence(file: str, rules: list[str]) -> str:
    """`Not evaluated in <file>: <rules> — the check did not finish in time`, plain text."""
    return (
        f"Not evaluated in {file}: {', '.join(rules)} — "
        f"{'the check' if len(rules) == 1 else 'these checks'} did not finish in time"
    )


def not_evaluated_lines(pairs: Iterable[tuple[str, str]]) -> list[str]:
    """One dim line per file naming its `(rule id, file)` pairs, in first-seen order; empty when there are none."""
    return [f"[dim]{escape(not_evaluated_sentence(file, rules))}[/dim]" for file, rules in group_not_evaluated(pairs)]


def print_not_evaluated(console: Console, pairs: Iterable[tuple[str, str]]) -> None:
    """Print the not-evaluated lines under the run's results; nothing when every check finished."""
    lines = not_evaluated_lines(pairs)
    if lines:
        console.print()
        for line in lines:
            console.print(f"  {line}", soft_wrap=True)


def unevaluated_target_sentence(target: str, reason: NotEvaluatedReason) -> str:
    """`<target> not checked: <reason>`, plain text."""
    return f"{target} not checked: {_REASON_TEXT[reason]}"


def target_reason(value: str) -> NotEvaluatedReason | None:
    """The reason a document names, or None when this version does not know it."""
    return next((reason for reason in _REASON_TEXT if reason == value), None)


def unevaluated_target_lines(targets: Iterable[UnevaluatedTarget]) -> list[str]:
    """One plain line per target the run did not check."""
    return [unevaluated_target_sentence(t.target, t.reason) for t in targets]
