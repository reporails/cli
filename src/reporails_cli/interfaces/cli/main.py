"""Typer CLI for reporails - validate and score AI instruction files."""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────
# CRITICAL: the torch import blocker MUST run before any import that could
# transitively pull torch in, which is slow and unused on the CLI critical path.
from reporails_cli.core.platform.runtime import _torch_blocker

_torch_blocker.install()
# ─────────────────────────────────────────────────────────────────────

import logging  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

import typer  # noqa: E402

logger = logging.getLogger(__name__)

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

from reporails_cli.core.platform.adapters.registry import infer_agent_from_rule_id, load_rules  # noqa: E402
from reporails_cli.formatters import text as text_formatter  # noqa: E402
from reporails_cli.interfaces.cli.check_flow import CheckInputs, CheckState, run_check_flow  # noqa: E402
from reporails_cli.interfaces.cli.check_orchestration import _validate_output_format  # noqa: E402
from reporails_cli.interfaces.cli.check_support import (  # noqa: E402
    _arm_check_timeout,
    _autocomplete_agent,
    _autocomplete_rule_token,
    _autocomplete_target_token,
    _explain_rules_paths,
    _resolve_rule_token,
    _serialize_match,
)
from reporails_cli.interfaces.cli.helpers import (  # noqa: E402
    _print_unknown_rule,
    app,
    console,
)


@app.command(rich_help_panel="Get started")
def check(
    targets: list[str] = typer.Argument(  # noqa: B008
        None,
        help=(
            "What to check: a path like ./CLAUDE.md, a bare capability like skills "
            "(every skill), or capability:name like skill:backlog (one skill). "
            "Repeatable and mixable; no target scans the whole project. "
            "Run 'ails rules capabilities' for the full capability list."
        ),
        autocompletion=_autocomplete_target_token,
    ),
    format: str = typer.Option(None, "--format", "-f", help="Output format: text, json, github"),
    agent: str = typer.Option(
        "",
        "--agent",
        help="Agent type (e.g., claude, copilot)",
        autocompletion=_autocomplete_agent,
    ),
    exclude_dirs: list[str] | None = typer.Option(None, "--exclude-dirs", help="Directories to exclude"),  # noqa: B008
    exclude_files: list[str] | None = typer.Option(None, "--exclude-files", help="File globs to exclude"),  # noqa: B008
    ascii: bool = typer.Option(False, "--ascii", "-a", help="ASCII characters only"),
    strict: bool = typer.Option(False, "--strict", help="Exit code 1 if violations found"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show details"),
    heal: bool = typer.Option(
        False,
        "--heal",
        "--fix",
        help="Apply auto-fixes after validation. Needs an account — run `ails auth login` first.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="With --heal: preview fixes without writing."),
    cwd: bool = typer.Option(False, "--cwd", help="With --heal: opt into rewriting the whole project."),
) -> None:
    """Validate and score your instruction files.

    Run `ails rules capabilities` to see the capability names you can target.
    """
    _validate_output_format(format)  # a retired/misspelled format is a usage error, not a silent text run
    _arm_check_timeout()  # wall-clock backstop against a runaway/hung check (POSIX)
    state = CheckState(
        inputs=CheckInputs(
            targets=targets,
            format_opt=format,
            agent=agent,
            exclude_dirs=exclude_dirs,
            exclude_files=exclude_files,
            ascii_mode=ascii,
            strict=strict,
            verbose=verbose,
            heal=heal,
            dry_run=dry_run,
            cwd=cwd,
            project_root=Path.cwd().resolve(),
        )
    )
    run_check_flow(state)


@app.command(rich_help_panel="Explore")
def explain(
    rule_id: str = typer.Argument(
        ...,
        help="Rule ID (e.g., CORE:S:0024) or slug (e.g., italic-constraints).",
        autocompletion=_autocomplete_rule_token,
    ),
    rules: list[str] = typer.Option(  # noqa: B008
        None,
        "--rules",
        "-r",
        help="Directory containing rules to look the rule up in (repeatable). Defaults to the bundled framework rules.",
    ),
) -> None:
    """Show what a rule checks, by ID or slug."""
    rules_paths = _explain_rules_paths(rules)
    rule_id_upper = _resolve_rule_token(rule_id)
    agent = infer_agent_from_rule_id(rule_id_upper)  # auto-load agent-namespaced rules
    loaded_rules = load_rules(rules_paths, agent=agent)

    if rule_id_upper not in loaded_rules:
        _print_unknown_rule(rule_id, loaded_rules)
        raise typer.Exit(2)

    rule = loaded_rules[rule_id_upper]
    rule_data: dict[str, Any] = {
        "title": rule.title,
        "category": rule.category.value,
        "type": rule.type.value,
        "slug": rule.slug,
        "match": _serialize_match(rule.match),
        "severity": rule.severity.value,
        "execution": rule.execution.value,
        "checks": [{"id": c.id, "type": c.type, "severity": c.severity or rule.severity.value} for c in rule.checks],
        "see_also": rule.see_also,
    }

    # The rule body and its Pass / Fail examples — the same fence-aware extraction
    # `ails rules -f md` uses, so the surfaces agree (examples named as absent when missing).
    from reporails_cli.core.lint.rule_pages import load_rule_description, load_rule_examples

    description = load_rule_description(rule)
    if description:
        rule_data["description"] = description
    rule_data["examples"] = load_rule_examples(rule)

    output = text_formatter.format_rule(rule_id_upper, rule_data)
    # markup=False: the rule body / Pass-Fail examples contain literal `[...]` (markdown
    # links, regex classes, the `[type]` check annotation) that Rich would eat as tags.
    console.print(output, markup=False)


def main() -> None:
    """Entry point for CLI."""
    app()


import reporails_cli.interfaces.cli.checks_command  # noqa: E402  # list_checks helper backing rules_command
import reporails_cli.interfaces.cli.commands  # noqa: E402  # Register commands
import reporails_cli.interfaces.cli.install  # noqa: E402  # Register install command
import reporails_cli.interfaces.cli.rules_command  # noqa: E402  # Register `ails rules`
import reporails_cli.interfaces.cli.test_command  # noqa: F401, E402  # Register test command
from reporails_cli.interfaces.cli.auth_command import auth_app  # noqa: E402
from reporails_cli.interfaces.cli.config_command import config_app  # noqa: E402
from reporails_cli.interfaces.cli.daemon_cmd import daemon_app  # noqa: E402
from reporails_cli.interfaces.cli.stopwords_command import stopwords_app  # noqa: E402

app.add_typer(auth_app, rich_help_panel="Account & setup")
app.add_typer(config_app, rich_help_panel="Account & setup")
app.add_typer(daemon_app, hidden=True)
app.add_typer(stopwords_app, hidden=True)

if __name__ == "__main__":
    main()
