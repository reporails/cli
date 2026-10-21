"""The `ails check` and `ails explain` commands."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import typer

from reporails_cli.core.platform.policy.exclusion import first_folder_value_problem
from reporails_cli.interfaces.cli.completion import complete_agent, complete_rule_token, complete_target_token
from reporails_cli.interfaces.cli.helpers import _print_unknown_rule, console
from reporails_cli.interfaces.cli.option_groups import command_options
from reporails_cli.interfaces.cli.typer_app import app


def _checked_exclude_dirs(values: list[str] | None) -> list[str] | None:
    """Refuse a `--exclude-dirs` value that is not a folder name or a folder path."""
    problem = first_folder_value_problem(values or [])
    if problem is not None:
        raise typer.BadParameter(f"{problem}; use --exclude-files for file patterns")
    return values


@dataclass
class CheckOptions:
    """The options of `ails check`; each default is the `typer.Option` / `typer.Argument` that declares it."""

    targets: list[str] = typer.Argument(  # noqa: RUF009
        None,
        help=(
            "What to check: a path like ./CLAUDE.md, a bare capability like skills "
            "(every skill), or capability:name like skill:backlog (one skill). "
            "Repeatable and mixable; no target scans the whole project. "
            "Run 'ails rules capabilities' for the full capability list."
        ),
        autocompletion=complete_target_token,
    )
    output_format: str = typer.Option(None, "--format", "-f", help="Output format: text, json, github")
    agent: str = typer.Option(
        "",
        "--agent",
        help="Agent type (e.g., claude, copilot)",
        autocompletion=complete_agent,
    )
    exclude_dirs: list[str] | None = typer.Option(  # noqa: RUF009
        None,
        "--exclude-dirs",
        help="Folders to leave out: a name, or a path from the project root",
        callback=_checked_exclude_dirs,
    )
    exclude_files: list[str] | None = typer.Option(  # noqa: RUF009
        None, "--exclude-files", help="File globs to exclude"
    )
    ascii_mode: bool = typer.Option(False, "--ascii", "-a", help="ASCII characters only")
    strict: bool = typer.Option(False, "--strict", help="Exit code 1 on any finding in scope, or a rejected API key")
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show details")
    heal: bool = typer.Option(
        False,
        "--heal",
        "--fix",
        help="Apply auto-fixes after validation. Needs an account — run `ails login` first.",
    )
    no_promo: bool = typer.Option(
        False,
        "--no-promo",
        help="Hide announcements from reporails; messages about your account still show. Same as AILS_NO_PROMO=1.",
    )
    dry_run: bool = typer.Option(False, "--dry-run", help="With --heal: preview fixes without writing.")
    cwd: bool = typer.Option(False, "--cwd", help="With --heal: opt into rewriting the whole project.")


@app.command(rich_help_panel="Get started")
@command_options(CheckOptions)
def check(options: CheckOptions) -> None:
    """Validate and score your instruction files.

    Run `ails rules capabilities` to see the capability names you can target.
    """
    from reporails_cli.interfaces.cli.check_flow import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        CheckInputs,
        CheckRender,
        CheckState,
        run_check_flow,
    )
    from reporails_cli.interfaces.cli.check_orchestration import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        _validate_output_format,
    )
    from reporails_cli.interfaces.cli.check_support import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        _arm_check_timeout,
    )

    # a retired/misspelled format is a usage error, not a silent text run
    _validate_output_format(options.output_format)
    _arm_check_timeout()  # wall-clock backstop against a runaway/hung check (POSIX)
    state = CheckState(
        inputs=CheckInputs(
            targets=options.targets,
            format_opt=options.output_format,
            agent=options.agent,
            exclude_dirs=options.exclude_dirs,
            exclude_files=options.exclude_files,
            ascii_mode=options.ascii_mode,
            strict=options.strict,
            verbose=options.verbose,
            heal=options.heal,
            dry_run=options.dry_run,
            cwd=options.cwd,
            project_root=Path.cwd().resolve(),
        ),
        render=CheckRender(no_promo=options.no_promo),
    )
    run_check_flow(state)


@app.command(rich_help_panel="Explore")
def explain(
    rule_id: str = typer.Argument(
        ...,
        help="Rule ID (e.g., CORE:S:0024) or slug (e.g., italic-constraints).",
        autocompletion=complete_rule_token,
    ),
    rules: list[str] = typer.Option(  # noqa: B008
        None,
        "--rules",
        "-r",
        help="Directory containing rules to look the rule up in (repeatable). Defaults to the bundled framework rules.",
    ),
) -> None:
    """Show what a rule checks, by ID or slug."""
    from reporails_cli.core.lint.rule_pages import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        rule_page_data,
    )
    from reporails_cli.core.platform.adapters.registry import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        infer_agent_from_rule_id,
        load_rules,
    )
    from reporails_cli.formatters import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        text as text_formatter,
    )
    from reporails_cli.interfaces.cli.explain_support import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        _explain_rules_paths,
        _resolve_rule_token,
    )

    rules_paths = _explain_rules_paths(rules)
    rule_id_upper = _resolve_rule_token(rule_id)
    agent = infer_agent_from_rule_id(rule_id_upper)  # auto-load agent-namespaced rules
    loaded_rules = load_rules(rules_paths, agent=agent)

    if rule_id_upper not in loaded_rules:
        _print_unknown_rule(rule_id, loaded_rules)
        raise typer.Exit(2)

    output = text_formatter.format_rule(rule_id_upper, rule_page_data(loaded_rules[rule_id_upper]))
    # markup=False: the rule body / Pass-Fail examples contain literal `[...]` (markdown
    # links, regex classes, the `[type]` check annotation) that Rich would eat as tags.
    console.print(output, markup=False)
