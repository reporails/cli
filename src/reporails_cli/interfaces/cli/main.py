"""Typer CLI for reporails - validate and score AI instruction files."""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────
# CRITICAL: torch import blocker MUST run before any import that could
# transitively reach thinc/spacy or sentence-transformers. See the
# module docstring of `_torch_blocker` for the full story — short
# version: spaCy's thinc backend does `try: import torch` as a side
# effect that costs ~20s on cold start. We don't use torch anywhere on
# the CLI critical path; ONNX Runtime + tokenizers handle everything.
from reporails_cli.core import _torch_blocker

_torch_blocker.install()
# ─────────────────────────────────────────────────────────────────────

import json  # noqa: E402
import logging  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

import typer  # noqa: E402

logger = logging.getLogger(__name__)

from reporails_cli.core.models import FileMatch, LocalFinding  # noqa: E402
from reporails_cli.core.registry import infer_agent_from_rule_id, load_rules  # noqa: E402
from reporails_cli.formatters import text as text_formatter  # noqa: E402
from reporails_cli.formatters.text.display import print_text_result  # noqa: E402
from reporails_cli.interfaces.cli.helpers import (  # noqa: E402
    _default_format,
    _handle_no_instruction_files,
    _print_unknown_rule,
    _resolve_agent_filters,
    _show_agent_auto_detect_hint,
    _validate_agent,
    app,
    console,
)


def _serialize_match(match: FileMatch | None) -> dict[str, object]:
    """Serialize FileMatch to dict, including all non-None properties."""
    if match is None:
        return {}
    result: dict[str, object] = {}
    if match.type is not None:
        result["type"] = match.type
    for prop in ("format", "scope", "cardinality", "lifecycle", "maintainer", "vcs", "loading", "precedence"):
        val = getattr(match, prop)
        if val is not None:
            result[prop] = val
    return result


def _explain_rules_paths(rules: list[str] | None) -> list[Path] | None:
    """Resolve rules paths for explain command, auto-including recommended."""
    if rules:
        return [Path(r).resolve() for r in rules]
    from reporails_cli.core.bootstrap import get_recommended_package_path
    from reporails_cli.core.registry import get_rules_dir

    rec_path = get_recommended_package_path()
    return [get_rules_dir(), rec_path] if rec_path.is_dir() else None


@app.command(rich_help_panel="Commands")
def check(  # noqa: C901  # pylint: disable=too-many-locals
    path: str = typer.Argument(".", help="File or directory to validate"),
    format: str = typer.Option(None, "--format", "-f", help="Output format: text, json, github"),
    agent: str = typer.Option("", "--agent", help="Agent type (e.g., claude, copilot)"),
    exclude_dirs: list[str] = typer.Option(None, "--exclude-dirs", help="Directories to exclude"),  # noqa: B008
    ascii: bool = typer.Option(False, "--ascii", "-a", help="ASCII characters only"),
    strict: bool = typer.Option(False, "--strict", help="Exit code 1 if violations found"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show details"),
) -> None:
    """Validate AI instruction files against reporails rules."""
    from contextlib import nullcontext

    from reporails_cli.core.agents import detect_agents, get_all_instruction_files
    from reporails_cli.core.api_client import AilsClient
    from reporails_cli.core.client_checks import run_client_checks
    from reporails_cli.core.config import get_project_config
    from reporails_cli.core.merger import merge_results
    from reporails_cli.core.rule_runner import run_content_quality_checks, run_m_probes
    from reporails_cli.formatters import json as json_formatter

    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(2)

    output_format = format or _default_format()

    # 1. Detect agents and resolve which one to use
    detected = detect_agents(target)
    config = get_project_config(target)
    agent_arg = agent or config.default_agent
    excl = exclude_dirs if exclude_dirs is not None else config.exclude_dirs
    if agent_arg:
        _validate_agent(agent_arg, console)
    effective_agent, assumed, mixed, filtered = _resolve_agent_filters(
        agent_arg,
        detected,
        target,
        excl,
    )
    instruction_files = get_all_instruction_files(target, agents=filtered)
    if not instruction_files:
        _handle_no_instruction_files(effective_agent, output_format, console)
        return

    # 1a. EAGERLY start the mapper daemon BEFORE any other expensive work.
    _cache_dir = target / ".ails" / ".cache"
    _suppress_ml_noise()
    try:
        from reporails_cli.core.mapper.daemon_client import ensure_daemon

        ensure_daemon(_cache_dir)
    except (ImportError, OSError):
        pass

    show_progress = sys.stdout.isatty() and output_format not in ("json", "github")

    spinner = console.status("[bold]Discovering files...[/bold]") if show_progress else nullcontext()

    start_time = time.perf_counter()

    with spinner:
        # 2. Build map (needed before M probes to enable content_query checks)
        ruleset_map = None
        try:
            if show_progress:
                spinner.update("[bold]Mapping...[/bold]")  # type: ignore[union-attr]

            from reporails_cli.core.mapper.daemon_client import map_ruleset_via_daemon

            ruleset_map = map_ruleset_via_daemon(list(instruction_files), target, _cache_dir)

            if ruleset_map is None:
                # Daemon unreachable (fork failed, Windows, etc.) — fall back
                # to in-process mapping, which still benefits from MapCache.
                if show_progress:
                    spinner.update("[bold]Loading models...[/bold]")  # type: ignore[union-attr]
                ruleset_map = _map_in_process(instruction_files, _cache_dir)
        except (ImportError, RuntimeError) as exc:
            logger.warning("Mapper unavailable: %s. Content checks skipped.", exc)
            if verbose:
                console.print(f"[dim]Mapper unavailable: {exc}. Content checks skipped.[/dim]")

        # 3. Run M probes (mechanical + structural deterministic)
        if show_progress:
            spinner.update("[bold]Running M probes...[/bold]")  # type: ignore[union-attr]
        m_findings = run_m_probes(target, instruction_files, agent=effective_agent)

        # 4. Run content-quality checks + client checks on map
        content_findings: list[LocalFinding] = []
        client_findings: list[LocalFinding] = []
        if ruleset_map is not None:
            if show_progress:
                spinner.update("[bold]Running content checks...[/bold]")  # type: ignore[union-attr]
            content_findings = run_content_quality_checks(ruleset_map, target, instruction_files, agent=effective_agent)
            client_findings = run_client_checks(ruleset_map)

        # 5. Server call (stub — returns None offline)
        if show_progress:
            spinner.update("[bold]Checking server...[/bold]")  # type: ignore[union-attr]
        lint_result = AilsClient().lint(ruleset_map) if ruleset_map is not None else None
        server_report = lint_result.report if lint_result else None
        hints = lint_result.hints if lint_result else ()
        cross_file_coordinates = lint_result.cross_file_coordinates if lint_result else ()

    # 5b. Memory index validation (client-side, reads local filesystem)
    memory_findings: list[LocalFinding] = []
    if ruleset_map is not None:
        from reporails_cli.core.memory_checks import validate_memory_files

        memory_file_paths = [f.path for f in ruleset_map.files]
        memory_findings = validate_memory_files(memory_file_paths)

    # 6. Merge results (content_findings + client_findings + memory_findings go together)
    all_client_findings = content_findings + client_findings + memory_findings
    result = merge_results(
        m_findings,
        all_client_findings,
        server_report,
        hints=hints,
        cross_file_coordinates=cross_file_coordinates,
        project_root=target,
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # 7. Format and display
    if output_format == "json":
        data = json_formatter.format_combined_result(result)
        data["elapsed_ms"] = round(elapsed_ms, 1)
        print(json.dumps(data, indent=2))
    elif output_format == "github":
        from reporails_cli.formatters import github as github_formatter

        print(github_formatter.format_combined_annotations(result))
    else:
        print_text_result(result, elapsed_ms, ascii, verbose, ruleset_map=ruleset_map)

    _show_agent_auto_detect_hint(effective_agent, output_format, assumed, mixed, detected)

    if strict and result.findings:
        raise typer.Exit(1)


def _suppress_ml_noise() -> None:
    """Suppress sentence-transformers/HF stderr noise."""
    import logging as _logging
    import os as _os

    _os.environ["TRANSFORMERS_VERBOSITY"] = "error"
    _os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    _os.environ["TOKENIZERS_PARALLELISM"] = "false"
    _os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
    for lib in ("sentence_transformers", "transformers", "huggingface_hub", "reporails_cli.core.mapper"):
        _logging.getLogger(lib).setLevel(_logging.ERROR)


def _map_in_process(instruction_files: list[Path], cache_dir: Path) -> Any:
    """Run mapper in-process with stderr suppressed. Returns RulesetMap or None.

    Does NOT eagerly call ``get_models().warmup()`` — when the MapCache is
    mostly warm, model loads can be skipped entirely, and an eager warmup
    here would defeat that fast path. The daemon DOES eagerly warm up
    because its models amortize across many requests; the in-process path
    is single-use and should stay lazy.
    """
    import io as _io

    saved_stderr = sys.stderr
    sys.stderr = _io.StringIO()
    try:
        from reporails_cli.core.mapper import map_ruleset

        return map_ruleset(list(instruction_files), cache_dir=cache_dir)
    except (ImportError, RuntimeError) as exc:
        logger.warning("In-process mapper unavailable: %s", exc)
        return None
    finally:
        sys.stderr = saved_stderr


@app.command(rich_help_panel="Commands")
def explain(
    rule_id: str = typer.Argument(..., help="Rule ID (e.g., S1, C2)"),
    rules: list[str] = typer.Option(  # noqa: B008
        None,
        "--rules",
        "-r",
        help="Directory containing rules (repeatable). Same semantics as check --rules.",
    ),
) -> None:
    """Show rule details."""
    rules_paths = _explain_rules_paths(rules)
    rule_id_upper = rule_id.upper()
    agent = infer_agent_from_rule_id(rule_id_upper)  # auto-load agent-namespaced rules
    loaded_rules = load_rules(rules_paths, agent=agent)

    if rule_id_upper not in loaded_rules:
        _print_unknown_rule(rule_id, loaded_rules)
        raise typer.Exit(2)

    rule = loaded_rules[rule_id_upper]
    rule_data = {
        "title": rule.title,
        "category": rule.category.value,
        "type": rule.type.value,
        "slug": rule.slug,
        "match": _serialize_match(rule.match),
        "severity": rule.severity.value,
        "checks": [{"id": c.id, "type": c.type} for c in rule.checks],
        "see_also": rule.see_also,
    }

    # Read description from markdown file if available
    if rule.md_path and rule.md_path.exists():
        content = rule.md_path.read_text(encoding="utf-8")
        parts = content.split("---", 2)
        if len(parts) >= 3:
            rule_data["description"] = parts[2].strip()[:500]

    output = text_formatter.format_rule(rule_id_upper, rule_data)
    console.print(output)


import reporails_cli.interfaces.cli.heal  # noqa: E402  # Register heal command


def main() -> None:
    """Entry point for CLI."""
    app()


import reporails_cli.interfaces.cli.commands  # noqa: E402  # Register commands
import reporails_cli.interfaces.cli.install  # noqa: E402  # Register install command
import reporails_cli.interfaces.cli.test_command  # noqa: F401, E402  # Register test command
from reporails_cli.interfaces.cli.auth_command import auth_app  # noqa: E402
from reporails_cli.interfaces.cli.config_command import config_app  # noqa: E402
from reporails_cli.interfaces.cli.daemon_cmd import daemon_app  # noqa: E402
from reporails_cli.interfaces.cli.stopwords_command import stopwords_app  # noqa: E402

app.add_typer(auth_app, rich_help_panel="Commands")
app.add_typer(config_app, rich_help_panel="Configuration")
app.add_typer(daemon_app, hidden=True)
app.add_typer(stopwords_app, hidden=True)

if __name__ == "__main__":
    main()
