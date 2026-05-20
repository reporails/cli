"""Typer CLI for reporails - validate and score AI instruction files."""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────
# CRITICAL: torch import blocker MUST run before any import that could
# transitively reach thinc/spacy or sentence-transformers. See the
# module docstring of `_torch_blocker` for the full story — short
# version: spaCy's thinc backend does `try: import torch` as a side
# effect that costs ~20s on cold start. We don't use torch anywhere on
# the CLI critical path; ONNX Runtime + tokenizers handle everything.
from reporails_cli.core.platform.runtime import _torch_blocker

_torch_blocker.install()
# ─────────────────────────────────────────────────────────────────────

import json  # noqa: E402
import logging  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from collections.abc import Callable  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

import typer  # noqa: E402

logger = logging.getLogger(__name__)

from reporails_cli.core.platform.adapters.registry import infer_agent_from_rule_id, load_rules  # noqa: E402
from reporails_cli.core.platform.dto.models import FileMatch, LocalFinding  # noqa: E402
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
    for prop in (
        "format",
        "scope",
        "cardinality",
        "lifecycle",
        "maintainer",
        "vcs",
        "loading",
        "precedence",
        "loading_verb",
        "link_source_type",
    ):
        val = getattr(match, prop)
        if val is not None:
            result[prop] = val
    return result


def _explain_rules_paths(rules: list[str] | None) -> list[Path] | None:
    """Resolve rules paths for explain command."""
    if rules:
        return [Path(r).resolve() for r in rules]
    return None


def _resolve_rule_token(token: str) -> str:
    """Map either a rule ID or a rule slug to a canonical ID."""
    if ":" in token:
        return token.upper()
    from reporails_cli.core.platform.adapters.rules_query import load_all_rules

    for rule in load_all_rules():
        if rule.slug == token:
            return rule.id
    return token


@app.command(rich_help_panel="Commands")
def check(  # noqa: C901  # pylint: disable=too-many-locals
    targets: list[str] = typer.Argument(  # noqa: B008
        None,
        help=(
            "Targets to check. Each token is `capability:name` (`skill:backlog`), "
            "`@capability` (`@skill` for all skills), or a path (`./CLAUDE.md`). "
            "Repeatable and mixable. No targets = whole-project scan."
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
    exclude_dirs: list[str] = typer.Option(None, "--exclude-dirs", help="Directories to exclude"),  # noqa: B008
    ascii: bool = typer.Option(False, "--ascii", "-a", help="ASCII characters only"),
    strict: bool = typer.Option(False, "--strict", help="Exit code 1 if violations found"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show details"),
    heal: bool = typer.Option(False, "--heal", help="Apply auto-fixes after validation."),
    dry_run: bool = typer.Option(False, "--dry-run", help="With --heal: preview fixes without writing."),
) -> None:
    """Validate AI instruction files against reporails rules.

    Each positional target is a `capability:name`, `@capability`, or path.
    Capability vocabulary comes from the detected agent's
    `framework/rules/<agent>/config.yml` `file_types:` keys.
    """
    from contextlib import nullcontext

    from reporails_cli.core.discovery.agents import detect_agents, get_all_instruction_files
    from reporails_cli.core.lint.client_checks import run_client_checks
    from reporails_cli.core.lint.rule_runner import run_content_quality_checks, run_m_probes
    from reporails_cli.core.platform.adapters.api_client import AilsClient
    from reporails_cli.core.platform.config.config import get_project_config
    from reporails_cli.core.platform.runtime.merger import merge_results

    project_root = Path.cwd().resolve()

    capability_specs: list[tuple[str, str]] = []
    path_targets: set[Path] = set()
    if targets:
        sniff_agent = _sniff_agent(agent, project_root)
        for token in targets:
            kind, payload = _classify_target_token(token, sniff_agent, project_root)
            if kind == "capability":
                capability_specs.append(payload)  # type: ignore[arg-type]
            else:
                resolved_path = payload  # type: ignore[assignment]
                if not resolved_path.exists():
                    console.print(f"[red]Error:[/red] Path not found: {resolved_path}")
                    raise typer.Exit(2)
                path_targets.add(resolved_path)

    # Single-path-only mode: scope discovery to that path (matches the
    # pre-variadic single-target behavior for empty-dir and single-file
    # cases). Mixed or multi-target invocations stay rooted at cwd so all
    # tokens see the full discovery set.
    if path_targets and not capability_specs and len(path_targets) == 1:
        target = next(iter(path_targets))
    else:
        target = project_root

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
    # When `target` is a specific path (not project_root), drop user-scope
    # and other paths outside the target subtree — `get_all_instruction_files`
    # collects per-agent patterns including `~/.claude/CLAUDE.md` regardless of
    # target, which would otherwise mask "no project files for this agent".
    if target != project_root:
        instruction_files = [
            f for f in instruction_files
            if f == target or (target.is_dir() and f.resolve().is_relative_to(target.resolve()))
        ]
    if not instruction_files:
        _handle_no_instruction_files(effective_agent, output_format, console)
        return

    # Single-path mode already narrowed discovery via `target`; nothing
    # more to do. Otherwise build the upfront path filter from capability
    # specs and (multi-)path tokens and narrow `instruction_files`.
    single_path_mode = bool(path_targets and not capability_specs and len(path_targets) == 1)
    upfront_paths: set[Path] = set()
    if not single_path_mode:
        if capability_specs:
            upfront_paths |= _resolve_capability_paths(capability_specs, effective_agent, project_root, excl)
        if path_targets:
            upfront_paths |= set(_narrow_to_path_targets(instruction_files, path_targets))
        if (capability_specs or path_targets) and not upfront_paths:
            _handle_no_instruction_files(effective_agent, output_format, console)
            return
        if upfront_paths:
            instruction_files = [f for f in instruction_files if f in upfront_paths]
            if not instruction_files:
                _handle_no_instruction_files(effective_agent, output_format, console)
                return

    # 1a. EAGERLY start the global mapper daemon BEFORE any other expensive work.
    _suppress_ml_noise()

    show_progress = sys.stdout.isatty() and output_format not in ("json", "github")
    _progress: Callable[[str], None] = (
        (lambda msg: print(msg, file=sys.stderr, flush=True)) if verbose and not show_progress else (lambda _: None)
    )

    spinner = console.status("[bold]Starting...[/bold]") if show_progress else nullcontext()

    start_time = time.perf_counter()

    with spinner:
        try:
            from reporails_cli.core.mapper.daemon_client import ensure_daemon

            _progress("Starting mapper daemon...")
            ensure_daemon()
        except (ImportError, OSError):
            pass

        # 2. Build map (needed before M probes to enable content_query checks)
        ruleset_map = None
        try:
            if show_progress:
                spinner.update("[bold]Mapping...[/bold]")  # type: ignore[union-attr]
            _progress("Mapping instruction files...")

            from reporails_cli.core.mapper.daemon_client import map_ruleset_via_daemon

            ruleset_map = map_ruleset_via_daemon(list(instruction_files), target)

            if ruleset_map is None:
                # Daemon unreachable (fork failed, Windows, etc.) — fall back
                # to in-process mapping, which still benefits from MapCache.
                _progress("Daemon unavailable, loading models in-process...")
                if show_progress:
                    spinner.update("[bold]Loading models...[/bold]")  # type: ignore[union-attr]
                ruleset_map = _map_in_process(instruction_files)
        except (ImportError, RuntimeError) as exc:
            logger.warning("Mapper unavailable: %s. Content checks skipped.", exc)
            if verbose:
                console.print(f"[dim]Mapper unavailable: {exc}. Content checks skipped.[/dim]")

        # 3. Run M probes (mechanical + structural deterministic)
        if show_progress:
            spinner.update("[bold]Running M probes...[/bold]")  # type: ignore[union-attr]
        _progress("Running M probes...")
        m_findings = run_m_probes(target, instruction_files, agent=effective_agent)

        # 4. Run content-quality checks + client checks on map
        content_findings: list[LocalFinding] = []
        client_findings: list[LocalFinding] = []
        if ruleset_map is not None:
            if show_progress:
                spinner.update("[bold]Running content checks...[/bold]")  # type: ignore[union-attr]
            _progress("Running content checks...")
            content_findings = run_content_quality_checks(ruleset_map, target, instruction_files, agent=effective_agent)
            client_findings = run_client_checks(ruleset_map)

        # 5. Server call (stub — returns None offline)
        if show_progress:
            spinner.update("[bold]Checking server...[/bold]")  # type: ignore[union-attr]
        response = AilsClient().lint(ruleset_map) if ruleset_map is not None else None
        lint_result = response.result if response else None
        funnel_error = response.funnel_error if response else None
        server_report = lint_result.report if lint_result else None
        hints = lint_result.hints if lint_result else ()
        cross_file_coordinates = lint_result.cross_file_coordinates if lint_result else ()

    # 5b. Memory index validation (client-side, reads local filesystem)
    memory_findings: list[LocalFinding] = []
    if ruleset_map is not None:
        from reporails_cli.core.lint.memory_checks import validate_memory_files

        memory_file_paths = [f.path for f in ruleset_map.files]
        memory_findings = validate_memory_files(memory_file_paths)

    # 6. Compute project capability level (per docs/capability-levels.md ladder)
    from reporails_cli.core.discovery.features import detect_features_filesystem
    from reporails_cli.core.platform.policy.levels import determine_level_from_gates

    project_features = detect_features_filesystem(target, agents=filtered)
    project_level = determine_level_from_gates(project_features)

    # 7. Merge results (content_findings + client_findings + memory_findings go together)
    all_client_findings = content_findings + client_findings + memory_findings
    result = merge_results(
        m_findings,
        all_client_findings,
        server_report,
        hints=hints,
        cross_file_coordinates=cross_file_coordinates,
        project_root=target,
        level=project_level,
        tier=lint_result.tier if lint_result else "",
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # 7. Path filter for the display: reuse the upfront-narrow set so
    # display, heal pass, and strict-exit all see the same path set. For
    # single-path mode with a file target, narrow display to that file
    # (matches the pre-variadic single-file behavior).
    capability_paths = upfront_paths
    if single_path_mode and target.is_file():
        capability_paths = {target.resolve()}

    # 8. Filter result + ruleset_map to capability_paths so every rendered
    # block (file cards, surface-health, scorecard) sees the same set.
    from reporails_cli.formatters.text.display import filter_result_to_paths, filter_ruleset_map_to_paths

    if capability_paths:
        display_result = filter_result_to_paths(result, capability_paths, project_root)
        display_map = filter_ruleset_map_to_paths(ruleset_map, capability_paths, project_root)
    else:
        display_result = result
        display_map = ruleset_map

    if not (heal and output_format == "json"):
        _dispatch_output(
            output_format,
            display_result,
            display_map,
            elapsed_ms,
            capability_paths,
            project_root,
            ascii,
            verbose,
            funnel_error,
        )

    _show_agent_auto_detect_hint(effective_agent, output_format, assumed, mixed, detected)

    if heal:
        heal_files = (
            [f for f in instruction_files if f in capability_paths] if capability_paths else instruction_files
        )
        _run_heal_pass(target, heal_files, ruleset_map, effective_agent, dry_run, output_format)

    if _should_exit_strict(strict, capability_paths, project_root, result):
        raise typer.Exit(1)


def _resolve_capability_paths_one(
    capability: str,
    capability_name: str,
    effective_agent: str,
    project_root: Path,
    exclude_dirs: list[str] | tuple[str, ...] | None = None,
) -> set[Path]:
    """Resolve one (capability, name) spec to its file set."""
    from reporails_cli.core.classify.capability_paths import (
        available_capabilities,
        list_capability_targets,
        resolve_capability,
    )
    from reporails_cli.core.classify.focus_expansion import expand_focus

    if not _capability_declared(capability, effective_agent, project_root):
        console.print(
            f"[red]Error:[/red] capability [bold]{capability}[/bold] is not declared "
            f"for agent [bold]{effective_agent}[/bold]. "
            f"Available: {', '.join(available_capabilities(effective_agent, project_root)) or '(none)'}"
        )
        raise typer.Exit(2)
    if not capability_name:
        return set(list_capability_targets(effective_agent, capability, project_root, exclude_dirs))
    resolved = resolve_capability(effective_agent, capability, capability_name, project_root)
    if resolved is None:
        available = list_capability_targets(effective_agent, capability, project_root, exclude_dirs)
        console.print(
            f"[red]Error:[/red] no {capability} named [bold]{capability_name}[/bold] "
            f"for agent [bold]{effective_agent}[/bold] under {project_root}."
        )
        if available:
            console.print(
                f"[dim]Found {len(available)} {capability}(s) — run `ails check @{capability}` to list.[/dim]"
            )
        raise typer.Exit(2)
    paths = {resolved}
    if capability == "agents":
        paths = expand_focus(paths, effective_agent, project_root)
    return paths


def _resolve_capability_paths(
    specs: list[tuple[str, str]],
    effective_agent: str,
    project_root: Path,
    exclude_dirs: list[str] | tuple[str, ...] | None = None,
) -> set[Path]:
    """Union of every (capability, name) spec resolved against the agent's vocabulary."""
    paths: set[Path] = set()
    for capability, capability_name in specs:
        paths |= _resolve_capability_paths_one(
            capability, capability_name, effective_agent, project_root, exclude_dirs
        )
    return paths


def _classify_target_token(
    token: str, sniff_agent: str, project_root: Path
) -> tuple[str, tuple[str, str] | Path]:
    """Classify one CLI token as 'capability', 'all-capability', or 'path'.

    Returns ("capability", (cap, name)), ("capability", (cap, "")), or ("path", Path).
    Capability tokens are canonicalized through the agent vocabulary.
    """
    from reporails_cli.core.classify.capability_paths import canonicalize_capability

    if token.startswith("@"):
        cap = token[1:]
        canonical = canonicalize_capability(cap, sniff_agent, project_root) if sniff_agent else None
        if canonical is not None:
            return ("capability", (canonical, ""))
        return ("capability", (cap, ""))
    if ":" in token:
        cap, name = token.split(":", 1)
        canonical = canonicalize_capability(cap, sniff_agent, project_root) if sniff_agent else None
        if canonical is not None:
            return ("capability", (canonical, name))
        return ("capability", (cap, name))
    return ("path", Path(token).resolve())


def _narrow_to_path_targets(instruction_files: list[Path], path_targets: set[Path]) -> list[Path]:
    """Keep only instruction files that are equal to or beneath one of `path_targets`."""
    narrowed: list[Path] = []
    for f in instruction_files:
        f_res = f.resolve()
        for tgt in path_targets:
            if tgt.is_file() and f_res == tgt:
                narrowed.append(f)
                break
            if tgt.is_dir() and (f_res == tgt or f_res.is_relative_to(tgt)):
                narrowed.append(f)
                break
    return narrowed


def _sniff_agent(agent: str, project_root: Path) -> str:
    """Detect the agent to use for capability-vocabulary lookups during token classification."""
    from reporails_cli.core.discovery.agents import detect_agents
    from reporails_cli.core.platform.config.config import get_project_config

    if agent:
        return agent
    try:
        cfg = get_project_config(project_root)
        if cfg.default_agent:
            return cfg.default_agent
    except (OSError, ValueError):
        pass
    for det in detect_agents(project_root):
        return det.agent_type.id
    return ""


def _capability_declared(capability: str, effective_agent: str, project_root: Path) -> bool:
    """True when `capability` is declared (config) or virtual (synthesized) for the agent.

    Virtual capabilities — `referenced` — are agent-agnostic; they're
    synthesized by the classifier rather than declared in any agent config.
    """
    from reporails_cli.core.classify.capability_paths import (
        _CAPABILITY_FOLD,
        _VIRTUAL_CAPABILITIES,
        available_capabilities,
    )

    if capability in _VIRTUAL_CAPABILITIES:
        return True
    decls = available_capabilities(effective_agent, project_root)
    if capability in decls:
        return True
    fold = _CAPABILITY_FOLD.get(capability)
    return bool(fold and any(f in decls for f in fold))


def _relativize_paths(paths: set[Path], project_root: Path) -> set[str]:
    return {str(p.relative_to(project_root)) if p.is_relative_to(project_root) else str(p) for p in paths}


def _dispatch_output(
    output_format: str,
    display_result: Any,
    ruleset_map: Any,
    elapsed_ms: float,
    capability_paths: set[Path],
    project_root: Path,
    ascii_mode: bool,
    verbose: bool,
    funnel_error: Any,
) -> None:
    """Route formatted output to JSON / GitHub / text."""
    from reporails_cli.formatters import json as json_formatter

    if output_format == "json":
        data = json_formatter.format_combined_result(display_result, ruleset_map=ruleset_map)
        data["elapsed_ms"] = round(elapsed_ms, 1)
        if capability_paths:
            data["capability_paths"] = sorted(_relativize_paths(capability_paths, project_root))
        print(json.dumps(data, indent=2))
        return
    if output_format == "github":
        from reporails_cli.formatters import github as github_formatter

        print(github_formatter.format_combined_annotations(display_result))
        return
    print_text_result(
        display_result, elapsed_ms, ascii_mode, verbose, ruleset_map=ruleset_map, funnel_error=funnel_error
    )


def _run_heal_pass(
    target: Path,
    instruction_files: list[Path],
    ruleset_map: Any,
    effective_agent: str,
    dry_run: bool,
    output_format: str,
) -> None:
    """Apply mechanical + additive fixers using the already-built map."""
    from reporails_cli.interfaces.cli.heal import (
        _apply_additive_fixes,
        _apply_mechanical_fixes,
        _output_heal_results,
    )

    show = sys.stdout.isatty() and output_format != "json"
    heal_start = time.perf_counter()
    mech = _apply_mechanical_fixes(ruleset_map, target, dry_run, show, console)
    additive = _apply_additive_fixes(target, instruction_files, effective_agent, dry_run, show, console)
    heal_ms = round((time.perf_counter() - heal_start) * 1000, 1)
    _output_heal_results(mech + additive, mech, additive, dry_run, heal_ms, output_format, console)


def _should_exit_strict(
    strict: bool,
    capability_paths: set[Path],
    project_root: Path,
    result: Any,
) -> bool:
    if not strict:
        return False
    if capability_paths:
        rel_keys = _relativize_paths(capability_paths, project_root)
        return any(f.file in rel_keys for f in result.findings)
    return bool(result.findings)


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


def _map_in_process(instruction_files: list[Path]) -> Any:
    """Run mapper in-process with stderr suppressed. Returns RulesetMap or None.

    Does NOT eagerly call ``get_models().warmup()`` — when the MapCache is
    mostly warm, model loads can be skipped entirely, and an eager warmup
    here would defeat that fast path. The daemon DOES eagerly warm up
    because its models amortize across many requests; the in-process path
    is single-use and should stay lazy.
    """
    import io as _io

    from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir

    saved_stderr = sys.stderr
    sys.stderr = _io.StringIO()
    try:
        from reporails_cli.core.mapper import map_ruleset

        return map_ruleset(list(instruction_files), cache_dir=get_global_cache_dir())
    except (ImportError, RuntimeError) as exc:
        logger.warning("In-process mapper unavailable: %s", exc)
        return None
    finally:
        sys.stderr = saved_stderr


@app.command(rich_help_panel="Commands")
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
        help="Directory containing rules (repeatable). Same semantics as check --rules.",
    ),
) -> None:
    """Show rule details — accepts either a rule ID or a rule slug."""
    rules_paths = _explain_rules_paths(rules)
    rule_id_upper = _resolve_rule_token(rule_id)
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


def main() -> None:
    """Entry point for CLI."""
    app()


import reporails_cli.interfaces.cli.checks_command  # noqa: E402, F401  # list_checks helper backing rules_command
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
