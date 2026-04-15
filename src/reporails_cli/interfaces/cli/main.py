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

    # 5b. Memory index validation (client-side, reads local filesystem)
    memory_findings: list[LocalFinding] = []
    if ruleset_map is not None:
        from reporails_cli.core.memory_checks import validate_memory_files

        memory_file_paths = [f.path for f in ruleset_map.files]
        memory_findings = validate_memory_files(memory_file_paths)

    # 6. Merge results (content_findings + client_findings + memory_findings go together)
    all_client_findings = content_findings + client_findings + memory_findings
    result = merge_results(m_findings, all_client_findings, server_report, hints=hints, project_root=target)
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
        _print_text_result(result, elapsed_ms, ascii, verbose, ruleset_map=ruleset_map)

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
    except (ImportError, RuntimeError):
        return None
    finally:
        sys.stderr = saved_stderr


# Diagnostics NOT in this set are displayed as structural findings (top of card).
# This includes: "general" (no atoms), memory-*, description-mismatch, and any
# new diagnostics — they appear as actionable structural items by default.
_AGGREGATE_RULES = {
    # Equation diagnostics — per-atom
    "CORE:C:0042",
    "CORE:E:0004",
    "CORE:C:0043",
    "CORE:E:0003",
    # Equation diagnostics — interaction
    "CORE:C:0041",
    "CORE:C:0044",
    "CORE:C:0046",
    "CORE:C:0047",
    "CORE:D:0002",
    "CORE:C:0051",
    "CORE:C:0050",
    "CORE:C:0040",
    # Client check labels
    "format",
    "bold",
    "orphan",
    "heading_instruction",
    "ordering",
    "scope",
    # Classifier confidence
    "ambiguous_charge",
}
_AGGREGATE_LABELS: dict[str, str] = {
    "CORE:C:0042": "vague",
    "CORE:E:0004": "brief",
    "CORE:C:0043": "weak",
    "CORE:E:0003": "bold issues",
    "CORE:C:0041": "diluted",
    "CORE:C:0044": "competing",
    "CORE:C:0046": "conflicting",
    "CORE:C:0047": "buried",
    "CORE:D:0002": "unbalanced",
    "CORE:C:0051": "weak overall",
    "CORE:C:0050": "low coverage",
    "CORE:C:0040": "redundant",
    "format": "unformatted",
    "bold": "bold",
    "orphan": "orphan",
    "heading_instruction": "heading as instruction",
    "ordering": "misordered",
    "scope": "broad scope",
    "ambiguous_charge": "ambiguous",
}
_AGG_ORDER = [
    "CORE:C:0042",
    "CORE:E:0004",
    "CORE:C:0043",
    "format",
    "CORE:E:0003",
    "bold",
    "ordering",
    "orphan",
    "heading_instruction",
    "scope",
    "ambiguous_charge",
    "CORE:C:0044",
    "CORE:C:0041",
    "CORE:C:0047",
    "CORE:D:0002",
    "CORE:C:0046",
    "CORE:C:0051",
    "CORE:C:0050",
    "CORE:C:0040",
]
_SEV_WEIGHT = {"error": 0, "warning": 1, "info": 2}
_HRULE = "\u2500" * 56


def _get_sev_icons(ascii_mode: bool) -> dict[str, str]:
    if ascii_mode:
        return {"error": "[red]![/red]", "warning": "[yellow]![/yellow]", "info": "[dim]-[/dim]"}
    return {"error": "[red]\u2717[/red]", "warning": "[yellow]\u26a0[/yellow]", "info": "[dim]\u2139[/dim]"}


def _classify_file(filepath: str) -> str:
    """Classify a file path into a human-readable type tag."""
    p = Path(filepath)
    name = p.name
    parts = p.parts

    # Skills: .claude/skills/<name>/SKILL.md
    if "skills" in parts and name == "SKILL.md":
        idx = parts.index("skills")
        if idx + 1 < len(parts) - 1:
            return f"skill:{parts[idx + 1]}"
        return "skill"

    # Agents: .claude/agents/<name>.md
    if "agents" in parts and name.endswith(".md"):
        return f"agent:{p.stem}"

    # Rules: .claude/rules/<name>.md
    if "rules" in parts and name.endswith(".md"):
        return f"rule:{p.stem}"

    # Config: settings.json, .mcp.json, config.yml
    if name in ("settings.json", ".mcp.json", "config.yml", "settings.local.json"):
        return "config"

    # Memory
    if "memory" in parts:
        return "memory"

    # Main instruction files (including tests/CLAUDE.md)
    upper = name.upper()
    if upper in ("CLAUDE.MD", "AGENTS.MD", ".CURSORRULES", ".WINDSURFRULES", "COPILOT-INSTRUCTIONS.MD"):
        return "main"

    return "file"


def _file_type_summary(filepaths: set[str]) -> str:
    """Build a compact type breakdown like '1 main, 8 rules, 3 skills'."""
    from collections import Counter

    type_counts: Counter[str] = Counter()
    for fp in filepaths:
        tag = _classify_file(fp)
        base = tag.split(":")[0]
        type_counts[base] += 1

    order = ["main", "rule", "skill", "agent", "config", "memory", "file"]
    plurals = {
        "main": "main",
        "rule": "rules",
        "skill": "skills",
        "agent": "agents",
        "config": "configs",
        "memory": "memory",
        "file": "files",
    }
    # No special handling needed — tests already classified as main
    parts = []
    for t in order:
        n = type_counts.get(t, 0)
        if n > 0:
            label = plurals.get(t, t) if n > 1 else t
            parts.append(f"{n} {label}")
    return ", ".join(parts)


def _per_file_stats(filepath: str, ruleset_map: Any) -> str:
    """Compute per-file stats from RulesetMap atoms. Returns compact stat string."""
    if ruleset_map is None:
        return ""
    try:
        # Require at least a filename-length match to avoid "." matching everything
        if len(filepath) < 3:
            return ""
        # Atom file_path may be absolute; finding filepath is relative.
        # Normalize both to project-relative for comparison.
        from reporails_cli.core.merger import normalize_finding_path

        project_root = Path.cwd()
        norm_target = normalize_finding_path(filepath, project_root)
        atoms = [a for a in ruleset_map.atoms if normalize_finding_path(a.file_path, project_root) == norm_target]
    except (AttributeError, TypeError):
        return ""
    if not atoms:
        return ""

    n_dir = sum(1 for a in atoms if a.charge_value == +1)
    n_con = sum(1 for a in atoms if a.charge_value == -1)
    n_amb = sum(1 for a in atoms if a.ambiguous)
    n_total = len(atoms)
    n_charged = n_dir + n_con
    prose_pct = round(100 * (n_total - n_charged) / n_total) if n_total else 0

    instr_parts = []
    if n_dir:
        instr_parts.append(f"{n_dir} dir")
    if n_con:
        instr_parts.append(f"{n_con} con")
    if n_amb:
        instr_parts.append(f"{n_amb} amb")
    instr_str = " / ".join(instr_parts) if instr_parts else "0 instr"

    return f"{instr_str} \u00b7 {prose_pct}% prose"


def _get_group_atoms(
    group_key: str,  # noqa: ARG001
    group_files: list[tuple[str, list[Any]]],
    ruleset_map: Any,
) -> list[Any]:
    """Get all atoms belonging to files in this group."""
    if ruleset_map is None:
        return []
    try:
        from reporails_cli.core.merger import normalize_finding_path

        project_root = Path.cwd()
        norm_fps = {normalize_finding_path(fp, project_root) for fp, _ in group_files}
        return [a for a in ruleset_map.atoms if normalize_finding_path(a.file_path, project_root) in norm_fps]
    except (AttributeError, TypeError):
        return []


def _friendly_name(filepath: str, tag: str) -> str:
    """Extract a friendly display name from the tag. Falls back to filename."""
    if ":" in tag:
        return tag.split(":", 1)[1]
    p = Path(filepath)
    # Include parent directory for disambiguation when name alone is ambiguous
    if p.parent.name and p.parent.name != ".":
        return f"{p.parent.name}/{p.name}"
    return p.name


def _group_stats_line(atoms: list[Any]) -> str:
    """Build a stats summary for a group of atoms."""
    n_dir = sum(1 for a in atoms if a.charge_value == +1)
    n_con = sum(1 for a in atoms if a.charge_value == -1)
    n_total = len(atoms)
    prose_pct = round(100 * (n_total - n_dir - n_con) / n_total) if n_total else 0
    instr_parts = []
    if n_dir:
        instr_parts.append(f"{n_dir} directive")
    if n_con:
        instr_parts.append(f"{n_con} constraint")
    instr_str = " / ".join(instr_parts) if instr_parts else "0 instructions"
    return f"{instr_str} \u00b7 {prose_pct}% prose"


def _get_term_width() -> int:
    """Get terminal width, defaulting to 80."""
    import shutil

    return shutil.get_terminal_size((80, 24)).columns


def _truncate(text: str, max_len: int) -> str:
    """Truncate text to max_len, adding ellipsis if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "\u2026"


def _print_file_card(
    filepath: str,
    findings: list[Any],
    sev_icons: dict[str, str],
    verbose: bool,
    ruleset_map: Any = None,
) -> None:
    """Print one file's card: name, stats, structural findings, then quality aggregate."""
    from collections import Counter

    quality_counts: Counter[str] = Counter()
    structural: list[Any] = []
    for f in findings:
        if f.rule in _AGGREGATE_RULES:
            quality_counts[f.rule] += 1
        else:
            structural.append(f)

    tag = _classify_file(filepath)
    name = _friendly_name(filepath, tag)
    stats = _per_file_stats(filepath, ruleset_map)
    b = "\u2502"
    tw = _get_term_width()
    # Prefix: "  │    ⚠ L42   " ≈ 18 chars; suffix: "  CORE:C:0003" ≈ 17 chars
    msg_width = tw - 35

    # Line 1: friendly name + stats
    stats_str = f"  [dim]{stats}[/dim]" if stats else ""
    console.print(f"  [dim]{b}[/dim] [bold]{name}[/bold]{stats_str}")
    if verbose:
        short = _short_path(filepath)
        # Only show path if it differs from the friendly name
        if short != name:
            console.print(f"  [dim]{b}   {short}[/dim]")

    # Structural findings first (M1/M2 — actionable)
    structural.sort(key=lambda f: _SEV_WEIGHT.get(f.severity, 9))
    limit = 2 if not verbose else 999
    for f in structural[:limit]:
        icon = sev_icons.get(f.severity, " ")
        raw = f.message or ""
        msg = _truncate(raw, msg_width).replace("[", "\\[")
        line_ref = f"L{f.line:<4d} " if f.line > 1 else "      "
        rule_id = f.rule.replace("[", "\\[")
        console.print(f"  [dim]{b}[/dim]   {icon} {line_ref}{msg}  [dim]{rule_id}[/dim]")
    if len(structural) > limit:
        console.print(f"  [dim]{b}     ... and {len(structural) - limit} more[/dim]")

    # Quality: verbose shows per-finding lines (deduped), compact shows aggregate counts
    if verbose:
        quality_findings = [f for f in findings if f.rule in _AGGREGATE_RULES]
        quality_findings.sort(key=lambda f: (f.line, f.rule))
        # Dedup: group by (line, message, rule) — same diagnostic on same line is noise
        seen: dict[tuple[int, str, str], int] = {}
        for f in quality_findings:
            msg = f.message or _AGGREGATE_LABELS.get(f.rule, f.rule)
            key = (f.line, msg, f.rule)
            seen[key] = seen.get(key, 0) + 1
        for (line, msg, rule), count in seen.items():
            line_ref = f"L{line:<4d} " if line > 1 else "      "
            suffix = f" ({count}\u00d7)" if count > 1 else ""
            full = f"{msg}{suffix}"
            console.print(f"  [dim]{b}     {line_ref}{_truncate(full, msg_width)}  {rule}[/dim]")
    else:
        parts = [f"{quality_counts[rule]} {_AGGREGATE_LABELS[rule]}" for rule in _AGG_ORDER if rule in quality_counts]
        if parts:
            agg_line = " \u00b7 ".join(parts)
            console.print(f"  [dim]{b}     {_truncate(agg_line, tw - 8)}[/dim]")

    console.print(f"  [dim]{b}[/dim]")


def _compute_score(result: Any, has_quality: bool, n_atoms: int = 0) -> float:
    """Compute a 0-10 display score from compliance band + finding severity.

    Band sets the base range, severity rates adjust within it.
    Rates are relative to instruction count so larger projects
    aren't penalized for having more atoms to check.
    Does not expose equation internals.
    """
    s = result.stats
    hint_errors = sum(getattr(h, "error_count", 0) for h in result.hints) if result.hints else 0
    hint_warnings = sum(getattr(h, "warning_count", 0) for h in result.hints) if result.hints else 0
    total_errors = s.errors + hint_errors
    total_warnings = s.warnings + hint_warnings
    total = total_errors + total_warnings + s.infos

    if total == 0:
        return 10.0

    # Base from compliance band (equation ran)
    if has_quality:
        band = result.quality.compliance_band
        base = 8.5 if band == "HIGH" else 5.5 if band == "MODERATE" else 3.0
    else:
        base = 6.0

    # Rate-based penalties — relative to project size
    denom = max(n_atoms, total, 1)
    error_rate = total_errors / denom
    warning_rate = total_warnings / denom

    # Errors are structural problems: -3 at 10% error rate, caps at -4
    error_penalty = min(4.0, error_rate * 30)
    # Warnings are per-atom quality: -1 at 50% warning rate, caps at -2
    warning_penalty = min(2.0, warning_rate * 2)

    score = base - error_penalty - warning_penalty

    return float(round(max(0.0, min(10.0, score)), 1))


def _print_score_line(score: float, tw: int) -> None:
    """Print score with progress bar."""
    bar_width = min(40, tw - 26)
    filled = round(bar_width * score / 10)
    empty = bar_width - filled
    bar = "\u2593" * filled + "\u2591" * empty

    color = "green" if score >= 7.0 else "yellow" if score >= 4.0 else "red"
    console.print(f"  Score: [{color} bold]{score:.1f}[/{color} bold] / 10  [dim]{bar}[/dim]")


# Category extraction from rule IDs and client check labels
_RULE_CATEGORY_MAP = {
    "S": "Structure", "C": "Content", "E": "Efficiency",
    "G": "Governance", "D": "Maintenance",
}
_CLIENT_CHECK_CATEGORY = {
    "format": "S", "bold": "E", "orphan": "C", "heading_instruction": "S",
    "ordering": "C", "scope": "S", "ambiguous_charge": "C",
}


def _finding_category(rule: str) -> str:
    """Extract category letter from rule ID or client check label."""
    # CORE:C:0034 → C, CLAUDE:S:0001 → S
    parts = rule.split(":")
    if len(parts) >= 2 and len(parts[1]) == 1 and parts[1].isalpha():
        return parts[1]
    return _CLIENT_CHECK_CATEGORY.get(rule, "C")


def _print_category_bars(findings: tuple[Any, ...], tw: int) -> None:
    """Print per-category finding breakdown with colored bars."""
    from collections import Counter

    cat_counts: Counter[str] = Counter()
    cat_errors: Counter[str] = Counter()
    for f in findings:
        cat = _finding_category(f.rule)
        cat_counts[cat] += 1
        if f.severity == "error":
            cat_errors[cat] += 1

    if not cat_counts:
        return

    max_count = max(cat_counts.values())
    bar_max = min(20, tw - 30)

    console.print()
    for cat_key in ["S", "C", "E", "G", "D"]:
        count = cat_counts.get(cat_key, 0)
        if count == 0:
            continue
        name = _RULE_CATEGORY_MAP.get(cat_key, cat_key)
        bar_len = max(1, round(bar_max * count / max_count))
        has_errors = cat_errors.get(cat_key, 0) > 0
        bar_color = "yellow" if has_errors else "green"
        bar = "\u2588" * bar_len
        pad = " " * (bar_max - bar_len + 1)
        sev_icon = "[red]\u2717[/red]" if has_errors else "[dim]\u25cb[/dim]"
        console.print(f"  {name:<14s}[{bar_color}]{bar}[/{bar_color}]{pad}[dim]{count:>4d}[/dim]  {sev_icon}")
    console.print()


def _print_scorecard(  # noqa: C901
    result: Any, has_quality: bool, n_atoms: int = 0,
    tier: str = "", elapsed_ms: float = 0,
    agent: str = "", type_str: str = "",
    n_dir: int = 0, n_con: int = 0, n_amb: int = 0, n_prose: int = 0,
) -> None:
    """Print the bottom scorecard — the payoff users scroll to."""
    tw = _get_term_width()
    s = result.stats

    hint_errors = sum(getattr(h, "error_count", 0) for h in result.hints) if result.hints else 0
    hint_warnings = sum(getattr(h, "warning_count", 0) for h in result.hints) if result.hints else 0
    total_errors = s.errors + hint_errors
    total_warnings = s.warnings + hint_warnings
    total = total_errors + total_warnings + s.infos

    console.print(f"  [dim]\u2500\u2500 Summary {_HRULE}[/dim]\n")

    # ── Score line ──
    score = _compute_score(result, has_quality, n_atoms)
    bar_width = min(30, tw - 40)
    filled = round(bar_width * score / 10)
    bar = "\u2593" * filled + "\u2591" * (bar_width - filled)
    color = "green" if score >= 7.0 else "yellow" if score >= 4.0 else "red"
    elapsed_s = f"  [dim]({elapsed_ms / 1000:.1f}s)[/dim]" if elapsed_ms else ""
    console.print(f"  Score: [{color} bold]{score:.1f}[/{color} bold] / 10  [dim]{bar}[/dim]{elapsed_s}")

    # ── Agent ──
    agent_name = agent.title() if agent else "auto"
    console.print(f"  Agent: {agent_name}")

    # ── Scope ──
    console.print()
    console.print("  Scope:")
    if type_str:
        console.print(f"    capabilities: {type_str}")
    instr_parts = []
    if n_dir or n_prose:
        instr_parts.append(f"{n_dir} directive / {n_prose} prose ({round(100 * n_prose / n_atoms) if n_atoms else 0}%)")
    if n_con or n_amb:
        con_parts = [f"{n_con} constraint"]
        if n_amb:
            con_parts.append(f"{n_amb} ambiguous")
        instr_parts.append(" / ".join(con_parts))
    if instr_parts:
        console.print(f"    instructions: {instr_parts[0]}")
        for extra in instr_parts[1:]:
            console.print(f"                  {extra}")

    # ── Results ──
    console.print()
    parts = []
    if total_errors:
        parts.append(f"[red]{total_errors} errors[/red]")
    parts.append(f"{total_warnings} warnings")
    parts.append(f"{s.infos} info")
    console.print(f"  {total} findings \u00b7 {' \u00b7 '.join(parts)}")

    if result.cross_file:
        n_conflicts = sum(1 for cf in result.cross_file if cf.finding_type == "conflict")
        n_reps = sum(1 for cf in result.cross_file if cf.finding_type == "repetition")
        cf_parts = []
        if n_conflicts:
            cf_parts.append(f"{n_conflicts} cross-file conflicts")
        if n_reps:
            cf_parts.append(f"{n_reps} cross-file repetitions")
        if cf_parts:
            console.print(f"  {' \u00b7 '.join(cf_parts)}")

    if has_quality:
        band = result.quality.compliance_band
        band_color = "green" if band == "HIGH" else "yellow" if band == "MODERATE" else "red"
        console.print(f"  Compliance: [{band_color}]{band}[/{band_color}]")

    # ── Beta CTA for unauthenticated users ──
    if tier == "free":
        console.print()
        console.print("  [dim]Full diagnostics free for the first 100 registering users during beta[/dim]")
        console.print("  [bold]ails auth login[/bold]")

    console.print()


def _print_text_result(  # noqa: C901
    result: object,
    elapsed_ms: float,
    ascii_mode: bool,
    verbose: bool,
    ruleset_map: object = None,
) -> None:
    """Print compact text output: files sorted worst-first, aggregated counts, scorecard at bottom."""
    from reporails_cli.core.merger import CombinedResult

    if not isinstance(result, CombinedResult):
        return

    # ── Header ──
    # Normalize to relative paths so absolute and relative forms don't double-count
    from reporails_cli.core.merger import normalize_finding_path

    project_root = Path.cwd()
    all_files: set[str] = set()
    if result.findings:
        all_files.update(normalize_finding_path(f.file, project_root) for f in result.findings)
    try:
        from reporails_cli.core.mapper.mapper import RulesetMap

        if isinstance(ruleset_map, RulesetMap):
            all_files.update(normalize_finding_path(fr.path, project_root) for fr in ruleset_map.files)
    except ImportError:
        pass

    # Instruction breakdown from atoms
    n_dir = n_con = n_amb = n_prose = n_total = 0
    try:
        if isinstance(ruleset_map, RulesetMap):
            for a in ruleset_map.atoms:
                n_total += 1
                if a.charge_value == +1:
                    n_dir += 1
                elif a.charge_value == -1:
                    n_con += 1
                if a.ambiguous:
                    n_amb += 1
            n_prose = n_total - n_dir - n_con
    except (ImportError, NameError):
        pass

    has_quality = result.quality is not None and bool(result.quality.compliance_band)
    # Determine display tier: beta if authenticated with beta key, else free/pro
    creds_tier = ""
    try:
        from reporails_cli.interfaces.cli.auth_command import _read_credentials

        creds_tier = _read_credentials().get("tier", "")
    except Exception:
        pass
    if result.offline:
        tier = "offline"
    elif creds_tier == "beta":
        tier = "Pro (beta)"
    elif result.hints:
        tier = "free"
    elif has_quality:
        tier = "Pro"
    else:
        tier = "free"

    type_str = _file_type_summary(all_files) if all_files else "0 files"

    # Detect primary agent from ruleset_map file records
    _detected_agent_name = ""
    try:
        if isinstance(ruleset_map, RulesetMap):
            from collections import Counter as _Ctr

            agent_counts = _Ctr(fr.agent for fr in ruleset_map.files if fr.agent != "generic")
            if agent_counts:
                _detected_agent_name = agent_counts.most_common(1)[0][0]
    except (AttributeError, TypeError):
        pass

    tier_badge = f" — [bold]{tier}[/bold]" if tier and tier != "free" else ""
    console.print(f"\n[bold]Reporails[/bold] — Diagnostics{tier_badge}\n")

    if not result.findings:
        mark = "ok" if ascii_mode else "\u2713"
        console.print(f"  {mark}  No findings.")
        return

    # ── Group files by type ──
    sev_icons = _get_sev_icons(ascii_mode)

    by_file: dict[str, list[Any]] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)

    # Classify each file and group — skip project-level "." findings
    groups: dict[str, list[tuple[str, list[Any]]]] = {}
    for filepath, findings in by_file.items():
        if filepath == "." or filepath == ".:0":
            continue  # Project-level "no matching files" noise
        tag = _classify_file(filepath)
        group_key = tag.split(":")[0]
        groups.setdefault(group_key, []).append((filepath, findings))

    # Sort files within each group by severity then count
    for group_files in groups.values():
        group_files.sort(key=lambda x: (min(_SEV_WEIGHT.get(f.severity, 9) for f in x[1]), -len(x[1])))

    # Display order and labels
    group_order = ["main", "agent", "skill", "rule", "config", "memory"]
    group_labels = {
        "main": "Main",
        "agent": "Agents",
        "skill": "Skills",
        "rule": "Rules",
        "config": "Config",
        "memory": "Memory",
    }

    max_per_group = 3 if not verbose else 999
    total_remaining = 0

    for gkey in group_order:
        group_files = groups.get(gkey, [])
        if not group_files:
            continue

        label = group_labels.get(gkey, gkey.title())
        n_group_findings = sum(len(fs) for _, fs in group_files)
        b = "\u2502"  # left border

        # Group header: top border + stats
        group_atoms = _get_group_atoms(gkey, group_files, ruleset_map)
        stats_str = ""
        if group_atoms:
            stats_str = f"  [dim]{_group_stats_line(group_atoms)}[/dim]"
        console.print(f"  [dim]\u250c\u2500[/dim] [bold]{label}[/bold] [dim]({len(group_files)})[/dim]{stats_str}")

        # File cards with left border
        for i, (filepath, findings) in enumerate(group_files):
            if i >= max_per_group:
                remaining = sum(len(fs) for _, fs in group_files[i:])
                total_remaining += remaining
                n_more = len(group_files) - i
                console.print(f"  [dim]{b}   ... and {n_more} more ({remaining} findings)[/dim]")
                break
            _print_file_card(filepath, findings, sev_icons, verbose, ruleset_map=ruleset_map)

        # Bottom border
        console.print(f"  [dim]\u2514\u2500 {n_group_findings} findings[/dim]\n")

    # ── Hints ──
    if result.hints:
        agg_hints = _aggregate_hints(result.hints)
        if agg_hints:
            console.print(f"  [dim]\u2500\u2500 Hints {_HRULE}[/dim]\n")
            for sev, line in agg_hints:
                icon = sev_icons.get(sev, "\u25cf")
                console.print(f"  {icon}  {line}")
            console.print("\n  [dim]Beta: full diagnostics free \u2192 ails auth login[/dim]")
            console.print()

    _print_scorecard(
        result, has_quality, n_atoms=n_total, tier=tier,
        elapsed_ms=elapsed_ms, agent=_detected_agent_name,
        type_str=type_str, n_dir=n_dir, n_con=n_con,
        n_amb=n_amb, n_prose=n_prose,
    )


def _short_path(file_path: str) -> str:
    """Extract short display path for file headers."""
    p = Path(file_path)
    # Home-relative paths (e.g., ~/.claude/projects/.../memory/MEMORY.md)
    home = Path.home()
    if p.is_absolute():
        try:
            rel = str(p.relative_to(home))
            # Shorten deep ~/.claude/projects/<hash>/memory/X paths
            if "memory" in p.parts:
                idx = p.parts.index("memory")
                return "~/" + str(Path(*p.parts[idx:]))
            return "~/" + rel
        except ValueError:
            pass
    parts = p.parts
    # Shorten relative ~/.claude/projects/<hash>/memory/X paths too
    if "memory" in parts:
        idx = parts.index("memory")
        return str(Path(*parts[idx:]))
    for i, part in enumerate(parts):
        if part in (".claude", "tests"):
            return str(Path(*parts[i:]))
        if part.endswith(".md") and part[:1].isupper():
            return str(Path(*parts[i:]))
    return p.name


_HINT_SEV_ORDER = {"error": 0, "warning": 1, "info": 2}


def _aggregate_hints(hints: tuple[Any, ...]) -> list[tuple[str, str]]:
    """Aggregate per-file hints into system-wide summary lines with severity.

    Returns list of (severity, message) tuples, sorted worst-first.
    """
    by_type: dict[str, list[Any]] = {}
    for h in hints:
        by_type.setdefault(h.diagnostic_type, []).append(h)

    lines: list[tuple[str, str]] = []
    for dtype, group in sorted(by_type.items(), key=lambda x: -len(x[1])):
        n_files = len({h.file for h in group})
        total_count = sum(h.count for h in group)
        s = "s" if total_count != 1 else ""
        # Worst severity across all hints of this type
        worst_sev = min(
            (getattr(h, "severity", "warning") for h in group),
            key=lambda sv: _HINT_SEV_ORDER.get(sv, 9),
        )

        templates: dict[str, str] = {
            "CORE:C:0044": f"{n_files} files have overlapping topics — differentiate with named constructs",
            "CORE:C:0046": f"{total_count} contradicting instruction{s} across {n_files} files",
            "CORE:C:0041": f"{n_files} files have instructions diluted by surrounding content",
            "CORE:C:0051": f"{n_files} files have vague instructions overall",
            "CORE:C:0047": f"{total_count} instruction{s} buried in {n_files} files",
            "CORE:D:0002": f"Unbalanced topics in {n_files} files",
            "CORE:C:0050": f"{n_files} files lack named constructs",
        }
        lines.append((worst_sev, templates.get(dtype, f"{total_count} {dtype} issue{s} in {n_files} files")))

    # Sort by severity (errors first)
    lines.sort(key=lambda x: _HINT_SEV_ORDER.get(x[0], 9))
    return lines


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
