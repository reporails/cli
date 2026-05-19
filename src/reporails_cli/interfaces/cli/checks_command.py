"""`ails list checks` — browse + preflight the framework check registry.

`ails list checks --for=skill` returns the workflow-ordered checks to
follow when authoring a SKILL.md. Default format `text` (compact); `md`
adds Pass / Fail examples; `json` is structured.
"""

from __future__ import annotations

import json as _json
import sys
from collections.abc import Iterable

import typer

from reporails_cli.core.platform.adapters.rules_query import (
    filter_rules_by_capability,
    filter_rules_by_severity,
    list_known_agents,
    load_all_rules,
    load_rule_examples,
    sort_rules_for_authoring,
)
from reporails_cli.core.platform.dto.models import Rule, Severity
from reporails_cli.interfaces.cli.helpers import app, console

list_app = typer.Typer(
    help="List things from the reporails registry (checks, ...).",
    no_args_is_help=True,
)
app.add_typer(list_app, name="list", rich_help_panel="Commands")


@list_app.command(name="checks")
def list_checks(
    capability: str = typer.Option(
        None,
        "--for",
        "-c",
        help="Capability to preflight (`skill`, `agent`, `rule`, `main`, ...).",
    ),
    agent: str = typer.Option(None, "--agent", "-a", help="Restrict to this agent's namespace plus CORE."),
    severity: str = typer.Option(None, "--severity", "-s", help="Minimum severity (`critical|high|medium|low`)."),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text | md | json."),
    no_examples: bool = typer.Option(False, "--no-examples", help="Strip Pass / Fail blocks from md output."),
) -> None:
    """List framework checks, optionally filtered to a capability / agent / severity."""
    agents = [agent] if agent else None
    rules = load_all_rules(agents=agents)
    if capability:
        rules = filter_rules_by_capability(rules, capability)
    if severity:
        rules = filter_rules_by_severity(rules, _parse_severity(severity))
    rules = sort_rules_for_authoring(rules)
    _emit(rules, output_format, capability=capability, agent=agent, no_examples=no_examples)


def _emit(
    rules: list[Rule], output_format: str, *, capability: str | None, agent: str | None, no_examples: bool
) -> None:
    if output_format == "json":
        sys.stdout.write(_json.dumps(_payload(rules, capability=capability, agent=agent), indent=2) + "\n")
        return
    if output_format == "md":
        _print_md(rules, capability=capability, agent=agent, with_examples=not no_examples)
        return
    _print_text(rules, capability=capability, agent=agent)


def _print_text(rules: list[Rule], *, capability: str | None, agent: str | None) -> None:
    if not rules:
        console.print(f"[yellow]No checks match.[/yellow] capability={capability} agent={agent}")
        return
    scope = f"authoring a {capability}" if capability else "registry"
    agent_tag = f" ({agent})" if agent else f" ({', '.join(list_known_agents())})"
    console.print(f"[bold]Checks for {scope}{agent_tag} — {len(rules)} applicable[/bold]")
    console.print()
    by_cat: dict[str, list[Rule]] = {}
    for r in rules:
        by_cat.setdefault(r.category.value, []).append(r)
    for cat in _category_order(by_cat.keys()):
        cat_rules = by_cat[cat]
        console.print(f"[bold]# {cat.title()}[/bold] ({len(cat_rules)})")
        for r in cat_rules:
            console.print(f"  [dim]{r.id:14}[/dim] {r.severity.value:8}  {r.title}")
        console.print()


def _print_md(rules: list[Rule], *, capability: str | None, agent: str | None, with_examples: bool) -> None:
    title = f"Checks for authoring a {capability}" if capability else "Framework checks"
    if agent:
        title += f" ({agent})"
    print(f"# {title}")
    print()
    print("Follow in workflow order: structure → direction → coherence → efficiency → maintenance → governance.")
    print()
    by_cat: dict[str, list[Rule]] = {}
    for r in rules:
        by_cat.setdefault(r.category.value, []).append(r)
    for cat in _category_order(by_cat.keys()):
        cat_rules = by_cat[cat]
        print(f"## {cat.title()} ({len(cat_rules)})")
        print()
        for r in cat_rules:
            _print_md_section(r, with_examples=with_examples)
            print()


def _print_md_section(rule: Rule, *, with_examples: bool) -> None:
    print(f"### {rule.id} — {rule.title} ({rule.severity.value})")
    print()
    body = _read_body(rule)
    if body:
        first_para = body.split("\n\n", 1)[0].strip()
        if first_para:
            print(first_para)
            print()
    if not with_examples:
        return
    examples = load_rule_examples(rule)
    if examples.get("pass"):
        print("**Pass**:")
        print()
        print(examples["pass"])
        print()
    if examples.get("fail"):
        print("**Fail**:")
        print()
        print(examples["fail"])


def _payload(rules: list[Rule], *, capability: str | None, agent: str | None) -> dict[str, object]:
    return {
        "capability": capability,
        "agent": agent,
        "agents_loaded": list_known_agents(),
        "count": len(rules),
        "checks": [_rule_to_dict(r) for r in rules],
    }


def _rule_to_dict(rule: Rule) -> dict[str, object]:
    return {
        "id": rule.id,
        "title": rule.title,
        "slug": rule.slug,
        "category": rule.category.value,
        "severity": rule.severity.value,
        "type": rule.type.value,
        "match": _serialize_match(rule.match),
    }


def _serialize_match(match: object) -> dict[str, object]:
    if match is None:
        return {}
    result: dict[str, object] = {}
    for prop in ("type", "format", "scope", "cardinality", "lifecycle", "maintainer", "vcs", "loading", "precedence"):
        val = getattr(match, prop, None)
        if val is not None:
            result[prop] = val
    return result


def _category_order(present: Iterable[str]) -> list[str]:
    order = ["structure", "direction", "coherence", "efficiency", "maintenance", "governance"]
    present_set: set[str] = set(present)
    out = [c for c in order if c in present_set]
    return out + sorted(present_set - set(order))


def _parse_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError as exc:
        console.print(f"[red]Invalid severity:[/red] {value!r}. Expected: critical, high, medium, low.")
        raise typer.Exit(2) from exc


def _read_body(rule: Rule) -> str:
    if rule.md_path is None or not rule.md_path.exists():
        return ""
    try:
        text = rule.md_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            text = text[end + 4 :]
    return text.lstrip("\n").rstrip()
