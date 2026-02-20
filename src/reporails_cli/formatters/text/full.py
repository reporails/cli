"""Full terminal output formatter.

Provides rich, detailed output for interactive terminal use.
"""
# pylint: disable=too-many-locals

from __future__ import annotations

from reporails_cli.core.models import ScanDelta, ValidationResult
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters.text.box import format_assessment_box
from reporails_cli.formatters.text.violations import format_violations_section


def _format_semantic_cta(
    result: ValidationResult,
) -> str:
    """Format semantic CTA for installed users with partial results."""
    if not result.is_partial:
        return ""
    return "[dim]For full semantic analysis: ails install[/dim]"


def _format_install_cta() -> str:
    """CTA for ephemeral (npx/uvx) users to install permanently."""
    from reporails_cli.core.self_update import is_ephemeral_install

    if not is_ephemeral_install():
        return ""
    return "[dim]Run ails install to enable MCP scoring and faster checks.[/dim]"


def format_result(
    result: ValidationResult,
    ascii_mode: bool | None = None,
    quiet_semantic: bool = False,
    _show_legend: bool = True,
    delta: ScanDelta | None = None,
    show_mcp_cta: bool = True,
    elapsed_ms: float | None = None,
    surface: dict[str, object] | None = None,
) -> str:
    """Format validation result for terminal output."""
    data = json_formatter.format_result(result, delta)

    # Copy violations so injections don't affect scorecard counts
    violations = list(data.get("violations", []))

    # Inject pending semantic checks as inline violations
    if not quiet_semantic:
        violations.extend(
            {
                "rule_id": jr.rule_id,
                "location": jr.location,
                "message": jr.rule_title,
                "severity": "pending",
            }
            for jr in result.judgment_requests
        )

    sections = []

    # Violations first
    sections.append(format_violations_section(violations, ascii_mode))

    # Spacer before scorecard
    sections.append("")

    # Assessment box (scorecard at bottom)
    sections.append(format_assessment_box(data, ascii_mode, delta, elapsed_ms=elapsed_ms, surface=surface))

    # CTA: ephemeral install CTA takes priority over semantic CTA
    if show_mcp_cta:
        install_cta = _format_install_cta()
        if install_cta:
            sections.append("")
            sections.append(install_cta)
        elif result.is_partial and not quiet_semantic:
            cta = _format_semantic_cta(result)
            if cta:
                sections.append("")
                sections.append(cta)

    return "\n".join(sections)
