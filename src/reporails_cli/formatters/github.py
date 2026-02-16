"""GitHub Actions workflow command formatter.

Emits ::error and ::warning workflow commands for inline PR annotations,
plus a JSON line on stdout for machine parsing by composite actions.

See: https://docs.github.com/en/actions/writing-workflows/
choosing-what-your-workflow-does/workflow-commands-for-github-actions
"""

from __future__ import annotations

import json
from typing import Any

from reporails_cli.core.models import ScanDelta, Severity, ValidationResult
from reporails_cli.formatters import json as json_formatter


def _severity_to_command(severity: Severity) -> str:
    """Map violation severity to GitHub workflow command level.

    critical/high → ::error (blocks PR if repo requires it)
    medium/low    → ::warning (shown but non-blocking)
    """
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    return "warning"


def _escape_workflow_property(value: str) -> str:
    """Escape a value for use in workflow command properties.

    Properties (file, line, title) must escape: % \r \n : ,
    """
    out = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return out.replace(":", "%3A").replace(",", "%2C")


def _escape_workflow_data(value: str) -> str:
    """Escape a value for use in workflow command data (message body).

    Data must escape: % \r \n
    """
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def format_annotations(result: ValidationResult) -> str:
    """Emit GitHub workflow commands for each violation.

    Format: ::error file=F,line=L,title=T::message
    """
    lines: list[str] = []

    for v in result.violations:
        command = _severity_to_command(v.severity)

        # Parse file:line from location (e.g. "CLAUDE.md:45")
        if ":" in v.location:
            file_part, line_part = v.location.rsplit(":", 1)
            try:
                line_num = int(line_part)
            except ValueError:
                file_part = v.location
                line_num = 1
        else:
            file_part = v.location
            line_num = 1

        title = _escape_workflow_property(f"[{v.rule_id}] {v.rule_title}")
        file_val = _escape_workflow_property(file_part)
        message = _escape_workflow_data(v.message)

        lines.append(f"::{command} file={file_val},line={line_num},title={title}::{message}")

    return "\n".join(lines)


def format_result(
    result: ValidationResult,
    delta: ScanDelta | None = None,
) -> str:
    """Format validation result as GitHub workflow commands + JSON summary.

    Output:
    - One ::error or ::warning line per violation (for PR annotations)
    - One JSON line at the end (for action output parsing)
    """
    parts: list[str] = []

    annotations = format_annotations(result)
    if annotations:
        parts.append(annotations)

    # JSON summary on last line for machine parsing
    data: dict[str, Any] = json_formatter.format_result(result, delta)
    parts.append(json.dumps(data))

    return "\n".join(parts)
