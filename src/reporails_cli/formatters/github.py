"""GitHub Actions workflow command formatter.

Emits ::error, ::warning and ::notice workflow commands for inline PR
annotations, plus a JSON line on stdout for machine parsing by composite
actions.

See: https://docs.github.com/en/actions/writing-workflows/
choosing-what-your-workflow-does/workflow-commands-for-github-actions
"""

from __future__ import annotations

import json
from pathlib import Path

from reporails_cli.core.platform.contract.json_value import as_str
from reporails_cli.core.platform.dto.diagnostics import FindingSeverity, Notice
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.runtime.merger import CombinedResult
from reporails_cli.formatters import json as json_formatter


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


def _notice_annotations(notices: tuple[Notice, ...]) -> list[str]:
    """One `::warning` (a `warn` notice) or `::notice` line per notice; announcements get none."""
    return [
        f"::{'warning' if n.level == 'warn' else 'notice'} title=reporails::"
        + _escape_workflow_data(f"{n.text} {n.url}".strip())
        for n in notices
        if n.kind != "promo"
    ]


def _finding_command(severity: FindingSeverity) -> str:
    """The workflow command that carries a finding of this severity."""
    if severity == "error":
        return "error"
    return "notice" if severity == "info" else "warning"


def _finding_annotation(command: str, file_val: str, line: int, title: str, message: str) -> str:
    """One `::error` / `::warning` / `::notice` line for a finding.

    `line` is GitHub's optional annotation property, not a required one: a file-level
    finding (no specific line — e.g. a missing-file or directory-shaped check) carries
    `line=0` internally, and GitHub's own workflow-command grammar has no line 0, so
    emitting it produces a property no documented annotation ever carries. Per GitHub's
    docs, the property is simply omitted for a file-level annotation, so the line clause
    is dropped entirely rather than substituted with an arbitrary line number.
    """
    loc = f"file={file_val},line={line}" if line else f"file={file_val}"
    return f"::{command} {loc},title={title}::{message}"


def format_combined_annotations(
    result: CombinedResult,
    ruleset_map: RulesetMap | None = None,
    project_root: Path | None = None,
    file_type_by_path: dict[str, str] | None = None,
    elapsed_ms: float | None = None,
) -> str:
    """Emit GitHub workflow commands from CombinedResult findings.

    The trailing JSON line is the json formatter's document verbatim, so the
    context arguments are the same ones `--format json` takes and the two
    renderings of one run agree field for field — notably the `surface_health`
    denominators, which collapse to "files that produced findings" when the
    discovery context is missing.

    Args:
        result: CombinedResult from merger
        ruleset_map: Optional RulesetMap for accurate file counts
        project_root: Root to relativize regime keys against (defaults to cwd)
        file_type_by_path: Generic-scan file types, so surface_health routes
            @-imports to the Imported surface consistently with the text view
        elapsed_ms: Scan duration, when the caller has one to attach — matches the
            `elapsed_ms` the `-f json` trailer carries, so a consumer reading either
            format sees the same run duration.
    """

    lines: list[str] = []
    server_error = json_formatter.format_server_error(result.reply.server_error)
    if server_error is not None:
        title = _escape_workflow_property(f"reporails: server {as_str(server_error['error'])}")
        message = _escape_workflow_data(as_str(server_error["message"]))
        lines.append(f"::warning title={title}::{message}")
    lines.extend(_notice_annotations(result.reply.notices))
    for f in result.findings:
        command = _finding_command(f.severity)
        # Canonical rule id, matching the trailing JSON summary's `rule` field.
        title = _escape_workflow_property(f"[{f.rule}]")
        file_val = _escape_workflow_property(f.file)
        message = _escape_workflow_data(f.message)
        lines.append(_finding_annotation(command, file_val, f.line, title, message))

    # JSON summary
    data = json_formatter.format_combined_result(
        result,
        ruleset_map=ruleset_map,
        project_root=project_root,
        file_type_by_path=file_type_by_path,
    )
    if elapsed_ms is not None:
        data["elapsed_ms"] = round(elapsed_ms, 1)
    lines.append(json.dumps(data))
    return "\n".join(lines)
