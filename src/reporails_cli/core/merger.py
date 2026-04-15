"""Result merger — combines local findings with server diagnostics.

Deduplicates when server and local checks fire on the same (file, line, rule),
keeping the server version (richer fix text from equation computation).
All file paths are normalized to project-relative before dedup and output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from reporails_cli.core.api_client import (
    CrossFileFinding,
    FileAnalysis,
    QualityResult,
    RulesetReport,
)
from reporails_cli.core.models import LocalFinding

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def normalize_finding_path(file_path: str, project_root: Path | None = None) -> str:
    """Normalize a finding's file path to project-relative.

    Handles absolute paths, relative paths, and external paths (~/.claude/...).
    Ensures all three sources (m_probe, client_check, server) produce the same
    path for the same file, so dedup and display grouping work correctly.

    Priority: project-relative > home-relative > as-is.
    """
    p = Path(file_path)

    # Without project_root, return paths as-is (no resolution)
    if project_root is None:
        return str(p)

    # Resolve to absolute for comparison
    resolved = project_root / p if not p.is_absolute() else p

    # Project-relative first — paths within the project get short relative form
    if project_root is not None:
        try:
            return str(resolved.relative_to(project_root))
        except ValueError:
            pass  # Not within project — fall through

    # External paths (outside project) — shorten with ~/
    home = Path.home()
    if resolved.is_absolute():
        try:
            return "~/" + str(resolved.relative_to(home))
        except ValueError:
            pass

    # Already relative or fallback
    return str(p)


@dataclass(frozen=True)
class FindingItem:
    """A single finding in the combined output, from any source."""

    file: str
    line: int
    severity: str  # "error" | "warning" | "info"
    rule: str  # theory-native label or rule_id
    message: str
    fix: str = ""
    source: str = "local"  # "m_probe" | "client_check" | "server"
    line_2: int = 0  # secondary line for cross-file findings


@dataclass(frozen=True)
class CombinedStats:
    """Aggregate statistics for the combined result."""

    total_findings: int = 0
    errors: int = 0
    warnings: int = 0
    infos: int = 0
    cross_file_conflicts: int = 0
    cross_file_repetitions: int = 0
    m_probe_count: int = 0
    client_check_count: int = 0
    server_diagnostic_count: int = 0


@dataclass(frozen=True)
class CombinedResult:
    """Merged local + server findings — the output of the new pipeline."""

    findings: tuple[FindingItem, ...] = ()
    cross_file: tuple[CrossFileFinding, ...] = ()
    quality: QualityResult | None = None
    per_file_analysis: tuple[FileAnalysis, ...] = ()
    stats: CombinedStats = field(default_factory=CombinedStats)
    offline: bool = True
    hints: tuple = ()  # tuple[Hint, ...] from tier gating


def merge_results(
    m_probe_findings: list[LocalFinding],
    client_check_findings: list[LocalFinding],
    server_report: RulesetReport | None,
    hints: tuple = (),
    project_root: Path | None = None,
) -> CombinedResult:
    """Merge M-probe findings, client checks, and server diagnostics.

    When server_report is None, returns local findings only with offline=True.
    When present, deduplicates: server diagnostic at same (file, line, rule)
    replaces the local finding. All paths normalized to project-relative.
    """
    _norm = lambda fp: normalize_finding_path(fp, project_root)  # noqa: E731
    items: list[FindingItem] = []

    # Collect server diagnostics and build dedup set
    server_keys: set[tuple[str, int, str]] = set()
    server_count = 0
    cross_file: tuple[CrossFileFinding, ...] = ()
    quality: QualityResult | None = None
    per_file: tuple[FileAnalysis, ...] = ()

    if server_report is not None:
        cross_file = server_report.cross_file
        quality = server_report.quality
        per_file = server_report.per_file

        for fa in server_report.per_file:
            for diag in fa.diagnostics:
                norm_file = _norm(diag.file)
                server_keys.add((norm_file, diag.line, diag.rule))
                items.append(
                    FindingItem(
                        file=norm_file,
                        line=diag.line,
                        severity=diag.severity,
                        rule=diag.rule,
                        message=diag.message,
                        fix=diag.fix,
                        source="server",
                        line_2=diag.line_2,
                    )
                )
                server_count += 1

    # Convert local findings, deduplicating against server
    m_probe_count = 0
    client_count = 0
    for finding in m_probe_findings:
        norm_file = _norm(finding.file)
        key = (norm_file, finding.line, finding.rule)
        if key not in server_keys:
            items.append(
                FindingItem(
                    file=norm_file,
                    line=finding.line,
                    severity=finding.severity,
                    rule=finding.rule,
                    message=finding.message,
                    fix=finding.fix,
                    source="m_probe",
                )
            )
            m_probe_count += 1

    for finding in client_check_findings:
        norm_file = _norm(finding.file)
        key = (norm_file, finding.line, finding.rule)
        if key not in server_keys:
            items.append(
                FindingItem(
                    file=norm_file,
                    line=finding.line,
                    severity=finding.severity,
                    rule=finding.rule,
                    message=finding.message,
                    fix=finding.fix,
                    source="client_check",
                )
            )
            client_count += 1

    # Sort by file, severity, line
    items.sort(key=lambda f: (f.file, _SEVERITY_ORDER.get(f.severity, 9), f.line))

    # Compute stats
    errors = sum(1 for f in items if f.severity == "error")
    warnings = sum(1 for f in items if f.severity == "warning")
    infos = sum(1 for f in items if f.severity == "info")
    conflicts = sum(1 for cf in cross_file if cf.finding_type == "conflict")
    repetitions = sum(1 for cf in cross_file if cf.finding_type == "repetition")

    return CombinedResult(
        findings=tuple(items),
        cross_file=cross_file,
        quality=quality,
        per_file_analysis=per_file,
        stats=CombinedStats(
            total_findings=len(items),
            errors=errors,
            warnings=warnings,
            infos=infos,
            cross_file_conflicts=conflicts,
            cross_file_repetitions=repetitions,
            m_probe_count=m_probe_count,
            client_check_count=client_count,
            server_diagnostic_count=server_count,
        ),
        offline=server_report is None,
        hints=hints,
    )
