"""Tests for the GitHub Actions workflow command formatter.

Tests cover:
- Severity mapping (critical/high → error, medium/low → warning)
- File:line parsing from violation location
- Special character escaping (colons, commas, newlines)
- Empty violations → no annotations
- JSON line is valid and contains score/level
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.diagnostics import FunnelError
from reporails_cli.core.platform.dto.models import Level, Severity, Violation
from reporails_cli.core.platform.dto.results import FrictionEstimate, ScanDelta, ValidationResult
from reporails_cli.core.platform.runtime.merger import CombinedResult, CombinedStats
from reporails_cli.formatters import github as github_formatter


def _make_violation(
    rule_id: str = "CORE:S:0005",
    rule_title: str = "Instruction File Size Limit",
    location: str = "CLAUDE.md:45",
    message: str = "File exceeds recommended size",
    severity: Severity = Severity.HIGH,
    check_id: str = "CORE:S:0005:check:0001",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_title=rule_title,
        location=location,
        message=message,
        severity=severity,
        check_id=check_id,
    )


def _make_result(
    violations: tuple[Violation, ...] = (),
    score: float = 7.5,
    level: Level = Level.L3,
) -> ValidationResult:
    return ValidationResult(
        score=score,
        level=level,
        violations=violations,
        judgment_requests=(),
        rules_checked=10,
        rules_passed=10 - len(violations),
        rules_failed=len(violations),
        feature_summary="Root file",
        friction=FrictionEstimate(level="small"),
    )


class TestSeverityMapping:
    """Test _severity_to_command mapping."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize(
        "severity, expected",
        [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "warning"),
            (Severity.INFO, "notice"),
        ],
    )
    def test_severity_to_command(self, severity: Severity, expected: str) -> None:
        assert github_formatter._severity_to_command(severity) == expected


class TestLocationParsing:
    """Test file:line parsing from violation location."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize(
        "location, expected_fragment",
        [
            ("CLAUDE.md:45", "file=CLAUDE.md,line=45"),
            ("CLAUDE.md", "file=CLAUDE.md,line=1"),  # no line → default 1
            (".claude/rules/testing.md:12", "file=.claude/rules/testing.md,line=12"),
            ("CLAUDE.md:abc", "file=CLAUDE.md%3Aabc,line=1"),  # non-numeric → default 1
        ],
        ids=["standard", "file-only", "path-with-dir", "non-numeric-line"],
    )
    def test_location_parsing(self, location: str, expected_fragment: str) -> None:
        v = _make_violation(location=location)
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        assert expected_fragment in output


class TestEscaping:
    """Test special character escaping in workflow commands."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize(
        "input_str, expected",
        [
            ("a:b", "a%3Ab"),
            ("a,b", "a%2Cb"),
            ("100%", "100%25"),
            ("a\nb", "a%0Ab"),
            ("a\rb", "a%0Db"),
        ],
        ids=["colon", "comma", "percent", "newline", "carriage-return"],
    )
    def test_escape_workflow_property(self, input_str: str, expected: str) -> None:
        assert github_formatter._escape_workflow_property(input_str) == expected

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize(
        "input_str, expected",
        [
            ("100%", "100%25"),
            ("line1\nline2", "line1%0Aline2"),
            ("a:b", "a:b"),  # data does NOT escape colons
        ],
        ids=["percent", "newline", "preserves-colon"],
    )
    def test_escape_workflow_data(self, input_str: str, expected: str) -> None:
        assert github_formatter._escape_workflow_data(input_str) == expected

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_title_with_special_chars(self) -> None:
        v = _make_violation(
            rule_id="CORE:S:0012",
            rule_title="Reusable Skills Over Repeated Prompts",
            message="Multi-step procedure found inline",
        )
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        # Colons in rule_id should be escaped in title property
        assert "[CORE%3AS%3A0012]" in output

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_percent_in_message_escaped_before_other_chars(self) -> None:
        """Percent must be escaped first to avoid double-escaping."""
        result = github_formatter._escape_workflow_data("100%\n")
        assert result == "100%25%0A"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_percent_in_property_escaped_before_other_chars(self) -> None:
        result = github_formatter._escape_workflow_property("100%\n:")
        assert result == "100%25%0A%3A"


class TestAnnotations:
    """Test format_annotations output."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_empty_violations_returns_empty(self) -> None:
        result = _make_result(violations=())
        output = github_formatter.format_annotations(result)
        assert output == ""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_single_violation_format(self) -> None:
        v = _make_violation(
            rule_id="CORE:S:0012",
            rule_title="Reusable Skills",
            location="CLAUDE.md:45",
            message="Multi-step procedure found",
            severity=Severity.HIGH,
        )
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        assert output.startswith("::error ")
        assert "file=CLAUDE.md" in output
        assert "line=45" in output
        assert "Multi-step procedure found" in output

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_multiple_violations_one_per_line(self) -> None:
        v1 = _make_violation(severity=Severity.HIGH, location="a.md:1")
        v2 = _make_violation(severity=Severity.MEDIUM, location="b.md:2")
        result = _make_result(violations=(v1, v2))
        output = github_formatter.format_annotations(result)
        lines = output.strip().split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("::error ")
        assert lines[1].startswith("::warning ")

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_warning_severity(self) -> None:
        v = _make_violation(severity=Severity.LOW)
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        assert output.startswith("::warning ")


class TestFormatResult:
    """Test full format_result output (annotations + JSON)."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_json_line_is_last(self) -> None:
        v = _make_violation()
        result = _make_result(violations=(v,))
        output = github_formatter.format_result(result)
        last_line = output.strip().split("\n")[-1]
        data = json.loads(last_line)
        assert "score" in data
        assert "level" in data

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_json_line_contains_score_and_level(self) -> None:
        result = _make_result(score=8.5, level=Level.L4)
        output = github_formatter.format_result(result)
        last_line = output.strip().split("\n")[-1]
        data = json.loads(last_line)
        assert data["score"] == 8.5
        assert data["level"] == "L4"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_empty_violations_only_json(self) -> None:
        result = _make_result(violations=())
        output = github_formatter.format_result(result)
        lines = output.strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["violations"] == []

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_delta_included_in_json(self) -> None:
        result = _make_result(score=7.5)
        delta = ScanDelta(
            score_delta=0.5,
            level_previous="L2",
            level_improved=True,
            violations_delta=-2,
        )
        output = github_formatter.format_result(result, delta)
        last_line = output.strip().split("\n")[-1]
        data = json.loads(last_line)
        assert data["score_delta"] == 0.5
        assert data["level_previous"] == "L2"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_annotations_before_json(self) -> None:
        v = _make_violation(location="CLAUDE.md:10")
        result = _make_result(violations=(v,))
        output = github_formatter.format_result(result)
        lines = output.strip().split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("::")
        # Last line is JSON
        json.loads(lines[1])


def _combined_result(**overrides: object) -> CombinedResult:
    defaults: dict[str, object] = {
        "findings": (),
        "cross_file": (),
        "quality": None,
        "per_file_analysis": (),
        "stats": CombinedStats(total_findings=0, errors=0, warnings=0, infos=0),
        "offline": True,
        "hints": (),
        "cross_file_coordinates": (),
    }
    defaults.update(overrides)
    return CombinedResult(**defaults)  # type: ignore[arg-type]


class TestCombinedAnnotationsServerError:
    """A server rejection/timeout/network failure must surface as a
    `::warning::` annotation, not silently vanish alongside `offline: true`."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_server_error_no_warning_line(self) -> None:
        output = github_formatter.format_combined_annotations(_combined_result())
        lines = output.strip().split("\n")
        # Only the trailing JSON summary line — no findings, no server_error.
        assert len(lines) == 1
        json.loads(lines[0])

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_rejection_emits_named_warning_and_json_field(self) -> None:
        server_error = FunnelError(
            error="payload_too_large", tier="free", upgrade_url="https://reporails.com/account", status=413
        )
        output = github_formatter.format_combined_annotations(_combined_result(server_error=server_error))
        lines = output.strip().split("\n")
        assert lines[0].startswith("::warning ")
        assert "payload_too_large" in lines[0]
        data = json.loads(lines[-1])
        assert data["server_error"]["error"] == "payload_too_large"
        assert data["server_error"]["status"] == 413

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_transport_failure_emits_warning(self) -> None:
        server_error = FunnelError(error="network_error", message="Could not reach the diagnostics server")
        output = github_formatter.format_combined_annotations(_combined_result(server_error=server_error))
        lines = output.strip().split("\n")
        assert lines[0].startswith("::warning ")
        assert "network_error" in lines[0]
        data = json.loads(lines[-1])
        assert data["server_error"]["error"] == "network_error"
        assert data["server_error"]["status"] is None

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_annotation_message_carries_no_terminal_rich_markup(self) -> None:
        """The `::warning::` annotation echoed
        `format_server_error`'s raw `format_cta` string, so a real rate-limit rejection
        with a resolvable CTA URL put literal `[link=...][bold]...[/bold][/link]` tags
        into the PR annotation text."""
        server_error = FunnelError(
            error="rate_limit_exceeded", tier="free", limit=5, upgrade_url="https://reporails.com/account", status=429
        )
        output = github_formatter.format_combined_annotations(_combined_result(server_error=server_error))
        annotation_line = output.strip().split("\n")[0]
        assert "[link=" not in annotation_line
        assert "[bold]" not in annotation_line


@dataclass(frozen=True)
class _FileRecord:
    path: str


@dataclass(frozen=True)
class _RulesetMap:
    files: tuple = ()


class TestCombinedAnnotationsJsonSummary:
    """The trailing JSON line is the same document `--format json` prints.

    Built without the discovery context, `surface_health[].file_count` counts
    only the files that produced findings, so the github summary reported a
    smaller denominator than the json output of the very same run.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_trailing_json_equals_json_formatter_output(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem
        from reporails_cli.formatters import json as json_formatter

        result = _combined_result(
            findings=(
                FindingItem(
                    file=".claude/agents/one.md",
                    line=3,
                    severity="warning",
                    rule="CORE:S:0005",
                    message="too long",
                ),
            ),
            stats=CombinedStats(total_findings=1, errors=0, warnings=1, infos=0),
        )
        ruleset = _RulesetMap(
            files=tuple(
                _FileRecord(path=(tmp_path / ".claude" / "agents" / name).as_posix())
                for name in ("one.md", "two.md", "three.md")
            )
        )

        gh_output = github_formatter.format_combined_annotations(result, ruleset_map=ruleset, project_root=tmp_path)
        gh_json = json.loads(gh_output.strip().split("\n")[-1])
        js_json = json_formatter.format_combined_result(result, ruleset_map=ruleset, project_root=tmp_path)

        assert gh_json["surface_health"] == js_json["surface_health"]
        # The denominator is the discovered file list, not "files that had findings".
        assert [s["file_count"] for s in gh_json["surface_health"]] == [3]
        assert gh_json == json.loads(json.dumps(js_json))


class TestInfoSeverityAnnotation:
    """`info` findings are informational notes, not CI warnings."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_info_renders_as_notice(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        result = _combined_result(
            findings=(
                FindingItem(file="CLAUDE.md", line=1, severity="error", rule="CORE:S:0001", message="e"),
                FindingItem(file="CLAUDE.md", line=2, severity="warning", rule="CORE:S:0002", message="w"),
                FindingItem(file="CLAUDE.md", line=3, severity="info", rule="CORE:S:0003", message="i"),
            ),
            stats=CombinedStats(total_findings=3, errors=1, warnings=1, infos=1),
        )

        lines = github_formatter.format_combined_annotations(result).strip().split("\n")

        assert sum(1 for line in lines if line.startswith("::error ")) == 1
        assert sum(1 for line in lines if line.startswith("::warning ")) == 1
        assert sum(1 for line in lines if line.startswith("::notice ")) == 1


class TestFileLevelAnnotationLine:
    """A file-level finding (no specific line — e.g. `CORE:S:0024` unresolved-import or
    `CORE:G:0001` not-a-git-repo) carries `line: 0` in the finding data. GitHub's own
    workflow-command grammar has no line 0: the fix omits
    the `line=` property entirely for such a finding, the form GitHub's docs use for a
    file-level annotation, rather than substituting an arbitrary line number."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_line_zero_finding_omits_the_line_property(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        result = _combined_result(
            findings=(FindingItem(file="CLAUDE.md", line=0, severity="error", rule="CORE:S:0024", message="m"),),
            stats=CombinedStats(total_findings=1, errors=1, warnings=0, infos=0),
        )

        line = github_formatter.format_combined_annotations(result).strip().split("\n")[0]

        assert line.startswith("::error file=CLAUDE.md,title=")
        assert "line=0" not in line
        assert ",line=" not in line

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_normal_line_finding_still_carries_its_line(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        result = _combined_result(
            findings=(FindingItem(file="CLAUDE.md", line=45, severity="warning", rule="CORE:S:0001", message="m"),),
            stats=CombinedStats(total_findings=1, errors=0, warnings=1, infos=0),
        )

        line = github_formatter.format_combined_annotations(result).strip().split("\n")[0]

        assert "line=45" in line


class TestTrailingJsonElapsedMs:
    """The github trailer lacked `elapsed_ms` although `-f json` carries it on the same run."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_elapsed_ms_rides_the_trailer_when_the_caller_has_one(self) -> None:
        output = github_formatter.format_combined_annotations(_combined_result(), elapsed_ms=14158.23)
        data = json.loads(output.strip().split("\n")[-1])
        assert data["elapsed_ms"] == 14158.2

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_elapsed_ms_key_when_the_caller_passes_none(self) -> None:
        output = github_formatter.format_combined_annotations(_combined_result())
        data = json.loads(output.strip().split("\n")[-1])
        assert "elapsed_ms" not in data
