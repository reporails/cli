"""Unit tests for SARIF parsing — all functions are pure, no mocking needed."""

from __future__ import annotations

from reporails_cli.core.models import Category, Check, Rule, RuleType, Severity, Violation
from reporails_cli.core.sarif import (
    dedupe_violations,
    extract_check_slug,
    extract_rule_id,
    get_location,
    get_severity,
    parse_sarif,
)

# ---------------------------------------------------------------------------
# extract_rule_id
# ---------------------------------------------------------------------------


class TestExtractRuleId:
    def test_standard_format(self) -> None:
        assert extract_rule_id("checks.structure.S1-many-h2-headings") == "S1"

    def test_multi_digit_id(self) -> None:
        assert extract_rule_id("checks.content.C10-no-examples") == "C10"

    def test_ails_prefix(self) -> None:
        assert extract_rule_id("checks.efficiency.AILS_E4-some-slug") == "AILS_E4"

    def test_claude_prefix(self) -> None:
        assert extract_rule_id("checks.structure.CLAUDE_S2-some-slug") == "CLAUDE_S2"

    def test_ails_claude_prefix(self) -> None:
        assert extract_rule_id("checks.maintenance.AILS_CLAUDE_M1-slug") == "AILS_CLAUDE_M1"

    def test_no_match_returns_original(self) -> None:
        raw = "some.unexpected.format"
        assert extract_rule_id(raw) == raw


# ---------------------------------------------------------------------------
# extract_check_slug
# ---------------------------------------------------------------------------


class TestExtractCheckSlug:
    def test_standard_slug(self) -> None:
        assert extract_check_slug("checks.structure.S1-many-sections") == "many-sections"

    def test_prefixed_slug(self) -> None:
        assert extract_check_slug("checks.efficiency.AILS_E4-no-grep") == "no-grep"

    def test_no_match_returns_none(self) -> None:
        assert extract_check_slug("no-dot-prefix") is None


# ---------------------------------------------------------------------------
# get_location
# ---------------------------------------------------------------------------


class TestGetLocation:
    def test_normal_result(self) -> None:
        result = {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "CLAUDE.md"},
                        "region": {"startLine": 42},
                    }
                }
            ]
        }
        assert get_location(result) == "CLAUDE.md:42"

    def test_missing_locations(self) -> None:
        assert get_location({}) == "unknown"
        assert get_location({"locations": []}) == "unknown"

    def test_missing_region(self) -> None:
        result = {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file.md"},
                    }
                }
            ]
        }
        assert get_location(result) == "file.md:0"


# ---------------------------------------------------------------------------
# get_severity
# ---------------------------------------------------------------------------


def _make_rule(checks: list[Check]) -> Rule:
    return Rule(
        id="T1",
        title="Test",
        category=Category.STRUCTURE,
        type=RuleType.DETERMINISTIC,
        level="L2",
        checks=checks,
    )


class TestGetSeverity:
    def test_rule_none(self) -> None:
        assert get_severity(None, "slug") == Severity.MEDIUM

    def test_matching_check(self) -> None:
        checks = [Check(id="T1-slug", name="Slug", severity=Severity.HIGH)]
        rule = _make_rule(checks)
        assert get_severity(rule, "slug") == Severity.HIGH

    def test_no_matching_check_returns_first(self) -> None:
        checks = [Check(id="T1-other", name="Other", severity=Severity.LOW)]
        rule = _make_rule(checks)
        assert get_severity(rule, "no-match") == Severity.LOW

    def test_empty_checks_returns_medium(self) -> None:
        rule = _make_rule([])
        assert get_severity(rule, "slug") == Severity.MEDIUM


# ---------------------------------------------------------------------------
# parse_sarif
# ---------------------------------------------------------------------------


class TestParseSarif:
    def _rule(self, rule_id: str, checks: list[Check] | None = None) -> Rule:
        return Rule(
            id=rule_id,
            title=f"Rule {rule_id}",
            category=Category.STRUCTURE,
            type=RuleType.DETERMINISTIC,
            level="L2",
            checks=checks or [Check(id=f"{rule_id}-check", name="Check", severity=Severity.MEDIUM)],
        )

    def test_empty_runs(self) -> None:
        assert parse_sarif({"runs": []}, {}) == []
        assert parse_sarif({}, {}) == []

    def test_info_findings_skipped(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "checks.structure.S1-check", "defaultConfiguration": {"level": "note"}}
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "checks.structure.S1-check",
                            "message": {"text": "info finding"},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": "f.md"}, "region": {"startLine": 1}}}
                            ],
                        }
                    ],
                }
            ]
        }
        assert parse_sarif(sarif, {"S1": self._rule("S1")}) == []

    def test_unknown_rules_skipped(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"rules": []}},
                    "results": [
                        {
                            "ruleId": "checks.structure.UNKNOWN1-check",
                            "message": {"text": "msg"},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": "f.md"}, "region": {"startLine": 1}}}
                            ],
                        }
                    ],
                }
            ]
        }
        # Rule not in provided dict → skipped
        assert parse_sarif(sarif, {"S1": self._rule("S1")}) == []

    def test_full_parse(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "checks.structure.S1-check", "defaultConfiguration": {"level": "warning"}}
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "checks.structure.S1-check",
                            "message": {"text": "violation msg"},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": "CLAUDE.md"}, "region": {"startLine": 10}}}
                            ],
                        }
                    ],
                }
            ]
        }
        rules = {"S1": self._rule("S1")}
        violations = parse_sarif(sarif, rules)

        assert len(violations) == 1
        v = violations[0]
        assert v.rule_id == "S1"
        assert v.location == "CLAUDE.md:10"
        assert v.message == "violation msg"


# ---------------------------------------------------------------------------
# dedupe_violations (moved from test_scoring.py)
# ---------------------------------------------------------------------------


class TestViolationDeduplication:
    """Test that duplicate violations are handled correctly."""

    def test_duplicate_violations_deduped(self) -> None:
        """Duplicate violations should be deduplicated."""
        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Same violation",
                severity=Severity.MEDIUM,
                check_id="test",
            ),
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:5",
                message="Same violation",
                severity=Severity.MEDIUM,
                check_id="test",
            ),
        ]

        deduped = dedupe_violations(violations)

        assert len(deduped) == 1

    def test_different_files_not_deduped(self) -> None:
        """Same rule in different files should not be deduped."""
        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="a.md:1",
                message="Violation",
                severity=Severity.MEDIUM,
                check_id="test",
            ),
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="b.md:1",
                message="Violation",
                severity=Severity.MEDIUM,
                check_id="test",
            ),
        ]

        deduped = dedupe_violations(violations)

        assert len(deduped) == 2

    def test_different_rules_not_deduped(self) -> None:
        """Different rules in same file should not be deduped."""
        violations = [
            Violation(
                rule_id="S1",
                rule_title="Rule 1",
                location="test.md:1",
                message="Violation 1",
                severity=Severity.MEDIUM,
                check_id="test1",
            ),
            Violation(
                rule_id="S2",
                rule_title="Rule 2",
                location="test.md:1",
                message="Violation 2",
                severity=Severity.MEDIUM,
                check_id="test2",
            ),
        ]

        deduped = dedupe_violations(violations)

        assert len(deduped) == 2
