"""Unit tests for SARIF parsing — all functions are pure, no mocking needed."""

from __future__ import annotations

import pytest

from reporails_cli.core.models import Category, Check, Rule, RuleType, Severity, Violation
from reporails_cli.core.sarif import (
    dedupe_violations,
    extract_check_id,
    extract_rule_id,
    get_location,
    get_severity,
    parse_sarif,
)

# ---------------------------------------------------------------------------
# extract_rule_id (coordinate format)
# ---------------------------------------------------------------------------


class TestExtractRuleId:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("CORE.S.0001.check.0001", "CORE:S:0001"),
            ("CLAUDE.S.0002.check.0001", "CLAUDE:S:0002"),
            ("RRAILS_CLAUDE.S.0002.check.0001", "RRAILS_CLAUDE:S:0002"),
            ("CORE.C.0010", "CORE:C:0010"),  # no check suffix
            ("some-unexpected-format", "some-unexpected-format"),  # no dots
            # Temp path prefix handling (template-resolved yml files)
            ("tmp.tmpbb5ongfm.CORE.C.0006.check.0001", "CORE:C:0006"),
            ("tmp.tmpXXXXXX.CLAUDE.S.0005.check.0001", "CLAUDE:S:0005"),
            ("tmp.abc123.RRAILS.C.0001.check.0001", "RRAILS:C:0001"),
            ("tmp.xyz.RRAILS_CLAUDE.S.0002.check.0001", "RRAILS_CLAUDE:S:0002"),
            ("tmp.foo.CODEX.S.0001.check.0001", "CODEX:S:0001"),
        ],
    )
    def test_extract_rule_id(self, raw: str, expected: str) -> None:
        assert extract_rule_id(raw) == expected


# ---------------------------------------------------------------------------
# extract_check_id
# ---------------------------------------------------------------------------


class TestExtractCheckId:
    def test_standard_check_id(self) -> None:
        assert extract_check_id("CORE.S.0001.check.0001") == "check:0001"

    def test_no_check_suffix_returns_none(self) -> None:
        assert extract_check_id("CORE.S.0001") is None

    def test_two_parts_returns_none(self) -> None:
        assert extract_check_id("CORE.S") is None

    # Temp path prefix handling

    def test_temp_prefix_stripped(self) -> None:
        assert extract_check_id("tmp.tmpbb5ongfm.CORE.C.0006.check.0001") == "check:0001"

    def test_temp_prefix_stripped_no_check(self) -> None:
        """Coordinate with temp prefix but no check suffix."""
        assert extract_check_id("tmp.xyz.CORE.S.0001") is None


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
        id="CORE:S:0001",
        title="Test",
        category=Category.STRUCTURE,
        type=RuleType.DETERMINISTIC,
        level="L2",
        checks=checks,
    )


class TestGetSeverity:
    @pytest.mark.parametrize(
        "checks, check_id, expected",
        [
            (None, "check:0001", Severity.MEDIUM),  # rule=None fallback
            ([Check(id="CORE:S:0001:check:0001", severity=Severity.HIGH)], "check:0001", Severity.HIGH),
            (
                [Check(id="CORE:S:0001:check:0001", severity=Severity.LOW)],
                "check:9999",
                Severity.LOW,
            ),  # no match → first
            ([], "check:0001", Severity.MEDIUM),  # empty checks fallback
        ],
        ids=["rule-none", "matching-check", "no-match-returns-first", "empty-checks"],
    )
    def test_severity_resolution(self, checks: list[Check] | None, check_id: str, expected: Severity) -> None:
        rule = _make_rule(checks) if checks is not None else None
        assert get_severity(rule, check_id) == expected


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
            checks=checks or [Check(id=f"{rule_id}:check:0001", severity=Severity.MEDIUM)],
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
                            "rules": [{"id": "CORE.S.0001.check.0001", "defaultConfiguration": {"level": "note"}}]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "CORE.S.0001.check.0001",
                            "message": {"text": "info finding"},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": "f.md"}, "region": {"startLine": 1}}}
                            ],
                        }
                    ],
                }
            ]
        }
        assert parse_sarif(sarif, {"CORE:S:0001": self._rule("CORE:S:0001")}) == []

    def test_unknown_rules_skipped(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {"driver": {"rules": []}},
                    "results": [
                        {
                            "ruleId": "CORE.S.9999.check.0001",
                            "message": {"text": "msg"},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": "f.md"}, "region": {"startLine": 1}}}
                            ],
                        }
                    ],
                }
            ]
        }
        assert parse_sarif(sarif, {"CORE:S:0001": self._rule("CORE:S:0001")}) == []

    def test_full_parse(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [{"id": "CORE.S.0001.check.0001", "defaultConfiguration": {"level": "warning"}}]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "CORE.S.0001.check.0001",
                            "message": {"text": "violation msg"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "CLAUDE.md"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        rules = {"CORE:S:0001": self._rule("CORE:S:0001")}
        violations = parse_sarif(sarif, rules)

        assert len(violations) == 1
        v = violations[0]
        assert v.rule_id == "CORE:S:0001"
        assert v.location == "CLAUDE.md:10"
        assert v.message == "violation msg"
        assert v.check_id == "check:0001"

    def test_temp_prefixed_ruleid_parsed(self) -> None:
        """SARIF ruleIds with temp directory prefix are matched to rules."""
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "tmp.tmpXXX.CORE.C.0006.check.0001",
                                    "defaultConfiguration": {"level": "warning"},
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "tmp.tmpXXX.CORE.C.0006.check.0001",
                            "message": {"text": "vague qualifier found"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "CLAUDE.md"},
                                        "region": {"startLine": 7},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        rules = {"CORE:C:0006": self._rule("CORE:C:0006")}
        violations = parse_sarif(sarif, rules)

        assert len(violations) == 1
        assert violations[0].rule_id == "CORE:C:0006"
        assert violations[0].check_id == "check:0001"


# ---------------------------------------------------------------------------
# dedupe_violations
# ---------------------------------------------------------------------------


class TestViolationDeduplication:
    """Test that duplicate violations are handled correctly."""

    def test_duplicate_violations_deduped(self) -> None:
        """Duplicate violations (same file, rule, check) should be deduplicated."""
        violations = [
            Violation(
                rule_id="CORE:S:0001",
                rule_title="Test",
                location="test.md:1",
                message="Same violation",
                severity=Severity.MEDIUM,
                check_id="check:0001",
            ),
            Violation(
                rule_id="CORE:S:0001",
                rule_title="Test",
                location="test.md:5",
                message="Same violation",
                severity=Severity.MEDIUM,
                check_id="check:0001",
            ),
        ]
        assert len(dedupe_violations(violations)) == 1

    def test_different_files_not_deduped(self) -> None:
        """Same rule in different files should not be deduped."""
        violations = [
            Violation(
                rule_id="CORE:S:0001",
                rule_title="Test",
                location="a.md:1",
                message="Violation",
                severity=Severity.MEDIUM,
                check_id="check:0001",
            ),
            Violation(
                rule_id="CORE:S:0001",
                rule_title="Test",
                location="b.md:1",
                message="Violation",
                severity=Severity.MEDIUM,
                check_id="check:0001",
            ),
        ]
        assert len(dedupe_violations(violations)) == 2

    def test_different_rules_not_deduped(self) -> None:
        """Different rules in same file should not be deduped."""
        violations = [
            Violation(
                rule_id="CORE:S:0001",
                rule_title="Rule 1",
                location="test.md:1",
                message="Violation 1",
                severity=Severity.MEDIUM,
                check_id="check:0001",
            ),
            Violation(
                rule_id="CORE:S:0002",
                rule_title="Rule 2",
                location="test.md:1",
                message="Violation 2",
                severity=Severity.MEDIUM,
                check_id="check:0001",
            ),
        ]
        assert len(dedupe_violations(violations)) == 2

    def test_different_checks_not_deduped(self) -> None:
        """Different checks on same rule/file should not be deduped."""
        violations = [
            Violation(
                rule_id="CORE:S:0001",
                rule_title="Test",
                location="test.md:1",
                message="Check 1",
                severity=Severity.MEDIUM,
                check_id="check:0001",
            ),
            Violation(
                rule_id="CORE:S:0001",
                rule_title="Test",
                location="test.md:5",
                message="Check 2",
                severity=Severity.HIGH,
                check_id="check:0002",
            ),
        ]
        assert len(dedupe_violations(violations)) == 2
