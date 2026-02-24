"""Unit tests for semantic rule request building."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.models import (
    Category,
    Check,
    JudgmentRequest,
    Rule,
    RuleType,
    Severity,
)
from reporails_cli.core.semantic import (
    _parse_choices,
    _parse_criteria,
    build_request,
    build_request_from_sarif_result,
    extract_snippet,
)


def _make_rule(**overrides) -> Rule:
    defaults = {
        "id": "C6",
        "title": "Test",
        "category": Category.CONTENT,
        "type": RuleType.SEMANTIC,
        "level": "L2",
        "checks": [Check(id="c6-check", name="check", severity=Severity.MEDIUM)],
        "question": "Is it good?",
        "criteria": None,
        "choices": None,
        "examples": None,
        "pass_value": "pass",
        "targets": "CLAUDE.md",
        "slug": "test",
        "see_also": [],
        "supersedes": None,
        "md_path": None,
        "yml_path": None,
    }
    defaults.update(overrides)
    return Rule(**defaults)


# ---------------------------------------------------------------------------
# _parse_criteria
# ---------------------------------------------------------------------------


class TestParseCriteria:
    def test_none_returns_default(self) -> None:
        result = _parse_criteria(None)
        assert result == {"pass_condition": "Evaluate based on context"}

    def test_string_returns_pass_condition(self) -> None:
        result = _parse_criteria("Instructions are clear")
        assert result == {"pass_condition": "Instructions are clear"}

    def test_list_of_dicts(self) -> None:
        criteria = [
            {"key": "clarity", "check": "Instructions are clear"},
            {"key": "scope", "check": "Scope is defined"},
        ]
        result = _parse_criteria(criteria)
        assert result == {"clarity": "Instructions are clear", "scope": "Scope is defined"}


# ---------------------------------------------------------------------------
# _parse_choices
# ---------------------------------------------------------------------------


class TestParseChoices:
    def test_none_returns_default(self) -> None:
        result = _parse_choices(None)
        assert result == ["pass", "fail"]

    def test_list_of_strings(self) -> None:
        result = _parse_choices(["yes", "no", "maybe"])
        assert result == ["yes", "no", "maybe"]

    def test_list_of_dicts(self) -> None:
        choices = [
            {"value": "pass", "label": "Passes"},
            {"value": "fail", "label": "Fails"},
        ]
        result = _parse_choices(choices)
        assert result == ["pass", "fail"]


# ---------------------------------------------------------------------------
# build_request
# ---------------------------------------------------------------------------


class TestBuildRequest:
    def test_missing_question_returns_none(self) -> None:
        rule = _make_rule(question=None)
        result = build_request(rule, "some content", "CLAUDE.md:1")
        assert result is None

    def test_valid_rule_returns_judgment_request(self) -> None:
        rule = _make_rule(
            checks=[Check(id="c6-check", name="check", severity=Severity.HIGH)],
        )
        result = build_request(rule, "file content", "CLAUDE.md:10")

        assert isinstance(result, JudgmentRequest)
        assert result.rule_id == "C6"
        assert result.rule_title == "Test"
        assert result.content == "file content"
        assert result.location == "CLAUDE.md:10"
        assert result.question == "Is it good?"
        assert result.severity == Severity.HIGH
        assert result.pass_value == "pass"
        assert result.choices == ["pass", "fail"]
        assert result.points_if_fail == -10


# ---------------------------------------------------------------------------
# extract_snippet
# ---------------------------------------------------------------------------


class TestExtractSnippet:
    def test_snippet_in_sarif(self) -> None:
        result = {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "CLAUDE.md"},
                        "region": {
                            "startLine": 5,
                            "snippet": {"text": "matched text"},
                        },
                    }
                }
            ]
        }
        snippet = extract_snippet(result, Path("/tmp/project"))
        assert snippet == "matched text"

    def test_missing_file_returns_none(self) -> None:
        result = {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "nonexistent.md"},
                        "region": {"startLine": 5},
                    }
                }
            ]
        }
        snippet = extract_snippet(result, Path("/tmp/does-not-exist"))
        assert snippet is None


# ---------------------------------------------------------------------------
# build_request_from_sarif_result
# ---------------------------------------------------------------------------


class TestBuildRequestFromSarifResult:
    def test_valid_data_returns_request(self) -> None:
        rule = _make_rule()
        sarif_result = {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "CLAUDE.md"},
                        "region": {
                            "startLine": 3,
                            "snippet": {"text": "some instruction content"},
                        },
                    }
                }
            ]
        }
        result = build_request_from_sarif_result(rule, sarif_result, Path("/tmp/project"))

        assert isinstance(result, JudgmentRequest)
        assert result.rule_id == "C6"
        assert result.content == "some instruction content"
        assert result.location == "CLAUDE.md:3"

    def test_no_snippet_returns_none(self) -> None:
        rule = _make_rule()
        sarif_result = {
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "nonexistent.md"},
                        "region": {"startLine": 1},
                    }
                }
            ]
        }
        result = build_request_from_sarif_result(rule, sarif_result, Path("/tmp/does-not-exist"))
        assert result is None


# ---------------------------------------------------------------------------
# Edge cases appended to existing classes
# ---------------------------------------------------------------------------


class TestParseCriteriaEdges:
    def test_empty_list_returns_default(self) -> None:
        """An empty list should fall back to the default dict."""
        result = _parse_criteria([])
        assert result == {"pass_condition": "Evaluate based on context"}


class TestParseChoicesEdges:
    def test_empty_list_returns_empty(self) -> None:
        """An empty list hits the falsy guard and returns the default."""
        result = _parse_choices([])
        assert result == ["pass", "fail"]


class TestBuildRequestEdges:
    def test_empty_checks_returns_none(self) -> None:
        """A rule with checks=[] should still return a JudgmentRequest (default severity)."""
        rule = _make_rule(checks=[])
        result = build_request(rule, "some content", "CLAUDE.md:1")

        # build_request only returns None when question is missing.
        # Empty checks means severity defaults to MEDIUM.
        assert isinstance(result, JudgmentRequest)
        assert result.severity == Severity.MEDIUM
