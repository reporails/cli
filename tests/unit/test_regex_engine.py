"""Adversarial tests for the Python regex engine.

Targets compiler, runner, and template resolution with edge cases
designed to find bugs, crashes, and performance issues.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.regex.compiler import (
    CompiledCheck,
    _compile_pattern,
    compile_rules,
)
from reporails_cli.core.regex.runner import (
    _file_matches_path_filter,
    _match_check,
    run_capability_detection,
    run_validation,
)
from reporails_cli.core.templates import (
    _glob_to_regex,
    has_templates,
    resolve_templates,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_rule(tmp_path: Path, rule_data: dict[str, Any], name: str = "rule.yml") -> Path:
    """Write a YAML rule file and return its path."""
    p = tmp_path / name
    p.write_text(yaml.dump(rule_data, default_flow_style=False))
    return p


def _write_target(tmp_path: Path, content: str, name: str = "CLAUDE.md") -> Path:
    """Write a target file and return its path."""
    p = tmp_path / name
    p.write_text(content)
    return p


def _sarif_results(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract results from SARIF output."""
    results: list[dict[str, Any]] = []
    for run in sarif.get("runs", []):
        results.extend(run.get("results", []))
    return results


def _sarif_rule_ids(sarif: dict[str, Any]) -> list[str]:
    """Extract rule IDs from SARIF results."""
    return [r["ruleId"] for r in _sarif_results(sarif)]


# ===========================================================================
# 1. COMPILER EDGE CASES
# ===========================================================================


class TestCompilerEdgeCases:
    """Test compiler resilience against malformed and degenerate inputs."""

    def test_empty_yaml_file(self, tmp_path: Path) -> None:
        """Empty YAML file should produce no checks, no errors."""
        p = tmp_path / "empty.yml"
        p.write_text("")
        result = compile_rules([p])
        assert result.checks == []
        assert result.skipped == []

    def test_yaml_with_no_rules_key(self, tmp_path: Path) -> None:
        """YAML without 'rules' key should be silently skipped."""
        p = _write_rule(tmp_path, {"metadata": {"version": "1.0"}})
        result = compile_rules([p])
        assert result.checks == []

    def test_yaml_with_empty_rules_list(self, tmp_path: Path) -> None:
        """YAML with empty rules list should produce no checks."""
        p = _write_rule(tmp_path, {"rules": []})
        result = compile_rules([p])
        assert result.checks == []

    def test_rule_with_no_operator(self, tmp_path: Path) -> None:
        """Rule with no recognized operator should be skipped."""
        p = _write_rule(tmp_path, {"rules": [{"id": "TEST-001", "message": "bad"}]})
        result = compile_rules([p])
        assert result.checks == []
        assert "TEST-001" in result.skipped

    def test_rule_with_unknown_operator(self, tmp_path: Path) -> None:
        """Rule with unsupported operator should be skipped gracefully."""
        p = _write_rule(
            tmp_path,
            {"rules": [{"id": "TEST-002", "pattern-metavar": "$X", "message": "bad"}]},
        )
        result = compile_rules([p])
        assert "TEST-002" in result.skipped

    def test_invalid_regex_pattern(self, tmp_path: Path) -> None:
        """Invalid regex should be caught and rule skipped."""
        p = _write_rule(
            tmp_path,
            {"rules": [{"id": "BAD-REGEX", "pattern-regex": "[invalid(", "message": "bad"}]},
        )
        result = compile_rules([p])
        assert result.checks == []
        assert "BAD-REGEX" in result.skipped

    def test_invalid_regex_in_pattern_either(self, tmp_path: Path) -> None:
        """Invalid regex inside pattern-either should skip the entire rule."""
        p = _write_rule(
            tmp_path,
            {
                "rules": [
                    {
                        "id": "BAD-EITHER",
                        "pattern-either": [{"pattern-regex": "[valid"}, {"pattern-regex": "ok"}],
                        "message": "bad",
                    }
                ]
            },
        )
        result = compile_rules([p])
        assert "BAD-EITHER" in result.skipped

    def test_nonexistent_yml_path(self, tmp_path: Path) -> None:
        """Non-existent path should be silently skipped."""
        result = compile_rules([tmp_path / "does-not-exist.yml"])
        assert result.checks == []

    def test_binary_yml_file(self, tmp_path: Path) -> None:
        """Binary file disguised as .yml should be handled gracefully."""
        p = tmp_path / "binary.yml"
        p.write_bytes(b"\x00\x01\x02\xff\xfe" * 100)
        result = compile_rules([p])
        assert result.checks == []

    def test_yaml_bomb(self, tmp_path: Path) -> None:
        """YAML with deeply nested anchors/aliases (billion laughs variant).

        yaml.safe_load should handle this safely.
        """
        content = "a: &a\n  b: &b\n    c: &c\n      d: test\nrules: []\n"
        p = tmp_path / "nested.yml"
        p.write_text(content)
        result = compile_rules([p])
        assert result.checks == []

    def test_pattern_either_empty_list(self, tmp_path: Path) -> None:
        """pattern-either with empty list should produce None."""
        p = _write_rule(
            tmp_path,
            {"rules": [{"id": "EMPTY-EITHER", "pattern-either": [], "message": "x"}]},
        )
        result = compile_rules([p])
        assert result.checks == []
        assert "EMPTY-EITHER" in result.skipped

    def test_patterns_only_negative(self, tmp_path: Path) -> None:
        """patterns block with ONLY pattern-not-regex (no positive patterns).

        This compiles successfully. The runner's _match_check returns []
        for positive patterns (vacuously true) but then checks negatives.
        """
        p = _write_rule(
            tmp_path,
            {
                "rules": [
                    {
                        "id": "NEG-ONLY",
                        "patterns": [{"pattern-not-regex": "(?i)secret"}],
                        "message": "should not have secrets",
                    }
                ]
            },
        )
        result = compile_rules([p])
        # Should compile — it has a recognized operator
        assert len(result.checks) == 1
        check = result.checks[0]
        assert check.patterns == ()
        assert len(check.negative_patterns) == 1

    def test_missing_id_and_message(self, tmp_path: Path) -> None:
        """Rule without id or message should use defaults."""
        p = _write_rule(
            tmp_path,
            {"rules": [{"pattern-regex": "test"}]},
        )
        result = compile_rules([p])
        assert len(result.checks) == 1
        assert result.checks[0].id == "unknown"
        assert result.checks[0].message == ""

    def test_severity_normalization(self, tmp_path: Path) -> None:
        """Various severity values should normalize correctly."""
        rules: list[dict[str, Any]] = [
            {"id": f"SEV-{i}", "pattern-regex": f"test{i}", "severity": sev, "message": "x"}
            for i, sev in enumerate(["ERROR", "error", "CRITICAL", "high", "WARNING", "warning", "info", "LOW", ""])
        ]
        p = _write_rule(tmp_path, {"rules": rules})
        result = compile_rules([p])
        severities = {c.id: c.severity for c in result.checks}
        assert severities["SEV-0"] == "error"  # ERROR
        assert severities["SEV-1"] == "error"  # error
        assert severities["SEV-2"] == "error"  # CRITICAL
        assert severities["SEV-3"] == "error"  # high
        assert severities["SEV-4"] == "warning"  # WARNING
        assert severities["SEV-5"] == "warning"  # warning
        assert severities["SEV-6"] == "warning"  # info
        assert severities["SEV-7"] == "warning"  # LOW
        assert severities["SEV-8"] == "warning"  # empty

    def test_multiple_yml_files(self, tmp_path: Path) -> None:
        """Multiple YAML files should merge checks."""
        p1 = _write_rule(
            tmp_path,
            {"rules": [{"id": "R1", "pattern-regex": "a", "message": "x"}]},
            "r1.yml",
        )
        p2 = _write_rule(
            tmp_path,
            {"rules": [{"id": "R2", "pattern-regex": "b", "message": "y"}]},
            "r2.yml",
        )
        result = compile_rules([p1, p2])
        ids = {c.id for c in result.checks}
        assert ids == {"R1", "R2"}


# ===========================================================================
# 2. RUNNER MATCHING LOGIC
# ===========================================================================


class TestMatchCheck:
    """Test _match_check with edge cases in matching logic."""

    @staticmethod
    def _make_check(
        patterns: list[str] | None = None,
        negative: list[str] | None = None,
        either: list[str] | None = None,
    ) -> CompiledCheck:
        return CompiledCheck(
            id="test",
            message="test",
            severity="warning",
            patterns=tuple(_compile_pattern(p) for p in (patterns or [])),
            negative_patterns=tuple(_compile_pattern(p) for p in (negative or [])),
            either_patterns=tuple(_compile_pattern(p) for p in (either or [])),
            path_includes=(),
        )

    def test_single_pattern_match(self) -> None:
        check = self._make_check(patterns=["hello"])
        assert _match_check(check, "hello world") != []

    def test_single_pattern_no_match(self) -> None:
        check = self._make_check(patterns=["hello"])
        assert _match_check(check, "goodbye world") == []

    def test_and_all_match(self) -> None:
        """All patterns must match (AND logic)."""
        check = self._make_check(patterns=["hello", "world"])
        assert _match_check(check, "hello world") != []

    def test_and_partial_match(self) -> None:
        """If only some AND patterns match, result should be empty."""
        check = self._make_check(patterns=["hello", "missing"])
        assert _match_check(check, "hello world") == []

    def test_negative_blocks_match(self) -> None:
        """Negative pattern should block a positive match."""
        check = self._make_check(patterns=["hello"], negative=["world"])
        assert _match_check(check, "hello world") == []

    def test_negative_allows_when_absent(self) -> None:
        """No negative match → positive match goes through."""
        check = self._make_check(patterns=["hello"], negative=["missing"])
        assert _match_check(check, "hello world") != []

    def test_either_any_match(self) -> None:
        """Any pattern in either list should match (OR logic)."""
        check = self._make_check(either=["hello", "goodbye"])
        assert _match_check(check, "goodbye world") != []

    def test_either_none_match(self) -> None:
        check = self._make_check(either=["missing", "absent"])
        assert _match_check(check, "hello world") == []

    def test_either_returns_all_matching(self) -> None:
        """either returns all matching patterns (not just first)."""
        check = self._make_check(either=["hello", "world"])
        matches = _match_check(check, "hello world")
        assert len(matches) == 2

    def test_either_returns_only_matching(self) -> None:
        """either should only return patterns that actually match."""
        check = self._make_check(either=["hello", "missing"])
        matches = _match_check(check, "hello world")
        assert len(matches) == 1
        assert matches[0].group(0) == "hello"

    def test_empty_content(self) -> None:
        """Empty string should not match any pattern."""
        check = self._make_check(patterns=["something"])
        assert _match_check(check, "") == []

    def test_empty_pattern_matches_everything(self) -> None:
        """Empty regex matches everything (this is valid Python re behavior)."""
        check = self._make_check(patterns=[""])
        assert _match_check(check, "anything") != []

    def test_negative_only_no_positive(self) -> None:
        """patterns=() with negatives only: positive loop returns [],
        so overall returns [] regardless of negative.

        This is the 'negative-only' edge case from the compiler test.
        The match_check function returns [] because the positive patterns
        loop processes zero patterns and returns the empty matches list.
        """
        check = self._make_check(negative=["secret"])
        matches = _match_check(check, "no secrets here")
        # Empty patterns list → returns empty matches list (line 106-110)
        # The loop iterates over 0 patterns → matches stays []
        assert matches == []

    def test_multiline_dotall_behavior(self) -> None:
        """Patterns should match across lines (DOTALL flag)."""
        check = self._make_check(patterns=["hello.*world"])
        content = "hello\nworld"
        assert _match_check(check, content) != []

    def test_multiline_caret_anchor(self) -> None:
        """^ should match at start of each line (MULTILINE flag)."""
        check = self._make_check(patterns=["^## Section"])
        content = "intro\n## Section\ndetail"
        assert _match_check(check, content) != []

    def test_unicode_content(self) -> None:
        """Unicode content should be handled correctly."""
        check = self._make_check(patterns=["(?i)résumé"])
        assert _match_check(check, "My Résumé") != []

    def test_unicode_dash_character_class(self) -> None:
        """Character class with Unicode dashes (em-dash, en-dash) should work.

        This mirrors CORE.C.0012 pattern.
        """
        check = self._make_check(patterns=["[A-Z]{2,}\\s*[=:\u2014\u2013-]"])
        assert _match_check(check, "API: value") != []
        assert _match_check(check, "API\u2014value") != []
        assert _match_check(check, "API\u2013value") != []
        assert _match_check(check, "api: value") == []  # lowercase


# ===========================================================================
# 3. RUNNER SARIF OUTPUT
# ===========================================================================


class TestRunValidation:
    """Test run_validation SARIF output shape and correctness."""

    def test_basic_match_sarif_shape(self, tmp_path: Path) -> None:
        """Verify SARIF output has all required fields."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "T-001", "pattern-regex": "hello", "message": "found hello", "severity": "WARNING"}]},
        )
        _write_target(tmp_path, "# Doc\nhello world\n")

        sarif = run_validation([rule_yml], tmp_path)

        assert "runs" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]

        # Tool section
        assert "tool" in run
        assert "driver" in run["tool"]
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "T-001"
        assert rules[0]["defaultConfiguration"]["level"] == "warning"

        # Results
        results = run["results"]
        assert len(results) == 1
        r = results[0]
        assert r["ruleId"] == "T-001"
        assert r["message"]["text"] == "found hello"
        loc = r["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert loc["region"]["startLine"] == 2
        assert "snippet" in loc["region"]

    def test_line_number_first_line(self, tmp_path: Path) -> None:
        """Match on first line should report line 1."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "L1", "pattern-regex": "^#", "message": "x"}]},
        )
        _write_target(tmp_path, "# Title\nBody\n")

        results = _sarif_results(run_validation([rule_yml], tmp_path))
        assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1

    def test_line_number_last_line(self, tmp_path: Path) -> None:
        """Match on last line should report correct line number."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "LL", "pattern-regex": "end", "message": "x"}]},
        )
        content = "line1\nline2\nline3\nthe end"
        _write_target(tmp_path, content)

        results = _sarif_results(run_validation([rule_yml], tmp_path))
        assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 4

    def test_no_match_empty_results(self, tmp_path: Path) -> None:
        """No matches should produce SARIF with empty results."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "MISS", "pattern-regex": "nonexistent", "message": "x"}]},
        )
        _write_target(tmp_path, "# Nothing here\n")

        sarif = run_validation([rule_yml], tmp_path)
        assert _sarif_results(sarif) == []

    def test_multiple_matches_same_file(self, tmp_path: Path) -> None:
        """Multiple matches in one file should produce multiple results."""
        rule_yml = _write_rule(
            tmp_path,
            {
                "rules": [
                    {"id": "MULTI", "pattern-regex": "TODO", "message": "found TODO"},
                ]
            },
        )
        _write_target(tmp_path, "TODO: first\nok\nTODO: second\nTODO: third\n")

        # pattern-regex uses re.search which finds only the first match
        results = _sarif_results(run_validation([rule_yml], tmp_path))
        assert len(results) == 1  # search returns first match only

    def test_multiple_rules_match_same_file(self, tmp_path: Path) -> None:
        """Multiple rules matching the same file should each produce results."""
        rule_yml = _write_rule(
            tmp_path,
            {
                "rules": [
                    {"id": "R-A", "pattern-regex": "hello", "message": "found hello"},
                    {"id": "R-B", "pattern-regex": "world", "message": "found world"},
                ]
            },
        )
        _write_target(tmp_path, "hello world\n")

        rule_ids = _sarif_rule_ids(run_validation([rule_yml], tmp_path))
        assert "R-A" in rule_ids
        assert "R-B" in rule_ids

    def test_empty_target_directory(self, tmp_path: Path) -> None:
        """Directory with no .md files should produce empty results."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir(parents=True)
        rule_yml = _write_rule(
            rules_dir,
            {"rules": [{"id": "X", "pattern-regex": "anything", "message": "x"}]},
            "rule.yml",
        )
        target = tmp_path / "project"
        target.mkdir()

        sarif = run_validation([rule_yml], target)
        assert _sarif_results(sarif) == []

    def test_binary_target_file_skipped(self, tmp_path: Path) -> None:
        """Binary files should be skipped silently."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "BIN", "pattern-regex": ".", "message": "x"}]},
        )
        binary_file = tmp_path / "CLAUDE.md"
        binary_file.write_bytes(b"# Title\n\x00\x01binary junk\n")

        sarif = run_validation([rule_yml], tmp_path)
        assert _sarif_results(sarif) == []

    def test_utf8_encoding_error(self, tmp_path: Path) -> None:
        """File with invalid UTF-8 should be skipped."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "ENC", "pattern-regex": "test", "message": "x"}]},
        )
        bad_file = tmp_path / "CLAUDE.md"
        bad_file.write_bytes(b"# Title\n\xff\xfe invalid utf8\n")

        sarif = run_validation([rule_yml], tmp_path)
        assert _sarif_results(sarif) == []

    def test_snippet_truncation(self, tmp_path: Path) -> None:
        """Very long matches should be truncated in snippet."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "LONG", "pattern-regex": "A+", "message": "x"}]},
        )
        _write_target(tmp_path, "A" * 500 + "\n")

        results = _sarif_results(run_validation([rule_yml], tmp_path))
        snippet = results[0]["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        assert len(snippet) <= 203  # 200 + "..."
        assert snippet.endswith("...")


# ===========================================================================
# 4. PATH FILTERING
# ===========================================================================


class TestPathFiltering:
    """Test path include filter edge cases."""

    def test_glob_star_star_slash_star_md(self) -> None:
        """**/*.md should match any .md file."""
        assert _file_matches_path_filter("docs/README.md", ("**/*.md",))
        assert _file_matches_path_filter("CLAUDE.md", ("**/*.md",))
        assert _file_matches_path_filter("deep/nested/file.md", ("**/*.md",))
        assert not _file_matches_path_filter("file.txt", ("**/*.md",))

    def test_exact_filename(self) -> None:
        """Exact filename match."""
        assert _file_matches_path_filter("CLAUDE.md", ("CLAUDE.md",))
        assert not _file_matches_path_filter("OTHER.md", ("CLAUDE.md",))

    def test_empty_path_includes(self) -> None:
        """Empty path_includes should match everything."""
        assert _file_matches_path_filter("anything.txt", ())

    def test_template_placeholder_skipped(self) -> None:
        """Patterns containing {{ should be skipped."""
        assert not _file_matches_path_filter("CLAUDE.md", ("{{instruction_files}}",))

    def test_dotslash_prefix_stripped(self) -> None:
        """./prefix should be stripped from file paths."""
        assert _file_matches_path_filter("./CLAUDE.md", ("CLAUDE.md",))

    def test_path_includes_with_rule(self, tmp_path: Path) -> None:
        """Rules with path filters should only match specified files."""
        rule_yml = _write_rule(
            tmp_path,
            {
                "rules": [
                    {
                        "id": "PATH-FILTER",
                        "pattern-regex": "test",
                        "message": "found",
                        "paths": {"include": ["**/CLAUDE.md"]},
                    }
                ]
            },
        )
        # Create matching and non-matching files
        _write_target(tmp_path, "test content", "CLAUDE.md")
        _write_target(tmp_path, "test content", "OTHER.md")

        results = _sarif_results(run_validation([rule_yml], tmp_path))
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results]

        assert any("CLAUDE.md" in u for u in uris)
        assert not any("OTHER.md" in u for u in uris)


# ===========================================================================
# 5. NEGATIVE PATTERNS (pattern-not-regex)
# ===========================================================================


class TestNegativePatterns:
    """Test the pattern-not-regex operator — zero framework rules use this."""

    def test_positive_with_negative_match_blocks(self, tmp_path: Path) -> None:
        """When negative pattern matches, the rule should NOT fire."""
        rule_yml = _write_rule(
            tmp_path,
            {
                "rules": [
                    {
                        "id": "NEG-1",
                        "patterns": [
                            {"pattern-regex": "(?i)password"},
                            {"pattern-not-regex": "(?i)password.*hashed"},
                        ],
                        "message": "unhashed password",
                    }
                ]
            },
        )
        _write_target(tmp_path, "password is hashed with bcrypt\n")
        assert _sarif_results(run_validation([rule_yml], tmp_path)) == []

    def test_positive_without_negative_fires(self, tmp_path: Path) -> None:
        """When negative pattern doesn't match, positive should fire."""
        rule_yml = _write_rule(
            tmp_path,
            {
                "rules": [
                    {
                        "id": "NEG-2",
                        "patterns": [
                            {"pattern-regex": "(?i)password"},
                            {"pattern-not-regex": "(?i)password.*hashed"},
                        ],
                        "message": "unhashed password",
                    }
                ]
            },
        )
        _write_target(tmp_path, "password is stored in plaintext\n")
        results = _sarif_results(run_validation([rule_yml], tmp_path))
        assert len(results) == 1
        assert results[0]["ruleId"] == "NEG-2"

    def test_multiple_negatives_all_must_not_match(self, tmp_path: Path) -> None:
        """All negative patterns block the match (AND-NOT logic)."""
        rule_yml = _write_rule(
            tmp_path,
            {
                "rules": [
                    {
                        "id": "NEG-MULTI",
                        "patterns": [
                            {"pattern-regex": "(?i)api"},
                            {"pattern-not-regex": "(?i)internal"},
                            {"pattern-not-regex": "(?i)deprecated"},
                        ],
                        "message": "exposed API",
                    }
                ]
            },
        )
        # Case 1: only first negative matches → blocks
        _write_target(tmp_path, "internal API for testing\n")
        assert _sarif_results(run_validation([rule_yml], tmp_path)) == []

        # Case 2: only second negative matches → blocks
        _write_target(tmp_path, "deprecated API v1\n")
        assert _sarif_results(run_validation([rule_yml], tmp_path)) == []

        # Case 3: neither negative matches → fires
        _write_target(tmp_path, "public API v2\n")
        results = _sarif_results(run_validation([rule_yml], tmp_path))
        assert len(results) == 1

    def test_negative_only_never_fires(self, tmp_path: Path) -> None:
        """patterns block with ONLY negative patterns never produces matches.

        This is a semantic edge case — no positive patterns means the
        positive match loop returns empty list, so rule never fires.
        """
        rule_yml = _write_rule(
            tmp_path,
            {
                "rules": [
                    {
                        "id": "NEG-ONLY",
                        "patterns": [{"pattern-not-regex": "(?i)good"}],
                        "message": "should fire when 'good' absent",
                    }
                ]
            },
        )
        _write_target(tmp_path, "this has no positive word\n")
        results = _sarif_results(run_validation([rule_yml], tmp_path))
        # Bug or design choice? No positive patterns → never matches.
        assert results == []


# ===========================================================================
# 6. PERFORMANCE / BACKTRACKING
# ===========================================================================


class TestPerformance:
    """Test performance and catastrophic backtracking resistance."""

    def test_catastrophic_backtracking_protection(self, tmp_path: Path) -> None:
        """Pattern with nested quantifiers on adversarial input.

        Classic ReDoS: (a+)+ against "aaa...!" should not hang.
        """
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "REDOS", "pattern-regex": "(a+)+b", "message": "x"}]},
        )
        # Adversarial input: many 'a's followed by non-matching char
        adversarial = "a" * 25 + "!"
        _write_target(tmp_path, adversarial + "\n")

        start = time.monotonic()
        sarif = run_validation([rule_yml], tmp_path)
        elapsed = time.monotonic() - start

        assert _sarif_results(sarif) == []
        # Should complete in under 5 seconds even with backtracking
        # (25 'a's is manageable; 30+ would hang without possessive quantifiers)
        assert elapsed < 5.0, f"Regex took {elapsed:.1f}s — possible ReDoS"

    def test_greedy_dot_star_large_file(self, tmp_path: Path) -> None:
        """Greedy .* between two patterns on a large file.

        Mirrors CLAUDE.S.0011: (?i)(deny|block).*(\\.env|\\.pem)
        """
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "GREEDY", "pattern-regex": "(?i)(deny|block).*(\\.env|\\.pem)", "message": "x"}]},
        )
        # Large file with 'deny' at start but no matching suffix
        content = "deny " + "x" * 50000 + "\n"
        _write_target(tmp_path, content)

        start = time.monotonic()
        run_validation([rule_yml], tmp_path)
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, f"Greedy .* took {elapsed:.1f}s"

    def test_many_files_performance(self, tmp_path: Path) -> None:
        """Scanning 100 files should complete quickly."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "PERF", "pattern-regex": "## Structure", "message": "x"}]},
        )
        for i in range(100):
            _write_target(tmp_path, f"# File {i}\n## Structure\nContent\n", f"doc_{i}.md")

        start = time.monotonic()
        sarif = run_validation([rule_yml], tmp_path)
        elapsed = time.monotonic() - start

        assert len(_sarif_results(sarif)) == 100
        assert elapsed < 5.0, f"100 files took {elapsed:.1f}s"


# ===========================================================================
# 7. TEMPLATE RESOLUTION
# ===========================================================================


class TestTemplateResolution:
    """Test template {{placeholder}} resolution edge cases."""

    def test_template_detected(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yml"
        p.write_text("pattern-regex: '{{files}}'\n")
        assert has_templates(p)

    def test_no_template(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yml"
        p.write_text("pattern-regex: 'hello'\n")
        assert not has_templates(p)

    def test_string_substitution(self, tmp_path: Path) -> None:
        p = tmp_path / "test.yml"
        p.write_text('  pattern-regex: "(?i){{name}}"')
        result = resolve_templates(p, {"name": "CLAUDE"})
        assert "CLAUDE" in result

    def test_list_in_array_context(self, tmp_path: Path) -> None:
        """List value in array context should expand to multiple items."""
        p = tmp_path / "test.yml"
        p.write_text('  - "{{files}}"')
        result = resolve_templates(p, {"files": ["a.md", "b.md"]})
        assert '"a.md"' in result
        assert '"b.md"' in result

    def test_list_in_regex_context(self, tmp_path: Path) -> None:
        """List value in pattern-regex context should produce alternation."""
        p = tmp_path / "test.yml"
        p.write_text('  pattern-regex: "{{patterns}}"')
        result = resolve_templates(p, {"patterns": ["*.md", "*.txt"]})
        assert "(" in result
        assert "|" in result

    def test_missing_placeholder(self, tmp_path: Path) -> None:
        """Template with placeholder not in context should remain unreplaced."""
        p = tmp_path / "test.yml"
        p.write_text('  pattern-regex: "{{missing}}"')
        result = resolve_templates(p, {"other": "value"})
        assert "{{missing}}" in result

    def test_template_injection_attempt(self, tmp_path: Path) -> None:
        """Context values with regex metacharacters should be inserted literally.

        This is NOT an attack vector for the template system itself, but the
        resulting regex could be broken. Template resolution does simple
        string substitution — it's the compiler's re.compile that would fail.
        """
        p = tmp_path / "test.yml"
        p.write_text('  pattern-regex: "{{value}}"')
        result = resolve_templates(p, {"value": "[unclosed"})
        assert "[unclosed" in result

    def test_glob_to_regex_special_chars(self) -> None:
        """glob_to_regex should escape regex special chars."""
        assert _glob_to_regex("file.md") == "file\\\\.md"  # for YAML
        assert _glob_to_regex("file.md", for_yaml=False) == "file\\.md"  # raw

    def test_glob_to_regex_double_star(self) -> None:
        """**/ prefix should be stripped, ** in middle consumes trailing /."""
        assert _glob_to_regex("**/CLAUDE.md") == "CLAUDE\\\\.md"
        # ** consumes the trailing /, so docs/**/file.md → docs/.*file\.md
        # This is correct: .* already matches /, so it matches docs/sub/file.md
        assert _glob_to_regex("docs/**/file.md", for_yaml=False) == "docs/.*file\\.md"

    def test_glob_to_regex_single_star(self) -> None:
        """Single * should not match /"""
        result = _glob_to_regex("*.md", for_yaml=False)
        assert result == "[^/]*\\.md"

    def test_template_with_empty_list(self, tmp_path: Path) -> None:
        """Empty list value should produce empty expansion."""
        p = tmp_path / "test.yml"
        p.write_text('  - "{{files}}"')
        result = resolve_templates(p, {"files": []})
        # Empty list → no items generated
        lines = [line for line in result.split("\n") if line.strip()]
        assert lines == []

    def test_template_with_empty_list_regex_context(self, tmp_path: Path) -> None:
        """Empty list in regex context should produce empty alternation."""
        p = tmp_path / "test.yml"
        p.write_text('  pattern-regex: "{{patterns}}"')
        result = resolve_templates(p, {"patterns": []})
        # Produces "()" — empty group, which is valid but matches empty string
        assert "()" in result


# ===========================================================================
# 8. INTEGRATION: FULL PIPELINE EDGE CASES
# ===========================================================================


class TestIntegration:
    """Full pipeline integration tests with edge cases."""

    def test_negate_interaction_with_regex(self, tmp_path: Path) -> None:
        """Test that regex results can be consumed by negated deterministic checks.

        In the pipeline, negate=True inverts the result. With the regex engine,
        this means: if regex finds no match → treat as violation.
        This tests the SARIF output shape is compatible.
        """
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "NEG-DET", "pattern-regex": "(?i)\\bMCP\\b", "message": "MCP not documented"}]},
        )
        # File mentions MCP → match → if negate=True in pipeline, this would be NOT a violation
        _write_target(tmp_path, "# MCP Config\nUse MCP servers\n")

        sarif = run_validation([rule_yml], tmp_path)
        results = _sarif_results(sarif)
        # Should produce a match (pipeline negate happens downstream)
        assert len(results) == 1

    def test_exclude_dirs(self, tmp_path: Path) -> None:
        """--exclude-dir should prevent scanning those directories."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "EXCL", "pattern-regex": "secret", "message": "x"}]},
        )
        # Create files in included and excluded directories
        sub = tmp_path / "vendor"
        sub.mkdir()
        _write_target(tmp_path, "secret content\n")
        (sub / "lib.md").write_text("secret in vendor\n")

        sarif = run_validation([rule_yml], tmp_path, exclude_dirs=["vendor"])
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in _sarif_results(sarif)]

        assert any("CLAUDE.md" in u for u in uris)
        assert not any("vendor" in u for u in uris)

    def test_symlink_extra_targets(self, tmp_path: Path) -> None:
        """Extra targets (from symlinks) should be scanned."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "SYM", "pattern-regex": "external", "message": "x"}]},
        )
        project = tmp_path / "project"
        project.mkdir()
        _write_target(project, "# Project\n")

        external_file = tmp_path / "external.md"
        external_file.write_text("external content\n")

        sarif = run_validation(
            [rule_yml],
            project,
            extra_targets=[external_file],
        )
        results = _sarif_results(sarif)
        assert len(results) == 1

    def test_instruction_files_explicit(self, tmp_path: Path) -> None:
        """When instruction_files is provided, only those files should be scanned."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "IF", "pattern-regex": "content", "message": "x"}]},
        )
        a = _write_target(tmp_path, "content in A\n", "a.md")
        _write_target(tmp_path, "content in B\n", "b.md")

        sarif = run_validation([rule_yml], tmp_path, instruction_files=[a])
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in _sarif_results(sarif)]

        assert any("a.md" in u for u in uris)
        assert not any("b.md" in u for u in uris)

    def test_capability_detection_runs(self, tmp_path: Path) -> None:
        """run_capability_detection should work with bundled patterns."""
        _write_target(tmp_path, "# Project\n\n## Structure\n\nSome content\n")
        sarif = run_capability_detection(tmp_path)
        # Should produce results (the bundled patterns detect features)
        assert "runs" in sarif

    def test_zero_byte_file(self, tmp_path: Path) -> None:
        """Zero-byte file should not crash."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "ZERO", "pattern-regex": "anything", "message": "x"}]},
        )
        (tmp_path / "empty.md").write_text("")

        sarif = run_validation([rule_yml], tmp_path)
        assert _sarif_results(sarif) == []

    def test_file_with_only_newlines(self, tmp_path: Path) -> None:
        """File with only newlines should not crash."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "NL", "pattern-regex": "\\S", "message": "x"}]},
        )
        (tmp_path / "newlines.md").write_text("\n\n\n\n")

        sarif = run_validation([rule_yml], tmp_path)
        assert _sarif_results(sarif) == []

    def test_very_long_line(self, tmp_path: Path) -> None:
        """File with a single very long line should not crash."""
        rule_yml = _write_rule(
            tmp_path,
            {"rules": [{"id": "VLONG", "pattern-regex": "needle", "message": "x"}]},
        )
        # 1MB line with needle buried in the middle
        content = "x" * 500000 + "needle" + "x" * 500000
        _write_target(tmp_path, content)

        start = time.monotonic()
        sarif = run_validation([rule_yml], tmp_path)
        elapsed = time.monotonic() - start

        results = _sarif_results(sarif)
        assert len(results) == 1
        assert elapsed < 5.0

    def test_pattern_either_all_sub_unsupported(self, tmp_path: Path) -> None:
        """pattern-either where no sub-entry has pattern-regex should skip."""
        rule_yml = _write_rule(
            tmp_path,
            {
                "rules": [
                    {
                        "id": "BAD-SUB",
                        "pattern-either": [
                            {"pattern-metavar": "$X"},
                            {"metavariable-regex": "test"},
                        ],
                        "message": "x",
                    }
                ]
            },
        )
        _write_target(tmp_path, "content\n")

        result = compile_rules([rule_yml])
        assert "BAD-SUB" in result.skipped
