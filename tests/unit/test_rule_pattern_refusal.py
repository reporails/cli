"""A check whose pattern operator is invalid refuses its rule at load, instead of skipping the check."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from reporails_cli.core.lint.harness_discovery import discover_rules
from reporails_cli.core.lint.harness_quality import lint_rules
from reporails_cli.core.lint.regex.compiler import compile_rules
from reporails_cli.core.platform.adapters import registry
from reporails_cli.core.platform.adapters.registry import RuleReadError, read_rule

_FRONTMATTER = (
    "---\nid: {rid}\ntitle: T\ncategory: structure\ntype: deterministic\nslug: {slug}\nseverity: medium\n---\n\nbody\n"
)

_FAULTS = [
    pytest.param("pattern-regex: 42", "pattern-regex", "Input should be a valid string", id="non-text"),
    pytest.param("pattern-regex: '(unclosed'", "pattern-regex", "does not compile", id="no-compile"),
    pytest.param(
        "patterns:\n    - pattern: foo",
        "patterns.0",
        "holds `pattern`; an item of `patterns` holds one of `pattern-regex`, `pattern-not-regex`",
        id="unsupported-sub-operator",
    ),
    pytest.param("message: nothing to match", "", "a deterministic check needs one pattern operator", id="no-operator"),
    pytest.param(
        "pattern-either:\n    - pattern-not-regex: x",
        "pattern-either.0",
        "an item of `pattern-either` holds one of `pattern-regex`",
        id="either-wrong-key",
    ),
    pytest.param(
        "patterns:\n    - pattern-regex: a\n    - pattern-not-regex: '[bad'",
        "patterns.1.pattern-not-regex",
        "does not compile",
        id="not-regex-no-compile",
    ),
    pytest.param("patterns: []", "patterns", "at least 1 item", id="empty-patterns"),
]

_EXACT_FAULTS = [
    pytest.param(
        "pattern-regex: ''",
        "pattern-regex",
        "is empty; an empty pattern matches every line",
        id="empty-pattern-regex",
    ),
    pytest.param(
        "pattern-either:\n    - pattern-regex: ''",
        "pattern-either.0.pattern-regex",
        "is empty; an empty pattern matches every line",
        id="empty-either-item",
    ),
    pytest.param(
        "patterns:\n    - pattern-regex: ''",
        "patterns.0.pattern-regex",
        "is empty; an empty pattern matches every line",
        id="empty-patterns-regex",
    ),
    pytest.param(
        "patterns:\n    - pattern-regex: a\n    - pattern-not-regex: ''",
        "patterns.1.pattern-not-regex",
        "is empty; an empty pattern matches every line",
        id="empty-patterns-not-regex",
    ),
    pytest.param(
        "patterns:\n    - pattern-not-regex: a",
        "patterns",
        "holds no `pattern-regex`; `pattern-not-regex` alone matches nothing",
        id="patterns-without-regex",
    ),
    pytest.param(
        "type: mechanical\n  check: file_exists\n  pattern-not-regex: x",
        "",
        "`pattern-not-regex` is read only inside `patterns` on a deterministic check",
        id="mechanical-top-not",
    ),
    pytest.param(
        "type: mechanical\n  check: file_exists\n  pattern-not-regex: '('",
        "",
        "`pattern-not-regex` is read only inside `patterns` on a deterministic check",
        id="mechanical-top-not-uncompilable",
    ),
    pytest.param(
        "type: mechanical\n  check: file_exists\n  patterns: ['*.md']",
        "patterns",
        "is read only on a deterministic check",
        id="mechanical-patterns-strings",
    ),
    pytest.param(
        "type: mechanical\n  check: file_exists\n  patterns:\n    - pattern-not-regex: x",
        "patterns",
        "is read only on a deterministic check",
        id="mechanical-patterns-negative-only",
    ),
    pytest.param(
        "type: mechanical\n  check: file_exists\n  pattern-regex: '('",
        "pattern-regex",
        "is read only on a deterministic check",
        id="mechanical-uncompilable-regex",
    ),
    pytest.param("pattern-regex:", "pattern-regex", "needs a value", id="null-regex"),
    pytest.param("patterns:", "patterns", "needs a value", id="null-patterns"),
    pytest.param("pattern-either:", "pattern-either", "needs a value", id="null-either"),
    pytest.param(
        "type: mechanical\n  check: file_exists\n  pattern-regex: x",
        "pattern-regex",
        "is read only on a deterministic check",
        id="mechanical-valid-regex",
    ),
    pytest.param(
        "type: mechanical\n  check: file_exists\n  pattern-either:\n    - pattern-regex: x",
        "pattern-either",
        "is read only on a deterministic check",
        id="mechanical-either",
    ),
    pytest.param(
        "pattern-regex: a\n  pattern-not-regex: b",
        "",
        "`pattern-not-regex` is read only inside `patterns` on a deterministic check",
        id="deterministic-top-not",
    ),
    pytest.param(
        "pattern-regex: a\n  patterns:\n    - pattern-regex: b",
        "",
        "holds more than one pattern operator (`pattern-regex`, `patterns`); keep one",
        id="two-operators",
    ),
    pytest.param(
        "message: nothing to match",
        "",
        "a deterministic check needs one pattern operator: pattern-regex, pattern-either or patterns",
        id="no-operator-exact",
    ),
    pytest.param(
        "type: null\n  pattern-regex: x",
        "type",
        "Input should be 'mechanical', 'deterministic' or 'content_query'",
        id="null-type-with-pattern",
    ),
    pytest.param(
        "severity: bogus",
        "severity",
        "Input should be 'critical', 'high', 'medium', 'low' or 'info'",
        id="bad-severity-no-operator",
    ),
    pytest.param(
        "type: mechanicl\n  check: file_exists",
        "type",
        "Input should be 'mechanical', 'deterministic' or 'content_query'",
        id="misspelled-type",
    ),
    pytest.param(
        "type: mechanical\n  check: file_exists\n  expect: presnt",
        "expect",
        "Input should be 'present' or 'absent'",
        id="misspelled-expect",
    ),
    pytest.param("pattern-regex: x\n  pattern-inside: b", "pattern-inside", "is not a known key", id="unknown-key"),
    pytest.param(
        "pattern-regex: x\n  paths:\n    include: [x]\n    exclude: [y]",
        "paths.exclude",
        "is not a known key",
        id="unknown-paths-key",
    ),
    pytest.param(
        "pattern-regex: x\n  paths:\n    include: []",
        "paths.include",
        "List should have at least 1 item after validation, not 0",
        id="paths-include-empty",
    ),
    pytest.param(
        "pattern-regex: x\n  min_lines: 0", "min_lines", "Input should be greater than 0", id="min-lines-zero"
    ),
    pytest.param(
        "pattern-regex: x\n  min_lines: '30'", "min_lines", "Input should be a valid integer", id="min-lines-text"
    ),
    pytest.param(
        "pattern-regex: x\n  follow_imports: 'yes'",
        "follow_imports",
        "Input should be a valid boolean",
        id="follow-imports-text",
    ),
    pytest.param(
        "type: mechanical\n  check: file_exists\n  entry_only: true",
        "entry_only",
        "is read only on a deterministic check; a mechanical check takes it under args",
        id="mechanical-entry-only",
    ),
]


def _write_rule(root: Path, slug: str, rid: str, check_body: str) -> Path:
    rule_dir = root / "core" / slug
    rule_dir.mkdir(parents=True)
    md = rule_dir / "rule.md"
    md.write_text(_FRONTMATTER.format(rid=rid, slug=slug))
    (rule_dir / "checks.yml").write_text(f"checks:\n- id: CORE.S.0001.check\n  {check_body}\n")
    return md


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("body", "field", "problem"), _FAULTS)
def test_an_invalid_pattern_operator_refuses_the_rule(tmp_path: Path, body: str, field: str, problem: str) -> None:
    md = _write_rule(tmp_path, "r", "CORE:S:0001", body)

    with pytest.raises(RuleReadError) as raised:
        read_rule(md)

    assert raised.value.path == md.parent / "checks.yml"
    message = str(raised.value)
    assert "check 1 (CORE.S.0001.check)" in message
    assert problem in message
    if field:
        assert f": {field}: " in message


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("body", "field", "problem"), _EXACT_FAULTS)
def test_a_refused_check_reports_exactly_its_problem(tmp_path: Path, body: str, field: str, problem: str) -> None:
    md = _write_rule(tmp_path, "r", "CORE:S:0001", body)

    with pytest.raises(RuleReadError) as raised:
        read_rule(md)

    located = f"{field}: {problem}" if field else problem
    assert str(raised.value) == f"{md.parent / 'checks.yml'}: check 1 (CORE.S.0001.check): {located}"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_refused_rule_is_skipped_with_a_warning_and_its_sibling_loads(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _write_rule(tmp_path, "bad", "CORE:S:0001", "pattern-regex: '(unclosed'")
    _write_rule(tmp_path, "good", "CORE:S:0002", "pattern-regex: fine")

    with caplog.at_level(logging.WARNING):
        rules = registry._scan_rules(tmp_path)

    assert list(rules) == ["CORE:S:0002"]
    assert "Skipping rule" in caplog.text
    assert "check 1 (CORE.S.0001.check): pattern-regex: does not compile" in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_ails_test_lint_reports_the_refused_rule(tmp_path: Path) -> None:
    _write_rule(tmp_path, "bad", "CORE:S:0001", "pattern-regex: '(unclosed'")

    messages = [e.message for e in lint_rules(discover_rules(tmp_path))]

    assert any("check 1 (CORE.S.0001.check): pattern-regex: does not compile" in m for m in messages)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_valid_checks_file_compiles_every_check_field(tmp_path: Path) -> None:
    yml = tmp_path / "checks.yml"
    yml.write_text(
        "checks:\n"
        "- id: A\n  message: m\n  severity: high\n  expect: absent\n  min_lines: 3\n  follow_imports: true\n"
        "  entry_only: true\n  paths:\n    include: ['**/*.md']\n  pattern-regex: foo\n"
        "- id: B\n  pattern-either:\n  - pattern-regex: x\n  - pattern-regex: y\n"
        "- id: C\n  patterns:\n  - pattern-regex: p\n  - pattern-not-regex: q\n"
        "- id: D\n  type: mechanical\n  check: file_exists\n"
    )

    a, b, c = compile_rules([yml]).checks

    assert (a.id, a.message, a.severity, a.every_match, a.min_lines, a.follow_imports, a.entry_only) == (
        "A",
        "m",
        "error",
        True,
        3,
        True,
        True,
    )
    assert a.path_includes == ("**/*.md",)
    assert [p.pattern for p in a.patterns] == ["foo"]
    assert (b.patterns, [p.pattern for p in b.either_patterns]) == ((), ["x", "y"])
    assert ([p.pattern for p in c.patterns], [p.pattern for p in c.negative_patterns]) == (["p"], ["q"])
    assert (b.severity, b.min_lines, b.every_match, b.path_includes) == ("warning", 0, False, ())
    assert a.patterns[0].flags & 8 and a.patterns[0].flags & 16  # MULTILINE | DOTALL


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_checks_file_without_a_checks_list_is_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    yml = tmp_path / "checks.yml"
    yml.write_text("foo: bar\n")

    with caplog.at_level(logging.WARNING):
        result = compile_rules([yml])

    assert result.checks == []
    assert "has no valid 'checks' list" in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("pattern", ["(?m)^(?!---)", "^$", "foo|", ".*", "(?:)", "x*", "(?<!\\n)\\Z"])
def test_a_pattern_that_can_match_empty_text_loads(tmp_path: Path, pattern: str) -> None:
    yml = tmp_path / "checks.yml"
    yml.write_text(f"checks:\n- id: A\n  pattern-regex: '{pattern}'\n")

    (check,) = compile_rules([yml]).checks

    assert [p.pattern for p in check.patterns] == [pattern]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_ails_test_reports_the_problem_that_refused_the_checks_not_an_empty_file(tmp_path: Path) -> None:
    from reporails_cli.core.lint.harness import _run_deterministic_check
    from reporails_cli.core.platform.dto.models import Check

    md = _write_rule(tmp_path, "r", "CORE:S:0001", "pattern-regex: x\n  pattern-inside: b")
    checks_yml = md.parent / "checks.yml"

    ok, count, message = _run_deterministic_check(
        checks_yml, Check.model_validate({"id": "CORE.S.0001.check", "pattern-regex": "x"}), tmp_path
    )

    assert (ok, count) == (False, 0)
    assert message == f"{checks_yml}: check 1 (CORE.S.0001.check): pattern-inside: is not a known key"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_ails_test_keeps_its_message_for_a_file_that_holds_no_checks(tmp_path: Path) -> None:
    from reporails_cli.core.lint.harness import _run_deterministic_check
    from reporails_cli.core.platform.dto.models import Check

    checks_yml = tmp_path / "checks.yml"
    checks_yml.write_text("checks: []\n")

    _, _, message = _run_deterministic_check(
        checks_yml, Check.model_validate({"id": "CORE.S.0001.check", "pattern-regex": "x"}), tmp_path
    )

    assert message == "checks.yml has no patterns (checks: [])"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rules_load_when_the_scanned_root_sits_inside_a_folder_named_tests(tmp_path: Path) -> None:
    root = tmp_path / "tests" / "_deferred" / "install"
    _write_rule(root, "r", "CORE:S:0001", "pattern-regex: x")

    assert list(registry._scan_rules(root)) == ["CORE:S:0001"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_tests_or_deferred_folder_below_the_root_is_still_skipped(tmp_path: Path) -> None:
    _write_rule(tmp_path, "r", "CORE:S:0001", "pattern-regex: x")
    _write_rule(tmp_path / "r" / "tests", "fixture", "CORE:S:0002", "pattern-regex: x")
    _write_rule(tmp_path / "_deferred", "later", "CORE:S:0003", "pattern-regex: x")

    assert list(registry._scan_rules(tmp_path)) == ["CORE:S:0001"]
