"""`ails stopwords` vocab sync and extract: round trip, refused terms, unreadable files, target slots."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from reporails_cli.core.classify.stopwords import extract_all
from reporails_cli.core.classify.stopwords_sync import sync_all, sync_vocab
from reporails_cli.interfaces.cli.stopwords_command import stopwords_app

pytestmark = [pytest.mark.unit, pytest.mark.subsys_lint]

_ALT = r"\b(?:x|y)\b"


def _rule(rule_dir: Path, checks: list[dict], vocab: object) -> Path:
    rule_dir.mkdir(parents=True, exist_ok=True)
    (rule_dir / "checks.yml").write_text(yaml.dump({"checks": checks}), encoding="utf-8")
    (rule_dir / "vocab.yml").write_text(yaml.dump(vocab), encoding="utf-8")
    return rule_dir


def _simple(pattern: str = _ALT) -> list[dict]:
    return [{"id": "R.c", "type": "deterministic", "pattern-regex": pattern}]


def _pattern(rule_dir: Path) -> str:
    return yaml.safe_load((rule_dir / "checks.yml").read_text(encoding="utf-8"))["checks"][0]["pattern-regex"]


@pytest.mark.parametrize("terms", [["a", "b"], ["a", "b", "c", "d", "e"]])
def test_sync_then_sync_again_has_nothing_to_change(tmp_path: Path, terms: list[str]) -> None:
    rule = _rule(tmp_path / "r", _simple(), {"c": terms})
    first = sync_vocab(rule)
    assert first.updated == 1
    assert _pattern(rule) == r"\b(?:" + "|".join(terms) + r")\b"
    second = sync_vocab(rule)
    assert (second.updated, second.skipped, second.messages) == (0, 0, [])


def test_one_term_list_is_refused_and_nothing_written(tmp_path: Path) -> None:
    rule = _rule(tmp_path / "r", _simple(), {"c": ["only"]})
    result = sync_vocab(rule)
    assert (result.updated, result.skipped) == (0, 1)
    assert any("'c'" in m and "needs two or more terms" in m for m in result.messages)
    assert _pattern(rule) == _ALT


def test_one_term_list_does_not_rewrite_a_structural_group(tmp_path: Path) -> None:
    pattern = r"x(?:must)\s+(?:a|b|c)"
    rule = _rule(tmp_path / "r", _simple(pattern), {"c": ["a"]})
    result = sync_vocab(rule)
    assert result.updated == 0
    assert any("needs two or more terms" in m for m in result.messages)
    assert _pattern(rule) == pattern


def test_terms_that_do_not_read_back_as_the_list_are_refused(tmp_path: Path) -> None:
    rule = _rule(tmp_path / "r", _simple(), {"c": ["a)|(b", "c"]})
    result = sync_vocab(rule)
    assert result.updated == 0
    assert any("a)|(b" in m and "No pattern written" in m for m in result.messages)
    assert _pattern(rule) == _ALT


def test_malformed_vocab_file_is_one_line(tmp_path: Path) -> None:
    rule = _rule(tmp_path / "r", _simple(), {"c": ["p", "q"]})
    (rule / "vocab.yml").write_text("c: [unclosed\n", encoding="utf-8")
    [message] = sync_vocab(rule).messages
    assert message.startswith("vocab.yml is not valid YAML (")
    assert "\n" not in message


def test_empty_term_is_refused_and_nothing_written(tmp_path: Path) -> None:
    rule = _rule(tmp_path / "r", _simple(), {"c": ["a", ""]})
    result = sync_vocab(rule)
    assert result.updated == 0
    assert any("item 2" in m and "blank" in m for m in result.messages)
    assert _pattern(rule) == _ALT


def test_whitespace_term_is_refused(tmp_path: Path) -> None:
    rule = _rule(tmp_path / "r", _simple(), {"c": ["a", "  "]})
    result = sync_vocab(rule)
    assert result.updated == 0
    assert any("item 2" in m for m in result.messages)
    assert _pattern(rule) == _ALT


def test_term_that_breaks_the_regex_is_refused(tmp_path: Path) -> None:
    rule = _rule(tmp_path / "r", _simple(), {"c": ["a", "b("]})
    result = sync_vocab(rule)
    assert result.updated == 0
    assert any("does not compile" in m and "a|b(" in m for m in result.messages)
    assert _pattern(rule) == _ALT


def test_unreadable_files_are_reported_and_the_good_rule_still_syncs(tmp_path: Path) -> None:
    bad_vocab = _rule(tmp_path / "a", _simple(), {"c": ["p", "q"]})
    (bad_vocab / "vocab.yml").write_bytes(b"c: [\xff\xfe]\n")
    bad_checks = _rule(tmp_path / "b", _simple(), {"c": ["p", "q"]})
    (bad_checks / "checks.yml").write_bytes(b"checks: \xff\xfe\n")
    good = _rule(tmp_path / "c", _simple(), {"c": ["p", "q"]})

    results = {r.rule_dir.name: r for r in sync_all(tmp_path)}

    assert any("vocab.yml is not UTF-8 text" in m for m in results["a"].messages)
    assert any("checks.yml" in m and "is not UTF-8 text" in m for m in results["b"].messages)
    assert results["c"].updated == 1
    assert _pattern(good) == r"\b(?:p|q)\b"


def test_named_field_still_targets_pattern_not_regex(tmp_path: Path) -> None:
    check = {"id": "R.c", "type": "deterministic", "patterns": [{"pattern-not-regex": _ALT}]}
    rule = _rule(tmp_path / "r", [check], {"c": {"pattern-not-regex": ["a", "b"]}})
    assert sync_vocab(rule).updated == 1
    written = yaml.safe_load((rule / "checks.yml").read_text(encoding="utf-8"))["checks"][0]["patterns"]
    assert written[0]["pattern-not-regex"] == r"\b(?:a|b)\b"


def test_message_names_every_non_alternation_slot(tmp_path: Path) -> None:
    check = {
        "id": "R.c",
        "type": "deterministic",
        "patterns": [{"pattern-regex": r"\d+"}, {"pattern-regex": r"\w+"}],
    }
    rule = _rule(tmp_path / "r", [check], {"c": ["a", "b"]})
    messages = " ".join(sync_vocab(rule).messages)
    assert r"'\\d+'" in messages
    assert r"'\\w+'" in messages


def test_mapping_field_value_says_mapping(tmp_path: Path) -> None:
    rule = _rule(tmp_path / "r", _simple(), {"c": {"pattern-regex": {"a": "b"}}})
    messages = sync_vocab(rule).messages
    assert any("holds a mapping, not a list of terms" in m for m in messages)
    assert not any("single value" in m for m in messages)


def test_extract_reports_a_broken_checks_file(tmp_path: Path) -> None:
    rule = tmp_path / "r"
    rule.mkdir()
    (rule / "checks.yml").write_text("checks: [unclosed\n", encoding="utf-8")

    [result] = extract_all(tmp_path)
    assert result.vocab is None
    assert result.problem.startswith("is not valid YAML (")

    cli = CliRunner(env={"COLUMNS": "300"}).invoke(stopwords_app, ["extract", "--rules-root", str(tmp_path)])
    assert cli.exit_code == 0
    assert "is not valid YAML" in cli.output
    assert not (rule / "vocab.yml").exists()


def test_compile_rules_skips_a_non_utf8_checks_file(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    from reporails_cli.core.lint.regex.compiler import compile_rules  # pylint: disable=import-outside-toplevel

    path = tmp_path / "checks.yml"
    path.write_bytes(b"checks: \xff\xfe\n")
    with caplog.at_level(logging.WARNING):
        result = compile_rules([path])
    assert result.checks == []
    assert any("Failed to load rule file" in r.message and "is not UTF-8 text" in r.message for r in caplog.records)


def test_compiler_warning_names_the_file_once(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    from reporails_cli.core.lint.regex.compiler import compile_rules  # pylint: disable=import-outside-toplevel

    path = tmp_path / "checks.yml"
    path.write_bytes(b"checks: \xff\xfe\n")
    with caplog.at_level(logging.WARNING):
        compile_rules([path])
    [record] = [r for r in caplog.records if "Failed to load rule file" in r.message]
    assert record.getMessage().count(str(path)) == 1


def test_extract_names_the_file_once(tmp_path: Path) -> None:
    rule = tmp_path / "r"
    rule.mkdir()
    (rule / "checks.yml").write_text("checks: [unclosed\n", encoding="utf-8")
    [result] = extract_all(tmp_path)
    assert str(rule) not in result.problem
    cli = CliRunner(env={"COLUMNS": "400"}).invoke(stopwords_app, ["extract", "--rules-root", str(tmp_path)])
    assert cli.output.count(str(rule / "checks.yml")) == 1


def test_sync_message_prints_a_character_class_intact(tmp_path: Path) -> None:
    _rule(tmp_path / "r", _simple(r"[a-z]+\d"), {"c": ["a", "b"]})
    cli = CliRunner(env={"COLUMNS": "400"}).invoke(stopwords_app, ["sync", "--rules-root", str(tmp_path)])
    assert "[a-z]+" in cli.output


def test_extract_skip_line_prints_a_bracketed_folder_intact(tmp_path: Path) -> None:
    rule = tmp_path / "[draft]"
    rule.mkdir()
    (rule / "checks.yml").write_text("checks: [unclosed\n", encoding="utf-8")
    cli = CliRunner(env={"COLUMNS": "400"}).invoke(stopwords_app, ["extract", "--rules-root", str(tmp_path)])
    assert str(rule / "checks.yml") in cli.output
