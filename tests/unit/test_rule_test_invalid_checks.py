"""`ails test` reports a rule whose `checks.yml` is invalid instead of ending in a traceback."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _model_fetch_step_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rules here use only mechanical checks, so no file is mapped and no model is read."""
    monkeypatch.setattr("reporails_cli.interfaces.cli.check_support._ensure_model_or_exit", lambda: True)


GOOD_CHECKS = "checks:\n- id: CORE.S.9998.size\n  type: mechanical\n  check: line_count\n  args: {max: 5}\n"


def _rule(root: Path, slug: str, rule_id: str, checks: str) -> Path:
    rule_dir = root / "core" / slug
    (rule_dir / "tests" / "pass").mkdir(parents=True)
    (rule_dir / "tests" / "fail").mkdir(parents=True)
    (rule_dir / "rule.md").write_text(
        f"---\nid: {rule_id}\nslug: {slug}\ntitle: Demo\ncategory: structure\ntype: mechanical\n"
        "severity: low\nmatch: {format: freeform}\n---\n\n# Demo\n\nText.\n",
        encoding="utf-8",
    )
    (rule_dir / "checks.yml").write_text(checks, encoding="utf-8")
    (rule_dir / "tests" / "pass" / "CLAUDE.md").write_text("# P\n\n## Commands\n\n- Run `make test`.\n")
    (rule_dir / "tests" / "fail" / "CLAUDE.md").write_text("x\n" * 20)
    return rule_dir


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "rules"
    root.mkdir()
    claude = root / "claude"
    claude.mkdir()
    (claude / "config.yml").write_text(
        "agent: claude\nprefix: CLAUDE\nfile_types:\n  main:\n    patterns: [CLAUDE.md]\n    scope: root\n",
        encoding="utf-8",
    )
    return root


INVALID = {
    "a check that is a bare string": "checks:\n- just-a-string\n",
    "args that is a number": "checks:\n- id: CORE.S.9999.x\n  type: mechanical\n  check: line_count\n  args: 3\n",
    "a check without an id": "checks:\n- type: mechanical\n  check: file_exists\n",
    "checks that is a string": "checks: nope\n",
    "a top-level list": "- a\n- b\n",
    "yaml that does not parse": "checks: [unclosed\n",
}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("body", INVALID.values(), ids=INVALID.keys())
def test_an_invalid_checks_file_is_reported_by_name_without_a_traceback(tmp_path: Path, body: str) -> None:
    root = _root(tmp_path)
    _rule(root, "demo-bad", "CORE:S:9999", body)
    _rule(root, "demo-good", "CORE:S:9998", GOOD_CHECKS)

    result = runner.invoke(app, ["test", "--rules-root", str(root)])

    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "core/demo-bad/checks.yml" in result.output
    assert "demo-good" not in result.output.split("FAILURES:")[1].split("SUMMARY:")[0]
    assert "Failed:          1" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_the_other_rules_still_run_when_one_checks_file_is_invalid(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _rule(root, "demo-bad", "CORE:S:9999", "checks:\n- just-a-string\n")
    _rule(root, "demo-good", "CORE:S:9998", GOOD_CHECKS)

    result = runner.invoke(app, ["test", "--rules-root", str(root), "--verbose"])

    assert "Discovered 2 rule(s)" in result.output
    assert "PASS  CORE:S:9998" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_lint_names_an_invalid_checks_file_without_a_traceback(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _rule(root, "demo-bad", "CORE:S:9999", "checks:\n- just-a-string\n")

    result = runner.invoke(app, ["test", "--lint", "--rules-root", str(root)])

    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "core/demo-bad/checks.yml" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("name", ["checks.yml", "rule.md"])
def test_a_rule_file_that_is_not_utf8_is_a_load_error_not_a_crash(
    tmp_path: Path, name: str, caplog: pytest.LogCaptureFixture
) -> None:
    from reporails_cli.core.platform.adapters.registry import _scan_rules

    root = _root(tmp_path)
    rule_dir = _rule(root, "demo-bad", "CORE:S:9999", GOOD_CHECKS)
    _rule(root, "demo-good", "CORE:S:9998", GOOD_CHECKS)
    if name == "rule.md":
        (rule_dir / name).write_bytes(
            b"---\nid: CORE:S:9999\nslug: demo-bad\ntitle: T\ncategory: structure\ntype: mechanical\n"
            b"enforcement_required: true\nnote: caf\xe9\n---\n"
        )
    else:
        (rule_dir / name).write_bytes(b"checks:\n# caf\xe9\n")

    with caplog.at_level("WARNING"):
        rules = _scan_rules(root)

    assert [rule.id for rule in rules.values()] == ["CORE:S:9998"]
    assert f"{Path('core') / 'demo-bad' / name}: is not UTF-8 text" in caplog.text

    result = runner.invoke(app, ["test", "--lint", "--rules-root", str(root)])

    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert f"core/demo-bad/{name}" in result.output
    plain = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
    assert plain.count("is not UTF-8 text") == 1
    # A rule.md whose frontmatter was recovered is linted on that frontmatter (no severity, an
    # unnamed enforcement partner); a checks.yml failure leaves a complete rule.md clean.
    assert ("rule.md: severity: Field required" in plain) is (name == "rule.md")
    assert ("enforcement_mechanism" in plain) is (name == "rule.md")
