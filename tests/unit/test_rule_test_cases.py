"""`ails test` runs the named fixture cases under a rule's `tests/cases/` directory."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _model_fetch_step_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rules here use only mechanical checks, so no file is mapped and no model is read."""
    monkeypatch.setattr("reporails_cli.interfaces.cli.check_support._ensure_model_or_exit", lambda: True)


CHECKS = "checks:\n- id: CORE.S.9998.size\n  type: mechanical\n  check: line_count\n  args: {max: 5}\n"
SHORT = "# P\n\n## Commands\n\n- Run `make test`.\n"
LONG = "x\n" * 20


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "rules"
    claude = root / "claude"
    claude.mkdir(parents=True)
    (claude / "config.yml").write_text(
        "agent: claude\nprefix: CLAUDE\nfile_types:\n  main:\n    patterns: [CLAUDE.md]\n    scope: root\n",
        encoding="utf-8",
    )
    return root


def _rule(root: Path, slug: str = "demo", rule_id: str = "CORE:S:9998", *, base: bool = True) -> Path:
    rule_dir = root / "core" / slug
    rule_dir.mkdir(parents=True)
    (rule_dir / "rule.md").write_text(
        f"---\nid: {rule_id}\nslug: {slug}\ntitle: Demo\ncategory: structure\ntype: mechanical\n"
        "severity: low\nmatch: {format: freeform}\n---\n\n# Demo\n\nText.\n",
        encoding="utf-8",
    )
    (rule_dir / "checks.yml").write_text(CHECKS.replace("9998", rule_id.rsplit(":", 1)[1]), encoding="utf-8")
    if base:
        _case(rule_dir, "pass", SHORT, cases=False)
        _case(rule_dir, "fail", LONG, cases=False)
    return rule_dir


def _case(rule_dir: Path, name: str, body: str, *, cases: bool = True) -> None:
    d = rule_dir / "tests" / ("cases" if cases else "") / name
    d.mkdir(parents=True)
    (d / "CLAUDE.md").write_text(body, encoding="utf-8")


def _run(root: Path, *extra: str):
    return runner.invoke(app, ["test", "--rules-root", str(root), *extra])


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_fail_case_that_does_not_fire_fails_the_rule_and_names_the_case(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _case(_rule(root), "fail-quiet", SHORT)

    result = _run(root)

    assert result.exit_code == 1, result.output
    assert "fail-quiet" in result.output
    assert "Failed:          1" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_pass_case_that_fires_fails_the_rule_and_names_the_case(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _case(_rule(root), "pass-noisy", LONG)

    result = _run(root)

    assert result.exit_code == 1, result.output
    assert "pass-noisy" in result.output
    assert "Failed:          1" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_cases_that_behave_as_named_pass_and_are_counted(tmp_path: Path) -> None:
    root = _root(tmp_path)
    rule_dir = _rule(root)
    _case(rule_dir, "pass-short", SHORT)
    _case(rule_dir, "fail-long", LONG)

    result = _run(root)

    assert result.exit_code == 0, result.output
    assert "Failed:          0" in result.output
    assert "Cases run:       2" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_oddly_named_case_directory_is_reported_by_name_and_does_not_run(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _case(_rule(root), "sketch-idea", LONG)

    result = _run(root)

    assert result.exit_code == 0, result.output
    assert "sketch-idea" in result.output
    assert "Cases not run:   1" in result.output
    assert "Cases run:       0" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_the_rule_filter_applies_to_cases(tmp_path: Path) -> None:
    root = _root(tmp_path)
    _case(_rule(root, "demo", "CORE:S:9998"), "fail-quiet", SHORT)
    _case(_rule(root, "other", "CORE:S:9997"), "pass-short", SHORT)

    result = _run(root, "--rule", "CORE:S:9997")

    assert result.exit_code == 0, result.output
    assert "fail-quiet" not in result.output
    assert "Cases run:       1" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_json_output_lists_the_cases_that_ran_and_did_not(tmp_path: Path) -> None:
    root = _root(tmp_path)
    rule_dir = _rule(root)
    _case(rule_dir, "pass-short", SHORT)
    _case(rule_dir, "odd", SHORT)

    result = _run(root, "--format", "json")

    data = json.loads(result.output)
    assert data["rules"][0]["cases_run"] == ["pass-short"]
    assert data["rules"][0]["cases_not_run"] == ["odd"]
    assert data["summary"]["cases_run"] == 1


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_rule_with_only_cases_runs_them(tmp_path: Path) -> None:
    root = _root(tmp_path)
    rule_dir = _rule(root, base=False)
    _case(rule_dir, "fail-quiet", SHORT)

    result = _run(root)

    assert result.exit_code == 1, result.output
    assert "fail-quiet" in result.output


_REPO = Path(__file__).resolve().parents[2]
_SOURCE_FIXTURES = [
    "framework/rules/claude/path-scope-declared/tests/pass/src/main.py",
    "framework/rules/copilot/path-scope-declared/tests/pass/src/main.py",
    "framework/rules/cursor/path-scope-declared/tests/pass/src/main.ts",
]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("fixture", _SOURCE_FIXTURES)
def test_path_scope_pass_fixture_source_file_is_tracked(fixture: str) -> None:
    """A pass fixture whose path globs need a source file ships that file, so a fresh clone passes."""
    import shutil
    import subprocess

    if shutil.which("git") is None or not (_REPO / ".git").exists():
        pytest.skip("not a git checkout")
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", fixture], cwd=_REPO, capture_output=True, text=True, check=False
    )
    assert tracked.returncode == 0, f"{fixture} is not tracked by git"
