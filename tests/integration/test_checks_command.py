"""Integration coverage for `ails list checks`."""

from __future__ import annotations

import json
import subprocess

import pytest


def _run(*args: str) -> tuple[int, str, str]:
    proc = subprocess.run(["ails", *args], capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_list_checks_help() -> None:
    code, out, _ = _run("list", "checks", "--help")
    assert code == 0
    assert "--for" in out
    assert "--agent" in out
    assert "--severity" in out


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_list_checks_for_skill_text() -> None:
    code, out, _ = _run("list", "checks", "--for=skill", "--agent=claude")
    assert code == 0
    assert "# Structure" in out
    assert "CORE:S:0024" in out


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_list_checks_for_skill_json() -> None:
    code, out, _ = _run("list", "checks", "--for=skill", "--agent=claude", "-f", "json")
    assert code == 0
    payload = json.loads(out)
    assert payload["capability"] == "skill"
    assert payload["agent"] == "claude"
    assert payload["count"] > 0
    for entry in payload["checks"]:
        for key in ("id", "title", "category", "severity", "type"):
            assert key in entry


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_list_checks_md_includes_examples() -> None:
    code, out, _ = _run("list", "checks", "--for=skill", "--agent=claude", "-f", "md")
    assert code == 0
    assert out.startswith("# Checks for authoring a skill")
    assert "**Pass**:" in out


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_list_checks_md_no_examples() -> None:
    code, out, _ = _run("list", "checks", "--for=skill", "--agent=claude", "-f", "md", "--no-examples")
    assert code == 0
    assert "**Pass**:" not in out
    assert "**Fail**:" not in out


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_list_checks_severity_filter() -> None:
    code, out, _ = _run("list", "checks", "--agent=claude", "--severity=high", "-f", "json")
    assert code == 0
    payload = json.loads(out)
    for entry in payload["checks"]:
        assert entry["severity"] in ("critical", "high")


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_list_checks_invalid_severity() -> None:
    code, _, _err = _run("list", "checks", "--severity=bogus")
    assert code != 0
