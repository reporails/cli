"""The default output format follows the runner's CI variables."""

from __future__ import annotations

import pytest

from reporails_cli.interfaces.cli.helpers import _default_format


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("var", ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI"])
def test_ci_variable_defaults_to_json(monkeypatch: pytest.MonkeyPatch, var: str) -> None:
    monkeypatch.setenv(var, "true")
    assert _default_format() == "json"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_no_ci_variable_defaults_to_text() -> None:
    assert _default_format() == "text"
