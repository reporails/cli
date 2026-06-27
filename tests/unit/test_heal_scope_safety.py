"""Scope-safety guard for `ails check --heal`.

`--heal` writes files. An implicit whole-project rewrite (no target) is refused
before any pipeline work; an explicit target, a `--dry-run` preview, or the
`--cwd` opt-in is required.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_without_target_is_refused() -> None:
    """Bare `ails check --heal` (whole-project, no target) exits 2 and writes nothing.

    The guard fires before the pipeline runs, so this stays fast and ML-free.
    """
    result = runner.invoke(app, ["check", "--heal"])
    assert result.exit_code == 2
    assert "needs an explicit target" in result.stdout


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize("dot", [".", "./"])
def test_heal_against_dot_is_refused(dot: str) -> None:
    """`ails check . --heal` resolves to the whole project root with no narrowing,
    so it is refused like a bare `--heal` (a non-empty target is not enough)."""
    result = runner.invoke(app, ["check", dot, "--heal"])
    assert result.exit_code == 2
    assert "needs an explicit target" in result.stdout


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_has_api_key_true_with_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """`--heal` is gated on auth; an env key reads as authenticated."""
    from reporails_cli.core.platform.adapters.api_client import has_api_key

    monkeypatch.setenv("AILS_API_KEY", "k")
    assert has_api_key() is True


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_has_api_key_false_when_anonymous(monkeypatch: pytest.MonkeyPatch) -> None:
    """No env key + isolated HOME (no credentials) reads as anonymous — `--heal` is gated off."""
    from reporails_cli.core.platform.adapters.api_client import has_api_key

    monkeypatch.delenv("AILS_API_KEY", raising=False)
    assert has_api_key() is False


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_refusal_is_json_parseable_under_json_format() -> None:
    """Under `-f json` the refusal is a parseable JSON error, not Rich text — a
    machine consumer still gets structured output (exit 2)."""
    result = runner.invoke(app, ["check", "--heal", "-f", "json"])
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == "heal_requires_target"
