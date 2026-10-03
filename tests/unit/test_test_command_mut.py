"""Regression test for `interfaces/cli/test_command.py`.

Covers the bare `ails test` invocation (no `--rules-root`), which used to resolve
`--rules-root`'s `"."` default relative to the invoking cwd — almost never a rules
directory with an agent `config.yml` — so it always printed "No rules found." /
"Agent config not found" and exited 1, regardless of the rule corpus's real state.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from reporails_cli.core.platform.config.bootstrap import get_rules_path
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.mark.unit
@pytest.mark.requires_model
@pytest.mark.subsys_cli_ux
def test_bare_test_resolves_the_bundled_rules() -> None:
    """A bare `ails test` (no `--rules-root`) must resolve the bundled framework
    rules — same resolution `get_rules_path()` gives every other command — instead
    of failing to find any rules from the invoking cwd."""
    result = runner.invoke(app, ["test", "--rule", "CORE:S:0002"])

    assert "No rules found." not in result.output
    assert "Agent config not found" not in result.output
    assert "Discovered 1 rule(s)" in result.output
    # Rule fixtures are kept out of the repository, so a clean checkout has none to run.
    fixtures = get_rules_path() / "core" / "section-headers-present" / "tests"
    if fixtures.is_dir():
        assert "Passed:          1" in result.output
    else:
        assert "No fixtures:     1" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_explicit_rules_root_still_honored(tmp_path) -> None:
    """An explicit `--rules-root` that does not exist still errors — the new
    default only applies when the flag is omitted."""
    result = runner.invoke(app, ["test", "--rules-root", str(tmp_path / "missing")])

    assert result.exit_code == 2
    assert "Rules root not found" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_test_fetches_the_model_before_running_the_rules(monkeypatch) -> None:
    """`ails test` obtains the model through the same fetch step `ails check` uses,
    before any rule is run."""
    import reporails_cli.bundled as bundled_mod
    from reporails_cli.core.lint import harness

    calls: list[str] = []
    monkeypatch.setattr(bundled_mod, "ensure_models_available", lambda: calls.append("fetch") or object())
    monkeypatch.setattr(harness, "run_harness", lambda *a, **k: calls.append("run") or [])

    runner.invoke(app, ["test", "--rule", "CORE:S:0002"])

    assert calls == ["fetch", "run"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_test_stops_with_a_short_error_when_the_model_cannot_be_fetched(monkeypatch) -> None:
    """A failed model download ends `ails test` with the one-line error and exit code 2, no traceback."""
    import reporails_cli.bundled as bundled_mod
    from reporails_cli.core.mapper.model_fetch import ModelFetchError

    def _fail() -> None:
        raise ModelFetchError("could not download the reporails model")

    monkeypatch.setattr(bundled_mod, "ensure_models_available", _fail)

    result = runner.invoke(app, ["test", "--rule", "CORE:S:0002"])

    assert result.exit_code == 2
    assert "could not download the reporails model" in result.output
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_test_stops_with_a_short_error_when_offline_and_no_model(monkeypatch) -> None:
    """With `AILS_MODEL_OFFLINE` set and no model on disk, `ails test` exits 2 with a short
    message instead of failing inside the rule run."""
    import reporails_cli.bundled as bundled_mod

    monkeypatch.setattr(bundled_mod, "ensure_models_available", lambda: None)

    result = runner.invoke(app, ["test", "--rule", "CORE:S:0002"])

    assert result.exit_code == 2
    assert "needs the reporails model" in result.output
    assert "Traceback" not in result.output
