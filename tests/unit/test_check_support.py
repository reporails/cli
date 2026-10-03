"""Behavioral tests for the check-command support helpers.

`_resume_check_timeout` must never touch `signal.setitimer` on win32 — that
module attribute does not exist there (no SIGALRM/setitimer support), which is
exactly what `mypy --platform=win32` catches statically. This guard mirrors
the one already on `_pause_check_timeout`.
"""

from __future__ import annotations

import sys

import pytest

from reporails_cli.interfaces.cli import check_support


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_resume_check_timeout_is_a_noop_on_win32(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")

    def _boom(*a, **k):
        raise AssertionError("setitimer must not be called on win32")

    # `signal` may not even have setitimer's real behavior mocked here; the
    # guard must return before importing/calling it at all.
    monkeypatch.setattr(check_support, "sys", sys)
    import signal

    monkeypatch.setattr(signal, "setitimer", _boom, raising=False)

    check_support._resume_check_timeout(5.0)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_resume_check_timeout_rearms_on_posix(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    calls = []
    import signal

    monkeypatch.setattr(signal, "setitimer", lambda which, secs: calls.append((which, secs)))

    check_support._resume_check_timeout(3.5)

    assert calls == [(signal.ITIMER_REAL, 3.5)]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_resume_check_timeout_skips_rearm_when_nothing_was_left(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    calls = []
    import signal

    monkeypatch.setattr(signal, "setitimer", lambda which, secs: calls.append((which, secs)))

    check_support._resume_check_timeout(0.0)

    assert calls == []


# ── AILS_MODEL_OFFLINE + a partial/absent model set is not silent ──


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_ensure_model_or_exit_announces_content_checks_skipped(monkeypatch, capsys):
    """REGRESSION: `AILS_MODEL_OFFLINE` with no (or only a partial) model set on
    disk must say content checks were skipped, not score on with no notice."""
    import reporails_cli.bundled as bundled_mod

    monkeypatch.setattr(bundled_mod, "ensure_models_available", lambda: None)

    assert check_support._ensure_model_or_exit() is False

    err = capsys.readouterr().err
    assert "content checks were skipped" in err
    assert "AILS_MODEL_OFFLINE" in err


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_ensure_model_or_exit_is_silent_when_the_model_is_available(monkeypatch, capsys):
    from pathlib import Path

    import reporails_cli.bundled as bundled_mod

    monkeypatch.setattr(bundled_mod, "ensure_models_available", lambda: Path("/some/model/dir"))

    assert check_support._ensure_model_or_exit() is True

    assert capsys.readouterr().err == ""
