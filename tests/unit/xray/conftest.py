"""The x-ray unit tests read the project's other sessions where they ask for it, not on a thread of their own."""

from __future__ import annotations

import pytest

from reporails_cli.core.xray import session as xray_session


@pytest.fixture(autouse=True)
def _earlier_sessions_read_inline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xray_session, "_in_background", lambda job: job())
