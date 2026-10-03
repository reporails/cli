"""Hermetic isolation for the e2e smoke suite.

The smoke tests invoke `ails check` end-to-end. An unset or empty `AILS_SERVER_URL`
means the default hosted endpoint, so the suite points it at a closed local port
instead: the connection is refused at once, and every invocation takes its local path.
The suite then runs deterministically and asserts only on local findings, exit codes,
and rendering. `HOME` isolation is handled by the repo-root `conftest._isolate_home`
autouse fixture.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _offline_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the server URL at a closed local port so no smoke test reaches the network."""
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
