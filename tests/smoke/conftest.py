"""Hermetic isolation for the e2e smoke suite.

The smoke tests invoke `ails check` end-to-end. By default the client posts the
ruleset map to the production endpoint (`https://api.reporails.com`), which makes
the suite depend on machine-local network reachability and the live edge — the
reason it was kept out of the gated CI matrix. Forcing an empty `AILS_SERVER_URL`
routes every invocation through the offline branch (`AilsClient.lint` returns an
empty `LintResponse` when `base_url` is falsy), so the suite runs deterministically
and asserts only on client-side findings, exit codes, and rendering. `HOME`
isolation is handled by the repo-root `conftest._isolate_home` autouse fixture.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _offline_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force offline diagnostics so the smoke suite never touches the network."""
    monkeypatch.setenv("AILS_SERVER_URL", "")
