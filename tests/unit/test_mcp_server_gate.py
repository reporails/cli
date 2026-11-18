"""The MCP server's service check: reused briefly when it passed, never when it refused."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.dto.pipeline import Refusal
from reporails_cli.core.platform.dto.sign_in import Handshake
from reporails_cli.interfaces.mcp import tools


@pytest.fixture(autouse=True)
def _fresh_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    tools._gate_passed.clear()
    monkeypatch.setattr(tools, "model_not_ready_error", lambda: None)


def _count_gate(monkeypatch: pytest.MonkeyPatch, answers: list[Refusal | None]) -> list[str]:
    calls: list[str] = []

    def fake_gate(surface: str, _handshake: object) -> Refusal | None:
        calls.append(surface)
        return answers.pop(0)

    monkeypatch.setattr(tools, "server_gate", fake_gate)
    return calls


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_passed_check_is_reused_inside_the_window_and_asked_again_after(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(tools.time, "monotonic", lambda: clock[0])
    calls = _count_gate(monkeypatch, [None, None])
    run = RunContext()
    assert tools.unserved_or_model_not_ready_error(run) is None
    clock[0] += tools.HANDSHAKE_REUSE_S - 1
    assert tools.unserved_or_model_not_ready_error(run) is None
    assert calls == ["mcp"]
    clock[0] += 2
    assert tools.unserved_or_model_not_ready_error(run) is None
    assert calls == ["mcp", "mcp"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_refusal_is_never_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    refused = Refusal("server_refused", "Try again in ~5 min. Limit reached.")
    calls = _count_gate(monkeypatch, [refused, None])
    run = RunContext()
    assert tools.unserved_or_model_not_ready_error(run) == {"error": "server_refused", "message": refused.message}
    assert tools.unserved_or_model_not_ready_error(run) is None
    assert calls == ["mcp", "mcp"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_unreachable_reply_names_the_server_environment_not_a_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AILS_OFFLINE", raising=False)
    monkeypatch.delenv("AILS_DEV_MODE", raising=False)
    from reporails_cli.core.pipeline.server_gate import server_gate

    refusal = server_gate("mcp", lambda _surface: Handshake("unreachable"))
    assert refusal is not None
    assert "AILS_OFFLINE=1" in refusal.message
    assert "--offline" not in refusal.message
    cli = server_gate("cli", lambda _surface: Handshake("unreachable"))
    assert cli is not None
    assert "--offline" in cli.message
