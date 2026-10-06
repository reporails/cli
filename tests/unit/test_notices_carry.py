"""Notices travel from the reply header to every output surface; an early rejected key reads as a delay."""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from reporails_cli.core.pipeline.assemble import AssembleInputs, assemble_result
from reporails_cli.core.platform.adapters.api_client import AilsClient
from reporails_cli.core.platform.adapters.notices_wire import NOTICES_HEADER
from reporails_cli.core.platform.dto.diagnostics import FunnelError, LintResponse, Notice
from reporails_cli.core.platform.dto.ruleset import RulesetMap, RulesetSummary
from reporails_cli.core.platform.runtime.merger import CombinedResult
from reporails_cli.formatters import json as json_formatter
from reporails_cli.interfaces.cli.main import app
from reporails_cli.interfaces.mcp import tools

WARN = Notice("pay", "warn", "Payment failed [bold]x[/bold]", "https://example.test/pay")
INFO = Notice("ends", "info", "Pro ends on 1 June")
RAW = [
    {"id": "pay", "level": "warn", "text": "Payment failed [bold]x[/bold]", "url": "https://example.test/pay"},
    {"id": "ends", "level": "info", "text": "Pro ends on 1 June", "url": ""},
]
STILL_REACHING = "Your sign-in is still reaching the server"
runner = CliRunner()


def _header() -> str:
    return base64.urlsafe_b64encode(json.dumps(RAW).encode()).decode().rstrip("=")


def _map() -> RulesetMap:
    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(),
        atoms=(),
        summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
    )


class _Reply:
    """A reply the fake transport hands back; raises like httpx for an error status."""

    def __init__(self, status: int, body: Any, headers: dict[str, str]) -> None:
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)
        self.headers = headers

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(str(self.status_code), request=None, response=self)  # type: ignore[arg-type]

    def json(self) -> Any:
        return self._body


def _lint(status: int, body: Any, headers: dict[str, str], *, key: str = "") -> LintResponse:
    payload = {"files": [{"path": "CLAUDE.md"}]}
    with (
        patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=payload),
        patch("httpx.post", return_value=_Reply(status, body, headers)),
    ):
        client = AilsClient(base_url="https://example.test", tier="pro")
        client.api_key = key
        return client.lint(_map(), root=Path("/tmp/notices-carry-root"))


def _ok_body() -> dict[str, Any]:
    return {"report": {"per_file": []}, "tier": "free"}


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("status", "body"),
    [(200, _ok_body()), (429, {"error": "rate_limit_exceeded"}), (401, {"error": "invalid_api_key"})],
)
def test_header_notices_ride_on_success_and_error_replies(status: int, body: dict[str, Any]) -> None:
    response = _lint(status, body, {NOTICES_HEADER: _header()})
    assert response.notices == (WARN, INFO)
    assert (response.funnel_error is None) == (status == 200)


@pytest.mark.unit
@pytest.mark.subsys_api
def test_reply_without_the_header_carries_none() -> None:
    assert _lint(200, _ok_body(), {}).notices == ()


@pytest.mark.unit
@pytest.mark.subsys_server
def test_assemble_result_puts_notices_on_the_result(tmp_path: Path) -> None:
    inp = AssembleInputs(
        m_findings=[],
        content_findings=[],
        client_findings=[],
        ruleset_map=None,
        scan_root=tmp_path,
        filter_agents=None,
        effective_agent="claude",
        lint_result=None,
        alias_fn=lambda _r: set(),
        notices=(WARN, INFO),
    )
    assert assemble_result(inp).notices == (WARN, INFO)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_json_carries_every_notice_and_an_empty_list_when_none() -> None:
    data = json_formatter.format_combined_result(CombinedResult(notices=(WARN, INFO)), ruleset_map=None)
    assert data["notices"] == RAW
    assert json_formatter.format_combined_result(CombinedResult(), ruleset_map=None)["notices"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_mcp_validate_payload_carries_notices_and_the_funnel_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    err = FunnelError(error="rate_limit_exceeded", tier="free", status=429)
    monkeypatch.setattr(tools, "_server_lint", lambda *_a, **_k: LintResponse(funnel_error=err, notices=(WARN,)))
    monkeypatch.setattr(tools, "_checks_over_pairs", lambda *_a, **_k: ([], [], []))
    monkeypatch.setattr(tools, "_mcp_agent_file_pairs", lambda *_a, **_k: [])
    ruleset_map = _map()
    result, funnel_error = tools._check_and_assemble(tmp_path, [], "claude", [], ruleset_map)
    payload = tools._attach_funnel(json_formatter.format_combined_result(result, ruleset_map=ruleset_map), funnel_error)
    from reporails_cli.formatters import mcp as mcp_formatter

    bounded = mcp_formatter.bound_validate_payload(payload)
    assert bounded["notices"] == [RAW[0]]
    assert bounded["funnel"]["error"] == "rate_limit_exceeded"


# --- the real `ails check` command -------------------------------------------------------


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path, None, None]:
    # A check run quiets the mapper's logger for the process; put it back for the tests after this one.
    mapper_logger = logging.getLogger("reporails_cli.core.mapper")
    level = mapper_logger.level
    root = tmp_path / "proj"
    root.mkdir()
    (root / "CLAUDE.md").write_text("# Project\n\nUse uv for Python.\n", encoding="utf-8")
    monkeypatch.chdir(root)
    monkeypatch.setattr("reporails_cli.core.pipeline.mapping.map_instruction_files", lambda *_a, **_k: _map())
    monkeypatch.setattr(
        AilsClient, "lint", lambda *_a, **_k: LintResponse(funnel_error=None, result=None, notices=(WARN, INFO))
    )
    yield root
    mapper_logger.setLevel(level)


def _check() -> str:
    result = runner.invoke(app, ["check", "-f", "text"])
    assert result.exit_code == 0, result.output
    return result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_text_prints_notices_after_the_header_escaped_and_info_only_once(project: Path) -> None:
    first = _check()
    header, notice = first.index("Diagnostics"), first.index("Payment failed [bold]x[/bold]")
    assert header < notice
    assert "Pro ends on 1 June" in first
    second = _check()
    assert "Payment failed [bold]x[/bold]" in second
    assert "Pro ends on 1 June" not in second


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_json_run_lists_every_notice_on_every_run(project: Path) -> None:
    for _ in range(2):
        out = runner.invoke(app, ["check", "-f", "json"]).stdout
        assert json.loads(out)["notices"] == RAW


# --- early rejection ----------------------------------------------------------------------


def _store_key(signed_in_at: datetime) -> None:
    from reporails_cli.core.platform.config.credentials import credentials_path

    path = credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"api_key": "k1", "tier": "free", "signed_in_at": signed_in_at.isoformat()}), encoding="utf-8"
    )


_REJECTION = {"error": "invalid_api_key", "message": "Your sign-in ended."}


@pytest.mark.unit
@pytest.mark.subsys_api
def test_key_rejected_within_two_minutes_of_sign_in_reads_as_a_delay() -> None:
    from reporails_cli.formatters.text.funnel_cta import plain_cta

    _store_key(datetime.now(UTC) - timedelta(seconds=30))
    err = _lint(401, _REJECTION, {}, key="k1").funnel_error
    assert err is not None
    assert err.error == "invalid_api_key"
    assert STILL_REACHING in err.message
    assert STILL_REACHING in plain_cta(err)


@pytest.mark.unit
@pytest.mark.subsys_api
def test_key_rejected_long_after_sign_in_keeps_the_servers_message() -> None:
    _store_key(datetime.now(UTC) - timedelta(minutes=10))
    err = _lint(401, _REJECTION, {}, key="k1").funnel_error
    assert err is not None
    assert err.message == "Your sign-in ended."


@pytest.mark.unit
@pytest.mark.subsys_api
def test_other_rejections_are_not_reworded_after_sign_in() -> None:
    _store_key(datetime.now(UTC))
    err = _lint(429, {"error": "rate_limit_exceeded", "message": "Slow down"}, {}, key="k1").funnel_error
    assert err is not None
    assert err.message == "Slow down"
