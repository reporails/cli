"""Tests for core/api_client.py — diagnostic API client."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.adapters import api_client as api_client_mod
from reporails_cli.core.platform.adapters.api_client import (
    AilsClient,
    _api_key_from_credentials,
    _deserialize_cross_file_coordinates,
    _deserialize_hints,
    _deserialize_lint_result,
    _deserialize_per_file,
    _tier_from_config,
)
from reporails_cli.core.platform.contract.errors import (
    ConfigUnreadableError,
    CredentialsUnreadableError,
)
from reporails_cli.core.platform.dto.diagnostics import LintResponse, LintResult
from reporails_cli.core.platform.dto.ruleset import FileRecord, RulesetMap, RulesetSummary
from reporails_cli.core.platform.policy.preflight import UNIVERSAL_ATOM_CAP, WIRE_MAX_FILES, preflight_oversized

_ROOT = Path("/tmp/reporails-test-scan-root")


def _make_map() -> RulesetMap:
    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(),
        atoms=(),
        summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
    )


class TestAilsClient:
    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_lint_empty_response_without_server(self) -> None:
        """No local fallback — lint requires the API."""
        client = AilsClient(base_url="")
        response = client.lint(_make_map(), root=_ROOT)
        assert isinstance(response, LintResponse)
        assert response.result is None
        assert response.funnel_error is None

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_lint_empty_response_on_unreachable_server(self) -> None:
        client = AilsClient(base_url="https://localhost:1")
        response = client.lint(_make_map(), root=_ROOT)
        assert isinstance(response, LintResponse)
        assert response.result is None

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_custom_base_url(self) -> None:
        client = AilsClient(base_url="https://custom.example.com")
        assert client.base_url == "https://custom.example.com"


class TestFaultDistinction:
    """A caught fault becomes a distinct typed cause; genuine absence stays "".

    Models `test_auth_error_messaging.py`: monkeypatch the file/config reads so each
    fault class is exercised without a real corrupt file on the host.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_missing_credentials_file_returns_empty(self, monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
        """Genuine absence (no file) → "" with no raise."""
        from pathlib import Path

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert _api_key_from_credentials() == ""

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_corrupt_credentials_raises_typed_cause(self, monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
        """A corrupt credentials file is a fault, not absence → CredentialsUnreadableError."""
        from pathlib import Path

        creds = tmp_path / ".reporails" / "credentials.yml"  # type: ignore[operator]
        creds.parent.mkdir(parents=True)
        creds.write_text("api_key: [unterminated", encoding="utf-8")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        with pytest.raises(CredentialsUnreadableError):
            _api_key_from_credentials()

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_absent_tier_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Genuine absence (config present, tier unset) → "" with no raise."""

        class _Cfg:
            tier = ""

        monkeypatch.setattr("reporails_cli.core.platform.config.config.get_global_config", lambda: _Cfg())
        assert _tier_from_config() == ""

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_unreadable_config_raises_typed_cause(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A config-read OSError is a fault, not absence → ConfigUnreadableError."""

        def _boom() -> object:
            raise OSError("disk gone")

        monkeypatch.setattr("reporails_cli.core.platform.config.config.get_global_config", _boom)
        with pytest.raises(ConfigUnreadableError):
            _tier_from_config()

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_client_degrades_to_anonymous_on_corrupt_credentials(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """AilsClient() with a fault on read → no raise, anonymous tier, visible WARNING."""
        import logging

        monkeypatch.delenv("AILS_API_KEY", raising=False)
        monkeypatch.delenv("AILS_TIER", raising=False)

        def _raise_creds() -> str:
            raise CredentialsUnreadableError("corrupt")

        monkeypatch.setattr(api_client_mod, "_api_key_from_credentials", _raise_creds)
        monkeypatch.setattr(api_client_mod, "_tier_from_config", lambda: "")

        with caplog.at_level(logging.WARNING, logger="reporails_cli.core.platform.adapters.api_client"):
            client = AilsClient()

        assert client.api_key == ""
        assert client.tier == "free"
        assert any(rec.levelno == logging.WARNING for rec in caplog.records)


class TestScanRootThreading:
    """The wire scan root is the checked project's own root, never the terminal's cwd."""

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_lint_threads_the_given_root_into_the_wire_payload(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: object
    ) -> None:
        """`lint(root=...)` must pass that exact root to `project_payload`, not `Path.cwd()`.

        The terminal's cwd is a different directory from the checked project, so a call
        that silently fell back to `Path.cwd()` would thread the wrong root and this
        assertion would catch it.
        """
        from unittest.mock import patch

        project_root = tmp_path / "project"  # type: ignore[operator]
        project_root.mkdir()
        elsewhere = tmp_path / "elsewhere"  # type: ignore[operator]
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)

        captured: list[object] = []

        def _fake_project_payload(ruleset_map: object, root: object) -> dict:
            captured.append(root)
            return _payload_with_file()

        with (
            patch(
                "reporails_cli.core.platform.adapters.payload.project_payload",
                side_effect=_fake_project_payload,
            ),
            patch("httpx.post") as mock_post,
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            client.lint(_make_map(), root=project_root)

        assert captured == [project_root]
        assert mock_post.call_count == 1

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_lint_threads_the_given_root_into_local_findings(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: object
    ) -> None:
        """`lint(local=..., root=...)` must pass the same root to `project_local`."""
        from unittest.mock import patch

        from reporails_cli.core.platform.dto.models import LocalEntry

        project_root = tmp_path / "project"  # type: ignore[operator]
        project_root.mkdir()
        elsewhere = tmp_path / "elsewhere"  # type: ignore[operator]
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)

        captured: list[object] = []

        def _fake_project_local(local: object, mapped: object, root: object) -> dict:
            captured.append(root)
            return {"local": []}

        local = (LocalEntry(rule="r", file=str(project_root / "CLAUDE.md"), line=1, severity="warning", check=""),)

        with (
            patch(
                "reporails_cli.core.platform.adapters.payload.project_payload",
                return_value=_payload_with_file(),
            ),
            patch(
                "reporails_cli.core.platform.adapters.payload.project_local",
                side_effect=_fake_project_local,
            ),
            patch("httpx.post") as mock_post,
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            client.lint(_make_map(), local, root=project_root)

        assert captured == [project_root]
        assert mock_post.call_count == 1


class TestPayloadCaps:
    """Preflight rejects oversized payloads before the HTTP round-trip."""

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_within_caps_returns_none(self) -> None:
        assert preflight_oversized({"files": [], "atoms": []}, has_api_key=True) is None

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_files_over_cap(self) -> None:
        payload = {"files": [{}] * (WIRE_MAX_FILES + 1), "atoms": []}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.error == "file_cap_exceeded"
        assert err.limit == WIRE_MAX_FILES

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_atoms_over_cap(self) -> None:
        payload = {"files": [], "atoms": [{}] * (UNIVERSAL_ATOM_CAP + 1)}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.error == "atom_cap_exceeded"
        assert err.limit == UNIVERSAL_ATOM_CAP

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_at_cap_boundary_passes(self) -> None:
        payload = {
            "files": [{}] * WIRE_MAX_FILES,
            "atoms": [{}] * UNIVERSAL_ATOM_CAP,
        }
        assert preflight_oversized(payload, has_api_key=True) is None

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_lint_skips_http_when_over_cap(self) -> None:
        """Oversized payload short-circuits before any network call."""
        from unittest.mock import patch

        from reporails_cli.core.platform.dto.ruleset import RulesetMap, RulesetSummary

        rm = RulesetMap(
            schema_version="1.0.0",
            embedding_model="test",
            generated_at="2026-01-01T00:00:00Z",
            files=(),
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        oversized = {
            "schema_version": "3",
            "embedding_model": "test",
            "generated_at": "2026-01-01T00:00:00Z",
            "files": [{}] * (WIRE_MAX_FILES + 1),  # over the file cap → file_cap_exceeded
            "atoms": [],
            "summary": {"n_atoms": 0, "n_charged": 0, "n_neutral": 0},
        }
        with (
            patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=oversized),
            patch("httpx.post") as mock_post,
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            response = client.lint(rm, root=_ROOT)
        assert response.result is None
        assert response.funnel_error is not None
        assert response.funnel_error.error == "file_cap_exceeded"
        mock_post.assert_not_called()

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_lint_skips_http_when_no_files(self) -> None:
        """Empty-files payload short-circuits — no request is sent."""
        from unittest.mock import patch

        from reporails_cli.core.platform.dto.ruleset import RulesetMap, RulesetSummary

        rm = RulesetMap(
            schema_version="1.0.0",
            embedding_model="test",
            generated_at="2026-01-01T00:00:00Z",
            files=(),
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )
        empty_payload = {
            "schema_version": "2",
            "embedding_model": "test",
            "generated_at": "2026-01-01T00:00:00Z",
            "files": [],
            "atoms": [],
            "summary": {"n_atoms": 0, "n_charged": 0, "n_neutral": 0},
        }
        with (
            patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=empty_payload),
            patch("httpx.post") as mock_post,
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            response = client.lint(rm, root=_ROOT)
        assert response.result is None
        assert response.funnel_error is None
        mock_post.assert_not_called()


def _payload_with_file() -> dict:
    return {
        "schema_version": "1.0.0",
        "embedding_model": "test",
        "generated_at": "2026-01-01T00:00:00Z",
        "files": [{"path": "CLAUDE.md"}],
        "atoms": [],
        "summary": {"n_atoms": 0, "n_charged": 0, "n_neutral": 0},
    }


class TestTransportFailureFunnelError:
    """A timeout, network failure, 5xx, or malformed
    2xx body used to return a bare `LintResponse()` (`funnel_error=None`) — the
    exact shape a designed offline run produces. A machine consumer (`--format
    json`/`github`, the GitHub Action) could not tell the two apart. Each of these
    reddens against the pre-fix code (bare `LintResponse()`, `funnel_error is None`)
    and greens against the fix (a typed reason token)."""

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_timeout_reports_timeout_token_and_no_status(self) -> None:
        from unittest.mock import patch

        import httpx

        def _raise_timeout(*args: object, **kwargs: object) -> None:
            raise httpx.TimeoutException("timed out")

        with (
            patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=_payload_with_file()),
            patch("httpx.post", side_effect=_raise_timeout),
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            response = client.lint(_make_map(), root=_ROOT)
        assert response.result is None
        assert response.funnel_error is not None
        assert response.funnel_error.error == "timeout"
        assert response.funnel_error.status is None

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_network_error_reports_network_error_token(self) -> None:
        from unittest.mock import patch

        import httpx

        def _raise_connect_error(*args: object, **kwargs: object) -> None:
            raise httpx.ConnectError("connection refused")

        with (
            patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=_payload_with_file()),
            patch("httpx.post", side_effect=_raise_connect_error),
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            response = client.lint(_make_map(), root=_ROOT)
        assert response.result is None
        assert response.funnel_error is not None
        assert response.funnel_error.error == "network_error"

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_5xx_reports_http_error_token_with_status(self) -> None:
        from unittest.mock import patch

        import httpx

        class _FakeResponse:
            status_code = 503
            text = "Service Unavailable"

            def raise_for_status(self) -> None:
                raise httpx.HTTPStatusError("503", request=None, response=self)

        def _fake_post(*args: object, **kwargs: object) -> _FakeResponse:
            return _FakeResponse()

        with (
            patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=_payload_with_file()),
            patch("httpx.post", side_effect=_fake_post),
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            response = client.lint(_make_map(), root=_ROOT)
        assert response.result is None
        assert response.funnel_error is not None
        assert response.funnel_error.error == "http_error"
        assert response.funnel_error.status == 503

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_malformed_2xx_body_reports_malformed_response_token(self) -> None:
        from unittest.mock import patch

        class _FakeResponse:
            status_code = 200

            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, object]:
                raise ValueError("not json")

        def _fake_post(*args: object, **kwargs: object) -> _FakeResponse:
            return _FakeResponse()

        with (
            patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=_payload_with_file()),
            patch("httpx.post", side_effect=_fake_post),
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            response = client.lint(_make_map(), root=_ROOT)
        assert response.result is None
        assert response.funnel_error is not None
        assert response.funnel_error.error == "malformed_response"

    @pytest.mark.unit
    @pytest.mark.subsys_api
    @pytest.mark.parametrize("body", [[1, 2, 3], "text", 7, None])
    def test_2xx_body_that_is_not_an_object_reports_malformed_response_token(self, body: object) -> None:
        from unittest.mock import patch

        class _FakeResponse:
            status_code = 200

            def raise_for_status(self) -> None:
                return None

            def json(self) -> object:
                return body

        with (
            patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=_payload_with_file()),
            patch("httpx.post", return_value=_FakeResponse()),
        ):
            client = AilsClient(base_url="https://example.test", tier="pro")
            response = client.lint(_make_map(), root=_ROOT)
        assert response.result is None
        assert response.funnel_error is not None
        assert response.funnel_error.error == "malformed_response"

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_per_file_entries_that_are_not_objects_are_skipped(self) -> None:
        good = {
            "file": "CLAUDE.md",
            "diagnostics": [None, {"line": 1, "severity": "warning", "rule": "R", "message": "m"}],
        }
        result = _deserialize_lint_result({"report": {"per_file": [None, 3, "x", good]}})
        (fa,) = result.report.per_file
        assert fa.file == "CLAUDE.md"
        assert len(fa.diagnostics) == 1


class TestOutgoingHeaders:
    """Asserts on the outgoing HTTP request shape.

    The default `httpx` User-Agent (`python-httpx/*`) trips the upstream
    edge bot-mitigation rules on anonymous-tier requests, producing a 403
    with a "Just a moment..." HTML challenge. Cost-free unit assertion that
    every outgoing diagnostic request carries a custom UA prevents the
    next regression of the same shape.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_anonymous_post_carries_custom_user_agent(self) -> None:
        from unittest.mock import patch

        from reporails_cli.core.platform.dto.ruleset import RulesetMap, RulesetSummary

        rm = RulesetMap(
            schema_version="1.0.0",
            embedding_model="test",
            generated_at="2026-01-01T00:00:00Z",
            files=(FileRecord(path="CLAUDE.md", content_hash="sha256:abc", agent="claude"),),
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )

        captured: dict[str, dict[str, str]] = {}

        class _FakeResponse:
            status_code = 200

            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, object]:
                return {
                    "schema_version": "1.0.0",
                    "score": 0.0,
                    "level": "L1",
                    "violations": [],
                    "stats": {},
                    "tier": "anonymous",
                }

        def _fake_post(url: str, **kwargs: object) -> _FakeResponse:
            captured["headers"] = dict(kwargs.get("headers") or {})
            return _FakeResponse()

        with patch("httpx.post", side_effect=_fake_post):
            client = AilsClient(base_url="https://example.test", tier="anonymous", api_key=None)
            client.lint(rm, root=_ROOT)

        ua = captured["headers"].get("User-Agent", "")
        assert ua.startswith("reporails-cli/"), (
            f"outgoing request UA must start with 'reporails-cli/' to avoid an edge bot-mitigation 403; got {ua!r}"
        )

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_authenticated_post_carries_custom_user_agent_and_bearer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from unittest.mock import patch

        monkeypatch.delenv("AILS_DEV_MODE", raising=False)

        from reporails_cli.core.platform.dto.ruleset import RulesetMap, RulesetSummary

        rm = RulesetMap(
            schema_version="1.0.0",
            embedding_model="test",
            generated_at="2026-01-01T00:00:00Z",
            files=(FileRecord(path="CLAUDE.md", content_hash="sha256:abc", agent="claude"),),
            atoms=(),
            summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
        )

        captured: dict[str, dict[str, str]] = {}

        class _FakeResponse:
            status_code = 200

            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, object]:
                return {
                    "schema_version": "1.0.0",
                    "score": 0.0,
                    "level": "L1",
                    "violations": [],
                    "stats": {},
                    "tier": "pro",
                }

        def _fake_post(url: str, **kwargs: object) -> _FakeResponse:
            captured["headers"] = dict(kwargs.get("headers") or {})
            return _FakeResponse()

        with patch("httpx.post", side_effect=_fake_post):
            client = AilsClient(base_url="https://example.test", tier="pro", api_key="test-key")
            client.lint(rm, root=_ROOT)

        headers = captured["headers"]
        assert headers.get("User-Agent", "").startswith("reporails-cli/")
        assert headers.get("Authorization") == "Bearer test-key"


class TestDeserializeHints:
    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_valid_hints(self) -> None:
        data = {
            "hints": [
                {
                    "file": "CLAUDE.md",
                    "diagnostic_type": "CORE:C:0044",
                    "count": 3,
                    "summary": "3 topics",
                    "severity": "error",
                    "error_count": 2,
                    "warning_count": 1,
                },
            ]
        }
        hints = _deserialize_hints(data)
        assert len(hints) == 1
        assert hints[0].file == "CLAUDE.md"
        assert hints[0].error_count == 2
        assert hints[0].severity == "error"

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_missing_fields_skipped(self) -> None:
        hints = _deserialize_hints({"hints": [{"file": "x.md"}]})
        assert len(hints) == 0

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_empty(self) -> None:
        assert _deserialize_hints({}) == ()
        assert _deserialize_hints({"hints": []}) == ()


class TestDeserializeCrossFileCoordinates:
    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_valid_coordinates(self) -> None:
        data = {
            "cross_file_coordinates": [
                {"file_1": "a.md", "file_2": "b.md", "finding_type": "conflict", "count": 2},
                {"file_1": "c.md", "file_2": "d.md", "finding_type": "repetition", "count": 1},
            ]
        }
        coords = _deserialize_cross_file_coordinates(data)
        assert len(coords) == 2
        assert coords[0].finding_type == "conflict"
        assert coords[0].count == 2

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_missing_fields_skipped(self) -> None:
        coords = _deserialize_cross_file_coordinates({"cross_file_coordinates": [{"file_1": "a.md"}]})
        assert len(coords) == 0

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_empty(self) -> None:
        assert _deserialize_cross_file_coordinates({}) == ()


class TestDeserializeLintResult:
    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_full_response_with_coordinates(self) -> None:
        data = {
            "report": {"per_file": [], "cross_file": [], "quality": {"display_score": 7.0}},
            "hints": [{"file": "CLAUDE.md", "diagnostic_type": "CORE:C:0044", "count": 3}],
            "cross_file_coordinates": [
                {"file_1": "a.md", "file_2": "b.md", "finding_type": "conflict", "count": 1},
            ],
            "tier": "anonymous",
        }
        result = _deserialize_lint_result(data)
        assert isinstance(result, LintResult)
        assert result.tier == "anonymous"
        assert len(result.hints) == 1
        assert len(result.cross_file_coordinates) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_pro_tier_no_hints_or_coordinates(self) -> None:
        data = {"report": {"per_file": [], "cross_file": [], "quality": {}}, "tier": "pro"}
        result = _deserialize_lint_result(data)
        assert result.tier == "pro"
        assert result.hints == ()
        assert result.cross_file_coordinates == ()


class TestDeserializePerFileImpactTier:
    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_impact_tier_parsed_when_present(self) -> None:
        data = {
            "per_file": [
                {
                    "file": "a.md",
                    "diagnostics": [
                        {
                            "line": 1,
                            "severity": "warning",
                            "rule": "CORE:C:0042",
                            "message": "x",
                            "impact_tier": "gate_mover",
                        },
                    ],
                }
            ]
        }
        (fa,) = _deserialize_per_file(data)
        assert fa.diagnostics[0].impact_tier == "gate_mover"

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_impact_tier_defaults_empty_when_absent(self) -> None:
        data = {
            "per_file": [
                {"file": "a.md", "diagnostics": [{"line": 1, "severity": "warning", "rule": "r", "message": "x"}]}
            ]
        }
        (fa,) = _deserialize_per_file(data)
        assert fa.diagnostics[0].impact_tier == ""


class TestTierForwardedOnMalformedReport:
    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_tier_forwarded_when_report_missing(self) -> None:
        """Regression: a 2xx response with a missing/garbled `report` but a real `tier`
        was deserialized as tier 'free', silently relabeling a pro/anonymous session."""
        result = _deserialize_lint_result({"tier": "pro"})
        assert result.tier == "pro"

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_tier_is_empty_when_the_response_names_none(self) -> None:
        """No tier on the wire means EMPTY, not `free`.

        Defaulting to a concrete tier made the client state something the server never
        said: it labelled an entitled response `free`, and it made the reader's own
        no-tier fallback unreachable, because "server said free" and "server said
        nothing" became the same value.
        """
        assert _deserialize_lint_result({}).tier == ""

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_tier_is_empty_when_a_malformed_report_names_none(self) -> None:
        assert _deserialize_lint_result({"report": "not-a-dict"}).tier == ""

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_tier_is_empty_when_the_wire_sends_null(self) -> None:
        assert _deserialize_lint_result({"tier": None}).tier == ""


class TestRateLimitCooldown:
    """A 429 is remembered locally: runs inside its window replay the rate-limit
    error without a round-trip, and the call resumes once the window ends."""

    _BODY_429 = (
        '{"error": "rate_limit_exceeded", "tier": "anonymous", "limit": 5, '
        '"reset_in": 1200, "upgrade_url": "https://reporails.com/account"}'
    )

    def _fake_post(self, status: int, text: str):  # type: ignore[no-untyped-def]
        import httpx

        class _FakeResponse:
            status_code = status

            def __init__(self) -> None:
                self.text = text

            def raise_for_status(self) -> None:
                raise httpx.HTTPStatusError(str(status), request=None, response=self)

        return lambda *args, **kwargs: _FakeResponse()

    def _lint(self, post, api_key: str = "") -> tuple[LintResponse, int]:  # type: ignore[no-untyped-def]
        from unittest.mock import MagicMock, patch

        mock_post = MagicMock(side_effect=post)
        with (
            patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=_payload_with_file()),
            patch("httpx.post", mock_post),
        ):
            client = AilsClient(base_url="https://example.test", api_key=api_key or None, tier="free")
            client.api_key = api_key
            response = client.lint(_make_map(), root=_ROOT)
        return response, mock_post.call_count

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_429_is_replayed_locally_without_a_request(self) -> None:
        first, calls = self._lint(self._fake_post(429, self._BODY_429))
        assert calls == 1
        assert first.funnel_error is not None and first.funnel_error.error == "rate_limit_exceeded"

        second, calls = self._lint(self._fake_post(200, "{}"))
        assert calls == 0
        err = second.funnel_error
        assert err is not None
        assert err.error == "rate_limit_exceeded"
        assert (err.tier, err.limit, err.status) == ("anonymous", 5, 429)
        assert err.upgrade_url == "https://reporails.com/account"
        assert 0 < err.reset_in <= 1200

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_free_signed_in_user_reaches_the_server_after_upgrading(self) -> None:
        body = self._BODY_429.replace('"anonymous"', '"free"')
        first, calls = self._lint(self._fake_post(429, body), api_key="rr_same_key")
        assert calls == 1
        assert first.funnel_error is not None and first.funnel_error.tier == "free"

        _, calls = self._lint(self._fake_post(429, body), api_key="rr_same_key")
        assert calls == 1  # a free window is not held: the server decides again

        class _Ok:
            status_code = 200
            text = ""

            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, str]:
                return {"tier": "pro"}

        third, calls = self._lint(lambda *args, **kwargs: _Ok(), api_key="rr_same_key")
        assert calls == 1
        assert third.funnel_error is None
        assert third.result is not None and third.result.tier == "pro"

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_pro_signed_in_user_over_its_cap_is_still_held(self) -> None:
        body = self._BODY_429.replace('"anonymous"', '"pro"')
        self._lint(self._fake_post(429, body), api_key="rr_pro_key")
        second, calls = self._lint(self._fake_post(200, "{}"), api_key="rr_pro_key")
        assert calls == 0
        assert second.funnel_error is not None and second.funnel_error.tier == "pro"

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_request_resumes_after_window_ends(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        from reporails_cli.core.platform.adapters import rate_cooldown

        self._lint(self._fake_post(429, self._BODY_429))
        later = time.time() + 1201
        monkeypatch.setattr(rate_cooldown.time, "time", lambda: later)
        _, calls = self._lint(self._fake_post(429, self._BODY_429))
        assert calls == 1

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_cooldown_is_per_credential(self) -> None:
        self._lint(self._fake_post(429, self._BODY_429))
        _, calls = self._lint(self._fake_post(429, self._BODY_429), api_key="rr_signed_in")
        assert calls == 1

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_other_4xx_does_not_start_a_cooldown(self) -> None:
        body = '{"error": "payload_too_large", "tier": "anonymous", "limit": 1, "size": 2}'
        self._lint(self._fake_post(413, body))
        _, calls = self._lint(self._fake_post(413, body))
        assert calls == 1

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_corrupt_cooldown_file_is_ignored(self) -> None:
        from reporails_cli.core.platform.adapters import rate_cooldown

        path = rate_cooldown._cooldown_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        _, calls = self._lint(self._fake_post(429, self._BODY_429))
        assert calls == 1

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_cooldown_never_exceeds_the_cap(self) -> None:
        from reporails_cli.core.platform.adapters import rate_cooldown
        from reporails_cli.core.platform.dto.diagnostics import FunnelError

        err = FunnelError(error="rate_limit_exceeded", reset_in=10 * 86400)
        rate_cooldown.record_cooldown("https://example.test", "", err, now=0.0)
        stored = rate_cooldown.active_cooldown("https://example.test", "", now=1.0)
        assert stored is not None
        assert stored.reset_in <= rate_cooldown.MAX_COOLDOWN_SECONDS
        assert (
            rate_cooldown.active_cooldown("https://example.test", "", now=rate_cooldown.MAX_COOLDOWN_SECONDS + 1)
            is None
        )

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_cooldown_file_lives_outside_the_cache_dir(self) -> None:
        """The cache dir is restored across CI runs (each a fresh runner with its own
        quota); a cooldown stored there would block runs it does not belong to."""
        from reporails_cli.core.platform.adapters import rate_cooldown
        from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir

        assert not rate_cooldown._cooldown_path().is_relative_to(get_global_cache_dir())
