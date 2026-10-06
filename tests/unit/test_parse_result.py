"""Unit tests for action/parse_result.py — GitHub Actions output parser.

`--format json` carried `offline: true` with no reason
for a server rejection, timeout, or network failure, so the Action's `min-score`
gate silently skipped instead of failing loud, and the run read as a clean pass.
These tests demonstrate the fix at the seam that consumes the JSON: feed a
`server_error`-carrying payload and assert the eval-safe `_RESULT`/`_SERVER_REASON`
lines this module now emits; feed a normal payload and assert they read as `ok`/empty.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

# Load parse_result.py as a module since action/ is not a package.
_parse_result_path = Path(__file__).resolve().parents[2] / "action" / "parse_result.py"
_spec = importlib.util.spec_from_file_location("parse_result", _parse_result_path)
assert _spec and _spec.loader
parse_result = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(parse_result)

main = parse_result.main
_server_error_token = parse_result._server_error_token


def _run_main(capsys, monkeypatch, payload: dict) -> dict[str, str]:
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(payload)))
    main()
    out = capsys.readouterr().out
    return dict(line.split("=", 1) for line in out.strip().splitlines())


class TestServerErrorToken:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_none_when_absent(self):
        assert _server_error_token(None) == ""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_passes_through_known_token(self):
        assert _server_error_token({"error": "network_error"}) == "network_error"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_rejects_shell_metacharacters(self):
        # Defense-in-depth: this value reaches the calling shell via `eval`, so a
        # server-controlled (or malformed) `error` string with shell metacharacters
        # must never pass through verbatim, even though upstream already restricts
        # `FunnelError.error` to a fixed vocabulary.
        malicious = "$(rm -rf /)"
        assert _server_error_token({"error": malicious}) == "unknown_error"
        assert "$(" not in _server_error_token({"error": malicious})


class TestMainEmitsServerOutcome:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_healthy_run_is_ok_with_empty_server_error(self, capsys, monkeypatch):
        payload = {
            "quality": 7.4,
            "level": "L7",
            "stats": {"total_findings": 3},
            "files": {},
        }
        env = _run_main(capsys, monkeypatch, payload)
        assert env["_SCORE"] == "7.4"
        assert env["_RESULT"] == "ok"
        assert env["_SERVER_REASON"] == ""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_designed_offline_run_is_still_ok(self, capsys, monkeypatch):
        # No `server_error` key at all (an older CLI, or offline-by-design) must
        # not be misread as an outage.
        payload = {"quality": None, "level": "L0", "stats": {"total_findings": 0}, "files": {}}
        env = _run_main(capsys, monkeypatch, payload)
        assert env["_SCORE"] == ""
        assert env["_RESULT"] == "ok"
        assert env["_SERVER_REASON"] == ""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_rejection_sets_server_unavailable(self, capsys, monkeypatch):
        payload = {
            "quality": None,
            "level": "L0",
            "stats": {"total_findings": 0},
            "files": {},
            "offline": True,
            "server_error": {
                "status": 401,
                "error": "unknown_error",
                "message": "API key not recognized",
                "tier": "",
                "upgrade_url": "",
            },
        }
        env = _run_main(capsys, monkeypatch, payload)
        assert env["_SCORE"] == ""
        assert env["_RESULT"] == "server-unavailable"
        assert env["_SERVER_REASON"] == "unknown_error"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_network_error_sets_server_unavailable(self, capsys, monkeypatch):
        payload = {
            "quality": None,
            "level": "L0",
            "stats": {"total_findings": 0},
            "files": {},
            "offline": True,
            "server_error": {
                "status": None,
                "error": "network_error",
                "message": "Could not reach the diagnostics server",
                "tier": "",
                "upgrade_url": "",
            },
        }
        env = _run_main(capsys, monkeypatch, payload)
        assert env["_RESULT"] == "server-unavailable"
        assert env["_SERVER_REASON"] == "network_error"


class TestContentChecksSkipped:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize(("flag", "expected"), [(True, "true"), (False, "false"), (None, "false")])
    def test_flag_is_surfaced(self, capsys, monkeypatch, flag, expected):
        payload = {"quality": 7.4, "level": "L3", "stats": {"total_findings": 1}, "files": {}}
        if flag is not None:
            payload["content_checks_skipped"] = flag
        assert _run_main(capsys, monkeypatch, payload)["_CONTENT_SKIPPED"] == expected


def _gate_script() -> str:
    import yaml

    action = yaml.safe_load((Path(__file__).resolve().parents[2] / "action" / "action.yml").read_text())
    step = next(s for s in action["runs"]["steps"] if s.get("name") == "Apply min-score gate")
    return step["run"].split('python3 -c "', 1)[1].rsplit('"', 1)[0]


class TestMinScoreGate:
    def _gate(self, **env):
        import subprocess
        import sys

        base = {
            "SCORE": "",
            "SERVER_STATUS": "ok",
            "SERVER_ERROR": "",
            "CONTENT_SKIPPED": "false",
            "INPUT_MIN_SCORE": "5",
        }
        return subprocess.run(
            [sys.executable, "-c", _gate_script()], env={**base, **env}, capture_output=True, text=True, check=False
        )

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_fails_when_content_checks_were_skipped_even_with_passing_score(self):
        proc = self._gate(SCORE="9.0", CONTENT_SKIPPED="true")
        assert proc.returncode == 1
        assert "content checks were skipped" in proc.stdout

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_passes_when_score_meets_threshold(self):
        assert self._gate(SCORE="9.0").returncode == 0
