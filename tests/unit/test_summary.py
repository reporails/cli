"""Unit tests for action/summary.py — GitHub Actions step summary generator."""

from __future__ import annotations

import importlib.util
from pathlib import Path

# Load summary.py as a module since action/ is not a package
_summary_path = Path(__file__).resolve().parents[2] / "action" / "summary.py"
_spec = importlib.util.spec_from_file_location("summary", _summary_path)
assert _spec and _spec.loader
summary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(summary)

generate_summary = summary.generate_summary
main = summary.main


# Helper: build a CombinedResult-style dict
def _result(
    files: dict | None = None,
    stats: dict | None = None,
    offline: bool = True,
) -> dict:
    return {
        "offline": offline,
        "files": files or {},
        "stats": stats or {"errors": 0, "warnings": 0},
    }


def _file(findings: list[dict]) -> dict:
    return {"findings": findings, "count": len(findings)}


def _finding(severity: str = "warning", rule: str = "CORE:S:0001", line: int = 1, message: str = "msg") -> dict:
    return {"severity": severity, "rule": rule, "line": line, "message": message}


# ---------------------------------------------------------------------------
# generate_summary — header table
# ---------------------------------------------------------------------------


class TestHeaderTable:
    """Status/findings/files/mode header table."""

    def test_status_pass_no_findings(self):
        md = generate_summary(_result())
        assert "Pass" in md

    def test_findings_count(self):
        md = generate_summary(_result(
            files={"CLAUDE.md": _file([_finding(), _finding()])},
            stats={"errors": 0, "warnings": 2},
        ))
        assert "**2**" in md

    def test_file_count(self):
        md = generate_summary(_result(
            files={"CLAUDE.md": _file([_finding()]), "rules/foo.md": _file([_finding()])},
        ))
        assert "| Files | 2 |" in md

    def test_offline_mode(self):
        md = generate_summary(_result(offline=True))
        assert "offline" in md

    def test_online_mode(self):
        md = generate_summary(_result(offline=False))
        assert "online" in md


# ---------------------------------------------------------------------------
# generate_summary — status line
# ---------------------------------------------------------------------------


class TestStatus:
    """Status line derivation from findings."""

    def test_no_findings_pass(self):
        md = generate_summary(_result())
        assert "Pass" in md

    def test_errors_fail(self):
        md = generate_summary(_result(
            files={"f.md": _file([_finding(severity="error")])},
            stats={"errors": 1, "warnings": 0},
        ))
        assert "Fail" in md

    def test_warnings_only(self):
        md = generate_summary(_result(
            files={"f.md": _file([_finding(severity="warning")])},
            stats={"errors": 0, "warnings": 1},
        ))
        assert "Warnings" in md


# ---------------------------------------------------------------------------
# generate_summary — findings table
# ---------------------------------------------------------------------------


class TestFindingsTable:
    """Findings detail table rendering."""

    def test_row_rendered(self):
        md = generate_summary(_result(
            files={"CLAUDE.md": _file([_finding(rule="CORE:S:0001", message="Missing section")])},
        ))
        assert "### Findings" in md
        assert "`CORE:S:0001`" in md
        assert "CLAUDE.md" in md
        assert "Missing section" in md

    def test_long_message_truncated(self):
        long_msg = "A" * 100
        md = generate_summary(_result(
            files={"f.md": _file([_finding(message=long_msg)])},
        ))
        assert "AAA..." in md
        assert "A" * 78 not in md

    def test_empty_findings_no_table(self):
        md = generate_summary(_result())
        assert "### Findings" not in md

    def test_severity_icons(self):
        findings = [_finding(severity=s) for s in ("error", "warning", "medium", "info")]
        md = generate_summary(_result(
            files={"f.md": _file(findings)},
        ))
        assert "\u274c" in md       # error
        assert "\u26a0\ufe0f" in md  # warning/medium
        assert "\U0001f535" in md    # info


# ---------------------------------------------------------------------------
# main() — CLI entry point
# ---------------------------------------------------------------------------


class TestMain:
    """main() reads from REPORAILS_RESULT env var."""

    def test_no_env_var(self, capsys, monkeypatch):
        monkeypatch.delenv("REPORAILS_RESULT", raising=False)
        main()
        out = capsys.readouterr().out
        assert "No results available" in out

    def test_empty_env_var(self, capsys, monkeypatch):
        monkeypatch.setenv("REPORAILS_RESULT", "  ")
        main()
        out = capsys.readouterr().out
        assert "No results available" in out

    def test_invalid_json(self, capsys, monkeypatch):
        monkeypatch.setenv("REPORAILS_RESULT", "not-json")
        main()
        out = capsys.readouterr().out
        assert "Failed to parse" in out

    def test_valid_json(self, capsys, monkeypatch):
        import json

        payload = json.dumps(_result(
            files={"CLAUDE.md": _file([_finding()])},
            stats={"errors": 0, "warnings": 1},
        ))
        monkeypatch.setenv("REPORAILS_RESULT", payload)
        main()
        out = capsys.readouterr().out
        assert "Reporails Check" in out
        assert "Warnings" in out
